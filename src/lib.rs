mod cert;

use boring::ssl::{SslContextBuilder, SslMethod};
use clap::Parser;
use log::{info, trace};
use quiche_mio_runner as runner;
use quiche_mio_runner::mio::unix::pipe::Receiver;
use quiche_mio_runner::quiche_endpoint::quiche::{ConnectionError, Shutdown};
use quiche_mio_runner::quiche_endpoint::Endpoint;
use quiche_mio_runner::quiche_endpoint::{quiche, Conn, EndpointConfig, ServerConfig};
use quiche_mio_runner::Socket;
use slab::Slab;
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::PathBuf;
use std::str::from_utf8;
pub use crate::cert::load_or_generate_keys;

type Runner = runner::Runner<ConnAppData, AppData, ()>;

#[derive(Parser)]
pub struct Args {
    /// TLS certificate path. Generated if not specified
    #[arg(long, value_name = "PATH")]
    pub cert: Option<PathBuf>,
    /// TLS certificate key path. Generated if not specified
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,
    /// Disable Generic Receive Offload
    #[arg(long)]
    pub disable_gro: bool,
    /// Disable Generic Send Offload
    #[arg(long)]
    pub disable_gso: bool,
    /// Address to bind socket to
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:4433")]
    pub bind: SocketAddr,
    /// Don't verify server's certificate
    #[arg(long)]
    pub no_verify: bool,
    /// The server port to forwards packets to
    #[arg(long, value_name = "PORT", default_value = "443")]
    pub forward_port: u16,
    #[arg(long, default_value = "h3")]
    pub alpn: String,
}

pub fn run_proxy(args: Args, close_pipe_rx: Option<&mut Receiver>) {
    let (cert, key) = load_or_generate_keys(&args.cert, &args.key);

    let socket = Socket::bind(args.bind, args.disable_gro, false, args.disable_gso).unwrap();
    assert_eq!(socket.enable_gro, !args.disable_gro);
    assert!(socket.enable_pacing);
    assert_eq!(socket.enable_gso, !args.disable_gso);
    info!("Proxy listening on https://{}", socket.local_addr);

    let client_config = {
        let mut c = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, {
            let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
            b.set_private_key(&key).unwrap();
            b.set_certificate(&cert).unwrap();
            b
        }).unwrap();
        c.set_application_protos(&[args.alpn.as_bytes()]).unwrap();
        c.set_max_idle_timeout(30000);
        c.set_initial_max_streams_bidi(100);
        c.set_initial_max_streams_uni(100);
        c.set_initial_max_data(10000000);
        c.set_initial_max_stream_data_bidi_remote(1000000);
        c.set_initial_max_stream_data_bidi_local(1000000);
        c.set_initial_max_stream_data_uni(1000000);
        c.set_max_connection_window(25165824);
        c.set_max_stream_window(16777216);
        c
    };

    let server_facing_config = {
        let mut c = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        c.verify_peer(!args.no_verify);
        c.set_application_protos(&[args.alpn.as_bytes()]).unwrap();
        c.set_max_idle_timeout(30000);
        c.set_initial_max_streams_bidi(100);
        c.set_initial_max_streams_uni(100);
        c.set_initial_max_data(10000000);
        c.set_initial_max_stream_data_bidi_remote(1000000);
        c.set_initial_max_stream_data_bidi_local(1000000);
        c.set_initial_max_stream_data_uni(1000000);
        c.set_active_connection_id_limit(2);
        c.set_initial_congestion_window_packets(10);
        c.set_max_connection_window(25165824);
        c.set_max_stream_window(16777216);
        c.enable_pacing(true);
        c.grease(false);
        c
    };

    let endpoint = Endpoint::new(
        Some({
            let mut c = ServerConfig::default();
            c.client_config = client_config;
            c
        }),
        EndpointConfig::default(),
        AppData {
            proxy_conns: Default::default(),
            args,
            buf: [0u8; 1 << 16],
            server_facing_config: Some(server_facing_config),
        },
    );

    let mut runner = Runner::new(
        {
            let mut c = runner::Config::default();
            c.post_handle_recvs = post_handle_recvs;
            c
        },
        endpoint,
        close_pipe_rx,
    );

    runner.register_socket(socket);

    runner.run()
}

fn post_handle_recvs(runner: &mut Runner) {
    let endpoint = &mut runner.endpoint;
    let mut setup_queue = VecDeque::<HalfOpenProxyConn>::new();
    for cid in &mut endpoint.conn_index_iter() {
        let Some(conn) = endpoint.conn(cid) else {
            continue
        };
        if !conn.conn.is_established() && !conn.conn.is_in_early_data() {
            continue; // not ready for h3 yet
        }
        if conn.conn.is_draining() | conn.conn.is_closed() {
            continue;
        }

        let server_name = match conn.conn.server_name() {
            Some(v) => v,
            None => {
                let conn = endpoint.conn_mut(cid).unwrap(); // upgrade mut
                let _ = conn.conn.close(false, 0, b"no SNI provided");
                continue;
            }
        };

        if conn.app_data.proxy_conn_id.is_none() {
            let proxy_conn = HalfOpenProxyConn {
                server_name: server_name.to_string(),
                client_side_conn_id: conn.client_id,
            };
            setup_queue.push_back(proxy_conn);
        };
    }

    while let Some(proxy_conn) = setup_queue.pop_front() {
        let mut server_facing_config = endpoint.app_data_mut().server_facing_config.take().unwrap();
        let client_side_conn_id = proxy_conn.client_side_conn_id;
        let client_side_conn = endpoint.conn(client_side_conn_id).unwrap();
        let client_side_addr = client_side_conn.conn.path_stats().next().unwrap().peer_addr;
        let client_side_trace_id = client_side_conn.conn.trace_id().to_string();

        let args = &endpoint.app_data().args;
        create_server_side_config(client_side_conn, &mut server_facing_config);

        info!("resolve IP of {}", &proxy_conn.server_name);
        let server_side_addr: SocketAddrV4 = (proxy_conn.server_name.as_ref(), args.forward_port)
            .to_socket_addrs()
            .unwrap()
            .filter_map(|a| match a {
                SocketAddr::V4(a) => Some(a),
                _ => None,
            })
            .next()
            .unwrap();

        let server_side_conn_id = endpoint.connect(
            Some(proxy_conn.server_name.as_ref()),
            runner.sockets.sockets.get(0).unwrap().local_addr,
            server_side_addr.into(),
            &mut server_facing_config,
            ConnAppData {
                proxy_conn_id: None,
            },
            None,
            None,
        );
        endpoint.app_data_mut().server_facing_config.replace(server_facing_config); // put back

        let proxy_conn = proxy_conn.with_server(server_side_conn_id);
        let proxy_conn_id = endpoint.app_data_mut().proxy_conns.insert(proxy_conn);

        endpoint.conn_mut(client_side_conn_id).unwrap().app_data.proxy_conn_id = Some(proxy_conn_id);
        endpoint.conn_mut(server_side_conn_id).unwrap().app_data.proxy_conn_id = Some(proxy_conn_id);

        let proxy_conn = endpoint.app_data().proxy_conns.get(proxy_conn_id).unwrap();
        info!(
            "proxy conn {} setup {}",
            proxy_conn_id,
            fmt(|f| f.debug_struct("ProxyConn")
                .field("server_name", &proxy_conn.server_name)
                .field("client_side_conn_id", &client_side_conn_id)
                .field("client_side_addr", &client_side_addr)
                .field("client_side_trace_id", &client_side_trace_id)
                .field("server_side_conn_id", &server_side_conn_id)
                .field("server_side_addr", &server_side_addr)
                .finish())
        );
    }

    for proxy_conn_id in 0..endpoint.app_data().proxy_conns.capacity() {
        let Some(proxy_conn) = endpoint.app_data().proxy_conns.get(proxy_conn_id) else { continue };
        let (conns, app_data) = endpoint.conn2_with_app_data_mut(proxy_conn.client_side_conn_id, proxy_conn.server_side_conn_id);
        let (client_side_conn, server_side_conn) = conns.unwrap();
        let buf = &mut app_data.buf;
        let closed = forward_error_and_timeout(client_side_conn, server_side_conn, proxy_conn_id)
            | forward_error_and_timeout(server_side_conn, client_side_conn, proxy_conn_id);

        if closed {
            info!("proxy conn {} close", proxy_conn_id);
            // upgrade mut
            let proxy_conn = endpoint.app_data_mut().proxy_conns.get_mut(proxy_conn_id).unwrap();
            proxy_conn.closed = true;
            continue;
        }

        for stream_id in client_side_conn.conn.readable() {
            forward_stream(&mut client_side_conn.conn, &mut server_side_conn.conn, stream_id, proxy_conn_id, buf);
        }

        for stream_id in server_side_conn.conn.readable() {
            forward_stream(&mut server_side_conn.conn, &mut client_side_conn.conn, stream_id, proxy_conn_id, buf);
        }
    }

    endpoint.app_data_mut().proxy_conns.retain(|_, proxy_conn| {
        !proxy_conn.closed
    });
}

/// applies similar config from the client-side connection to the server-side connection
fn create_server_side_config(client_side_conn: &Conn<ConnAppData>, c: &mut quiche::Config) {
    // for h3, datagram frame support must be mirrored because it is also part of the h3 settings
    c.enable_dgram(
        client_side_conn
            .conn
            .dgram_max_writable_len()
            .is_some(),
        10,
        10,
    );
}

/// return true if closed
fn forward_error_and_timeout(rx_conn: &mut Conn<ConnAppData>, tx_conn: &mut Conn<ConnAppData>, proxy_conn_id: usize) -> bool {
    let err = if rx_conn.conn.is_timed_out() {
        &ConnectionError {
            is_app: false,
            error_code: 0,
            reason: b"timed out".to_vec(),
        }
    } else if let Some(err) = rx_conn.conn.peer_error() {
        if !err.is_app && (0x0100..=0x01ff).contains(&err.error_code) { // is CRYPTO_ERROR
            //todo convert, because those can only be sent during the handshake, but i have not found an error that stops chromium from retrying, similar to crypto_error 0x0128
            err
        } else {
            err
        }
    } else if let Some(_) = rx_conn.conn.local_error() {
        &ConnectionError {
            is_app: false,
            error_code: 0,
            reason: b"proxy error".to_vec(),
        }
    } else {
        return false // not closed
    };

    match tx_conn.conn.close(err.is_app, err.error_code, &err.reason) {
        Ok(()) => {}
        Err(quiche::Error::Done) => return true, // already closed
        Err(e) => panic!("proxy conn {} unexpected error: {}", proxy_conn_id, e),
    }

    info!(
        "proxy conn {} forward {} to {}",
        proxy_conn_id,
        fmt(|f| f.debug_struct("ConnectionError")
            .field("is_app", &err.is_app)
            .field("error_code", &err.error_code)
            .field("reason", &from_utf8(&err.reason).unwrap_or("<invalid UTF-8>"))
            .finish()),
        if rx_conn.conn.is_server() {
            "server"
        } else {
            "client"
        }
    );

    true
}

/// forward stream data between two connections;
/// also forwards STOP_SENDING frames;
fn forward_stream(rx_conn: &mut quiche::Connection, tx_conn: &mut quiche::Connection, stream_id: u64, proxy_conn_id: usize, buf: &mut [u8]) {
    debug_assert_ne!(rx_conn.is_server(), tx_conn.is_server());
    if !tx_conn.is_established() && !tx_conn.is_in_early_data() {
        return; // not ready yet
    }
    match tx_conn.stream_send(stream_id, &[], false) { // create if not exist
        Ok(_) => {}
        Err(quiche::Error::Done) => {}
        Err(quiche::Error::StreamStopped(err_code)) => {
            rx_conn.stream_shutdown(stream_id, Shutdown::Read, err_code).unwrap();
            info!("proxy conn {} stream {} forward STOP_SENDING ({})", proxy_conn_id, stream_id, err_code);
            return;
        }
        Err(quiche::Error::StreamLimit) => return, // not ready yet
        Err(e) => panic!("{}", e),
    }
    let start_cap = match tx_conn.stream_capacity(stream_id) {
        Ok(v) => v,
        Err(quiche::Error::InvalidStreamState(_)) => return, // sometimes streams are still readable after fin
        Err(e) => panic!("unexpected error: {}", e),
    };
    let mut total_written = 0;
    let mut fin = false;

    loop {
        let cap = start_cap - total_written;
        if cap == 0 {
            break; // no sent capacity available on that stream, must wait until flow or congestion window becomes available
        }
        let buf = if cap >= buf.len() {
            &mut buf[..]
        } else {
            &mut buf[..cap]
        };
        let received;
        (received, fin) = match rx_conn.stream_recv(stream_id, buf) {
            Ok(v) => v,
            Err(quiche::Error::Done) => (0, false),
            Err(e) => panic!("recv error: {:?}", e),
        };
        if received == 0 && !fin {
            break;
        }
        let buf = &mut buf[..received];

        let written = tx_conn.stream_send(stream_id, &buf, fin).unwrap();
        total_written += written;
        if fin {
            break;
        }
    }
    if total_written == 0 && !fin {
        return;
    }
    trace!(
        "proxy conn {} stream {} forward to {} {} B (fin: {}) ",
        proxy_conn_id,
        stream_id,
        if rx_conn.is_server() {
            "server"
        } else {
            "client"
        },
        total_written,
        fin
    );
}

struct AppData {
    proxy_conns: Slab<ProxyConn>,
    args: Args,
    buf: [u8; 1 << 16],
    /// it is only optional to temporary take it
    server_facing_config: Option<quiche::Config>,
}

struct HalfOpenProxyConn {
    server_name: String,
    client_side_conn_id: usize,
}

impl HalfOpenProxyConn {
    /// upgrade to a full connection once the associated server-side connection id is known
    fn with_server(self, server_side_conn_id: usize) -> ProxyConn {
        ProxyConn {
            server_name: self.server_name,
            client_side_conn_id: self.client_side_conn_id,
            server_side_conn_id,
            closed: false,
        }
    }
}

#[derive(Debug)]
struct ProxyConn {
    server_name: String,
    client_side_conn_id: usize,
    server_side_conn_id: usize,
    /// mark proxy conn as closed.
    /// will be removed from list in next iteration.
    closed: bool,
}

#[derive(Debug)]
struct ConnAppData {
    proxy_conn_id: Option<usize>,
}

impl Default for ConnAppData {
    fn default() -> Self {
        Self {
            proxy_conn_id: None,
        }
    }
}

/// helper for formating outputs
/// example: `println!("{}", fmt(|f| f.debug_struct("Test").finish()))`
fn fmt<F>(f: F) -> impl Display
where
    F: Fn(&mut Formatter<'_>) -> std::fmt::Result,
{
    struct A<F> {
        f: F,
    }
    impl<F> Display for A<F>
    where
        F: Fn(&mut Formatter<'_>) -> std::fmt::Result,
    {
        fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
            (self.f)(fmt)
        }
    }
    A {
        f,
    }
}