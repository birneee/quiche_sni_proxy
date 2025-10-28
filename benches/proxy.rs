use boring::ssl::{SslContextBuilder, SslMethod};
use criterion::{criterion_group, criterion_main, Bencher, Criterion, Throughput};
use quiche_mio_runner::mio::unix::pipe::Receiver;
use quiche_mio_runner::quiche_endpoint::quiche::PROTOCOL_VERSION;
use quiche_mio_runner::quiche_endpoint::{quiche, Endpoint, EndpointConfig, ServerConfig};
use quiche_mio_runner::{mio, Config, Runner, Socket};
use quiche_sni_proxy::{load_or_generate_keys, run_proxy};
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));
    targets = targets
);
criterion_main!(benches);

fn targets(c: &mut Criterion) {
    env_logger::builder().format_timestamp_nanos().init();
    {
        let mut g = c.benchmark_group("request");
        let num_bytes = 1E9 as usize;
        g.throughput(Throughput::Bits(num_bytes as u64 * 8));
        g.bench_function("1G", |b| bench_transmit(b, num_bytes, false, false, false));
        g.bench_function("1G-gso-gro", |b| bench_transmit(b, num_bytes, true, true, false));
        g.bench_function("1G-proxy", |b| bench_transmit(b, num_bytes, false, false, true));
        g.bench_function("1G-gso-gro-proxy", |b| bench_transmit(b, num_bytes, true, true, true));
        g.finish();
    }
    {
        let mut g = c.benchmark_group("ping");
        g.throughput(Throughput::Elements(1));
        g.bench_function("1B", |b| bench_transmit(b, 1, false, false, false));
        g.bench_function("1B-proxy", |b| bench_transmit(b, 1, false, false, true));
        g.finish();
    }
}

fn bench_transmit(b: &mut Bencher, num_bytes: usize, gso: bool, gro: bool, proxy: bool) {
    b.iter_custom(|iters| {
        let mut duration = Duration::ZERO;
        for _ in 0..iters {
            duration += std::hint::black_box(transmit(num_bytes, gso, gro, proxy));
        }
        duration
    });
}

const PROTO: &[u8] = b"proto1";
const COPY_BUF_SIZE: usize = 1 << 16;
const MAX_DATA: u64 = 1_000_000;

struct ClientAppData {
    sent_req: bool,
    received_bytes: usize,
    receive_expected_bytes: usize,
    buf: [u8; COPY_BUF_SIZE],
    req_instant: Option<Instant>,
    done_instant: Option<Instant>,
}

impl ClientAppData {
    fn new(receive_expected_bytes: usize) -> Self {
        Self {
            sent_req: false,
            received_bytes: 0,
            receive_expected_bytes,
            buf: [0u8; COPY_BUF_SIZE],
            req_instant: None,
            done_instant: None,
        }
    }
}

fn run_client(num_bytes: usize, gso: bool, gro: bool, proxy: bool) -> Duration {
    let socket = Socket::bind("0.0.0.0:0".parse().unwrap(), !gro, false, !gso).unwrap();
    let local_addr = socket.local_addr;
    let peer_addr = if proxy {
        "127.0.0.1:4433".parse().unwrap()
    } else {
        "127.0.0.1:4434".parse().unwrap()
    };
    let mut r = Runner::new(
        {
            let mut c = Config::<(), ClientAppData, ()>::default();
            c.post_handle_recvs = |r| {
                let (conn, app_data) = r.endpoint.conn_with_app_data_mut(0);
                let conn = &mut conn.unwrap().conn;
                let buf = &mut app_data.buf;
                if !conn.is_established() {
                    return;
                }
                if !app_data.sent_req {
                    conn.stream_send(0, &buf[..0], true).unwrap();
                    app_data.sent_req = true;
                    app_data.req_instant = Some(Instant::now());
                }
                loop {
                    let (len, _fin) = match conn.stream_recv(0, buf) {
                        Ok(v) => v,
                        Err(quiche::Error::InvalidStreamState(_)) => break,
                        Err(quiche::Error::Done) => break,
                        Err(e) => panic!("{:?}", e),
                    };
                    app_data.received_bytes += len;
                    if app_data.received_bytes >= app_data.receive_expected_bytes {
                        app_data.done_instant = Some(Instant::now());
                        r.endpoint.remove_conn(0);
                        break
                    }
                }
            };
            c
        },
        {
            let mut e = Endpoint::new(
                None,
                {
                    let c = EndpointConfig::<(), ClientAppData>::default();
                    c
                },
                ClientAppData::new(num_bytes),
            );
            e.connect(
                Some("localhost"),
                local_addr,
                peer_addr,
                &mut {
                    let mut c = quiche::Config::new(PROTOCOL_VERSION).unwrap();
                    c.verify_peer(false);
                    c.set_application_protos(&[PROTO]).unwrap();
                    c.set_initial_max_data(MAX_DATA);
                    c.set_initial_max_stream_data_bidi_local(MAX_DATA);
                    c
                },
                (),
                None,
                None,
            );
            e
        },
        None,
    );
    r.register_socket(socket);
    r.run();
    let app_data = r.endpoint.app_data();
    app_data.done_instant.unwrap() - app_data.req_instant.unwrap()
}

struct ServerAppData {
    received_req: bool,
    buf: [u8; COPY_BUF_SIZE]
}

impl Default for ServerAppData {
    fn default() -> Self {
        Self {
            received_req: false,
            buf: [0u8; COPY_BUF_SIZE],
        }
    }
}

fn run_server(close_pipe_rx: &mut Receiver, gso: bool, gro: bool) {
    let (cert, key) = load_or_generate_keys(&None, &None);

    let socket = Socket::bind("0.0.0.0:4434".parse().unwrap(), !gro, false, !gso).unwrap();
    let mut r = Runner::new(
        {
            let mut c = Config::<ServerAppData, (), ()>::default();
            c.post_handle_recvs = |r| {
                let Some(conn) = r.endpoint.conn_mut(0) else { return; };
                let (conn, app_data) = (&mut conn.conn, &mut conn.app_data);
                let buf = &mut app_data.buf;
                if !conn.is_established() {
                    return;
                }
                if !app_data.received_req {
                    let (_len, fin) = match conn.stream_recv(0, buf) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            println!("server no req");
                            return;
                        },
                        Err(e) => panic!("{:?}", e)
                    };
                    if !fin {
                        return;
                    }
                    app_data.received_req = true;
                }
                loop {
                    match conn.stream_send(0, buf, false) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => break,
                        Err(e) => panic!("{:?}", e)
                    }
                }
            };
            c
        },
        {
            let e = Endpoint::<ServerAppData, ()>::new(
                Some({
                    let mut c = ServerConfig::<ServerAppData>::default();
                    c.client_config = {
                        let mut c = quiche::Config::with_boring_ssl_ctx_builder(
                            PROTOCOL_VERSION,
                            {
                                let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
                                b.set_private_key(&key).unwrap();
                                b.set_certificate(&cert).unwrap();
                                b
                            },
                        )
                        .unwrap();
                        c.set_application_protos(&[PROTO]).unwrap();
                        c.set_initial_max_streams_bidi(5);
                        c.set_initial_max_data(MAX_DATA);
                        c.set_initial_max_stream_data_bidi_remote(MAX_DATA);
                        c
                    };
                    c
                }),
                {
                    let c = EndpointConfig::default();
                    c
                },
                (),
            );

            e
        },
        Some(close_pipe_rx),
    );
    r.register_socket(socket);
    r.run();
}

fn transmit(num_bytes: usize, gso: bool, gro: bool, proxy: bool) -> Duration {
    let (mut close_server_pipe_tx, mut close_server_pipe_rx) = mio::unix::pipe::new().unwrap();
    let (mut close_proxy_pipe_tx, mut close_proxy_pipe_rx) = mio::unix::pipe::new().unwrap();
    let server_join_handle = thread::spawn(move || run_server(&mut close_server_pipe_rx, gso, gro));
    let proxy_join_handle = thread::spawn(move || {
        run_proxy(
            quiche_sni_proxy::Args {
                no_verify: true,
                disable_gro: !gro,
                disable_gso: !gso,
                cert: None,
                key: None,
                bind: "127.0.0.1:4433".parse().unwrap(),
                forward_port: 4434,
                alpn: str::from_utf8(PROTO).unwrap().to_string(),
            },
            Some(&mut close_proxy_pipe_rx),
        );
    });
    thread::sleep(Duration::from_millis(100));
    let client_join_handle = thread::spawn(move || run_client(num_bytes, gso, gro, proxy));
    let duration = client_join_handle.join().unwrap();
    close_server_pipe_tx.write(&[0]).unwrap();
    server_join_handle.join().unwrap();
    close_proxy_pipe_tx.write(&[0]).unwrap();
    proxy_join_handle.join().unwrap();
    duration
}
