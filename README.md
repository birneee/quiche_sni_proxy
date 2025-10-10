# Quiche SNI Proxy

> ⚠️ Not production ready

> This project is not affiliated with [Cloudflare quiche](https://github.com/cloudflare/quiche)

A simple QUIC proxy, using the QUIC TLS SNI for mapping.
Client must accept the certificate provided by this proxy.
By default, the proxy is listening on port 4433 and forwards packets to 443 of the DNS resolved SNI IPv4.

## Build

With cargo:
```bash
cargo build --release
```

With nix:
```bash
nix build
```

## Run

> See [here](../../README.md#generate-certificate) how to generate a certificate

> If no keys are specified a key pair is generated, and the spki hash is logged to stdout

```bash
RUST_LOG=info ../../target/release/proxy --cert ../../cert.pem --key ../../key.pem
```

## Open in browser

```bash
SSLKEYLOGFILE=../../sslkeylog chromium 'https://example.com' \
  --user-data-dir=../../chromium-data \
  --origin-to-force-quic-on="*" \
  --ignore-certificate-errors-spki-list="<spki>" \
  --host-resolver-rules="MAP * 127.0.0.1:4433"
```
