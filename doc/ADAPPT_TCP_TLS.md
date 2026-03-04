# TCP and TLS Transport for Firewall Traversal

Roughenough supports TCP transport alongside its default UDP transport. This enables
traversing firewalls and corporate networks where UDP traffic is blocked but TCP/443
is allowed.

## Architecture

```
                        +------------------+
                        |  AWS NLB / ALB   |
  Client (TLS/TCP:443) |  TLS termination |  Server (plain TCP)
  --------------------->|  on port 443     |--------------------->
                        +------------------+
```

- **Server**: Listens on plain TCP (no TLS). AWS NLB/ALB handles TLS termination.
- **Client**: Connects via TLS over TCP using rustls with OS root certificates.

The Roughtime protocol's wire framing (8-byte ROUGHTIM magic + 4-byte LE length +
payload) works identically over TCP. Each TCP connection carries exactly one
request-response exchange and is then closed.

## Server Configuration

Enable TCP by adding `--tcp-port`:

```bash
# Listen on UDP:2003 (default) and TCP:443
roughenough_server --tcp-port 443

# Or via environment variable
ROUGHENOUGH_TCP_PORT=443 roughenough_server
```

The server binds TCP with `SO_REUSEPORT`, so all worker threads share the TCP port
just like they do for UDP. The kernel load-balances incoming TCP connections across
workers.

When `--tcp-port` is not specified, the server operates in UDP-only mode (no
behavior change from before this feature was added).

## Client Configuration

### Building with TLS support

TLS is an optional feature to avoid pulling in rustls for UDP-only use:

```bash
# Build with TLS support
cargo build -p roughenough-client --features tls

# Or build the whole workspace with TLS
cargo build --features roughenough-client/tls
```

### Transport options

```bash
# Default: UDP
roughenough_client roughtime.example.com 2003

# Plain TCP (no encryption, for direct server connections or testing)
roughenough_client roughtime.example.com 443 --tcp

# TLS over TCP (for production use behind TLS-terminating load balancers)
roughenough_client roughtime.example.com 443 --tls

# TLS without certificate verification (needed for initial time sync
# when the system clock is wrong and cert expiry checks would fail)
roughenough_client roughtime.example.com 443 --tls --tls-no-verify
```

### When to use --tls-no-verify

TLS certificate verification depends on the system clock being approximately correct
(certificates have validity windows). During initial time synchronization -- the exact
scenario where Roughtime is needed -- the system clock may be wildly wrong, causing
TLS handshakes to fail with certificate expiry errors.

Use `--tls-no-verify` for this bootstrap scenario. The Roughtime protocol itself
provides cryptographic authentication via the server's Ed25519 public key (`-k`
flag), so the TLS layer is only needed for firewall traversal, not for
authentication.

Typical bootstrap sequence:

```bash
# 1. Initial sync with TLS verification disabled but Roughtime auth enabled
roughenough_client roughtime.example.com 443 \
    --tls --tls-no-verify \
    -k AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE= \
    --set-clock

# 2. Subsequent syncs can use full TLS verification
roughenough_client roughtime.example.com 443 \
    --tls \
    -k AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=
```

## TLS Details

- **Library**: rustls (pure Rust, no OpenSSL dependency)
- **Root certificates**: Loaded from the OS certificate store via `rustls-native-certs`
  (reads from `/etc/ssl/certs/` on Linux)
- **SNI**: The hostname argument is used for TLS Server Name Indication
- **Feature flag**: `tls` on the `roughenough-client` crate

## Files

Server-side:
- `crates/roughenough-server/src/args.rs` - `--tcp-port` CLI argument
- `crates/roughenough-server/src/tcp_network.rs` - TCP connection handler
- `crates/roughenough-server/src/worker.rs` - Event loop handling UDP + TCP
- `crates/roughenough-server/src/main.rs` - TCP listener setup

Client-side:
- `crates/roughenough-client/src/args.rs` - `--tcp`, `--tls`, `--tls-no-verify` flags
- `crates/roughenough-client/src/transport.rs` - `TcpTransport` and `TlsTcpTransport`
- `crates/roughenough-client/src/main.rs` - Transport selection logic
