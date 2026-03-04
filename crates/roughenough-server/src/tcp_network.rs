use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;

use mio::net::{TcpListener, TcpStream};
use mio::{Interest, Poll, Token};
use roughenough_protocol::request::REQUEST_SIZE;
use tracing::{debug, trace, warn};

use crate::metrics::types::NetworkMetrics;

/// Token offset for TCP client connections. The TCP listener uses token 1,
/// and client connections start at token offset 1000.
const CLIENT_TOKEN_OFFSET: usize = 1000;

/// State of a single TCP client connection.
struct TcpClient {
    stream: TcpStream,
    addr: SocketAddr,
    buf: [u8; REQUEST_SIZE],
    bytes_read: usize,
}

/// Handles TCP connections for the Roughtime server.
///
/// Each TCP connection carries exactly one request-response exchange:
/// the client sends a 1024-byte framed request, the server sends back
/// the framed response, then the connection is closed.
pub struct TcpNetworkHandler {
    next_token_id: usize,
    clients: HashMap<usize, TcpClient>,
    metrics: NetworkMetrics,
}

impl Default for TcpNetworkHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpNetworkHandler {
    pub fn new() -> Self {
        Self {
            next_token_id: CLIENT_TOKEN_OFFSET,
            clients: HashMap::new(),
            metrics: NetworkMetrics::default(),
        }
    }

    /// Accept all pending connections from the TCP listener and register them
    /// with the poll instance for readable events.
    pub fn accept_connections(&mut self, listener: &TcpListener, poll: &Poll) {
        loop {
            match listener.accept() {
                Ok((stream, addr)) => {
                    let token_id = self.next_token_id;
                    self.next_token_id += 1;

                    let mut client = TcpClient {
                        stream,
                        addr,
                        buf: [0u8; REQUEST_SIZE],
                        bytes_read: 0,
                    };

                    if let Err(e) = poll.registry().register(
                        &mut client.stream,
                        Token(token_id),
                        Interest::READABLE,
                    ) {
                        warn!("failed to register TCP client {addr}: {e}");
                        continue;
                    }

                    debug!("accepted TCP connection from {addr}, token={token_id}");
                    self.clients.insert(token_id, client);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!("TCP accept error: {e}");
                    break;
                }
            }
        }
    }

    /// Try to read a complete request from the connection identified by `token_id`.
    /// Returns `Some((request_bytes, addr))` when a full 1024-byte request has been
    /// received, or `None` if more data is needed or the connection errored.
    pub fn try_read_request(
        &mut self,
        token_id: usize,
        poll: &Poll,
    ) -> Option<([u8; REQUEST_SIZE], SocketAddr)> {
        let client = self.clients.get_mut(&token_id)?;

        loop {
            let remaining = REQUEST_SIZE - client.bytes_read;
            if remaining == 0 {
                break;
            }

            let start = client.bytes_read;
            match client.stream.read(&mut client.buf[start..]) {
                Ok(0) => {
                    // Connection closed before full request received
                    trace!(
                        "TCP client {} closed early ({} bytes)",
                        client.addr, client.bytes_read
                    );
                    self.remove_client(token_id, poll);
                    return None;
                }
                Ok(n) => {
                    client.bytes_read += n;
                    trace!(
                        "TCP read {} bytes from {} (total: {})",
                        n, client.addr, client.bytes_read
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Not enough data yet
                    return None;
                }
                Err(e) => {
                    warn!("TCP read error from {}: {e}", client.addr);
                    self.remove_client(token_id, poll);
                    return None;
                }
            }
        }

        // Full request received
        let client = self.clients.get(&token_id).unwrap();
        let buf = client.buf;
        let addr = client.addr;

        Some((buf, addr))
    }

    /// Send a response back on the TCP connection and close it.
    pub fn send_response(&mut self, token_id: usize, data: &[u8], poll: &Poll) {
        if let Some(client) = self.clients.get_mut(&token_id) {
            match client.stream.write_all(data) {
                Ok(()) => {
                    debug!("sent {} byte TCP response to {}", data.len(), client.addr);
                    self.metrics.num_successful_sends += 1;
                }
                Err(e) => {
                    warn!("TCP write error to {}: {e}", client.addr);
                    self.metrics.num_failed_sends += 1;
                }
            }
        }
        self.remove_client(token_id, poll);
    }

    /// Check if a token ID belongs to a TCP client connection.
    pub fn is_tcp_client(&self, token_id: usize) -> bool {
        self.clients.contains_key(&token_id)
    }

    fn remove_client(&mut self, token_id: usize, poll: &Poll) {
        if let Some(mut client) = self.clients.remove(&token_id) {
            let _ = poll.registry().deregister(&mut client.stream);
        }
    }

    pub fn metrics(&self) -> NetworkMetrics {
        self.metrics
    }

    pub fn reset_metrics(&mut self) {
        self.metrics = NetworkMetrics::default();
    }
}
