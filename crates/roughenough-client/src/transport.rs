//! Abstraction for network transport mechanisms used by clients.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use roughenough_protocol::wire::{FRAME_OVERHEAD, MINIMUM_FRAME_SIZE};
use tracing::{debug, trace};

use crate::ClientError;

/// Abstraction for network transport mechanisms used by clients.
/// Allows clients to work with different protocols (UDP, TCP, etc.) through a common interface.
pub trait ClientTransport {
    /// Sends data to the specified network address.
    /// Returns the number of bytes sent or an error if the operation fails.
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError>;

    /// Receives data from any network address.
    /// Returns the number of bytes received and the sender's address, or an error on failure.
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError>;
}

/// UDP implementation of ClientTransport.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn new(timeout: Duration) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(timeout)).unwrap();
        socket.set_write_timeout(Some(timeout)).unwrap();

        Self { socket }
    }
}

impl ClientTransport for UdpTransport {
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError> {
        debug!("sending {} bytes to {}", data.len(), addr);
        trace_dump(data)?;
        Ok(self.socket.send_to(data, addr)?)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
        match self.socket.recv_from(buf) {
            Ok((nbytes, addr)) => {
                debug!("received {} bytes from {}", nbytes, addr);
                trace_dump(&buf[..nbytes])?;
                Ok((nbytes, addr))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    Err(ClientError::ServerTimeout)
                } else {
                    Err(ClientError::IoError(e))
                }
            }
        }
    }
}

/// Plain TCP transport. Connects to the server, sends the request, reads the
/// framed response, then the connection is dropped.
pub struct TcpTransport {
    timeout: Duration,
}

impl TcpTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl ClientTransport for TcpTransport {
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError> {
        debug!("TCP: connecting to {addr}");
        let stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // Store the connected stream for recv() to use. This is a
        // single-threaded request-response exchange so thread_local is fine.
        TCP_STREAM.with(|cell| {
            *cell.borrow_mut() = Some(StreamState { stream, addr });
        });

        debug!("TCP: sending {} bytes to {addr}", data.len());
        trace_dump(data)?;

        TCP_STREAM.with(|cell| {
            let mut state = cell.borrow_mut();
            let s = state.as_mut().expect("stream must be connected");
            s.stream.write_all(data)?;
            Ok(data.len())
        })
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
        TCP_STREAM.with(|cell| {
            let mut state = cell.borrow_mut();
            let s = state.as_mut().expect("stream must be connected");

            let nbytes = read_framed_response(&mut s.stream, buf)?;
            let addr = s.addr;

            debug!("TCP: received {nbytes} bytes from {addr}");
            trace_dump(&buf[..nbytes])?;

            Ok((nbytes, addr))
        })
    }
}

struct StreamState {
    stream: TcpStream,
    addr: SocketAddr,
}

thread_local! {
    static TCP_STREAM: RefCell<Option<StreamState>> = const { RefCell::new(None) };
}

/// TLS over TCP transport. Uses rustls with OS root certificates for verification.
#[cfg(feature = "tls")]
pub struct TlsTcpTransport {
    timeout: Duration,
    hostname: String,
    verify: bool,
}

#[cfg(feature = "tls")]
impl TlsTcpTransport {
    pub fn new(timeout: Duration, hostname: &str) -> Self {
        Self {
            timeout,
            hostname: hostname.to_string(),
            verify: true,
        }
    }

    pub fn no_verify(mut self) -> Self {
        self.verify = false;
        self
    }
}

#[cfg(feature = "tls")]
thread_local! {
    static TLS_STREAM: RefCell<Option<TlsStreamState>> = const { RefCell::new(None) };
}

#[cfg(feature = "tls")]
struct TlsStreamState {
    tls_stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    addr: SocketAddr,
}

#[cfg(feature = "tls")]
impl ClientTransport for TlsTcpTransport {
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError> {
        debug!("TLS: connecting to {addr} (SNI: {})", self.hostname);

        let tcp_stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        tcp_stream.set_read_timeout(Some(self.timeout))?;
        tcp_stream.set_write_timeout(Some(self.timeout))?;

        let tls_config = if self.verify {
            let native = rustls_native_certs::load_native_certs();
            for e in &native.errors {
                debug!("error loading OS root cert: {e}");
            }
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_parsable_certificates(native.certs);

            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            debug!("TLS: certificate verification DISABLED");
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
                .with_no_client_auth()
        };

        let server_name = rustls::pki_types::ServerName::try_from(self.hostname.as_str())
            .map_err(|e| {
                ClientError::InvalidConfiguration(format!("invalid TLS server name: {e}"))
            })?
            .to_owned();

        let tls_conn = rustls::ClientConnection::new(std::sync::Arc::new(tls_config), server_name)
            .map_err(|e| {
                ClientError::InvalidConfiguration(format!("TLS connection setup failed: {e}"))
            })?;

        let mut tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);

        debug!("TLS: sending {} bytes to {addr}", data.len());
        trace_dump(data)?;

        tls_stream.write_all(data)?;
        let len = data.len();

        TLS_STREAM.with(|cell| {
            *cell.borrow_mut() = Some(TlsStreamState { tls_stream, addr });
        });

        Ok(len)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
        TLS_STREAM.with(|cell| {
            let mut state = cell.borrow_mut();
            let s = state.as_mut().expect("TLS stream must be connected");

            let nbytes = read_framed_response(&mut s.tls_stream, buf)?;
            let addr = s.addr;

            debug!("TLS: received {nbytes} bytes from {addr}");
            trace_dump(&buf[..nbytes])?;

            Ok((nbytes, addr))
        })
    }
}

/// A rustls ServerCertVerifier that accepts any certificate without validation.
/// Used when the system clock is wrong (e.g., initial time sync) and certificate
/// expiry checks would fail.
#[cfg(feature = "tls")]
#[derive(Debug)]
struct NoVerify;

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Read a complete Roughtime framed response from a stream.
///
/// The frame format is: 8-byte magic + 4-byte LE length + payload.
/// Returns the total number of bytes read (header + payload).
fn read_framed_response(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, ClientError> {
    if buf.len() < FRAME_OVERHEAD + MINIMUM_FRAME_SIZE {
        return Err(ClientError::InvalidConfiguration(
            "receive buffer too small for framed response".to_string(),
        ));
    }

    // Read the 12-byte frame header
    reader.read_exact(&mut buf[..FRAME_OVERHEAD])?;

    // Extract payload length from bytes 8..12 (little-endian u32)
    let payload_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;

    let total = FRAME_OVERHEAD + payload_len;
    if total > buf.len() {
        return Err(ClientError::InvalidConfiguration(format!(
            "response frame too large: {total} bytes (buffer is {} bytes)",
            buf.len()
        )));
    }

    // Read the payload
    reader.read_exact(&mut buf[FRAME_OVERHEAD..total])?;

    Ok(total)
}

fn trace_dump(data: &[u8]) -> Result<(), ClientError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        let mut dump = Vec::new();
        roughenough_common::encoding::hexdump(data, &mut dump)?;
        trace!("\n{}", String::from_utf8_lossy(&dump));
    }
    Ok(())
}
