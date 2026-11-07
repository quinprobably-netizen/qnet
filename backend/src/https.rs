//! Minimal HTTPS client for one self-signed server (the Pi-hole).
//!
//! Trust is a SHA-256 pin of the leaf certificate: the handshake is accepted
//! only when the server's leaf certificate hashes to the configured value.
//! There is no chain building, no name check and no clock check; the pin
//! replaces all of them. Handshake signatures are still verified with the
//! certificate's key, so the peer must hold the pinned certificate's private
//! key.
//!
//! The client speaks just enough HTTP/1.1: Content-Length and chunked
//! bodies, response bodies capped, one deadline over the whole request.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError,
    SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};

pub const MAX_BODY: usize = 256 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// TCP connect failed or timed out.
    Connect(String),
    /// The overall deadline expired.
    Timeout,
    /// The certificate did not match the pin (carries the fingerprint seen).
    PinMismatch(String),
    /// Any other TLS failure.
    Tls(String),
    /// The response (or its declared length) exceeded the cap.
    TooLarge,
    /// The peer spoke something other than the HTTP subset we accept.
    Protocol(String),
    Io(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Connect(e) => write!(f, "connect: {e}"),
            HttpError::Timeout => write!(f, "timed out"),
            HttpError::PinMismatch(got) => {
                write!(f, "certificate does not match the pinned fingerprint (saw {got})")
            }
            HttpError::Tls(e) => write!(f, "TLS: {e}"),
            HttpError::TooLarge => write!(f, "response too large"),
            HttpError::Protocol(e) => write!(f, "protocol: {e}"),
            HttpError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HttpError {}

fn map_io(e: io::Error) -> HttpError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => HttpError::Timeout,
        _ => HttpError::Io(e.to_string()),
    }
}

/// Certificate verifier that implements the pin.
#[derive(Debug)]
pub struct PinVerifier {
    /// `None` accepts any certificate (used only to read a fingerprint for
    /// the user to confirm during setup).
    pin: Option<[u8; 32]>,
    algs: WebPkiSupportedAlgorithms,
    mismatch: AtomicBool,
    seen: Mutex<Option<[u8; 32]>>,
}

impl PinVerifier {
    pub fn new(pin: Option<[u8; 32]>) -> Self {
        Self {
            pin,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            mismatch: AtomicBool::new(false),
            seen: Mutex::new(None),
        }
    }

    pub fn mismatched(&self) -> bool {
        self.mismatch.load(Ordering::SeqCst)
    }

    pub fn seen(&self) -> Option<[u8; 32]> {
        self.seen.lock().ok().and_then(|g| *g)
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn leaf_sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = leaf_sha256(end_entity.as_ref());
        if let Ok(mut g) = self.seen.lock() {
            *g = Some(digest);
        }
        match &self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(pin) if constant_time_eq(pin, &digest) => Ok(ServerCertVerified::assertion()),
            Some(_) => {
                self.mismatch.store(true, Ordering::SeqCst);
                Err(TlsError::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn client_config(verifier: Arc<PinVerifier>) -> Result<Arc<ClientConfig>, HttpError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// A stream whose every operation honours one absolute deadline.
struct DeadlineStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
    deadline: Instant,
}

impl DeadlineStream {
    fn arm(&self) -> io::Result<()> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline"))?;
        self.inner.sock.set_read_timeout(Some(left))?;
        self.inner.sock.set_write_timeout(Some(left))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.inner.flush()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct Head {
    status: u16,
    http10: bool,
    content_length: Option<u64>,
    chunked: bool,
    close: bool,
}

fn read_line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<String, HttpError> {
    let mut line = Vec::new();
    loop {
        let (done, used) = {
            let buf = r.fill_buf().map_err(map_io)?;
            if buf.is_empty() {
                return Err(HttpError::Protocol("connection closed in headers".into()));
            }
            match buf.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&buf[..=i]);
                    (true, i + 1)
                }
                None => {
                    line.extend_from_slice(buf);
                    (false, buf.len())
                }
            }
        };
        r.consume(used);
        if line.len() > *budget {
            return Err(HttpError::Protocol("header section too large".into()));
        }
        if done {
            break;
        }
    }
    *budget -= line.len();
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| HttpError::Protocol("non-UTF-8 header".into()))
}

fn read_head<R: BufRead>(r: &mut R) -> Result<Head, HttpError> {
    let mut budget = MAX_HEAD;
    let status_line = read_line(r, &mut budget)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Protocol(format!("bad status line {status_line:?}")));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpError::Protocol("bad status code".into()))?;
    let mut head = Head {
        status,
        http10: version == "HTTP/1.0",
        content_length: None,
        chunked: false,
        close: false,
    };
    loop {
        let line = read_line(r, &mut budget)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::Protocol("malformed header".into()));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                head.content_length = Some(
                    value
                        .parse()
                        .map_err(|_| HttpError::Protocol("bad content-length".into()))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                head.chunked = true;
            }
            "connection" if value.to_ascii_lowercase().contains("close") => {
                head.close = true;
            }
            _ => {}
        }
    }
    Ok(head)
}

fn read_exact_capped<R: Read>(r: &mut R, n: usize, out: &mut Vec<u8>) -> Result<(), HttpError> {
    let start = out.len();
    out.resize(start + n, 0);
    r.read_exact(&mut out[start..]).map_err(map_io)
}

fn read_chunked<R: BufRead>(r: &mut R, cap: usize) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    loop {
        let mut budget = 1024;
        let line = read_line(r, &mut budget)?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| HttpError::Protocol("bad chunk size".into()))?;
        if size == 0 {
            // Trailers until the blank line.
            let mut budget = MAX_HEAD;
            while !read_line(r, &mut budget)?.is_empty() {}
            return Ok(body);
        }
        if size > cap || body.len() + size > cap {
            return Err(HttpError::TooLarge);
        }
        read_exact_capped(r, size, &mut body)?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf).map_err(map_io)?;
        if &crlf != b"\r\n" {
            return Err(HttpError::Protocol("bad chunk terminator".into()));
        }
    }
}

/// Read one response. Returns it and whether the connection may be reused.
fn read_response<R: BufRead>(
    r: &mut R,
    head_request: bool,
    cap: usize,
) -> Result<(Response, bool), HttpError> {
    let head = read_head(r)?;
    let no_body = head_request || head.status == 204 || head.status == 304 || head.status / 100 == 1;
    let mut reusable = !head.close && !head.http10;
    let body = if no_body {
        Vec::new()
    } else if head.chunked {
        read_chunked(r, cap)?
    } else if let Some(n) = head.content_length {
        if n > cap as u64 {
            return Err(HttpError::TooLarge);
        }
        let mut body = Vec::with_capacity(n as usize);
        read_exact_capped(r, n as usize, &mut body)?;
        body
    } else {
        // Delimited by connection close.
        reusable = false;
        let mut body = Vec::new();
        let mut limited = r.take(cap as u64 + 1);
        match limited.read_to_end(&mut body) {
            Ok(_) => {}
            // Servers often close without a TLS close_notify.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(map_io(e)),
        }
        if body.len() > cap {
            return Err(HttpError::TooLarge);
        }
        body
    };
    Ok((
        Response {
            status: head.status,
            body,
        },
        reusable,
    ))
}

fn header_safe(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn path_safe(s: &str) -> bool {
    s.starts_with('/') && !s.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

struct Conn {
    rd: BufReader<DeadlineStream>,
}

pub struct HttpsClient {
    addr: SocketAddr,
    verifier: Arc<PinVerifier>,
    config: Arc<ClientConfig>,
    timeout: Duration,
    max_body: usize,
    idle: Option<Conn>,
}

impl HttpsClient {
    pub fn new(addr: SocketAddr, pin: Option<[u8; 32]>) -> Result<Self, HttpError> {
        let verifier = Arc::new(PinVerifier::new(pin));
        let config = client_config(verifier.clone())?;
        Ok(Self {
            addr,
            verifier,
            config,
            timeout: REQUEST_TIMEOUT,
            max_body: MAX_BODY,
            idle: None,
        })
    }

    #[cfg(test)]
    pub fn with_limits(mut self, timeout: Duration, max_body: usize) -> Self {
        self.timeout = timeout;
        self.max_body = max_body;
        self
    }

    /// Drop any kept-alive connection.
    pub fn close(&mut self) {
        self.idle = None;
    }

    fn connect(&self, deadline: Instant) -> Result<Conn, HttpError> {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(HttpError::Timeout)?;
        let sock = TcpStream::connect_timeout(&self.addr, left).map_err(|e| {
            if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
                HttpError::Timeout
            } else {
                HttpError::Connect(e.to_string())
            }
        })?;
        let _ = sock.set_nodelay(true);
        let name = ServerName::IpAddress(self.addr.ip().into());
        let tls = ClientConnection::new(self.config.clone(), name)
            .map_err(|e| HttpError::Tls(e.to_string()))?;
        Ok(Conn {
            rd: BufReader::new(DeadlineStream {
                inner: StreamOwned::new(tls, sock),
                deadline,
            }),
        })
    }

    fn classify(&self, e: HttpError) -> HttpError {
        if self.verifier.mismatched() {
            let got = self
                .verifier
                .seen()
                .map(|d| crate::util::format_fingerprint(&d))
                .unwrap_or_default();
            return HttpError::PinMismatch(got);
        }
        match e {
            HttpError::Io(m) if m.to_lowercase().contains("certificate") || m.contains("tls") => {
                HttpError::Tls(m)
            }
            other => other,
        }
    }

    fn exchange(
        &self,
        conn: &mut Conn,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        keep_alive: bool,
    ) -> Result<(Response, bool), HttpError> {
        let host = match self.addr.ip() {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => format!("[{a}]"),
        };
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: qnet\r\nAccept: application/json\r\n"
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        req.push_str(if keep_alive {
            "Connection: keep-alive\r\n\r\n"
        } else {
            "Connection: close\r\n\r\n"
        });
        let w = conn.rd.get_mut();
        w.write_all(req.as_bytes()).map_err(map_io)?;
        if let Some(b) = body {
            w.write_all(b).map_err(map_io)?;
        }
        w.flush().map_err(map_io)?;
        read_response(&mut conn.rd, method == "HEAD", self.max_body)
    }

    /// Send one request. GETs reuse a kept-alive connection when there is
    /// one (and retry once on a fresh connection if the old one is dead);
    /// everything else uses a fresh `Connection: close` connection.
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        if !path_safe(path) || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(HttpError::Protocol("invalid request line".into()));
        }
        for (k, v) in headers {
            if !header_safe(k) || !header_safe(v) || k.contains(':') {
                return Err(HttpError::Protocol("invalid header".into()));
            }
        }
        let idempotent = method == "GET";
        let deadline = Instant::now() + self.timeout;
        if !idempotent {
            // Free the kept-alive connection before opening another.
            self.idle = None;
        }

        if idempotent {
            if let Some(mut conn) = self.idle.take() {
                conn.rd.get_mut().deadline = deadline;
                if let Ok((resp, reusable)) =
                    self.exchange(&mut conn, method, path, headers, body, true)
                {
                    if reusable {
                        self.idle = Some(conn);
                    }
                    return Ok(resp);
                }
                // Stale connection: fall through to a fresh one.
            }
        }

        let mut conn = self.connect(deadline)?;
        let res = self.exchange(&mut conn, method, path, headers, body, idempotent);
        match res {
            Ok((resp, reusable)) => {
                if idempotent && reusable {
                    self.idle = Some(conn);
                }
                Ok(resp)
            }
            Err(e) => Err(self.classify(e)),
        }
    }
}

/// Complete a TLS handshake against `addr` accepting any certificate and
/// return the SHA-256 of the leaf. For the trust-on-first-use prompt only:
/// nothing is sent over the connection.
pub fn fetch_fingerprint(addr: SocketAddr, timeout: Duration) -> Result<[u8; 32], HttpError> {
    let verifier = Arc::new(PinVerifier::new(None));
    let config = client_config(verifier.clone())?;
    let deadline = Instant::now() + timeout;
    let sock = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| HttpError::Connect(e.to_string()))?;
    let conn = ClientConnection::new(config, ServerName::IpAddress(addr.ip().into()))
        .map_err(|e| HttpError::Tls(e.to_string()))?;
    let mut stream = DeadlineStream {
        inner: StreamOwned::new(conn, sock),
        deadline,
    };
    while stream.inner.conn.is_handshaking() {
        stream.arm().map_err(map_io)?;
        let StreamOwned { conn, sock } = &mut stream.inner;
        conn.complete_io(sock)
            .map_err(|e| HttpError::Tls(e.to_string()))?;
    }
    verifier
        .seen()
        .ok_or_else(|| HttpError::Tls("no certificate presented".into()))
}

#[cfg(test)]
pub mod testutil {
    //! A throwaway TLS server for tests.
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::ServerConfig;
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    pub struct TestServer {
        pub addr: SocketAddr,
        pub fingerprint: [u8; 32],
        pub handle: JoinHandle<()>,
    }

    pub fn self_signed() -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["pi.hole".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
    }

    /// Accept `conns` connections; for each, read the request head (and body
    /// if Content-Length is present) and answer with `respond(request_text)`
    /// raw bytes. `respond` may return None to hang up without answering.
    pub fn serve<F>(conns: usize, respond: F) -> TestServer
    where
        F: Fn(usize, &str) -> Option<Vec<u8>> + Send + 'static,
    {
        let (cert, key) = self_signed();
        let fingerprint = leaf_sha256(&cert);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        let cfg = Arc::new(cfg);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for n in 0..conns {
                let Ok((sock, _)) = listener.accept() else { return };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, sock);
                // Serve requests until the client hangs up.
                let mut served = 0usize;
                loop {
                    let mut reader = BufReader::new(&mut tls);
                    let mut text = String::new();
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => {
                                text.clear();
                                break;
                            }
                            Ok(_) => {}
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                        let end = line == "\r\n";
                        text.push_str(&line);
                        if end {
                            break;
                        }
                    }
                    if text.is_empty() {
                        break;
                    }
                    let mut body = vec![0u8; content_len];
                    if content_len > 0 && reader.read_exact(&mut body).is_err() {
                        break;
                    }
                    text.push_str(&String::from_utf8_lossy(&body));
                    drop(reader);
                    match respond(n * 100 + served, &text) {
                        Some(bytes) => {
                            if tls.write_all(&bytes).is_err() || tls.flush().is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                    served += 1;
                    if text.contains("Connection: close") {
                        break;
                    }
                }
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        TestServer {
            addr,
            fingerprint,
            handle,
        }
    }

    pub fn ok_json(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use std::io::Cursor;

    fn der_of_self_signed() -> Vec<u8> {
        self_signed().0
    }

    #[test]
    fn verifier_accepts_matching_leaf_only() {
        let der = der_of_self_signed();
        let pin = leaf_sha256(&der);
        let v = PinVerifier::new(Some(pin));
        let name = ServerName::try_from("pi.hole").unwrap();
        let cert = CertificateDer::from(der.clone());
        assert!(v
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_ok());
        assert!(!v.mismatched());

        // A different certificate must be rejected, and flagged.
        let other = CertificateDer::from(der_of_self_signed());
        let err = v
            .verify_server_cert(&other, &[], &name, &[], UnixTime::now())
            .unwrap_err();
        assert!(matches!(
            err,
            TlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
        assert!(v.mismatched());
        assert_eq!(v.seen(), Some(leaf_sha256(other.as_ref())));
    }

    #[test]
    fn verifier_one_bit_off_is_rejected() {
        let der = der_of_self_signed();
        let mut pin = leaf_sha256(&der);
        pin[31] ^= 1;
        let v = PinVerifier::new(Some(pin));
        let name = ServerName::try_from("pi.hole").unwrap();
        assert!(v
            .verify_server_cert(&CertificateDer::from(der), &[], &name, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn verifier_ignores_intermediates_and_name() {
        // A chain whose leaf matches is accepted whatever the name; a chain
        // with a matching intermediate but a different leaf is not.
        let leaf = der_of_self_signed();
        let inter = der_of_self_signed();
        let v = PinVerifier::new(Some(leaf_sha256(&inter)));
        let name = ServerName::try_from("not-the-name.example").unwrap();
        assert!(v
            .verify_server_cert(
                &CertificateDer::from(leaf),
                &[CertificateDer::from(inter)],
                &name,
                &[],
                UnixTime::now()
            )
            .is_err());
    }

    #[test]
    fn https_get_with_correct_pin() {
        let srv = serve(1, |_, req| {
            assert!(req.starts_with("GET /api/ping HTTP/1.1\r\n"), "{req}");
            assert!(req.contains("X-FTL-SID: abc"));
            Some(ok_json(r#"{"ok":true}"#))
        });
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint)).unwrap();
        let r = c.request("GET", "/api/ping", &[("X-FTL-SID", "abc")], None).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, br#"{"ok":true}"#);
        c.close();
        srv.handle.join().unwrap();
    }

    #[test]
    fn https_rejects_wrong_pin() {
        let srv = serve(1, |_, _| Some(ok_json("{}")));
        let mut wrong = srv.fingerprint;
        wrong[0] ^= 0xFF;
        let mut c = HttpsClient::new(srv.addr, Some(wrong)).unwrap();
        let err = c.request("GET", "/x", &[], None).unwrap_err();
        match err {
            HttpError::PinMismatch(got) => {
                assert_eq!(got, crate::util::format_fingerprint(&srv.fingerprint))
            }
            other => panic!("expected PinMismatch, got {other:?}"),
        }
        srv.handle.join().unwrap();
    }

    #[test]
    fn fetch_fingerprint_reads_leaf() {
        let srv = serve(1, |_, _| Some(ok_json("{}")));
        let fp = fetch_fingerprint(srv.addr, Duration::from_secs(3)).unwrap();
        assert_eq!(fp, srv.fingerprint);
        let _ = srv.handle.join();
    }

    #[test]
    fn https_keepalive_reuses_connection_for_gets() {
        // One accepted connection serves two GETs.
        let srv = serve(1, |i, _| Some(ok_json(&format!("{{\"n\":{i}}}"))));
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint)).unwrap();
        let a = c.request("GET", "/a", &[], None).unwrap();
        let b = c.request("GET", "/b", &[], None).unwrap();
        assert_eq!(a.body, br#"{"n":0}"#);
        assert_eq!(b.body, br#"{"n":1}"#);
        c.close();
        srv.handle.join().unwrap();
    }

    #[test]
    fn https_post_sends_body_and_closes() {
        let srv = serve(1, |_, req| {
            assert!(req.starts_with("POST /api/auth HTTP/1.1\r\n"));
            assert!(req.contains("Connection: close"));
            assert!(req.ends_with(r#"{"password":"x"}"#));
            Some(ok_json(r#"{"session":{}}"#))
        });
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint)).unwrap();
        let r = c
            .request("POST", "/api/auth", &[], Some(br#"{"password":"x"}"#))
            .unwrap();
        assert_eq!(r.status, 200);
        srv.handle.join().unwrap();
    }

    #[test]
    fn https_body_cap_enforced_by_header_and_by_stream() {
        // Declared length too large.
        let srv = serve(1, |_, _| {
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\nx".to_vec())
        });
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint))
            .unwrap()
            .with_limits(Duration::from_secs(3), 1024);
        assert_eq!(c.request("GET", "/", &[], None), Err(HttpError::TooLarge));
        drop(srv);

        // Close-delimited body longer than the cap.
        let srv = serve(1, |_, _| {
            let mut v = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
            v.extend(std::iter::repeat_n(b'a', 5000));
            Some(v)
        });
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint))
            .unwrap()
            .with_limits(Duration::from_secs(3), 1024);
        assert_eq!(c.request("GET", "/", &[], None), Err(HttpError::TooLarge));
    }

    #[test]
    fn https_times_out_on_silent_server() {
        let srv = serve(1, |_, _| {
            std::thread::sleep(Duration::from_millis(1500));
            None
        });
        let mut c = HttpsClient::new(srv.addr, Some(srv.fingerprint))
            .unwrap()
            .with_limits(Duration::from_millis(300), 1024);
        let t0 = Instant::now();
        assert_eq!(c.request("GET", "/", &[], None), Err(HttpError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(1200));
    }

    #[test]
    fn https_connect_refused_is_connect_error() {
        // Bind then drop to get a closed port.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let mut c = HttpsClient::new(addr, Some([0; 32])).unwrap();
        assert!(matches!(
            c.request("GET", "/", &[], None),
            Err(HttpError::Connect(_))
        ));
    }

    #[test]
    fn rejects_header_injection() {
        let mut c = HttpsClient::new("127.0.0.1:9".parse().unwrap(), Some([0; 32])).unwrap();
        assert!(matches!(
            c.request("GET", "/ok", &[("X-FTL-SID", "a\r\nX-Evil: 1")], None),
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            c.request("GET", "/ok HTTP/1.1\r\nX: y", &[], None),
            Err(HttpError::Protocol(_))
        ));
    }

    // Framing, without TLS.

    #[test]
    fn parses_content_length_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        let (resp, reusable) = read_response(&mut r, false, 100).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
        assert!(reusable);
    }

    #[test]
    fn parses_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        let (resp, reusable) = read_response(&mut r, false, 100).unwrap();
        assert_eq!(resp.body, b"hello world");
        assert!(reusable);
    }

    #[test]
    fn chunked_cap_and_garbage() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        assert_eq!(read_response(&mut r, false, 16).unwrap_err(), HttpError::TooLarge);

        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        assert!(matches!(
            read_response(&mut r, false, 100).unwrap_err(),
            HttpError::Protocol(_)
        ));

        let raw = b"SMTP/1.0 220 hi\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        assert!(matches!(
            read_response(&mut r, false, 100).unwrap_err(),
            HttpError::Protocol(_)
        ));
    }

    #[test]
    fn no_body_statuses_and_close_delimited() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        let (resp, _) = read_response(&mut r, false, 100).unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());

        let raw = b"HTTP/1.0 200 OK\r\n\r\nabc";
        let mut r = BufReader::new(Cursor::new(&raw[..]));
        let (resp, reusable) = read_response(&mut r, false, 100).unwrap();
        assert_eq!(resp.body, b"abc");
        assert!(!reusable);
    }

    #[test]
    fn oversized_headers_rejected() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD + 10));
        raw.extend_from_slice(b"\r\n\r\n");
        let mut r = BufReader::new(Cursor::new(raw));
        assert!(matches!(
            read_response(&mut r, false, 100).unwrap_err(),
            HttpError::Protocol(_)
        ));
    }
}
