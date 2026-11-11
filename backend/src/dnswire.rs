//! A tiny DNS client: build an A query, parse the answer, and a UDP probe
//! that sends it straight to one server and measures the round trip.
//!
//! Only what the health probe needs. No TCP fallback, no EDNS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    BadName,
    Short,
    NotResponse,
    IdMismatch,
    QuestionMismatch,
    BadPointer,
    Io(String),
    Timeout,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::BadName => write!(f, "invalid DNS name"),
            DnsError::Short => write!(f, "truncated DNS message"),
            DnsError::NotResponse => write!(f, "not a DNS response"),
            DnsError::IdMismatch => write!(f, "DNS id mismatch"),
            DnsError::QuestionMismatch => write!(f, "DNS question mismatch"),
            DnsError::BadPointer => write!(f, "bad DNS compression pointer"),
            DnsError::Io(e) => write!(f, "{e}"),
            DnsError::Timeout => write!(f, "timed out"),
        }
    }
}

pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Encode a dotted name as wire-format labels.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::BadName);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(DnsError::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

pub const TYPE_OPT: u16 = 41;
/// UDP payload size advertised in the EDNS0 OPT record.
pub const EDNS_UDP_SIZE: u16 = 1232;

/// Build a recursion-desired A/IN query. With `edns`, an EDNS0 OPT record
/// is added, as systemd-resolved sends: a Pi-hole (or a path to it) that
/// mishandles EDNS0 then shows up in the probes instead of only in
/// resolved's logs.
pub fn build_query(id: u16, name: &str, edns: bool) -> Result<Vec<u8>, DnsError> {
    let qname = encode_name(name)?;
    let mut m = Vec::with_capacity(12 + qname.len() + 4 + 11);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&[0, 0, 0, 0]); // AN/NS
    m.extend_from_slice(&u16::from(edns).to_be_bytes()); // ARCOUNT
    m.extend_from_slice(&qname);
    m.extend_from_slice(&TYPE_A.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    if edns {
        m.push(0); // root name
        m.extend_from_slice(&TYPE_OPT.to_be_bytes());
        m.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes()); // "class" = payload size
        m.extend_from_slice(&[0, 0, 0, 0]); // extended rcode, version 0, flags 0
        m.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }
    Ok(m)
}

/// Read a (possibly compressed) name starting at `pos`. Returns the
/// lowercased dotted name and the position just after the name's first
/// encoding in the stream.
fn read_name(msg: &[u8], pos: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = pos;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *msg.get(p).ok_or(DnsError::Short)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    p += 1;
                    break;
                }
                let l = len as usize;
                let label = msg.get(p + 1..p + 1 + l).ok_or(DnsError::Short)?;
                total += l + 1;
                if total > 255 {
                    return Err(DnsError::BadName);
                }
                labels.push(
                    label
                        .iter()
                        .map(|b| (*b as char).to_ascii_lowercase())
                        .collect(),
                );
                p += 1 + l;
            }
            0xC0 => {
                let lo = *msg.get(p + 1).ok_or(DnsError::Short)? as usize;
                let target = (((len & 0x3F) as usize) << 8) | lo;
                if end.is_none() {
                    end = Some(p + 2);
                }
                jumps += 1;
                // A pointer must go strictly backwards; that also bounds loops.
                if jumps > 32 || target >= p {
                    return Err(DnsError::BadPointer);
                }
                p = target;
            }
            _ => return Err(DnsError::BadPointer),
        }
    }
    Ok((labels.join("."), end.unwrap_or(p)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    /// Every A record in the answer section, in order.
    pub answers: Vec<Ipv4Addr>,
}

/// Parse a response to the query `(expect_id, expect_name, A, IN)`.
pub fn parse_response(msg: &[u8], expect_id: u16, expect_name: &str) -> Result<Reply, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::Short);
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotResponse);
    }
    if id != expect_id {
        return Err(DnsError::IdMismatch);
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;

    let want = expect_name
        .strip_suffix('.')
        .unwrap_or(expect_name)
        .to_ascii_lowercase();
    let mut pos = 12;
    let mut matched = false;
    for _ in 0..qd {
        let (name, next) = read_name(msg, pos)?;
        let fixed = msg.get(next..next + 4).ok_or(DnsError::Short)?;
        let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        if name == want && qtype == TYPE_A && qclass == CLASS_IN {
            matched = true;
        }
        pos = next + 4;
    }
    // Some servers answer REFUSED/FORMERR with an empty question section.
    if qd > 0 && !matched {
        return Err(DnsError::QuestionMismatch);
    }
    if qd == 0 && rcode == RCODE_NOERROR {
        return Err(DnsError::QuestionMismatch);
    }

    let mut answers = Vec::new();
    for _ in 0..an {
        let (_, next) = read_name(msg, pos)?;
        let fixed = msg.get(next..next + 10).ok_or(DnsError::Short)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata = msg
            .get(next + 10..next + 10 + rdlen)
            .ok_or(DnsError::Short)?;
        if rtype == TYPE_A && rclass == CLASS_IN && rdlen == 4 {
            answers.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        pos = next + 10 + rdlen;
    }
    Ok(Reply {
        id,
        rcode,
        truncated,
        answers,
    })
}

/// A probe result: the parsed reply and the round-trip time.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub reply: Reply,
    pub rtt: Duration,
}

/// Send one A query to `server` and wait for the matching answer.
///
/// The socket is `connect`ed, so the kernel drops datagrams from any other
/// peer. The query is repeated once at `retry_after` (same id) to ride out
/// a single lost datagram on Wi-Fi. `timeout` bounds the whole exchange.
#[cfg(test)]
pub fn query_a(
    server: SocketAddr,
    name: &str,
    timeout: Duration,
    retry_after: Option<Duration>,
) -> Result<Probe, DnsError> {
    query_a_counted(server, name, timeout, retry_after).1
}

/// Like `query_a`, but also says how many datagrams were sent: the server
/// logs every one of them as a query, and the stats need to subtract them.
pub fn query_a_counted(
    server: SocketAddr,
    name: &str,
    timeout: Duration,
    retry_after: Option<Duration>,
) -> (u32, Result<Probe, DnsError>) {
    let mut sent = 0u32;
    let res = exchange(server, name, timeout, retry_after, &mut sent);
    (sent, res)
}

fn exchange(
    server: SocketAddr,
    name: &str,
    timeout: Duration,
    retry_after: Option<Duration>,
    sent: &mut u32,
) -> Result<Probe, DnsError> {
    let id = crate::util::random_u16();
    let query = build_query(id, name, true)?;
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("static addr"),
        SocketAddr::V6(_) => "[::]:0".parse().expect("static addr"),
    };
    let sock = UdpSocket::bind(bind).map_err(|e| DnsError::Io(e.to_string()))?;
    sock.connect(server)
        .map_err(|e| DnsError::Io(e.to_string()))?;

    let start = Instant::now();
    sock.send(&query).map_err(|e| DnsError::Io(e.to_string()))?;
    *sent += 1;
    let mut retried = retry_after.is_none();
    let mut buf = [0u8; 1500];
    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(DnsError::Timeout);
        }
        let mut wait = timeout - elapsed;
        if !retried {
            let at = retry_after.unwrap_or(timeout);
            if elapsed >= at {
                if sock.send(&query).is_ok() {
                    *sent += 1;
                }
                retried = true;
            } else {
                wait = wait.min(at - elapsed);
            }
        }
        sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|e| DnsError::Io(e.to_string()))?;
        match sock.recv(&mut buf) {
            Ok(n) => match parse_response(&buf[..n], id, name) {
                Ok(reply) => {
                    return Ok(Probe {
                        reply,
                        rtt: start.elapsed(),
                    })
                }
                // Garbage or a stray datagram: keep waiting.
                Err(_) => continue,
            },
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(DnsError::Io("connection refused".into()))
            }
            Err(e) => return Err(DnsError::Io(e.to_string())),
        }
    }
}

/// A name nobody has asked for: `<16 hex digits>.<domain>`. It forces the
/// resolver past its cache and all the way upstream.
pub fn random_name_under(domain: &str) -> String {
    let mut r = [0u8; 8];
    if crate::util::urandom(&mut r).is_err() {
        r = crate::util::unix_now().to_bits().to_be_bytes();
    }
    let label: String = r.iter().map(|b| format!("{b:02x}")).collect();
    format!("{label}.{domain}")
}

/// Classification of a probe against a blocking resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The server answered usefully (NOERROR or NXDOMAIN).
    pub ok: bool,
    /// The canary was blocked (null address, the server's own address,
    /// NXDOMAIN or an empty answer).
    pub blocked: bool,
}

/// `strict` is for names that are *expected* to be NXDOMAIN when not blocked
/// (the dedicated `.invalid` canary): only an explicit null or self address
/// counts. Otherwise NXDOMAIN and empty answers also count as blocked, which
/// covers Pi-hole's other blocking modes for a real blocklisted domain.
pub fn judge(reply: &Reply, server: IpAddr, strict: bool) -> Verdict {
    let ok = reply.rcode == RCODE_NOERROR || reply.rcode == RCODE_NXDOMAIN;
    if !ok {
        return Verdict {
            ok: false,
            blocked: false,
        };
    }
    let all_null = !reply.answers.is_empty()
        && reply
            .answers
            .iter()
            .all(|a| a.is_unspecified() || IpAddr::V4(*a) == server);
    let blocked = if strict {
        reply.rcode == RCODE_NOERROR && all_null
    } else {
        reply.rcode == RCODE_NXDOMAIN || reply.answers.is_empty() || all_null
    };
    Verdict { ok, blocked }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response for `name` with the given A answers, using a
    /// compression pointer back to the question like real servers do.
    fn response(id: u16, name: &str, rcode: u8, answers: &[Ipv4Addr]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&(0x8180u16 | rcode as u16).to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&encode_name(name).unwrap());
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        for a in answers {
            m.extend_from_slice(&[0xC0, 0x0C]);
            m.extend_from_slice(&TYPE_A.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&60u32.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(&a.octets());
        }
        m
    }

    #[test]
    fn query_layout() {
        let q = build_query(0xBEEF, "doubleclick.net", false).unwrap();
        assert_eq!(&q[..2], &[0xBE, 0xEF]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(q[12], 11);
        assert_eq!(&q[13..24], b"doubleclick");
        assert_eq!(q[24], 3);
        assert_eq!(&q[25..28], b"net");
        assert_eq!(q[28], 0);
        assert_eq!(&q[29..], &[0, 1, 0, 1]);
        assert_eq!(q.len(), 33);
    }

    #[test]
    fn edns_query_carries_an_opt_record() {
        let plain = build_query(7, "doubleclick.net", false).unwrap();
        let q = build_query(7, "doubleclick.net", true).unwrap();
        assert_eq!(&q[10..12], &[0, 1], "ARCOUNT = 1");
        assert_eq!(&plain[10..12], &[0, 0]);
        assert_eq!(q.len(), plain.len() + 11);
        // Same question, then the OPT RR: root, type 41, size 1232, no rdata.
        assert_eq!(&q[12..plain.len()], &plain[12..]);
        assert_eq!(
            &q[plain.len()..],
            &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0],
            "root name, TYPE OPT, UDP size 1232, ext-rcode/version/flags 0, RDLEN 0"
        );
        // A response that echoes the OPT record still parses.
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        let p = parse_response(&r, 7, "doubleclick.net").unwrap();
        assert_eq!(p.rcode, 0);
    }

    #[test]
    fn name_encoding_rules() {
        assert_eq!(encode_name("a.b.").unwrap(), vec![1, b'a', 1, b'b', 0]);
        assert_eq!(encode_name(""), Err(DnsError::BadName));
        assert_eq!(encode_name("a..b"), Err(DnsError::BadName));
        assert_eq!(encode_name(&"x".repeat(64)), Err(DnsError::BadName));
        assert_eq!(encode_name("bücher.de"), Err(DnsError::BadName));
        let long = vec!["abcdefghi"; 30].join(".");
        assert_eq!(encode_name(&long), Err(DnsError::BadName));
    }

    #[test]
    fn parses_blocked_answer() {
        let r = response(7, "doubleclick.net", 0, &[Ipv4Addr::UNSPECIFIED]);
        let p = parse_response(&r, 7, "doubleclick.net").unwrap();
        assert_eq!(p.rcode, 0);
        assert_eq!(p.answers, vec![Ipv4Addr::UNSPECIFIED]);
        assert!(!p.truncated);
    }

    #[test]
    fn parses_multiple_answers_and_case() {
        let ips = [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let r = response(9, "Example.COM", 0, &ips);
        let p = parse_response(&r, 9, "example.com").unwrap();
        assert_eq!(p.answers, ips.to_vec());
    }

    #[test]
    fn skips_cname_records() {
        // question + CNAME(example.com -> x.example.com) + A
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 5, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        m.extend_from_slice(&encode_name("example.com").unwrap());
        m.extend_from_slice(&[0, 1, 0, 1]);
        // CNAME rr
        m.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60]);
        let target = encode_name("x.example.com").unwrap();
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        m.extend_from_slice(&target);
        // A rr owned by the cname target (pointer to offset of target)
        let target_off = m.len() - target.len();
        m.extend_from_slice(&[0xC0 | (target_off >> 8) as u8, target_off as u8]);
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 9, 9, 9]);
        let p = parse_response(&m, 5, "example.com").unwrap();
        assert_eq!(p.answers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
    }

    #[test]
    fn rejects_wrong_id_question_and_queries() {
        let r = response(1, "a.com", 0, &[Ipv4Addr::LOCALHOST]);
        assert_eq!(parse_response(&r, 2, "a.com"), Err(DnsError::IdMismatch));
        assert_eq!(
            parse_response(&r, 1, "b.com"),
            Err(DnsError::QuestionMismatch)
        );
        let q = build_query(1, "a.com", false).unwrap();
        assert_eq!(parse_response(&q, 1, "a.com"), Err(DnsError::NotResponse));
        assert_eq!(parse_response(&[0; 5], 1, "a.com"), Err(DnsError::Short));
    }

    #[test]
    fn rejects_truncated_and_hostile_messages() {
        let r = response(1, "a.com", 0, &[Ipv4Addr::LOCALHOST]);
        for cut in 12..r.len() {
            // Never panics; either parses with fewer records or errors.
            let _ = parse_response(&r[..cut], 1, "a.com");
        }
        // Compression pointer loop: name at 12 points to itself.
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert_eq!(parse_response(&m, 1, "a.com"), Err(DnsError::BadPointer));
        // Forward pointer.
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0x20, 0, 1, 0, 1]);
        assert_eq!(parse_response(&m, 1, "a.com"), Err(DnsError::BadPointer));
        // Reserved label type 0x40.
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0x40, 0, 0, 1, 0, 1]);
        assert_eq!(parse_response(&m, 1, "a.com"), Err(DnsError::BadPointer));
        // rdlength beyond the buffer.
        let mut r = response(1, "a.com", 0, &[Ipv4Addr::LOCALHOST]);
        let n = r.len();
        r[n - 5] = 0xFF;
        assert_eq!(parse_response(&r, 1, "a.com"), Err(DnsError::Short));
    }

    #[test]
    fn nxdomain_and_empty_question() {
        let r = response(3, "a.com", RCODE_NXDOMAIN, &[]);
        let p = parse_response(&r, 3, "a.com").unwrap();
        assert_eq!(p.rcode, RCODE_NXDOMAIN);
        // REFUSED with no question section.
        let m = vec![0, 3, 0x81, 0x85, 0, 0, 0, 0, 0, 0, 0, 0];
        let p = parse_response(&m, 3, "a.com").unwrap();
        assert_eq!(p.rcode, 5);
    }

    #[test]
    fn verdicts() {
        let pi = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 153));
        let mk = |rcode, answers: Vec<Ipv4Addr>| Reply {
            id: 1,
            rcode,
            truncated: false,
            answers,
        };
        let blocked = judge(&mk(0, vec![Ipv4Addr::UNSPECIFIED]), pi, false);
        assert_eq!(
            blocked,
            Verdict {
                ok: true,
                blocked: true
            }
        );
        let paused = judge(&mk(0, vec![Ipv4Addr::new(142, 250, 1, 1)]), pi, false);
        assert_eq!(
            paused,
            Verdict {
                ok: true,
                blocked: false
            }
        );
        let ip_mode = judge(&mk(0, vec![Ipv4Addr::new(192, 168, 1, 153)]), pi, false);
        assert!(ip_mode.blocked);
        let nx = judge(&mk(RCODE_NXDOMAIN, vec![]), pi, false);
        assert_eq!(
            nx,
            Verdict {
                ok: true,
                blocked: true
            }
        );
        let nodata = judge(&mk(0, vec![]), pi, false);
        assert_eq!(
            nodata,
            Verdict {
                ok: true,
                blocked: true
            }
        );
        let servfail = judge(&mk(2, vec![]), pi, false);
        assert_eq!(
            servfail,
            Verdict {
                ok: false,
                blocked: false
            }
        );
        let refused = judge(&mk(5, vec![]), pi, false);
        assert!(!refused.ok);
    }

    #[test]
    fn strict_verdicts_need_an_explicit_null_answer() {
        let pi = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 153));
        let mk = |rcode, answers: Vec<Ipv4Addr>| Reply {
            id: 1,
            rcode,
            truncated: false,
            answers,
        };
        // A `.invalid` name that is not on the deny list comes back NXDOMAIN
        // from upstream; that must not read as "blocked".
        assert_eq!(
            judge(&mk(RCODE_NXDOMAIN, vec![]), pi, true),
            Verdict {
                ok: true,
                blocked: false
            }
        );
        assert_eq!(
            judge(&mk(0, vec![]), pi, true),
            Verdict {
                ok: true,
                blocked: false
            }
        );
        assert_eq!(
            judge(&mk(0, vec![Ipv4Addr::UNSPECIFIED]), pi, true),
            Verdict {
                ok: true,
                blocked: true
            }
        );
        assert_eq!(
            judge(&mk(0, vec![Ipv4Addr::new(192, 168, 1, 153)]), pi, true),
            Verdict {
                ok: true,
                blocked: true
            }
        );
        assert_eq!(
            judge(&mk(0, vec![Ipv4Addr::new(1, 2, 3, 4)]), pi, true),
            Verdict {
                ok: true,
                blocked: false
            }
        );
        assert!(!judge(&mk(2, vec![]), pi, true).ok);
    }

    #[test]
    fn udp_probe_against_local_server() {
        use std::thread;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        let h = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = srv.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            // First send a stray datagram with the wrong id, then the real one.
            let stray = response(
                id.wrapping_add(1),
                "doubleclick.net",
                0,
                &[Ipv4Addr::LOCALHOST],
            );
            srv.send_to(&stray, from).unwrap();
            let good = response(id, "doubleclick.net", 0, &[Ipv4Addr::UNSPECIFIED]);
            srv.send_to(&good, from).unwrap();
            n
        });
        let p = query_a(addr, "doubleclick.net", Duration::from_secs(2), None).unwrap();
        assert_eq!(p.reply.answers, vec![Ipv4Addr::UNSPECIFIED]);
        assert!(p.rtt < Duration::from_secs(1));
        assert!(h.join().unwrap() > 12);
    }

    #[test]
    fn udp_probe_times_out_and_retries_once() {
        use std::thread;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        srv.set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let h = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut seen = 0;
            while srv.recv_from(&mut buf).is_ok() {
                seen += 1;
            }
            seen
        });
        let t0 = Instant::now();
        let r = query_a(
            addr,
            "doubleclick.net",
            Duration::from_millis(400),
            Some(Duration::from_millis(200)),
        );
        assert_eq!(r, Err(DnsError::Timeout));
        assert!(t0.elapsed() >= Duration::from_millis(390));
        assert_eq!(h.join().unwrap(), 2, "one send plus one retry");
    }

    #[test]
    fn counts_every_datagram_sent() {
        use std::thread;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        srv.set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let h = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let mut seen = 0;
            while srv.recv_from(&mut buf).is_ok() {
                seen += 1;
            }
            seen
        });
        let (sent, res) = query_a_counted(
            addr,
            "doubleclick.net",
            Duration::from_millis(400),
            Some(Duration::from_millis(150)),
        );
        assert_eq!(res, Err(DnsError::Timeout));
        assert_eq!(sent, 2);
        assert_eq!(
            h.join().unwrap(),
            2,
            "the server saw exactly what we counted"
        );

        // An immediate answer is one datagram.
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (_, from) = srv.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            srv.send_to(
                &response(id, "a.example.com", 0, &[Ipv4Addr::LOCALHOST]),
                from,
            )
            .unwrap();
        });
        let (sent, res) = query_a_counted(
            addr,
            "a.example.com",
            Duration::from_secs(2),
            Some(Duration::from_secs(1)),
        );
        assert!(res.is_ok());
        assert_eq!(sent, 1);
    }

    #[test]
    fn random_names_are_unique_valid_subdomains() {
        let a = random_name_under("example.com");
        let b = random_name_under("example.com");
        assert_ne!(a, b);
        assert!(a.ends_with(".example.com"));
        assert_eq!(a.split('.').next().unwrap().len(), 16);
        assert!(encode_name(&a).is_ok());
    }
}
