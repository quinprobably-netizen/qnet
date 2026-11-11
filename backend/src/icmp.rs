//! An unprivileged ICMP echo (a "ping socket": SOCK_DGRAM + IPPROTO_ICMP,
//! allowed by `net.ipv4.ping_group_range`). Used only to show the gateway's
//! round-trip time while the panel is open. No child process, no root.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// Internet checksum (RFC 1071). The kernel fills it in for ping sockets,
/// but a correct one costs nothing.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        // An odd trailing byte is padded with a zero byte.
        sum += match c {
            [hi, lo] => u32::from(u16::from_be_bytes([*hi, *lo])),
            [hi] => u32::from(*hi) << 8,
            _ => 0,
        };
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Echo request with the given sequence number and payload. The identifier
/// is set by the kernel for ping sockets.
pub fn build_echo(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&[ECHO_REQUEST, 0, 0, 0, 0, 0]);
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// Is `buf` the echo reply to our request?
pub fn is_reply_to(buf: &[u8], seq: u16, payload: &[u8]) -> bool {
    buf.len() >= 8 + payload.len()
        && buf[0] == ECHO_REPLY
        && buf[1] == 0
        && u16::from_be_bytes([buf[6], buf[7]]) == seq
        && &buf[8..8 + payload.len()] == payload
}

fn ping_socket() -> Option<UdpSocket> {
    // SAFETY: socket(2) returns a fresh descriptor or -1; on success we hand
    // sole ownership to UdpSocket, which accepts any datagram socket.
    unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        );
        if fd < 0 {
            None
        } else {
            Some(UdpSocket::from_raw_fd(fd))
        }
    }
}

/// Round-trip time to `dst`, or None (no ping socket permission, timeout,
/// unreachable).
pub fn echo_rtt(dst: Ipv4Addr, timeout: Duration) -> Option<Duration> {
    let sock = ping_socket()?;
    sock.connect(SocketAddr::new(IpAddr::V4(dst), 0)).ok()?;
    let mut payload = [0u8; 16];
    crate::util::urandom(&mut payload).ok()?;
    let seq = crate::util::random_u16();
    let req = build_echo(seq, &payload);
    let start = Instant::now();
    sock.send(&req).ok()?;
    let mut buf = [0u8; 256];
    loop {
        let left = timeout
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())?;
        sock.set_read_timeout(Some(left)).ok()?;
        let n = sock.recv(&mut buf).ok()?;
        if is_reply_to(&buf[..n], seq, &payload) {
            return Some(start.elapsed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vectors() {
        // RFC 1071 example words.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        assert_eq!(checksum(&[]), 0xFFFF);
        // Odd length pads with a zero byte.
        assert_eq!(checksum(&[0x01]), !0x0100u16);
    }

    #[test]
    fn built_packet_verifies_to_zero() {
        let p = build_echo(0x1234, b"qnet-gateway-pin");
        assert_eq!(p[0], 8);
        assert_eq!(&p[6..8], &[0x12, 0x34]);
        assert_eq!(checksum(&p), 0, "a correct checksum sums to zero");
    }

    #[test]
    fn reply_matching() {
        let payload = b"0123456789abcdef";
        let mut reply = build_echo(7, payload);
        reply[0] = ECHO_REPLY;
        assert!(is_reply_to(&reply, 7, payload));
        assert!(!is_reply_to(&reply, 8, payload), "wrong sequence");
        assert!(
            !is_reply_to(&reply, 7, b"fedcba9876543210"),
            "wrong payload"
        );
        assert!(!is_reply_to(&reply[..10], 7, payload), "truncated");
        let mut req = reply.clone();
        req[0] = ECHO_REQUEST;
        assert!(
            !is_reply_to(&req, 7, payload),
            "an echo request is not a reply"
        );
    }

    #[test]
    fn loopback_ping_when_the_kernel_allows_it() {
        // Needs net.ipv4.ping_group_range to include our group; skip if not.
        if ping_socket().is_none() {
            eprintln!("skipped: no ping socket permission");
            return;
        }
        let rtt = echo_rtt(Ipv4Addr::LOCALHOST, Duration::from_secs(2)).expect("loopback answers");
        assert!(rtt < Duration::from_secs(1));
    }

    #[test]
    fn unroutable_target_times_out() {
        if ping_socket().is_none() {
            return;
        }
        // TEST-NET-1 is never routed.
        let t0 = Instant::now();
        assert!(echo_rtt(Ipv4Addr::new(192, 0, 2, 1), Duration::from_millis(300)).is_none());
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
