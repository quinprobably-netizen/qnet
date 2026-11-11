//! Run a child process without a shell: arguments are argv elements, secrets
//! go through stdin, output is capped and the whole run has a deadline.
//!
//! The child gets its own process group, so a timeout kills it and anything
//! it spawned, and output readers are never joined unconditionally: a
//! grandchild that keeps a pipe open must not be able to hang us.

use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How long to wait for the readers after the child has exited.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    /// Wiped on drop: this may be a secret from the keyring.
    pub stdout: Zeroizing<Vec<u8>>,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

type Captured = Arc<Mutex<Zeroizing<Vec<u8>>>>;

/// Read `r` into a shared buffer (capped); the receiver fires at EOF.
fn drain<R: Read + Send + 'static>(mut r: R, cap: usize) -> (Captured, Receiver<()>) {
    // Reserve up front so growth never leaves unwiped copies behind.
    let buf: Captured = Arc::new(Mutex::new(Zeroizing::new(Vec::with_capacity(
        cap.min(1 << 16),
    ))));
    let sink = buf.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut kept) = sink.lock() {
                        let room = cap.saturating_sub(kept.len());
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        }
        let _ = tx.send(());
    });
    (buf, rx)
}

fn snapshot(c: &Captured) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(c.lock().map(|g| g.to_vec()).unwrap_or_default())
}

fn kill_group(pid: u32) {
    // SAFETY: killpg with a pid we spawned (its own process group leader).
    unsafe {
        libc::killpg(pid as libc::pid_t, libc::SIGKILL);
    }
}

/// Run `program` with `args`. `stdin` bytes (if any) are written and the pipe
/// closed. stdout is capped at `max_out` bytes; stderr is discarded.
pub fn run(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    max_out: usize,
) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .process_group(0)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let (out, out_done) = drain(child.stdout.take().expect("piped"), max_out);
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let data = Zeroizing::new(data.to_vec());
        // Detached on purpose: a child that never reads must not block us.
        thread::spawn(move || {
            let _ = pipe.write_all(&data[..]);
        });
    }
    let start = Instant::now();
    let pid = child.id();
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill_group(pid);
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(15));
    };
    if timed_out {
        // Whatever was read is returned; the reader may outlive us if some
        // process escaped the group, which is harmless.
        return Ok(Output {
            code: status.code(),
            stdout: snapshot(&out),
            timed_out,
        });
    }
    // The child is gone; a lingering grandchild may still hold the pipe.
    let _ = out_done.recv_timeout(DRAIN_GRACE);
    Ok(Output {
        code: status.code(),
        stdout: snapshot(&out),
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_and_feeds_stdin() {
        let o = run("cat", &[], Some(b"hello"), Duration::from_secs(5), 1024).unwrap();
        assert!(o.success());
        assert_eq!(&o.stdout[..], b"hello");
    }

    #[test]
    fn args_are_not_interpreted_by_a_shell() {
        let o = run(
            "echo",
            &["$(id)", ";", "`id`"],
            None,
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert_eq!(&o.stdout[..], b"$(id) ; `id`\n");
    }

    #[test]
    fn caps_output_and_reports_exit_code() {
        let o = run(
            "sh",
            &["-c", "yes | head -c 100000; exit 3"],
            None,
            Duration::from_secs(5),
            100,
        )
        .unwrap();
        assert_eq!(o.stdout.len(), 100);
        assert_eq!(o.code, Some(3));
    }

    #[test]
    fn kills_on_timeout() {
        let t0 = Instant::now();
        let o = run("sleep", &["30"], None, Duration::from_millis(200), 10).unwrap();
        assert!(o.timed_out && !o.success());
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn timeout_kills_the_whole_process_group_and_returns_partial_output() {
        // The shell prints, then waits on a child that holds the pipe open.
        let t0 = Instant::now();
        let o = run(
            "sh",
            &["-c", "echo partial; sleep 30 & sleep 30"],
            None,
            Duration::from_millis(300),
            1024,
        )
        .unwrap();
        assert!(o.timed_out);
        assert_eq!(&o.stdout[..], b"partial\n");
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "must not wait for the grandchild"
        );
    }

    #[test]
    fn a_grandchild_holding_the_pipe_cannot_hang_us() {
        // The shell exits at once; the background sleep keeps stdout open.
        let t0 = Instant::now();
        let o = run(
            "sh",
            &["-c", "echo hi; sleep 8 &"],
            None,
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert!(!o.timed_out);
        assert_eq!(&o.stdout[..], b"hi\n");
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "returned after {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn a_child_that_never_reads_stdin_does_not_block() {
        let big = vec![b'x'; 1 << 20];
        let t0 = Instant::now();
        let o = run(
            "sh",
            &["-c", "exit 0"],
            Some(&big),
            Duration::from_secs(5),
            16,
        )
        .unwrap();
        assert!(o.success());
        assert!(t0.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn missing_program_is_an_error() {
        assert!(run(
            "/nonexistent/qnet-test",
            &[],
            None,
            Duration::from_secs(1),
            1
        )
        .is_err());
    }
}
