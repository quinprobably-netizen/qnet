//! Run a child process without a shell: arguments are argv elements, secrets
//! go through stdin, output is capped and the whole run has a deadline.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

fn drain<R: Read + Send + 'static>(mut r: R, cap: usize) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        kept
    })
}

/// Run `program` with `args`. `stdin` bytes (if any) are written and the pipe
/// closed. stdout/stderr are each capped at `max_out` bytes.
pub fn run(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    max_out: usize,
) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out_h = drain(child.stdout.take().expect("piped"), max_out);
    let err_h = drain(child.stderr.take().expect("piped"), max_out);
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => {
            let data = data.to_vec();
            Some(thread::spawn(move || {
                let _ = pipe.write_all(&data);
                // Dropping the pipe closes it.
            }))
        }
        _ => None,
    };
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(15));
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let stdout = out_h.join().unwrap_or_default();
    let _ = err_h.join();
    Ok(Output {
        code: status.code(),
        stdout,
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
        assert_eq!(o.stdout, b"hello");
    }

    #[test]
    fn args_are_not_interpreted_by_a_shell() {
        let o = run("echo", &["$(id)", ";", "`id`"], None, Duration::from_secs(5), 1024).unwrap();
        assert_eq!(o.stdout, b"$(id) ; `id`\n");
    }

    #[test]
    fn caps_output_and_reports_exit_code() {
        let o = run("sh", &["-c", "yes | head -c 100000; exit 3"], None, Duration::from_secs(5), 100).unwrap();
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
    fn missing_program_is_an_error() {
        assert!(run("/nonexistent/qnet-test", &[], None, Duration::from_secs(1), 1).is_err());
    }
}
