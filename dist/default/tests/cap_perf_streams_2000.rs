// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cap.perf.streams-2000` (BUSBAR-1.6.0.md l.663; the plane ABI review's "a cap.perf cell with 2000
//! concurrent streams", l.4426; a correctness check, every stream
//! completes, no speed threshold): the shipped binary carries 2,000 streamed answers AT ONCE, and
//! every one of them reaches its caller whole.
//!
//! The stand-in upstream holds every stream open after its first events until all 2,000 have
//! arrived, so the 2,000 are in flight through busbar together, never one after another; then it
//! finishes them. Each caller must read a 200 and the far end's exact stream, byte for byte. There
//! is deliberately no speed threshold: the PERF phase's A/B against published 1.5.5 is the speed
//! proof (THE DESIGN §11.9); this cell proves nothing is dropped, cut, crossed or parked.
//!
//! 2,000 streams are 4,000 sockets on each side of busbar, above many hosts' default soft limit on
//! open files. The cell therefore runs itself again under `ulimit -n` raised to the hard limit
//! (`run_under_raised_open_files`), and refuses loudly, naming the limit, where the host cannot hold
//! the streams: a host that cannot run the cell is a red, never a pass.
#![cfg(unix)]
// Needs a bootable server with a route to send a real request through.
#![cfg(linked_axis_body_ingress)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The concurrent streams.
const STREAMS: usize = 2000;
/// The open files the cell needs: two sockets per stream on each side of busbar, and headroom.
const OPEN_FILES: u64 = 16_384;
/// How long the upstream waits for every stream to arrive before it finishes them anyway (the
/// assertion on the peak then says how many arrived).
const ARRIVAL_WAIT: Duration = Duration::from_secs(120);
/// A caller that has not read its whole answer by now is parked or cut.
const CALLER_BUDGET: Duration = Duration::from_secs(240);
/// The content deltas each stream carries.
const DELTAS: usize = 8;
/// The environment variable the re-run is told it is the re-run by.
const CHILD: &str = "BUSBAR_CAP_PERF_STREAMS_2000_CHILD";

/// THE CELL: re-run under a raised open-files limit, which must succeed.
#[test]
fn cap_perf_streams_2000() {
    if std::env::var_os(CHILD).is_some() {
        cap_perf_streams_2000_body();
        return;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let script = format!(
        "ulimit -n {OPEN_FILES} 2>/dev/null || ulimit -n \"$(ulimit -Hn)\"; \
         n=\"$(ulimit -n)\"; \
         if [ \"$n\" != unlimited ] && [ \"$n\" -lt {need} ]; then \
           echo \"cap.perf.streams-2000: this host allows $n open files, the cell needs {need}\" >&2; exit 3; \
         fi; \
         exec \"$0\" --exact cap_perf_streams_2000 --nocapture",
        need = STREAMS * 2 + 512
    );
    let out = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(&exe)
        .env(CHILD, "1")
        .output()
        .expect("run the cell under a raised open-files limit");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("1 passed"),
        "the cell failed (status {:?}):\n{text}",
        out.status
    );
}

/// The cell's body, run by [`cap_perf_streams_2000`] in its re-run under the raised limit.
fn cap_perf_streams_2000_body() {
    let dir = fixture_dir();
    let upstream = Upstream::spawn();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port, upstream.port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening ({status:?}):\n{}",
                read(&log_path)
            );
        }
        if healthz_ok(data_port) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not answer on {data_port} within 30s:\n{}",
            read(&log_path)
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let callers: Vec<_> = (0..STREAMS)
        .map(|i| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn(move || stream_chat(data_port, i))
                .expect("a caller thread")
        })
        .collect();
    let answers: Vec<Answer> = callers
        .into_iter()
        .map(|h| h.join().expect("a caller did not panic"))
        .collect();
    let peak = upstream.peak.load(Ordering::SeqCst);
    let _ = child.kill();
    let _ = child.wait();

    let want = expected_stream();
    let bad: Vec<String> = answers
        .iter()
        .enumerate()
        .filter(|(_, a)| a.status != 200 || a.body != want)
        .map(|(i, a)| {
            format!(
                "stream {i}: status {} body {} bytes{}",
                a.status,
                a.body.len(),
                if a.body == want {
                    ""
                } else {
                    " (not the far end's stream)"
                }
            )
        })
        .take(10)
        .collect();
    assert!(
        bad.is_empty(),
        "every stream must reach its caller whole; first failures: {bad:?}; log:\n{}",
        read(&log_path)
    );
    assert_eq!(
        peak, STREAMS,
        "all {STREAMS} streams must be in flight through busbar at once (peak {peak})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── the stand-in upstream ────────────────────────────────────────────────────────────────────────

/// An OpenAI-shaped streaming upstream: each request is answered with its first events at once,
/// then held until every stream has arrived (or [`ARRIVAL_WAIT`]), then finished.
struct Upstream {
    port: u16,
    peak: Arc<AtomicUsize>,
}

impl Upstream {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peak = Arc::new(AtomicUsize::new(0));
        let arrived = Arc::new((Mutex::new(0usize), Condvar::new()));
        let p = Arc::clone(&peak);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let (p, arrived) = (Arc::clone(&p), Arc::clone(&arrived));
                let _ = std::thread::Builder::new()
                    .stack_size(128 * 1024)
                    .spawn(move || serve(stream, &p, &arrived));
            }
        });
        Upstream { port, peak }
    }
}

fn serve(mut stream: TcpStream, peak: &AtomicUsize, arrived: &(Mutex<usize>, Condvar)) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut body = vec![0u8; content_length];
    let _ = reader.read_exact(&mut body);
    let events = events();
    let (head, tail) = events.split_at(2);
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
    );
    for e in head {
        let _ = stream.write_all(e.as_bytes());
    }
    let _ = stream.flush();
    // Hold until every stream is in flight together.
    let (count, all) = arrived;
    let mut n = count.lock().unwrap();
    *n += 1;
    peak.fetch_max(*n, Ordering::SeqCst);
    if *n >= STREAMS {
        drop(n);
        all.notify_all();
    } else {
        let _ = all.wait_timeout_while(n, ARRIVAL_WAIT, |n| *n < STREAMS);
    }
    for e in tail {
        let _ = stream.write_all(e.as_bytes());
        let _ = stream.flush();
    }
}

/// The far end's stream, event by event: a role delta, [`DELTAS`] content deltas, the finish, the
/// usage the caller asked for, and the terminator.
fn events() -> Vec<String> {
    let chunk = |delta: &str, finish: &str| {
        format!(
            "data: {{\"id\":\"chatcmpl-cap\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"cap-model\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":{finish}}}]}}\n\n"
        )
    };
    let mut out = vec![chunk(r#"{"role":"assistant","content":""}"#, "null")];
    out.extend((0..DELTAS).map(|i| chunk(&format!(r#"{{"content":"t{i} "}}"#), "null")));
    out.push(chunk("{}", r#""stop""#));
    out.push(
        "data: {\"id\":\"chatcmpl-cap\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"cap-model\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":8,\"total_tokens\":11}}\n\n"
            .to_string(),
    );
    out.push("data: [DONE]\n\n".to_string());
    out
}

fn expected_stream() -> Vec<u8> {
    events().concat().into_bytes()
}

// ── the callers ──────────────────────────────────────────────────────────────────────────────────

struct Answer {
    status: u16,
    body: Vec<u8>,
}

/// One streamed chat on its own connection, asking for usage itself (so the far end's stream is
/// relayed as it is), read to its end and de-chunked.
fn stream_chat(port: u16, i: usize) -> Answer {
    let body = format!(
        r#"{{"model":"cap-model","stream":true,"stream_options":{{"include_usage":true}},"messages":[{{"role":"user","content":"stream {i}"}}]}}"#
    );
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return Answer {
            status: 0,
            body: Vec::new(),
        };
    };
    let _ = stream.set_read_timeout(Some(CALLER_BUDGET));
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse(&raw)
}

fn parse(raw: &[u8]) -> Answer {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Answer {
            status: 0,
            body: Vec::new(),
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let rest = &raw[split + 4..];
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let chunked = head
        .lines()
        .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    Answer {
        status,
        body: if chunked {
            dechunk(rest)
        } else {
            rest.to_vec()
        },
    }
}

/// An HTTP/1.1 chunked body, de-chunked; a malformed or cut one yields what was whole before it.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = raw.windows(2).position(|w| w == b"\r\n") else {
            return out;
        };
        let size_line = String::from_utf8_lossy(&raw[..eol]);
        let Ok(size) = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
        else {
            return out;
        };
        if size == 0 || raw.len() < eol + 2 + size {
            return out;
        }
        out.extend_from_slice(&raw[eol + 2..eol + 2 + size]);
        raw = raw.get(eol + 2 + size + 2..).unwrap_or(&[]);
    }
}

// ── fixture ──────────────────────────────────────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-cap-perf-streams-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    // The provider catalog row is test data (`fixtures/perf_mock_provider.yaml`, the upstream's
    // dialect), not a literal here.
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/perf_mock_provider.yaml")
            .replace("{upstream_port}", &upstream_port.to_string()),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
limits:
  max_inbound_concurrent: {cap}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  cap-model:
    provider: mock
"#,
            cap = STREAMS * 2
        ),
    )
    .unwrap();
}

fn healthz_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf.starts_with("HTTP/1.1 200")
}

fn read(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let tail = bytes.len().saturating_sub(4000);
    String::from_utf8_lossy(&bytes[tail..]).into_owned()
}
