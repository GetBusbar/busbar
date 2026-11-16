// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

const STREAMS: usize = 2000;

const OPEN_FILES: u64 = 16_384;

const ARRIVAL_WAIT: Duration = Duration::from_secs(120);

const CALLER_BUDGET: Duration = Duration::from_secs(240);

const DELTAS: usize = 8;

const CHILD: &str = "BUSBAR_CAP_PERF_STREAMS_2000_CHILD";

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

fn cap_perf_streams_2000_body() {
    // The callers and the far end are tasks on one small runtime, not a thread each: the cell
    // measures busbar holding the streams, so it must not need thousands of host threads itself.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the cell's runtime");
    let dir = fixture_dir();
    let upstream = runtime.block_on(Upstream::spawn());
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port, upstream.port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = common::boot::Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn busbar"),
    );
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

    let answers: Vec<Answer> = runtime.block_on(async {
        let callers: Vec<_> = (0..STREAMS)
            .map(|i| tokio::spawn(stream_chat(data_port, i)))
            .collect();
        let mut answers = Vec::with_capacity(STREAMS);
        for caller in callers {
            answers.push(caller.await.expect("a caller did not panic"));
        }
        answers
    });
    let peak = upstream.peak.load(Ordering::SeqCst);
    let barrier_failed = upstream.arrived.lock().unwrap().failed;
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !barrier_failed,
        "the upstream barrier expired before all {STREAMS} streams were live together (peak {peak})"
    );
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

struct Upstream {
    port: u16,
    peak: Arc<AtomicUsize>,
    arrived: Arc<Mutex<ArrivalState>>,
}

#[derive(Default)]
struct ArrivalState {
    live: usize,
    released: bool,
    failed: bool,
}

/// The barrier's phase, published to every held stream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    Released,
    Failed,
}

struct LiveStream<'a> {
    arrived: &'a Mutex<ArrivalState>,
    registered: bool,
}

impl Drop for LiveStream<'_> {
    fn drop(&mut self) {
        if self.registered {
            let mut state = self.arrived.lock().unwrap_or_else(|p| p.into_inner());
            state.live -= 1;
        }
    }
}

impl Upstream {
    async fn spawn() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peak = Arc::new(AtomicUsize::new(0));
        let arrived = Arc::new(Mutex::new(ArrivalState::default()));
        let (phase, _) = tokio::sync::watch::channel(Phase::Waiting);
        let phase = Arc::new(phase);
        let held = Arc::clone(&arrived);
        let p = Arc::clone(&peak);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (p, arrived, phase) =
                    (Arc::clone(&p), Arc::clone(&arrived), Arc::clone(&phase));
                tokio::spawn(async move { serve(stream, &p, &arrived, &phase).await });
            }
        });
        Upstream {
            port,
            peak,
            arrived: held,
        }
    }
}

async fn serve(
    stream: tokio::net::TcpStream,
    peak: &AtomicUsize,
    arrived: &Mutex<ArrivalState>,
    phase: &tokio::sync::watch::Sender<Phase>,
) {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
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
    if reader.read_exact(&mut body).await.is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let events = events();
    let (head, tail) = events.split_at(2);
    if stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    for e in head {
        if stream.write_all(e.as_bytes()).await.is_err() {
            return;
        }
    }
    if stream.flush().await.is_err() {
        return;
    }

    let mut live = LiveStream {
        arrived,
        registered: false,
    };
    let mut watching = phase.subscribe();
    {
        let mut state = arrived.lock().unwrap();
        if state.failed {
            return;
        }
        state.live += 1;
        live.registered = true;
        peak.fetch_max(state.live, Ordering::SeqCst);
        if state.live == STREAMS {
            state.released = true;
            drop(state);
            phase.send_replace(Phase::Released);
        }
    }
    let released = matches!(
        tokio::time::timeout(
            ARRIVAL_WAIT,
            watching.wait_for(|phase| *phase != Phase::Waiting)
        )
        .await,
        Ok(Ok(seen)) if *seen == Phase::Released
    );
    if !released {
        let mut state = arrived.lock().unwrap();
        if !state.released {
            state.failed = true;
            drop(state);
            phase.send_replace(Phase::Failed);
        }
        return;
    }
    for e in tail {
        let _ = stream.write_all(e.as_bytes()).await;
        let _ = stream.flush().await;
    }
}

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

struct Answer {
    status: u16,
    body: Vec<u8>,
}

async fn stream_chat(port: u16, i: usize) -> Answer {
    let body = format!(
        r#"{{"model":"cap-model","stream":true,"stream_options":{{"include_usage":true}},"messages":[{{"role":"user","content":"stream {i}"}}]}}"#
    );
    let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
        return Answer {
            status: 0,
            body: Vec::new(),
        };
    };
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    // Each read waits at most the caller's budget, as a blocking read timeout would.
    while let Ok(Ok(n @ 1..)) = tokio::time::timeout(CALLER_BUDGET, stream.read(&mut buf)).await {
        raw.extend_from_slice(&buf[..n]);
    }
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
