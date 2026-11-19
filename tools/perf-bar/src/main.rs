// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The measurement client of DONE statement 5: one black-box method for every serving binary,
//! v1.5.5 included, over plain HTTP/1.1 and over TLS, for a whole answer and a streamed one.
//!
//! ```text
//! perf-bar stub <port>
//! perf-bar wait <addr> <route> [tls]
//! perf-bar keep <label> <threads> <n> <warm> <addr> <pid> <route> [tls]
//! perf-bar new  <label> <threads> <n> <warm> <addr> <pid> <route> [tls]
//! perf-bar idle <label> <conns> <addr> <pid> <route> [tls]
//! ```
//! `route` is `healthz`, `chat` (`POST /v1/messages`, whole answer) or `stream` (the same request
//! with `"stream": true`). `tls` is `tls:<ca.pem>:<server name>`. `n` and `warm` are per thread.
//! `PERF_KEY` (the caller key) and `PERF_MODEL` are read from the environment; `PERF_CLK_TCK` is
//! the machine's clock ticks per second (`getconf CLK_TCK`, default 100).
//!
//! Every run prints one tab-separated row, header in [`HEADER`]. Times are microseconds.
//! `cpu_us` is the server process's user plus system time per operation, read from
//! `/proc/<pid>/stat` around the measured part only. `first_us` is the time to the first byte of
//! the answer's body (the same as the whole time for an answer that is not streamed in pieces).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEADER: &str = "label\tmode\troute\ttransport\tthreads\tops\tmedian_us\tp99_us\tfirst_median_us\tfirst_p99_us\tcpu_us\trss_before_kib\trss_after_kib\tper_conn_bytes";

type Fault = Box<dyn std::error::Error + Send + Sync>;

trait Wire: Read + Write + Send {}
impl<T: Read + Write + Send> Wire for T {}

#[derive(Clone)]
struct Tls {
    config: Arc<rustls::ClientConfig>,
    name: rustls::pki_types::ServerName<'static>,
}

#[derive(Clone)]
struct Target {
    addr: String,
    tls: Option<Tls>,
}

impl Target {
    fn parse(addr: &str, tls: Option<&String>) -> Result<Self, Fault> {
        let tls = match tls {
            None => None,
            Some(spec) => {
                let mut parts = spec.splitn(3, ':');
                let (Some("tls"), Some(ca), Some(name)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return Err("the transport argument is tls:<ca.pem>:<server name>".into());
                };
                use rustls::pki_types::pem::PemObject;
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls::pki_types::CertificateDer::pem_file_iter(ca)? {
                    roots.add(cert?)?;
                }
                let mut config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                // A resumed session would hide the handshake the new-connection figure measures.
                config.resumption = rustls::client::Resumption::disabled();
                Some(Tls {
                    config: Arc::new(config),
                    name: rustls::pki_types::ServerName::try_from(name.to_owned())?,
                })
            }
        };
        Ok(Self {
            addr: addr.to_owned(),
            tls,
        })
    }

    fn transport(&self) -> &'static str {
        if self.tls.is_some() {
            "tls"
        } else {
            "plain"
        }
    }

    /// One connection, ready for a request: the TCP connect and, over TLS, the whole handshake.
    fn open(&self) -> Result<Box<dyn Wire>, Fault> {
        let tcp = TcpStream::connect(&self.addr)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some(tls) => {
                let conn = rustls::ClientConnection::new(tls.config.clone(), tls.name.clone())?;
                let mut stream = rustls::StreamOwned::new(conn, tcp);
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock)?;
                }
                Ok(Box::new(stream))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Healthz,
    Chat,
    Stream,
}

impl Route {
    fn parse(word: &str) -> Result<Self, Fault> {
        match word {
            "healthz" => Ok(Self::Healthz),
            "chat" => Ok(Self::Chat),
            "stream" => Ok(Self::Stream),
            other => Err(format!("unknown route {other}: healthz, chat or stream").into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Healthz => "healthz",
            Self::Chat => "chat",
            Self::Stream => "stream",
        }
    }

    /// The request bytes, built once per run. `close` asks the server to end the connection.
    fn request(self, host: &str, close: bool) -> Vec<u8> {
        let connection = if close { "close" } else { "keep-alive" };
        match self {
            Self::Healthz => {
                format!("GET /healthz HTTP/1.1\r\nhost: {host}\r\nconnection: {connection}\r\n\r\n")
                    .into_bytes()
            }
            Self::Chat | Self::Stream => {
                let key = std::env::var("PERF_KEY").unwrap_or_default();
                let model = std::env::var("PERF_MODEL").unwrap_or_else(|_| "mock".to_owned());
                let stream = if self == Self::Stream {
                    ",\"stream\":true"
                } else {
                    ""
                };
                let body = format!(
                    "{{\"model\":\"{model}\",\"max_tokens\":64,\"messages\":[{{\"role\":\"user\",\"content\":\"ping\"}}]{stream}}}"
                );
                format!(
                    "POST /v1/messages HTTP/1.1\r\nhost: {host}\r\nconnection: {connection}\r\n\
                     content-type: application/json\r\nanthropic-version: 2023-06-01\r\n\
                     x-api-key: {key}\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            }
        }
    }
}

/// What one answer cost the caller.
struct Answer {
    status: u16,
    /// From the request's first byte written to the first byte of the body read.
    first: Duration,
    /// To the last byte of the body.
    whole: Duration,
    /// The server said it would close, or the body ran to the end of the connection.
    closed: bool,
}

/// A connection with the bytes read past the last answer kept for the next one.
struct Http {
    wire: Box<dyn Wire>,
    buf: Vec<u8>,
}

impl Http {
    fn new(wire: Box<dyn Wire>) -> Self {
        Self {
            wire,
            buf: Vec::with_capacity(16 * 1024),
        }
    }

    /// Read more; `Ok(false)` at the end of the connection.
    fn fill(&mut self) -> Result<bool, Fault> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.wire.read(&mut chunk)?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n != 0)
    }

    fn need(&mut self, len: usize) -> Result<(), Fault> {
        while self.buf.len() < len {
            if !self.fill()? {
                return Err("the connection ended inside an answer".into());
            }
        }
        Ok(())
    }

    /// The index just past the next `\r\n` at or after `from`.
    fn line_end(&mut self, from: usize) -> Result<usize, Fault> {
        let mut scanned = from;
        loop {
            if let Some(at) = self.buf[scanned..].windows(2).position(|w| w == b"\r\n") {
                return Ok(scanned + at + 2);
            }
            scanned = self.buf.len().saturating_sub(1).max(from);
            if !self.fill()? {
                return Err("the connection ended inside a line".into());
            }
        }
    }

    fn exchange(&mut self, request: &[u8]) -> Result<Answer, Fault> {
        let start = Instant::now();
        self.wire.write_all(request)?;
        self.wire.flush()?;
        // The head.
        let head_end = loop {
            if let Some(at) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if !self.fill()? {
                return Err("the connection ended before an answer".into());
            }
        };
        let head = String::from_utf8_lossy(&self.buf[..head_end]).to_ascii_lowercase();
        let status: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or("an answer without a status")?;
        let field = |name: &str| {
            head.lines()
                .find_map(|line| line.strip_prefix(name))
                .map(|value| value.trim().to_owned())
        };
        let mut closed = field("connection:").is_some_and(|value| value == "close");
        let chunked = field("transfer-encoding:").is_some_and(|value| value.contains("chunked"));
        let length: Option<usize> = field("content-length:").and_then(|value| value.parse().ok());
        self.buf.drain(..head_end);

        let mut first = None;
        if chunked {
            loop {
                let line = self.line_end(0)?;
                let size = usize::from_str_radix(
                    String::from_utf8_lossy(&self.buf[..line - 2])
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim(),
                    16,
                )?;
                self.buf.drain(..line);
                if size == 0 {
                    // Trailers, then the empty line.
                    loop {
                        let end = self.line_end(0)?;
                        let empty = end == 2;
                        self.buf.drain(..end);
                        if empty {
                            break;
                        }
                    }
                    break;
                }
                self.need(1)?;
                first.get_or_insert_with(|| start.elapsed());
                self.need(size + 2)?;
                self.buf.drain(..size + 2);
            }
        } else if let Some(length) = length {
            if length != 0 {
                self.need(1)?;
                first.get_or_insert_with(|| start.elapsed());
            }
            self.need(length)?;
            self.buf.drain(..length);
        } else if status != 204 && status != 304 {
            // No length and not chunked: the body runs to the end of the connection.
            closed = true;
            loop {
                if !self.buf.is_empty() {
                    first.get_or_insert_with(|| start.elapsed());
                }
                if !self.fill()? {
                    break;
                }
            }
            self.buf.clear();
        }
        let whole = start.elapsed();
        Ok(Answer {
            status,
            first: first.unwrap_or(whole),
            whole,
            closed,
        })
    }
}

/// The server's user plus system time so far, microseconds.
fn cpu_us(pid: u32) -> u64 {
    let ticks_per_s: u64 = std::env::var("PERF_CLK_TCK")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // The command name may hold spaces: the numbered fields start after its closing bracket.
    let Some(after) = stat.rsplit_once(')') else {
        return 0;
    };
    let fields: Vec<&str> = after.1.split_whitespace().collect();
    // utime and stime are fields 14 and 15 of the line, 11 and 12 after the name.
    let ticks: u64 = [11usize, 12]
        .iter()
        .filter_map(|&at| fields.get(at).and_then(|value| value.parse::<u64>().ok()))
        .sum();
    ticks * 1_000_000 / ticks_per_s
}

fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
            })
        })
        .unwrap_or(0)
}

fn percentile(sorted: &[u64], per_mille: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let at = (sorted.len() * per_mille / 1000).min(sorted.len() - 1);
    sorted[at] as f64 / 1000.0
}

/// `keep`: every operation is one request on a connection kept open. `new`: every operation is
/// a connection opened, one request with `connection: close`, and the connection read to its end.
fn drive(mode: &str, args: &[String]) -> Result<(), Fault> {
    let [label, threads, n, warm, addr, pid, route, rest @ ..] = args else {
        return Err("keep|new <label> <threads> <n> <warm> <addr> <pid> <route> [tls]".into());
    };
    let (threads, n, warm): (usize, usize, usize) = (threads.parse()?, n.parse()?, warm.parse()?);
    let pid: u32 = pid.parse()?;
    let route = Route::parse(route)?;
    let target = Target::parse(addr, rest.first())?;
    let fresh = mode == "new";
    let request = Arc::new(route.request(addr, fresh));

    let run = |count: usize| -> Result<(Vec<u64>, Vec<u64>), Fault> {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                let (target, request) = (target.clone(), Arc::clone(&request));
                std::thread::spawn(move || -> Result<(Vec<u64>, Vec<u64>), Fault> {
                    let mut whole = Vec::with_capacity(count);
                    let mut first = Vec::with_capacity(count);
                    let mut kept: Option<Http> = None;
                    for _ in 0..count {
                        let start = Instant::now();
                        let mut http = match kept.take() {
                            Some(http) if !fresh => http,
                            _ => Http::new(target.open()?),
                        };
                        let answer = http.exchange(&request)?;
                        if answer.status != 200 {
                            return Err(format!("status {}", answer.status).into());
                        }
                        if fresh {
                            // The operation is the whole life of the connection.
                            drop(http);
                            whole.push(start.elapsed().as_nanos() as u64);
                        } else {
                            whole.push(answer.whole.as_nanos() as u64);
                            if !answer.closed {
                                kept = Some(http);
                            }
                        }
                        first.push(answer.first.as_nanos() as u64);
                    }
                    Ok((whole, first))
                })
            })
            .collect();
        let (mut whole, mut first) = (Vec::new(), Vec::new());
        for worker in workers {
            let (w, f) = worker.join().map_err(|_| "a client thread panicked")??;
            whole.extend(w);
            first.extend(f);
        }
        whole.sort_unstable();
        first.sort_unstable();
        Ok((whole, first))
    };

    run(warm)?;
    let (rss_before, cpu_before) = (rss_kib(pid), cpu_us(pid));
    let (whole, first) = run(n)?;
    let (rss_after, cpu_after) = (rss_kib(pid), cpu_us(pid));
    let ops = whole.len();
    println!(
        "{label}\t{mode}\t{}\t{}\t{threads}\t{ops}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{:.1}\t{rss_before}\t{rss_after}\t",
        route.name(),
        target.transport(),
        percentile(&whole, 500),
        percentile(&whole, 990),
        percentile(&first, 500),
        percentile(&first, 990),
        (cpu_after.saturating_sub(cpu_before)) as f64 / ops.max(1) as f64,
    );
    Ok(())
}

/// Memory per connection: resident memory with `conns` connections open and idle (over TLS,
/// after the handshake), and again after one request on each, both against the memory before.
fn idle(args: &[String]) -> Result<(), Fault> {
    let [label, conns, addr, pid, route, rest @ ..] = args else {
        return Err("idle <label> <conns> <addr> <pid> <route> [tls]".into());
    };
    let conns: usize = conns.parse()?;
    let pid: u32 = pid.parse()?;
    let route = Route::parse(route)?;
    let target = Target::parse(addr, rest.first())?;
    let request = route.request(addr, false);
    let settle = Duration::from_millis(500);

    let before = rss_kib(pid);
    let mut held = Vec::with_capacity(conns);
    for _ in 0..conns {
        held.push(Http::new(target.open()?));
    }
    std::thread::sleep(settle);
    let open = rss_kib(pid);
    for http in &mut held {
        let answer = http.exchange(&request)?;
        if answer.status != 200 {
            return Err(format!("status {}", answer.status).into());
        }
    }
    std::thread::sleep(settle);
    let used = rss_kib(pid);
    let per = |after: u64| after.saturating_sub(before) * 1024 / conns.max(1) as u64;
    for (mode, after) in [("idle", open), ("idle-after-one", used)] {
        println!(
            "{label}\t{mode}\t{}\t{}\t1\t{conns}\t\t\t\t\t\t{before}\t{after}\t{}",
            route.name(),
            target.transport(),
            per(after),
        );
    }
    drop(held);
    Ok(())
}

fn wait(args: &[String]) -> Result<(), Fault> {
    let [addr, route, rest @ ..] = args else {
        return Err("wait <addr> <route> [tls]".into());
    };
    let route = Route::parse(route)?;
    let target = Target::parse(addr, rest.first())?;
    let request = route.request(addr, true);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answered = target
            .open()
            .and_then(|wire| Http::new(wire).exchange(&request))
            .is_ok_and(|answer| answer.status == 200);
        if answered {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{addr} did not answer {} within 60 s", route.name()).into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// THE UPSTREAM STUB: a provider that answers `POST /v1/messages` at once, whole or (when the
/// request says `"stream":true`) as a server-sent event stream of [`STUB_DELTAS`] text pieces.
/// One thread per connection; it measures nothing.
const STUB_DELTAS: usize = 16;

fn stub(args: &[String]) -> Result<(), Fault> {
    let [port] = args else {
        return Err("stub <port>".into());
    };
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        std::thread::spawn(move || {
            let _ = conn.set_nodelay(true);
            let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
            let mut chunk = [0u8; 8 * 1024];
            loop {
                let head_end = loop {
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                while buf.len() < head_end + length {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = String::from_utf8_lossy(&buf[head_end..head_end + length]).into_owned();
                buf.drain(..head_end + length);
                let streamed = body.replace(' ', "").contains("\"stream\":true");
                let sent = if streamed {
                    stub_stream(&mut conn)
                } else {
                    let answer = "{\"id\":\"msg_stub\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"stub\",\"content\":[{\"type\":\"text\",\"text\":\"pong\"}],\"stop_reason\":\"end_turn\",\"stop_sequence\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}";
                    conn.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{answer}",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                };
                if sent.is_err() {
                    return;
                }
            }
        });
    }
    Ok(())
}

fn stub_stream(conn: &mut TcpStream) -> std::io::Result<()> {
    fn event(conn: &mut TcpStream, name: &str, data: &str) -> std::io::Result<()> {
        let frame = format!("event: {name}\ndata: {data}\n\n");
        conn.write_all(format!("{:x}\r\n{frame}\r\n", frame.len()).as_bytes())
    }
    conn.write_all(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\n\r\n",
    )?;
    event(conn, "message_start", "{\"type\":\"message_start\",\"message\":{\"id\":\"msg_stub\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"stub\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}")?;
    event(conn, "content_block_start", "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}")?;
    for _ in 0..STUB_DELTAS {
        event(conn, "content_block_delta", "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"pong \"}}")?;
    }
    event(
        conn,
        "content_block_stop",
        "{\"type\":\"content_block_stop\",\"index\":0}",
    )?;
    event(conn, "message_delta", "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":16}}")?;
    event(conn, "message_stop", "{\"type\":\"message_stop\"}")?;
    conn.write_all(b"0\r\n\r\n")?;
    conn.flush()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let done = match args.first().map(String::as_str) {
        Some("stub") => stub(&args[1..]),
        Some("wait") => wait(&args[1..]),
        Some(mode @ ("keep" | "new")) => drive(mode, &args[1..]),
        Some("idle") => idle(&args[1..]),
        Some("header") => {
            println!("{HEADER}");
            Ok(())
        }
        _ => Err("perf-bar stub|wait|keep|new|idle|header (see the head of main.rs)".into()),
    };
    if let Err(fault) = done {
        eprintln!("perf-bar: {fault}");
        std::process::exit(1);
    }
}
