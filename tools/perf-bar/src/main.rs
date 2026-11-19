// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The measurement client of DONE statement 5: one black-box method for every serving binary,
//! v1.5.5 included. It is the load generator and the stub of the v1.5.5 baseline (perf-155
//! `loadgen.rs`, `stub.rs`) with the same request bytes, the same timed sections, the same
//! percentile and the same memory reading, extended by the two things the baseline left out:
//! TLS, and a streamed answer.
//!
//! ```text
//! perf-bar stub <port> <threads>
//! perf-bar wait <port> [tls]
//! perf-bar keep <label> <threads> <n> <warm> <port> <pid> <route> [tls]
//! perf-bar new  <label> <threads> <n> <warm> <port> <pid> <route> [tls]
//! perf-bar hold <label> <connections> <port> <pid> <route> [tls]
//! perf-bar header
//! ```
//! `keep`: each thread opens ONE connection and sends warm+n requests on it. `new`: each thread
//! sends warm+n requests, each on a NEW connection, and closes it. `hold`: open the connections,
//! hold them idle, read the server's resident memory before, idle, and after one request on each.
//! `route`: `healthz` (GET /healthz), `chat` (POST /v1/messages, whole answer) or `stream` (the
//! same request with `"stream":true`). `tls` is `tls:<ca.pem>:<server name>`. `pid` is the
//! server's process id: its user plus system CPU time is read from /proc around the timed section
//! only.
//!
//! A request's time runs from just before connect() (`new`; over TLS that includes the whole
//! handshake) or just before the write (`keep`) to the last byte of the response. `first` is the
//! same start to the first byte of the response body. In `new` and `hold` the destination
//! address rotates over 127.0.0.1 to 127.0.0.200 so closed connections waiting out TIME_WAIT
//! never exhaust the local port range.
//!
//! Every run prints one tab-separated row ([`HEADER`]); times are nanoseconds.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const HEADER: &str = "label\tmode\troute\ttransport\tthreads\tn_per_thread\tmed_ns\tp99_ns\tmean_ns\tfirst_med_ns\tfirst_p99_ns\tconnect_med_ns\tconnect_p99_ns\tserver_cpu_ns_per_req\tnot_200\tclosed_by_server\trss_before_kib\trss_idle_kib\trss_after_one_request_kib\tper_idle_connection_bytes\tper_used_connection_bytes";

const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
const CHAT_BODY: &str =
    r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
const STREAM_BODY: &str = r#"{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"stream":true}"#;

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
    port: u16,
    tls: Option<Tls>,
}

impl Target {
    fn parse(port: &str, tls: Option<&String>) -> Result<Self, Fault> {
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
            port: port.parse()?,
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

    /// One connection ready for a request, and how long connect() itself took.
    fn open(&self, last: u8) -> Result<(Box<dyn Wire>, u64), Fault> {
        let t0 = Instant::now();
        let tcp = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, last), self.port))?;
        let connect = t0.elapsed().as_nanos() as u64;
        tcp.set_nodelay(true)?;
        match &self.tls {
            None => Ok((Box::new(tcp), connect)),
            Some(tls) => {
                let conn = rustls::ClientConnection::new(tls.config.clone(), tls.name.clone())?;
                let mut stream = rustls::StreamOwned::new(conn, tcp);
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock)?;
                }
                Ok((Box::new(stream), connect))
            }
        }
    }
}

fn request_of(route: &str) -> Result<Vec<u8>, Fault> {
    let post = |body: &str| {
        format!(
            "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
             anthropic-version: 2023-06-01\r\nx-api-key: k\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    };
    match route {
        "healthz" => Ok(HEALTHZ.to_vec()),
        "chat" => Ok(post(CHAT_BODY)),
        "stream" => Ok(post(STREAM_BODY)),
        other => Err(format!("unknown route {other}: healthz, chat or stream").into()),
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Read one response. Returns its status and the instant its first body byte arrived (the end of
/// the read that brought it). A close or reset before a full response is status 1, never a panic.
/// A chunked response is complete at its terminating chunk, as the baseline judged it.
fn response(s: &mut dyn Wire, buf: &mut Vec<u8>) -> (u16, Option<Instant>) {
    buf.clear();
    let mut chunk = [0u8; 16384];
    let mut need: Option<usize> = None;
    let mut chunked = false;
    let mut body_from: Option<usize> = None;
    let mut first: Option<Instant> = None;
    loop {
        if let Some(n) = need {
            if buf.len() >= n {
                break;
            }
        }
        if chunked && buf.ends_with(b"0\r\n\r\n") {
            break;
        }
        let n = match s.read(&mut chunk) {
            Ok(0) | Err(_) => return (1, first),
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if body_from.is_none() {
            if let Some(end) = find(buf, b"\r\n\r\n") {
                body_from = Some(end + 4);
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                if head.contains("transfer-encoding: chunked") {
                    chunked = true;
                } else {
                    let cl = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    need = Some(end + 4 + cl);
                }
            }
        }
        if first.is_none() && body_from.is_some_and(|from| buf.len() > from) {
            first = Some(Instant::now());
        }
    }
    let status = buf
        .get(9..12)
        .and_then(|digits| std::str::from_utf8(digits).ok())
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0);
    (status, first)
}

fn cpu_ns(pid: u32) -> u64 {
    if pid == 0 {
        return 0;
    }
    let ticks_per_s: u64 = std::env::var("PERF_CLK_TCK")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // The command name may hold spaces: the numbered fields start after its closing bracket.
    let Some(at) = stat.rfind(')') else {
        return 0;
    };
    let f: Vec<&str> = stat[at + 1..].split_whitespace().collect();
    // utime and stime: fields 14 and 15 of the line, 11 and 12 after the name.
    let ticks: u64 = [11usize, 12]
        .iter()
        .filter_map(|&i| f.get(i).and_then(|v| v.parse::<u64>().ok()))
        .sum();
    ticks * (1_000_000_000 / ticks_per_s)
}

fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

/// The baseline's percentile: the value at rank ceil(n * p).
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[i.saturating_sub(1).min(sorted.len() - 1)]
}

#[derive(Default)]
struct Out {
    total: Vec<u64>,
    first: Vec<u64>,
    connect: Vec<u64>,
    bad: u64,
    closed: bool,
}

fn drive(mode: &str, args: &[String]) -> Result<(), Fault> {
    let [label, threads, n, warm, port, pid, route, rest @ ..] = args else {
        return Err("keep|new <label> <threads> <n> <warm> <port> <pid> <route> [tls]".into());
    };
    let (threads, n, warm): (usize, usize, usize) = (threads.parse()?, n.parse()?, warm.parse()?);
    let pid: u32 = pid.parse()?;
    let target = Target::parse(port, rest.first())?;
    let request = Arc::new(request_of(route)?);
    let keep = mode == "keep";

    let warmed = Arc::new(Barrier::new(threads + 1));
    let go = Arc::new(Barrier::new(threads + 1));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (target, request) = (target.clone(), Arc::clone(&request));
        let (warmed, go) = (Arc::clone(&warmed), Arc::clone(&go));
        handles.push(std::thread::spawn(move || -> Result<Out, Fault> {
            let mut buf = Vec::with_capacity(65536);
            let mut out = Out::default();
            // A worker that fails before the start line still walks through both barriers, so a
            // failed connection ends the run with its error and never leaves the others waiting.
            if keep {
                let opened: Result<Box<dyn Wire>, Fault> = target.open(1).map(|(mut s, _)| {
                    for _ in 0..warm {
                        if s.write_all(&request).is_err() || response(s.as_mut(), &mut buf).0 == 1 {
                            out.closed = true;
                            break;
                        }
                    }
                    s
                });
                warmed.wait();
                go.wait();
                let mut s = opened?;
                for _ in 0..n {
                    if out.closed {
                        break;
                    }
                    let t0 = Instant::now();
                    let (status, first) = if s.write_all(&request).is_err() {
                        (1, None)
                    } else {
                        response(s.as_mut(), &mut buf)
                    };
                    let end = Instant::now();
                    if status == 1 {
                        out.closed = true;
                        break;
                    }
                    out.total.push((end - t0).as_nanos() as u64);
                    out.first
                        .push((first.unwrap_or(end) - t0).as_nanos() as u64);
                    out.bad += u64::from(status != 200);
                }
            } else {
                let mut one = |i: usize, out: Option<&mut Out>| -> Result<(), Fault> {
                    let last = 1 + ((i + t * 25) % 200) as u8;
                    let t0 = Instant::now();
                    let (mut s, connect) = target.open(last)?;
                    let _ = s.write_all(&request);
                    let (status, first) = response(s.as_mut(), &mut buf);
                    let end = Instant::now();
                    drop(s);
                    if let Some(out) = out {
                        out.total.push((end - t0).as_nanos() as u64);
                        out.first
                            .push((first.unwrap_or(end) - t0).as_nanos() as u64);
                        out.connect.push(connect);
                        out.bad += u64::from(status != 200);
                    }
                    Ok(())
                };
                let warmed_up = (0..warm).try_for_each(|i| one(i, None));
                warmed.wait();
                go.wait();
                warmed_up?;
                for i in 0..n {
                    one(warm + i, Some(&mut out))?;
                }
            }
            Ok(out)
        }));
    }
    warmed.wait();
    let cpu0 = cpu_ns(pid);
    go.wait();
    let mut outs = Vec::with_capacity(threads);
    for handle in handles {
        outs.push(handle.join().map_err(|_| "a client thread panicked")??);
    }
    let cpu1 = cpu_ns(pid);

    let sorted = |pick: fn(&Out) -> &Vec<u64>| {
        let mut all: Vec<u64> = outs.iter().flat_map(|o| pick(o).iter().copied()).collect();
        all.sort_unstable();
        all
    };
    let (total, first, connect) = (
        sorted(|o| &o.total),
        sorted(|o| &o.first),
        sorted(|o| &o.connect),
    );
    let reqs = total.len() as u64;
    let mean = total.iter().sum::<u64>() / reqs.max(1);
    let bad: u64 = outs.iter().map(|o| o.bad).sum();
    let closed = outs.iter().filter(|o| o.closed).count();
    println!(
        "{label}\t{mode}\t{route}\t{}\t{threads}\t{n}\t{}\t{}\t{mean}\t{}\t{}\t{}\t{}\t{}\t{bad}\t{closed}\t\t\t\t\t",
        target.transport(),
        pct(&total, 0.50),
        pct(&total, 0.99),
        pct(&first, 0.50),
        pct(&first, 0.99),
        pct(&connect, 0.50),
        pct(&connect, 0.99),
        cpu1.saturating_sub(cpu0) / reqs.max(1),
    );
    // A run in which the server closed a kept connection or answered other than 200 is not a
    // measurement of the route: it fails the run, as an unmeasured figure fails the verdict.
    if bad != 0 || closed != 0 || reqs == 0 {
        return Err(
            format!("{label} {mode} {route}: not_200={bad} closed_by_server={closed}").into(),
        );
    }
    Ok(())
}

/// Idle-connection memory, as the baseline's `hold`: the server's resident memory before, with
/// the connections open and idle for 3 s (over TLS: after the handshake), and 3 s after one
/// request on each.
fn hold(args: &[String]) -> Result<(), Fault> {
    let [label, connections, port, pid, route, rest @ ..] = args else {
        return Err("hold <label> <connections> <port> <pid> <route> [tls]".into());
    };
    let connections: usize = connections.parse()?;
    let pid: u32 = pid.parse()?;
    let target = Target::parse(port, rest.first())?;
    let request = request_of(route)?;

    let before = rss_kib(pid);
    let mut held = Vec::with_capacity(connections);
    for i in 0..connections {
        held.push(target.open(1 + (i % 200) as u8)?.0);
    }
    std::thread::sleep(Duration::from_secs(3));
    let idle = rss_kib(pid);
    let mut buf = Vec::new();
    let mut answered = 0usize;
    for s in &mut held {
        if s.write_all(&request).is_ok() && response(s.as_mut(), &mut buf).0 == 200 {
            answered += 1;
        }
    }
    std::thread::sleep(Duration::from_secs(3));
    let used = rss_kib(pid);
    let per = |after: u64| after.saturating_sub(before) * 1024 / connections.max(1) as u64;
    println!(
        "{label}\thold\t{route}\t{}\t1\t{connections}\t\t\t\t\t\t\t\t\t{}\t0\t{before}\t{idle}\t{used}\t{}\t{}",
        target.transport(),
        connections - answered,
        per(idle),
        per(used),
    );
    drop(held);
    if answered != connections {
        return Err(format!("{label} hold: {answered} of {connections} answered").into());
    }
    Ok(())
}

fn wait(args: &[String]) -> Result<(), Fault> {
    let [port, rest @ ..] = args else {
        return Err("wait <port> [tls]".into());
    };
    let target = Target::parse(port, rest.first())?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut buf = Vec::new();
    loop {
        if let Ok((mut s, _)) = target.open(1) {
            if s.write_all(HEALTHZ).is_ok() && response(s.as_mut(), &mut buf).0 == 200 {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("port {port} never answered /healthz").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE STUB: the baseline's upstream (each thread accepts a connection and serves it to the end;
/// a request with a body gets an anthropic-shaped message, any other gets `ok`), extended so that
/// a body saying `"stream":true` gets the same message as a server-sent event stream of
/// [`STUB_DELTAS`] text pieces, chunked.
const MESSAGE: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"test-model","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#;
const STUB_DELTAS: usize = 16;

fn stream_reply() -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    let mut event = |name: &str, data: &str| {
        let frame = format!("event: {name}\ndata: {data}\n\n");
        out.extend_from_slice(format!("{:x}\r\n{frame}\r\n", frame.len()).as_bytes());
    };
    event(
        "message_start",
        r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"test-model","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}"#,
    );
    event(
        "content_block_start",
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
    );
    for _ in 0..STUB_DELTAS {
        event(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok "}}"#,
        );
    }
    event(
        "content_block_stop",
        r#"{"type":"content_block_stop","index":0}"#,
    );
    event(
        "message_delta",
        r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":16}}"#,
    );
    event("message_stop", r#"{"type":"message_stop"}"#);
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn stub(args: &[String]) -> Result<(), Fault> {
    let [port, threads] = args else {
        return Err("stub <port> <threads>".into());
    };
    let (port, threads): (u16, usize) = (port.parse()?, threads.parse()?);
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
    let plain =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok".to_vec();
    let message = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        MESSAGE.len(),
        MESSAGE
    )
    .into_bytes();
    let streamed = stream_reply();
    let mut handles = Vec::new();
    for _ in 0..threads {
        let listener = listener.try_clone()?;
        let (plain, message, streamed) = (plain.clone(), message.clone(), streamed.clone());
        handles.push(std::thread::spawn(move || loop {
            let Ok((mut s, _)) = listener.accept() else {
                continue;
            };
            let _ = s.set_nodelay(true);
            let mut buf = [0u8; 16384];
            let mut have = 0usize;
            'conn: loop {
                let (end, body) = loop {
                    if let Some(end) = find(&buf[..have], b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                        let cl = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if have >= end + 4 + cl {
                            break (end + 4 + cl, cl);
                        }
                    }
                    if have == buf.len() {
                        break 'conn;
                    }
                    match s.read(&mut buf[have..]) {
                        Ok(0) | Err(_) => break 'conn,
                        Ok(n) => have += n,
                    }
                };
                let wants_stream =
                    body > 0 && find(&buf[end - body..end], br#""stream":true"#).is_some();
                let reply = if wants_stream {
                    &streamed
                } else if body > 0 {
                    &message
                } else {
                    &plain
                };
                if s.write_all(reply).is_err() {
                    break 'conn;
                }
                buf.copy_within(end..have, 0);
                have -= end;
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let done = match args.first().map(String::as_str) {
        Some("stub") => stub(&args[1..]),
        Some("wait") => wait(&args[1..]),
        Some(mode @ ("keep" | "new")) => drive(mode, &args[1..]),
        Some("hold") => hold(&args[1..]),
        Some("header") => {
            println!("{HEADER}");
            Ok(())
        }
        _ => Err("perf-bar stub|wait|keep|new|hold|header (see the head of main.rs)".into()),
    };
    if let Err(fault) = done {
        eprintln!("perf-bar: {fault}");
        std::process::exit(1);
    }
}
