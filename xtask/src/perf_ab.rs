//! `cargo xtask perf-ab` — THE SAME-MACHINE A/B: a base busbar against a candidate busbar on the
//! llm path, one command, anywhere the tree is checked out.
//!
//! It measures a same-machine A/B against the published 1.5.5 on the llm path against the release
//! tolerances (p50 ≤ +5 %, p99 ≤ +10 %, req/s ≥ −5 %) plus 2,000 concurrent streams, and runs after
//! every landing as a report-only trend line. It NEVER gates: the pass/fail A/B is a separate,
//! later release check, so this command has no pass/fail mode at all — a breach of the tolerances
//! is printed and the run exits 0.
//!
//! WHAT ONE RUN DOES. For each concurrency level (default 1, 64, 512) it boots the base, loads it
//! closed-loop for `--secs` after a warm-up, stops it, then does the same for the candidate — the two
//! runs of a level are back to back, so machine drift lands on both. Each binary gets a fresh config
//! directory, a fresh key and the same upstream: a deterministic openai-dialect mock in a child
//! process (so the mock's threads and sockets are never the load generator's). Then the streams
//! cell: `--streams` concurrent streaming requests (default 2,000), each answered by the mock as a
//! paced SSE stream, measured for completion, time-to-first-byte and time-to-last-byte.
//!
//! WHAT IT PRINTS: per level, base and candidate p50/p99 latency and req/s with the deltas; for the
//! streams cell, completed/failed and TTFB/TTLB p50/p99 with the deltas. With `--trend <file>` it
//! appends ONE line to that file (TSV, header written when the file is new). A level outside the
//! spec's tolerances (p50 ≤ +5 %, p99 ≤ +10 %, req/s ≥ −5 %) or a stream that did not complete is
//! REPORTED, never failed on (report-only — the trend line). A harness that could not measure (a boot
//! that never came up, a mint that failed) is exit 3: no number is not a good number.
//!
//! THE BASE defaults to the published 1.5.5 binary exactly where `./bin/oracle fetch-golden` puts it
//! (`~/.cache/busbar-oracle/1.5.5/busbar`; that command verifies it against the pinned digests), and
//! the sha256 of whatever base ran is printed and written into the trend line. `--base` overrides it.
//!
//! THE CONFIG is 1.5.5-shaped (one openai provider, one priced model, the key chain). A candidate that
//! refuses it is taken through its own `--migrate-config`, and a refusal naming billable classes the
//! card leaves unpriced is answered as the operator upgrade does (each named class at 0) — the same
//! two steps the shadow oracle applies to a candidate boot.
//!
//! Std only, like the rest of xtask: threads and blocking sockets, no async runtime.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const USAGE: &str = "\
usage: cargo xtask perf-ab [--base <busbar>] [--candidate <busbar>] [--conc 1,64,512] [--secs 10]
                           [--warmup 2] [--streams 2000] [--stream-chunks 20] [--stream-gap-ms 50]
                           [--trend <file>] [--label <text>]
  defaults: --base = the published 1.5.5 (~/.cache/busbar-oracle/1.5.5/busbar, via ./bin/oracle fetch-golden)
            --candidate = target/release/busbar
  report-only: a breach of p50 <= +5%, p99 <= +10%, req/s >= -5% or an incomplete stream is printed,
  never failed on (exit 0 on any measurement). exit 3 = the harness could not measure.";

/// The release tolerances the report compares against.
pub const P50_MAX_PCT: f64 = 5.0;
pub const P99_MAX_PCT: f64 = 10.0;
pub const RPS_MIN_PCT: f64 = -5.0;

#[derive(Debug, Clone)]
struct Opts {
    base: Option<PathBuf>,
    candidate: PathBuf,
    conc: Vec<usize>,
    secs: u64,
    warmup: u64,
    streams: usize,
    stream_chunks: usize,
    stream_gap_ms: u64,
    trend: Option<PathBuf>,
    label: String,
}

fn parse(root: &Path, args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        base: None,
        candidate: root.join("target/release/busbar"),
        conc: vec![1, 64, 512],
        secs: 10,
        warmup: 2,
        streams: 2000,
        stream_chunks: 20,
        stream_gap_ms: 50,
        trend: None,
        label: String::new(),
    };
    let mut i = 0;
    let val = |i: usize| -> Result<&String, String> {
        args.get(i + 1)
            .ok_or_else(|| format!("{} needs a value", args[i]))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--base" => o.base = Some(PathBuf::from(val(i)?)),
            "--candidate" => o.candidate = PathBuf::from(val(i)?),
            "--conc" => {
                o.conc = val(i)?
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse::<usize>()
                            .map_err(|e| format!("--conc: {e}"))
                    })
                    .collect::<Result<_, _>>()?
            }
            "--secs" => o.secs = val(i)?.parse().map_err(|e| format!("--secs: {e}"))?,
            "--warmup" => o.warmup = val(i)?.parse().map_err(|e| format!("--warmup: {e}"))?,
            "--streams" => o.streams = val(i)?.parse().map_err(|e| format!("--streams: {e}"))?,
            "--stream-chunks" => {
                o.stream_chunks = val(i)?
                    .parse()
                    .map_err(|e| format!("--stream-chunks: {e}"))?
            }
            "--stream-gap-ms" => {
                o.stream_gap_ms = val(i)?
                    .parse()
                    .map_err(|e| format!("--stream-gap-ms: {e}"))?
            }
            "--trend" => o.trend = Some(PathBuf::from(val(i)?)),
            "--label" => o.label = val(i)?.clone(),
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 2;
    }
    if o.conc.is_empty() || o.conc.contains(&0) {
        return Err("--conc needs one or more levels, each at least 1".into());
    }
    Ok(o)
}

/// The entry point (`cargo xtask perf-ab …`).
pub fn main(root: &Path, args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    let opts = match parse(root, args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("perf-ab: {e}\n{USAGE}");
            return 2;
        }
    };
    // THE FILE-DESCRIPTOR CEILING. 512 keep-alive clients and 2,000 streams need more descriptors
    // than a default shell grants (macOS: 256). std cannot raise the limit, so the command re-runs
    // itself once under `ulimit -n` (raised to the hard limit), and every busbar it starts inherits it.
    if std::env::var_os("PERF_AB_RAISED").is_none() {
        return reexec_with_raised_fd_limit(args);
    }
    match run(root, &opts) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("perf-ab: the harness could not measure: {e}");
            3
        }
    }
}

fn reexec_with_raised_fd_limit(args: &[String]) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("perf-ab: cannot find this executable to raise the fd limit: {e}");
            return 3;
        }
    };
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("ulimit -n \"$(ulimit -Hn)\" 2>/dev/null || ulimit -n 65536 2>/dev/null; exec \"$0\" \"$@\"")
        .arg(&exe)
        .arg("perf-ab")
        .args(args)
        .env("PERF_AB_RAISED", "1");
    match cmd.status() {
        Ok(st) => st.code().unwrap_or(3),
        Err(e) => {
            eprintln!("perf-ab: could not re-run under a raised fd limit: {e}");
            3
        }
    }
}

// ── the upstream mock (a child process: `cargo xtask perf-ab-mock`) ──────────────────────────────

const CHAT_BODY: &str = "{\"id\":\"chatcmpl-perf\",\"object\":\"chat.completion\",\"created\":0,\"model\":\"m-perf\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"perf-marker\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}";

/// The mock's entry point: bind loopback, print the port, answer until killed. Every connection is
/// keep-alive HTTP/1.1; a body carrying `"stream":true` is answered as a paced SSE stream.
pub fn mock_main(args: &[String]) -> i32 {
    let arg = |k: &str, d: u64| -> u64 {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let chunks = arg("--chunks", 20) as usize;
    let gap = Duration::from_millis(arg("--gap-ms", 50));
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("perf-ab-mock: bind: {e}");
            return 3;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    println!("{port}");
    let _ = std::io::stdout().flush();
    for conn in listener.incoming().flatten() {
        let _ = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || mock_conn(conn, chunks, gap));
    }
    0
}

fn mock_conn(s: TcpStream, chunks: usize, gap: Duration) {
    let _ = s.set_nodelay(true);
    let mut w = match s.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut r = BufReader::new(s);
    while let Some((_head, body)) = read_request(&mut r) {
        let stream = find_bytes(&body, b"\"stream\":true").is_some();
        let ok = if stream {
            let mut out = String::from(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            );
            if w.write_all(out.as_bytes()).is_err() {
                return;
            }
            out.clear();
            let mut fine = true;
            for i in 0..chunks {
                let ev = format!(
                    "data: {{\"id\":\"chatcmpl-perf\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"m-perf\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"t{i} \"}},\"finish_reason\":null}}]}}\n\n"
                );
                if w.write_all(format!("{:x}\r\n{ev}\r\n", ev.len()).as_bytes())
                    .is_err()
                {
                    fine = false;
                    break;
                }
                if i + 1 < chunks {
                    std::thread::sleep(gap);
                }
            }
            if fine {
                let tail = "data: {\"id\":\"chatcmpl-perf\",\"object\":\"chat.completion.chunk\",\"created\":0,\"model\":\"m-perf\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\ndata: [DONE]\n\n";
                fine = w
                    .write_all(format!("{:x}\r\n{tail}\r\n0\r\n\r\n", tail.len()).as_bytes())
                    .is_ok();
            }
            fine
        } else {
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{CHAT_BODY}",
                CHAT_BODY.len()
            );
            w.write_all(resp.as_bytes()).is_ok()
        };
        if !ok {
            return;
        }
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// One HTTP/1.1 request (Content-Length framing), or None at EOF / on a malformed head.
fn read_request<R: BufRead>(r: &mut R) -> Option<(String, Vec<u8>)> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let len = header_value(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    Some((head, body))
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

// ── one busbar under test ────────────────────────────────────────────────────────────────────────

struct Node {
    child: Child,
    listen: u16,
    token: String,
    _dir: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-s", "TERM", &self.child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("no free port: {e}"))
}

const ADMIN_TOKEN: &str = "perf-ab-admin";

fn write_config(dir: &Path, bin: &Path, listen: u16, admin: u16, mock: u16) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let key = Command::new(bin)
        .arg("--generate-signing-key")
        .output()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    if key.stdout.is_empty() {
        return Err(format!(
            "{} --generate-signing-key printed nothing",
            bin.display()
        ));
    }
    std::fs::write(dir.join("signing.key"), &key.stdout).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("providers.yaml"),
        format!("p:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{mock}\"\n"),
    )
    .map_err(|e| e.to_string())?;
    let d = dir.display();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{listen}\"\nadmin_listen: \"127.0.0.1:{admin}\"\nproviders_file: \"{d}/providers.yaml\"\nidentity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: {{ env: BUSBAR_ADMIN_TOKEN }}\nauth:\n  chain: [keys]\n  signing_key: {{ file: \"{d}/signing.key\" }}\n  admin_auth: [admin-tokens]\ngroups:\n  perf:\n    limits:\n      - {{ budget: 100000000000000, per: day }}\nproviders:\n  p:\n    api_key: {{ env: PERF_UPSTREAM_KEY }}\nmodels:\n  m-perf:\n    provider: p\nrate_card:\n  m-perf: {{ input_utok: 1, output_utok: 1 }}\n"
        ),
    )
    .map_err(|e| e.to_string())
}

fn busbar_env(cmd: &mut Command, dir: &Path) {
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("PERF_UPSTREAM_KEY", "perf-upstream-key")
        .env("RUST_LOG", "error")
        .env("TMPDIR", dir.join("tmp"));
}

fn validate(bin: &Path, dir: &Path) -> Result<(bool, String), String> {
    let mut cmd = Command::new(bin);
    cmd.arg("--validate");
    busbar_env(&mut cmd, dir);
    let out = cmd.output().map_err(|e| e.to_string())?;
    Ok((
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        ),
    ))
}

/// Raw first; a refusal gets the candidate's own `--migrate-config`, and a refusal naming billable
/// classes the card leaves unpriced gets each of them at 0 on the one card entry (the operator
/// upgrade the shadow oracle applies too).
fn accept(bin: &Path, dir: &Path) -> Result<&'static str, String> {
    let cfg = dir.join("config.yaml");
    let (ok, text) = validate(bin, dir)?;
    if ok {
        return Ok("raw");
    }
    // The upgrade step on the RAW document first (a build that only wants the classes priced).
    if let Some(classes) = billable_gap(&text) {
        price_classes(&cfg, &classes)?;
        if validate(bin, dir)?.0 {
            return Ok("upgraded");
        }
    }
    let m = Command::new(bin)
        .arg("--migrate-config")
        .arg(&cfg)
        .output()
        .map_err(|e| e.to_string())?;
    if m.status.success() && !m.stdout.is_empty() {
        std::fs::write(&cfg, &m.stdout).map_err(|e| e.to_string())?;
    }
    for _ in 0..3 {
        let (ok, text) = validate(bin, dir)?;
        if ok {
            return Ok("migrated");
        }
        let Some(classes) = billable_gap(&text) else {
            return Err(format!("the candidate refuses the perf config:\n{text}"));
        };
        price_classes(&cfg, &classes)?;
    }
    Err("the candidate still refuses the perf config after the upgrade step".into())
}

/// Add each named class at 0 to the one card entry, flow-map or block style.
fn price_classes(cfg: &Path, classes: &[String]) -> Result<(), String> {
    let doc = std::fs::read_to_string(cfg).map_err(|e| e.to_string())?;
    let flow = classes
        .iter()
        .map(|c| format!("{c}: 0"))
        .collect::<Vec<_>>()
        .join(", ");
    let patched = if doc.contains("input_utok: 1, output_utok: 1") {
        doc.replacen(
            "input_utok: 1, output_utok: 1",
            &format!("input_utok: 1, output_utok: 1, units: {{ {flow} }}"),
            1,
        )
    } else {
        // Block style (a migrated document): a `units:` block under the entry's `output_utok:`.
        let mut out = Vec::new();
        let mut done = false;
        for line in doc.lines() {
            out.push(line.to_string());
            if !done && line.trim() == "output_utok: 1" {
                let ind = &line[..line.len() - line.trim_start().len()];
                out.push(format!("{ind}units:"));
                for c in classes {
                    out.push(format!("{ind}  {c}: 0"));
                }
                done = true;
            }
        }
        if !done {
            return Err(format!(
                "cannot place the billable classes {classes:?} on the card"
            ));
        }
        out.join("\n") + "\n"
    };
    std::fs::write(cfg, patched).map_err(|e| e.to_string())
}

fn billable_gap(text: &str) -> Option<Vec<String>> {
    let marker = "does not configure billable unit(s) ";
    let at = text.find(marker)? + marker.len();
    let rest = &text[at..];
    let end = rest.find(" declared by")?;
    Some(
        rest[..end]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn boot(bin: &Path, work: &Path, tag: &str, mock: u16) -> Result<Node, String> {
    let dir = work.join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tmp")).map_err(|e| e.to_string())?;
    let listen = free_port()?;
    let admin = free_port()?;
    write_config(&dir, bin, listen, admin, mock)?;
    accept(bin, &dir)?;
    let log = std::fs::File::create(dir.join("busbar.log")).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(bin);
    busbar_env(&mut cmd, &dir);
    let child = cmd
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let mut node = Node {
        child,
        listen,
        token: String::new(),
        _dir: dir.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(st)) = node.child.try_wait() {
            let tail = std::fs::read_to_string(dir.join("busbar.log")).unwrap_or_default();
            return Err(format!("{} exited {st} at boot:\n{tail}", bin.display()));
        }
        if let Ok((200, _)) = request(listen, "GET", "/healthz", &[], "") {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!("{} never answered /healthz", bin.display()));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let (st, body) = request(
        admin,
        "POST",
        "/api/v1/admin/keys",
        &[
            ("Authorization", &format!("Bearer {ADMIN_TOKEN}")),
            ("Content-Type", "application/json"),
        ],
        "{\"name\":\"perf\",\"group\":\"perf\"}",
    )?;
    let token = json_str_field(&body, "token")
        .ok_or_else(|| format!("minting the perf key answered {st}: {body}"))?;
    node.token = token;
    Ok(node)
}

fn json_str_field(body: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get(key)?.as_str().map(str::to_string)
}

/// One-shot request on its own connection (setup traffic, not measured).
fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, String), String> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    c.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    c.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let _ = c.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

// ── the load generator ───────────────────────────────────────────────────────────────────────────

/// A keep-alive client connection issuing one request at a time.
struct Client {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl Client {
    fn connect(port: u16) -> std::io::Result<Self> {
        let s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(Duration::from_secs(60)))?;
        Ok(Self {
            w: s.try_clone()?,
            r: BufReader::new(s),
        })
    }

    /// Send `req`; return (status, time to the first body byte, time to the end of the body).
    fn exchange(&mut self, req: &[u8]) -> std::io::Result<(u16, Duration, Duration)> {
        let t0 = Instant::now();
        self.w.write_all(req)?;
        let mut line = String::new();
        self.r.read_line(&mut line)?;
        let status = line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut len: Option<usize> = None;
        let mut chunked = false;
        let mut close = false;
        loop {
            line.clear();
            if self.r.read_line(&mut line)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            if line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let (k, v) = (k.trim(), v.trim());
                if k.eq_ignore_ascii_case("content-length") {
                    len = v.parse().ok();
                } else if k.eq_ignore_ascii_case("transfer-encoding")
                    && v.eq_ignore_ascii_case("chunked")
                {
                    chunked = true;
                } else if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close") {
                    close = true;
                }
            }
        }
        let mut first: Option<Duration> = None;
        if chunked {
            loop {
                line.clear();
                self.r.read_line(&mut line)?;
                let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
                    .unwrap_or(0);
                if first.is_none() {
                    first = Some(t0.elapsed());
                }
                let mut buf = vec![0u8; n + 2];
                self.r.read_exact(&mut buf)?;
                if n == 0 {
                    break;
                }
            }
        } else if let Some(n) = len {
            let mut buf = vec![0u8; n];
            self.r.read_exact(&mut buf)?;
            first = Some(t0.elapsed());
        } else {
            let mut buf = Vec::new();
            self.r.read_to_end(&mut buf)?;
            first = Some(t0.elapsed());
            close = true;
        }
        if close {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        Ok((status, first.unwrap_or_default(), t0.elapsed()))
    }
}

fn chat_request(port: u16, token: &str, stream: bool) -> Vec<u8> {
    let body = if stream {
        "{\"model\":\"m-perf\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}"
    } else {
        "{\"model\":\"m-perf\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}"
    };
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[derive(Debug, Clone, Default)]
struct LoadResult {
    ok: u64,
    errors: u64,
    p50_us: f64,
    p99_us: f64,
    rps: f64,
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)] as f64
}

/// Closed loop: `conc` connections, each issuing back-to-back requests, measured for `secs` after a
/// `warmup` whose samples are discarded.
fn load(port: u16, token: &str, conc: usize, warmup: u64, secs: u64) -> LoadResult {
    let stop = Arc::new(AtomicBool::new(false));
    let measuring = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));
    let samples: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let req = Arc::new(chat_request(port, token, false));
    let mut handles = Vec::new();
    for _ in 0..conc {
        let (stop, measuring, errors, samples, req) = (
            Arc::clone(&stop),
            Arc::clone(&measuring),
            Arc::clone(&errors),
            Arc::clone(&samples),
            Arc::clone(&req),
        );
        handles.push(
            std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let mut mine = Vec::with_capacity(4096);
                    let mut client = Client::connect(port).ok();
                    while !stop.load(Ordering::Relaxed) {
                        let Some(c) = client.as_mut() else {
                            errors.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_millis(10));
                            client = Client::connect(port).ok();
                            continue;
                        };
                        match c.exchange(&req) {
                            Ok((200, _, total)) => {
                                if measuring.load(Ordering::Relaxed) {
                                    mine.push(total.as_micros() as u64);
                                }
                            }
                            Ok(_) => {
                                if measuring.load(Ordering::Relaxed) {
                                    errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                if measuring.load(Ordering::Relaxed) {
                                    errors.fetch_add(1, Ordering::Relaxed);
                                }
                                client = Client::connect(port).ok();
                            }
                        }
                    }
                    if let Ok(mut s) = samples.lock() {
                        s.extend(mine);
                    }
                })
                .expect("spawn a load thread"),
        );
    }
    std::thread::sleep(Duration::from_secs(warmup));
    measuring.store(true, Ordering::Relaxed);
    let t0 = Instant::now();
    std::thread::sleep(Duration::from_secs(secs));
    measuring.store(false, Ordering::Relaxed);
    let elapsed = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let mut s = samples.lock().map(|g| g.clone()).unwrap_or_default();
    s.sort_unstable();
    LoadResult {
        ok: s.len() as u64,
        errors: errors.load(Ordering::Relaxed),
        p50_us: percentile(&s, 0.50),
        p99_us: percentile(&s, 0.99),
        rps: s.len() as f64 / elapsed.as_secs_f64(),
    }
}

#[derive(Debug, Clone, Default)]
struct StreamResult {
    n: usize,
    completed: usize,
    ttfb_p50_ms: f64,
    ttfb_p99_ms: f64,
    ttlb_p50_ms: f64,
    ttlb_p99_ms: f64,
}

/// `n` concurrent streaming requests, released together.
fn streams(port: u16, token: &str, n: usize) -> StreamResult {
    let req = Arc::new(chat_request(port, token, true));
    let gate = Arc::new(std::sync::Barrier::new(n + 1));
    let out: Arc<Mutex<Vec<(Duration, Duration)>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..n {
        let (req, gate, out) = (Arc::clone(&req), Arc::clone(&gate), Arc::clone(&out));
        handles.push(
            std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    let client = Client::connect(port);
                    gate.wait();
                    if let Ok(mut c) = client {
                        if let Ok((200, first, total)) = c.exchange(&req) {
                            if let Ok(mut o) = out.lock() {
                                o.push((first, total));
                            }
                        }
                    }
                })
                .expect("spawn a stream thread"),
        );
    }
    gate.wait();
    for h in handles {
        let _ = h.join();
    }
    let got = out.lock().map(|g| g.clone()).unwrap_or_default();
    let mut ttfb: Vec<u64> = got.iter().map(|(f, _)| f.as_micros() as u64).collect();
    let mut ttlb: Vec<u64> = got.iter().map(|(_, t)| t.as_micros() as u64).collect();
    ttfb.sort_unstable();
    ttlb.sort_unstable();
    StreamResult {
        n,
        completed: got.len(),
        ttfb_p50_ms: percentile(&ttfb, 0.50) / 1000.0,
        ttfb_p99_ms: percentile(&ttfb, 0.99) / 1000.0,
        ttlb_p50_ms: percentile(&ttlb, 0.50) / 1000.0,
        ttlb_p99_ms: percentile(&ttlb, 0.99) / 1000.0,
    }
}

// ── the run ──────────────────────────────────────────────────────────────────────────────────────

fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::sha256::hex(&bytes))
}

/// The published 1.5.5 base, where `./bin/oracle fetch-golden` installs it. That command verifies
/// the download and the extracted binary against the pinned digests on every call; this harness does
/// not re-read the oracle's pin file (xtask reads no oracle data it is not allowlisted for — the
/// segregation gate), it RECORDS the base's sha256 in the report and the trend line instead, so a run
/// against anything else is visible in its own output.
fn default_base() -> Result<(PathBuf, String), String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let cache = std::env::var_os("BUSBAR_ORACLE_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".cache/busbar-oracle"));
    let bin = cache.join("1.5.5/busbar");
    if !bin.is_file() {
        return Err(format!(
            "the published 1.5.5 base is not at {} — run `./bin/oracle fetch-golden` first, or pass --base",
            bin.display()
        ));
    }
    let digest = sha256_hex(&bin)?;
    Ok((bin, digest))
}

fn pct(base: f64, cand: f64) -> f64 {
    if base == 0.0 {
        return 0.0;
    }
    (cand - base) / base * 100.0
}

fn run(root: &Path, o: &Opts) -> Result<i32, String> {
    let (base, base_digest) = match &o.base {
        Some(b) => (b.clone(), sha256_hex(b)?),
        None => default_base()?,
    };
    let cand_digest = sha256_hex(&o.candidate)?;
    let work = std::env::temp_dir().join(format!("busbar-perf-ab-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;

    // The mock, a child of this process.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut mock = Command::new(&exe)
        .args([
            "perf-ab-mock",
            "--chunks",
            &o.stream_chunks.to_string(),
            "--gap-ms",
            &o.stream_gap_ms.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("the mock: {e}"))?;
    let mock_port: u16 = {
        let mut line = String::new();
        let out = mock.stdout.take().ok_or("the mock has no stdout")?;
        BufReader::new(out)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        line.trim()
            .parse()
            .map_err(|_| format!("the mock printed no port: {line:?}"))?
    };
    struct Reap(Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _mock = Reap(mock);

    println!(
        "perf-ab: base      {} (sha256 {})",
        base.display(),
        &base_digest[..16]
    );
    println!(
        "perf-ab: candidate {} (sha256 {})",
        o.candidate.display(),
        &cand_digest[..16]
    );
    println!(
        "perf-ab: levels {:?}, {}s measured after {}s warm-up; streams {} x {} chunks @ {}ms",
        o.conc, o.secs, o.warmup, o.streams, o.stream_chunks, o.stream_gap_ms
    );

    let mut rows: Vec<(usize, LoadResult, LoadResult)> = Vec::new();
    for &c in &o.conc {
        let mut pair = Vec::new();
        for (tag, bin) in [("base", &base), ("candidate", &o.candidate)] {
            let node = boot(bin, &work, &format!("{tag}-c{c}"), mock_port)?;
            let r = load(node.listen, &node.token, c, o.warmup, o.secs);
            drop(node);
            if r.ok == 0 {
                return Err(format!(
                    "{tag} served no request at concurrency {c} ({} errors)",
                    r.errors
                ));
            }
            pair.push(r);
        }
        let cand = pair.pop().expect("two");
        let base_r = pair.pop().expect("two");
        rows.push((c, base_r, cand));
    }
    let mut stream_pair: Option<(StreamResult, StreamResult)> = None;
    if o.streams > 0 {
        let mut pair = Vec::new();
        for (tag, bin) in [("base", &base), ("candidate", &o.candidate)] {
            let node = boot(bin, &work, &format!("{tag}-streams"), mock_port)?;
            pair.push(streams(node.listen, &node.token, o.streams));
        }
        let cand = pair.pop().expect("two");
        let b = pair.pop().expect("two");
        stream_pair = Some((b, cand));
    }
    let _ = std::fs::remove_dir_all(&work);

    // Report.
    println!();
    println!(
        "{:>5}  {:>10} {:>10} {:>8}  {:>10} {:>10} {:>8}  {:>10} {:>10} {:>8}",
        "conc",
        "p50 base",
        "p50 cand",
        "Δ%",
        "p99 base",
        "p99 cand",
        "Δ%",
        "rps base",
        "rps cand",
        "Δ%"
    );
    let mut breaches: Vec<String> = Vec::new();
    for (c, b, k) in &rows {
        let (d50, d99, drps) = (
            pct(b.p50_us, k.p50_us),
            pct(b.p99_us, k.p99_us),
            pct(b.rps, k.rps),
        );
        println!(
            "{c:>5}  {:>8.0}µs {:>8.0}µs {d50:>+7.1}%  {:>8.0}µs {:>8.0}µs {d99:>+7.1}%  {:>10.0} {:>10.0} {drps:>+7.1}%{}",
            b.p50_us,
            k.p50_us,
            b.p99_us,
            k.p99_us,
            b.rps,
            k.rps,
            if b.errors + k.errors > 0 {
                format!("  (errors: base {}, candidate {})", b.errors, k.errors)
            } else {
                String::new()
            }
        );
        if d50 > P50_MAX_PCT {
            breaches.push(format!("c={c}: p50 {d50:+.1}% > +{P50_MAX_PCT}%"));
        }
        if d99 > P99_MAX_PCT {
            breaches.push(format!("c={c}: p99 {d99:+.1}% > +{P99_MAX_PCT}%"));
        }
        if drps < RPS_MIN_PCT {
            breaches.push(format!("c={c}: req/s {drps:+.1}% < {RPS_MIN_PCT}%"));
        }
    }
    if let Some((b, k)) = &stream_pair {
        println!();
        println!(
            "streams-{}: completed base {}/{} candidate {}/{} · TTFB p50 {:.1}→{:.1}ms p99 {:.1}→{:.1}ms ({:+.1}%) · TTLB p50 {:.1}→{:.1}ms p99 {:.1}→{:.1}ms ({:+.1}%)",
            b.n,
            b.completed,
            b.n,
            k.completed,
            k.n,
            b.ttfb_p50_ms,
            k.ttfb_p50_ms,
            b.ttfb_p99_ms,
            k.ttfb_p99_ms,
            pct(b.ttfb_p99_ms, k.ttfb_p99_ms),
            b.ttlb_p50_ms,
            k.ttlb_p50_ms,
            b.ttlb_p99_ms,
            k.ttlb_p99_ms,
            pct(b.ttlb_p99_ms, k.ttlb_p99_ms)
        );
        if k.completed < k.n {
            breaches.push(format!("streams-{}: only {} completed", k.n, k.completed));
        }
    }

    if let Some(trend) = &o.trend {
        append_trend(
            root,
            trend,
            o,
            &base_digest,
            &cand_digest,
            &rows,
            stream_pair.as_ref(),
        )?;
        println!("\nperf-ab: appended one line to {}", trend.display());
    }

    if breaches.is_empty() {
        println!("\nperf-ab: within tolerance (p50 ≤ +{P50_MAX_PCT}%, p99 ≤ +{P99_MAX_PCT}%, req/s ≥ {RPS_MIN_PCT}%)");
        Ok(0)
    } else {
        println!(
            "\nperf-ab: report-only — outside tolerance (not failing):\n  {}",
            breaches.join("\n  ")
        );
        Ok(0)
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn append_trend(
    root: &Path,
    trend: &Path,
    o: &Opts,
    base_digest: &str,
    cand_digest: &str,
    rows: &[(usize, LoadResult, LoadResult)],
    streams: Option<&(StreamResult, StreamResult)>,
) -> Result<(), String> {
    let path = if trend.is_absolute() {
        trend.to_path_buf()
    } else {
        root.join(trend)
    };
    let mut cols: BTreeMap<usize, String> = BTreeMap::new();
    for (c, b, k) in rows {
        cols.insert(
            *c,
            format!(
                "c{c}:p50 {:.0}/{:.0}us {:+.1}% p99 {:.0}/{:.0}us {:+.1}% rps {:.0}/{:.0} {:+.1}%",
                b.p50_us,
                k.p50_us,
                pct(b.p50_us, k.p50_us),
                b.p99_us,
                k.p99_us,
                pct(b.p99_us, k.p99_us),
                b.rps,
                k.rps,
                pct(b.rps, k.rps)
            ),
        );
    }
    let s = streams.map_or_else(
        || "streams:skipped".to_string(),
        |(b, k)| {
            format!(
                "streams-{}: done {}/{} ttfb-p99 {:.1}/{:.1}ms ttlb-p99 {:.1}/{:.1}ms",
                k.n,
                b.completed,
                k.completed,
                b.ttfb_p99_ms,
                k.ttfb_p99_ms,
                b.ttlb_p99_ms,
                k.ttlb_p99_ms
            )
        },
    );
    let when = git(root, &["log", "-1", "--format=%cI"]);
    let line = format!(
        "{when}\t{}\t{}\t{}\t{}\t{}\t{}\n",
        git(root, &["rev-parse", "--short", "HEAD"]),
        if o.label.is_empty() { "-" } else { &o.label },
        &base_digest[..12],
        &cand_digest[..12],
        cols.into_values().collect::<Vec<_>>().join(" | "),
        s
    );
    let new = !path.exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if new {
        f.write_all(b"# cargo xtask perf-ab trend (report-only; base = published 1.5.5 unless noted). commit-time\tcommit\tlabel\tbase-sha256\tcandidate-sha256\tlevels (base/candidate, delta)\tstreams\n")
            .map_err(|e| e.to_string())?;
    }
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spec_tolerances_are_the_design_numbers() {
        assert_eq!((P50_MAX_PCT, P99_MAX_PCT, RPS_MIN_PCT), (5.0, 10.0, -5.0));
    }

    #[test]
    fn a_billable_gap_names_its_classes() {
        let t = "BUSBAR-9007: pools.rate_card does not configure billable unit(s) search_units, x declared by this plane (declared: …)";
        assert_eq!(
            billable_gap(t),
            Some(vec!["search_units".to_string(), "x".to_string()])
        );
        assert_eq!(billable_gap("fine"), None);
    }

    #[test]
    fn percentiles_read_the_sorted_samples() {
        let s: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&s, 0.5), 51.0);
        assert_eq!(percentile(&s, 0.99), 99.0);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn arguments_parse_and_refuse() {
        let root = Path::new("/r");
        let o = parse(root, &["--conc".into(), "1,8".into()]).unwrap();
        assert_eq!(o.conc, vec![1, 8]);
        // Report-only: there is no pass/fail mode to ask for.
        assert!(parse(root, &["--gate".into()]).is_err());
        assert!(parse(root, &["--conc".into(), "0".into()]).is_err());
        assert!(parse(root, &["--bogus".into()]).is_err());
    }

    /// The mock and the client agree on keep-alive framing, buffered and streamed.
    #[test]
    fn the_mock_answers_keep_alive_and_streams() {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                std::thread::spawn(move || mock_conn(c, 3, Duration::from_millis(1)));
            }
        });
        let mut c = Client::connect(port).unwrap();
        for _ in 0..3 {
            let (st, _, _) = c.exchange(&chat_request(port, "t", false)).unwrap();
            assert_eq!(st, 200);
        }
        let (st, first, total) = c.exchange(&chat_request(port, "t", true)).unwrap();
        assert_eq!(st, 200);
        assert!(first <= total);
    }
}
