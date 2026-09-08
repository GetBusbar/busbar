//! THE SHIPPED-PATH MEASUREMENT — boot the release binary, send one request per plane, and read
//! back from the binary's own journal WHICH HALF OF IT ANSWERED.
//!
//! `qa/teller-steps.json` makes a claim, per plane, about the shipped path: whether an arriving
//! request is answered by the kernel loop in the composition root or by the legacy plane crate the
//! root was built to replace. Before this module the matrix's own `--root-legs` arm proved
//! something weaker and easy to mistake for it — that the named unit-test cells still EXECUTE under
//! the five root features. A cell that runs is not a request that arrived, and a gate that asserts
//! something it never measures is a lie however carefully the assertion is worded.
//!
//! So this module measures it. One boot of the real, default-feature release binary against a
//! config that CLAIMS every plane, one request per leg over the wire, and the verdict read out of
//! the per-unit records the binary emits at `DEBUG`
//! (`crates/busbar/src/root/journal.rs`) — `loop` when the root's kernel loop produced the answer,
//! `legacy` when the root handed the request back to the legacy router to answer.
//!
//! ## The three verdicts, and how each is reached
//!
//! * `loop` — the leg journalled `loop` records and no `legacy` record.
//! * `split` — the leg journalled BOTH. The loop gated the request and the legacy half produced the
//!   answer bytes; that is one leg, half moved.
//! * `legacy` — the leg's probe WAS SERVED (the binary answered it with a status) and the leg
//!   journalled nothing at all. The root took no part.
//!
//! ## Why an absent record is only readable when the instrument is known to work
//!
//! "This leg emitted nothing" and "nothing emits anything, because the reader is broken, the binary
//! did not boot, the log went somewhere else or the level filter swallowed it" produce the same
//! empty set, and the second one reads as five legacy legs — the vacuous green this whole exercise
//! exists to refuse. [`Measured::vacuous`] is that floor: a run in which NO leg journalled a single
//! `loop` record is refused as an unmeasured run rather than reported as a measurement.
//!
//! ## What this probe does NOT settle, stated rather than papered over
//!
//! Two of the five probes (`mcp`, `voice`) are refused by the deployment's own admission bar before
//! they reach their plane, because both planes bind an audience that busbar's own minted keys do
//! not carry — serving them past that bar needs an OAuth issuer this measurement will not stand up.
//! For those two the measurement says exactly what it saw: the binary ANSWERED the request, and no
//! part of the composition root took part in answering it. That is a true statement about the
//! shipped path and it is a weaker one than the `a2a` and `llm` probes, which do reach their
//! planes. The union is read over the WHOLE run rather than per probe, so a leg that gains a
//! production loop site shows up the moment any request in the run reaches it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::ctx::Ctx;

/// The overlay key a selftest plants a measurement under, instead of booting anything.
pub const OVERLAY_KEY: &str = "shipped-path";

/// The planes this measurement covers, in the matrix's own spelling.
pub const LEGS: [&str; 5] = ["admin", "llm", "mcp", "a2a", "voice"];

/// The two words the binary's journal uses, and the only two this reader understands. They are the
/// contract between `crates/busbar/src/root/journal.rs` and this file.
pub const WORD_LOOP: &str = "loop";
pub const WORD_LEGACY: &str = "legacy";

/// The journal record's message, as the binary writes it.
const RECORD_MESSAGE: &str = "root served unit";

/// The three shipped-path verdicts a claim may name.
pub const VERDICTS: [&str; 3] = ["loop", "legacy", "split"];

/// How long to wait for the booted binary to answer `/healthz`.
const BOOT_BUDGET: Duration = Duration::from_secs(60);

/// The per-request socket budget. Generous: one probe deliberately dials an upstream that is not
/// there, and the answer to that is the gateway's own, not a hang.
const REQUEST_BUDGET: Duration = Duration::from_secs(20);

/// The port window this measurement is allowed to bind in. A window rather than an ephemeral port
/// because the binary prints and binds the CONFIGURED address, so the port has to be chosen before
/// the process exists; a window keeps the choice out of every other harness's way.
const PORT_LOW: u16 = 45_000;
const PORT_HIGH: u16 = 45_999;

// -------------------------------------------------------------------------------------------
// What one leg's probe observed
// -------------------------------------------------------------------------------------------

/// One leg's measurement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Observed {
    /// The HTTP status the binary answered the probe with. `None` is "the binary never answered",
    /// which is an unmeasured leg and never a verdict.
    pub status: Option<u16>,
    /// The journal words this leg emitted across the whole probe run.
    pub records: BTreeSet<String>,
    /// What the probe was, in one line, so a red names the request it was reached by.
    pub probe: String,
    /// Set when the probe itself could not be carried out. An error is never a verdict.
    pub error: Option<String>,
}

impl Observed {
    /// The measured shipped path, or the reason this leg was NOT measured.
    pub fn verdict(&self) -> Result<&'static str, String> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        if self.status.is_none() {
            return Err(format!(
                "the binary never answered the probe ({}), so nothing about this leg was measured",
                self.probe
            ));
        }
        let saw_loop = self.records.contains(WORD_LOOP);
        let saw_legacy = self.records.contains(WORD_LEGACY);
        Ok(match (saw_loop, saw_legacy) {
            (true, true) => "split",
            (true, false) => "loop",
            (false, _) => "legacy",
        })
    }

    /// The one-line evidence a report prints beside the verdict.
    pub fn evidence(&self) -> String {
        let words = if self.records.is_empty() {
            "no root record".to_string()
        } else {
            self.records.iter().cloned().collect::<Vec<_>>().join("+")
        };
        match (self.status, &self.error) {
            (_, Some(e)) => format!("{} -> NOT MEASURED: {e}", self.probe),
            (Some(s), None) => format!("{} -> HTTP {s}, {words}", self.probe),
            (None, None) => format!("{} -> no answer", self.probe),
        }
    }
}

/// Every leg's measurement, plus the floor that says the instrument worked.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Measured {
    pub legs: BTreeMap<String, Observed>,
}

impl Measured {
    /// TRUE when not one leg journalled a single `loop` record. An empty instrument reads exactly
    /// like five legacy legs, so this is refused rather than reported.
    pub fn vacuous(&self) -> bool {
        !self.legs.values().any(|o| o.records.contains(WORD_LOOP))
    }
}

// -------------------------------------------------------------------------------------------
// The planted form, for the selftest
// -------------------------------------------------------------------------------------------

/// Render a measurement in the one-line-per-leg form [`parse`] reads. The selftest builds its
/// plants by rendering a MUTATED copy of the real measurement, so a plant is always the shape the
/// real probe produces.
pub fn render(m: &Measured) -> String {
    let mut out = String::new();
    for (leg, o) in &m.legs {
        out.push_str(leg);
        if let Some(e) = &o.error {
            out.push_str(&format!(" error={}\n", e.replace(['\n', ' '], "_")));
            continue;
        }
        match o.status {
            Some(s) => out.push_str(&format!(" status={s}")),
            None => out.push_str(" status=-"),
        }
        out.push_str(&format!(
            " records={}",
            if o.records.is_empty() {
                "-".to_string()
            } else {
                o.records.iter().cloned().collect::<Vec<_>>().join(",")
            }
        ));
        out.push_str(&format!(" probe={}\n", o.probe.replace(' ', "_")));
    }
    out
}

/// Read the one-line-per-leg form back.
pub fn parse(text: &str) -> Result<Measured, String> {
    let mut m = Measured::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let leg = parts.next().ok_or("a measurement line with no leg")?;
        let mut o = Observed::default();
        for kv in parts {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| format!("{leg}: `{kv}` is not a key=value"))?;
            match k {
                "error" => o.error = Some(v.replace('_', " ")),
                "status" => {
                    o.status = if v == "-" {
                        None
                    } else {
                        Some(v.parse().map_err(|_| format!("{leg}: status `{v}`"))?)
                    };
                }
                "records" => {
                    if v != "-" {
                        o.records = v.split(',').map(str::to_string).collect();
                    }
                }
                "probe" => o.probe = v.replace('_', " "),
                other => return Err(format!("{leg}: unknown measurement key `{other}`")),
            }
        }
        m.legs.insert(leg.to_string(), o);
    }
    Ok(m)
}

// -------------------------------------------------------------------------------------------
// The measurement
// -------------------------------------------------------------------------------------------

/// The measured shipped path per leg — planted if the caller planted one, otherwise MEASURED, once
/// per process.
///
/// Memoised because the selftest runs the gate a dozen times over a dozen planted matrices, and
/// booting the binary a dozen times to answer the same question a dozen identical ways is a cost
/// with no reading behind it. The memo is keyed by nothing on purpose: the subject is the tree this
/// process was opened over, and a `Ctx` overlay never changes it — a planted measurement takes the
/// branch above and never reaches here.
pub fn measure(cx: &Ctx) -> Result<Measured, String> {
    if let Some(text) = cx.planted(OVERLAY_KEY) {
        return parse(text);
    }
    static MEMO: OnceLock<Result<Measured, String>> = OnceLock::new();
    MEMO.get_or_init(|| probe(cx)).clone()
}

/// Build the shipped binary, boot it against a config that claims every plane, drive one request
/// per leg, and read the journal back.
fn probe(cx: &Ctx) -> Result<Measured, String> {
    let bin = build_release_binary(cx)?;
    let work = cx.scratch().join("shipped-path");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;

    let data = free_port(PORT_LOW)?;
    let admin = free_port(data + 1)?;
    // Deliberately NOT bound by anything: the LLM probe's upstream. A chat completion that cannot
    // reach its provider still enters the loop, which is the only thing being measured, and not
    // standing up a mock keeps this measurement free of a second moving part.
    let upstream = free_port(admin + 1)?;

    let signing = work.join("signing.key");
    let key_material = run_capture(&bin, &["--generate-signing-key".to_string()], &work)?;
    std::fs::write(&signing, key_material).map_err(|e| format!("{}: {e}", signing.display()))?;

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        format!(
            "probe-upstream:\n  protocol: openai\n  base_url: \"http://127.0.0.1:{upstream}\"\n"
        ),
    )
    .map_err(|e| format!("{}: {e}", providers.display()))?;

    let config = work.join("config.yaml");
    std::fs::write(&config, config_yaml(data, admin, &signing, &providers))
        .map_err(|e| format!("{}: {e}", config.display()))?;

    let log = work.join("busbar.log");
    let sink = std::fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
    let errs = sink
        .try_clone()
        .map_err(|e| format!("{}: {e}", log.display()))?;
    let admin_token = "teller-steps-shipped-path-probe";
    let child = Command::new(&bin)
        .current_dir(&work)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_ADMIN_TOKEN", admin_token)
        .env("PROBE_UPSTREAM_KEY", "unused")
        // The journal is a DEBUG record and the binary's stderr filter takes a bare level word.
        .env("RUST_LOG", "debug")
        .stdout(Stdio::from(sink))
        .stderr(Stdio::from(errs))
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let mut guard = Reaped(child);

    let boot = wait_for_boot(data, &log);
    let measured = boot.and_then(|()| drive(data, admin, admin_token));
    guard.stop();
    let mut measured = measured?;

    // THE JOURNAL IS READ AT THE END AND GROUPED BY THE LEG THE BINARY NAMED, not by which probe
    // was in flight. The record carries its own leg, so attribution needs no clock — and a leg that
    // takes part in answering ANOTHER plane's request is a leg that took part, which is the honest
    // reading of "did the root serve this".
    let journal = std::fs::read_to_string(&log).map_err(|e| format!("{}: {e}", log.display()))?;
    for (leg, word) in records(&journal) {
        if let Some(o) = measured.legs.get_mut(&leg) {
            o.records.insert(word);
        }
    }
    Ok(measured)
}

/// The config every plane is claimed in. Written here as one string rather than assembled from
/// fragments: it is a fixture a reader has to be able to read, and every block in it is load-bearing
/// (a plane whose block is absent mounts no route, and a probe against no route measures nothing).
fn config_yaml(data: u16, admin: u16, signing: &Path, providers: &Path) -> String {
    format!(
        "listen: \"127.0.0.1:{data}\"\n\
         admin_listen: \"127.0.0.1:{admin}\"\n\
         public_url: \"http://127.0.0.1:{data}\"\n\
         providers_file: \"{providers}\"\n\
         identity-providers:\n\
         \x20 admin-tokens:\n\
         \x20   module: admin-tokens\n\
         \x20   token: {{ env: BUSBAR_ADMIN_TOKEN }}\n\
         auth:\n\
         \x20 chain: [keys]\n\
         \x20 signing_key: {{ file: \"{signing}\" }}\n\
         \x20 admin_auth: [admin-tokens]\n\
         groups:\n\
         \x20 probe:\n\
         \x20   limits:\n\
         \x20     - {{ budget: 1000000, per: day }}\n\
         providers:\n\
         \x20 probe-upstream:\n\
         \x20   api_key: {{ env: PROBE_UPSTREAM_KEY }}\n\
         models:\n\
         \x20 probe-model:\n\
         \x20   provider: probe-upstream\n\
         rate_card:\n\
         \x20 probe-model: {{ input_utok: 100000, output_utok: 200000 }}\n\
         mcp:\n\
         \x20 canonical_uri: \"http://127.0.0.1:{data}/mcp\"\n\
         \x20 authorization_servers: [\"http://127.0.0.1:{data}/issuer\"]\n\
         agents:\n\
         \x20 probe-agent:\n\
         \x20   url: \"http://127.0.0.1:{data}/agent\"\n\
         \x20   pin: {{ mechanism: unpinned }}\n\
         streams:\n\
         \x20 session:\n\
         \x20   voice: marin\n\
         \x20 session_max_secs: 1800\n",
        providers = providers.display(),
        signing = signing.display(),
    )
}

/// Send every leg's probe and record what the binary answered.
fn drive(data: u16, admin: u16, admin_token: &str) -> Result<Measured, String> {
    let mut m = Measured::default();
    for leg in LEGS {
        m.legs.insert(leg.to_string(), Observed::default());
    }
    let bearer = |t: &str| format!("Bearer {t}");

    // The LLM probe needs a credential the deployment issued, so the key is minted first — through
    // the admin plane, which is itself one of the legs under measurement.
    let minted = request(
        admin,
        "POST",
        "/api/v1/admin/keys",
        &[
            ("authorization", bearer(admin_token)),
            ("content-type", "application/json".to_string()),
        ],
        Some("{\"name\":\"shipped-path-probe\",\"group\":\"probe\"}"),
        false,
    );
    let token = minted
        .as_ref()
        .ok()
        .and_then(|(_, body)| json_string_field(body, "token"))
        .unwrap_or_default();

    // ── admin ────────────────────────────────────────────────────────────────────────────────
    // TWO reads, and the pair is the point. The ledger view exists on no legacy route, so it can
    // only be the loop's answer; the key list is one of the table's legacy verbs. A leg that
    // answers one from each half is a leg that is half moved, and `split` is what that measures as.
    let a = m.legs.get_mut("admin").expect("seeded above");
    a.probe = "GET /api/v1/admin/ledger/totals + GET /api/v1/admin/keys (admin listener)".into();
    match request(
        admin,
        "GET",
        "/api/v1/admin/ledger/totals",
        &[("authorization", bearer(admin_token))],
        None,
        false,
    ) {
        Ok((status, _)) => a.status = Some(status),
        Err(e) => a.error = Some(e),
    }
    if let Err(e) = request(
        admin,
        "GET",
        "/api/v1/admin/keys",
        &[("authorization", bearer(admin_token))],
        None,
        false,
    ) {
        a.error.get_or_insert(e);
    }

    // ── llm ──────────────────────────────────────────────────────────────────────────────────
    let l = m.legs.get_mut("llm").expect("seeded above");
    l.probe = "POST /v1/chat/completions (data listener)".into();
    if token.is_empty() {
        l.error = Some(format!(
            "no key could be minted to authenticate the chat completion with: {}",
            minted
                .err()
                .unwrap_or_else(|| "the mint answered no token".into())
        ));
    } else {
        match request(
            data,
            "POST",
            "/v1/chat/completions",
            &[
                ("authorization", bearer(&token)),
                ("content-type", "application/json".to_string()),
            ],
            Some("{\"model\":\"probe-model\",\"messages\":[{\"role\":\"user\",\"content\":\"probe\"}]}"),
            false,
        ) {
            Ok((status, _)) => l.status = Some(status),
            Err(e) => l.error = Some(e),
        }
    }

    // ── mcp ──────────────────────────────────────────────────────────────────────────────────
    let c = m.legs.get_mut("mcp").expect("seeded above");
    c.probe = "POST /mcp jsonrpc initialize (data listener)".into();
    match request(
        data,
        "POST",
        "/mcp",
        &[
            ("authorization", bearer(&token)),
            ("content-type", "application/json".to_string()),
        ],
        Some(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\
             \"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"probe\",\"version\":\"1\"}}}",
        ),
        false,
    ) {
        Ok((status, _)) => c.status = Some(status),
        Err(e) => c.error = Some(e),
    }

    // ── a2a ──────────────────────────────────────────────────────────────────────────────────
    let g = m.legs.get_mut("a2a").expect("seeded above");
    g.probe = "GET /.well-known/agent-card.json (data listener)".into();
    match request(
        data,
        "GET",
        "/.well-known/agent-card.json",
        &[],
        None,
        false,
    ) {
        Ok((status, _)) => g.status = Some(status),
        Err(e) => g.error = Some(e),
    }

    // ── voice ────────────────────────────────────────────────────────────────────────────────
    let v = m.legs.get_mut("voice").expect("seeded above");
    v.probe = "GET /v1/realtime/sideband/probe websocket upgrade (data listener)".into();
    match request(
        data,
        "GET",
        "/v1/realtime/sideband/probe",
        &[
            ("authorization", bearer(&token)),
            ("connection", "Upgrade".to_string()),
            ("upgrade", "websocket".to_string()),
            ("sec-websocket-version", "13".to_string()),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==".to_string()),
        ],
        None,
        true,
    ) {
        Ok((status, _)) => v.status = Some(status),
        Err(e) => v.error = Some(e),
    }

    // The journal is written by the process as it answers; give the last record a moment to reach
    // the file before the caller reads it back.
    std::thread::sleep(Duration::from_millis(300));
    Ok(m)
}

// -------------------------------------------------------------------------------------------
// Reading the journal
// -------------------------------------------------------------------------------------------

/// Every `(leg, word)` pair the binary journalled, out of a log that carries terminal colouring,
/// every other DEBUG line in the process, and nothing this reader may assume the shape of beyond
/// the record's own message and its two fields.
pub fn records(log: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in log.lines() {
        let plain = strip_ansi(line);
        if !plain.contains(RECORD_MESSAGE) {
            continue;
        }
        let (Some(leg), Some(word)) = (field(&plain, "leg"), field(&plain, "answered")) else {
            continue;
        };
        out.push((leg, word));
    }
    out
}

/// `name="value"` out of a formatted tracing line.
fn field(line: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let at = line.find(&needle)? + needle.len();
    let rest = &line[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Drop CSI escape sequences. The binary colours its own log when it feels like it, and a field
/// name wrapped in an escape is a field name this reader would otherwise not find.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            for t in chars.by_ref() {
                if t.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }
    out
}

// -------------------------------------------------------------------------------------------
// The plumbing: build, ports, boot, HTTP
// -------------------------------------------------------------------------------------------

/// Build the SHIPPED binary — default features, release profile — and hand back the path cargo
/// itself named for it. Parsed out of cargo's own artifact stream rather than guessed at
/// `target/release/…`, because a workspace with a redirected target directory would otherwise be
/// measured through a binary that is not there.
fn build_release_binary(cx: &Ctx) -> Result<PathBuf, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let argv: Vec<String> = [
        "build",
        "--release",
        "-p",
        "busbar",
        "--bin",
        "busbar",
        "--message-format",
        "json-render-diagnostics",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let out = cx
        .run_checked(&cargo, &argv)
        .map_err(|e| format!("the shipped binary did not build: {e}"))?;
    for line in out.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        if v.pointer("/target/name")
            .and_then(serde_json::Value::as_str)
            != Some("busbar")
        {
            continue;
        }
        if let Some(exe) = v.get("executable").and_then(serde_json::Value::as_str) {
            return Ok(PathBuf::from(exe));
        }
    }
    Err(
        "cargo built the binary crate and named no executable for it -- there is nothing to \
         measure the shipped path through"
            .to_string(),
    )
}

/// The first port at or above `from` that binds, inside the allowed window.
fn free_port(from: u16) -> Result<u16, String> {
    for port in from.max(PORT_LOW)..=PORT_HIGH {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(format!(
        "no free port in {PORT_LOW}..={PORT_HIGH} for the shipped-path probe"
    ))
}

/// Wait for the booted binary to answer, or say what it printed instead of booting.
fn wait_for_boot(data: u16, log: &Path) -> Result<(), String> {
    let deadline = Instant::now() + BOOT_BUDGET;
    while Instant::now() < deadline {
        if let Ok((200, _)) = request(data, "GET", "/healthz", &[], None, false) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let tail = std::fs::read_to_string(log).unwrap_or_default();
    let tail: Vec<&str> = tail.lines().rev().take(8).collect();
    Err(format!(
        "the shipped binary did not answer /healthz within {}s. Its last lines: {}",
        BOOT_BUDGET.as_secs(),
        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
    ))
}

/// One HTTP/1.1 request over a plain socket, hand-written because this crate carries no HTTP
/// client and a gate runner is the last place to start adding one.
///
/// `headers_only` stops after the header block, which is what a `101` upgrade needs: the socket
/// stays open and reading a body that will never arrive is a hang.
fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
    headers_only: bool,
) -> Result<(u16, String), String> {
    let addr = format!("127.0.0.1:{port}");
    let mut sock = TcpStream::connect(&addr).map_err(|e| format!("{method} {path}: {e}"))?;
    sock.set_read_timeout(Some(REQUEST_BUDGET)).ok();
    sock.set_write_timeout(Some(REQUEST_BUDGET)).ok();

    let mut req = format!("{method} {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("content-length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    sock.write_all(req.as_bytes())
        .map_err(|e| format!("{method} {path}: {e}"))?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if headers_only && find_header_end(&buf).is_some() {
                    break;
                }
            }
            Err(e) => {
                if buf.is_empty() {
                    return Err(format!("{method} {path}: {e}"));
                }
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("{method} {path}: the answer had no status line"))?;
    let body = find_header_end(&buf)
        .map(|at| String::from_utf8_lossy(&buf[at..]).into_owned())
        .unwrap_or_default();
    Ok((status, body))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// `"name":"value"` out of a flat JSON object, without asking this crate to model the document.
fn json_string_field(body: &str, name: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_string)
}

/// Run the binary for one line of output — the signing key it mints for its own config.
fn run_capture(bin: &Path, args: &[String], cwd: &Path) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} exited {}",
            bin.display(),
            args.join(" "),
            out.status.code().unwrap_or(-1)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{}: {e}", bin.display()))
}

/// A booted binary that is killed however this measurement leaves — including on the `?` of a
/// probe that failed. A gate that leaks a listening gateway is a gate whose next run measures the
/// previous one.
struct Reaped(Child);

impl Reaped {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Reaped {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, records, render, Measured, Observed};
    use std::collections::BTreeSet;

    fn observed(status: Option<u16>, words: &[&str], probe: &str) -> Observed {
        Observed {
            status,
            records: words.iter().map(|w| (*w).to_string()).collect(),
            probe: probe.to_string(),
            error: None,
        }
    }

    #[test]
    fn both_words_is_a_split_one_is_the_loop_and_none_is_legacy() {
        assert_eq!(
            observed(Some(200), &["loop", "legacy"], "p").verdict(),
            Ok("split")
        );
        assert_eq!(observed(Some(503), &["loop"], "p").verdict(), Ok("loop"));
        assert_eq!(observed(Some(401), &[], "p").verdict(), Ok("legacy"));
        assert_eq!(
            observed(Some(200), &["legacy"], "p").verdict(),
            Ok("legacy")
        );
    }

    /// AN UNANSWERED PROBE IS NOT A LEGACY LEG. The empty record set is identical either way, so
    /// the status is what separates "the root took no part" from "nothing was measured".
    #[test]
    fn a_probe_the_binary_never_answered_is_not_a_verdict() {
        assert!(observed(None, &[], "GET /nowhere").verdict().is_err());
        let mut refused = observed(Some(200), &["loop"], "p");
        refused.error = Some("the socket was refused".into());
        assert!(refused.verdict().is_err());
    }

    /// THE INSTRUMENT FLOOR. Five legs that each journalled nothing is what a broken reader looks
    /// like, and it is also what five legacy legs look like.
    #[test]
    fn a_run_in_which_nothing_journalled_a_loop_record_is_vacuous() {
        let mut m = Measured::default();
        m.legs.insert("mcp".into(), observed(Some(401), &[], "p"));
        m.legs.insert("a2a".into(), observed(Some(200), &[], "p"));
        assert!(m.vacuous());
        m.legs
            .insert("llm".into(), observed(Some(503), &["loop"], "p"));
        assert!(!m.vacuous());
    }

    #[test]
    fn a_rendered_measurement_reads_back_as_itself() {
        let mut m = Measured::default();
        m.legs.insert(
            "admin".into(),
            observed(Some(200), &["loop", "legacy"], "GET /api/v1/admin/keys"),
        );
        m.legs
            .insert("mcp".into(), observed(Some(401), &[], "POST /mcp"));
        let mut broken = observed(None, &[], "GET /x");
        broken.error = Some("connection refused".into());
        m.legs.insert("voice".into(), broken);
        let round = parse(&render(&m)).expect("the rendered form is the parsed form");
        assert_eq!(round.legs.len(), 3);
        assert_eq!(round.legs["admin"].verdict(), Ok("split"));
        assert_eq!(round.legs["mcp"].verdict(), Ok("legacy"));
        assert!(round.legs["voice"].verdict().is_err());
    }

    /// THE READER MUST SURVIVE THE BINARY'S OWN FORMATTING. These are real lines, colouring and
    /// all, off a real boot; a reader that only works on the uncoloured form reports every leg as
    /// legacy the moment the log is a terminal's.
    #[test]
    fn the_journal_reader_finds_records_through_terminal_colouring() {
        let log = "\u{1b}[2m2026-09-08T10:34:14.296746Z\u{1b}[0m \u{1b}[34mDEBUG\u{1b}[0m root \
                   served unit \u{1b}[3mleg\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"admin\" \
                   \u{1b}[3manswered\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"loop\"\n\
                   2026-09-08T10:34:14.310533Z DEBUG root served unit leg=\"admin\" \
                   answered=\"legacy\"\n\
                   2026-09-08T10:34:14.310654Z DEBUG some other debug line leg=\"llm\"\n";
        let got: BTreeSet<String> = records(log)
            .into_iter()
            .map(|(l, w)| format!("{l}/{w}"))
            .collect();
        assert_eq!(
            got,
            ["admin/legacy".to_string(), "admin/loop".to_string()]
                .into_iter()
                .collect()
        );
    }
}
