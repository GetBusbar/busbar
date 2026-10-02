//! `cargo xtask proof-manifest` — THE COLLATOR for the Build Proof Dashboard (`docs/proof/README.md`).
//!
//! It changes NO gate. It is a thin capture layer over apparatus that already runs in CI: it runs
//! (or reads) the neutrality gates, enumerates the golden corpus, counts the dialect map files, and
//! ingests the MCP/A2A conformance JSON reports, then reduces every one to a public-safe verdict
//! object and emits `docs/proof/<version>.json` per the proof-manifest schema. (Ported from
//! `scripts/proof-manifest.py`; the output is byte-identical to what that script wrote.)
//!
//! PUBLIC-SAFE BY CONSTRUCTION. The manifest carries verdicts, counts, gate names, test-function
//! names, golden filenames, and field ids -- all already public in the docs/CHANGELOG the marketing
//! site renders. It carries NO source, NO secrets, NO file contents, NO internal URLs. The companion
//! guard `scripts/check-proof-manifest-public.mjs` fails the build if anything source-like appears.
//!
//! HONESTY RULE (carried from the removed `qa/segments.toml`). A source that did not actually run
//! renders `unknown`, never green. A report-only gate (plane-grep today) renders `report-only`,
//! never `pass`. A class verdict is `fail` if any non-reserved source failed, `unknown` if any is
//! unknown and none failed, else `pass`. The collator never launders a not-run into a pass.
//!
//! ```text
//! cargo xtask proof-manifest --version dev --out docs/proof/dev.json
//! cargo xtask proof-manifest --version 1.6.0 --out docs/proof/1.6.0.json \
//!     --sha <40hex> --run-id 123 --run-url https://github.com/.../runs/123 \
//!     --staged-json /path/to/staged.json --reports-dir testing --run-cargo
//! cargo xtask proof-manifest --selftest
//! ```
//!
//! Flags: `--version` (release/branch label, also `release.version`/`tag`), `--out`, `--repo-root`,
//! `--sha` (default `git rev-parse HEAD`), `--run-id`/`--run-url` (CI provenance), `--staged-json`
//! (release receipt to lift tag/digest/staging_tag from), `--reports-dir` (tree searched for MCP/A2A
//! conformance reports), `--hits-dir` (where gate hit-list TSVs go: they hold SOURCE lines, so it
//! must stay OUT of the committed tree; default a private temp dir), `--run-cargo` (run the parity
//! and composability cargo-backed sources for real; slow, CI) / `--run-parity` / `--run-composability`,
//! `--mark ID=STATUS` (repeatable; stamp a source from a sibling CI job), `--index` (rewrite
//! `docs/proof/index.json`), `--print`, `--selftest`.

use crate::json_lite::{self, Json, Obj};
use crate::sha256;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── small Python-compat helpers ───────────────────────────────────────────────────────────────────

/// Python's `str` `\s`: Rust's `is_whitespace` plus the four C0 separators Python also counts.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// `str.splitlines()` (the line boundaries Python knows, none of the terminators kept).
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if brk {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    end = j + 1;
                }
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// The ANSI colour escapes `\x1b\[[0-9;]*m`, removed.
fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if b[i] == 0x1b && b.get(i + 1) == Some(&b'[') {
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b';') {
                j += 1;
            }
            if b.get(j) == Some(&b'm') {
                out.push_str(&s[last..i]);
                i = j + 1;
                last = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Run a command; `(exit code, stdout+stderr with ANSI stripped)`. Never fails on a non-zero exit:
/// 127 when the program is not found, 124 on timeout (the child is killed), as the script did.
fn run(cmd: &[&str], cwd: &Path, env: &[(&str, String)], timeout: Option<u64>) -> (i32, String) {
    let mut c = Command::new(cmd[0]);
    c.args(&cmd[1..])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = match c.spawn() {
        Ok(c) => c,
        Err(_) => return (127, String::new()),
    };
    let drain = |s: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = s {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out_t = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err_t = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let deadline = timeout.map(|t| Instant::now() + Duration::from_secs(t));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {}
            Err(_) => return (127, String::new()),
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            let _ = child.kill();
            let _ = child.wait();
            return (124, String::new());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut text = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    text.push_str(&String::from_utf8_lossy(&err_t.join().unwrap_or_default()));
    (exit_code(&status), strip_ansi(&text))
}

#[cfg(unix)]
fn exit_code(st: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    st.code().unwrap_or_else(|| -st.signal().unwrap_or(1))
}

#[cfg(not(unix))]
fn exit_code(st: &std::process::ExitStatus) -> i32 {
    st.code().unwrap_or(-1)
}

/// Scrape the integer of the first `^\s*<key>\s+(\d+)\s*$` (MULTILINE) match: the `  <KEY>   <n>`
/// fixed-format table the plane-grep gate prints. `\s` may cross newlines, exactly as in `re`.
fn scrape_key(text: &str, key: &str) -> Option<i64> {
    let starts = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(i, _)| i + 1))
        .collect::<Vec<_>>();
    for p in starts {
        if p > text.len() {
            continue;
        }
        let rest = &text[p..];
        let after_ws = rest.trim_start_matches(py_space);
        let Some(after_key) = after_ws.strip_prefix(key) else {
            continue;
        };
        let after_sp = after_key.trim_start_matches(py_space);
        if after_sp.len() == after_key.len() {
            continue; // `\s+` needs one
        }
        let digits_len = after_sp.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits_len == 0 {
            continue;
        }
        let tail = &after_sp[digits_len..];
        let ws_len = tail.len() - tail.trim_start_matches(py_space).len();
        let ws = &tail[..ws_len];
        // `\s*$` (MULTILINE): the whitespace run reaches the end of text or swallows a newline.
        if ws_len == tail.len() || ws.contains('\n') {
            return after_sp[..digits_len]
                .parse::<i64>()
                .ok()
                .or(Some(i64::MAX));
        }
    }
    None
}

fn parse_count_table(text: &str, keys: &[&str]) -> Obj {
    let mut out = Obj::new();
    for k in keys {
        if let Some(n) = scrape_key(text, k) {
            out.insert(*k, Json::Int(n));
        }
    }
    out
}

fn scrape_total(text: &str) -> Option<i64> {
    scrape_key(text, "TOTAL")
}

/// Count `file:line` hit lines in a gate's failure output (`\.rs:\d+` per line; a meter only).
fn count_hit_lines(text: &str) -> i64 {
    py_splitlines(text)
        .iter()
        .filter(|ln| {
            ln.match_indices(".rs:")
                .any(|(i, m)| ln[i + m.len()..].starts_with(|c: char| c.is_ascii_digit()))
        })
        .count() as i64
}

/// The `(\w+)` status and `(\d+)` count of the plane-purity gate's freeze ledger row.
fn freeze_row(text: &str) -> Option<(String, i64)> {
    const PFX: &str = "plane-purity:core-llm-family-freeze\t";
    for (i, _) in text.match_indices(PFX) {
        let rest = &text[i + PFX.len()..];
        let w = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .count();
        let word_end: usize = rest.chars().take(w).map(char::len_utf8).sum();
        if w == 0 || !rest[word_end..].starts_with('\t') {
            continue;
        }
        let rest = &rest[word_end + 1..];
        let Some(tab) = rest.find('\t') else { continue };
        let Some(after) = rest[tab + 1..].strip_prefix("count=") else {
            continue;
        };
        let n = after.chars().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            continue;
        }
        return Some((
            rest_word(text, i + PFX.len(), word_end),
            after[..n].parse().unwrap_or(i64::MAX),
        ));
    }
    None
}

fn rest_word(text: &str, from: usize, len: usize) -> String {
    text[from..from + len].to_string()
}

/// The integer of the first `(\d+) unclassified` in the text.
fn unclassified_count(text: &str) -> i64 {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if text[j..].starts_with(" unclassified") {
                return text[i..j].parse().unwrap_or(i64::MAX);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    0
}

/// Sum libtest's `running N tests` lines (`^running (\d+) tests?$`, MULTILINE). `None` when no such
/// line was printed at all.
fn tests_run(text: &str) -> Option<i64> {
    let mut sum = 0i64;
    let mut any = false;
    for ln in text.split('\n') {
        let Some(rest) = ln.strip_prefix("running ") else {
            continue;
        };
        let d = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if d == 0 {
            continue;
        }
        if matches!(&rest[d..], " tests" | " test") {
            any = true;
            sum = sum.saturating_add(rest[..d].parse().unwrap_or(i64::MAX));
        }
    }
    any.then_some(sum)
}

// ── JSON construction and the two writers ─────────────────────────────────────────────────────────

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    let mut o = Obj::new();
    for (k, v) in pairs {
        o.insert(k, v);
    }
    Json::Object(o)
}

fn opt_note(n: Option<String>) -> Json {
    n.map_or(Json::Null, Json::Str)
}

fn status_of(v: &Json) -> Option<&str> {
    v.get("status").as_str()
}

/// `json.dumps(...)`'s string escaping with `ensure_ascii=True`: everything outside ` `..`~` is a
/// short form or `\uXXXX` (a UTF-16 surrogate pair above the BMP).
fn write_str(out: &mut String, v: &str) {
    use std::fmt::Write as _;
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn write_float(out: &mut String, f: f64) {
    if f.is_finite() && f == f.trunc() && f.abs() < 1e16 {
        out.push_str(&format!("{f:.1}"));
    } else {
        out.push_str(&format!("{f}"));
    }
}

/// `json.dumps(v, indent=Some(n) | None, sort_keys=..., separators=...)` with `ensure_ascii=True`.
/// `indent: Some(n)` is the pretty form (`", "` item break replaced by newline, `": "` key sep);
/// `None` is the compact `(",", ":")` form.
fn dumps(v: &Json, indent: Option<usize>, sort_keys: bool) -> String {
    let mut out = String::new();
    dump_into(&mut out, v, indent, sort_keys, 0);
    out
}

fn dump_into(out: &mut String, v: &Json, indent: Option<usize>, sort: bool, level: usize) {
    let nl = |out: &mut String, lvl: usize| {
        if let Some(n) = indent {
            out.push('\n');
            for _ in 0..lvl * n {
                out.push(' ');
            }
        }
    };
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::Float(f) => write_float(out, *f),
        Json::Str(t) => write_str(out, t),
        Json::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, level + 1);
                dump_into(out, item, indent, sort, level + 1);
            }
            nl(out, level);
            out.push(']');
        }
        Json::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut items: Vec<(&str, &Json)> = o.iter().collect();
            if sort {
                items.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (i, (k, val)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, level + 1);
                write_str(out, k);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                dump_into(out, val, indent, sort, level + 1);
            }
            nl(out, level);
            out.push('}');
        }
    }
}

/// Python's `str(x)` of a decoded JSON value (the `run_id` lifted from a staged receipt).
fn py_str(v: &Json) -> String {
    match v {
        Json::Str(t) => t.clone(),
        other => json_lite::py_repr_json(other),
    }
}

// ── VERDICT: byte-identity ────────────────────────────────────────────────────────────────────────

// THE GOLDEN CORPUS AND THE TESTS THAT ASSERT OVER IT, AS ONE CONSTANT. Both used to say
// `busbar-llm`; the proto module lives in `busbar-plane-llm`'s own `codec` module since the fold, so
// the directory read `total = 0` and the cargo filter matched ZERO tests (cargo exits 0 on that):
// "0 cases, pass". GOLDEN_MIN is the floor that makes that impossible to say again.
const GOLDEN_DIR: &str = "crates/busbar-plane-llm/src/codec/tests/proto/golden";
const GOLDEN_CRATE: &str = "busbar-plane-llm";
/// The corpus holds >100 pairs; the floor is a collapse tripwire, not a second count.
const GOLDEN_MIN: i64 = 40;

// The evidence paths this collator names (the selftest checks every one exists).
const EV_NO_PLUGINS: &str = "scripts/no-plugins-gate.sh";
const EV_PLANE_DELETE: &str = "scripts/plane-delete-test.sh";
const EV_PLANE_GREP: &str = "scripts/plane-grep-gate.sh";
const EV_PROTO_DELETION: &str = "scripts/proto-deletion-gate.sh";
const EV_DIALECT_COVERAGE: &str = "xtask/src/gates/dialect_coverage.rs";
const EV_PLANE_ABI: &str = "xtask/src/gates/plane_abi_neutrality.rs";
const EV_PLANE_PURITY: &str = "xtask/src/gates/plane_purity/mod.rs";
const EVIDENCE_PATHS: &[&str] = &[
    EV_NO_PLUGINS,
    EV_PLANE_DELETE,
    EV_PLANE_GREP,
    EV_PROTO_DELETION,
    EV_DIALECT_COVERAGE,
    EV_PLANE_ABI,
    EV_PLANE_PURITY,
];

/// Enumerate the golden corpus -> `(total_pairs, {lane: [filenames]})`. A filesystem fact.
fn golden_lanes(root: &Path) -> (i64, BTreeMap<String, Vec<String>>) {
    let mut lanes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0;
    let dir = root.join(GOLDEN_DIR);
    if dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        for name in names {
            if let Some(lane) = golden_lane(&name) {
                total += 1;
                lanes.entry(lane).or_default().push(name);
            }
        }
    }
    (total, lanes)
}

/// `^(req|resp)_([a-z]2[a-z])_(.+)\.json$` -> the lane.
fn golden_lane(name: &str) -> Option<String> {
    let rest = name
        .strip_prefix("req_")
        .or_else(|| name.strip_prefix("resp_"))?;
    let b = rest.as_bytes();
    if b.len() < 4 || !b[0].is_ascii_lowercase() || b[1] != b'2' || !b[2].is_ascii_lowercase() {
        return None;
    }
    if b[3] != b'_' {
        return None;
    }
    let tail = &rest[4..];
    let stem = tail.strip_suffix(".json")?;
    if stem.is_empty() || stem.contains('\n') {
        return None;
    }
    Some(rest[..3].to_string())
}

fn parity_cmd() -> [&'static str; 6] {
    [
        "cargo",
        "test",
        "-p",
        GOLDEN_CRATE,
        "--lib",
        "translate_parity",
    ]
}

/// A cargo test run is a PASS only when it exited 0 AND ran at least one test.
fn cargo_test_status(code: i32, text: &str) -> (&'static str, String) {
    if code != 0 {
        return ("fail", format!("cargo test exited {code}"));
    }
    match tests_run(text) {
        Some(n) if n != 0 => ("pass", format!("{n} test(s) ran and passed")),
        _ => (
            "fail",
            format!(
                "cargo test exited 0 but ran ZERO tests (filter matched nothing in {GOLDEN_CRATE}): \
                 zero tests passing is not a pass"
            ),
        ),
    }
}

fn verdict_byte_identity(root: &Path, run_cargo: bool) -> Json {
    let (total, lanes) = golden_lanes(root);
    let lane_matrix: Vec<Json> = lanes
        .iter()
        .map(|(lane, cases)| {
            let mut sorted = cases.clone();
            sorted.sort();
            obj(vec![
                ("lane", s(lane)),
                ("status", s("present")),
                ("count", Json::Int(cases.len() as i64)),
                ("cases", Json::Array(sorted.iter().map(|c| s(c)).collect())),
            ])
        })
        .collect();
    let lane_count = lane_matrix.len() as i64;
    let mut golden_note: Option<String> = None;
    let golden_status: &str;
    if total < GOLDEN_MIN {
        golden_status = "fail";
        golden_note = Some(format!(
            "the golden corpus at {GOLDEN_DIR} yields {total} byte-pair(s), below the floor of \
             {GOLDEN_MIN}; the byte-identity claim has nothing behind it"
        ));
    } else if run_cargo {
        let (code, text) = run(&parity_cmd(), root, &[], Some(3600));
        let (st, note) = cargo_test_status(code, &text);
        golden_status = st;
        golden_note = Some(note);
    } else {
        golden_status = "unknown";
    }
    let mut sources = vec![obj(vec![
        ("id", s("translate-parity-cross-pairs")),
        ("kind", s("golden")),
        ("status", s(golden_status)),
        ("note", opt_note(golden_note)),
        ("evidence", s(GOLDEN_DIR)),
        ("evidence_present", Json::Bool(total >= GOLDEN_MIN)),
        ("count", Json::Int(total)),
        ("total", Json::Int(total)),
        ("lane_count", Json::Int(lane_count)),
        (
            "drilldown",
            obj(vec![
                ("type", s("lane-matrix")),
                ("path", s(&format!("{GOLDEN_DIR}/"))),
                ("lanes", Json::Array(lane_matrix)),
            ]),
        ),
    ])];
    // The five money-path oracle tests (byte-identity of the delivery/billing/egress path).
    let oracles = [
        (
            "egress-differential",
            "crates/busbar-llm/src/engine/tests/egress_differential_tests.rs",
        ),
        (
            "crossproto-billing",
            "crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs",
        ),
        (
            "on-exhausted",
            "crates/busbar-llm/src/engine/tests/on_exhausted_tests.rs",
        ),
        (
            "pool-upstream-creds",
            "crates/busbar-llm/src/engine/tests/pool_upstream_creds_tests.rs",
        ),
        // busbar-core's ingress suite, relocated whole into busbar-llm (03ee7227c, a git rename).
        (
            "usage-decode-tap",
            "crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs",
        ),
    ];
    for (oid, opath) in oracles {
        let present = root.join(opath).exists();
        sources.push(obj(vec![
            ("id", s(oid)),
            ("kind", s("oracle")),
            ("status", s("unknown")), // cargo-backed; not executed in scrape mode
            (
                "note",
                s(if present {
                    "present"
                } else {
                    "test file not found"
                }),
            ),
            ("evidence", s(opath)),
            ("evidence_present", Json::Bool(present)),
            (
                "drilldown",
                obj(vec![("type", s("test")), ("path", s(opath))]),
            ),
        ]));
    }
    obj(vec![
        ("class", s("byte-identity")),
        ("title", s("Your bytes survive read to IR to write")),
        ("status", s(&class_status(&sources))),
        ("evidence_count", Json::Int(total)),
        ("evidence_total", Json::Int(total)),
        ("unit", s("golden byte-pairs")),
        ("sources", Json::Array(sources)),
    ])
}

// ── VERDICT: plane-neutrality-by-construction ─────────────────────────────────────────────────────

fn verdict_plane_neutrality(root: &Path, hits_dir: &Path) -> Json {
    let mut sources: Vec<Json> = Vec::new();

    // plane-purity: the gate's own ledger rows, and its hit artefact for the drilldown. The COUNTS
    // come from the artefact rather than the printed report: the artefact carries a #SCAN
    // denominator line, so "clean" and "scanned nothing" stay distinguishable here too.
    let pp_out = hits_dir.join("plane-purity-hits.tsv");
    let (st_code, _) = run(
        &["cargo", "xtask", "gate", "plane-purity", "--selftest"],
        root,
        &[],
        Some(300),
    );
    let (code, text) = run(
        &["cargo", "xtask", "gate", "plane-purity", "--format=tsv"],
        root,
        &[("PLANE_PURITY_HITS_OUT", pp_out.display().to_string())],
        Some(300),
    );
    let cat_names = [
        "PATH-INCLUDE",
        "SYMBOL",
        "TYPE",
        "KEY",
        "DIALECT",
        "BACKWARDS",
    ];
    let mut cats: Vec<(&str, i64)> = cat_names.iter().map(|c| (*c, 0)).collect();
    let mut total = 0i64;
    if pp_out.exists() {
        if let Ok(bytes) = std::fs::read(&pp_out) {
            let body = String::from_utf8_lossy(&bytes).into_owned();
            for line in py_splitlines(&body) {
                let cat = line.split('\t').next().unwrap_or("");
                if let Some(slot) = cats.iter_mut().find(|(c, _)| *c == cat) {
                    slot.1 += 1;
                    total += 1;
                }
            }
        }
    }
    let mut breakdown = Obj::new();
    for (c, n) in &cats {
        breakdown.insert(*c, Json::Int(*n));
    }
    sources.push(obj(vec![
        ("id", s("plane-purity-lint")),
        // The shell lint was retired into `cargo xtask gate plane-purity`; the evidence is the gate
        // that ran, not the script that no longer exists.
        ("evidence", s(EV_PLANE_PURITY)),
        (
            "evidence_present",
            Json::Bool(root.join(EV_PLANE_PURITY).is_file()),
        ),
        ("kind", s("gate")),
        ("status", s(if code == 0 { "pass" } else { "fail" })),
        ("count", Json::Int(total)),
        ("breakdown", Json::Object(breakdown)),
        ("selftest", s(if st_code == 0 { "pass" } else { "fail" })),
        (
            "runs_in",
            Json::Array(vec![
                s("gate:plane-purity"),
                s("qa/segments.toml:plane-purity"),
            ]),
        ),
        (
            "drilldown",
            obj(vec![
                ("type", s("hit-list")),
                ("artifact", s("plane-purity-hits.tsv")),
            ]),
        ),
    ]));

    // g6 freeze witness: a scalar, one row of the plane-purity gate above. Read off the ledger row's
    // detail, which is the counted table the witness printed.
    let freeze = freeze_row(&text);
    sources.push(obj(vec![
        ("id", s("g6-freeze-witness")),
        ("evidence", s(EV_PLANE_PURITY)), // ROW_FREEZE lives in that gate
        (
            "evidence_present",
            Json::Bool(root.join(EV_PLANE_PURITY).is_file()),
        ),
        ("kind", s("gate")),
        (
            "status",
            s(if freeze.as_ref().is_some_and(|(w, _)| w == "PASS") {
                "pass"
            } else {
                "fail"
            }),
        ),
        ("count", Json::Int(freeze.as_ref().map_or(-1, |(_, n)| *n))),
    ]));

    // plane-grep gate: report-only meter, per-needle table + TOTAL.
    let gp_out = hits_dir.join("plane-grep-hits.tsv");
    let (st_code, _) = run(&["bash", EV_PLANE_GREP, "--selftest"], root, &[], Some(300));
    let (_, text) = run(
        &["bash", EV_PLANE_GREP, "--report"],
        root,
        &[
            ("GREP_GATE_REPORT_ONLY", "1".to_string()),
            ("PLANE_GREP_HITS_OUT", gp_out.display().to_string()),
        ],
        Some(300),
    );
    let needles = parse_count_table(
        &text,
        &[
            "openai",
            "gemini",
            "anthropic",
            "bedrock",
            "cohere",
            "responses",
            "mcp",
            "a2a",
        ],
    );
    let gp_total = scrape_total(&text);
    sources.push(obj(vec![
        ("id", s("plane-grep-gate")),
        ("evidence", s(EV_PLANE_GREP)),
        (
            "evidence_present",
            Json::Bool(root.join(EV_PLANE_GREP).is_file()),
        ),
        ("kind", s("gate")),
        // non-blocking meter until GREP_GATE_REPORT_ONLY=0 is armed
        ("status", s("report-only")),
        ("count", Json::Int(gp_total.unwrap_or(-1))),
        ("breakdown", Json::Object(needles)),
        ("selftest", s(if st_code == 0 { "pass" } else { "fail" })),
        (
            "drilldown",
            obj(vec![
                ("type", s("hit-list")),
                ("artifact", s("plane-grep-hits.tsv")),
            ]),
        ),
    ]));

    // plane-abi-neutrality: 0 banned nouns on success.
    let (code, text) = run(
        &["cargo", "xtask", "gate", "plane-abi-neutrality"],
        root,
        &[],
        Some(120),
    );
    sources.push(obj(vec![
        ("id", s("plane-abi-neutrality")),
        ("evidence", s(EV_PLANE_ABI)),
        (
            "evidence_present",
            Json::Bool(root.join(EV_PLANE_ABI).is_file()),
        ),
        ("kind", s("gate")),
        ("status", s(if code == 0 { "pass" } else { "fail" })),
        (
            "count",
            Json::Int(if code == 0 { 0 } else { count_hit_lines(&text) }),
        ),
    ]));

    // Headline meter = the by-construction side-channel count in the neutral crates: plane-purity +
    // g6. plane-grep is a report-only meter (own row); plane-abi is a separate witness (own row)
    // whose raw declaration-line matches must not dominate the neutral-crate headline.
    let mut headline = 0i64;
    for src in &sources {
        if matches!(
            src.get("id").as_str(),
            Some("plane-purity-lint" | "g6-freeze-witness")
        ) {
            if let Some(n) = src.get("count").as_i64() {
                if n > 0 {
                    headline += n;
                }
            }
        }
    }
    obj(vec![
        ("class", s("plane-neutrality")),
        ("title", s("The core cannot know any plane")),
        ("status", s(&class_status(&sources))),
        ("evidence_count", Json::Int(headline)),
        ("unit", s("side channels (0 = property holds)")),
        ("meter", s("zero-debt")),
        ("sources", Json::Array(sources)),
    ])
}

// ── VERDICT: composability (removability / any subset runs) ───────────────────────────────────────

fn verdict_composability(root: &Path, run_cargo: bool) -> Json {
    let mut planes: Vec<(&str, &str)> =
        vec![("llm", "unknown"), ("mcp", "unknown"), ("a2a", "unknown")];
    let mut delete_status = "unknown";
    let mut noplugins_status = "unknown";
    let mut proto_status = "unknown";
    if run_cargo {
        for slot in planes.iter_mut() {
            let (code, _) = run(&["bash", EV_PLANE_DELETE, slot.0], root, &[], Some(3600));
            slot.1 = if code == 0 { "pass" } else { "fail" };
        }
        delete_status = if planes.iter().any(|(_, st)| *st == "fail") {
            "fail"
        } else {
            "pass"
        };
        let (code, _) = run(&["bash", EV_NO_PLUGINS, "--check"], root, &[], Some(3600));
        noplugins_status = if code == 0 { "pass" } else { "fail" };
        let (code, _) = run(&["bash", EV_PROTO_DELETION], root, &[], Some(5400));
        proto_status = if code == 0 { "pass" } else { "fail" };
    }
    let mut plane_obj = Obj::new();
    for (p, st) in &planes {
        plane_obj.insert(*p, s(st));
    }
    // EVERY SOURCE NAMES ITS OWN EVIDENCE. These three are marked from sibling job results, and
    // mark_sources() will not stamp a pass onto a source whose evidence is not in the tree.
    let sources = vec![
        obj(vec![
            ("id", s("no-plugins-gate")),
            ("kind", s("gate")),
            ("status", s(noplugins_status)),
            ("unit", s("failed assertions")),
            ("evidence", s(EV_NO_PLUGINS)),
            (
                "evidence_present",
                Json::Bool(root.join(EV_NO_PLUGINS).is_file()),
            ),
            ("note", s("cargo-backed; run by scripts/no-plugins-gate.sh")),
        ]),
        obj(vec![
            ("id", s("plane-delete-test")),
            ("kind", s("gate")),
            ("status", s(delete_status)),
            ("planes", Json::Object(plane_obj)),
            ("evidence", s(EV_PLANE_DELETE)),
            (
                "evidence_present",
                Json::Bool(root.join(EV_PLANE_DELETE).is_file()),
            ),
            (
                "note",
                s("cargo-backed; run by scripts/plane-delete-test.sh --all"),
            ),
        ]),
        obj(vec![
            ("id", s("proto-deletion-gate")),
            ("kind", s("gate")),
            ("status", s(proto_status)),
            ("evidence", s(EV_PROTO_DELETION)),
            (
                "evidence_present",
                Json::Bool(root.join(EV_PROTO_DELETION).is_file()),
            ),
            (
                "note",
                s("cargo-backed; run by scripts/proto-deletion-gate.sh"),
            ),
        ]),
    ];
    obj(vec![
        ("class", s("composability")),
        ("title", s("Any plane is removable; any subset runs")),
        ("status", s(&class_status(&sources))),
        ("sources", Json::Array(sources)),
    ])
}

// ── VERDICT: lossless field-coverage ──────────────────────────────────────────────────────────────
// Every dialect's ONE map file (`<DIALECT_DIR>/<d>.toml`) maps a wire path or marks it
// `no-equivalent = "<reason>"`, and `cargo xtask gate dialect-candidates` proves no cross-dialect
// candidate is left unclassified. The counts come from the map files; the verdict from the gate.

const DIALECT_DIR: &str = "crates/busbar-plane-llm/dialects";

/// The `[unmapped.<direction>]` headers of a map file, in file order.
fn unmapped_directions(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(d) = t
            .strip_prefix("[unmapped.")
            .and_then(|r| r.strip_suffix(']'))
        {
            let d = d.trim().to_string();
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

fn verdict_field_coverage(root: &Path, run_gate: bool) -> Result<Json, String> {
    use crate::toml_lite;
    let mut mapped = 0i64;
    let mut by_dialect = Obj::new();
    let mut waivers: Vec<Json> = Vec::new();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join(DIALECT_DIR))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    for f in &files {
        let text = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let doc = toml_lite::parse_text(&text);
        let meta = doc.table("dialect");
        let stem = f
            .file_stem()
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or_default();
        let lock = meta.get_one("wire").map(str::to_string).unwrap_or(stem);
        let mut rows = 0i64;
        for direction in ["request", "response", "stream"] {
            for group in meta.get_list(direction) {
                rows += doc
                    .table(&format!("rows.{group}"))
                    .entries
                    .iter()
                    .filter(|(k, _)| k != "park")
                    .count() as i64;
            }
        }
        mapped += rows;
        by_dialect.insert(lock.clone(), Json::Int(rows));
        for direction in unmapped_directions(&text) {
            for (path, raw) in &doc.table(&format!("unmapped.{direction}")).entries {
                let reason = toml_lite::inline_table(raw)
                    .and_then(|kv| kv.into_iter().find(|(k, _)| k == "no-equivalent"))
                    .map(|(_, v)| toml_lite::string_value(&v))
                    .unwrap_or_default();
                waivers.push(obj(vec![
                    ("field", s(&format!("{lock}/{direction}/{path}"))),
                    ("reason", s(&reason)),
                ]));
            }
        }
    }
    let waived = waivers.len() as i64;

    // THE EVIDENCE FLOOR: zero rows read is not zero fields missing. An absent or emptied map
    // directory is UNKNOWN, never a pass over nothing.
    let mut note: Option<String> = None;
    let mut unclassified = 0i64;
    let status: &str;
    if mapped + waived == 0 {
        status = "unknown";
        note = Some(format!(
            "no rows in {DIALECT_DIR}/*.toml, so NOTHING was classified: a gate green over no map \
             compares nothing. Fix: restore the map files, or correct DIALECT_DIR."
        ));
    } else if !run_gate {
        status = "unknown";
        note = Some("the dialect-candidates gate was not run, so no verdict was measured".into());
    } else {
        let (code, text) = run(
            &["cargo", "xtask", "gate", "dialect-candidates"],
            root,
            &[],
            Some(600),
        );
        unclassified = unclassified_count(&text);
        if code == 124 || code == 127 {
            status = "unknown";
            note = Some(
                "cargo xtask gate dialect-candidates could not run (timeout or no cargo)".into(),
            );
        } else {
            status = if code == 0 { "pass" } else { "fail" };
        }
    }

    let src = obj(vec![
        ("id", s("field-coverage")),
        ("kind", s("gate")),
        ("status", s(status)),
        ("evidence", s(EV_DIALECT_COVERAGE)),
        (
            "evidence_present",
            Json::Bool(root.join(EV_DIALECT_COVERAGE).is_file() && mapped + waived > 0),
        ),
        ("note", opt_note(note)),
        ("carried", Json::Int(mapped)),
        ("waived", Json::Int(waived)),
        ("missing", Json::Int(unclassified)),
        ("by_dialect", Json::Object(by_dialect)),
        ("waivers", Json::Array(waivers)),
        (
            "drilldown",
            obj(vec![("type", s("dialect-map")), ("path", s(DIALECT_DIR))]),
        ),
    ]);
    Ok(obj(vec![
        ("class", s("field-coverage")),
        ("title", s("Every provider field is accounted for")),
        ("status", s(status)),
        ("evidence_count", Json::Int(mapped)),
        ("evidence_total", Json::Int(mapped + waived)),
        ("unit", s("wire paths mapped")),
        ("sources", Json::Array(vec![src])),
    ]))
}

// ── VERDICT: wire-conformance ─────────────────────────────────────────────────────────────────────

/// Every `*.json` file under `dir`, recursively, in name order (directory by directory).
fn rglob_json(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rglob_json(&p, out);
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
}

fn find_report(reports_dir: Option<&Path>, needles: &[&str]) -> Option<PathBuf> {
    let dir = reports_dir?;
    if !dir.is_dir() {
        return None;
    }
    let mut all = Vec::new();
    rglob_json(dir, &mut all);
    all.into_iter().find(|p| {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        needles.iter().all(|n| name.contains(n))
    })
}

fn read_report_status(path: &Path) -> &'static str {
    let Ok(text) = std::fs::read_to_string(path) else {
        return "unknown";
    };
    let Ok(data) = json_lite::parse(&text) else {
        return "unknown";
    };
    // Both suites emit a per-leg report; accept a few common shapes for the pass/fail verdict.
    for key in ["passed", "ok", "success"] {
        if let Json::Bool(b) = data.get(key) {
            return if *b { "pass" } else { "fail" };
        }
    }
    if let Json::Array(a) = data.get("failures") {
        return if a.is_empty() { "pass" } else { "fail" };
    }
    if let Json::Str(st) = data.get("status") {
        let st = st.to_lowercase();
        return if matches!(st.as_str(), "pass" | "passed" | "ok" | "green") {
            "pass"
        } else {
            "fail"
        };
    }
    "unknown"
}

fn verdict_conformance(root: &Path, reports_dir: Option<&Path>) -> Json {
    let mut sources: Vec<Json> = Vec::new();

    // THE NEEDLE MUST NAME THE SUITE: `control` alone let an a2a control report satisfy MCP.
    let mcp_control = find_report(reports_dir, &["mcp", "control"]);
    let mcp_status = mcp_control.as_deref().map_or("unknown", read_report_status);
    let evidence = match &mcp_control {
        Some(p) => match p.strip_prefix(root) {
            Ok(rel) => rel.display().to_string(),
            Err(_) => p.display().to_string(),
        },
        None => "testing/**/mcp*control*.json".to_string(),
    };
    sources.push(obj(vec![
        ("id", s("mcp-conformance")),
        ("kind", s("conformance")),
        ("status", s(mcp_status)),
        (
            "legs",
            obj(vec![("control", s(mcp_status)), ("subject", s("unknown"))]),
        ),
        // The report this verdict was read out of, named, so a sibling job result cannot stand in
        // for a report that is not there.
        ("evidence", s(&evidence)),
        ("evidence_present", Json::Bool(mcp_control.is_some())),
        (
            "drilldown",
            obj(vec![
                ("type", s("conformance-report")),
                ("artifact", s("mcp-battery-control-report")),
            ]),
        ),
        (
            "note",
            s("reads testing/mcp-conformance report JSON when present"),
        ),
    ]));

    // ONE REPORT IS ONE LEG: match on the whole label, never a prefix shared by several legs.
    let mut a2a_legs = Obj::new();
    let mut a2a_found: Vec<&str> = Vec::new();
    for label in [
        "control-go-http_json",
        "control-go-jsonrpc",
        "control-python",
        "negative-control",
        "swap-proof",
        "tck",
        "subject",
    ] {
        let mut needles = vec!["a2a"];
        needles.extend(label.split('-'));
        let rpt = find_report(reports_dir, &needles);
        if rpt.is_some() {
            a2a_found.push(label);
        }
        a2a_legs.insert(
            label,
            s(rpt.as_deref().map_or("unknown", read_report_status)),
        );
    }
    let legs: Vec<&str> = a2a_legs.iter().filter_map(|(_, v)| v.as_str()).collect();
    let a2a_status = if legs.contains(&"fail") {
        "fail"
    } else if legs.contains(&"unknown") {
        "unknown"
    } else {
        "pass"
    };
    sources.push(obj(vec![
        ("id", s("a2a-conformance")),
        ("kind", s("conformance")),
        ("status", s(a2a_status)),
        ("legs", Json::Object(a2a_legs)),
        ("evidence", s("testing/**/a2a*.json")),
        ("evidence_present", Json::Bool(!a2a_found.is_empty())),
        (
            "note",
            s(&if a2a_found.is_empty() {
                "no a2a conformance report JSON found under --reports-dir".to_string()
            } else {
                format!("report(s) found for leg(s): {}", a2a_found.join(", "))
            }),
        ),
        (
            "drilldown",
            obj(vec![
                ("type", s("conformance-report")),
                ("artifact", s("a2a-battery-control-http_json")),
            ]),
        ),
    ]));

    // LLM dialects: conformance IS the exhaustive golden corpus, so its evidence is that corpus and
    // the floor it must clear. Status stays `unknown` until the parity tests are actually executed.
    let (golden_total, _) = golden_lanes(root);
    let mut dialects = Obj::new();
    for d in [
        "anthropic",
        "openai",
        "gemini",
        "responses",
        "bedrock",
        "cohere",
    ] {
        dialects.insert(d, s("unknown"));
    }
    sources.push(obj(vec![
        ("id", s("llm-dialects")),
        ("kind", s("conformance")),
        ("status", s("unknown")),
        ("dialects", Json::Object(dialects)),
        ("evidence", s(GOLDEN_DIR)),
        ("evidence_present", Json::Bool(golden_total >= GOLDEN_MIN)),
        ("count", Json::Int(golden_total)),
        (
            "note",
            s(&format!(
                "proven by the exhaustive translate-parity golden corpus (see byte-identity): \
                 {golden_total} byte-pair(s), floor {GOLDEN_MIN}"
            )),
        ),
    ]));

    obj(vec![
        ("class", s("wire-conformance")),
        ("title", s("We speak every protocol to spec")),
        ("status", s(&class_status(&sources))),
        ("sources", Json::Array(sources)),
    ])
}

// ── CROSS-JOB CAPTURE, AND THE TWO THINGS IT MUST NOT DO ──────────────────────────────────────────

/// Stamp sources from sibling CI job results, without manufacturing claims.
///
/// A GitHub job result of `success` means the job passed. The manifest is a public claim about WHAT
/// that proves, and the old implementation over-claimed in two distinct ways:
///
/// 1. IT PROMOTED SOURCES WITH NO EVIDENCE. A green `check` job published `pass` for oracles
///    standing on a test file that does not exist. Now: no evidence, no pass. The source is left
///    `unknown` and says why.
/// 2. IT FANNED ONE RESULT OUT OVER A SUB-MAP (six dialects, seven a2a legs, three planes). Those
///    sub-maps say which INDIVIDUAL legs were proven; filling them from one aggregate makes them
///    say something nobody measured. They are left as their producer computed them.
///
/// `shared_with` records when the same result marked several sources, so the manifest does not read
/// as several independent measurements.
fn mark_sources(verdicts: &mut [Json], specs: &[String]) {
    let mut marks: BTreeMap<String, &'static str> = BTreeMap::new();
    for spec in specs {
        let Some((sid, res)) = spec.split_once('=') else {
            continue;
        };
        let res = py_strip(res).to_lowercase();
        if res.is_empty() {
            continue;
        }
        marks.insert(
            py_strip(sid).to_string(),
            if res == "success" || res == "pass" {
                "pass"
            } else {
                "fail"
            },
        );
    }
    if marks.is_empty() {
        return;
    }
    // Which ids were given the same verdict value? Only meaningful as "these came from one place".
    let mut by_value: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (sid, st) in &marks {
        by_value.entry(*st).or_default().push(sid.clone());
    }
    for v in verdicts.iter_mut() {
        if let Some(Json::Array(srcs)) = v.as_object_mut().and_then(|o| o.get_mut("sources")) {
            for src in srcs.iter_mut() {
                mark_one(src, &marks, &by_value);
            }
        }
        let st = match v.get("sources") {
            Json::Array(a) => class_status(a),
            _ => class_status(&[]),
        };
        if let Some(o) = v.as_object_mut() {
            o.insert("status", Json::Str(st));
        }
    }
}

fn mark_one(
    src: &mut Json,
    marks: &BTreeMap<String, &'static str>,
    by_value: &BTreeMap<&str, Vec<String>>,
) {
    let Some(sid) = src.get("id").as_str().map(str::to_string) else {
        return;
    };
    let Some(&st) = marks.get(&sid) else { return };
    let prior_note = match src.get("note") {
        n if n.truthy() => n.as_str().map(str::to_string),
        _ => None,
    };
    let cur_status = src.get("status").as_str().map(str::to_string);
    let evidence = src.get("evidence").clone();
    let present = src.get("evidence_present").truthy();
    let o = src.as_object_mut().expect("a source is an object");
    // A SIBLING'S PASS DOES NOT OVERWRITE THIS COLLATOR'S OWN FAIL. A producer that measured `fail`
    // (a collapsed corpus, a cargo filter that ran zero tests) measured it here; a sibling job's
    // `success` is a result about what THAT job ran, not a re-measurement.
    if cur_status.as_deref() == Some("fail") && st == "pass" {
        let head = prior_note.map(|n| format!("{n}; ")).unwrap_or_default();
        o.insert(
            "note",
            Json::Str(format!(
                "{head}the sibling ci.yml job reported pass, which does NOT overwrite this \
                 collator's own fail measurement"
            )),
        );
        return;
    }
    // FAIL CLOSED ON A SOURCE THAT NAMES NO EVIDENCE AT ALL: an unnamed subject is not a weaker
    // claim than a missing one; it is the same claim with less to check.
    if !evidence.truthy() {
        o.insert("status", s("unknown"));
        o.insert(
            "note",
            Json::Str(format!(
                "NOT captured: the sibling ci.yml job reported '{st}', but this source names NO \
                 evidence of its own, so there is nothing that result could be a result ABOUT. Give \
                 the source an `evidence` path (the gate script, test file or report it stands on) \
                 before marking it."
            )),
        );
        return;
    }
    if !present {
        o.insert("status", s("unknown"));
        o.insert(
            "note",
            Json::Str(format!(
                "NOT captured: the sibling ci.yml job reported '{st}', but this source's own \
                 evidence ({}) is not present in the tree, so that result says nothing about it. A \
                 job result is evidence for what the job ran; it cannot stand in for a test file \
                 that does not exist.",
                py_str(&evidence)
            )),
        );
        return;
    }
    o.insert("status", s(st));
    o.insert("note", s("captured from the sibling ci.yml job result"));
    let mut siblings: Vec<&String> = by_value
        .get(st)
        .into_iter()
        .flatten()
        .filter(|x| **x != sid)
        .collect();
    if !siblings.is_empty() {
        // Named so the manifest cannot be read as N independent measurements.
        siblings.sort();
        o.insert(
            "shared_with",
            Json::Array(siblings.into_iter().map(|x| s(x)).collect()),
        );
    }
    // Sub-maps are DELIBERATELY not touched.
}

// ── class-status reducer (the honesty rule) ───────────────────────────────────────────────────────

fn class_status(sources: &[Json]) -> String {
    let statuses: Vec<Option<&str>> = sources
        .iter()
        .filter(|x| status_of(x) != Some("reserved"))
        .map(status_of)
        .collect();
    let has = |x: &str| statuses.contains(&Some(x));
    if has("fail") {
        return "fail".into();
    }
    if has("unknown") {
        return "unknown".into();
    }
    // report-only sources are measured-but-non-blocking: they never redden, never green a class alone.
    let concrete: Vec<&str> = statuses
        .iter()
        .flatten()
        .copied()
        .filter(|x| matches!(*x, "pass" | "fail"))
        .collect();
    if !concrete.is_empty() && concrete.iter().all(|x| *x == "pass") {
        return "pass".into();
    }
    if !statuses.is_empty() && statuses.iter().all(|x| *x == Some("report-only")) {
        return "report-only".into();
    }
    if has("pass") {
        "pass".into()
    } else {
        "unknown".into()
    }
}

// ── the manifest ──────────────────────────────────────────────────────────────────────────────────

/// UTC `%Y-%m-%dT%H:%M:%SZ` of a unix time (civil-from-days; no timezone database needed).
fn utc_stamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn now_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    utc_stamp(secs)
}

/// The release provenance lifted from a staged receipt over the CLI defaults.
struct Release {
    version: String,
    tag: Json,
    qa_sha: Json,
    staging_tag: Json,
    digest: Json,
    run_id: String,
    run_url: String,
    recorded_at: String,
}

/// `staged.json` lift: `tag`, `staging_tag`, `digest`, `qa_sha` (over `sha`) and, when `--run-id`
/// was not given, `run_id`. An unreadable receipt, or one that is not an object, lifts nothing.
fn lift_staged(staged_text: Option<&str>, rel: &mut Release) {
    let Some(text) = staged_text else { return };
    let Ok(staged) = json_lite::parse(text) else {
        return;
    };
    let Json::Object(o) = &staged else { return };
    rel.tag = o.get("tag").cloned().unwrap_or(rel.tag.clone());
    rel.staging_tag = o.get("staging_tag").cloned().unwrap_or(Json::Null);
    rel.digest = o.get("digest").cloned().unwrap_or(Json::Null);
    rel.qa_sha = o.get("qa_sha").cloned().unwrap_or(rel.qa_sha.clone());
    if rel.run_id.is_empty() {
        rel.run_id = o.get("run_id").map_or(String::new(), py_str);
    }
}

/// Assemble the manifest object from finished verdicts: marks (through the ONE guarded
/// [`mark_sources`]), the release block, and the content digest over the verdicts.
fn assemble(mut verdicts: Vec<Json>, marks: &[String], rel: &Release, collator: &str) -> Json {
    // Honest cross-job capture: stamp a source's verdict from the sibling CI job that actually ran it.
    mark_sources(&mut verdicts, marks);
    let release = obj(vec![
        ("version", s(&rel.version)),
        ("tag", rel.tag.clone()),
        ("qa_sha", rel.qa_sha.clone()),
        ("staging_tag", rel.staging_tag.clone()),
        ("digest", rel.digest.clone()),
        ("run_id", s(&rel.run_id)),
        ("run_url", s(&rel.run_url)),
        ("recorded_at", s(&rel.recorded_at)),
    ]);
    // content digest over the verdicts (tamper-evidence; provenance is git history + run_url).
    let verdict_arr = Json::Array(verdicts);
    let digest = sha256::hex(dumps(&verdict_arr, None, true).as_bytes());
    obj(vec![
        ("schema_version", s("1")),
        ("release", release),
        ("verdicts", verdict_arr),
        (
            "provenance",
            obj(vec![
                ("content_digest", s(&format!("sha256:{digest}"))),
                ("collator", s(collator)),
            ]),
        ),
    ])
}

const COLLATOR: &str = "cargo xtask proof-manifest";

// ── the index ─────────────────────────────────────────────────────────────────────────────────────

/// Roll every `<proof_dir>/<v>.json` into `index.json`. AN INDEX OVER NOTHING IS NOT AN EMPTY
/// PROBLEM SET: `releases: []` reads exactly like a dashboard with nothing wrong, so unparseable
/// manifests are named, and a roll-up that found no manifest at all refuses to overwrite the index.
fn write_index(proof_dir: &Path) -> i32 {
    let mut names: Vec<PathBuf> = std::fs::read_dir(proof_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut entries: Vec<Json> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for p in names {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "index.json" {
            continue;
        }
        let stem = p
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let m = match std::fs::read(&p) {
            Err(_) => {
                skipped.push(format!("{name} (OSError)"));
                continue;
            }
            Ok(bytes) => match String::from_utf8(bytes) {
                Err(_) => {
                    skipped.push(format!("{name} (UnicodeDecodeError)"));
                    continue;
                }
                Ok(t) => match json_lite::parse(&t) {
                    Err(_) => {
                        skipped.push(format!("{name} (JSONDecodeError)"));
                        continue;
                    }
                    Ok(j) => j,
                },
            },
        };
        let rel = m.get("release");
        let verdicts: Vec<Json> = match m.get("verdicts") {
            Json::Array(a) => a
                .iter()
                .map(|v| {
                    obj(vec![
                        ("class", v.get("class").clone()),
                        ("status", v.get("status").clone()),
                    ])
                })
                .collect(),
            _ => Vec::new(),
        };
        let version = match rel.as_object().and_then(|o| o.get("version")) {
            Some(v) => v.clone(),
            None => s(&stem),
        };
        entries.push(obj(vec![
            ("version", version),
            ("tag", rel.get("tag").clone()),
            ("qa_sha", rel.get("qa_sha").clone()),
            ("recorded_at", rel.get("recorded_at").clone()),
            ("file", s(&name)),
            ("verdicts", Json::Array(verdicts)),
        ]));
    }
    for sk in &skipped {
        eprintln!("proof-manifest: SKIPPED unreadable manifest {sk}");
    }
    if entries.is_empty() {
        eprintln!(
            "proof-manifest: REFUSING to write an EMPTY index over {}. Zero readable manifests is \
             not zero problems -- an index with no releases renders as a dashboard with nothing \
             wrong on it. Leaving any existing index.json in place.",
            proof_dir.display()
        );
        return 1;
    }
    let n = entries.len();
    let index = obj(vec![
        ("schema_version", s("1")),
        ("releases", Json::Array(entries)),
    ]);
    let path = proof_dir.join("index.json");
    if let Err(e) = std::fs::write(&path, dumps(&index, Some(2), false) + "\n") {
        eprintln!("proof-manifest: cannot write {}: {e}", path.display());
        return 3;
    }
    eprintln!("proof-manifest: wrote {} ({n} release(s))", path.display());
    0
}

// ── the selftest ──────────────────────────────────────────────────────────────────────────────────

/// A private temp dir for the hit-list TSVs. The caller removes it (WE MADE IT, WE REMOVE IT).
fn default_hits_dir() -> Result<PathBuf, String> {
    private_tmp("proof-hits-")
}

fn private_tmp(prefix: &str) -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for n in 0..1000u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = base.join(format!("{prefix}{pid}-{nanos}-{n}"));
        if std::fs::create_dir(&p).is_ok() {
            return Ok(p);
        }
    }
    Err("could not create a private temp directory".into())
}

/// Prove the manifest cannot publish a claim with nothing behind it. Every case here is one the
/// collator got WRONG in the green direction before the case existed: a corpus path that had moved
/// (published `total: 0, status: pass`), a cargo filter that selected nothing (cargo exits 0 on
/// that), two oracle paths with no file at them (published `pass` from a sibling job's result), and
/// a single job result fanned out over a six-entry dialect map.
fn selftest(root: &Path) -> i32 {
    let mut bad = false;
    let mut ok = |cond: bool, label: &str, detail: &str| {
        if cond {
            println!("  [ok]     {label}");
        } else {
            let d = if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            };
            println!("  [FAILED] {label}{d}");
            bad = true;
        }
    };
    println!("proof-manifest selftest");

    // 1. The corpus is where this file says it is, and it is not empty.
    let v = verdict_byte_identity(root, false);
    let src = v
        .get("sources")
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Json::Null);
    let total = src.get("total").as_i64().unwrap_or(-1);
    ok(
        root.join(GOLDEN_DIR).is_dir(),
        &format!("the golden corpus path resolves to a real directory ({GOLDEN_DIR})"),
        "",
    );
    ok(
        total >= GOLDEN_MIN,
        &format!("the corpus yields {total} byte-pairs, at or above the floor of {GOLDEN_MIN}"),
        "a moved corpus used to publish total=0 alongside status=pass",
    );

    // 2. A corpus that yields nothing is a FAIL, never a pass. Driven through the real function
    //    against a root with no corpus in it, which is the state the stale path produced.
    match private_tmp("proof-selftest-") {
        Ok(empty_root) => {
            let v0 = verdict_byte_identity(&empty_root, false);
            let s0 = v0
                .get("sources")
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(Json::Null);
            ok(
                s0.get("total").as_i64() == Some(0) && status_of(&s0) == Some("fail"),
                "a corpus of zero byte-pairs is FAIL, not pass/unknown",
                &format!(
                    "got total={:?} status={:?}",
                    s0.get("total").as_i64(),
                    status_of(&s0)
                ),
            );
            ok(
                s0.get("note").as_str().unwrap_or("").contains("floor"),
                "and it says why, naming the floor",
                "",
            );
            let _ = std::fs::remove_dir_all(&empty_root);
        }
        Err(e) => ok(
            false,
            "a corpus of zero byte-pairs is FAIL, not pass/unknown",
            &e,
        ),
    }

    // 2b. THE SAME FLOOR ON THE DIALECT MAPS. A gate green over no map file classifies nothing.
    match private_tmp("proof-selftest-") {
        Ok(empty_root) => {
            let fc0 = verdict_field_coverage(&empty_root, true).unwrap_or(Json::Null);
            ok(
                status_of(&fc0) == Some("unknown") && fc0.get("evidence_count").as_i64() == Some(0),
                "absent dialect maps are UNKNOWN, not a pass over zero fields",
                &format!(
                    "got status={:?} count={:?}",
                    status_of(&fc0),
                    fc0.get("evidence_count").as_i64()
                ),
            );
            let note = fc0
                .get("sources")
                .as_array()
                .and_then(|a| a.first())
                .and_then(|x| x.get("note").as_str().map(str::to_string))
                .unwrap_or_default();
            ok(
                note.contains("classified"),
                "and it says why, naming that nothing was classified",
                "",
            );
            let _ = std::fs::remove_dir_all(&empty_root);
        }
        Err(e) => ok(
            false,
            "absent dialect maps are UNKNOWN, not a pass over zero fields",
            &e,
        ),
    }
    let fc = verdict_field_coverage(root, false).unwrap_or(Json::Null);
    let evidence_total = fc.get("evidence_total").as_i64().unwrap_or(0);
    let waived = fc
        .get("sources")
        .as_array()
        .and_then(|a| a.first())
        .and_then(|x| x.get("waived").as_i64())
        .unwrap_or(0);
    ok(
        evidence_total > 0 && waived > 0,
        &format!("the real map files yield {evidence_total} classified path(s), marks included"),
        "the floor must refuse an empty map, not refuse the map",
    );

    // 3. Every oracle names a file that is actually there.
    let missing: Vec<String> = v
        .get("sources")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .filter(|x| x.get("evidence").truthy() && !x.get("evidence_present").truthy())
        .map(|x| format!("{} -> {}", py_str(x.get("id")), py_str(x.get("evidence"))))
        .collect();
    ok(
        missing.is_empty(),
        "every money-path oracle names a test file that exists",
        &format!("missing: {}", missing.join(", ")),
    );

    // 4. A sibling job's result cannot promote a source whose evidence is absent.
    let mut fake = vec![obj(vec![
        ("class", s("c")),
        (
            "sources",
            Json::Array(vec![
                obj(vec![
                    ("id", s("ghost")),
                    ("status", s("unknown")),
                    ("evidence", s("crates/nope/tests/nope.rs")),
                    ("evidence_present", Json::Bool(false)),
                ]),
                obj(vec![
                    ("id", s("real")),
                    ("status", s("unknown")),
                    ("evidence", s(GOLDEN_DIR)),
                    ("evidence_present", Json::Bool(true)),
                ]),
            ]),
        ),
    ])];
    mark_sources(&mut fake, &["ghost=success".into(), "real=success".into()]);
    let pair = fake[0].get("sources").as_array().unwrap_or(&[]).to_vec();
    let (g, r) = (&pair[0], &pair[1]);
    ok(
        status_of(g) == Some("unknown")
            && g.get("note")
                .as_str()
                .unwrap_or("")
                .contains("NOT captured"),
        "a job result does NOT promote an oracle whose test file is missing",
        &format!("got {:?}", status_of(g)),
    );
    ok(
        status_of(r) == Some("pass"),
        "and it DOES promote one whose evidence is present",
        &format!("got {:?}", status_of(r)),
    );
    let one = |x: &Json, want: &str| {
        x.get("shared_with")
            .as_array()
            .is_some_and(|a| a.len() == 1 && a[0].as_str() == Some(want))
    };
    ok(
        one(g, "real") || one(r, "ghost"),
        "sources stamped from the same result say so, so the manifest is not read as N measurements",
        "",
    );

    // 4b. NOR CAN IT PROMOTE A SOURCE THAT NAMES NO EVIDENCE AT ALL.
    let mut keyless = vec![obj(vec![
        ("class", s("c")),
        (
            "sources",
            Json::Array(vec![obj(vec![
                ("id", s("keyless")),
                ("status", s("unknown")),
            ])]),
        ),
    ])];
    mark_sources(&mut keyless, &["keyless=success".into()]);
    let k = keyless[0].get("sources").as_array().unwrap_or(&[])[0].clone();
    ok(
        status_of(&k) == Some("unknown")
            && k.get("note")
                .as_str()
                .unwrap_or("")
                .contains("names NO evidence"),
        "a job result does NOT promote a source that names no evidence at all",
        &format!("got {:?}", status_of(&k)),
    );

    // 4c. And every source this collator actually emits names its evidence, so none of them are
    //     silently unmarkable. Checked over the whole manifest rather than one class.
    let all_v = [
        verdict_byte_identity(root, false),
        verdict_composability(root, false),
        verdict_field_coverage(root, false).unwrap_or(Json::Null),
        verdict_conformance(root, None),
    ];
    let unnamed: Vec<String> = all_v
        .iter()
        .flat_map(|v| v.get("sources").as_array().unwrap_or(&[]).to_vec())
        .filter(|x| !x.get("evidence").truthy())
        .map(|x| py_str(x.get("id")))
        .collect();
    ok(
        unnamed.is_empty(),
        "every source the collator emits names an evidence path",
        &format!("sources with no evidence key: {}", unnamed.join(", ")),
    );

    // 5. One job result is not six dialect verdicts.
    let mut dialects = Obj::new();
    for d in [
        "anthropic",
        "openai",
        "gemini",
        "responses",
        "bedrock",
        "cohere",
    ] {
        dialects.insert(d, s("unknown"));
    }
    let mut fan = vec![obj(vec![
        ("class", s("c")),
        (
            "sources",
            Json::Array(vec![obj(vec![
                ("id", s("llm-dialects")),
                ("status", s("unknown")),
                ("evidence", s(GOLDEN_DIR)),
                ("evidence_present", Json::Bool(true)),
                ("dialects", Json::Object(dialects)),
            ])]),
        ),
    ])];
    mark_sources(&mut fan, &["llm-dialects=success".into()]);
    let f0 = fan[0].get("sources").as_array().unwrap_or(&[])[0].clone();
    let all_unknown = f0
        .get("dialects")
        .as_object()
        .is_some_and(|o| o.iter().all(|(_, x)| x.as_str() == Some("unknown")));
    ok(
        all_unknown,
        "one job result is not fanned out into six per-dialect verdicts",
        &format!("got {}", dumps(f0.get("dialects"), None, false)),
    );
    ok(
        status_of(&f0) == Some("pass"),
        "while the source's own aggregate status is still captured",
        "",
    );

    // 6. THE PARITY RUN NAMES THE CRATE THE TESTS ARE IN, AND ZERO TESTS RUN IS NOT A PASS.
    let cmd = parity_cmd();
    let crate_name = cmd[cmd.iter().position(|x| *x == "-p").unwrap_or(0) + 1];
    let crate_src = root.join("crates").join(crate_name).join("src");
    let holder = crate_src.is_dir() && any_file_mentions(&crate_src, "translate_parity");
    ok(
        holder,
        &format!("the parity command's crate ({crate_name}) contains translate_parity tests"),
        &format!("crates/{crate_name}/src holds no file mentioning translate_parity"),
    );
    let (zst, _) = cargo_test_status(
        0,
        "running 0 tests\n\ntest result: ok. 0 passed; 0 failed\n",
    );
    ok(
        zst == "fail",
        "a cargo run that exits 0 having run ZERO tests is FAIL",
        &format!("got {zst:?}"),
    );
    let (pst, _) = cargo_test_status(0, "running 7 tests\ntest result: ok. 7 passed; 0 failed\n");
    ok(
        pst == "pass",
        "and one that ran tests and exited 0 is PASS (control)",
        &format!("got {pst:?}"),
    );

    // 7. A sibling's pass does not overwrite this collator's own fail.
    let mut own = vec![obj(vec![
        ("class", s("c")),
        (
            "sources",
            Json::Array(vec![obj(vec![
                ("id", s("measured")),
                ("status", s("fail")),
                ("evidence", s(GOLDEN_DIR)),
                ("evidence_present", Json::Bool(true)),
            ])]),
        ),
    ])];
    mark_sources(&mut own, &["measured=success".into()]);
    let o0 = own[0].get("sources").as_array().unwrap_or(&[])[0].clone();
    ok(
        status_of(&o0) == Some("fail"),
        "a sibling job's pass does NOT overwrite a fail this collator measured itself",
        &format!("got {:?}", status_of(&o0)),
    );

    // 8. THE COLLATION MARKS THROUGH mark_sources(), not a second, unguarded copy of it. Read off
    //    the source of `assemble` (the one place verdicts are marked): it must call mark_sources and
    //    must not assign a `status` itself.
    let body = fn_body(include_str!("proof_manifest.rs"), "fn assemble(");
    let writes = body.contains("insert(\"status\"") || body.contains("[\"status\"] =");
    ok(
        body.contains("mark_sources(") && !writes,
        "main() marks sources only through the guarded mark_sources()",
        &format!(
            "calls mark_sources={}, writes s['status'] itself={writes}",
            body.contains("mark_sources(")
        ),
    );

    // 9. EVERY MODULE THIS FILE USES IS IMPORTED: the Rust compiler proves that at build time (the
    //    Python collator needed an AST pass for it). The default-hits-dir path is also driven for
    //    real: it must create its private temp dir.
    ok(true, "every module referenced as `x.attr` is imported", "");
    match default_hits_dir() {
        Ok(hd) => {
            ok(
                hd.is_dir(),
                "the default (no --hits-dir) path creates its private temp dir",
                "",
            );
            let _ = std::fs::remove_dir_all(&hd);
        }
        Err(e) => ok(
            false,
            "the default (no --hits-dir) path creates its private temp dir",
            &e,
        ),
    }

    // 10. EVERY EVIDENCE PATH THIS COLLATOR NAMES EXISTS, so a gate script retired into
    //     `cargo xtask gate ...` cannot leave `evidence_present: false` on a gate that ran and
    //     passed. (Globs name report patterns, not files, and are not in the list.)
    let gone: Vec<&str> = EVIDENCE_PATHS
        .iter()
        .copied()
        .filter(|p| !root.join(p).exists())
        .collect();
    ok(
        gone.is_empty(),
        &format!(
            "every evidence path named in this file exists ({} checked)",
            EVIDENCE_PATHS.len()
        ),
        &format!("missing: {}", gone.join(", ")),
    );

    println!();
    if bad {
        println!("proof-manifest selftest: FAILED");
        return 1;
    }
    println!("proof-manifest selftest: every published claim maps to evidence that exists");
    0
}

/// The text of the function starting at `sig`, up to the next top-level `\nfn ` / `\nconst ` item.
fn fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
    let Some(i) = src.find(sig) else { return "" };
    let rest = &src[i + sig.len()..];
    let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 3);
    &rest[..end]
}

fn any_file_mentions(dir: &Path, needle: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_dir() {
            if any_file_mentions(&p, needle) {
                return true;
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            if let Ok(b) = std::fs::read(&p) {
                if String::from_utf8_lossy(&b).contains(needle) {
                    return true;
                }
            }
        }
    }
    false
}

// ── main ──────────────────────────────────────────────────────────────────────────────────────────

const USAGE: &str = "\
usage: cargo xtask proof-manifest [--selftest] [--version V] [--out FILE] [--repo-root DIR]
       [--sha SHA] [--run-id ID] [--run-url URL] [--staged-json FILE] [--reports-dir DIR]
       [--hits-dir DIR] [--run-cargo] [--run-parity] [--run-composability]
       [--mark ID=STATUS]... [--index] [--print]";

#[derive(Default)]
struct Args {
    selftest: bool,
    version: Option<String>,
    out: Option<String>,
    repo_root: Option<String>,
    sha: Option<String>,
    run_id: String,
    run_url: String,
    staged_json: Option<String>,
    reports_dir: Option<String>,
    hits_dir: Option<String>,
    run_cargo: bool,
    run_parity: bool,
    run_composability: bool,
    marks: Vec<String>,
    index: bool,
    print: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let raw = &argv[i];
        let (flag, inline) = match raw.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (raw.clone(), None),
        };
        let value = |i: &mut usize| -> Result<String, String> {
            if let Some(v) = &inline {
                return Ok(v.clone());
            }
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("argument {flag}: expected one argument"))
        };
        match flag.as_str() {
            "--selftest" => a.selftest = true,
            "--run-cargo" => a.run_cargo = true,
            "--run-parity" => a.run_parity = true,
            "--run-composability" => a.run_composability = true,
            "--index" => a.index = true,
            "--print" => a.print = true,
            "--version" => a.version = Some(value(&mut i)?),
            "--out" => a.out = Some(value(&mut i)?),
            "--repo-root" => a.repo_root = Some(value(&mut i)?),
            "--sha" => a.sha = Some(value(&mut i)?),
            "--run-id" => a.run_id = value(&mut i)?,
            "--run-url" => a.run_url = value(&mut i)?,
            "--staged-json" => a.staged_json = Some(value(&mut i)?),
            "--reports-dir" => a.reports_dir = Some(value(&mut i)?),
            "--hits-dir" => a.hits_dir = Some(value(&mut i)?),
            "--mark" => a.marks.push(value(&mut i)?),
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }
    Ok(a)
}

fn resolve(p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    let abs = if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_or(path.clone(), |c| c.join(&path))
    };
    std::fs::canonicalize(&abs).unwrap_or(abs)
}

/// The entry point (`cargo xtask proof-manifest …`). `default_root` is the workspace root, the
/// stand-in for "the script's parent's parent".
pub fn main(default_root: &Path, argv: &[String]) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{USAGE}\nproof-manifest: error: {e}");
            return 2;
        }
    };
    let root = match &args.repo_root {
        Some(r) => resolve(r),
        None => resolve(&default_root.display().to_string()),
    };
    if args.selftest {
        return selftest(&root);
    }
    let (Some(version), Some(out)) = (args.version.clone(), args.out.clone()) else {
        eprintln!("{USAGE}\nproof-manifest: error: --version and --out are required (except with --selftest)");
        return 2;
    };
    match collate(&root, &args, &version, &out) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("proof-manifest: {e}");
            3
        }
    }
}

fn collate(root: &Path, args: &Args, version: &str, out: &str) -> Result<i32, String> {
    let out_path = if Path::new(out).is_absolute() {
        PathBuf::from(out)
    } else {
        root.join(out)
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let sha = match &args.sha {
        Some(x) if !x.is_empty() => x.clone(),
        _ => {
            let (code, text) = run(&["git", "rev-parse", "HEAD"], root, &[], None);
            if code == 0 {
                py_strip(&text).to_string()
            } else {
                "unknown".to_string()
            }
        }
    };
    let mut rel = Release {
        version: version.to_string(),
        tag: s(version),
        qa_sha: s(&sha),
        staging_tag: Json::Null,
        digest: Json::Null,
        run_id: args.run_id.clone(),
        run_url: args.run_url.clone(),
        recorded_at: now_stamp(),
    };
    if let Some(sj) = args.staged_json.as_deref().filter(|p| !p.is_empty()) {
        if Path::new(sj).is_file() {
            let text = std::fs::read(sj)
                .ok()
                .and_then(|b| String::from_utf8(b).ok());
            lift_staged(text.as_deref(), &mut rel);
        }
    }

    // Hit-list TSVs contain SOURCE lines -> they must never land in the committed manifest tree.
    // Default to a temp dir (WE MADE IT, WE REMOVE IT); CI can point --hits-dir at a scratch path.
    let (hits_dir, own_hits) = match &args.hits_dir {
        Some(h) => (resolve(h), false),
        None => (default_hits_dir()?, true),
    };
    std::fs::create_dir_all(&hits_dir).map_err(|e| format!("{}: {e}", hits_dir.display()))?;
    let reports_dir = args.reports_dir.as_deref().map(resolve);

    let run_parity = args.run_cargo || args.run_parity;
    let run_composability = args.run_cargo || args.run_composability;
    let verdicts = vec![
        verdict_byte_identity(root, run_parity),
        verdict_plane_neutrality(root, &hits_dir),
        verdict_composability(root, run_composability),
        verdict_field_coverage(root, true)?,
        verdict_conformance(root, reports_dir.as_deref()),
    ];
    if own_hits {
        let _ = std::fs::remove_dir_all(&hits_dir);
    }

    let manifest = assemble(verdicts, &args.marks, &rel, COLLATOR);
    std::fs::write(&out_path, dumps(&manifest, Some(2), false) + "\n")
        .map_err(|e| format!("{}: {e}", out_path.display()))?;
    eprintln!("proof-manifest: wrote {}", out_path.display());

    if args.index {
        let dir = out_path.parent().unwrap_or(Path::new("."));
        if write_index(dir) != 0 {
            // The manifest itself was written; only the roll-up refused. Non-zero so CI cannot
            // publish an index that says nothing and call the step green.
            return Ok(1);
        }
    }
    if args.print {
        println!("{}", dumps(&manifest, Some(2), false));
    }
    Ok(0)
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn src(id: &str, status: &str, evidence: Option<(&str, bool)>) -> Json {
        let mut v = vec![("id", s(id)), ("status", s(status))];
        if let Some((e, p)) = evidence {
            v.push(("evidence", s(e)));
            v.push(("evidence_present", Json::Bool(p)));
        }
        obj(v)
    }

    fn class(name: &str, sources: Vec<Json>) -> Json {
        obj(vec![("class", s(name)), ("sources", Json::Array(sources))])
    }

    fn only_source(v: &Json, i: usize) -> Json {
        v.get("sources").as_array().unwrap()[i].clone()
    }

    #[test]
    fn class_status_reduction() {
        let st =
            |xs: &[&str]| class_status(&xs.iter().map(|x| src("a", x, None)).collect::<Vec<_>>());
        assert_eq!(st(&["pass", "pass"]), "pass");
        assert_eq!(st(&["pass", "unknown"]), "unknown");
        assert_eq!(st(&["pass", "unknown", "fail"]), "fail");
        assert_eq!(st(&["report-only"]), "report-only");
        assert_eq!(st(&["report-only", "report-only"]), "report-only");
        // report-only never greens or reddens a class alone, but pass beside it is pass.
        assert_eq!(st(&["report-only", "pass"]), "pass");
        assert_eq!(st(&["reserved", "pass"]), "pass");
        assert_eq!(st(&["reserved"]), "unknown");
        assert_eq!(st(&[]), "unknown");
    }

    #[test]
    fn ensure_ascii_and_separators() {
        let v = obj(vec![
            ("b", s("é\u{1f600}\u{7f}\"/")),
            ("a", Json::Array(vec![])),
        ]);
        assert_eq!(
            dumps(&v, None, true),
            r#"{"a":[],"b":"\u00e9\ud83d\ude00\u007f\"/"}"#
        );
        assert_eq!(
            dumps(&v, Some(2), false),
            "{\n  \"b\": \"\\u00e9\\ud83d\\ude00\\u007f\\\"/\",\n  \"a\": []\n}"
        );
    }

    #[test]
    fn scrapers_follow_python_regex_semantics() {
        let t = "header\n  openai     12\n  mcp   3  \nTOTAL  15\n";
        assert_eq!(scrape_key(t, "openai"), Some(12));
        assert_eq!(scrape_key(t, "mcp"), Some(3));
        assert_eq!(scrape_total(t), Some(15));
        assert_eq!(scrape_key(t, "gemini"), None);
        assert_eq!(scrape_key("TOTAL 7 trailing", "TOTAL"), None);
        assert_eq!(scrape_key("TOTAL 7", "TOTAL"), Some(7));
        assert_eq!(count_hit_lines("a.rs:12\nb.rs:x\nc.rs:3: z"), 2);
        assert_eq!(unclassified_count("x 3 unclassified; 9 unclassified"), 3);
        assert_eq!(unclassified_count("none"), 0);
        assert_eq!(
            tests_run("running 1 test\nrunning 4 tests\nrunning 2 testsx"),
            Some(5)
        );
        assert_eq!(tests_run("nothing"), None);
        assert_eq!(
            freeze_row("x\nplane-purity:core-llm-family-freeze\tPASS\tdetail\tcount=42\n"),
            Some(("PASS".to_string(), 42))
        );
        assert_eq!(
            freeze_row("plane-purity:core-llm-family-freeze\tPASS\tno count"),
            None
        );
    }

    #[test]
    fn utc_stamp_matches_known_instants() {
        assert_eq!(utc_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_stamp(1_759_276_800), "2025-10-01T00:00:00Z");
        assert_eq!(utc_stamp(1_709_164_800 + 3661), "2024-02-29T01:01:01Z");
    }

    #[test]
    fn golden_lane_filter() {
        assert_eq!(golden_lane("req_o2a_basic.json").as_deref(), Some("o2a"));
        assert_eq!(golden_lane("resp_a2o_x.json").as_deref(), Some("a2o"));
        assert_eq!(golden_lane("req_o2a_.json"), None);
        assert_eq!(golden_lane("rsp_o2a_x.json"), None);
        assert_eq!(golden_lane("req_O2a_x.json"), None);
        assert_eq!(golden_lane("req_o2a_x.txt"), None);
    }

    /// Fixed synthetic verdicts pushed through the reduction, a `--mark` override and the
    /// staged-json lift: the whole published document, byte for byte.
    #[test]
    fn manifest_bytes_for_synthetic_verdicts() {
        let verdicts = vec![
            class(
                "alpha",
                vec![
                    src("measured-fail", "fail", Some(("a/b.rs", true))),
                    src("sibling-pass", "unknown", Some(("c/d.rs", true))),
                ],
            ),
            class(
                "beta",
                vec![src("meter", "report-only", Some(("e.sh", true)))],
            ),
            class(
                "gamma",
                vec![src("never-ran", "unknown", Some(("f.rs", true)))],
            ),
        ];
        let mut rel = Release {
            version: "9.9.9".into(),
            tag: s("9.9.9"),
            qa_sha: s("cafe"),
            staging_tag: Json::Null,
            digest: Json::Null,
            run_id: String::new(),
            run_url: "https://example.invalid/1".into(),
            recorded_at: "2026-01-02T03:04:05Z".into(),
        };
        lift_staged(
            Some(
                r#"{"tag":"v9.9.9-rc","staging_tag":"stg","digest":"sha256:abc","qa_sha":"beef","run_id":77}"#,
            ),
            &mut rel,
        );
        assert_eq!(rel.tag, s("v9.9.9-rc"));
        assert_eq!(rel.qa_sha, s("beef"));
        assert_eq!(rel.run_id, "77");
        let marks: Vec<String> = vec![
            "measured-fail=success".into(), // its own fail must stand
            "sibling-pass=success".into(),  // promoted: evidence present
            "bogus".into(),                 // no `=`: ignored
            "never-ran=".into(),            // empty result: ignored
        ];
        let m = assemble(verdicts, &marks, &rel, COLLATOR);
        let v = m.get("verdicts").as_array().unwrap();
        // class reduction: fail stays fail, report-only alone is report-only, never-ran is unknown.
        assert_eq!(v[0].get("status").as_str(), Some("fail"));
        assert_eq!(v[1].get("status").as_str(), Some("report-only"));
        assert_eq!(v[2].get("status").as_str(), Some("unknown"));
        let text = dumps(&m, Some(2), false) + "\n";
        let again = dumps(&m, Some(2), false) + "\n";
        assert_eq!(text, again);
        // Exact bytes of the marked classes.
        let alpha0 = only_source(&m.get("verdicts").as_array().unwrap()[0], 0);
        assert_eq!(
            dumps(&alpha0, None, false),
            r#"{"id":"measured-fail","status":"fail","evidence":"a/b.rs","evidence_present":true,"note":"the sibling ci.yml job reported pass, which does NOT overwrite this collator's own fail measurement"}"#
        );
        let alpha1 = only_source(&m.get("verdicts").as_array().unwrap()[0], 1);
        assert_eq!(
            dumps(&alpha1, None, false),
            r#"{"id":"sibling-pass","status":"pass","evidence":"c/d.rs","evidence_present":true,"note":"captured from the sibling ci.yml job result","shared_with":["measured-fail"]}"#
        );
        // The release block and provenance, byte for byte.
        let release = dumps(m.get("release"), None, false);
        assert_eq!(
            release,
            r#"{"version":"9.9.9","tag":"v9.9.9-rc","qa_sha":"beef","staging_tag":"stg","digest":"sha256:abc","run_id":"77","run_url":"https://example.invalid/1","recorded_at":"2026-01-02T03:04:05Z"}"#
        );
        let digest = sha256::hex(dumps(m.get("verdicts"), None, true).as_bytes());
        assert_eq!(
            dumps(m.get("provenance"), None, false),
            format!(
                r#"{{"content_digest":"sha256:{digest}","collator":"cargo xtask proof-manifest"}}"#
            )
        );
    }

    /// The honesty rule on whole classes: a not-run source renders `unknown`, a report-only meter
    /// `report-only`, a failed source `fail` -- each class re-reduced after marks.
    #[test]
    fn classes_render_unknown_report_only_and_fail() {
        let mut vs = vec![
            class(
                "c-fail",
                vec![
                    src("x", "pass", Some(("p", true))),
                    src("y", "fail", Some(("p", true))),
                ],
            ),
            class("c-ro", vec![src("m", "report-only", Some(("p", true)))]),
            class("c-unk", vec![src("n", "unknown", Some(("p", true)))]),
        ];
        mark_sources(&mut vs, &["nothing-matches=success".into()]);
        let st: Vec<String> = vs
            .iter()
            .map(|v| v.get("status").as_str().unwrap().to_string())
            .collect();
        assert_eq!(st, ["fail", "report-only", "unknown"]);
        // An all-empty / malformed --mark never re-reduces (and so never writes a status).
        let mut untouched = vec![class("c", vec![src("x", "unknown", Some(("p", true)))])];
        mark_sources(&mut untouched, &["x".into(), "x=  ".into()]);
        assert_eq!(untouched[0].get("status"), &Json::Null);
        // --mark overrides a fail only through the guard: an unknown becomes a pass; a pass of its own
        // is replaced by a sibling's fail.
        let mut o = vec![class(
            "c",
            vec![
                src("x", "unknown", Some(("p", true))),
                src("z", "pass", Some(("p", true))),
            ],
        )];
        mark_sources(&mut o, &["x=Success".into(), "z=failure".into()]);
        assert_eq!(status_of(&only_source(&o[0], 0)), Some("pass"));
        assert_eq!(status_of(&only_source(&o[0], 1)), Some("fail"));
        assert_eq!(o[0].get("status").as_str(), Some("fail"));
    }

    #[test]
    fn staged_receipt_that_is_not_an_object_lifts_nothing() {
        let mk = || Release {
            version: "v".into(),
            tag: s("v"),
            qa_sha: s("sha"),
            staging_tag: Json::Null,
            digest: Json::Null,
            run_id: "keep".into(),
            run_url: String::new(),
            recorded_at: String::new(),
        };
        let mut r = mk();
        lift_staged(Some("[1,2]"), &mut r);
        lift_staged(Some("not json"), &mut r);
        lift_staged(None, &mut r);
        assert_eq!(
            (r.tag.clone(), r.run_id.clone()),
            (s("v"), "keep".to_string())
        );
        // An explicit --run-id wins over the receipt's.
        lift_staged(Some(r#"{"run_id": 5}"#), &mut r);
        assert_eq!(r.run_id, "keep");
        // A receipt's null tag is lifted as null, as `staged.get("tag", tag)` would.
        lift_staged(Some(r#"{"tag": null}"#), &mut r);
        assert_eq!(r.tag, Json::Null);
    }

    #[test]
    fn cargo_test_status_cases() {
        assert_eq!(cargo_test_status(101, "").0, "fail");
        assert_eq!(cargo_test_status(0, "running 0 tests\n").0, "fail");
        assert_eq!(cargo_test_status(0, "").0, "fail");
        let (st, note) = cargo_test_status(0, "running 7 tests\n");
        assert_eq!((st, note.as_str()), ("pass", "7 test(s) ran and passed"));
    }

    #[test]
    fn mark_guards_ported_from_the_selftest() {
        // No evidence key, evidence absent, sibling pass over own fail, no sub-map fan-out.
        let mut v = vec![class(
            "c",
            vec![
                src("keyless", "unknown", None),
                src("ghost", "unknown", Some(("nope.rs", false))),
                src("measured", "fail", Some((GOLDEN_DIR, true))),
            ],
        )];
        mark_sources(
            &mut v,
            &[
                "keyless=success".into(),
                "ghost=success".into(),
                "measured=success".into(),
            ],
        );
        let k = only_source(&v[0], 0);
        assert_eq!(status_of(&k), Some("unknown"));
        assert!(k
            .get("note")
            .as_str()
            .unwrap()
            .contains("names NO evidence"));
        let g = only_source(&v[0], 1);
        assert_eq!(status_of(&g), Some("unknown"));
        assert!(g
            .get("note")
            .as_str()
            .unwrap()
            .contains("(nope.rs) is not present"));
        assert_eq!(status_of(&only_source(&v[0], 2)), Some("fail"));
    }

    #[test]
    fn index_rolls_up_and_refuses_empty() {
        let dir = private_tmp("pm-index-test-").unwrap();
        // Nothing readable: refuse, write nothing.
        std::fs::write(dir.join("bad.json"), "{nope").unwrap();
        assert_eq!(write_index(&dir), 1);
        assert!(!dir.join("index.json").exists());
        std::fs::write(
            dir.join("1.0.json"),
            r#"{"release":{"version":"1.0","tag":"t","qa_sha":"s","recorded_at":"r"},"verdicts":[{"class":"c","status":"pass","x":1}]}"#,
        )
        .unwrap();
        assert_eq!(write_index(&dir), 0);
        assert_eq!(
            std::fs::read_to_string(dir.join("index.json")).unwrap(),
            "{\n  \"schema_version\": \"1\",\n  \"releases\": [\n    {\n      \"version\": \"1.0\",\n      \"tag\": \"t\",\n      \"qa_sha\": \"s\",\n      \"recorded_at\": \"r\",\n      \"file\": \"1.0.json\",\n      \"verdicts\": [\n        {\n          \"class\": \"c\",\n          \"status\": \"pass\"\n        }\n      ]\n    }\n  ]\n}\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn arg_parsing() {
        let a = parse_args(
            &[
                "--version",
                "x",
                "--out=o.json",
                "--mark",
                "a=b",
                "--mark",
                "c=d",
                "--print",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(
            (a.version.as_deref(), a.out.as_deref()),
            (Some("x"), Some("o.json"))
        );
        assert_eq!(a.marks, ["a=b", "c=d"]);
        assert!(a.print && !a.index);
        assert!(parse_args(&["--bogus".to_string()]).is_err());
        assert!(parse_args(&["--version".to_string()]).is_err());
    }
}
