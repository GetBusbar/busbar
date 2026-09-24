//! `cargo xtask gate hot-path-perf` — THE HOT-PATH PERF WITNESS, ENFORCED.
//!
//! `docs/design/BUSBAR-1.6.0.md` Part 3 §8 owes a perf gate: "criterion,
//! plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a per-token host-call counter
//! on the streaming path asserted == 0", and it is one of the two criterion benches that
//! raise the core-engine tests/benches dimension 8→9. The MEASUREMENT lives in the criterion
//! instrument `crates/busbar-kernel/benches/plane_host_vtable_perf.rs`; this gate is what keeps that
//! instrument making every one of the budget's claims, so a claim cannot be quietly dropped from the bench
//! without an owed row going missing.
//!
//! Five claims, five rows — the same shape as `duplex-ws-default-edge`:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND its OWN `[[bench]]` block says `harness = false` |
//! | `:vtable-vs-direct` | it measures the REAL `PlaneHostVtable` slot against a direct-call baseline |
//! | `:delta-p50-under-1us` | it asserts `p50_delta_nanos < HOT_PATH_BUDGET_NANOS`, the budget `1_000` |
//! | `:delta-p99-under-1us` | …and `p99_delta_nanos < HOT_PATH_BUDGET_NANOS` |
//! | `:per-token-host-calls-zero` | it asserts `per_token_crossings == 0` on the stream |
//!
//! EACH ROW HOLDS ITS OWN COMPARISON, NOT ITS TOKENS. A claim is a list of CLAUSES — token
//! sequences such as `assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS,` — matched against the
//! bench's LEXED token stream, so a comment cannot supply one and a clause cannot be assembled from
//! tokens the file carries for another row. These rows were independent `contains` tests over the
//! whole file, and p50 and p99 shared two of three markers: deleting either assertion left the
//! other's `assert!` and the budget const standing in for it, and `assert_eq!(x, x)` kept every
//! token of a zero-check that checks nothing. The manifest half is the same fault: `harness =
//! false` was looked for anywhere in a manifest with three `[[bench]]` blocks, each carrying one.
//!
//! TWO MODES: THE CONTRACT AND THE MEASUREMENT. The registered gate (`cargo xtask gate
//! hot-path-perf`, Tier::Fast) builds nothing — `xtask` depends on no product crate (the
//! `segregation` gate) — and holds the CONTRACT: the instrument still constructs the vtable, still
//! compares it to a direct call, and still asserts the exact budget at both percentiles and a zero
//! per-token crossing. That alone never proved the budget is MET: `qa/segments.toml`'s `benches`
//! segment is `cargo bench --workspace --no-run`, which compiles this bench and never executes it.
//! [`HotPathPerfExecGate`] is the other half: the same text rows plus four `:executed*` rows that
//! RUN the bench (`cargo bench -p busbar-kernel --bench plane_host_vtable_perf`) and judge its real
//! output — criterion's recorded samples against the `< 1µs` p50/p99 budget, and the bench's own
//! assertions against its exit. A bench that did not run is RED on every executed row, never
//! skipped-green. It builds the bench profile, so it runs on the qa cadence through
//! `xtask/tests/hot_path_gates.rs`'s `--ignored` executing tests, not on every push.
//!
//! THE PENDING-RIDER DEPENDENCY. `PlaneHostVtable`
//! (`crates/busbar-plugin/src/hot/host.rs`) has NO production caller yet — the keystone
//! loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the keystone wave)
//! has not landed. So the instrument this gate guards is ARMED against the vtable's own construction
//! (the `#[repr(C)]` subject `crates/busbar-plugin/tests/layout_golden.rs` pins), and binds to the
//! production crossing unchanged when the rider lands: the measured slot is the same fn pointer
//! either way. This gate is GREEN now and stays green across that transition.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, prove_red_by_configuration, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-perf:instrument-present";
pub const ROW_SUBJECT: &str = "hot-path-perf:vtable-vs-direct";
pub const ROW_P50: &str = "hot-path-perf:delta-p50-under-1us";
pub const ROW_P99: &str = "hot-path-perf:delta-p99-under-1us";
pub const ROW_PER_TOKEN: &str = "hot-path-perf:per-token-host-calls-zero";

const BENCH_REL: &str = "crates/busbar-kernel/benches/plane_host_vtable_perf.rs";
const MANIFEST_REL: &str = "crates/busbar-kernel/Cargo.toml";
const BENCH_NAME: &str = "plane_host_vtable_perf";

/// One text claim: the row it answers, and the CLAUSES the instrument must ALL carry for it. A
/// clause is a token sequence (see [`clause_tokens`]) matched against the bench's lexed code, so it
/// is the claim's code itself — the comparison, not the names that appear in it.
pub(crate) struct Claim {
    pub(crate) row: &'static str,
    pub(crate) clauses: &'static [&'static str],
    pub(crate) ok: &'static str,
    pub(crate) bad: &'static str,
}

const CLAIMS: &[Claim] = &[
    Claim {
        row: ROW_SUBJECT,
        clauses: &[
            "use busbar_plugin::hot::host::{",
            "PlaneHostVtable",
            "bench_function(\"HOT_PATH_DIRECT_CALL\"",
            "bench_function(\"HOT_PATH_VTABLE_CALL\"",
        ],
        ok: "the instrument measures the real PlaneHostVtable slot against a direct-call baseline",
        bad: "the instrument no longer compares the vtable crossing to a direct call",
    },
    Claim {
        row: ROW_P50,
        clauses: &[
            "const HOT_PATH_BUDGET_NANOS: u64 = 1_000;",
            "let p50_delta_nanos = vtable_p50.saturating_sub(direct_p50);",
            "assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS,",
        ],
        ok: "the instrument asserts the crossing delta is under 1µs at p50",
        bad: "the instrument no longer asserts the p50 delta under budget",
    },
    Claim {
        row: ROW_P99,
        clauses: &[
            "const HOT_PATH_BUDGET_NANOS: u64 = 1_000;",
            "let p99_delta_nanos = vtable_p99.saturating_sub(direct_p99);",
            "assert!(p99_delta_nanos < HOT_PATH_BUDGET_NANOS,",
        ],
        ok: "the instrument asserts the crossing delta is under 1µs at p99",
        bad: "the instrument no longer asserts the p99 delta under budget",
    },
    Claim {
        row: ROW_PER_TOKEN,
        clauses: &[
            "PER_TOKEN_HOST_CALLS.fetch_add(1,",
            "let per_token_crossings = PER_TOKEN_HOST_CALLS.load(",
            "assert_eq!(per_token_crossings, 0,",
        ],
        ok: "the instrument asserts zero per-token host-vtable crossings on the streaming path",
        bad: "the instrument no longer asserts the per-token host-call counter is zero",
    },
];

/// Split a clause into the tokens `proc_macro2` would lex it into: an identifier/number run is one
/// token, a `"…"` string is one token, and every other non-space character is one punct or
/// delimiter token (`::` is two `:`, exactly as the lexer yields it).
pub(crate) fn clause_tokens(clause: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut chars = clause.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        if c == '"' {
            let mut lit = String::from('"');
            for d in chars.by_ref() {
                lit.push(d);
                if d == '"' {
                    break;
                }
            }
            out.push(lit);
        } else if !c.is_whitespace() {
            out.push(c.to_string());
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// The CODE of a Rust source as a flat token list: lexed by `proc_macro2`, so `//` comments are
/// gone and a doc comment is one string-literal token that no clause can match into. Groups are
/// flattened to open delimiter, contents, close delimiter.
pub(crate) fn code_tokens(src: &str) -> Result<Vec<String>, String> {
    use proc_macro2::{Delimiter, TokenStream, TokenTree};
    fn walk(ts: TokenStream, out: &mut Vec<String>) {
        for tt in ts {
            match tt {
                TokenTree::Group(g) => {
                    let (open, close) = match g.delimiter() {
                        Delimiter::Parenthesis => ("(", ")"),
                        Delimiter::Brace => ("{", "}"),
                        Delimiter::Bracket => ("[", "]"),
                        Delimiter::None => ("", ""),
                    };
                    if !open.is_empty() {
                        out.push(open.to_string());
                    }
                    walk(g.stream(), out);
                    if !close.is_empty() {
                        out.push(close.to_string());
                    }
                }
                TokenTree::Punct(p) => out.push(p.as_char().to_string()),
                TokenTree::Ident(i) => out.push(i.to_string()),
                TokenTree::Literal(l) => out.push(l.to_string()),
            }
        }
    }
    let ts: TokenStream = src
        .parse()
        .map_err(|e| format!("does not lex as Rust: {e}"))?;
    let mut out = Vec::new();
    walk(ts, &mut out);
    Ok(out)
}

/// Does `code` (from [`code_tokens`]) carry `clause` as one contiguous token run?
pub(crate) fn carries_clause(code: &[String], clause: &str) -> bool {
    let want = clause_tokens(clause);
    !want.is_empty() && code.windows(want.len()).any(|w| w == want.as_slice())
}

/// Strike every textual occurrence of `clause` from `src`, whitespace between its tokens flexible.
/// The selftest's plant: it removes the clause wherever it is written, comment or code, so the
/// only way the planted row stays green is a gate that is not reading that clause at all. The
/// clause's delimiters are kept, so the planted file still lexes.
pub(crate) fn strike_clause(src: &str, clause: &str) -> String {
    let want = clause_tokens(clause);
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    'scan: while i < bytes.len() {
        if src.is_char_boundary(i) {
            let mut j = i;
            let mut ok = true;
            for (k, tok) in want.iter().enumerate() {
                if k > 0 {
                    while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() {
                        j += 1;
                    }
                }
                if src[j..].starts_with(tok.as_str()) {
                    j += tok.len();
                } else {
                    ok = false;
                    break;
                }
            }
            // A clause ending in a word must not match the head of a longer identifier.
            let word_end = |b: u8| (b as char).is_ascii_alphanumeric() || b == b'_';
            if ok
                && !want.is_empty()
                && !(j < bytes.len() && word_end(bytes[j]) && word_end(bytes[j - 1]))
            {
                // Keep the struck span's delimiters, in order, so the planted file still LEXES:
                // a plant that makes the file unreadable reds every row for the wrong reason.
                out.push_str("__struck__");
                out.extend(src[i..j].chars().filter(|c| "()[]{}".contains(*c)));
                i = j;
                continue 'scan;
            }
        }
        let ch = src[i..].chars().next().expect("i is on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Does `manifest` register `[[bench]] name = "<name>"` with `harness = false` IN THAT SAME BLOCK?
/// A block runs from its `[[bench]]` header to the next table header. `Err` says what is wrong.
pub(crate) fn bench_block_is_harness_false(manifest: &str, name: &str) -> Result<(), String> {
    let mut blocks: Vec<Vec<(String, String)>> = Vec::new();
    let mut in_bench = false;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_bench = line == "[[bench]]";
            if in_bench {
                blocks.push(Vec::new());
            }
            continue;
        }
        if !in_bench {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if let Some(block) = blocks.last_mut() {
                block.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    let quoted = format!("\"{name}\"");
    let own: Vec<&Vec<(String, String)>> = blocks
        .iter()
        .filter(|b| b.iter().any(|(k, v)| k == "name" && *v == quoted))
        .collect();
    match own.as_slice() {
        [] => Err(format!("no `[[bench]]` block has `name = {quoted}`")),
        [block] => {
            if block.iter().any(|(k, v)| k == "harness" && v == "false") {
                Ok(())
            } else {
                Err(format!(
                    "the `[[bench]]` block for `name = {quoted}` does not itself set `harness = \
                     false` (another bench's block setting it does not register this one)"
                ))
            }
        }
        _ => Err(format!(
            "{} `[[bench]]` blocks claim `name = {quoted}`",
            own.len()
        )),
    }
}

/// One claim's row over the lexed bench: PASS iff every clause is carried. Shared with
/// `hot-path-alloc`, whose instrument has the same shape.
pub(crate) fn claim_row_over(claim: &Claim, bench_rel: &str, code: &[String], what: &str) -> Row {
    let missing: Vec<&str> = claim
        .clauses
        .iter()
        .copied()
        .filter(|c| !carries_clause(code, c))
        .collect();
    if missing.is_empty() {
        Row::pass(
            claim.row,
            claim.ok,
            format!("{bench_rel}: every clause of the claim is present as code"),
        )
    } else {
        let missing = missing
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        Row::fail(
            claim.row,
            claim.bad,
            format!(
                "{bench_rel} does not carry {missing} as code — a budget claim was dropped from \
                 the {what} instrument"
            ),
        )
    }
}

/// The registration row: the bench file is present AND the manifest registers it `harness = false`
/// (so cargo builds the criterion binary, not a default libtest harness that would never compile).
fn instrument_row(cx: &Ctx) -> Row {
    if !cx.exists(BENCH_REL) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the perf instrument is missing",
            format!("{BENCH_REL} does not exist — the perf gate has nothing to enforce"),
        );
    }
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    if let Err(why) = bench_block_is_harness_false(&manifest, BENCH_NAME) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the perf instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL}: {why} — an unregistered criterion bench is built as a libtest \
                 harness and never runs the budget measurement"
            ),
        );
    }
    Row::pass(
        ROW_INSTRUMENT,
        "the perf instrument exists and is a registered criterion bench",
        format!("{BENCH_REL}, its own [[bench]] block sets harness = false in {MANIFEST_REL}"),
    )
}

pub struct HotPathPerfGate;

impl Gate for HotPathPerfGate {
    fn name(&self) -> &'static str {
        "hot-path-perf"
    }

    fn owed(&self) -> Vec<String> {
        std::iter::once(ROW_INSTRUMENT.to_string())
            .chain(CLAIMS.iter().map(|c| c.row.to_string()))
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(text_rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed perf instrument makes every budget claim",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        text_cases(cx, self, &mut report);
        report
    }
}

/// The five text rows: the registration row, then one row per claim. A missing instrument makes
/// every text claim fail too — a rule that could not read its subject is not a rule that passed.
fn text_rows(cx: &Ctx) -> Vec<Row> {
    let mut rows = vec![instrument_row(cx)];
    let bench = cx.read(BENCH_REL).and_then(|t| code_tokens(&t));
    for claim in CLAIMS {
        match &bench {
            Ok(code) => rows.push(claim_row_over(claim, BENCH_REL, code, "perf")),
            Err(e) => rows.push(Row::fail(
                claim.row,
                claim.bad,
                format!("{BENCH_REL}: {e} — the perf instrument could not be read"),
            )),
        }
    }
    rows
}

/// The text rows' RED plants, each an overlay over the committed bench or manifest. Driven through
/// `gate`, which is the text-only [`HotPathPerfGate`] for BOTH gates: an overlay cannot reach a
/// bench binary that is built from disk, so re-running the bench under each text plant would pay a
/// criterion run to learn nothing — the executing gate's text rows are this same `text_rows`.
fn text_cases<'a>(cx: &'a Ctx, gate: &'a dyn Gate, report: &mut Report<'a>) {
    // INSTRUMENT, NAME HALF: strike the registration's name. The bench source is untouched,
    // so only this row goes red.
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    let mut ov = Overlay::new();
    ov.set(
        MANIFEST_REL,
        manifest.replace(&format!("name = \"{BENCH_NAME}\""), "name = \"struck\""),
    );
    report.push(prove_red(
        cx,
        gate,
        "an unregistered instrument is RED, not read as present",
        &[ROW_INSTRUMENT],
        ov,
        &["not a registered criterion bench"],
    ));

    // INSTRUMENT, HARNESS HALF: strike `harness = false` from THIS bench's block only. The two
    // sibling `[[bench]]` blocks keep theirs, which is exactly what a whole-file test reads.
    let mut ov = Overlay::new();
    ov.set(
        MANIFEST_REL,
        manifest.replace(
            &format!("name = \"{BENCH_NAME}\"\nharness = false"),
            &format!("name = \"{BENCH_NAME}\""),
        ),
    );
    report.push(prove_red(
        cx,
        gate,
        "an instrument whose own block drops `harness = false` is RED while siblings keep theirs",
        &[ROW_INSTRUMENT],
        ov,
        &["does not itself set `harness = false`"],
    ));

    // One RED plant per CLAUSE of every claim: strike it out of the real committed bench, so
    // that row goes red naming the clause it lost. Every clause, not the first — p50 and p99
    // must each go red on their OWN assertion with the other's standing.
    let bench = cx.read(BENCH_REL).unwrap_or_default();
    for claim in CLAIMS {
        for clause in claim.clauses {
            let mut ov = Overlay::new();
            ov.set(BENCH_REL, strike_clause(&bench, clause));
            report.push(prove_red(
                cx,
                gate,
                format!("a perf instrument that drops `{clause}` is RED"),
                &[claim.row],
                ov,
                &[*clause],
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE EXECUTING MODE — the bench is RUN and its real output is judged against the budget.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// The text rows above hold the CONTRACT: the bench still asserts the budget. They cannot hold that
// the budget is MET, because nothing on this tree ran the bench (`qa/segments.toml`'s `benches`
// segment is `cargo bench --workspace --no-run`). [`HotPathPerfExecGate`] closes that half: it
// builds and runs `cargo bench -p busbar-kernel --bench plane_host_vtable_perf` into a FRESH criterion
// home, then judges three things of what came back, independently of each other:
//
// | row | the judgement |
// | --- | --- |
// | `:executed` | the bench process was spawned, exited 0, and criterion recorded samples for BOTH legs in this run's fresh home |
// | `:executed-p50-under-1us` | from criterion's own recorded samples (per-iteration ns), vtable p50 − direct p50 < 1_000ns, and the bench's own p50 assertion did not fire |
// | `:executed-p99-under-1us` | …the same at p99 |
// | `:executed-per-token-zero` | the run completed (so the bench's `assert_eq!(per_token_crossings, 0, …)` executed) and it did not fire |
//
// A BENCH THAT DID NOT RUN IS RED, NEVER SKIPPED-GREEN. Every executed row is FAIL when the process
// could not be spawned, exited non-zero, or left no samples: there is no Skip row in this mode, and
// the criterion home is created empty for every run so a previous run's samples cannot stand in.
//
// The p50/p99 judgement is the gate's OWN arithmetic over criterion's samples, not a re-reading of
// the bench's verdict: the bench computes its own percentiles over its own batches and asserts
// them (that fires as a non-zero exit and fails `:executed`); the gate reads what criterion
// measured and holds the same `< 1µs` over it. Two measurements, one budget.

/// The budget the executed rows hold the measurement to. The text row `:delta-p50-under-1us` pins
/// the bench's own `HOT_PATH_BUDGET_NANOS` to this same `1_000`; a unit test holds the two equal.
pub(crate) const EXEC_BUDGET_NANOS: f64 = 1_000.0;

pub const ROW_EXEC_RAN: &str = "hot-path-perf:executed";
pub const ROW_EXEC_P50: &str = "hot-path-perf:executed-p50-under-1us";
pub const ROW_EXEC_P99: &str = "hot-path-perf:executed-p99-under-1us";
pub const ROW_EXEC_PER_TOKEN: &str = "hot-path-perf:executed-per-token-zero";

/// The criterion benchmark ids the perf bench registers — the two legs whose samples are judged.
const DIRECT_ID: &str = "HOT_PATH_DIRECT_CALL";
const VTABLE_ID: &str = "HOT_PATH_VTABLE_CALL";

/// The bench's own RED knobs. Stripped from every executed run's environment unless the run is a
/// plant, so an unplanted run measures the committed instrument and nothing a shell left set.
pub(crate) const BENCH_KNOBS: &[&str] = &["BUSBAR_PERF_STREAM_CROSS", "BUSBAR_ALLOC_INJECT"];

/// How an executing gate is planted for its selftest. `None` is the gate as it ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecPlant {
    /// The shipped configuration: run the committed bench, judge it.
    None,
    /// Set one of the bench's own RED knobs (`BUSBAR_PERF_STREAM_CROSS`, `BUSBAR_ALLOC_INJECT`)
    /// in the bench's environment — a REAL budget violation inside the real bench binary.
    Env(&'static str),
    /// Ask cargo for a bench target that does not exist — the "bench did not run" shape.
    BenchName(&'static str),
    /// Add this many ns to every vtable-leg per-iteration sample BEFORE judging — a crossing made
    /// slower than the budget, planted into the real run's recorded measurement.
    SlowVtableNanos(u64),
}

/// One executed bench run: its exit, its combined output, and the per-iteration samples criterion
/// recorded for each requested id (read out of a fresh criterion home before it is removed).
pub(crate) struct BenchRun {
    pub(crate) bench: String,
    /// `Ok(code)` for a process that exited with a code; `Err` for one that could not be spawned
    /// or was killed by a signal.
    pub(crate) exit: Result<i32, String>,
    pub(crate) output: String,
    pub(crate) samples: std::collections::BTreeMap<String, Result<Vec<f64>, String>>,
}

impl BenchRun {
    /// `None` when the run COMPLETED — spawned, exit 0, samples for every id. Otherwise the reason
    /// it did not, which every executed row carries: a bench that did not run is RED.
    pub(crate) fn not_completed(&self) -> Option<String> {
        let bench = &self.bench;
        match &self.exit {
            Err(e) => return Some(format!("`cargo bench --bench {bench}` did not run: {e}")),
            Ok(0) => {}
            Ok(code) => {
                return Some(format!(
                    "`cargo bench --bench {bench}` exited {code}: {}",
                    self.evidence()
                ))
            }
        }
        let missing: Vec<String> = self
            .samples
            .iter()
            .filter_map(|(id, s)| s.as_ref().err().map(|e| format!("{id}: {e}")))
            .collect();
        if missing.is_empty() {
            None
        } else {
            Some(format!(
                "`cargo bench --bench {bench}` exited 0 but recorded no samples ({}) — the \
                 measurement did not run",
                missing.join("; ")
            ))
        }
    }

    /// Every output line carrying `marker` — the bench's own budget-assertion panics.
    pub(crate) fn lines_with(&self, marker: &str) -> Vec<String> {
        self.output
            .lines()
            .filter(|l| l.contains(marker))
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// What to show for a failed run: the bench's own `HOT-PATH` assertion lines when there are
    /// any, else the last lines cargo printed.
    fn evidence(&self) -> String {
        let hot = self.lines_with("HOT-PATH");
        if !hot.is_empty() {
            return hot.join(" | ");
        }
        let lines: Vec<&str> = self
            .output
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        lines[lines.len().saturating_sub(4)..].join(" | ")
    }
}

/// Criterion's `sample.json` → per-iteration nanoseconds (`times[i] / iters[i]`).
pub(crate) fn per_iteration_nanos(sample_json: &str) -> Result<Vec<f64>, String> {
    use crate::json_lite::{parse, Json};
    let doc = parse(sample_json).map_err(|e| format!("sample.json does not parse: {e}"))?;
    let obj = doc.as_object().ok_or("sample.json is not an object")?;
    let nums = |key: &str| -> Result<Vec<f64>, String> {
        obj.get(key)
            .and_then(Json::as_array)
            .ok_or(format!("sample.json has no `{key}` array"))?
            .iter()
            .map(|v| match v {
                Json::Int(i) => Ok(*i as f64),
                Json::Float(f) => Ok(*f),
                other => Err(format!(
                    "sample.json `{key}` carries a non-number {other:?}"
                )),
            })
            .collect()
    };
    let (iters, times) = (nums("iters")?, nums("times")?);
    if iters.is_empty() || iters.len() != times.len() {
        return Err(format!(
            "sample.json carries {} iters against {} times — not a measurement",
            iters.len(),
            times.len()
        ));
    }
    iters
        .iter()
        .zip(&times)
        .map(|(i, t)| {
            if *i > 0.0 {
                Ok(t / i)
            } else {
                Err("sample.json records a sample of zero iterations".to_string())
            }
        })
        .collect()
}

/// `(p50, p99)` of `samples`, indexed exactly as the bench indexes its own distribution.
pub(crate) fn p50_p99(samples: &[f64]) -> (f64, f64) {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    (v[n / 2], v[((n * 99) / 100).min(n - 1)])
}

/// Build and RUN `cargo bench -p busbar-kernel --bench <bench>` from `root`, into a criterion home
/// created empty for this run, and read back the samples for `ids`. The bench's RED knobs are
/// stripped from the environment, then `env` is applied (a plant's knob).
pub(crate) fn run_bench(
    root: &std::path::Path,
    bench: &str,
    ids: &[&str],
    env: &[(&str, &str)],
) -> BenchRun {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NTH: AtomicUsize = AtomicUsize::new(0);
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let home = target.join("xtask-hot-path").join(format!(
        "{bench}-{}-{}",
        std::process::id(),
        NTH.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&home);
    let mut run = BenchRun {
        bench: bench.to_string(),
        exit: Err("not started".to_string()),
        output: String::new(),
        samples: Default::default(),
    };
    if let Err(e) = std::fs::create_dir_all(&home) {
        run.exit = Err(format!(
            "the criterion home {} could not be made: {e}",
            home.display()
        ));
        for id in ids {
            run.samples
                .insert((*id).to_string(), Err("no run".to_string()));
        }
        return run;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = std::process::Command::new(&cargo);
    cmd.args([
        "bench",
        "-p",
        "busbar-kernel",
        "--bench",
        bench,
        "--",
        "--noplot",
    ])
    .current_dir(root)
    .env("CRITERION_HOME", &home);
    for k in BENCH_KNOBS {
        cmd.env_remove(k);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    match cmd.output() {
        Err(e) => run.exit = Err(format!("{cargo}: {e}")),
        Ok(out) => {
            run.output = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            run.exit = out
                .status
                .code()
                .ok_or_else(|| format!("killed by a signal ({:?})", out.status));
        }
    }
    for id in ids {
        let path = home.join(id).join("new").join("sample.json");
        let got = std::fs::read_to_string(&path)
            .map_err(|e| format!("{} not written ({e})", path.display()))
            .and_then(|t| per_iteration_nanos(&t));
        run.samples.insert((*id).to_string(), got);
    }
    let _ = std::fs::remove_dir_all(&home);
    run
}

/// The executed rows over one run. Pure over the [`BenchRun`], so it is unit-testable against a
/// synthetic run without building anything.
pub(crate) fn perf_exec_rows(run: &BenchRun, slow_vtable_nanos: u64) -> Vec<Row> {
    let not_completed = run.not_completed();
    let mut rows = Vec::new();

    rows.push(match &not_completed {
        Some(why) => Row::fail(
            ROW_EXEC_RAN,
            "the perf bench did not run to completion",
            format!("{why} — a bench that did not run is RED, never skipped-green"),
        ),
        None => Row::pass(
            ROW_EXEC_RAN,
            "the perf bench was executed and completed",
            format!(
                "`cargo bench --bench {}` exited 0 with criterion samples for {DIRECT_ID} and \
                 {VTABLE_ID}",
                run.bench
            ),
        ),
    });

    let legs = match (run.samples.get(DIRECT_ID), run.samples.get(VTABLE_ID)) {
        (Some(Ok(d)), Some(Ok(v))) if !d.is_empty() && !v.is_empty() => {
            let v: Vec<f64> = v.iter().map(|x| x + slow_vtable_nanos as f64).collect();
            Ok((p50_p99(d), p50_p99(&v)))
        }
        _ => Err(not_completed
            .clone()
            .unwrap_or_else(|| "no samples for both legs".to_string())),
    };
    for (row, pct, idx, marker) in [
        (ROW_EXEC_P50, "p50", 0usize, "HOT-PATH PERF (p50)"),
        (ROW_EXEC_P99, "p99", 1usize, "HOT-PATH PERF (p99)"),
    ] {
        let fired = run.lines_with(marker);
        rows.push(match &legs {
            Err(why) => Row::fail(
                row,
                format!("the {pct} crossing delta was not measured"),
                format!("{why} — no {pct} was measured, so none is under budget"),
            ),
            Ok((direct, vtable)) => {
                let (d, v) = if idx == 0 { (direct.0, vtable.0) } else { (direct.1, vtable.1) };
                let delta = (v - d).max(0.0);
                if delta >= EXEC_BUDGET_NANOS {
                    Row::fail(
                        row,
                        format!("the measured {pct} vtable crossing is over budget"),
                        format!(
                            "criterion measured direct {pct} {d:.1}ns, vtable {pct} {v:.1}ns: delta \
                             {delta:.1}ns >= budget {EXEC_BUDGET_NANOS}ns"
                        ),
                    )
                } else if !fired.is_empty() {
                    Row::fail(
                        row,
                        format!("the bench's own {pct} budget assertion fired"),
                        fired.join(" | "),
                    )
                } else {
                    Row::pass(
                        row,
                        format!("the measured {pct} vtable crossing is under 1µs"),
                        format!(
                            "criterion measured direct {pct} {d:.1}ns, vtable {pct} {v:.1}ns: delta \
                             {delta:.1}ns < budget {EXEC_BUDGET_NANOS}ns"
                        ),
                    )
                }
            }
        });
    }

    let fired = run.lines_with("HOT-PATH PER-TOKEN");
    rows.push(if !fired.is_empty() {
        Row::fail(
            ROW_EXEC_PER_TOKEN,
            "the executed bench crossed the host vtable per token",
            fired.join(" | "),
        )
    } else if let Some(why) = &not_completed {
        Row::fail(
            ROW_EXEC_PER_TOKEN,
            "the per-token crossing count was not measured",
            format!("{why} — the per-token assertion did not complete, so 0 is unproven"),
        )
    } else {
        Row::pass(
            ROW_EXEC_PER_TOKEN,
            "the executed streaming model crossed the host vtable 0 times per token",
            "the run completed and `assert_eq!(per_token_crossings, 0, …)` held".to_string(),
        )
    });
    rows
}

/// `hot-path-perf`, EXECUTING: the five text rows AND the four executed rows. Not the registry's
/// Tier::Fast build (that one builds nothing); this one builds the bench in the bench profile and
/// runs it, so it belongs to the qa cadence. Driven by `xtask/tests/hot_path_gates.rs`.
pub struct HotPathPerfExecGate {
    plant: ExecPlant,
}

impl HotPathPerfExecGate {
    pub const fn new() -> Self {
        HotPathPerfExecGate {
            plant: ExecPlant::None,
        }
    }

    pub const fn planted(plant: ExecPlant) -> Self {
        HotPathPerfExecGate { plant }
    }
}

impl Default for HotPathPerfExecGate {
    fn default() -> Self {
        Self::new()
    }
}

static PERF_PLANT_STREAM_CROSS: HotPathPerfExecGate =
    HotPathPerfExecGate::planted(ExecPlant::Env("BUSBAR_PERF_STREAM_CROSS"));
static PERF_PLANT_NO_BENCH: HotPathPerfExecGate =
    HotPathPerfExecGate::planted(ExecPlant::BenchName("plane_host_vtable_perf_struck"));
static PERF_PLANT_SLOW: HotPathPerfExecGate =
    HotPathPerfExecGate::planted(ExecPlant::SlowVtableNanos(2_000));

impl Gate for HotPathPerfExecGate {
    fn name(&self) -> &'static str {
        "hot-path-perf"
    }

    fn baseline_key(&self) -> Option<String> {
        Some(format!("hot-path-perf:execute:{:?}", self.plant))
    }

    fn owed(&self) -> Vec<String> {
        let mut owed = HotPathPerfGate.owed();
        owed.extend(
            [ROW_EXEC_RAN, ROW_EXEC_P50, ROW_EXEC_P99, ROW_EXEC_PER_TOKEN].map(str::to_string),
        );
        owed
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = text_rows(cx);
        let (bench, env, slow): (&str, Vec<(&str, &str)>, u64) = match self.plant {
            ExecPlant::None => (BENCH_NAME, vec![], 0),
            ExecPlant::Env(k) => (BENCH_NAME, vec![(k, "1")], 0),
            ExecPlant::BenchName(n) => (n, vec![], 0),
            ExecPlant::SlowVtableNanos(ns) => (BENCH_NAME, vec![], ns),
        };
        let run = run_bench(cx.root(), bench, &[DIRECT_ID, VTABLE_ID], &env);
        rows.extend(perf_exec_rows(&run, slow));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed perf bench, EXECUTED, meets every budget claim",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        text_cases(cx, &HotPathPerfGate, &mut report);
        report.push(prove_red_by_configuration(
            cx,
            self,
            &PERF_PLANT_STREAM_CROSS,
            "the executed bench with BUSBAR_PERF_STREAM_CROSS (a per-token crossing) is RED",
            &[ROW_EXEC_RAN, ROW_EXEC_PER_TOKEN],
            &["HOT-PATH PER-TOKEN"],
        ));
        report.push(prove_red_by_configuration(
            cx,
            self,
            &PERF_PLANT_SLOW,
            "a vtable leg measured 2µs slower than it ran is RED at p50 and p99",
            &[ROW_EXEC_P50, ROW_EXEC_P99],
            &["over budget"],
        ));
        report.push(prove_red_by_configuration(
            cx,
            self,
            &PERF_PLANT_NO_BENCH,
            "a bench that did not run is RED on every executed row, never skipped-green",
            &[ROW_EXEC_RAN, ROW_EXEC_P50, ROW_EXEC_P99, ROW_EXEC_PER_TOKEN],
            &["did not run", "not measured"],
        ));
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Status;

    fn cx() -> Ctx {
        Ctx::workspace().expect("the workspace opens")
    }

    /// Run the gate over the real tree with one file replaced, and return `row`'s status. The
    /// replacement is asserted to have changed the file — an inert rewrite proves nothing.
    fn status_with(rel: &str, from: &str, to: &str, row: &str) -> Status {
        let cx = cx();
        let text = cx.read(rel).expect("the subject file reads");
        let planted = text.replacen(from, to, 1);
        assert_ne!(
            planted, text,
            "the rewrite of {rel} must bite: `{from}` not found"
        );
        let mut ov = Overlay::new();
        ov.set(rel, planted);
        let verdict = HotPathPerfGate.run(&cx.with_overlay(ov));
        verdict
            .rows
            .iter()
            .find(|r| r.id == row)
            .map(|r| r.status)
            .expect("the gate emits the row")
    }

    /// Item 170/195: `harness = false` struck from THIS bench's own `[[bench]]` block, while the two
    /// sibling blocks keep theirs, is an unregistered instrument.
    #[test]
    fn harness_false_is_read_from_this_benchs_own_block() {
        let st = status_with(
            MANIFEST_REL,
            "name = \"plane_host_vtable_perf\"\nharness = false",
            "name = \"plane_host_vtable_perf\"",
            ROW_INSTRUMENT,
        );
        assert_eq!(st, Status::Fail);
    }

    /// Item 169/196: deleting the p50 assertion while its binding, the budget const and the p99
    /// `assert!` all survive is a dropped p50 claim.
    #[test]
    fn a_deleted_p50_assertion_is_red_even_though_p99_supplies_the_tokens() {
        let st = status_with(
            BENCH_REL,
            "    assert!(\n        p50_delta_nanos < HOT_PATH_BUDGET_NANOS,",
            "    let _ = (\n        p50_delta_nanos,",
            ROW_P50,
        );
        assert_eq!(st, Status::Fail);
    }

    /// Item 196: the same regression on the p99 side.
    #[test]
    fn a_deleted_p99_assertion_is_red_even_though_p50_supplies_the_tokens() {
        let st = status_with(
            BENCH_REL,
            "    assert!(\n        p99_delta_nanos < HOT_PATH_BUDGET_NANOS,",
            "    let _ = (\n        p99_delta_nanos,",
            ROW_P99,
        );
        assert_eq!(st, Status::Fail);
    }

    /// Item 169: the assertion kept but its comparison no longer against the budget is RED — the
    /// comparison itself is the claim, not the presence of its tokens.
    #[test]
    fn a_p50_compare_against_anything_but_the_budget_is_red() {
        let st = status_with(
            BENCH_REL,
            "p50_delta_nanos < HOT_PATH_BUDGET_NANOS,",
            "p50_delta_nanos < u64::MAX,",
            ROW_P50,
        );
        assert_eq!(st, Status::Fail);
    }

    /// Item 169: the budget constant is part of the claim ("under 1µs").
    #[test]
    fn a_widened_budget_constant_is_red() {
        let st = status_with(
            BENCH_REL,
            "const HOT_PATH_BUDGET_NANOS: u64 = 1_000;",
            "const HOT_PATH_BUDGET_NANOS: u64 = u64::MAX;",
            ROW_P50,
        );
        assert_eq!(st, Status::Fail);
    }

    /// A clause written only in a comment or a doc comment is not code, and a clause's tokens
    /// spread across two statements are not the clause.
    #[test]
    fn a_clause_is_matched_as_contiguous_code_only() {
        let clause = "assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS,";
        let code = |src: &str| code_tokens(src).expect("lexes");
        assert!(carries_clause(
            &code("fn f() { assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS, \"m\"); }"),
            clause
        ));
        assert!(carries_clause(
            &code("fn f() { assert!(\n    p50_delta_nanos\n  < HOT_PATH_BUDGET_NANOS,\n\"m\"); }"),
            clause
        ));
        assert!(!carries_clause(
            &code("// assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS,\nfn f() {}"),
            clause
        ));
        assert!(!carries_clause(
            &code("/// assert!(p50_delta_nanos < HOT_PATH_BUDGET_NANOS,\nfn f() {}"),
            clause
        ));
        assert!(!carries_clause(
            &code(
                "fn f() { let _ = p50_delta_nanos; assert!(p99 < HOT_PATH_BUDGET_NANOS, \"m\"); }"
            ),
            clause
        ));
    }

    /// `harness = false` belongs to the block it is written in.
    #[test]
    fn harness_false_is_scoped_to_its_own_bench_block() {
        let two = "[[bench]]\nname = \"a\"\nharness = false\n\n[[bench]]\nname = \"b\"\n\n[lints]\nharness = false\n";
        assert!(bench_block_is_harness_false(two, "a").is_ok());
        assert!(bench_block_is_harness_false(two, "b").is_err());
        assert!(bench_block_is_harness_false(two, "c").is_err());
        let commented = "[[bench]]\nname = \"a\"\n# harness = false\n";
        assert!(bench_block_is_harness_false(commented, "a").is_err());
    }

    /// The per-token row: an `assert_eq!` against the counter itself holds nothing.
    #[test]
    fn a_self_compared_per_token_counter_is_red() {
        let st = status_with(
            BENCH_REL,
            "per_token_crossings, 0,",
            "per_token_crossings, per_token_crossings,",
            ROW_PER_TOKEN,
        );
        assert_eq!(st, Status::Fail);
    }

    fn synthetic_run(
        exit: Result<i32, String>,
        output: &str,
        direct: &[f64],
        vtable: &[f64],
    ) -> BenchRun {
        let mut samples = std::collections::BTreeMap::new();
        let leg = |v: &[f64]| {
            if v.is_empty() {
                Err("sample.json not written".to_string())
            } else {
                Ok(v.to_vec())
            }
        };
        samples.insert(DIRECT_ID.to_string(), leg(direct));
        samples.insert(VTABLE_ID.to_string(), leg(vtable));
        BenchRun {
            bench: BENCH_NAME.to_string(),
            exit,
            output: output.to_string(),
            samples,
        }
    }

    fn statuses(rows: &[Row]) -> Vec<(String, Status)> {
        rows.iter().map(|r| (r.id.clone(), r.status)).collect()
    }

    /// Item 10: the executed rows judge criterion's samples against the SAME budget the bench's
    /// const carries — the gate's constant cannot drift from the text row's pinned `1_000`.
    #[test]
    fn the_executed_budget_is_the_benchs_budget() {
        assert_eq!(EXEC_BUDGET_NANOS, 1_000.0);
        assert!(CLAIMS.iter().any(|c| c
            .clauses
            .contains(&"const HOT_PATH_BUDGET_NANOS: u64 = 1_000;")));
    }

    /// Item 10: criterion's `sample.json` is read as per-iteration nanoseconds.
    #[test]
    fn criterion_samples_read_as_per_iteration_nanos() {
        let got = per_iteration_nanos(
            r#"{"sampling_mode":"Linear","iters":[10.0,20.0],"times":[50.0,300]}"#,
        )
        .expect("parses");
        assert_eq!(got, vec![5.0, 15.0]);
        assert!(per_iteration_nanos(r#"{"iters":[1.0],"times":[]}"#).is_err());
        assert!(per_iteration_nanos(r#"{"iters":[0.0],"times":[1.0]}"#).is_err());
    }

    /// Item 10: a completed run under budget is GREEN on every executed row.
    #[test]
    fn a_completed_run_under_budget_is_green() {
        let d: Vec<f64> = (0..100).map(|i| 1.0 + i as f64 / 100.0).collect();
        let v: Vec<f64> = d.iter().map(|x| x + 0.5).collect();
        let rows = perf_exec_rows(&synthetic_run(Ok(0), "", &d, &v), 0);
        assert!(
            rows.iter().all(|r| r.status == Status::Pass),
            "{:?}",
            statuses(&rows)
        );
    }

    /// Item 10: a vtable leg over budget at p99 only is RED at p99 and green at p50 — each
    /// percentile is its own judgement.
    #[test]
    fn a_p99_only_blowout_is_red_at_p99_alone() {
        let d = vec![1.0; 100];
        let mut v = vec![1.5; 100];
        v[99] = 5_000.0;
        let rows = perf_exec_rows(&synthetic_run(Ok(0), "", &d, &v), 0);
        let st = statuses(&rows);
        assert!(
            st.contains(&(ROW_EXEC_P50.to_string(), Status::Pass)),
            "{st:?}"
        );
        assert!(
            st.contains(&(ROW_EXEC_P99.to_string(), Status::Fail)),
            "{st:?}"
        );
    }

    /// Item 10: a bench that did not run — not spawned, non-zero exit, or no samples — is RED on
    /// every executed row, never skipped-green.
    #[test]
    fn a_bench_that_did_not_run_is_red_on_every_executed_row() {
        let d = vec![1.0; 100];
        for run in [
            synthetic_run(Err("no cargo".into()), "", &[], &[]),
            synthetic_run(
                Ok(101),
                "thread 'main' panicked\nHOT-PATH PER-TOKEN: crossed 10000",
                &d,
                &d,
            ),
            synthetic_run(Ok(0), "", &[], &[]),
        ] {
            let rows = perf_exec_rows(&run, 0);
            assert_eq!(rows.len(), 4);
            for r in &rows {
                if r.id == ROW_EXEC_P50 || r.id == ROW_EXEC_P99 {
                    // A per-token-only failure left both legs' samples standing, and the delta
                    // rows judge those; every other shape has nothing to judge.
                    if run.exit == Ok(101) {
                        continue;
                    }
                }
                assert_eq!(
                    r.status,
                    Status::Fail,
                    "{} was not RED for {:?}",
                    r.id,
                    run.exit
                );
                assert_ne!(r.status, Status::Skip);
            }
        }
    }
}
