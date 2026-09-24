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
//! WHY A SOURCE GATE AND NOT A `cargo bench` RUNNER. `xtask` depends on no product crate (the
//! `segregation` gate), and a Tier::Fast gate builds nothing; the microsecond measurement is the
//! bench's job and runs in the perf lane. What this gate owns is the CONTRACT — that the instrument
//! still constructs the vtable, still compares it to a direct call, and still asserts the exact
//! budget at both percentiles and a zero per-token crossing. Deleting an assertion from the bench is
//! the drift this catches, and the bench's own `BUSBAR_PERF_STREAM_CROSS` knob is what proves those
//! assertions can still fire. NOTE WHAT DOES NOT RUN IT: `qa/segments.toml`'s `benches` segment is
//! `cargo bench --workspace --no-run`, which compiles this bench and never executes it, so on this
//! tree the source contract below is the only thing standing behind these rows.
//!
//! THE PENDING-RIDER DEPENDENCY. `PlaneHostVtable`
//! (`crates/busbar-plugin/src/hot/host.rs`) has NO production caller yet — the keystone
//! loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the keystone wave)
//! has not landed. So the instrument this gate guards is ARMED against the vtable's own construction
//! (the `#[repr(C)]` subject `crates/busbar-plugin/tests/layout_golden.rs` pins), and binds to the
//! production crossing unchanged when the rider lands: the measured slot is the same fn pointer
//! either way. This gate is GREEN now and stays green across that transition.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
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
        let mut rows = vec![instrument_row(cx)];
        // A missing instrument makes every text claim fail too — a rule that could not read its
        // subject is not a rule that passed.
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
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed perf instrument makes every budget claim",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

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
            self,
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
            self,
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
                    self,
                    format!("a perf instrument that drops `{clause}` is RED"),
                    &[claim.row],
                    ov,
                    &[*clause],
                ));
            }
        }

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
}
