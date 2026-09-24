//! `cargo xtask gate kernel-token-wire-purity` — THE KERNEL NEVER RE-DERIVES A USAGE TOKEN CLASS
//! FROM A RAW PROVIDER WIRE POINTER. The successor to
//! `scripts/kernel-token-wire-purity-lint.sh`, rule for rule.
//!
//! The four token classes (`tokens_in`, `tokens_out`, `cache_read`, `cache_write`) are read through
//! the plane's own usage normalization, never by the kernel reaching past that seam into a
//! provider's raw response shape. This is the negative-space proof: it scans the kernel's
//! production source for the raw wire field names the six dialects use for token counts and is RED
//! the day one of them appears there.
//!
//! Two rows, because the shell carried two refusals and only one of them was about a finding:
//!
//! * `kernel-token-wire-purity:scan-root` — the root is a directory AND holds production `.rs`.
//!   Both halves were bugs the audit fixed: `[ -d "$root" ] || return 0` meant a kernel that moved,
//!   split or was renamed scanned NOTHING and printed GREEN, and a root that existed but held no
//!   `.rs` scanned zero files, which finds zero wire fields and is indistinguishable from a clean
//!   kernel. A scan set under its floor is a FAIL row. Since item 199 the set is every
//!   `busbar-kernel*` crate's `src/` (the ledger that computes money among them), each named
//!   kernel crate must yield files, and the floor is over the set, not 4% of one crate.
//! * `kernel-token-wire-purity:no-raw-wire-field` — the finding itself.
//!
//! The other fixed bug does not need a rule because it cannot be written: `return "$hits"` handed
//! the finding COUNT back as an exit status, which is one byte, so 256 findings exited 0 and the
//! lint got greener the worse the tree got. A `Vec<String>` has no modulus.

use crate::ctx::{Ctx, Edit, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::parity::LegacyRun;
use crate::scan;

pub const ROW_SCAN_ROOT: &str = "kernel-token-wire-purity:scan-root";
pub const ROW_NO_RAW_FIELD: &str = "kernel-token-wire-purity:no-raw-wire-field";

/// The kernel crate's own production source — kept as the plant target for the selftest.
const KERNEL_SRC: &str = "crates/busbar-kernel/src";

/// WHERE "THE KERNEL" IS (item 199). It is not one directory: it is `busbar-kernel` and every
/// `busbar-kernel-*` sibling, and the one that computes money — `busbar-kernel-ledger` — was outside
/// the single root this gate used to read. The scan set is DISCOVERED (every `crates/<name>/src/`
/// whose crate name is `busbar-kernel` or starts `busbar-kernel-`), so a new kernel sibling is in
/// scope the day it lands.
const CRATES: &str = "crates";
const KERNEL_CRATE: &str = "busbar-kernel";

/// The kernel crates that exist today, each of which must still yield production source. Discovery
/// alone cannot see a crate that was renamed OUT of the prefix; a named crate that scans zero files
/// is a crate that left the scan, and that is refused rather than read as clean.
const REQUIRED_KERNEL_CRATES: &[&str] = &[
    "busbar-kernel",
    "busbar-kernel-audit",
    "busbar-kernel-breaker",
    "busbar-kernel-budget",
    "busbar-kernel-egress",
    "busbar-kernel-identity",
    "busbar-kernel-ledger",
    "busbar-kernel-scope",
    "busbar-kernel-wal",
];

/// The denominator floor over the WHOLE kernel scan set. Measured 292 production files across the
/// nine crates (busbar-kernel 200, -ledger 23, -egress 20, -identity 14, -audit 10, -breaker 8,
/// -wal 8, -budget 7, -scope 2) when item 199 raised it from 8 (which was 4% of `busbar-kernel`
/// alone). 200 leaves room for the 1.6.0 deletion lists and still refuses the failure the old floor
/// admitted: `handlers/` + `ingress/` lifted into a crate outside the prefix drops the set to ~100.
const SCAN_FLOOR: usize = 200;

/// The `find … -name '*.rs'` exclusions the shell carried, verbatim: an integration-test tree and a
/// `*_tests.rs` sibling are fixtures, and a wire literal in one is a fixture's literal.
const EXCLUDE_TESTS_DIR: &str = "/tests/";

/// The raw wire field name a dialect uses for a token count, WORD-BOUNDARY matched so
/// `input_tokens_total` (a plane-normalized aggregate, if one ever exists) is not a false hit but
/// the bare provider field name is. The same twelve names, in the same order, the shell listed:
///
/// * anthropic/bedrock — `input_tokens`, `output_tokens`, `cache_read_input_tokens`,
///   `cache_creation_input_tokens`
/// * openai/responses — `prompt_tokens`, `completion_tokens`, `cached_tokens`
/// * gemini — `promptTokenCount`, `candidatesTokenCount`, `thoughtsTokenCount`,
///   `cachedContentTokenCount`
/// * cohere — `billed_units`
pub const WIRE_FIELDS: &[&str] = &[
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "prompt_tokens",
    "completion_tokens",
    "cached_tokens",
    "promptTokenCount",
    "candidatesTokenCount",
    "thoughtsTokenCount",
    "cachedContentTokenCount",
    "billed_units",
];

pub struct KernelTokenWirePurityGate;

/// The crate a `crates/<crate>/src/…` path belongs to, when it is a KERNEL crate's production source.
fn kernel_crate_of(rel: &str) -> Option<&str> {
    let rest = rel.strip_prefix("crates/")?;
    let (krate, tail) = rest.split_once('/')?;
    if !tail.starts_with("src/") {
        return None;
    }
    (krate == KERNEL_CRATE || krate.starts_with("busbar-kernel-")).then_some(krate)
}

/// The kernel scan set: every kernel crate's production `.rs`, tests excluded — or the reason it
/// could not be taken (walk failure, a required crate that yields nothing, a set under its floor).
fn kernel_files(cx: &Ctx) -> Result<Vec<SourceFile>, String> {
    let spec = WalkSpec::new([CRATES])
        .ext("rs")
        .exclude([EXCLUDE_TESTS_DIR, "_tests.rs"]);
    let files = cx.walk(&spec).map_err(|e| e.to_string())?;
    let kernel: Vec<SourceFile> = files
        .into_iter()
        .filter(|f| kernel_crate_of(&f.rel_str()).is_some())
        .collect();
    let missing: Vec<&str> = REQUIRED_KERNEL_CRATES
        .iter()
        .copied()
        .filter(|k| {
            !kernel
                .iter()
                .any(|f| kernel_crate_of(&f.rel_str()) == Some(*k))
        })
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "kernel crate(s) with no production source under crates/<crate>/src: {} — a kernel \
             crate that scans zero files left the scan; it is not a clean crate",
            missing.join(", ")
        ));
    }
    if kernel.len() < SCAN_FLOOR {
        return Err(format!(
            "the kernel scan set holds {} production file(s) across busbar-kernel and its \
             busbar-kernel-* siblings, below the floor of {SCAN_FLOOR}",
            kernel.len()
        ));
    }
    Ok(kernel)
}

/// The one line a finding is written as, on BOTH sides of a parity run. The Rust gate builds it
/// from its own scan; the legacy translator reads the identical line out of the script's stdout.
/// Neither may spell it its own way, which is what makes the comparison a comparison of offenders
/// rather than of prose.
fn finding(rel: &str, line: usize, field: &str) -> String {
    format!("{rel}:{line}: raw wire field '{field}' in kernel production source")
}

/// Is `needle` present in `hay` at an identifier boundary? `grep -E '\bpat\b'` over ASCII: the
/// characters either side must not be alphanumeric or `_`. Without it
/// `cache_read_input_tokens` would report `input_tokens` a second time on the same line.
fn word_hit(hay: &str, needle: &str) -> bool {
    let bytes = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > bytes.len() {
        return false;
    }
    let wordy = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for i in 0..=(bytes.len() - n.len()) {
        if &bytes[i..i + n.len()] != n {
            continue;
        }
        let before_ok = i == 0 || !wordy(bytes[i - 1]);
        let after_ok = i + n.len() == bytes.len() || !wordy(bytes[i + n.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// A PASSING row's detail carries NO run-specific count. Both sides of a parity run must be able
/// to write it, and the legacy script never printed how many files it opened — but more to the
/// point, the denominator is guarded by [`SCAN_FLOOR`], which is a reviewable `const`, not by a
/// number printed into a row where a drift would read as a finding.
const CLEAN: &str = "the scan cleared its floor and named nothing";

/// The finding row, built from an offender list — the ONE constructor both `run` and the legacy
/// translator call, so a parity diff can only ever be about which offenders were found.
fn row_no_raw_field(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_RAW_FIELD,
            "no raw provider wire token field reaches busbar-kernel",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_RAW_FIELD,
        "a raw provider wire token field reaches busbar-kernel production source",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

impl Gate for KernelTokenWirePurityGate {
    fn name(&self) -> &'static str {
        "kernel-token-wire-purity"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_SCAN_ROOT.to_string(), ROW_NO_RAW_FIELD.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let files = match kernel_files(cx) {
            Ok(f) => f,
            Err(e) => {
                // The scan could not be taken. It is NOT a clean kernel, and the finding row says
                // so in its own words rather than being quietly omitted — an owed row with no
                // answer is DID NOT RUN, and the reconciler would red it anyway, but a reader
                // deserves to be told which of the two facts they are looking at.
                return Verdict::of(vec![
                    Row::fail(
                        ROW_SCAN_ROOT,
                        "the kernel scan root could not be read",
                        format!(
                            "{e} If the kernel legitimately moved, point the root at its new home \
                             in a reviewed diff that says so — do not lower the floor."
                        ),
                    ),
                    Row::fail(
                        ROW_NO_RAW_FIELD,
                        "the wire-field scan did not run",
                        "nothing was read, and nothing read is not a clean kernel".to_string(),
                    ),
                ]);
            }
        };

        let mut offenders = Vec::new();
        for f in &files {
            let mut in_block = false;
            for (i, raw) in f.text.lines().enumerate() {
                // Comments stripped, string literals INTACT — the same rule the shell's
                // `strip_comments` awk applied. A wire field name inside a literal is still the
                // kernel naming a provider's shape; only prose about the ban is exempt.
                let code = scan::strip_comment_line(raw, &mut in_block);
                for field in WIRE_FIELDS {
                    if word_hit(&code, field) {
                        offenders.push(finding(&f.rel_str(), i + 1, field));
                    }
                }
            }
        }
        offenders.sort();

        Verdict::of(vec![
            Row::pass(
                ROW_SCAN_ROOT,
                "the kernel scan root holds production source",
                CLEAN,
            ),
            row_no_raw_field(&offenders),
        ])
    }

    /// The legacy script prints one `path:line: raw wire field '…'` line per finding and a
    /// `RED --`/`GREEN --` verdict line. Both rows are read out of that, and out of nothing else.
    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        Some(translate(&runs[0]))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the kernel names no raw provider wire token field",
            &[ROW_SCAN_ROOT, ROW_NO_RAW_FIELD],
        ));

        // The field name is BUILT rather than written, so this gate's own source does not carry
        // the needle it hunts and cannot be reported by a sibling scanner for holding it.
        let raw_field = format!("{}_{}", "input", "tokens");

        report.push(plant(
            cx,
            self,
            "a raw wire field in kernel production source is flagged",
            &[ROW_NO_RAW_FIELD],
            &format!("{KERNEL_SRC}/planted_wire_read.rs"),
            Edit::Create(format!(
                "pub fn class_of(v: &Value) -> i64 {{\n    v[\"{raw_field}\"].as_i64()\n}}\n"
            )),
            &[&raw_field],
        ));

        // A COMMENT-ONLY MENTION IS PROSE. The rule that exempts it is the rule that lets the
        // kernel document the ban, and a gate its own explanation fails is a gate people delete.
        let mut ov = Overlay::new();
        ov.set(
            format!("{KERNEL_SRC}/planted_prose.rs"),
            format!(
                "// This crate must never read a raw `{raw_field}` wire field.\npub fn f() {{}}\n"
            ),
        );
        report.push(Case {
            name: "a comment-only mention of the vocabulary stays green".to_string(),
            covers: vec![ROW_NO_RAW_FIELD.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // A HIT UNDER A `/tests/` DIRECTORY IS A FIXTURE'S LITERAL, not the kernel's read.
        let mut ov = Overlay::new();
        ov.set(
            format!("{KERNEL_SRC}/tests/planted_fixture.rs"),
            format!("fn f() {{ let _ = \"{raw_field}\"; }}\n"),
        );
        report.push(Case {
            name: "a hit under a /tests/ directory is excluded".to_string(),
            covers: vec![ROW_NO_RAW_FIELD.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // ITEM 199: THE LEDGER IS KERNEL. `busbar-kernel-ledger` prices usage, and a wire pointer in
        // it is the exact act this gate bans; it sat outside the single root this gate read.
        report.push(plant(
            cx,
            self,
            "a raw wire field in busbar-kernel-ledger production source is flagged",
            &[ROW_NO_RAW_FIELD],
            "crates/busbar-kernel-ledger/src/planted_wire_read.rs",
            Edit::Create(format!(
                "pub fn class_of(v: &Value) -> i64 {{\n    v[\"{raw_field}\"].as_i64()\n}}\n"
            )),
            &["busbar-kernel-ledger", &raw_field],
        ));

        // ITEM 199: THE FLOOR IS OVER THE SET, NOT 4% OF ONE CRATE. `busbar-kernel` keeps nine
        // production files — the rest lifted into a crate outside the prefix — and the old floor
        // of 8 cleared it.
        match kernel_files(cx) {
            Ok(files) => {
                let mut ov = Overlay::new();
                let mut kept = 0usize;
                for f in &files {
                    if kernel_crate_of(&f.rel_str()) == Some(KERNEL_CRATE) {
                        if kept < 9 {
                            kept += 1;
                        } else {
                            ov.remove(&f.rel);
                        }
                    }
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a kernel scan set left holding nine busbar-kernel files is under its floor",
                    &[ROW_SCAN_ROOT],
                    ov,
                    &["below the floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "kernel-token-wire-purity selftest: the base tree's kernel scan set is unreadable \
                 ({e}), so the lifted-crate plant has nothing to lift"
            )),
        }

        // THE INSTRUMENT: the root that is not there. `[ -d "$root" ] || return 0` read a renamed
        // kernel as zero hits and printed GREEN. Every production file is deleted from the
        // overlay, which is what a rename looks like from the scan's side.
        let mut ov = Overlay::new();
        match cx.walk(
            &WalkSpec::new([KERNEL_SRC])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR, "_tests.rs"]),
        ) {
            Ok(files) => {
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a scan root that reads as empty is refused, not scanned as zero hits",
                    &[ROW_SCAN_ROOT],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "kernel-token-wire-purity selftest: the base tree's kernel root is unreadable \
                 ({e}), so the empty-root plant has nothing to empty"
            )),
        }

        // THE COUNT IS NOT A BYTE. 256 findings exited 0 under `return "$hits"`, so the lint was
        // exactly wrong at 256, 512, 768 … Planted at 256 because that is where the old code was
        // not merely imprecise but inverted.
        let mut body = String::from("pub fn f(v: &Value) {\n");
        for _ in 0..256 {
            body.push_str(&format!("    let _ = v[\"{raw_field}\"];\n"));
        }
        body.push_str("}\n");
        let mut ov = Overlay::new();
        ov.set(format!("{KERNEL_SRC}/planted_many.rs"), body);
        report.push(prove_red(
            cx,
            self,
            "256 findings are 256 findings (an exit status would have wrapped to zero)",
            &[ROW_NO_RAW_FIELD],
            ov,
            &["256 finding(s)"],
        ));

        report
    }
}

fn verdict_expect(gate: &dyn Gate, cx: &Ctx) -> crate::gates::Expect {
    let verdict = crate::gates::execute(gate, cx);
    if verdict.red {
        crate::gates::Expect::Red {
            naming: verdict
                .rows
                .iter()
                .filter(|r| r.status != Status::Pass)
                .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
                .chain(verdict.problems.iter().cloned())
                .collect(),
        }
    } else {
        crate::gates::Expect::Green
    }
}

fn plant<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = Overlay::new();
    if edit.apply(cx, path, &mut ov).is_err() {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: crate::gates::Expect::Red {
                naming: naming.iter().map(|s| (*s).to_string()).collect(),
            },
            got: crate::gates::Expect::Skipped,
        }
        .into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

/// Read the shell gate's stdout into the same two rows. The findings are its own printed lines,
/// taken verbatim; the scan-root verdict is its own refusal text. Nothing here re-derives a
/// verdict from the tree — a translator that scanned would be proving the Rust against itself.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut offenders: Vec<String> = Vec::new();
    let mut refused: Option<String> = None;
    let mut scanned_clean = false;

    for line in run.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("kernel-token-wire-purity: RED -- ") {
            // Two of the script's three REDs are refusals to scan; the third is a finding count.
            if rest.starts_with("the scan root") || rest.contains("holds no production .rs") {
                refused = Some(rest.to_string());
            }
            continue;
        }
        if t.starts_with("kernel-token-wire-purity: GREEN") {
            scanned_clean = true;
            continue;
        }
        if t.contains(": raw wire field '") && t.contains("' in kernel production source") {
            offenders.push(t.to_string());
        }
    }

    if refused.is_none() && !scanned_clean && offenders.is_empty() {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no verdict line, no \
             findings. Silence read as a clean kernel is the exact defect this gate exists for.",
            run.argv.join(" ")
        ));
    }

    offenders.sort();
    let scan_root = match &refused {
        Some(why) => Row::fail(
            ROW_SCAN_ROOT,
            "the kernel scan root could not be read",
            why.clone(),
        ),
        None => Row::pass(
            ROW_SCAN_ROOT,
            "the kernel scan root holds production source",
            CLEAN,
        ),
    };
    let mut rows = vec![scan_root];
    if refused.is_some() {
        rows.push(Row::fail(
            ROW_NO_RAW_FIELD,
            "the wire-field scan did not run",
            "nothing was read, and nothing read is not a clean kernel".to_string(),
        ));
    } else {
        rows.push(row_no_raw_field(&offenders));
    }
    Ok(rows)
}
