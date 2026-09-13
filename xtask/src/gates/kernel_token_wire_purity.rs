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
//!   kernel. Here it is [`WalkSpec::min_files`], and a walk under its floor is a FAIL row.
//! * `kernel-token-wire-purity:no-raw-wire-field` — the finding itself.
//!
//! The other fixed bug does not need a rule because it cannot be written: `return "$hits"` handed
//! the finding COUNT back as an exit status, which is one byte, so 256 findings exited 0 and the
//! lint got greener the worse the tree got. A `Vec<String>` has no modulus.

use crate::ctx::{Ctx, Edit, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::parity::LegacyRun;
use crate::scan;

pub const ROW_SCAN_ROOT: &str = "kernel-token-wire-purity:scan-root";
pub const ROW_NO_RAW_FIELD: &str = "kernel-token-wire-purity:no-raw-wire-field";

/// The kernel's production source. One root, and its absence is the gate's loudest finding.
const KERNEL_SRC: &str = "crates/busbar-kernel/src";

/// The denominator floor. Eleven production files when this was written; the floor tracks the real
/// tree rather than `> 0`, because one surviving file is as vacuous as none.
const SCAN_FLOOR: usize = 8;

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
        let spec = WalkSpec::new([KERNEL_SRC])
            .ext("rs")
            .exclude([EXCLUDE_TESTS_DIR, "_tests.rs"])
            .min_files(SCAN_FLOOR);
        let files = match cx.walk(&spec) {
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
