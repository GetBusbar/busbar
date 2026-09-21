//! `cargo xtask gate no-float-money` — NO FLOATING POINT ON ANY MONEY RUNTIME PATH (DECISION
//! #77(8), #66).
//!
//! The 1.6.0 money model is UNITLESS integer arithmetic: a rate is an integer nano-unit, an
//! accumulation is a `u128`, a projection truncates once with an integer divisor. `f32`/`f64` on the
//! money path is exactly the failure this bans — a float sums differently depending on order, rounds
//! in ways nobody configured, and turns "the bill equals the sum of the lines" from a proof into a
//! hope. So the crate that owns the money arithmetic (`busbar-kernel-ledger`) and the binary's
//! dedicated money-unit files carry no float in production source.
//!
//! # THE ONE EXEMPT BOUNDARY (#44)
//!
//! A card is BUILT from configured decimals, and the one decimal-to-integer conversion is allowed to
//! see a float: [`busbar_kernel_ledger::cost::nano_rate`] multiplies a configured `micro_per_unit`
//! by a thousand and rounds half-away-from-zero, ONCE, at card build. That conversion lives in
//! `busbar-kernel-ledger/src/cost/rate.rs` and NOWHERE ELSE, and #44 PERMITS it: it is the
//! config-parse / card-build boundary, not the runtime path. This gate exempts exactly that one file
//! and nothing wider — a float that migrates out of it into `settle.rs`, `posting.rs`, `totals.rs`
//! or a durable-record file is the runtime-path float the ban is about. The card-build path in the
//! binary (the admin correction parser, `card_from_config`) lives in files this gate does not scan,
//! for the same reason: it is the boundary, and the boundary is where a decimal is allowed.
//!
//! Two rows:
//!
//! * `no-float-money:scan-floor` — the money scan set is the set it claims to be. The ledger crate
//!   holds production `.rs` above a floor (a shrunken scan reads exactly like a clean tree and is
//!   not one), AND every named binary money-unit file is present (a rename must move the scope in a
//!   reviewed diff, never silently drop a file out of the ban).
//! * `no-float-money:no-float` — the finding: an `f32`/`f64` token in money production source outside
//!   the one exempt boundary.

use crate::ctx::{Ctx, Edit, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan;

pub const ROW_SCAN_FLOOR: &str = "no-float-money:scan-floor";
pub const ROW_NO_FLOAT: &str = "no-float-money:no-float";

/// The consolidated one-book money crate (W3.a). Its whole job is integer money arithmetic.
const LEDGER_SRC: &str = "crates/busbar-kernel-ledger/src";

/// THE ONE EXEMPT BOUNDARY (#44). The only file in the money path allowed a float, because it is the
/// config-decimal-to-integer conversion and it happens once, at card build. Matched as a substring
/// of the `/`-prefixed relative path, so it is this file and not a directory.
const CARD_BUILD_BOUNDARY: &str = "busbar-kernel-ledger/src/cost/rate.rs";

/// The `*_tests.rs` sibling and the `/tests/` tree are fixtures: a float in a test is a test's
/// number, not the money path's.
const EXCLUDE_TESTS_DIR: &str = "/tests/";
const EXCLUDE_TESTS_FILE: &str = "_tests.rs";

/// The denominator floor for the ledger scan. Twenty-three production files (excluding the exempt
/// boundary) when this was written; the floor tracks the real tree rather than `> 0`, because one
/// surviving file is as vacuous as none.
const SCAN_FLOOR: usize = 18;

/// The binary's DEDICATED money-unit files: the durable ledger, the reconciliation identity, the
/// money-book seam and the money migration. Whole files whose every line is money path, so scanning
/// them entire cannot flag a routing weight or a health score — those live in the plane files, which
/// this gate does not scan. The card-build boundary in the binary is NOT here, on purpose (see the
/// module header).
const BINARY_MONEY_FILES: &[&str] = &[
    "crates/busbar/src/root/durability.rs",
    "crates/busbar/src/root/ledger_identity.rs",
    "crates/busbar/src/root/money_book.rs",
    "crates/busbar/src/root/migration.rs",
];

/// The directory the binary money files live under — walked once, then filtered to the named set.
const BINARY_ROOT: &str = "crates/busbar/src/root";

/// The float tokens a money path may not name. Word-boundary matched so `nf64` or an identifier that
/// merely contains the text is not a hit, but the bare type is.
pub const FLOAT_TOKENS: &[&str] = &["f64", "f32"];

pub struct NoFloatMoneyGate;

/// The one line a finding is written as. Built by `run` from its own scan; a stable shape so the
/// row detail reads the same way for every offender.
fn finding(rel: &str, line: usize, token: &str) -> String {
    format!("{rel}:{line}: `{token}` on the money path (integer-only, #77.8) outside the #44 card-build boundary")
}

/// Is `needle` present in `hay` at an identifier boundary? The characters either side must not be
/// alphanumeric or `_`, so `f64` matches `x: f64` and `as f64` but not `nf64` or `f640`.
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

/// A PASSING row's detail carries no run-specific count: the denominator is guarded by the floor,
/// which is a reviewable `const`, not by a number printed into a row where a drift reads as a finding.
const CLEAN: &str = "the scan cleared its floor and named no float on the money path";

/// The finding row, built from an offender list — the one constructor `run` calls, so the detail is
/// only ever about which offenders were found.
fn row_no_float(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_FLOAT,
            "no floating point on the money runtime path",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_FLOAT,
        "floating point reaches the money runtime path (integer-only, #77.8)",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

/// Scan one file's comment-stripped lines for the banned float tokens, appending findings.
fn scan_file(rel: &str, text: &str, offenders: &mut Vec<String>) {
    let mut in_block = false;
    for (i, raw) in text.lines().enumerate() {
        // Comments stripped, string literals intact — a float in prose about the ban is exempt, a
        // float in code is not.
        let code = scan::strip_comment_line(raw, &mut in_block);
        for token in FLOAT_TOKENS {
            if word_hit(&code, token) {
                offenders.push(finding(rel, i + 1, token));
            }
        }
    }
}

impl Gate for NoFloatMoneyGate {
    fn name(&self) -> &'static str {
        "no-float-money"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_SCAN_FLOOR.to_string(), ROW_NO_FLOAT.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // The ledger crate, minus the one exempt boundary and the fixtures, held to its floor.
        let ledger_spec = WalkSpec::new([LEDGER_SRC])
            .ext("rs")
            .exclude([EXCLUDE_TESTS_DIR, EXCLUDE_TESTS_FILE, CARD_BUILD_BOUNDARY])
            .min_files(SCAN_FLOOR);
        let ledger_files = match cx.walk(&ledger_spec) {
            Ok(f) => f,
            Err(e) => {
                // The scan could not be taken. It is NOT a clean money path; both owed rows say so
                // rather than one being quietly omitted.
                return Verdict::of(vec![
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the money scan set could not be read",
                        format!(
                            "{e} If the ledger crate legitimately moved, point the root at its new \
                             home in a reviewed diff that says so — do not lower the floor."
                        ),
                    ),
                    Row::fail(
                        ROW_NO_FLOAT,
                        "the money-float scan did not run",
                        "nothing was read, and nothing read is not a clean money path".to_string(),
                    ),
                ]);
            }
        };

        // The binary's dedicated money files: walk the root once, keep the named set. Every named
        // file must be present — a rename that dropped one out of the ban is a scan-set integrity
        // failure, not a silent narrowing.
        let bin_spec = WalkSpec::new([BINARY_ROOT]).ext("rs");
        let (bin_files, bin_scan_err) = match cx.walk(&bin_spec) {
            Ok(f) => (f, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        let present: std::collections::BTreeSet<String> =
            bin_files.iter().map(|f| f.rel_str()).collect();
        let missing: Vec<&str> = BINARY_MONEY_FILES
            .iter()
            .copied()
            .filter(|want| !present.contains(*want))
            .collect();

        let mut offenders = Vec::new();
        for f in &ledger_files {
            scan_file(&f.rel_str(), &f.text, &mut offenders);
        }
        for f in &bin_files {
            if BINARY_MONEY_FILES.contains(&f.rel_str().as_str()) {
                scan_file(&f.rel_str(), &f.text, &mut offenders);
            }
        }
        offenders.sort();

        let scan_floor = if let Some(e) = bin_scan_err {
            Row::fail(
                ROW_SCAN_FLOOR,
                "the binary money-unit scan root could not be read",
                format!("{BINARY_ROOT}: {e}"),
            )
        } else if !missing.is_empty() {
            Row::fail(
                ROW_SCAN_FLOOR,
                "a named binary money-unit file is missing from the scan set",
                format!(
                    "{} missing: {} — a money file that moved must move the ban with it in a \
                     reviewed diff, never drop out of it silently",
                    missing.len(),
                    missing.join(", ")
                ),
            )
        } else {
            Row::pass(
                ROW_SCAN_FLOOR,
                "the money scan set holds the ledger crate and every named binary money file",
                CLEAN,
            )
        };

        Verdict::of(vec![scan_floor, row_no_float(&offenders)])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the money path names no floating point",
            &[ROW_SCAN_FLOOR, ROW_NO_FLOAT],
        ));

        // The token is BUILT, not written, so this gate's own source does not carry the needle it
        // hunts and cannot be reported by a sibling scanner for holding it.
        let float_ty = format!("f{}", "64");

        // A FLOAT IN THE LEDGER CRATE'S RUNTIME SOURCE IS FLAGGED.
        report.push(plant(
            cx,
            self,
            "a float in the ledger crate's runtime source is flagged",
            &[ROW_NO_FLOAT],
            &format!("{LEDGER_SRC}/planted_runtime_float.rs"),
            Edit::Create(format!(
                "pub fn drift(nanos: u128) -> u128 {{\n    let scale: {float_ty} = 1.0;\n    (nanos as {float_ty} * scale) as u128\n}}\n"
            )),
            &[&float_ty],
        ));

        // A FLOAT IN A NAMED BINARY MONEY FILE IS FLAGGED.
        report.push(plant(
            cx,
            self,
            "a float appended to a binary money-unit file is flagged",
            &[ROW_NO_FLOAT],
            BINARY_MONEY_FILES[0],
            Edit::Append(format!(
                "\npub fn planted_drift(x: {float_ty}) -> {float_ty} {{ x * 2.0 }}\n"
            )),
            &[&float_ty],
        ));

        // THE #44 EXEMPTION HOLDS. A float in the card-build boundary (cost/rate.rs) is PERMITTED —
        // it is the one decimal-to-integer conversion — so the gate stays GREEN. A gate that flagged
        // its own permitted boundary would force the float off the boundary, which #44 forbids.
        let mut ov = Overlay::new();
        match Edit::Append(format!(
            "\npub fn extra_boundary_rate(m: {float_ty}) -> u64 {{ (m * 1000.0) as u64 }}\n"
        ))
        .apply(cx, CARD_BUILD_BOUNDARY_REL, &mut ov)
        {
            Ok(()) => report.push(Case {
                name: "a float in the #44 card-build boundary stays green (exempt)".to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant into the card-build boundary ({e})"
            )),
        }

        // A FLOAT UNDER A `/tests/` DIRECTORY IS A FIXTURE'S NUMBER, not the money path's.
        let mut ov = Overlay::new();
        ov.set(
            format!("{LEDGER_SRC}/tests/planted_fixture.rs"),
            format!("fn f() {{ let _: {float_ty} = 1.0; }}\n"),
        );
        report.push(Case {
            name: "a float under a /tests/ directory is excluded".to_string(),
            covers: vec![ROW_NO_FLOAT.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // A COMMENT-ONLY MENTION IS PROSE. The rule that exempts it is the rule that lets the money
        // path document the ban.
        let mut ov = Overlay::new();
        ov.set(
            format!("{LEDGER_SRC}/planted_prose.rs"),
            format!(
                "// This crate must never name an {float_ty} on the money path.\npub fn f() {{}}\n"
            ),
        );
        report.push(Case {
            name: "a comment-only mention of the vocabulary stays green".to_string(),
            covers: vec![ROW_NO_FLOAT.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // THE INSTRUMENT: the root that reads as empty. A ledger crate that moved or was renamed must
        // be REFUSED, not scanned as zero hits and printed green.
        let mut ov = Overlay::new();
        match cx.walk(&WalkSpec::new([LEDGER_SRC]).ext("rs").exclude([
            EXCLUDE_TESTS_DIR,
            EXCLUDE_TESTS_FILE,
            CARD_BUILD_BOUNDARY,
        ])) {
            Ok(files) => {
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a ledger scan root that reads as empty is refused, not scanned as zero hits",
                    &[ROW_SCAN_FLOOR],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: the base tree's ledger root is unreadable ({e}), so the \
                 empty-root plant has nothing to empty"
            )),
        }

        // A NAMED BINARY MONEY FILE THAT VANISHES IS A SCAN-SET INTEGRITY FAILURE.
        let mut ov = Overlay::new();
        ov.remove(std::path::Path::new(BINARY_MONEY_FILES[0]));
        report.push(prove_red(
            cx,
            self,
            "a named binary money file dropping out of the tree is refused",
            &[ROW_SCAN_FLOOR],
            ov,
            &["missing"],
        ));

        report
    }
}

/// The `/`-prefixed-substring boundary constant re-expressed as the actual repo-relative path an
/// `Edit` writes to (the exclude fragment omits the leading `crates/`-less prefix nuance).
const CARD_BUILD_BOUNDARY_REL: &str = "crates/busbar-kernel-ledger/src/cost/rate.rs";

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
