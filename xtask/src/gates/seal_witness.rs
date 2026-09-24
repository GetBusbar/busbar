// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate seal-witness` — THE W2.e SEAL WITNESS, ENFORCED.
//!
//! This is the wave-W2.e proof (arm-gate-per-wave): after the capability-proof vocabulary was
//! unified to `Pass<stage>` + `Grant<capability>` + one kernel root minter (DECISIONS #72/#73), and
//! the single-minter posture was tightened (DECISIONS #65), this gate holds both properties so they
//! cannot silently regress. It is green on the tree and blocking in CI (`ci.yml`), and each of its
//! failing rows is proven RED-able by its own selftest over a green baseline.
//!
//! Three rows, two claims and one census:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `seal-witness:no-surviving-proof-name` | NO code under `crates/` — test code included — names ANY of the old proof-type zoo identifiers; the unified scheme is the only one that survives (#73) |
//! | `seal-witness:single-minter` | `KernelSeal::acquire_for_kernel(` is called, in code that compiles into a SHIPPED (lib/bin) target, only inside the kernel crate — the one root minter (#65) |
//! | `seal-witness:test-mints` | CENSUS, never a failure: every test-scope call of the minter, counted and named on every run |
//!
//! Both scans are comment-stripped (a migration note in a doc comment naming the old type is prose,
//! not a use). String literals stay INTACT, so a zoo name smuggled into a literal is still caught.
//!
//! ## WHY `single-minter` IS SCOPED TO SHIPPED CODE (item 181, architect ruling)
//!
//! #65's subject is the shipped binary: *"every KernelSeal must be unforgeable before 1.6.0 ships …
//! a gate proves no non-kernel code can mint a seal"*, and the seal's designed enforcement is a CI
//! symbol scan over code that ships. The row used to count the NAME across every `.rs` under
//! `crates/`, test fixtures included, and was red on 135 test-file calls with ZERO production sites
//! — unsatisfiable by anything the invariant is about, blocking CI and printing THE PROOF IS
//! IMPOSSIBLE for its own selftest. BUSBAR-1.6.0.md Part 1 ("What this means for the gates"): a gate
//! that reds on something outside its subject is scoped wrong, and the fix is the gate's scope.
//!
//! So a call counts against the row only when it is CODE (not a comment) in a file that compiles
//! into a non-test target: not under a `tests/` directory (which covers `src/tests/`), not a
//! module-style test file matching `(^|[/_])tests?\.rs$`, not under `benches/` or `examples/`, and
//! not inside a `#[cfg(test)]` item. Every one of those excluded calls is still COUNTED, named and
//! printed by `seal-witness:test-mints` — the rows print, so nothing is hidden. The test-file shape
//! is a filename anchor, not a substring, so a production `attests.rs` is still scanned.
//!
//! It complements the construction gate's `token-sealed`/`seal-sites`/`kernel-seal-impls` family
//! rather than replacing it: those hold the minting SURFACE; this holds the #73 vocabulary result
//! and gives the wave a single red-before-green witness of its own.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, prove_rows_green, Gate, Report};
#[cfg(test)]
use crate::ledger::Status;
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_NO_SURVIVING: &str = "seal-witness:no-surviving-proof-name";
pub const ROW_SINGLE_MINTER: &str = "seal-witness:single-minter";
pub const ROW_TEST_MINTS: &str = "seal-witness:test-mints";

/// The old capability-proof zoo (#73). None of these identifiers may survive anywhere under `crates/`.
pub const ZOO: &[&str] = &[
    "UnitToken",
    "AdmitToken",
    "TrustToken",
    "UsageToken",
    "LedgerToken",
    "DurabilityToken",
    "EgressAuthToken",
    "TransportKeyToken",
    "AdminToken",
    "RecoveryToken",
    "ExitToken",
];

/// The single root minter's one obtaining symbol (#65).
const MINTER: &str = "KernelSeal::acquire_for_kernel(";

/// Where the one root minter may be spelled at all.
const KERNEL_ROOT: &str = "crates/busbar-kernel/src/";

/// Every `.rs` under `crates/`, and from 2026-09-23 that means EVERY one.
///
/// ── WHY THE FOUR TEST EXCLUSIONS ARE GONE ───────────────────────────────────────────────────────
///
/// They read `["/tests/", "/tests.rs", "_tests.rs", "/benches/", "/target/"]` and the argument
/// beside them was that a unit's own tests mint sealed tokens by calling the seal directly, "exactly
/// as the construction gate does". That mirroring is the reason to drop them, not to keep them: the
/// construction gate's `token-sealed` family stopped being production-only on the same day, because
/// #65 (`docs/design/BUSBAR-1.6.0.md:401`) binds *"a gate proves no **non-kernel code** can mint a
/// seal"* — code, not production code. Two rows holding one property from two directions is the
/// design; two rows holding it over two different populations is two different properties wearing
/// one name, and they disagreed by 135 sites.
///
/// THE EXCLUSIONS WERE ALSO WIDER THAN THE WORD "TEST". `/tests/` matches an IN-SRC directory —
/// `crates/busbar-llm/src/tests/` and `crates/busbar-kernel-identity/src/egress_auth/tests.rs` are
/// both inside a crate's own `src` and were both unscanned — and `/benches/` excluded a scope that
/// is not test code at all. The census demonstrated it: eight seal/zoo sites planted, three found,
/// with `crates/busbar-llm/tests/`, `crates/busbar-llm/benches/` and `crates/busbar-llm/src/tests/`
/// all invisible while the inline `#[cfg(test)] mod` beside them was caught — this gate's own module
/// header claimed to be "test-scoped out" and never was, so the doc and the code disagreed and only
/// one of them was enforcing anything.
///
/// MEASURED before the change: the ZOO identifiers occur ZERO times in the newly-included scope, so
/// `:no-surviving-proof-name` gains a whole population and no finding. `:single-minter` gains 135
/// sites, which is the same 135 `construction`'s `token-sealed:kernel-seal` now reports — the two
/// rows agree for the first time.
///
/// `/target/` stays: build output is not source. `xtask` is deliberately NOT added to `ROOTS`, for
/// the reason `qa/construction.toml`'s `scan_roots` note gives at length — xtask declares no product
/// dependency, so it cannot spell a real mint, and line 51 of THIS FILE is
/// `const MINTER: &str = "KernelSeal::acquire_for_kernel("`.
const ROOTS: &[&str] = &["crates"];
const EXCLUDE: &[&str] = &["/target/"];
/// The denominator floor: a walk that finds fewer files than this is broken, not clean.
const SCAN_FLOOR: usize = 200;

/// Is `rel` a file that compiles only into a TEST, BENCH or EXAMPLE target — never into a shipped
/// lib/bin? A `tests/` directory anywhere on the path (which covers `src/tests/`), a `benches/` or
/// `examples/` directory, or a module-style test file whose NAME matches `(^|[/_])tests?\.rs$`
/// (`tests.rs`, `test.rs`, `foo_tests.rs`, `foo_test.rs`). The name rule is anchored at a `/` or `_`
/// boundary on purpose: `attests.rs` or `contests.rs` is production and stays scanned.
pub fn is_test_target_path(rel: &str) -> bool {
    if rel.contains("/tests/") || rel.contains("/benches/") || rel.contains("/examples/") {
        return true;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let Some(stem) = name
        .strip_suffix("tests.rs")
        .or_else(|| name.strip_suffix("test.rs"))
    else {
        return false;
    };
    stem.is_empty() || stem.ends_with('_')
}

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

struct Scan {
    files: usize,
    surviving: Vec<String>,
    minters_outside: Vec<String>,
    /// Minter calls in TEST scope (test-target path or `#[cfg(test)]`), outside the kernel crate.
    test_mints: Vec<String>,
}

fn scan_tree(cx: &Ctx) -> Result<Scan, String> {
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = cx.walk(&spec).map_err(|e| format!("{e:?}"))?;
    let mut surviving = Vec::new();
    let mut minters_outside = Vec::new();
    let mut test_mints = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        let test_path = is_test_target_path(&rel);
        // THE ONE TEST-SCOPE ANSWER every scanner in this crate uses: `gated` is true inside a
        // `#[cfg(test)]` item, `is_comment` on a whole-line comment, and `code` has trailing
        // comments stripped with string literals intact.
        let lines = scan::test_scope(&f.text);
        let mut in_block = false;
        for (i, raw) in f.text.lines().enumerate() {
            let code = scan::strip_comment_line(raw, &mut in_block);
            for name in ZOO {
                if word_hit(&code, name) {
                    surviving.push(format!("`{name}` at {rel}:{}", i + 1));
                }
            }
            if code.contains(MINTER) && !rel.starts_with(KERNEL_ROOT) {
                let gated = lines.get(i).is_some_and(|l| l.gated);
                let site = format!("{rel}:{}", i + 1);
                if test_path || gated {
                    test_mints.push(site);
                } else {
                    minters_outside.push(site);
                }
            }
        }
    }
    surviving.sort();
    minters_outside.sort();
    test_mints.sort();
    Ok(Scan {
        files: files.len(),
        surviving,
        minters_outside,
        test_mints,
    })
}

fn join_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

pub struct SealWitnessGate;

impl SealWitnessGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let scan = match scan_tree(cx) {
            Ok(s) => s,
            Err(e) => {
                return vec![
                    Row::fail(
                        ROW_NO_SURVIVING,
                        "the seal-witness scan could not run",
                        e.clone(),
                    ),
                    Row::fail(
                        ROW_SINGLE_MINTER,
                        "the seal-witness scan could not run",
                        e.clone(),
                    ),
                    Row::fail(ROW_TEST_MINTS, "the seal-witness scan could not run", e),
                ];
            }
        };
        let no_surviving = if scan.surviving.is_empty() {
            Row::pass(
                ROW_NO_SURVIVING,
                "no source under crates/ names a pre-#73 proof-type zoo identifier",
                format!(
                    "{} files scanned; the capability-proof types are exactly \
                     Pass<stage> + Grant<capability> + KernelSeal",
                    scan.files
                ),
            )
        } else {
            Row::fail(
                ROW_NO_SURVIVING,
                "a pre-#73 proof-type name survived the rename",
                format!(
                    "{} surviving zoo identifier(s): {}",
                    scan.surviving.len(),
                    join_or_none(&scan.surviving)
                ),
            )
        };
        let single_minter = if scan.minters_outside.is_empty() {
            Row::pass(
                ROW_SINGLE_MINTER,
                "in shipped code, the one root minter is called only inside the kernel crate",
                format!(
                    "`{MINTER}` is called in no lib/bin code outside {KERNEL_ROOT} ({} files \
                     scanned; {} test-scope call(s) are counted by {ROW_TEST_MINTS})",
                    scan.files,
                    scan.test_mints.len()
                ),
            )
        } else {
            Row::fail(
                ROW_SINGLE_MINTER,
                "shipped non-kernel code obtains the kernel seal",
                format!(
                    "{} production site(s) of `{MINTER}` outside {KERNEL_ROOT}: {}",
                    scan.minters_outside.len(),
                    join_or_none(&scan.minters_outside)
                ),
            )
        };
        // THE CENSUS. Never a failure: a test harness minting a seal is not the #65 breach, but it
        // is printed in full on every run so the population the minter row does not judge is never
        // a population nobody can see.
        let mut files: Vec<&str> = scan
            .test_mints
            .iter()
            .map(|s| s.rsplit_once(':').map_or(s.as_str(), |(f, _)| f))
            .collect();
        files.dedup();
        let test_mints = Row::pass(
            ROW_TEST_MINTS,
            "census: test-scope calls of the kernel minter outside the kernel crate",
            format!(
                "{} test-scope call(s) of `{MINTER}` in {} file(s) (tests/, benches/, examples/, \
                 *tests.rs, #[cfg(test)]) — informational, never red: {}",
                scan.test_mints.len(),
                files.len(),
                if files.is_empty() {
                    "none".to_string()
                } else {
                    files.join(", ")
                }
            ),
        );
        vec![no_surviving, single_minter, test_mints]
    }
}

impl Gate for SealWitnessGate {
    fn name(&self) -> &'static str {
        "seal-witness"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_NO_SURVIVING.to_string(),
            ROW_SINGLE_MINTER.to_string(),
            ROW_TEST_MINTS.to_string(),
        ]
    }

    /// The census row always passes by design; it prints, it does not judge.
    fn informational(&self) -> Vec<String> {
        vec![ROW_TEST_MINTS.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(SealWitnessGate::rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed tree carries only the unified Pass/Grant/KernelSeal scheme",
            &[ROW_NO_SURVIVING, ROW_SINGLE_MINTER, ROW_TEST_MINTS],
        ));

        // RED 1: a surviving zoo name in production is caught.
        let victim = "crates/busbar-kernel/src/teller.rs";
        let text = cx.read(victim).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            victim,
            format!("{text}\nfn __seal_witness_probe(_t: &LedgerToken) {{}}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "a resurrected `LedgerToken` in production is RED",
            &[ROW_NO_SURVIVING],
            ov,
            &["LedgerToken"],
        ));

        // RED 2: obtaining the seal outside the kernel crate is caught.
        let outsider = "crates/busbar-contract/src/lib.rs";
        let otext = cx.read(outsider).unwrap_or_default();
        let mut ov2 = Overlay::new();
        ov2.set(
            outsider,
            format!("{otext}\nfn __seal_witness_forge() {{ let _ = KernelSeal::acquire_for_kernel(); }}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "obtaining the kernel seal in a non-kernel crate's src/lib.rs is RED",
            &[ROW_SINGLE_MINTER],
            ov2,
            &["outside", outsider],
        ));

        // RED 3: a production file whose NAME merely ends in `tests.rs` is still production. The
        // test-file rule is anchored at `/` or `_`; `attests.rs` must not slip under it.
        let disguised = "crates/busbar-contract/src/attests.rs";
        let mut ov3 = Overlay::new();
        ov3.set(
            disguised,
            "pub fn __seal_witness_forge() { let _ = KernelSeal::acquire_for_kernel(); }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a mint hidden in a production file named `attests.rs` is RED",
            &[ROW_SINGLE_MINTER],
            ov3,
            &[disguised],
        ));

        // GREEN 1: a mint inside an inline `#[cfg(test)] mod` of a production file is test scope —
        // counted by the census, not by the minter row.
        let mut ov4 = Overlay::new();
        ov4.set(
            outsider,
            format!(
                "{otext}\n#[cfg(test)]\nmod __seal_witness_probe {{\n    fn f() {{\n        let _ = \
                 KernelSeal::acquire_for_kernel();\n    }}\n}}\n"
            ),
        );
        report.push(prove_rows_green(
            cx,
            self,
            "a mint inside an inline #[cfg(test)] mod is test scope, not a production minter",
            &[ROW_SINGLE_MINTER],
            ov4,
        ));

        // GREEN 2: a mint spelled in a doc comment is prose.
        let mut ov5 = Overlay::new();
        ov5.set(
            outsider,
            format!(
                "{otext}\n/// let seal = KernelSeal::acquire_for_kernel();\npub fn \
                 __seal_witness_doc() {{}}\n"
            ),
        );
        report.push(prove_rows_green(
            cx,
            self,
            "a mint in a doc comment is prose, not a production minter",
            &[ROW_SINGLE_MINTER],
            ov5,
        ));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ITEM 181: the test-target path rule — every shape it must catch, and the production names
    /// it must not over-match.
    #[test]
    fn the_test_target_path_rule_is_anchored() {
        for t in [
            "crates/a/tests/x.rs",
            "crates/a/src/tests/mod.rs",
            "crates/a/src/tests.rs",
            "crates/a/src/test.rs",
            "crates/a/src/hold_tests.rs",
            "crates/a/src/hold_test.rs",
            "crates/a/benches/b.rs",
            "crates/a/examples/e.rs",
        ] {
            assert!(is_test_target_path(t), "{t} is test scope");
        }
        for p in [
            "crates/a/src/attests.rs",
            "crates/a/src/contests.rs",
            "crates/a/src/lib.rs",
            "crates/a/src/latest.rs",
        ] {
            assert!(!is_test_target_path(p), "{p} is production");
        }
    }

    /// ITEM 181: the real tree is green on the minter row — the #65 invariant holds in shipped
    /// code — and a production mint outside the kernel still reds it.
    #[test]
    fn single_minter_is_green_on_the_tree_and_red_on_a_production_mint() {
        let cx = Ctx::workspace().expect("workspace context");
        let rows = SealWitnessGate::rows(&cx);
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Pass, "{}", minter.detail);
        let lib = "crates/busbar-contract/src/lib.rs";
        let text = cx.read(lib).unwrap();
        let mut ov = Overlay::new();
        ov.set(
            lib,
            format!("{text}\nfn __f() {{ let _ = KernelSeal::acquire_for_kernel(); }}\n"),
        );
        let rows = SealWitnessGate::rows(&cx.with_overlay(ov));
        let minter = rows.iter().find(|r| r.id == ROW_SINGLE_MINTER).unwrap();
        assert_eq!(minter.status, Status::Fail, "{}", minter.detail);
    }
}
