// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate seal-witness` — THE W2.e SEAL WITNESS, ENFORCED.
//!
//! This is the wave-W2.e proof (arm-gate-per-wave): after the capability-proof vocabulary was
//! unified to `Pass<stage>` + `Grant<capability>` + one kernel root minter (DECISIONS #72/#73), and
//! the single-minter posture was tightened (DECISIONS #65), this gate holds both properties so they
//! cannot silently regress.
//!
//! Two rows, two claims:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `seal-witness:no-surviving-proof-name` | NO source under `crates/` names ANY of the old proof-type zoo identifiers — the unified scheme is the only one that survives (#73) |
//! | `seal-witness:single-minter` | `KernelSeal::acquire_for_kernel(` is spelled only inside the kernel crate — the one root minter, unforgeable (#65) |
//!
//! The scan is comment-stripped (a migration note in a doc comment naming the old type is prose, not
//! a use). String literals stay INTACT, so a zoo name smuggled into a literal is still caught.
//!
//! IT IS NOT TEST-SCOPED OUT ANY MORE, AND THE WORD "production" IS GONE FROM BOTH CLAIMS. This
//! header used to say the scan was "test-scoped out ... mirroring the construction gate's
//! `token-sealed` classification" and the code did not do that either — an inline `#[cfg(test)] mod`
//! was always caught while `crates/*/tests/`, `crates/*/benches/` and an in-`src` `tests/` directory
//! were not, so the sentence described neither the rule nor the code. See [`EXCLUDE`] for the
//! measurement and for #65's own binding text, which says CODE and not production code.
//!
//! It complements the construction gate's `token-sealed`/`seal-sites`/`kernel-seal-impls` family
//! rather than replacing it: those hold the minting SURFACE; this holds the #73 vocabulary result
//! and gives the wave a single red-before-green witness of its own.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_NO_SURVIVING: &str = "seal-witness:no-surviving-proof-name";
pub const ROW_SINGLE_MINTER: &str = "seal-witness:single-minter";

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
}

fn scan_tree(cx: &Ctx) -> Result<Scan, String> {
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = cx.walk(&spec).map_err(|e| format!("{e:?}"))?;
    let mut surviving = Vec::new();
    let mut minters_outside = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        let mut in_block = false;
        for (i, raw) in f.text.lines().enumerate() {
            let code = scan::strip_comment_line(raw, &mut in_block);
            for name in ZOO {
                if word_hit(&code, name) {
                    surviving.push(format!("`{name}` at {rel}:{}", i + 1));
                }
            }
            if code.contains(MINTER) && !rel.starts_with(KERNEL_ROOT) {
                minters_outside.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    surviving.sort();
    minters_outside.sort();
    Ok(Scan {
        files: files.len(),
        surviving,
        minters_outside,
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
                    Row::fail(ROW_SINGLE_MINTER, "the seal-witness scan could not run", e),
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
                "the one root minter is spelled only inside the kernel crate",
                format!("`{MINTER}` appears only under {KERNEL_ROOT}"),
            )
        } else {
            Row::fail(
                ROW_SINGLE_MINTER,
                "a non-kernel site obtains the kernel seal",
                format!(
                    "{} site(s) of `{MINTER}` outside {KERNEL_ROOT}: {}",
                    scan.minters_outside.len(),
                    join_or_none(&scan.minters_outside)
                ),
            )
        };
        vec![no_surviving, single_minter]
    }
}

impl Gate for SealWitnessGate {
    fn name(&self) -> &'static str {
        "seal-witness"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_NO_SURVIVING.to_string(), ROW_SINGLE_MINTER.to_string()]
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
            &[ROW_NO_SURVIVING, ROW_SINGLE_MINTER],
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
            "obtaining the kernel seal outside the kernel crate is RED",
            &[ROW_SINGLE_MINTER],
            ov2,
            &["outside"],
        ));

        report
    }
}
