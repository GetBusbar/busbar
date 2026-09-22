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
//! | `seal-witness:no-surviving-proof-name` | no production source names ANY of the old proof-type zoo identifiers — the unified scheme is the only one that survives (#73) |
//! | `seal-witness:single-minter` | `KernelSeal::acquire_for_kernel(` is spelled in production only inside the kernel crate — the one root minter, unforgeable (#65) |
//!
//! The scan is comment-stripped (a migration note in a doc comment naming the old type is prose, not
//! a use) and test-scoped out (a unit's own tests mint sealed tokens by calling the seal directly,
//! mirroring the construction gate's `token-sealed` classification). String literals stay INTACT, so
//! a zoo name smuggled into a literal is still caught.
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

/// The old capability-proof zoo (#73). None of these identifiers may survive in production code.
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

/// Where the one root minter may be spelled in production.
const KERNEL_ROOT: &str = "crates/busbar-kernel/src/";

/// The production `.rs` under `crates/`, tests excluded. A unit's own tests mint sealed tokens by
/// calling the seal directly, so they are classified out exactly as the construction gate does.
const ROOTS: &[&str] = &["crates"];
const EXCLUDE: &[&str] = &["/tests/", "/tests.rs", "_tests.rs", "/benches/", "/target/"];
/// The denominator floor: a walk that finds fewer production files than this is broken, not clean.
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
                "no production source names a pre-#73 proof-type zoo identifier",
                format!(
                    "{} production files scanned; the capability-proof types are exactly \
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
                format!("`{MINTER}` appears in production only under {KERNEL_ROOT}"),
            )
        } else {
            Row::fail(
                ROW_SINGLE_MINTER,
                "a non-kernel production site obtains the kernel seal",
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
