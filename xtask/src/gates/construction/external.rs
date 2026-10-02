//! THE INPUTS THE CONSTRUCTION GATE DOES NOT MEASURE ITSELF.
//!
//! Each is a deliberate delegation the Python made and this port keeps, because in each case some
//! OTHER instrument already owns the policy and a second reading of it is a second policy:
//!
//! * `scripts/plane-purity-lint.sh` owns the dialect/plane-noun vocabulary and the frozen-wire
//!   allow-list. `neutral-no-dialect` counts its DIALECT/KEY rows and decides nothing itself.
//! * The surface-line count (`surface-ceiling:*`) is GONE, not delegated: size is not a CI check
//!   (owner 2026-10-02). `cargo xtask loc` is still the one line counter, run by hand at PERF.
//! * `cargo xtask denylist` owns the TRANSITIVE dependency closure, which no text scan can see.
//!   Here it is called IN PROCESS rather than as a subprocess: the Python had to spawn it, and had
//!   to tell "asked, nothing found" apart from "never asked" across a process boundary that could
//!   fail four different ways. In process there is no such boundary, so the distinction collapses
//!   to "the scan ran" — and a scan that ran but could not be TRUSTED (its `defects` channel is
//!   non-empty) is the same answer as one that never ran: [`denylist_hits`] returns `Err` with the
//!   scan's own reasons, and every `source-denylist` row goes RED as UNPROVEN, naming them.
//!
//! Every one of them is OVERLAY-OVERRIDABLE. A self-test cannot plant into a subprocess's view of
//! the tree — the overlay lives in this process — so a plant that needs one of these inputs sets
//! it directly, and what the case then proves is the rule's own counting, which is exactly what
//! the rule is.

use std::collections::BTreeMap;

use crate::ctx::Ctx;

/// The overlay key a self-test plants the delegated purity scan under.
pub const PURITY_HITS_KEY: &str = "construction:purity-hits";

/// THE ONE ANSWER A PLANTED STRING CANNOT OTHERWISE SPELL: the scan could not be made at all.
///
/// Every other planted value is a hits file, and the empty hits file is a REAL and different answer
/// — "the scan ran and found nothing", which the rule reads as a clean tree. "The scan did not run"
/// is the answer this rule exists to distinguish from that one, and before this sentinel a self-test
/// had no way to plant it: the artefact is produced in-process, so there is no file to remove and no
/// subprocess to break. That left the `hits.is_none()` refusal — the one the rule was WRITTEN for,
/// after a deleted script made the scan silently stop running — unproven.
pub const PURITY_HITS_ABSENT: &str = "#DID-NOT-RUN";
/// The overlay key a self-test plants the transitive-closure scan's answer under.
pub const DENYLIST_KEY: &str = "construction:denylist-tsv";
/// The planted spelling of "the transitive-closure scan did not answer" — the denylist twin of
/// [`PURITY_HITS_ABSENT`]. The empty plant is "the scan ran and found nothing"; this is the other
/// answer, and without it the self-test had no way to prove the UNPROVEN arm of `source-denylist`.
pub const DENYLIST_ABSENT: &str = "#DID-NOT-RUN";

/// The delegated dialect/plane-noun scan's hits artefact, asked of the gate that owns that policy.
///
/// THIS USED TO BE A SUBPROCESS, and the subprocess is what made the rule wrong. The rule delegated
/// to `scripts/plane-purity-lint.sh`; that script became `cargo xtask gate plane-purity` and was
/// deleted, so the spawn failed, no artefact appeared, and the row reported "the delegated scan did
/// not run" — while the shell gate, which had already been pointed at the new runner, went on
/// reporting the real count. Asking the gate IN THIS BINARY removes the failure mode along with the
/// spawn: there is no path for the two to disagree about which scanner ran.
///
/// `None` means the scan could not be made at all, which the rule reports as "did not run" — never
/// as zero hits.
pub fn purity_hits(cx: &Ctx) -> Option<String> {
    if let Some(planted) = cx.overlay_command(PURITY_HITS_KEY) {
        return (planted != PURITY_HITS_ABSENT).then_some(planted);
    }
    crate::gates::plane_purity::check_hits_artefact(cx).ok()
}

/// Per-crate transitive-closure hits, from the denylist scan `xtask` already owns.
///
/// `Err` is "the closure half never answered", with the reason, and the `source-denylist` rule turns
/// it into an UNPROVEN offender on every row. ITEM 167: this used to be an `Option` whose every
/// return path was `Some`, so the arm the rule spends on "never answered" was unreachable. Two
/// conditions reach it now:
///
/// * the tree this gate was pointed at is not a cargo workspace with an `xtask/` member — the
///   condition the Python checked before it spawned anything. It used to answer `Some(empty)`,
///   which the rule reads as "asked, and every crate is clean";
/// * the scan RAN and reported `defects` — its own statement that the run cannot be trusted (the
///   rule table renamed away, no crate matched a pure kind, a source tree that would not list).
///   Those carried no hits, so dropping the channel published a scan of nothing as a clean pass.
pub fn denylist_hits(cx: &Ctx) -> Result<BTreeMap<String, Vec<String>>, String> {
    if let Some(planted) = cx.overlay_command(DENYLIST_KEY) {
        if planted == DENYLIST_ABSENT {
            return Err("the planted scan did not run".to_string());
        }
        // The scan's own `<crate>\t<offender>\t<via>` wire form, so a plant says exactly what a
        // real run would have said and nothing here has to know a second shape. A line in any
        // other shape is refused rather than skipped: a skipped line is a hit that vanished.
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in planted.lines().filter(|l| !l.is_empty()) {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 3 {
                return Err(format!(
                    "the planted denylist answer has a malformed line (want \
                     `<crate>\\t<offender>\\t<via>`): {line:?}"
                ));
            }
            out.entry(parts[0].to_string()).or_default().push(format!(
                "`{}` via {} (cargo xtask denylist)",
                parts[1], parts[2]
            ));
        }
        return Ok(out);
    }
    if !cx.abs("Cargo.toml").is_file() || !cx.abs("xtask").is_dir() {
        return Err(format!(
            "{} is not a cargo workspace with an xtask/ member, so the closure scan cannot run",
            cx.root().display()
        ));
    }
    let report = crate::denylist::run(cx);
    if !report.defects.is_empty() {
        return Err(format!(
            "the scan ran but reported {} defect(s): {}",
            report.defects.len(),
            report.defects.join("; ")
        ));
    }
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in &report.hits {
        out.entry(h.crate_name.clone()).or_default().push(format!(
            "`{}` via {} (cargo xtask denylist)",
            h.offender, h.via
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ITEM 167: A SCAN THAT RAN AND REPORTED ITS OWN DEFECTS HAS NOT ANSWERED. With the
    /// `[rules.source-denylist]` table renamed away the denylist scan has no kinds and says so in
    /// its `defects` channel, with no hits; the construction gate used to read that as `Some(empty)`
    /// — every pure crate's closure clean.
    #[test]
    fn a_denylist_scan_that_reports_defects_is_not_an_answer() {
        let cx = Ctx::workspace().expect("workspace");
        let text = cx.read("qa/construction.toml").expect("the config");
        assert!(
            text.contains("[rules.source-denylist]"),
            "the control needs the table on disk"
        );
        let mut ov = crate::ctx::Overlay::new();
        ov.set(
            "qa/construction.toml",
            text.replace(
                "[rules.source-denylist]",
                "[rules.source-denylist-planted-away]",
            ),
        );
        let why = denylist_hits(&cx.with_overlay(ov))
            .expect_err("a scan with defects must not answer as a clean closure");
        assert!(why.contains("defect"), "{why}");
    }

    /// ITEM 167, THE PLANTED SPELLING: the sentinel is the not-answered arm, the empty plant is
    /// the clean one, and a malformed line is refused rather than dropped.
    #[test]
    fn the_planted_denylist_answer_has_three_distinct_readings() {
        let cx = Ctx::workspace().expect("workspace");
        let plant = |v: &str| {
            let mut ov = crate::ctx::Overlay::new();
            ov.set_command(DENYLIST_KEY, v);
            denylist_hits(&cx.with_overlay(ov))
        };
        assert!(plant(DENYLIST_ABSENT).is_err());
        assert!(plant("").expect("empty is a clean answer").is_empty());
        assert!(plant("busbar-plane-a2a\tlibc only-two-fields").is_err());
        let one = plant("busbar-plane-a2a\tlibc\tgetrandom\n").expect("well-formed");
        assert_eq!(one["busbar-plane-a2a"].len(), 1);
    }
}
