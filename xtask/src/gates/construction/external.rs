//! THE THREE INPUTS THE CONSTRUCTION GATE DOES NOT MEASURE ITSELF.
//!
//! Each is a deliberate delegation the Python made and this port keeps, because in each case some
//! OTHER instrument already owns the policy and a second reading of it is a second policy:
//!
//! * `scripts/plane-purity-lint.sh` owns the dialect/plane-noun vocabulary and the frozen-wire
//!   allow-list. `neutral-no-dialect` counts its DIALECT/KEY rows and decides nothing itself.
//! * `scripts/loc-surface.py` owns the surface-line counting rule the section 1.1 ceilings are
//!   expressed in. The four `surface-ceiling:*` rows turn its exit status into ledger rows.
//! * `cargo xtask denylist` owns the TRANSITIVE dependency closure, which no text scan can see.
//!   Here it is called IN PROCESS rather than as a subprocess: the Python had to spawn it, and had
//!   to tell "asked, nothing found" apart from "never asked" across a process boundary that could
//!   fail four different ways. In process there is no such boundary, so the distinction collapses
//!   to "the scan ran" — and the scan's own defects are folded into the rows as hits would be.
//!
//! Every one of them is OVERLAY-OVERRIDABLE. A self-test cannot plant into a subprocess's view of
//! the tree — the overlay lives in this process — so a plant that needs one of these inputs sets
//! it directly, and what the case then proves is the rule's own counting, which is exactly what
//! the rule is.

use std::collections::BTreeMap;
use std::process::Command;

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
/// The overlay key a self-test plants one surface-ceiling measurement under.
pub const SURFACE_KEY_PREFIX: &str = "construction:loc-surface:";
/// The overlay key a self-test plants the transitive-closure scan's answer under.
pub const DENYLIST_KEY: &str = "construction:denylist-tsv";

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

/// One `surface-ceiling:*` measurement: the `loc-surface.py` run's exit status, its `total` figure
/// and the tail of what it printed.
pub struct Surface {
    pub ok: bool,
    pub total: String,
    pub tail: String,
}

pub fn loc_surface(cx: &Ctx, crates: &str, limit: i64) -> Surface {
    let key = format!("{SURFACE_KEY_PREFIX}{crates}");
    let (ok, text) = match cx.overlay_command(&key) {
        // A planted measurement is `<ok 0|1>\n<stdout>`, so a self-test can plant the overage as
        // well as the figure.
        Some(planted) => {
            let (head, body) = planted.split_once('\n').unwrap_or((planted.as_str(), ""));
            (head.trim() == "0", body.to_string())
        }
        None => {
            let out = Command::new("python3")
                .arg("scripts/loc-surface.py")
                .arg("--ceiling")
                .arg(format!("{crates}={limit}"))
                .current_dir(cx.root())
                .output();
            match out {
                Ok(o) => {
                    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                    text.push_str(&String::from_utf8_lossy(&o.stderr));
                    (o.status.success(), text)
                }
                Err(e) => (false, format!("loc-surface.py could not be run: {e}\n")),
            }
        }
    };
    // `awk '$1=="total"{print $2}'`, and the shell's `${surface_now:-?}` when it printed none.
    let total = text
        .lines()
        .find_map(|l| {
            let mut f = l.split_whitespace();
            (f.next() == Some("total")).then(|| f.next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "?".to_string());
    // `tail -3 | tr '\n' ' '` — including the trailing space that leaves behind.
    let lines: Vec<&str> = text.lines().collect();
    let tail = lines[lines.len().saturating_sub(3)..]
        .iter()
        .map(|l| format!("{l} "))
        .collect::<String>();
    Surface { ok, total, tail }
}

/// Per-crate transitive-closure hits, from the denylist scan `xtask` already owns. `None` is
/// reserved for "the closure half never answered", which in process can only mean the tree this
/// gate was pointed at is not a cargo workspace with an `xtask/` member — the same condition the
/// Python checked before it ever spawned anything.
pub fn denylist_hits(cx: &Ctx) -> Option<BTreeMap<String, Vec<String>>> {
    if let Some(planted) = cx.overlay_command(DENYLIST_KEY) {
        // The scan's own `<crate>\t<offender>\t<via>` wire form, so a plant says exactly what a
        // real run would have said and nothing here has to know a second shape.
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in planted.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 3 {
                continue;
            }
            out.entry(parts[0].to_string()).or_default().push(format!(
                "`{}` via {} (cargo xtask denylist)",
                parts[1], parts[2]
            ));
        }
        return Some(out);
    }
    if !cx.abs("Cargo.toml").is_file() || !cx.abs("xtask").is_dir() {
        return Some(BTreeMap::new());
    }
    let report = crate::denylist::run(cx);
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in &report.hits {
        out.entry(h.crate_name.clone()).or_default().push(format!(
            "`{}` via {} (cargo xtask denylist)",
            h.offender, h.via
        ));
    }
    Some(out)
}
