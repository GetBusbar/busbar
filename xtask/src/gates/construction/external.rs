//! THE THREE INPUTS THE CONSTRUCTION GATE DOES NOT MEASURE ITSELF.
//!
//! Each is a deliberate delegation the Python made and this port keeps, because in each case some
//! OTHER instrument already owns the policy and a second reading of it is a second policy:
//!
//! * `scripts/plane-purity-lint.sh` owns the dialect/plane-noun vocabulary and the frozen-wire
//!   allow-list. `neutral-no-dialect` counts its DIALECT/KEY rows and decides nothing itself.
//! * ~~`scripts/loc-surface.py` owns the surface-line counting rule~~ — NO LONGER DELEGATED, AND
//!   NO LONGER PYTHON. That script was a second opinion about how big a crate is, and it was the
//!   wrong one: it excluded only the top-level `src/tests/`, so the nested `src/<module>/tests/**`
//!   this tree actually keeps its proofs in was counted as production surface. `cargo xtask loc`
//!   is now the single counter and [`loc_surface`] asks it in process, the way `denylist` below is
//!   asked in process and for the same reason — a second reading of a policy is a second policy.
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

/// One `surface-ceiling:*` measurement: whether the counter accepted the ceiling, its `total`
/// figure and the tail of what it printed. The shape is the deleted script's, kept byte-for-byte so
/// the row's detail line did not move when the counter behind it did.
pub struct Surface {
    pub ok: bool,
    pub total: String,
    pub tail: String,
}

/// ONE COUNTER, ASKED IN PROCESS. This used to spawn `python3 scripts/loc-surface.py`, and the
/// spawn was not the only thing wrong with it: that script was a SECOND opinion about how many
/// lines a crate is, and it excluded only the top-level `src/tests/`, so the nested
/// `src/<module>/tests/**` this tree keeps its proofs in was billed as production surface. It read
/// `busbar-contract` at 8,439 where the crate's real code is under 6,700, and `busbar-llm-codec` at
/// 63,074 against 22,749. `cargo xtask loc` is now the only counter in the tree and this asks it
/// directly — so the figure a ceiling is measured against and the figure `cargo xtask loc` prints
/// cannot disagree, because they are the same call.
pub fn loc_surface(cx: &Ctx, crates: &str, limit: i64) -> Surface {
    let key = format!("{SURFACE_KEY_PREFIX}{crates}");
    let (ok, text) = match cx.overlay_command(&key) {
        // A planted measurement is `<ok 0|1>\n<stdout>`, so a self-test can plant the overage as
        // well as the figure.
        Some(planted) => {
            let (head, body) = planted.split_once('\n').unwrap_or((planted.as_str(), ""));
            (head.trim() == "0", body.to_string())
        }
        None => measure_surface(cx, crates, limit),
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

/// The measurement itself, in the SAME text shape the script printed, so the row's detail line and
/// the `total` field a caller parses are unchanged by the port.
///
/// Two refusals survive the port unchanged because each is a real answer the counting cannot give:
/// a crate the run did not measure at all, and a crate that measured ZERO — which satisfies every
/// ceiling and is therefore never a pass.
fn measure_surface(cx: &Ctx, crates: &str, limit: i64) -> (bool, String) {
    let names: Vec<&str> = crates
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let report = match crate::loc::measure_worktree_cached(cx) {
        Ok(r) => r,
        Err(e) => {
            return (
                false,
                format!("cargo xtask loc could not measure the tree: {e}\n"),
            )
        }
    };
    let mut text = String::from("crate       surface\n----------  -------\n");
    let mut total: i64 = 0;
    let mut missing = Vec::new();
    for name in &names {
        // A SUBJECT IS A CRATE OR A FILE. It has to be both, because a ceiling's subject can stop
        // being a crate without stopping being surface: `busbar-grammar` folded INTO
        // `busbar-contract` (#40) and its row went on naming the retired crate, so it summed
        // nothing and passed — a ceiling in name only. A path here repoints it at the module the
        // crate became, and a path that no longer exists is REPORTED, not counted as zero.
        let found = if name.contains('/') {
            report.file_counts(name)
        } else {
            report.crate_counts(name)
        };
        match found {
            Some(c) => {
                text.push_str(&format!("{name:<10}  {:>7}\n", c.code));
                total += c.code as i64;
            }
            None => missing.push(*name),
        }
    }
    text.push_str("----------  -------\n");
    text.push_str(&format!("total       {total:>7}\n"));
    if !missing.is_empty() {
        text.push_str(&format!(
            "FAIL  {crates}  names crates that were not measured: {}. A ceiling is a statement \
             about code; there has to be some.\n",
            missing.join(", ")
        ));
        return (false, text);
    }
    if total == 0 {
        text.push_str(&format!(
            "FAIL  {crates}  measured 0 code lines. A crate with no code is under every ceiling, \
             so this is not a pass -- point the ceiling at where the code went.\n"
        ));
        return (false, text);
    }
    // Only THIS row's subjects. A broken file in a crate this ceiling does not measure is somebody
    // else's row to go red.
    let unreadable: Vec<&str> = names
        .iter()
        .flat_map(|n| report.errors_for(n))
        .map(|e| e.path.as_str())
        .collect();
    if !unreadable.is_empty() {
        text.push_str(&format!(
            "FAIL  {crates}  {} file(s) could not be parsed and were counted as NOTHING: {}\n",
            unreadable.len(),
            unreadable.join(", ")
        ));
        return (false, text);
    }
    if total > limit {
        text.push_str(&format!("FAIL  {crates}  {total} > {limit}\n"));
        return (false, text);
    }
    text.push_str(&format!("ok    {crates}  {total} <= {limit}\n"));
    (true, text)
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
