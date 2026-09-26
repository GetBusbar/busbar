// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE METER-STEP REACHABILITY GATE — the mechanical proof that every billing plane actually
//! traverses the core Meter step (the canonical path's `Meter` verb: record/debit spend to the
//! principal's ledger), instead of reimplementing or skipping it.
//!
//! Why this gate exists: neutrality/doctrine gates prove the core mentions no plane — a SYNTACTIC
//! property. They are structurally blind to a plane that is perfectly neutral yet never bills,
//! because it built its own detached metering apparatus and left it unwired. That is exactly how a
//! plane can price at $0 in the shipped binary while every existing gate stays green. This gate
//! closes that blind spot: it scans each billing plane's PRODUCTION source (tests excluded) and
//! fails RED unless the plane reaches the core Meter seam at least once.
//!
//! The core Meter seam (the attributed metering entry points on the host / governance state — the
//! ONE billing path every plane must use, never a plane-private ledger):
//!   - `meter_charge`   (EngineHost: attributed charge over a dispatch scope)
//!   - `meter_ledger`   (EngineHost: ledger a delivery's usage against the key's budget chain)
//!   - `meter_series`   (EngineHost: record raw consumption into the per-key metering series)
//!   - `record_metering`/`record_usage` (governance-state accrual the above drive)
//!
//! A plane that calls NONE of these in production has no way to put spend on the ledger — it bills
//! nobody. This gate makes that a build failure, named by plane.
//!
//! ## Two paths, the same question
//!
//! The scan above is the LEGACY path's answer: the plane crate serves the request and reaches the
//! host's metering entry points itself. Over the composition root the plane holds no host at all —
//! it contributes one method per Teller step and the loop calls them in order — so the Meter step
//! lives in that plane's leg under `crates/busbar/src/root/units_*.rs`. A leg can pass every
//! neutrality and isomorphism gate in the tree and still proceed with an EMPTY usage report, which
//! is the identical blind spot one path over. [`every_billing_plane_reaches_the_usage_seam_on_its_teller_meter_step`]
//! closes it: every billing plane's leg must carry a Meter step AND reach the one usage seam.
//!
//! A plane the kernel-loop rider serves (`root/gauntlet_kernel.rs`, flipped per capability key by
//! `root/gauntlet_install.rs`) has no root leg at all: the rider opens a zero hold and reports no
//! evidence BY DESIGN, and the plane's money is metered inside its own `drive`, through the host's
//! ledger seam, into the kernel's accrual. So that plane's row asks the SERVED leg the same question
//! ([`every_billing_plane_the_rider_serves_ledgers_its_declared_class_on_the_served_path`]): the
//! plane's ledger step must reach the host's ledger seam under the class the plane declares, the
//! served path must call that step, and the host's seam must reach the kernel's accrual.
//!
//! A SESSION plane the rider opens (its session runner carries the open, never a turn) meters each
//! turn on the kernel's SESSION ACCOUNT (OWNER RULING Q21b): the plane reports a turn's raw counts per
//! declared class to the account, and the account ledgers them through the same host seam
//! ([`every_billing_session_plane_ledgers_each_turn_on_the_kernels_session_account`]). Every billing
//! plane answers on exactly one of the three paths — none is dropped by moving between them.

//! ## What this gate reads, and what it deliberately does not
//!
//! Both scans read PRODUCTION source through `tests/common/mod.rs` — comments stripped, and every
//! `#[cfg(test)] mod` body removed. That is not a detail. Reading a leg file whole means a
//! `Usage::report(` written inside that file's own unit tests satisfies the gate, and a plane whose
//! Meter step reaches nothing passes on the strength of the mock its tests use to stand in for the
//! step that is missing. The same applies one level down: the waist hop is resolved to the Meter
//! step's OWN module rather than summed over the plane's whole `src/unit/` tree, because a token in
//! the plane's Admit or Audit step is not the Meter step reaching the ledger — it is a different
//! step, and counting it means the gate answers a question about the file layout instead of about
//! the step.
//!
//! And the scan is of the Meter step's BODY, not of the file the step lives in. A leg file names
//! the usage seam in several steps; asking the file is how a `fn meter` that returns
//! `Decision::proceed` with an empty report keeps a green gate.

mod common;

use std::path::{Path, PathBuf};

/// Every plane that performs billable work and therefore MUST reach the core Meter seam. Keyed by
/// the plane's crate directory name under `crates/`.
/// The list is DATA — `tests/fixtures/billing_plane_legs.txt`, one row per billing plane naming how
/// it is answered — and every row must be a LINKED plane (see
/// [`every_billing_plane_is_a_linked_plane`]), so the source names no plugin.
fn billing_plane_crates() -> &'static [&'static str] {
    static CRATES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CRATES.get_or_init(|| billing_rows().iter().map(|r| r[0]).collect())
}

/// The rows of `tests/fixtures/billing_plane_legs.txt`, whitespace-split and leaked once.
fn billing_rows() -> &'static [Vec<&'static str>] {
    static ROWS: std::sync::OnceLock<Vec<Vec<&'static str>>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        common::fixture_lines("billing_plane_legs.txt")
            .into_iter()
            .map(|l| {
                let l: &'static str = Box::leak(l.into_boxed_str());
                l.split_whitespace().collect()
            })
            .collect()
    })
}

/// Every billing plane named by the fixture is a plane the composition root LINKS (a
/// `[package.metadata.busbar.linked]` row carrying the `plane` axis) — so the data cannot drift onto
/// a crate this binary does not carry, and the gate cannot shrink by a row going stale.
#[test]
fn every_billing_plane_is_a_linked_plane() {
    let linked: Vec<String> = common::linked_plane_crates()
        .into_iter()
        .map(|(_, krate)| krate)
        .collect();
    assert!(!billing_plane_crates().is_empty(), "no billing plane named");
    for plane in billing_plane_crates() {
        assert!(
            linked.iter().any(|k| k == plane),
            "billing plane `{plane}` is not a linked plane of this binary: {linked:?}"
        );
    }
}

/// The core Meter-seam call tokens. A production line containing any of these (outside a comment)
/// counts as reaching the one billing path.
const METER_SEAM_TOKENS: &[&str] = &[
    "meter_charge(",
    "meter_ledger(",
    "meter_series(",
    "record_metering(",
    "record_usage(",
];

fn crates_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/busbar; its parent is the crates/ tree.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/busbar has a parent (crates/)")
        .to_path_buf()
}

/// The count of production Meter-seam reaches in a plane crate's `src/` tree. PRODUCTION means the
/// shipped binary's text: [`common::production_lines`] has already dropped the comments and every
/// `#[cfg(test)] mod` body, so a plane whose only `meter_charge(` is in the mock its unit tests use
/// counts as zero — which is what it is.
fn meter_seam_reaches(crate_dir: &Path) -> usize {
    let mut files = Vec::new();
    common::production_rs_files(&crate_dir.join("src"), &mut files);
    files
        .iter()
        .flat_map(|p| common::production_lines(p))
        .filter(|l| METER_SEAM_TOKENS.iter().any(|tok| l.code.contains(tok)))
        .count()
}

#[test]
fn every_billing_plane_reaches_the_core_meter_seam_in_production() {
    let root = crates_root();
    let mut offenders: Vec<String> = Vec::new();
    for plane in billing_plane_crates() {
        let dir = root.join(plane);
        assert!(
            dir.join("src").is_dir(),
            "plane crate src not found: {} — this gate is scanning the wrong tree",
            dir.display()
        );
        let reaches = meter_seam_reaches(&dir);
        if reaches == 0 {
            offenders.push(format!(
                "{plane}: 0 calls to the core Meter seam ({}) in production source — it cannot put \
                 spend on any principal's ledger; it bills nobody",
                METER_SEAM_TOKENS.join(" / "),
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "a billing plane does NOT traverse the core Meter step in the shipped binary — it must \
         record spend through the ONE core metering seam (never a plane-private ledger):\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// THE SAME QUESTION OVER THE TELLER PATH.
//
// The gate above scans the PLANE CRATE, which is the legacy path's answer: the plane crate serves
// the request and reaches the host's metering entry points itself. Over the composition root the
// plane does not hold the host at all — it contributes one method per Teller step
// (`busbar_kernel::teller::TellerPlane`) and the loop calls them in order, so the Meter step is
// `fn meter(&mut self, token: &Pass<Meter>, usage: &Grant<Consumption>, …) -> Decision<Meter>` in that
// plane's leg under `crates/busbar/src/root/`.
//
// A leg can satisfy every neutrality and isomorphism gate in the tree and still hand back a
// `Decision::proceed` with an EMPTY usage report — the loop would run, the audit step would seal a
// terminal, and the principal would be charged nothing. That is the identical blind spot the legacy
// gate closes, one path over, and it is the one that matters now that the planes are being switched
// onto the root. So: every billing plane's leg must reach the ONE usage seam on its Meter step.
// ---------------------------------------------------------------------------

/// Billing plane crate -> the file whose `Units` impl runs it through the Teller loop, as a path under
/// `crates/`: a `root` row names a leg file under `crates/busbar/src/root/`, and a `unit` row names
/// the plane's OWN unit file — the `Units` impl its linked entry hands the root's node (the node
/// drives it; the steps are the plane's). Admin is deliberately absent: `root-admin` answers to ZERO
/// ledger columns in `qa/capability-equality.json` (an admin request is unpriced), so it is owed no
/// Meter reach and a row here would be a claim the ledger contradicts.
fn billing_plane_root_legs() -> &'static [(&'static str, String)] {
    static LEGS: std::sync::OnceLock<Vec<(&'static str, String)>> = std::sync::OnceLock::new();
    LEGS.get_or_init(|| {
        billing_rows()
            .iter()
            .filter_map(|r| match r[1] {
                "root" => Some((r[0], format!("busbar/src/root/{}", r[2]))),
                "unit" => Some((r[0], r[2].to_string())),
                _ => None,
            })
            .collect()
    })
}

/// The ONE usage seam every Teller Meter step folds through, in the three spellings the tree
/// actually uses: the usage unit's own entry point, the report constructor it returns, and the
/// per-leg fold helper that wraps it. A leg reaching NONE of these reports no lines, and a Meter
/// step that reports no lines charges nobody.
const TELLER_USAGE_SEAM_TOKENS: &[&str] = &[
    "busbar_kernel_ledger::usage::meter(",
    "Usage::report(",
    "fold_usage(",
];

/// THE ONE HOP a Meter step is allowed. `units_llm.rs`'s step is `self.walk.meter(token, usage)`,
/// which lands in the plane's own Meter module — the same one usage seam, reached through the
/// plane's waist rather than restated in the root. What the hop may NOT do is land anywhere else in
/// the plane: the destination below is the Meter step's own module, and a `Usage::report(` in the
/// plane's Admit or Audit step is a different step doing a different thing.
const PLANE_METER_STEP_MODULE: &[&str] = &["src", "unit", "meter.rs"];

/// The call shapes that hand the Meter step off to the plane's own waist.
const WAIST_HOP_TOKENS: &[&str] = &[".meter(", "::meter("];

/// Whether a classified production line reaches a Teller usage seam.
fn line_reaches_usage_seam(line: &common::Line) -> bool {
    TELLER_USAGE_SEAM_TOKENS
        .iter()
        .any(|tok| line.code.contains(tok))
}

/// The count of usage-seam reaches among a set of production lines.
fn usage_seam_reaches(lines: &[&common::Line]) -> usize {
    lines.iter().filter(|l| line_reaches_usage_seam(l)).count()
}

/// The count of usage-seam reaches in the plane's OWN Meter step module — the single legal hop
/// destination, rather than a sum over the whole `src/unit/` tree.
fn usage_seam_reaches_in_plane_meter_step(crate_dir: &Path) -> Option<usize> {
    let mut path: PathBuf = crate_dir.to_path_buf();
    for part in PLANE_METER_STEP_MODULE {
        path = path.join(part);
    }
    if !path.is_file() {
        return None;
    }
    let lines = common::production_lines(&path);
    let refs: Vec<&common::Line> = lines.iter().collect();
    Some(usage_seam_reaches(&refs))
}

#[test]
fn every_billing_plane_reaches_the_usage_seam_on_its_teller_meter_step() {
    let root = crates_root();
    let mut offenders: Vec<String> = Vec::new();

    for (plane, leg) in billing_plane_root_legs() {
        let leg_path = root.join(leg);
        assert!(
            leg_path.is_file(),
            "billing plane `{plane}` names root leg {} , which does not exist — this gate is \
             scanning the wrong tree",
            leg_path.display()
        );
        let lines = common::production_lines(&leg_path);
        assert!(
            !lines.is_empty(),
            "root leg {} classified to zero production lines — the scan is reading nothing, and a \
             scan that reads nothing passes everything",
            leg_path.display()
        );

        // (1) The leg must CARRY the Teller Meter step at all, IN PRODUCTION. A leg with no
        //     `fn meter` contributes no Meter method to the loop, and the loop cannot call a step
        //     that is not there. A `fn meter` that exists only inside the leg's own
        //     `#[cfg(test)] mod` is not in the binary and does not count.
        let Some(body) = common::item_body(&lines, "fn meter(") else {
            offenders.push(format!(
                "{plane}: root leg {leg} has NO production `fn meter(` — it contributes no Meter \
                 step to the Teller loop, so nothing it serves over the root is ever priced"
            ));
            continue;
        };

        // (2) The STEP'S OWN BODY must reach the one usage seam, directly or through the single
        //     legal hop into the plane's own Meter module. The question is asked of the step, not
        //     of the file: another step in the same file reaching the seam says nothing about this
        //     one, and a `fn meter` that proceeds with an empty report charges nobody.
        let direct = usage_seam_reaches(&body);
        if direct > 0 {
            println!("  {plane:<13} {leg:<15} usage seam: {direct} in the step's own body");
            continue;
        }

        let hops = body
            .iter()
            .filter(|l| WAIST_HOP_TOKENS.iter().any(|tok| l.code.contains(tok)))
            .count();
        if hops == 0 {
            offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body reaches the usage seam ({}) directly and \
                 hands off to nothing. A Meter step that reports no lines proceeds with an empty \
                 usage report — the loop runs, the audit seals, and the principal is charged nothing",
                TELLER_USAGE_SEAM_TOKENS.join(" / "),
            ));
            continue;
        }

        let meter_module = root.join(plane).join(PLANE_METER_STEP_MODULE.join("/"));
        match usage_seam_reaches_in_plane_meter_step(&root.join(plane)) {
            None => offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body hands off to the plane's waist, but \
                 {} does not exist. The hop lands nowhere this gate can follow, so nothing proves \
                 the handoff ends at the usage seam rather than at a step that reports no lines",
                meter_module.display()
            )),
            Some(0) => offenders.push(format!(
                "{plane}: root leg {leg}'s `fn meter` body hands off to the plane's waist, and the \
                 plane's own Meter step ({}) reaches the usage seam ({}) ZERO times in production. \
                 The handoff is real and the destination meters nobody",
                meter_module.display(),
                TELLER_USAGE_SEAM_TOKENS.join(" / "),
            )),
            Some(n) => {
                println!("  {plane:<13} {leg:<15} usage seam: {n} in the plane's own Meter step");
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a billing plane does NOT reach the usage seam on its Teller Meter step — over the \
         composition root the plane holds no host, so the ONLY place spend can be put on the \
         principal's ledger is the loop's Meter step:\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// THE SAME QUESTION OVER THE SERVED LEG OF A PLANE THE KERNEL-LOOP RIDER SERVES.
//
// The rider (`crates/busbar/src/root/gauntlet_kernel.rs`) drives the plane's own `drive` through the
// unified loop, opens a zero hold and reports ZERO evidence, so its Meter step reports no lines on
// purpose: the plane meters inside `drive`, and a second count at the loop's exit would be a double
// charge. The pre-unification root legs these planes once had are not the path a request takes, so
// asking them was asking about code no request reaches. The served leg is asked instead, and it is
// asked the same three things the Teller row asks, in its own terms: does the plane's ledger step
// reach the ONE ledger seam, is it the class the plane declares, and does the served path actually
// call it. And the seam itself must land in the kernel's accrual, or every plane behind it
// ledgers into nothing.
// ---------------------------------------------------------------------------

/// A billing plane the kernel-loop rider serves, and the step on its served path that puts its
/// declared class on the principal's ledger.
struct ServedLeg {
    /// `<plane crate directory under crates/>/<production file under it>` — where the step lives.
    at: &'static str,
    /// The ledger step's name: the scan finds `fn <name>(` and the served path's `<name>(` calls.
    name: &'static str,
    /// The plane's declared class constant the step ledgers under, found as `::meta::<class>`.
    class: &'static str,
}

impl ServedLeg {
    /// The plane crate's directory under `crates/`.
    fn plane(&self) -> &'static str {
        self.at.split_once('/').map_or(self.at, |(plane, _)| plane)
    }

    /// The production file, relative to the plane crate.
    fn file(&self) -> &'static str {
        self.at.split_once('/').map_or("", |(_, file)| file)
    }
}

/// Every billing plane the rider serves, with its served ledger step.
fn billing_plane_served_legs() -> &'static [ServedLeg] {
    static LEGS: std::sync::OnceLock<Vec<ServedLeg>> = std::sync::OnceLock::new();
    LEGS.get_or_init(|| {
        billing_rows()
            .iter()
            .filter(|r| r[1] == "served")
            .map(|r| ServedLeg {
                at: r[2],
                name: r[3],
                class: r[4],
            })
            .collect()
    })
}

/// The ONE ledger seam a served plane reaches: the host's `meter_ledger`, which appends the plane's
/// raw counts to the caller's budget chain.
const SERVED_LEDGER_SEAM: &str = "meter_ledger(";

/// Where the host implements that seam, relative to `crates/`, and the kernel accrual its body must
/// reach. A seam whose body stops reaching the accrual ledgers every plane behind it into nothing.
const HOST_LEDGER_SEAM_FILE: &str = "busbar-kernel/src/plane_host/mod.rs";
const HOST_LEDGER_SEAM_STEP: &str = "fn meter_ledger(";
const KERNEL_ACCRUAL: &str = "record_usage(";

/// What is wrong with one served leg, or nothing. Split out so the self-test drives the same
/// judgement on synthetic source that the tree is judged by.
fn served_leg_offences(
    leg: &ServedLeg,
    lines: &[common::Line],
    crate_lines: &[common::Line],
) -> Vec<String> {
    let (plane, file) = (leg.plane(), leg.file());
    let step = format!("fn {}(", leg.name);
    let call = format!("{}(", leg.name);
    let class = format!("::meta::{}", leg.class);
    let step = step.as_str();
    let Some(body) = common::item_body(lines, step) else {
        return vec![format!(
            "{plane}: {file} has NO production `{step}` — the served path has no step that puts \
             this plane's declared class on any ledger"
        )];
    };
    let mut out = Vec::new();
    if !body.iter().any(|l| l.code.contains(SERVED_LEDGER_SEAM)) {
        out.push(format!(
            "{plane}: `{step}` in {file} does not reach the host ledger seam ({SERVED_LEDGER_SEAM}) \
             — the served path ledgers nothing, and the principal is charged nothing for this class"
        ));
    }
    if !body.iter().any(|l| l.code.contains(&class)) {
        out.push(format!(
            "{plane}: `{step}` in {file} does not ledger under the plane's declared class \
             ({class}) — a count under an undeclared class is one no card, cap or usage row can name"
        ));
    }
    let callers = crate_lines
        .iter()
        .filter(|l| l.code.contains(&call) && !l.code.contains(step))
        .count();
    if callers == 0 {
        out.push(format!(
            "{plane}: nothing in the plane's production source calls `{call}` — the ledger step \
             exists and the served path never reaches it"
        ));
    }
    out
}

#[test]
fn every_billing_plane_the_rider_serves_ledgers_its_declared_class_on_the_served_path() {
    let root = crates_root();

    // Totality: every billing plane answers on exactly one path, so moving a plane between the two
    // tables can never drop it from both.
    for plane in billing_plane_crates() {
        let on_root = billing_plane_root_legs()
            .iter()
            .filter(|(p, _)| p == plane)
            .count();
        let served = billing_plane_served_legs()
            .iter()
            .filter(|l| l.plane() == *plane)
            .count();
        let session = billing_plane_session_legs()
            .iter()
            .filter(|l| l.plane == *plane)
            .count();
        assert_eq!(
            on_root + served + session,
            1,
            "billing plane `{plane}` must be answered by exactly one row — a Teller root leg, a \
             served leg or a session leg — and is answered by {on_root} root, {served} served and \
             {session} session rows"
        );
    }

    let mut offenders: Vec<String> = Vec::new();

    let seam_path = root.join(HOST_LEDGER_SEAM_FILE);
    let seam_lines = common::production_lines(&seam_path);
    match common::item_body(&seam_lines, HOST_LEDGER_SEAM_STEP) {
        None => offenders.push(format!(
            "{HOST_LEDGER_SEAM_FILE} has no production `{HOST_LEDGER_SEAM_STEP}` — the seam every \
             served plane ledgers through is not implemented by the host"
        )),
        Some(body) if !body.iter().any(|l| l.code.contains(KERNEL_ACCRUAL)) => offenders.push(format!(
            "{HOST_LEDGER_SEAM_FILE}: the host's `{HOST_LEDGER_SEAM_STEP}` does not reach the kernel \
             accrual ({KERNEL_ACCRUAL}) — every served plane ledgers into nothing"
        )),
        Some(_) => {}
    }

    for leg in billing_plane_served_legs() {
        let dir = root.join(leg.plane());
        let path = dir.join(leg.file());
        assert!(
            path.is_file(),
            "billing plane `{}` names served leg {}, which does not exist — this gate is scanning \
             the wrong tree",
            leg.plane(),
            path.display()
        );
        let lines = common::production_lines(&path);
        assert!(
            !lines.is_empty(),
            "served leg {} classified to zero production lines — a scan that reads nothing passes \
             everything",
            path.display()
        );
        let mut files = Vec::new();
        common::production_rs_files(&dir.join("src"), &mut files);
        let crate_lines: Vec<common::Line> = files
            .iter()
            .flat_map(|p| common::production_lines(p))
            .collect();
        let found = served_leg_offences(leg, &lines, &crate_lines);
        if found.is_empty() {
            println!(
                "  {:<13} {:<20} served ledger seam reached",
                leg.plane(),
                leg.name
            );
        }
        offenders.extend(found);
    }

    assert!(
        offenders.is_empty(),
        "a billing plane the kernel-loop rider serves does NOT ledger its declared class on the \
         served path — the rider meters nothing by design, so the plane's own ledger step is the \
         ONLY place its spend reaches the principal's ledger:\n{}",
        offenders.join("\n")
    );
}

/// The served-leg judgement FIRES, on synthetic source: a ledger step that stopped reaching the
/// seam, one that ledgers an undeclared class, and one nothing calls are each named, and the whole
/// leg is clean only when all three hold.
#[test]
fn selftest_the_served_leg_judgement_fires() {
    let leg = ServedLeg {
        at: "busbar-demo/src/demo.rs",
        name: "ledger_demo",
        class: "CLASS_DEMO",
    };
    let prod = |src: &str| -> Vec<common::Line> {
        common::classify(src, false)
            .into_iter()
            .filter(|l| !l.intest)
            .collect()
    };
    let good = "fn ledger_demo(host: &H) {\n    let usage = busbar_plane_demo::meta::CLASS_DEMO;\n    host.meter_ledger(&usage);\n}\nfn drive() {\n    ledger_demo(host);\n}\n";
    let lines = prod(good);
    assert!(served_leg_offences(&leg, &lines, &lines).is_empty());

    let no_seam = good.replace("host.meter_ledger(&usage);", "let _ = usage;");
    let lines = prod(&no_seam);
    let found = served_leg_offences(&leg, &lines, &lines);
    assert!(
        found
            .iter()
            .any(|o| o.contains("does not reach the host ledger seam")),
        "{found:?}"
    );

    let wrong_class = good.replace("CLASS_DEMO", "CLASS_OTHER");
    let lines = prod(&wrong_class);
    let found = served_leg_offences(&leg, &lines, &lines);
    assert!(
        found.iter().any(|o| o.contains("declared class")),
        "{found:?}"
    );

    let uncalled = good.replace("    ledger_demo(host);\n", "");
    let lines = prod(&uncalled);
    let found = served_leg_offences(&leg, &lines, &lines);
    assert!(
        found.iter().any(|o| o.contains("never reaches it")),
        "{found:?}"
    );

    let only_in_tests = format!("#[cfg(test)]\nmod tests {{\n{}\n}}\n", good);
    let lines = prod(&only_in_tests);
    let found = served_leg_offences(&leg, &lines, &lines);
    assert!(
        found.iter().any(|o| o.contains("NO production")),
        "{found:?}"
    );
}

// ---------------------------------------------------------------------------
// THE SESSION LEG (a session plane the rider opens, metered per turn on the kernel's session account).
//
// The rider carries a session's OPEN and nothing after it; each turn of the served session is the
// plane's, and OWNER RULING Q21b puts its money on the kernel's session account: the plane reports
// the turn's raw counts per declared class, and the account ledgers them through the host's ledger
// seam. So the row asks the same questions in those terms: does the plane's turn step report to the
// session account, are the counts it reports the plane's declared classes, does the served session
// call that step, and does the account itself reach the host's ledger seam.
// ---------------------------------------------------------------------------

/// A billing plane whose served sessions are metered per turn on the kernel's session account.
struct SessionLeg {
    /// The billing plane's crate directory under `crates/`.
    plane: &'static str,
    /// `<crate>/<file>` — where the plane's turn step lives.
    step_at: &'static str,
    /// The turn step's name: the scan finds `fn <name>(`, and the served session's `.<name>(` calls.
    step: &'static str,
    /// `<crate>/<file>` — where the plane's declared classes for a turn are read.
    classes_at: &'static str,
    /// The function that reads them: its body names `meta::<class>`, and the step's file calls it.
    classes: &'static str,
    /// A declared class constant that function must name.
    class: &'static str,
}

/// Every billing plane metered on the kernel's session account.
fn billing_plane_session_legs() -> &'static [SessionLeg] {
    static LEGS: std::sync::OnceLock<Vec<SessionLeg>> = std::sync::OnceLock::new();
    LEGS.get_or_init(|| {
        billing_rows()
            .iter()
            .filter(|r| r[1] == "session")
            .map(|r| SessionLeg {
                plane: r[0],
                step_at: r[2],
                step: r[3],
                classes_at: r[4],
                classes: r[5],
                class: r[6],
            })
            .collect()
    })
}

/// The call a plane's turn step reports to the kernel's session account through.
const SESSION_ACCOUNT_CALL: &str = "account.report_turn(";
/// Where the kernel's session account lives, relative to `crates/`, and the step of it that must
/// reach the host's ledger seam.
const SESSION_ACCOUNT_FILE: &str = "busbar-kernel/src/plane_host/session_meter.rs";
const SESSION_ACCOUNT_STEP: &str = "fn report_turn(";

/// What is wrong with one session leg, or nothing: the plane's step lines, the lines of the file
/// its classes are read in, and the plane crate's production lines OUTSIDE the step's file.
fn session_leg_offences(
    leg: &SessionLeg,
    step_lines: &[common::Line],
    class_lines: &[common::Line],
    elsewhere: &[common::Line],
) -> Vec<String> {
    let (plane, step) = (leg.plane, format!("fn {}(", leg.step));
    let mut out = Vec::new();
    match common::item_body(step_lines, &step) {
        None => out.push(format!(
            "{plane}: {} has NO production `{step}` — a served session's turn reaches no ledger",
            leg.step_at
        )),
        Some(body) if !body.iter().any(|l| l.code.contains(SESSION_ACCOUNT_CALL)) => {
            out.push(format!(
                "{plane}: `{step}` in {} does not report to the kernel's session account \
                 ({SESSION_ACCOUNT_CALL}) — the served session's turns are ledgered nowhere",
                leg.step_at
            ))
        }
        Some(_) => {}
    }
    let classes_call = format!("{}(", leg.classes);
    if !step_lines
        .iter()
        .any(|l| l.code.contains(&classes_call) && !l.code.contains(&format!("fn {classes_call}")))
    {
        out.push(format!(
            "{plane}: {} never calls `{classes_call}` — what the turn reports is not the plane's \
             declared classes",
            leg.step_at
        ));
    }
    let class = format!("meta::{}", leg.class);
    match common::item_body(class_lines, &format!("fn {classes_call}")) {
        Some(body) if body.iter().any(|l| l.code.contains(&class)) => {}
        _ => out.push(format!(
            "{plane}: `fn {classes_call}` in {} does not count under the plane's declared class \
             ({class}) — a count under an undeclared class is one no card, cap or usage row can name",
            leg.classes_at
        )),
    }
    let call = format!(".{}(", leg.step);
    if !elsewhere.iter().any(|l| l.code.contains(&call)) {
        out.push(format!(
            "{plane}: nothing in the plane's served session calls `{call}` — the turn step exists and \
             no turn reaches it"
        ));
    }
    out
}

#[test]
fn every_billing_session_plane_ledgers_each_turn_on_the_kernels_session_account() {
    let root = crates_root();
    let mut offenders: Vec<String> = Vec::new();

    let account_lines = common::production_lines(&root.join(SESSION_ACCOUNT_FILE));
    match common::item_body(&account_lines, SESSION_ACCOUNT_STEP) {
        Some(body) if body.iter().any(|l| l.code.contains(SERVED_LEDGER_SEAM)) => {}
        _ => offenders.push(format!(
            "{SESSION_ACCOUNT_FILE}: the kernel session account's `{SESSION_ACCOUNT_STEP}` does not \
             reach the host ledger seam ({SERVED_LEDGER_SEAM}) — every session plane ledgers into \
             nothing"
        )),
    }

    for leg in billing_plane_session_legs() {
        let step_path = root.join(leg.step_at);
        let class_path = root.join(leg.classes_at);
        for path in [&step_path, &class_path] {
            assert!(
                path.is_file(),
                "billing plane `{}` names {}, which does not exist — this gate is scanning the \
                 wrong tree",
                leg.plane,
                path.display()
            );
        }
        let step_lines = common::production_lines(&step_path);
        assert!(
            !step_lines.is_empty(),
            "session leg {} classified to zero production lines — a scan that reads nothing \
             passes everything",
            step_path.display()
        );
        let class_lines = common::production_lines(&class_path);
        let mut files = Vec::new();
        common::production_rs_files(&root.join(leg.plane).join("src"), &mut files);
        let elsewhere: Vec<common::Line> = files
            .iter()
            .filter(|p| **p != step_path)
            .flat_map(|p| common::production_lines(p))
            .collect();
        let found = session_leg_offences(leg, &step_lines, &class_lines, &elsewhere);
        if found.is_empty() {
            println!(
                "  {:<13} {:<20} session account ledger seam reached",
                leg.plane, leg.step
            );
        }
        offenders.extend(found);
    }

    assert!(
        offenders.is_empty(),
        "a billing session plane does NOT ledger each turn's declared classes on the kernel's \
         session account — the rider carries the open and nothing after it, so the plane's turn step \
         is the ONLY place a served session's spend reaches the principal's ledger:\n{}",
        offenders.join("\n")
    );
}

/// The session-leg judgement FIRES, on synthetic source: a step that stopped reporting to the
/// account, a class read that names an undeclared class, and a step no turn calls are each named.
#[test]
fn selftest_the_session_leg_judgement_fires() {
    let leg = SessionLeg {
        plane: "busbar-demo",
        step_at: "busbar-demo/src/metering.rs",
        step: "report_turn",
        classes_at: "busbar-plane-demo/src/session.rs",
        classes: "class_counts",
        class: "CLASS_DEMO",
    };
    let prod = |src: &str| -> Vec<common::Line> {
        common::classify(src, false)
            .into_iter()
            .filter(|l| !l.intest)
            .collect()
    };
    let step =
        "fn report_turn(&self) {\n    self.account.report_turn(&counts(class_counts(u)));\n}\n";
    let classes = "fn class_counts(u: U) -> V {\n    vec![(meta::CLASS_DEMO, u.n)]\n}\n";
    let caller = "fn settle(&self) {\n    metering.report_turn();\n}\n";
    let judge =
        |s: &str, c: &str, e: &str| session_leg_offences(&leg, &prod(s), &prod(c), &prod(e));
    assert!(judge(step, classes, caller).is_empty());
    let found = judge(
        &step.replace("self.account.report_turn(", "drop("),
        classes,
        caller,
    );
    assert!(
        found.iter().any(|o| o.contains("session account")),
        "{found:?}"
    );
    let found = judge(step, &classes.replace("CLASS_DEMO", "CLASS_OTHER"), caller);
    assert!(
        found.iter().any(|o| o.contains("declared class")),
        "{found:?}"
    );
    let found = judge(step, classes, "fn settle(&self) {}\n");
    assert!(
        found.iter().any(|o| o.contains("no turn reaches it")),
        "{found:?}"
    );
    let found = judge(&step.replace("class_counts(u)", "u"), classes, caller);
    assert!(found.iter().any(|o| o.contains("never calls")), "{found:?}");
}

// ---------------------------------------------------------------------------
// SELF-TEST: both gates are proven to FIRE. A gate that cannot fail is worse than none.
// ---------------------------------------------------------------------------

/// Classify a synthetic leg and hand back its `fn meter` body's production lines.
fn meter_body_of(src: &str) -> Vec<String> {
    let lines = common::classify(src, false);
    let prod: Vec<common::Line> = lines.into_iter().filter(|l| !l.intest).collect();
    common::item_body(&prod, "fn meter(")
        .map(|b| b.iter().map(|l| l.code.clone()).collect())
        .unwrap_or_default()
}

#[test]
fn selftest_the_seam_scanners_discriminate() {
    let seam = |code: &str| {
        TELLER_USAGE_SEAM_TOKENS
            .iter()
            .any(|tok| code.contains(tok))
    };
    // A real call counts; the same token in a comment or with no call parens does not.
    let prod = |src: &str| {
        common::classify(src, false)
            .into_iter()
            .filter(|l| !l.intest)
            .map(|l| l.code)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(seam(&prod("Usage::report(usage, lines)\n")));
    assert!(!seam(&prod("// Usage::report(usage, lines)\n")));
    assert!(!seam(&prod("let x = 1; // fold_usage(y)\n")));
    assert!(!seam(&prod("let x = record_metering;\n")));
    assert!(METER_SEAM_TOKENS
        .iter()
        .any(|t| prod("host.meter_charge(&scope, n);\n").contains(t)));
}

/// THE FAILURE THIS GATE WAS BLIND TO. The scan used to read the leg file whole, so a seam token in
/// the leg's own `#[cfg(test)] mod tests` satisfied it — a Meter step reaching NOTHING passed on
/// the strength of the mock the tests use to stand in for the step that is missing. Driven here on
/// synthetic source so the proof does not require planting a fake leg in the tree.
#[test]
fn selftest_a_seam_reached_only_by_a_test_module_does_not_count() {
    let leg_that_meters_nobody = r#"
impl TellerPlane for Leg {
    fn meter(&self, token: &Pass<Meter>, usage: &Grant<Consumption>) -> Decision<Meter> {
        Decision::proceed(token, Default::default())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_step_meters() {
        let report = Usage::report(usage, lines);
        assert!(report.is_ok());
    }
}
"#;
    let body = meter_body_of(leg_that_meters_nobody).join("\n");
    assert!(
        !body.is_empty(),
        "the synthetic leg's Meter step must be found at all, or this self-test proves nothing"
    );
    assert!(
        !TELLER_USAGE_SEAM_TOKENS.iter().any(|t| body.contains(t)),
        "a `Usage::report(` that exists only inside the leg's `#[cfg(test)] mod tests` was counted \
         as the Meter step reaching the ledger. The whole gate is satisfiable by a mock while that \
         is true:\n{body}"
    );
    assert!(
        !WAIST_HOP_TOKENS.iter().any(|t| body.contains(t)),
        "the step hands off to nothing either, so this synthetic leg is exactly the shape the gate \
         must report: proceed with an empty report, charging nobody:\n{body}"
    );
}

/// THE SECOND FAILURE. The waist hop used to be summed over the plane's whole `src/unit/` tree, so
/// a `Usage::report(` in the plane's AUDIT step satisfied a gate asking about its METER step. The
/// hop destination is now one named module, and this proves the two are told apart.
#[test]
fn selftest_the_hop_lands_on_the_meter_step_and_not_the_neighbouring_step() {
    let root = crates_root();
    for (plane, _) in billing_plane_root_legs() {
        let dir = root.join(plane);
        let unit_dir = dir.join("src").join("unit");
        if !unit_dir.is_dir() {
            continue;
        }
        let mut all = Vec::new();
        common::production_rs_files(&unit_dir, &mut all);
        let tree_wide: usize = all
            .iter()
            .flat_map(|p| common::production_lines(p))
            .filter(line_reaches_usage_seam)
            .count();
        let step_only = usage_seam_reaches_in_plane_meter_step(&dir).unwrap_or(0);
        assert!(
            step_only <= tree_wide,
            "{plane}: the Meter step's own module cannot reach the seam more often than the whole \
             unit tree does — the scan is reading the wrong file"
        );
        println!("  {plane:<13} usage seam: {step_only} in the Meter step, {tree_wide} tree-wide");
    }
}
