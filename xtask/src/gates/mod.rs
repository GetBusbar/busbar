//! THE GATE REGISTRY, THE `Gate` TRAIT, AND THE PROOF CONTRACT.
//!
//! One subcommand, one registry: `cargo xtask gate <name>`, `--list`, `--all`, and
//! `cargo xtask selftest [<name>]`. The registry is a plain `&'static [Registration]`, not a
//! proc-macro inventory crate — the point of this crate is to have almost no dependencies, and one
//! array edit per gate is cheaper than a dependency whose whole job is to save that edit.
//!
//! Two properties are load-bearing and both are enforced here rather than left to a convention:
//!
//! 1. **THE OWED SET IS DERIVED FROM THE REGISTRY.** A gate declares the row ids it can emit
//!    ([`Gate::owed`]); [`execute`] reconciles what it emitted against what it declared and is RED
//!    in either direction. A rule cannot be added without being owed, so it cannot write a FAIL row
//!    into a ledger nobody diffs and exit 0 through it; and an owed row that stops being emitted is
//!    DID NOT RUN, not silence.
//! 2. **`selftest` PROVES RED, NOT MERELY "RAN".** [`Expect::Red`] carries the offender strings the
//!    report must name, so a fixture that goes green when it should go red is refused, and so is a
//!    red that does not NAME the planted offender. A selftest reaches its gate only through
//!    [`Gate::run`] — the trait gives it no other handle — so re-implementing the predicate beside
//!    the gate, the failure seven of the shell self-tests had, is not something a selftest CAN do.

pub mod blocking_ffi;
pub mod changelog;
pub mod changelog_register;
pub mod ci_umbrella;
pub mod denylist_gate;
pub mod duplex_ws_default_edge;
pub mod field_inventory;
pub mod inventory_ref;
pub mod kernel_token_wire_purity;
pub mod no_deferral;
pub mod no_self_filed_issues;
pub mod plane_abi_neutrality;
pub mod plane_purity;
pub mod plane_transport_neutrality;
pub mod qa_gate_dispatch;
pub mod release_order;
pub mod response_header;
pub mod segregation;
pub mod service_images;
pub mod settings_leak;
pub mod structure_lint;
pub mod teller_steps;
pub mod tracing;
pub mod workspace_deps;

use std::collections::BTreeSet;
use std::path::Path;

use crate::ctx::{Ctx, Overlay};
use crate::ledger::{Reconcile, Row, Verdict};

/// Which runner tier a gate belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Every push: pure text/graph reads, no build, no network, no service container.
    Fast,
    /// The local/full runner.
    Full,
    /// The release path.
    Release,
}

pub struct Registration {
    pub name: &'static str,
    pub batch: u8,
    pub tier: Tier,
    pub build: fn() -> Box<dyn Gate>,
    /// One line, printed by `--list`.
    pub summary: &'static str,
}

pub trait Gate {
    fn name(&self) -> &'static str;

    /// Every ledger row id this gate can emit. THE OWED SET. Non-empty by construction: a gate
    /// that owes nothing has nothing anybody reconciles.
    fn owed(&self) -> Vec<String>;

    /// The gate's verdict over the tree `cx` shows it. Never panics on a tree it does not like;
    /// panics only on its OWN bugs.
    fn run(&self, cx: &Ctx) -> Verdict;

    /// Proves the gate can still be RED, by planting violations into overlays and requiring the
    /// run to report them BY NAME.
    fn selftest(&self, cx: &Ctx) -> Report;

    /// The planted trees `cargo xtask gate <name> --parity` drives BOTH implementations over.
    ///
    /// A parity run that compares only the real tree compares one green against another green, and
    /// two implementations that both do nothing agree perfectly. Each probe is a violation planted
    /// into an overlay together with the row id the legacy script and this gate must BOTH report,
    /// so parity is asserted where the two could actually differ. A gate that declares no probes is
    /// refused by the harness rather than passing vacuously.
    ///
    /// The paths a probe touches are listed so the harness knows what to materialize for the
    /// legacy script, which reads a tree on disk and has no overlay.
    fn parity_probes(&self, _cx: &Ctx) -> Vec<ParityProbe> {
        Vec::new()
    }

    /// THE OTHER PROOF STYLE: extra legacy commands `--parity` must run beside the one named on
    /// the command line, for a gate whose legacy half was more than one script. Each is run over
    /// the same tree, with the same environment, and handed to [`Gate::legacy_rows`] in this order
    /// after the primary.
    fn legacy_companions(&self) -> Vec<Vec<String>> {
        Vec::new()
    }

    /// Environment the legacy scripts need so `--parity` can read WHAT THEY MEASURED rather than
    /// re-deriving it from prose. `scratch` is a directory the harness owns for this run.
    fn legacy_env(&self, _scratch: &Path) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Whether `--parity` reads the legacy half through [`Gate::legacy_rows`] instead of through
    /// the `$LEDGER` TSV. Answered ahead of the run so a gate without an adapter never pays for
    /// the legacy invocation, and so a `None` from `legacy_rows` is a BUG rather than a silent
    /// fall-back to an empty ledger file.
    fn has_legacy_adapter(&self) -> bool {
        false
    }

    /// Derive the legacy half's ledger rows from its own run — THE ROW-AGAINST-ROW PROOF.
    ///
    /// A gate proves parity one of two ways, and the two answer different questions. This one is
    /// the stronger claim: the legacy's own measurement is translated into rows built by the SAME
    /// constructor [`Gate::run`] uses, so the only thing a diff can be about is the offender set.
    /// The other is [`Gate::parity_probes`] — verdict against verdict over planted trees — for a
    /// legacy whose output no translator can key on; there the plants are what stop "both found
    /// nothing" from passing for agreement. A gate may declare both. A gate that declares neither
    /// is refused by the harness rather than claiming parity vacuously.
    ///
    /// `None` — the default — means the legacy script writes the TSV itself through `$LEDGER`, the
    /// shape `release-gate/lib.sh::record` established, or that this gate is proved by probes. A
    /// gate whose script PREDATES the ledger and prints a report instead supplies the adapter here,
    /// and the adapter must read the script's own MEASUREMENT artefact (its hit list with its
    /// `#SCAN` denominator, its counted table), never its prose: a parity proof built out of two
    /// prose parsers proves the parsers agree, not the gates.
    ///
    /// `runs` carries the primary invocation first and every [`Gate::legacy_companions`] entry
    /// after it, in the order they were declared — a single-script legacy reads `runs[0]` and
    /// ignores the rest.
    fn legacy_rows(&self, _cx: &Ctx, _runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        None
    }
}

/// ONE `LegacyRun`, WHICHEVER PROOF STYLE READS IT. The type lives in [`crate::parity`] beside the
/// harness that fills it in, and is re-exported here because a gate's adapter is written against
/// `gates::LegacyRun` and should not have to know which module the harness keeps it in.
pub use crate::parity::LegacyRun;

/// One planted tree both implementations are driven over.
pub struct ParityProbe {
    pub label: String,
    /// The overlay the Rust gate reads through.
    pub overlay: Overlay,
    /// Every path the legacy script must be shown, relative to the workspace root. The harness
    /// materializes the OVERLAID view of each one into a scratch tree.
    pub materialize: Vec<String>,
    /// The row id THIS GATE must report. `None` means "both must be green".
    pub expect_rule: Option<String>,
    /// The substring that identifies the SAME rule in the legacy script's output, when the two
    /// spell it differently.
    ///
    /// Two gates could not keep their legacy row ids, because those ids were not a fixed set: one
    /// keyed rows by file-and-line, the other by data-file entry. A `Gate::owed` set has to be
    /// predictable — that is the whole mechanism by which a rule that stopped being emitted is
    /// detectable — so the rule became the id and the moving part moved into the row detail. This
    /// field is how a probe still proves the two are red about the SAME THING across that rename,
    /// rather than merely both being red.
    pub legacy_names: Option<String>,
    /// A DECLARED difference between the two implementations, with the reason written down.
    ///
    /// The point of declaring one is that it is reviewable and that it EXPIRES: the harness checks
    /// the difference still exists, so a declaration the legacy has since grown out of is RED
    /// rather than a line nobody re-reads. That is the stale-waiver rule applied to parity.
    pub divergence: Option<Divergence>,
}

impl ParityProbe {
    /// A probe that plants a violation both implementations must report.
    pub fn red(
        label: impl Into<String>,
        overlay: Overlay,
        materialize: Vec<String>,
        rule: impl Into<String>,
    ) -> ParityProbe {
        ParityProbe {
            label: label.into(),
            overlay,
            materialize,
            expect_rule: Some(rule.into()),
            legacy_names: None,
            divergence: None,
        }
    }

    /// The same, where the legacy names the rule with a different string.
    pub fn named_by(mut self, legacy: impl Into<String>) -> ParityProbe {
        self.legacy_names = Some(legacy.into());
        self
    }

    /// The same, where the two genuinely differ and the difference is deliberate.
    pub fn diverges(mut self, d: Divergence) -> ParityProbe {
        self.divergence = Some(d);
        self
    }
}

/// The two ways a converted gate is allowed to differ from the script it replaces. Both carry a
/// reason, and [`Divergence::reason`] is refused when it is too short to be one.
pub enum Divergence {
    /// The legacy script does not see this violation AT ALL — it reports green where this gate
    /// reports a named failure. Every instance is the zero-is-not-clean rule applied where the
    /// legacy had no equivalent.
    LegacyGreen { reason: String },
    /// The legacy reaches the right VERDICT by crashing rather than by reporting a rule. An
    /// interpreter traceback and a considered refusal leave the same exit code, so without naming
    /// this the harness would read a crashed gate as a gate that ran.
    LegacyCrashes { reason: String },
}

impl Divergence {
    pub fn reason(&self) -> &str {
        match self {
            Divergence::LegacyGreen { reason } | Divergence::LegacyCrashes { reason } => reason,
        }
    }

    /// A declaration shorter than this is a shrug, not a reason.
    pub const MIN_REASON: usize = 40;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    Green,
    Red {
        naming: Vec<String>,
    },
    /// The plant had nothing to plant (the rule's subject is absent from this tree). Visible in the
    /// report and counted — never silently green.
    Skipped,
}

#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    /// The owed row ids this case exercises. Every owed id must be covered by some case.
    pub covers: Vec<String>,
    pub expected: Expect,
    pub got: Expect,
}

impl Case {
    fn failure(&self) -> Option<String> {
        match (&self.expected, &self.got) {
            (Expect::Green, Expect::Green) => None,
            (Expect::Red { naming: want }, Expect::Red { naming: got }) => {
                let missing: Vec<&String> = want
                    .iter()
                    .filter(|w| !got.iter().any(|g| g.contains(w.as_str())))
                    .collect();
                if missing.is_empty() {
                    None
                } else {
                    Some(format!(
                        "{}: went RED but did not name {missing:?} — 'something went red' is not \
                         an accepted answer (reported: {got:?})",
                        self.name
                    ))
                }
            }
            (_, Expect::Skipped) => Some(format!(
                "{}: nothing to plant — the rule's subject is absent from this tree, so the rule \
                 is unproven here rather than passing",
                self.name
            )),
            (want, got) => Some(format!("{}: expected {want:?}, got {got:?}", self.name)),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    cases: Vec<Case>,
    /// Failures that are not about a single case — an unplantable fixture, an unreadable tree.
    infra: Vec<String>,
}

impl Report {
    pub fn new() -> Report {
        Report::default()
    }

    pub fn push(&mut self, case: Case) {
        self.cases.push(case);
    }

    pub fn note_infra_failure(&mut self, msg: impl Into<String>) {
        self.infra.push(msg.into());
    }

    pub fn cases(&self) -> &[Case] {
        &self.cases
    }

    pub fn skipped(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| matches!(c.got, Expect::Skipped))
            .count()
    }

    pub fn failures(&self) -> Vec<String> {
        let mut out = self.infra.clone();
        out.extend(self.cases.iter().filter_map(Case::failure));
        out
    }

    pub fn ok(&self) -> bool {
        self.failures().is_empty()
    }
}

/// Run a gate and reconcile its rows against the owed set it declared. THIS is the only way a gate
/// is judged: a gate never marks itself green.
pub fn execute(gate: &dyn Gate, cx: &Ctx) -> Verdict {
    let verdict = gate.run(cx);
    Reconcile::new(gate.owed()).verdict(verdict.rows)
}

/// The same, with the gate's own narrow skip allowlist.
pub fn execute_with_skips(gate: &dyn Gate, cx: &Ctx, skip_allow: &[&str]) -> Verdict {
    let verdict = gate.run(cx);
    Reconcile::new(gate.owed())
        .allow_skip(skip_allow.iter().copied())
        .verdict(verdict.rows)
}

/// Refuse a report that does not prove the gate. Three refusals, each with its own case in
/// `xtask/tests/infra.rs`:
///
/// * a case that did not do what it expected;
/// * **a gate with no RED proof at all** — `cargo xtask selftest` will not accept it;
/// * an owed row id no case covers, which is the derived-owed-set rule applied to the selftest.
pub fn verify_report(gate: &dyn Gate, report: &Report) -> Result<(), Vec<String>> {
    let mut errs = report.failures();

    if !report
        .cases
        .iter()
        .any(|c| matches!(c.expected, Expect::Red { .. }))
    {
        errs.push(format!(
            "{}: no case in its selftest expects RED, so nothing proves this gate can still fail. \
             A gate without a RED proof is not a gate.",
            gate.name()
        ));
    }

    let covered: BTreeSet<String> = report
        .cases
        .iter()
        .flat_map(|c| c.covers.iter().cloned())
        .collect();
    for owed in gate.owed() {
        if !covered.contains(&owed) {
            errs.push(format!(
                "{}: owed row id `{owed}` is covered by no selftest case — the rule that emits it \
                 could be deleted with the selftest still green",
                gate.name()
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Plant an overlay, run the gate THROUGH `execute`, and require RED naming every string in
/// `naming`. The only way a gate's selftest touches its gate.
pub fn prove_red(
    cx: &Ctx,
    gate: &dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    overlay: Overlay,
    naming: &[&str],
) -> Case {
    let planted = cx.with_overlay(overlay);
    let verdict = execute(gate, &planted);
    let got = if verdict.red {
        Expect::Red {
            naming: reported_text(&verdict),
        }
    } else {
        Expect::Green
    };
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got,
    }
}

/// The red arm, NARROWED TO THE ROWS THE CASE IS ABOUT — the counterpart of [`prove_rows_green`],
/// and the STRONGER of the two proofs.
///
/// [`prove_red`] accepts any RED that names the planted offender, which is exactly right when the
/// gate has three rows. Over a gate with thirty-six, on a tree that carries real debt in some of
/// them, "the gate went red and something in the report said the word" is satisfiable by a row the
/// case is not about. Reading only the covered rows makes the case say what it means: THIS rule
/// went red, and it named the offender that was planted for it.
pub fn prove_rows_red(
    cx: &Ctx,
    gate: &dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    overlay: Overlay,
    naming: &[&str],
) -> Case {
    let planted = cx.with_overlay(overlay);
    let verdict = execute(gate, &planted);
    let reported: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass && covers.contains(&r.id.as_str()))
        .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
        .collect();
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got: if reported.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: reported }
        },
    }
}

/// The green arm, NARROWED TO THE ROWS THE CASE IS ABOUT.
///
/// [`prove_green`] asks whether the WHOLE gate is green, which is the right question for a gate
/// with three rows over a tree that satisfies all three. It is the wrong question for a gate with
/// thirty-six: "a grandfathered file over the cap is not a fresh violation" is a claim about ONE
/// row, and demanding the other thirty-five be clean to make it would hold every case in the file
/// hostage to whatever debt the tree happens to carry today — which is how a selftest ends up
/// deleted rather than fixed.
///
/// So this reads the covered rows and nothing else. It is not a weaker proof of the same claim, it
/// is the proof of a narrower and more honest one, and the row ids it reads are the same ones the
/// case must declare in `covers` anyway.
pub fn prove_rows_green(
    cx: &Ctx,
    gate: &dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    overlay: Overlay,
) -> Case {
    let planted = cx.with_overlay(overlay);
    let verdict = execute(gate, &planted);
    let offenders: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass && covers.contains(&r.id.as_str()))
        .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
        .collect();
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Green,
        got: if offenders.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: offenders }
        },
    }
}

/// The other arm: the unplanted tree must be GREEN, or every RED above proves only that the gate
/// is broken.
pub fn prove_green(cx: &Ctx, gate: &dyn Gate, name: impl Into<String>, covers: &[&str]) -> Case {
    let verdict = execute(gate, cx);
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Green,
        got: if verdict.red {
            Expect::Red {
                naming: reported_text(&verdict),
            }
        } else {
            Expect::Green
        },
    }
}

fn reported_text(verdict: &Verdict) -> Vec<String> {
    let mut out: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass)
        .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
        .collect();
    out.extend(verdict.problems.iter().cloned());
    out
}

pub static REGISTRY: &[Registration] = &[
    Registration {
        name: "denylist",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(denylist_gate::DenylistGate),
        summary: "the pure plugin kinds carry no banned transitive source (ARCHITECTURE.md 1.2)",
    },
    Registration {
        name: "changelog",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(changelog::ChangelogGate::new()),
        summary: "the changelog's grammar, and its newest entry carries a version and a date",
    },
    Registration {
        name: "changelog-register",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(changelog_register::ChangelogRegisterGate::new()),
        summary: "every accepted difference names a changelog line that was actually written",
    },
    Registration {
        name: "ci-umbrella",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(ci_umbrella::CiUmbrellaGate),
        summary: "every job is in the umbrella's needs or excluded for a written reason",
    },
    Registration {
        name: "inventory-ref",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(inventory_ref::InventoryRefGate),
        summary: "every design binding's inventory column names a file that exists",
    },
    Registration {
        name: "qa-gate-dispatch",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(qa_gate_dispatch::QaGateDispatchGate::new()),
        summary: "the dispatcher this branch declares is the dispatcher this branch ships",
    },
    Registration {
        name: "release-order",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(release_order::ReleaseOrderGate),
        summary: "nothing may be tagged until it has been verified from the consumer side",
    },
    Registration {
        name: "service-images",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(service_images::ServiceImagesGate),
        summary: "every container image a workflow or the release harness names is a pinned digest",
    },
    Registration {
        name: "workspace-deps",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(workspace_deps::WorkspaceDepsGate),
        summary: "every crate dependency goes through the workspace table",
    },
    Registration {
        name: "plane-purity",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(plane_purity::PlanePurityGate),
        summary:
            "no side channel in the neutral crates, no backwards reach, core names no LLM family",
    },
    Registration {
        name: "plane-purity-strict",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(plane_purity::PlanePurityStrictGate),
        summary:
            "test-scope side-channel debt stays under the ceilings in qa/plane-purity-strict.toml",
    },
    Registration {
        name: "segregation",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(segregation::SegregationGate),
        summary: "xtask depends on no product crate and the oracle imports nothing from the tree",
    },
    Registration {
        name: "kernel-token-wire-purity",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(kernel_token_wire_purity::KernelTokenWirePurityGate),
        summary: "the kernel never re-derives a usage token class from a raw provider wire pointer",
    },
    Registration {
        name: "tracing",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(tracing::TracingGate),
        summary: "every #[instrument] span is bound to an explicit Level, set in one place",
    },
    Registration {
        name: "no-self-filed-issues",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(no_self_filed_issues::NoSelfFiledIssuesGate),
        summary: "the repository does not open issues against itself, nor ask for the scope to",
    },
    Registration {
        name: "settings-leak",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(settings_leak::SettingsLeakGate),
        summary: "an admin READ never serves an operator settings bag's values, only its key names",
    },
    Registration {
        name: "response-header",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(response_header::ResponseHeaderGate),
        summary: "every busbar-injected response header is emitted from one config-gated site",
    },
    Registration {
        name: "blocking-ffi",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(blocking_ffi::BlockingFfiGate),
        summary: "a synchronous call into a dlopened plugin never runs on a Tokio worker",
    },
    Registration {
        name: "plane-transport-neutrality",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(plane_transport_neutrality::PlaneTransportNeutralityGate),
        summary: "no voice-transport or media noun reaches the neutral crates",
    },
    Registration {
        name: "plane-abi-neutrality",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(plane_abi_neutrality::PlaneAbiNeutralityGate),
        summary:
            "the plane ABI's hot lane is derived from the taxonomy, not named after a protocol",
    },
    Registration {
        name: "structure-lint",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(structure_lint::StructureLintGate::new()),
        summary: "the code-layout invariants, the choke-point registry and the declaration census",
    },
    Registration {
        name: "field-inventory",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(field_inventory::FieldInventoryGate),
        summary: "every dialect field is enumerated from a schema that carries its provenance",
    },
    Registration {
        name: "no-deferral",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(no_deferral::NoDeferralGate::check()),
        summary: "every deferral marker in shipped source is a floor-checked, expiring waiver",
    },
    Registration {
        name: "no-deferral-strict-done",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(no_deferral::NoDeferralGate::strict_done()),
        summary: "the same, plus: the only surviving waivers are the permanent hot/* fixtures",
    },
    Registration {
        name: "duplex-ws-default-edge",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(duplex_ws_default_edge::DuplexWsDefaultEdgeGate),
        summary: "no WebSocket crate in the default money-path dependency closure",
    },
    Registration {
        name: "teller-steps",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(teller_steps::TellerStepsGate),
        summary: "one cell per Teller step per plane, each with a second verdict over the root leg",
    },
];

pub fn find(name: &str) -> Option<&'static Registration> {
    REGISTRY.iter().find(|r| r.name == name)
}

pub fn names() -> Vec<&'static str> {
    REGISTRY.iter().map(|r| r.name).collect()
}

/// The registered names nearest an unknown one, so `cargo xtask gate <typo>` can say what it meant.
pub fn nearest(name: &str) -> Vec<&'static str> {
    let mut scored: Vec<(usize, &'static str)> = REGISTRY
        .iter()
        .map(|r| (distance(name, r.name), r.name))
        .collect();
    scored.sort();
    scored
        .into_iter()
        .filter(|(d, _)| *d <= 4)
        .map(|(_, n)| n)
        .collect()
}

fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// The human printer.
pub fn print_verdict(name: &str, verdict: &Verdict) {
    for row in &verdict.rows {
        match row.status {
            crate::ledger::Status::Pass => println!("PASS  {:<46} {}", row.id, row.title),
            _ => {
                println!("{}  {:<46} {}", row.status, row.id, row.title);
                println!("      {}", row.detail);
            }
        }
    }
    for problem in &verdict.problems {
        println!("RED   {name}: {problem}");
    }
    println!(
        "{}: {} row(s), {}",
        name,
        verdict.rows.len(),
        if verdict.red { "RED" } else { "green" }
    );
}

pub fn print_rows_tsv(rows: &[Row]) {
    for row in rows {
        println!("{}", row.tsv());
    }
}
