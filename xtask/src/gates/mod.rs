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

pub mod changelog;
pub mod changelog_register;
pub mod ci_umbrella;
pub mod denylist_gate;
pub mod inventory_ref;
pub mod kernel_token_wire_purity;
pub mod no_self_filed_issues;
pub mod qa_gate_dispatch;
pub mod release_order;
pub mod segregation;
pub mod service_images;
pub mod tracing_lint;
pub mod workspace_deps;

use std::collections::BTreeSet;

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

    /// THE OTHER PROOF STYLE: read the legacy script's OWN OUTPUT into the rows this gate would
    /// emit for the same tree, for the conversions whose legacy writes no ledger TSV to compare
    /// against.
    ///
    /// A gate proves parity one of two ways and the two are not interchangeable. A legacy that
    /// writes a `$LEDGER` TSV, or one whose findings can be READ BACK out of its stdout, is
    /// compared ROW AGAINST ROW — that is this method, and it is the stronger claim, because the
    /// only thing a diff can then be about is the offender set. A legacy that prints prose no
    /// translator can key on is compared VERDICT AGAINST VERDICT over planted trees — that is
    /// [`Gate::parity_probes`], where the plants are what stop "both found nothing" from passing
    /// for agreement. A gate may declare both; it may not declare neither and still claim parity.
    ///
    /// `None` — the default — means "this gate's legacy writes a ledger, or is proved by probes";
    /// `cargo xtask gate <name> --parity` then reads `$LEDGER` instead. A translator MUST build its
    /// rows with the same constructor [`Gate::run`] uses, so the only thing that can differ between
    /// the two sides is the offender set, which is the only thing worth comparing.
    fn legacy_rows(&self, _run: &crate::parity::LegacyRun) -> Option<Result<Vec<Row>, String>> {
        None
    }
}

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
        build: || Box::new(tracing_lint::TracingGate),
        summary: "every #[instrument] span is bound to an explicit Level, set in one place",
    },
    Registration {
        name: "no-self-filed-issues",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(no_self_filed_issues::NoSelfFiledIssuesGate),
        summary: "the repository does not open issues against itself, nor ask for the scope to",
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
