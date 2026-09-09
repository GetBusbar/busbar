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

pub mod audit_ledger;
pub mod blocking_ffi;
pub mod changelog;
pub mod changelog_register;
pub mod ci_umbrella;
pub mod config_schema;
pub mod construction;
pub mod denylist_gate;
pub mod design_bindings;
pub mod duplex_ws_default_edge;
pub mod field_inventory;
pub mod inventory_ref;
pub mod kernel_token_wire_purity;
pub mod kind_isolation;
pub mod no_deferral;
pub mod no_self_filed_issues;
pub mod plane_abi_neutrality;
pub mod plane_purity;
pub mod plane_transport_neutrality;
pub mod population;
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
use std::time::Duration;

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

/// THE GATES WHOSE VERDICT IS PRINTED BUT NOT COUNTED BY `--all`, and why that is data here rather
/// than a posture flag somebody remembers.
///
/// Exactly one gate is on this list today and it is not a loophole: the construction gate is RED BY
/// DESIGN on HEAD — rows sit over ceilings the construction work in flight is driving down — and
/// `ci.yml` has run it `continue-on-error` with the verdict printed by the umbrella since it was
/// written, while `qa/full-gate.toml` names it in its skip list for the same reason. That posture
/// existed in prose, in two files, with nothing in the runner that knew about it; a converted gate
/// that simply joined `--all` would have turned the whole local gate red on a fact CI does not
/// score. So it says out loud, next to the registry, what those two comments say: this one is
/// reported, not counted, until it is flipped.
///
/// A report-only gate is still fully reconciled, still self-tested and still exits non-zero when
/// run BY NAME (`cargo xtask gate construction`), which is what the CI job captures. This governs
/// one thing only: whether `--all` adds it to the red list.
const REPORT_ONLY: &[&str] = &["construction"];

impl Registration {
    /// Does this gate's verdict COUNT under `--all`, or is it printed and not scored?
    pub fn blocking(&self) -> bool {
        !REPORT_ONLY.contains(&self.name)
    }
}

pub trait Gate {
    fn name(&self) -> &'static str;

    /// Every ledger row id this gate can emit. THE OWED SET. Non-empty by construction: a gate
    /// that owes nothing has nothing anybody reconciles.
    fn owed(&self) -> Vec<String>;

    /// The narrow set of owed ids whose SKIP is not RED. EMPTY BY DEFAULT, and it should stay that
    /// way for almost every gate: a check that could not run is unreachable for users too.
    ///
    /// One gate needs it, and needs it to be DATA rather than a posture flag: the design bindings
    /// ledger's plain form reports a NAMED gap without turning the run red, and the name is the
    /// point — the allowlist is exactly the bindings the committed ledger records as `unmapped`, a
    /// file somebody edits and a reviewer reads. [`execute_strict`] runs the same rows with no
    /// allowlist at all, which is what makes "DONE means no gap" a claim rather than a hope.
    fn skip_allow(&self) -> Vec<String> {
        Vec::new()
    }

    /// The narrow set of owed ids that are PASS BY CONSTRUCTION — a measurement the gate reports
    /// and does not judge. EMPTY BY DEFAULT, and it must stay that way for anything that is a rule.
    ///
    /// One gate needs it. The construction gate reports `duplicate-dispatch` and the
    /// `forbid-unsafe:<crate>` rows of crates on its `known_missing_*` debt list as `Pass` however
    /// they measure: the first is a shape report with no threshold, and a ratcheted `forbid-unsafe`
    /// row measures 1 against a ceiling of 1, so no plant can drive it red. Demanding a RED case
    /// for a row that cannot be RED cannot be met honestly, and the two dishonest ways to meet it —
    /// hand-writing the case's `got`, or making the row judge something it does not — are both
    /// worse than saying which rows they are.
    ///
    /// THE LIST ONLY EVER SHRINKS BY ARGUMENT. The three `legacy-reach:<crate>` rows were on it,
    /// with a written reason, and the reason was wrong: it let one of them sit twenty-one over its
    /// own figure, passing, for as long as the gating total held. They gate now.
    ///
    /// WHAT IS AND IS NOT GIVEN UP. This never touches a verdict: unlike [`Gate::skip_allow`] it is
    /// read only by [`verify_report`], so a declared row that somehow went FAIL would still turn
    /// the gate red. What it gives up is the RED half of the coverage proof, and only that — the
    /// row must still be exercised by SOME case, and deleting the rule that emits it is still
    /// caught on every run, by the reconciliation, as DID NOT RUN. The RED demand exists to catch a
    /// rule that is GUTTED rather than deleted — one that still emits its row and always passes —
    /// and for a row that always passes by design there is nothing left for it to catch.
    fn informational(&self) -> Vec<String> {
        Vec::new()
    }

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

    /// Fold another report's cases and infra failures into this one, for a gate whose selftest is
    /// assembled from per-rule sub-reports rather than written as one list.
    pub fn append(&mut self, other: Report) {
        self.cases.extend(other.cases);
        self.infra.extend(other.infra);
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
    Reconcile::new(gate.owed())
        .allow_skip(gate.skip_allow())
        .verdict(verdict.rows)
}

// ---------------------------------------------------------------------------------------------
// the wall-clock ceiling
// ---------------------------------------------------------------------------------------------

/// How long any one gate may take before the runner stops believing it.
///
/// FIVE MINUTES IS A CEILING, NOT A BUDGET. The slowest converted gate reads the whole tree and
/// finishes in seconds; a gate that has been running for five minutes is not slow, it is stuck,
/// and every minute after that is a minute the run spends proving nothing.
pub const DEFAULT_GATE_CEILING: Duration = Duration::from_secs(300);

/// The ceiling for one gate: the default, a global override, then a per-gate override. `None`
/// means the ceiling is off, which `0` asks for.
///
/// It is read from the ENVIRONMENT rather than compiled in per gate, because the box that needs a
/// bigger number is never the box the number was written on — a cold CI runner building from
/// scratch is not a warm laptop. `XTASK_GATE_CEILING_SECS` moves them all;
/// `XTASK_GATE_CEILING_SECS_<GATE>` (the gate's name, uppercased, `-` becoming `_`) moves one.
///
/// `env` is a parameter and not a direct `std::env::var` call so the precedence can be PROVEN
/// without a test mutating the process environment out from under its neighbours.
pub fn ceiling_for(name: &str, env: impl Fn(&str) -> Option<String>) -> Option<Duration> {
    let key = format!(
        "XTASK_GATE_CEILING_SECS_{}",
        name.to_uppercase().replace(['-', '.', '/'], "_")
    );
    let raw = env(&key).or_else(|| env("XTASK_GATE_CEILING_SECS"));
    match raw {
        None => Some(DEFAULT_GATE_CEILING),
        // An unreadable override is the DEFAULT, never "no ceiling": a typo in an environment
        // variable must not be the thing that lets a hung gate hang forever again.
        Some(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => Some(DEFAULT_GATE_CEILING),
        },
    }
}

/// The ceiling as the runner reads it, from the real process environment.
pub fn ceiling_from_env(name: &str) -> Option<Duration> {
    ceiling_for(name, |k| std::env::var(k).ok())
}

/// [`execute`], UNDER A WALL-CLOCK CEILING. A gate that exceeds it is RED, with `hung` in every
/// owed row, and the run CONTINUES.
///
/// WHY THE RUNNER OWNS THIS. `cargo xtask gate --all` once sat for 43 minutes at 4% CPU: a gate
/// had deadlocked against a `git cat-file --batch` child, and because the runner simply called the
/// gate and waited, the whole gate set stopped at that row — not red, not green, not printed.
/// SILENTLY PENDING IS THE WORST VERDICT A GATE RUNNER CAN GIVE, because it is indistinguishable
/// from slow work and it is the one verdict nobody can act on. The particular deadlock is fixed in
/// [`crate::gitp::ask`]; this is the guard that means the NEXT one costs a red row and five
/// minutes instead of a night.
///
/// The gate is built and run on its own thread, so the ceiling is a real wall clock and not a
/// cooperative check the hung gate would have to reach in order to notice. A gate that blows the
/// ceiling is LEAKED: it is wedged in a syscall, there is nothing to cancel, and a `join` here
/// would reintroduce exactly the hang this exists to end. It dies with the process.
pub fn execute_within(
    name: &str,
    build: fn() -> Box<dyn Gate>,
    cx: &Ctx,
    ceiling: Duration,
) -> Verdict {
    let owed = build().owed();
    let (tx, rx) = std::sync::mpsc::channel();
    let mine = cx.clone();
    std::thread::spawn(move || {
        let gate = build();
        let _ = tx.send(execute(gate.as_ref(), &mine));
    });
    match rx.recv_timeout(ceiling) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => hung(name, &owed, ceiling),
        // The sender is gone without a verdict: the gate PANICKED. That is red too, and for the
        // same reason — nobody may read a missing verdict as a passing one.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Verdict::of(
            owed.iter()
                .map(|id| {
                    Row::fail(
                        id.clone(),
                        format!("{name} panicked"),
                        "the gate thread died without a verdict".to_string(),
                    )
                })
                .collect(),
        ),
    }
}

/// Every owed row, RED, saying it hung. Not one summary row: a caller grepping the ledger for a
/// row id must find that row failing rather than find nothing at all.
fn hung(name: &str, owed: &[String], ceiling: Duration) -> Verdict {
    let rows = owed
        .iter()
        .map(|id| {
            Row::fail(
                id.clone(),
                format!("{name} hung"),
                format!(
                    "hung: the gate did not finish within {}s (XTASK_GATE_CEILING_SECS[_{}] \
                     raises it, 0 disables it)",
                    ceiling.as_secs(),
                    name.to_uppercase().replace(['-', '.', '/'], "_")
                ),
            )
        })
        .collect();
    Verdict::of(rows)
}

/// The ceiling for the paths that do not run the gate on a thread of their own — `gate <name>`
/// and `gate <name> --selftest`, where the gate is built with flags a `fn()` pointer cannot carry.
///
/// It cannot return a verdict, because the thread that would print one is the wedged one. So it
/// PRINTS the red rows and takes the process down with a non-zero status: a hung single-gate run
/// ends in a refusal a human and a CI step both understand, rather than in a job timeout that
/// names nothing. Dropping it disarms it.
///
/// IT IS OFF UNTIL THE BINARY TURNS IT ON, and that is not timidity. `cargo test -p xtask` calls
/// [`crate::cli::main`] in-process, so an armed watchdog in a library caller would answer a slow
/// gate by killing the TEST HARNESS — every other case in the binary lost, no report, exit 1 with
/// nothing to read. A test process must report its own failures. `xtask`'s `main` calls
/// [`enable_process_watchdog`]; nothing else does.
pub struct Watchdog {
    disarm: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

static PROCESS_WATCHDOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Let [`Watchdog::arm`] do anything at all. Called by the `xtask` BINARY and by nothing else.
pub fn enable_process_watchdog() {
    PROCESS_WATCHDOG.store(true, std::sync::atomic::Ordering::SeqCst);
}

impl Watchdog {
    pub fn arm(name: &str, owed: Vec<String>, ceiling: Option<Duration>) -> Watchdog {
        let disarm = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ceiling =
            ceiling.filter(|_| PROCESS_WATCHDOG.load(std::sync::atomic::Ordering::SeqCst));
        if let Some(ceiling) = ceiling {
            let flag = std::sync::Arc::clone(&disarm);
            let name = name.to_string();
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + ceiling;
                while std::time::Instant::now() < deadline {
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let verdict = hung(&name, &owed, ceiling);
                print_verdict(&name, &verdict);
                eprintln!("cargo xtask gate {name}: hung -- killed at its wall-clock ceiling");
                std::process::exit(1);
            });
        }
        Watchdog { disarm }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.disarm.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The same, with the gate's own skip allowlist REFUSED. `cargo xtask gate <name> --strict` is
/// this: every owed row must have run and passed, and a named gap is red like any other SKIP.
pub fn execute_strict(gate: &dyn Gate, cx: &Ctx) -> Verdict {
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
///
/// COVERAGE IS COUNTED FROM THE RED CASES ONLY. A green case names the rows it expects to stay
/// quiet; it cannot distinguish a rule that ran and found nothing from a rule that is not there at
/// all, so a green case's `covers` list is not a proof that the rule can still fail. Counting it
/// as one is how a whole-tree `prove_green` naming the entire owed set discharges the coverage
/// check for rules with no RED proof anywhere — and those rules are then deletable with
/// `cargo xtask selftest` still green, which is the one thing this function exists to refuse.
///
/// The single exception is DECLARED, NAMED and stale-checked: [`Gate::informational`] rows are
/// PASS by construction, so they are held to being exercised rather than to going red, and a
/// declaration that no longer names an owed row is itself refused.
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
        .filter(|c| matches!(c.expected, Expect::Red { .. }))
        .flat_map(|c| c.covers.iter().cloned())
        .collect();
    let exercised: BTreeSet<String> = report
        .cases
        .iter()
        .flat_map(|c| c.covers.iter().cloned())
        .collect();
    let owed: Vec<String> = gate.owed();
    let informational: BTreeSet<String> = gate.informational().into_iter().collect();

    // A declaration that no longer names an owed row is a waiver that outlived what it excused,
    // and it is refused for the same reason every other stale waiver in this tree is.
    for id in &informational {
        if !owed.contains(id) {
            errs.push(format!(
                "{}: `{id}` is declared informational but is not an owed row id — an exemption \
                 that names nothing is a line nobody re-reads",
                gate.name()
            ));
        }
    }

    for owed in owed {
        if informational.contains(&owed) {
            if !exercised.contains(&owed) {
                errs.push(format!(
                    "{}: owed row id `{owed}` is declared informational and is exercised by no \
                     case at all — a row that cannot go RED must at least be measured by one",
                    gate.name()
                ));
            }
            continue;
        }
        if !covered.contains(&owed) {
            errs.push(format!(
                "{}: owed row id `{owed}` is covered by no RED selftest case — a green case cannot \
                 tell a rule that found nothing from a rule that is not there, so the rule that \
                 emits this row could be deleted with the selftest still green",
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

/// THE EVIDENCE FOR ONE ROW, and nothing else in the verdict.
///
/// A row goes red in two shapes and both are this row going red: a non-PASS row carrying the id, or
/// a reconciler problem about THAT id — `DID NOT RUN`, `SKIP`, `CONFLICT`. The second shape is why
/// this is not simply a row filter: a plant that stops the gate from emitting the row at all is the
/// strongest red there is for that row, and reading only `verdict.rows` would score it GREEN.
fn evidence_for(verdict: &Verdict, id: &str) -> Vec<String> {
    let mut out: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.id == id && r.status != crate::ledger::Status::Pass)
        .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
        .collect();
    let prefix = format!("{id}: ");
    out.extend(
        verdict
            .problems
            .iter()
            .filter(|p| p.starts_with(&prefix))
            .cloned(),
    );
    out
}

/// THE RED ROWS MUST COVER THE CASE'S `covers` SET, or the case proved nothing it claimed.
///
/// `Expect::Green` here means "this case's rules did not go red", whatever else in the gate did.
/// An empty `covers` is refused the same way: a red case that names no row is a red nobody can
/// attribute, and `verify_report` counts its (empty) claim as coverage of nothing.
fn narrowed_got(verdict: &Verdict, covers: &[&str]) -> Expect {
    if covers.is_empty() {
        return Expect::Green;
    }
    let mut evidence = Vec::new();
    for id in covers {
        let for_id = evidence_for(verdict, id);
        if for_id.is_empty() {
            return Expect::Green;
        }
        evidence.extend(for_id);
    }
    Expect::Red { naming: evidence }
}

/// Plant an overlay, run the gate THROUGH `execute`, and require RED naming every string in
/// `naming`. The only way a gate's selftest touches its gate.
///
/// THE RED IS READ OFF THE COVERED ROWS ONLY. It used to be enough that the gate went red and
/// that something anywhere in its report said the word: over a gate with thirty-six rows, on a tree
/// that carries real debt in some of them, that is satisfiable by a row the case is not about — so a
/// case could "prove" rule X while rule Y was what went red, and X was then deletable with `cargo
/// xtask selftest` still green. Now every id in `covers` must itself be red, which makes this
/// function and [`prove_rows_red`] the same proof; the latter survives as the name that says so at
/// the call site.
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
    let got = narrowed_got(&verdict, covers);
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
    Case {
        name: name.into(),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got: narrowed_got(&verdict, covers),
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

/// The tree in which `crates/` is present, readable and holds a file, and NO plane declares its
/// grammar. It is the plant for every `plane-roots` row: the scanners that share the plane
/// resolver read it with `std::fs`, so this is the only way to make a plane genuinely absent.
pub const PLANE_ROOT_MISSING_FIXTURE: &str = "xtask/fixtures/plane-root-missing";

/// The red arm for a rule whose subject is read OUTSIDE the overlay — narrowed to its rows, and
/// driven over a fixture tree the gate is re-rooted onto.
///
/// Some inputs are resolved from the real filesystem before any overlay can reach them: the plane
/// resolver walks `crates/` with `std::fs`, so `Overlay::remove` cannot make a plane vanish. The
/// answer is not to hand-write the case's `got` — that is a case with the gate taken out of it,
/// and it passes just as happily when the rule it names has been deleted. The answer is to point
/// a whole `Ctx` at a tree where the subject really is absent and run `execute` there.
pub fn prove_rows_red_at(
    cx: &Ctx,
    gate: &dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    fixture_rel: &str,
    naming: &[&str],
) -> Case {
    let name = name.into();
    let expected = Expect::Red {
        naming: naming.iter().map(|s| (*s).to_string()).collect(),
    };
    let covers_owned: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let Ok(fixture_cx) = Ctx::at(cx.abs(fixture_rel), cx.scratch()) else {
        return Case {
            name,
            covers: covers_owned,
            expected,
            got: Expect::Skipped,
        };
    };
    let verdict = execute(gate, &fixture_cx);
    Case {
        name,
        covers: covers_owned,
        expected,
        got: narrowed_got(&verdict, covers),
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
        name: "construction",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(construction::ConstructionGate),
        summary: "how the tree is BUILT, against ARCHITECTURE.md and qa/construction.toml",
    },
    Registration {
        name: "design-bindings",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(design_bindings::DesignBindingsGate),
        summary: "every ARCHITECTURE.md Appendix B binding cites a check that compares something",
    },
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
        name: "kind-isolation",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(kind_isolation::KindIsolationGate::check()),
        summary: "the ~10 plugin kinds never cross-contaminate: no name, edge or word fuses two",
    },
    Registration {
        name: "kind-isolation-ship",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(kind_isolation::KindIsolationGate::ship()),
        summary: "the same, plus the ship criterion: one surface per kind, one battery per kind",
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
    Registration {
        name: "config-schema",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(config_schema::ConfigSchemaGate),
        summary:
            "the config grammar is frozen at 1.5.3: snapshot drift plus additive-only vs a git ref",
    },
    Registration {
        name: "audit-ledger",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(audit_ledger::AuditLedgerGate),
        summary: "every tracked file is in a scope, and no audit result outlives the tree it read",
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
