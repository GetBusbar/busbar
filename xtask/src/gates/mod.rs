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
pub mod ship_ready;
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

/// THE GATES WHOSE VERDICT `--all` PRINTS AND DOES NOT COUNT, each with a written reason AND the
/// fact that reason turns on.
///
/// THIS LIST WAS ONE NAME AND A COMMENT, AND THAT COST THE ONE SIGNAL IT PROTECTS.
/// `cargo xtask gate --all` exited 1 on a clean tree — `RED in design-bindings,
/// kind-isolation-ship` — because both are red on HEAD for reasons nothing here knew about.
/// `.github/workflows/keep-proof.yml` runs exactly that command with no `continue-on-error`, and
/// `ci.yml` does not run on `keep-**` at all, so keep-proof is the ONLY judge of an agent
/// hand-back and its gate job was permanently red: a real regression on a keep branch was
/// indistinguishable from the standing red. Two excuse vocabularies existed — this one, and
/// `full_gate`'s [`crate::full_gate::REGISTRY_NOT_IN_CI`], which knew about `kind-isolation-ship`
/// and checks its claim against the tree — and `--all` read the wrong one.
///
/// So there is one vocabulary now, and every entry carries an [`Excused`] that is CHECKED on the
/// run. An entry whose fact no longer holds excuses nothing: the gate is scored, exactly as if the
/// entry had never been written. `--all` prints the excuse it applied on every run, so a red that
/// was not counted is never a red that was not mentioned.
///
/// An excused gate is still fully reconciled, still self-tested, and still exits non-zero when run
/// BY NAME (`cargo xtask gate construction`), which is what the CI job captures. This governs one
/// thing: whether `--all` adds it to the red list.
pub const REPORT_ONLY: &[Posture] = &[
    Posture {
        name: "construction",
        why: "RED BY DESIGN on HEAD while the construction work it measures is in flight — but \
              red about a NAMED, FINITE list of rows and nothing else",
        excuse: Excused::OnlyRows(CONSTRUCTION_STANDING_REDS),
    },
    Posture {
        name: "kind-isolation-ship",
        why: "the SHIP-criterion twin of kind-isolation. Its enforceable rows run on every push \
              under `kind-isolation`; the ones it adds are a claim about the SHIP SHA and are RED \
              on HEAD by design. It is a release-time gate, and full_gate's own excuse table is \
              where that claim is written down and checked.",
        excuse: Excused::ReleaseTime,
    },
    Posture {
        name: "ship-ready",
        why: "THE SHIP CRITERION, and the integration line is not the ship SHA. Every one of its \
              rows is a claim about a tree that is ready to promote — the twin at zero, the \
              ceilings tight, nothing standing red, the mutants caught — and this tree is \
              deliberately none of those things yet. It is a REQUIRED CHECK on `qa` and `main`, \
              which is where the claim is meant to bite and where branch protection scores it; \
              `--all` on the dev line is not. Same standing as the ship twin it reads.",
        excuse: Excused::ReleaseTime,
    },
    Posture {
        name: "design-bindings",
        why: "PB-0 cites `scripts/inventory-coverage.sh`, and that file is not in this tree — the \
              shell retired without the gate being converted, so the binding names a check that \
              settles nothing. That is a real finding and it is why the gate is red BY NAME. It is \
              not a finding `--all` can act on, and it is the only one: this excuse holds ONLY \
              while every non-PASS row of the gate names that absent path, so a design binding \
              that breaks for any other reason is scored here like any other red.",
        excuse: Excused::OnlyAbout("scripts/inventory-coverage.sh"),
    },
];

/// THE CONSTRUCTION GATE'S STANDING REDS, BY NAME.
///
/// `Excused::Whole` used to cover this gate: no fact-check, no expiry, no list. `gate --all` exited
/// 0 however red construction got, and a real regression landing on a keep branch was
/// indistinguishable from the standing red — which is the exact failure the header above this list
/// describes happening once already, to `design-bindings` and `kind-isolation-ship`.
///
/// So the excuse names its rows. A construction red that is NOT on this list is scored like any
/// other gate's, and a name on this list that is no longer red is STALE and also scores — otherwise
/// the list would only ever grow, and a list that only grows is the blanket excuse it replaces.
/// Draining a row means striking its name here in the same commit, which is the transaction the
/// whole gate exists to force.
///
/// Keep in step with `land_construction_standing_reds` in scripts/land.sh, which subtracts the same
/// rows so that every landing can run the gate over EVERY row instead of a caller-chosen few.
///
/// `ceiling-rose` is on this list for one reason only: the stale `[gate.ceiling_raises]` 26 -> 47
/// entry in qa/construction.toml, which is being struck separately. STRIKE THIS NAME ON THE SAME
/// COMMIT that strikes that entry — the stale-name check above will red until you do, which is the
/// point.
pub const CONSTRUCTION_STANDING_REDS: &[&str] = &[
    // The scan-set floor added 2026-09-09 scores an absent subject RED instead of PASS, and this
    // row is what it caught: a rule claiming "a cancellation-token check precedes every `.await` in
    // the route step" that found no `.await` in scope at all, and passed on that basis.
    "hold-discipline:cancellation-before-await",
    "hold-escapes",
    "kernel-seal-impls",
    "one-pick-site",
    "one-pricing-site:fee-fields",
    "plane-no-money",
    "ports-only-tests:busbar-llm",
    "request-path-fn-size",
    "terminal-doors-in-audit-step",
];

/// One entry of [`REPORT_ONLY`].
pub struct Posture {
    pub name: &'static str,
    pub why: &'static str,
    pub excuse: Excused,
}

/// The fact a posture rests on, checked on the run that relies on it.
pub enum Excused {
    /// The whole gate is reported, not scored, and the reason is about the gate rather than about
    /// any one of its rows.
    Whole,
    /// It is a RELEASE-TIME claim, and [`crate::full_gate::REGISTRY_NOT_IN_CI`] is where that is
    /// written down. The entry must still be there AND its own `Excuse` must still hold — a gate
    /// whose release script stopped invoking it is a gate nothing runs, and excusing it here would
    /// be the second vocabulary drifting from the first all over again.
    ReleaseTime,
    /// The gate is red about ONE known thing and nothing else. Every non-PASS row, and every
    /// reconciliation problem, must name this needle; one that does not is a red this excuse was
    /// not written for, and the gate is scored.
    OnlyAbout(&'static str),
    /// The gate is red about a NAMED, FINITE set of rows and nothing else.
    ///
    /// The `OnlyAbout` treatment for a gate whose standing reds have no single needle in common.
    /// It fails the excuse in BOTH directions, and the second is the one that gives it an expiry:
    ///
    /// * a non-PASS row (or a reconciliation problem) this list does not name is a NEW red, and the
    ///   gate is scored — which is the whole signal `Excused::Whole` threw away;
    /// * a name on this list that is NOT red any more is a STALE entry, and the gate is scored for
    ///   that too. Without it the list only ever grows and drifts back into being a blanket.
    OnlyRows(&'static [&'static str]),
}

/// Why `--all` did not count this gate's red, or `None` if it must count it.
///
/// Called only when the verdict IS red, and it never softens a green.
pub fn excused_from_all(name: &str, cx: &Ctx, verdict: &Verdict) -> Option<String> {
    let p = REPORT_ONLY.iter().find(|p| p.name == name)?;
    match &p.excuse {
        Excused::Whole => Some(p.why.to_string()),
        Excused::ReleaseTime => {
            let (_, reason, excuse) = crate::full_gate::REGISTRY_NOT_IN_CI
                .iter()
                .find(|(n, _, _)| *n == name)?;
            excuse.holds(cx).ok()?;
            Some(format!(
                "{} — full_gate's excuse still holds: {reason}",
                p.why
            ))
        }
        Excused::OnlyAbout(needle) => {
            // THE ROWS FIRST, THEN THE RECONCILIATION'S OWN LINES. A reconciler problem is
            // `"<id>: <what>"` and carries none of the row's detail, so matching the needle
            // against its text would score every excused row a second time. A problem is explained
            // exactly when the row it names is — and a problem about a row that emitted nothing at
            // all (`DID NOT RUN`) names no explained id and is therefore never excused, which is
            // the right answer: a rule that stopped running is not a rule that is red for a known
            // reason.
            let explained: BTreeSet<&str> = verdict
                .rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass && r.detail.contains(needle))
                .map(|r| r.id.as_str())
                .collect();
            let mut unexplained: Vec<String> = verdict
                .rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .filter(|r| !explained.contains(r.id.as_str()))
                .map(|r| format!("{} {}", r.id, r.detail))
                .collect();
            unexplained.extend(
                verdict
                    .problems
                    .iter()
                    .filter(|t| !explained.iter().any(|id| t.starts_with(&format!("{id}: "))))
                    .cloned(),
            );
            if unexplained.is_empty() {
                Some(format!("{} — every red row names `{needle}`", p.why))
            } else {
                None
            }
        }
        Excused::OnlyRows(named) => {
            // A row that emitted nothing at all reaches the verdict as a reconciliation problem
            // (`"<id>: … DID NOT RUN"`), never as a row, so the named ids are matched against both.
            // A rule that stopped running is not a rule that is red for a known reason: a problem
            // about an id this list does not name fails the excuse exactly like a new red row.
            let red_now: BTreeSet<&str> = verdict
                .rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .map(|r| r.id.as_str())
                .collect();

            let mut unexplained: Vec<String> = verdict
                .rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .filter(|r| !named.contains(&r.id.as_str()))
                .map(|r| format!("NEW RED {} {}", r.id, r.detail))
                .collect();
            unexplained.extend(
                verdict
                    .problems
                    .iter()
                    .filter(|t| !named.iter().any(|id| t.starts_with(&format!("{id}: "))))
                    .map(|t| format!("NEW RED {t}")),
            );
            // THE EXPIRY. A named row that is green again is a list that has outlived its facts.
            unexplained.extend(
                named
                    .iter()
                    .filter(|id| {
                        !red_now.contains(*id)
                            && !verdict
                                .problems
                                .iter()
                                .any(|t| t.starts_with(&format!("{id}: ")))
                    })
                    .map(|id| {
                        format!(
                            "STALE `{id}` is named as a standing red and is not red any more — \
                             strike it from CONSTRUCTION_STANDING_REDS (and from \
                             land_construction_standing_reds in scripts/land.sh)"
                        )
                    }),
            );

            if unexplained.is_empty() {
                Some(format!(
                    "{} — red on exactly the {} named standing row(s) and nothing else",
                    p.why,
                    named.len()
                ))
            } else {
                for u in &unexplained {
                    eprintln!("  construction posture: {u}");
                }
                None
            }
        }
    }
}

impl Registration {
    /// Does this gate's verdict COUNT under `--all` WHATEVER it says? A gate with a posture entry
    /// still counts unless the entry's fact holds on this run — see [`excused_from_all`].
    pub fn has_posture(&self) -> bool {
        REPORT_ONLY.iter().any(|p| p.name == self.name)
    }
}

/// TWO GUARDS, ONE RUNNER, AND THEY ARE NOT THE SAME GUARD.
///
/// [`execute_within`] and [`Watchdog`] are the HANG guard: a wall-clock ceiling, five minutes by
/// default, per gate RUN, tunable from the environment because the box that needs a bigger number
/// is never the box the number was written on. Its finding says `hung: the gate did not finish
/// within Ns`, and what it is about is a gate that has stopped making progress at all.
///
/// The budget below is the REGRESSION guard: it is about a self-test that still finishes and has
/// quietly become ten times more expensive, which no ceiling can see because every individual run
/// is still under it. Its finding says `spent N work units against a budget of M`. Neither
/// subsumes the other — a hang blows the ceiling and never reaches the budget; a regression that
/// triples the shard never blows the ceiling — so both are red, separately, with messages a reader
/// can tell apart.
///
/// THE SELF-TEST BUDGET, AND WHY IT IS NOT MEASURED IN SECONDS.
///
/// `cargo test -p xtask` runs `xtask selftest`, which drives EVERY registered gate's cases. That is
/// the only place several of these gates are ever proven RED-able, so the shard cannot simply be
/// made smaller -- and it grew past fifty-one minutes, on a runner whose ssh session dies at about
/// fifty and whose gate job was cancelled at twenty-five. Nothing measured it. A rule that grew a
/// whole-tree scan per plant looked exactly like one that did not, right up to the point where the
/// job was killed and the verdict was "cancelled", which is neither green nor red.
///
/// A WALL-CLOCK BUDGET WAS TRIED FIRST AND IS WRONG, and the measurement that says so was taken in
/// this repository: `cargo test -p xtask` runs the lib tests and the integration tests
/// CONCURRENTLY, and several of them drive whole gates, so a case that costs 4 seconds alone costs
/// 23 under the shard's own contention. Fifty-four budgets fired, on a tree with no regression in
/// it. A gate that is red because the machine was busy is a gate somebody deletes.
///
/// So the budget is denominated in WORK UNITS: [`work_unit`] times a fixed, deterministic piece of
/// arithmetic once per process, and every budget is a multiple of that. A box four times slower, or
/// four times more contended, produces a calibration four times slower too, and the ratio the
/// budget is about survives both. It is not a perfect proxy -- the calibration is arithmetic and
/// the gates are regex and I/O -- which is exactly why the multiples carry roughly twice the
/// measured cost rather than a tight fit. The failure being caught is a factor of ten.
///
/// THE BUDGET IS ON THE GATE'S TOTAL, not on one case. A rule that grew a whole-tree scan makes
/// EVERY case slower by the same factor, so a per-case limit would have to be set high enough to
/// pass the slowest legitimate case and would then miss the uniform regression that actually costs
/// the shard its hour. The slowest case is printed beside the total, because that is what a reader
/// needs in order to act on it.
/// Everything not named below. The most expensive gate that is NOT named measured 2 811 units, so
/// this is about three times the dearest ordinary self-test in the registry.
const DEFAULT_BUDGET_UNITS: f64 = 9000.0;

/// The gates whose self-tests legitimately cost more, each with its MEASURED cost and the reason.
/// An entry for a gate that is no longer registered is refused by `gates::posture_tests`.
///
/// Every number is about three times what the gate measured on the host this table was calibrated
/// on. Three, not one-point-two, for two reasons: the ruler is arithmetic and the gates are regex
/// and I/O, so the proxy drifts a little with the machine; and the failure being caught is a rule
/// that grew a whole-tree scan per plant, which is a factor of ten. A budget tight enough to flap
/// is a budget somebody raises without reading it.
const SELFTEST_BUDGETS: &[(&str, f64, &str)] = &[
    (
        "plane-purity",
        80000.0,
        "25 792 units measured, the dearest self-test in the registry by a factor of two. Not analysed here; the entry is the measurement, written down so that a doubling is a red row rather than four minutes nobody attributes. It is the first name on the shard's own drain list.",
    ),
    (
        "plane-purity-strict",
        45000.0,
        "13 959 units measured, the ratcheted twin of plane-purity and the second name on the same drain list. Not analysed here either.",
    ),
    (
        "structure-lint",
        22000.0,
        "6 914 units measured. One gate over a dozen rule families, each with its own planted tree, and the census walks the whole workspace.",
    ),
    (
        "audit-ledger",
        22000.0,
        "6 552 units measured, down from 7 868 once the reachability rule stopped forking a `merge-base` per record per pin. What is left is `ls-tree` and `cat-file` per planted register, which is the instrument reading the repository rather than the register.",
    ),
    (
        "construction",
        50000.0,
        "about 15 600 units: thirty-six rules over a 660k-line tree, thirty cases, the plants grouped by family so one case carries every edit a family needs. The file scan is memoised; what is left is the rules themselves.",
    ),
    (
        "kind-isolation",
        310000.0,
        "102 581 units measured over 126 cases, up from 86 069 over 107 when the VAULT DOOR round-two LOCK landed: the compiled set held against the scanned set (every `mod`/`#[path]` resolved to the file the compiler opens, and a `git check-ignore` hit on one reported in its own words), `include!` on the marker list with its argument read across lines and either resolved or refused, the build script held to the DIRECTORY rather than to the name, the entry face read as TOKENS so a `use … as` rename and a rustfmt-wrapped header are the same implementation, and a case for each of the ten registry-parser refusals a mutation campaign found unproven. Nineteen cases for about nineteen per cent more work: the new source-side rules lex every line of every file, which is why the per-file compiled set is memoised on (path, bytes) exactly as `matrix.rs` memoises its scan. Before that: 86 069 over 107, up from 79 594 over 88 when the round-two rules landed: the merge-base provenance of the ledger (a `[[dep]]` row may RECORD a not-allowed edge and never INTRODUCE one; a minted `[[cell]]` is a 0 -> N raise), the census refusals that fail closed, and the manifest reader's own unreadable-line report. Nineteen cases for about eight per cent more work, which is the shape a battery grows in when the new rules read history rather than the tree: the merge-base is read ONCE per process and memoised, so the cost is the plants, not the git. Before that: up from 19 500 when the dependency side landed -- eleven rows rather than eight, and a plant that ADDS OR REMOVES A CRATE changes the derived vocabulary and invalidates the matrix memo, which thirty of those cases do, because a census that walks the whole repository is proven by planting crates in it.",
    ),
    (
        "kind-isolation-ship",
        320000.0,
        "107 600 units projected over 122 cases when the VAULT DOOR round-two LOCK part five landed: the seven ship cases it adds are the three derivations with a degenerate answer (`no-exemplar`, `no-entry`, `no-battery`) and the four floors whose subject is the size of their own input (`:shape` and `:testkit` reaching no crate, `:control-path` reaching no surface, and the source index below MIN_SOURCES), plus the shared-arm `plane-names-dialect` case. TWO MEASUREMENTS, BOTH ON A CONTENDED HOST, and the spread between them is the entry: the base commit measured 100 557 units over 114 cases (882/case) and this tree measured 83 595 over 122 (685/case) with two other agents' selftests on the same four cores. The ruler is arithmetic in-process and the gates are I/O, so heavy contention moves the two apart rather than together, and a budget written off the LOWER reading is a budget that flaps the first time the machine is quiet. So the number written down is the HIGHER per-case rate carried across the new case count -- 882 x 122 ~ 107 600 -- and the budget is three times it. Before that: 94 236 units measured over 104 cases, up from 80 289 over 86 when the round-two LOCK landed.",
    ),
];

/// One WORK UNIT: how long THIS process takes to run a fixed piece of arithmetic, measured once.
///
/// Deterministic and dependency-free on purpose. It is not a benchmark of anything a gate does; it
/// is a ruler that shrinks and stretches with the machine and its load, which is the only property
/// a budget compared against it needs.
pub fn work_unit() -> std::time::Duration {
    static UNIT: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *UNIT.get_or_init(ruler_once)
}

/// The fixed arithmetic, once, on this thread.
fn ruler_once() -> std::time::Duration {
    let t = std::time::Instant::now();
    let buf: Vec<u8> = (0..1u32 << 16).map(|i| (i % 251) as u8).collect();
    let mut acc: u64 = 0;
    for round in 0..64u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        round.hash(&mut h);
        buf.hash(&mut h);
        acc = acc.wrapping_add(h.finish());
    }
    // The accumulator is fed to something the caller could observe, so the loop is not code the
    // optimiser may delete: a ruler that compiles away measures nothing.
    if acc == u64::MAX {
        eprintln!("xtask: the calibration ruler measured {acc}");
    }
    t.elapsed().max(std::time::Duration::from_micros(1))
}

/// ONE WORK UNIT AS THE THREAD THAT JUST TOOK A CASE FINDS IT — the ruler for a battery taken
/// across the cores.
///
/// THE BUG THIS EXISTS TO FIX, AND IT IS THE ONE THE BUDGET'S OWN DOCTRINE WARNED ABOUT. The cases
/// are summed by WALL CLOCK, so taking eighteen at once inflates every one of them: they share
/// memory bandwidth, caches and whatever else is on the machine. `construction` measured 68 063
/// units against a budget of 50 000 AT `--jobs 18` AND WAS COMFORTABLY UNDER IT AT `--jobs 1`, on
/// the same tree, in the same minute. A gate that is red because the box was busy is a gate
/// somebody deletes -- which is exactly why the budget is denominated in work units and not in
/// seconds in the first place.
///
/// The ruler was measured ONCE, ON ONE THREAD, so it did not stretch when the cases did. Here it
/// does: the same fixed arithmetic is run on `jobs` threads AT THE SAME TIME and the unit is the
/// mean of what each thread took. "Four times more contended produces a calibration four times
/// slower too" was always the claim; this is what makes it true when the contention is the
/// harness's own.
///
/// AND IT IS READ ON THE WORKER, BETWEEN CASES, NOT ONCE BEFORE THEM. Calibrating `jobs` threads of
/// arithmetic up front does not work and the measurement says so: on eighteen cores that is one
/// arithmetic thread per core and it barely stretches at all — `structure-lint`'s ruler moved from
/// 11.0 ms to 11.6 ms while the cases it was measuring went from 85.7 s to 152.5 s. Pure arithmetic
/// on an idle box is not what a battery does to a box.
///
/// So each worker reads the ruler immediately after the case it just took, WITH THE OTHER
/// SEVENTEEN STILL SCANNING. It is then competing for cache and memory with the real work, which is
/// the only condition under which the proxy tracks what it is a proxy for — and a case is scored
/// against the ruler read on its own thread, in its own seconds, rather than against a number taken
/// when the machine was quiet.
///
/// It costs one ruler per case: about 11 ms against cases that average a second, which is under one
/// per cent of a battery and is the price of a budget that does not flap.
fn work_unit_here() -> std::time::Duration {
    ruler_once()
}

fn selftest_budget(gate: &str) -> f64 {
    SELFTEST_BUDGETS
        .iter()
        .find(|(n, _, _)| *n == gate)
        .map(|(_, u, _)| *u)
        .unwrap_or(DEFAULT_BUDGET_UNITS)
}

/// `Sync`, because a self-test's cases are taken across the cores and every one of them reaches
/// its gate through `&dyn Gate`. Nothing here has interior mutability — the gates are unit structs
/// and flag-carrying structs read through `&self` — so this is a bound that says what was already
/// true rather than a constraint anything had to be changed to meet.
pub trait Gate: Sync {
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
    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a>;

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

/// ONE CASE THE HARNESS HAS NOT TAKEN YET.
///
/// WHY A SELF-TEST CASE IS A PLAN AND NOT A RESULT. Every case here plants an overlay and drives
/// the whole gate over the planted tree; the two dearest batteries do that a hundred and twenty
/// times over a 660k-line tree, and taken one after another that is the slowest leg of the release.
/// The work is embarrassingly parallel and always was — an [`Overlay`] is per-plant by
/// construction, `with_overlay` returns a NEW `Ctx` and never mutates the base, so no case can
/// observe another case's plant however many run at once — but a `prove_red` that returns a
/// finished `Case` has already spent the time by the time the report sees it, and a report cannot
/// spread work it was handed after the fact.
///
/// So the `prove_*` family returns the WORK rather than its answer, [`Report::push`] takes the plan
/// in the case's own position in the list, and [`Report::resolve`] runs them across the cores and
/// writes the answers back into those positions. The order the reader sees is the order they were
/// pushed, whichever thread finished first, so the printed report is the same report either way.
///
/// A `Case` converts into a plan that simply hands it back, so a gate that builds a case by hand —
/// or takes one and edits it — pushes it exactly as before.
pub struct CasePlan<'a> {
    take: Box<dyn FnOnce() -> Case + Send + 'a>,
    /// What this case had already cost by the time it was pushed: the overlay it built, and — for
    /// a case that was taken eagerly — the run itself. Measured by [`Report::push`] between two
    /// pushes, which is where that work happens.
    prepaid: Duration,
}

impl<'a> CasePlan<'a> {
    /// A plan from the work itself.
    pub fn new(take: impl FnOnce() -> Case + Send + 'a) -> CasePlan<'a> {
        CasePlan {
            take: Box::new(take),
            prepaid: Duration::ZERO,
        }
    }

    /// Take the case NOW, on this thread. For a case whose gate or context is built inside the
    /// plan itself — a gate constructed with a flag the registry does not carry — where the
    /// `prove_*` call has to happen where those locals live.
    pub fn take(self) -> Case {
        (self.take)()
    }

    /// Edit the case this plan will produce, WITHOUT taking it now. The shape a gate needs when it
    /// wants `prove_red`'s proof and one field of the resulting case changed.
    pub fn map(self, f: impl FnOnce(Case) -> Case + Send + 'a) -> CasePlan<'a> {
        let take = self.take;
        CasePlan {
            take: Box::new(move || f(take())),
            prepaid: self.prepaid,
        }
    }
}

impl<'a> From<Case> for CasePlan<'a> {
    fn from(case: Case) -> CasePlan<'a> {
        CasePlan::new(move || case)
    }
}

/// WHAT A CASE PLANTS, AND WHEN IT BUILDS IT.
///
/// An `Overlay` handed to `prove_*` was already BUILT by the time the plan was made, because Rust
/// evaluates arguments where they are written. For most cases that is nothing — a map with one file
/// in it. For the batteries that matter it is not: a plant that reads the ledger, lists `crates/`,
/// re-renders a registry or formats a thousand lines of filler is real work, and doing it at the
/// push is doing it ON ONE THREAD while seventeen sit idle.
///
/// THE MEASUREMENT THAT SAYS SO. `kind-isolation` took 1621 s serial and 201 s across eighteen
/// cores. Solve those two for the serial fraction and it is about 117 s — which is to say that
/// after the gate runs were spread across the box, MORE THAN HALF of what was left was the plants
/// being built one after another.
///
/// So a plant may be given as the overlay OR as the closure that makes one, and the closure is
/// called on the worker that takes the case. Both spellings are this one trait, so a case that
/// plants a single file keeps reading exactly as it did and only the dear ones say `move ||`.
pub trait Plant<'a>: Send + 'a {
    fn build(self) -> Overlay;
}

/// The plant that is already built. Unchanged, and the right answer whenever building it is a map
/// insert or two.
impl<'a> Plant<'a> for Overlay {
    fn build(self) -> Overlay {
        self
    }
}

/// The plant BUILT ON THE WORKER. `Overlay` is a local type and cannot implement `FnOnce`, which is
/// what lets these two impls coexist.
impl<'a, F: FnOnce() -> Overlay + Send + 'a> Plant<'a> for F {
    fn build(self) -> Overlay {
        self()
    }
}

/// How many cases run at once when nothing says otherwise: the cores this box will admit to.
///
/// `XTASK_SELFTEST_JOBS` overrides it and `--jobs N` on the command line overrides that. `1` is
/// the serial harness exactly as it was, which is what the two are for: a case that fails in
/// parallel is re-run at `1` before it is believed, and the measurement that justifies any of this
/// is `--jobs 1` against the default on the same box.
pub fn default_jobs() -> usize {
    let asked = SELFTEST_JOBS.load(std::sync::atomic::Ordering::SeqCst);
    if asked > 0 {
        return asked;
    }
    if let Some(n) = std::env::var("XTASK_SELFTEST_JOBS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// What `--jobs N` asked for. `0` — the default — means nobody asked, and [`default_jobs`] then
/// reads the environment and the box.
///
/// A PROCESS-WIDE SETTING BECAUSE A REPORT IS BUILT WHERE THE COMMAND LINE IS NOT. Every gate's
/// selftest builds its own `Report` (and several build sub-reports and fold them in), so a flag
/// carried down through forty `selftest` signatures would be forty diffs and a hole for the
/// forty-first. Set once by the runner, before any gate runs.
static SELFTEST_JOBS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `cargo xtask ... --selftest --jobs N`. `1` is the serial harness exactly as it was.
pub fn set_selftest_jobs(jobs: usize) {
    SELFTEST_JOBS.store(jobs, std::sync::atomic::Ordering::SeqCst);
}

/// What the cases cost, in the order they were pushed.
struct Taken {
    cases: Vec<Case>,
    took: Vec<Duration>,
    /// What each case cost IN WORK UNITS, scored against the ruler its own worker read right after
    /// taking it. Kept per case rather than as one divisor because the machine is not the same from
    /// one end of a battery to the other, and the whole point is that the ruler moves with it.
    units: Vec<f64>,
    /// The half of `took` that was spent BEFORE the case reached a worker — building the plant, on
    /// the one thread that pushes. THE SERIAL FRACTION, itemised: it is the only part of a battery
    /// that more cores cannot help, so it is the only part worth rewriting, and a number beats a
    /// guess about which plants are dear.
    prepaid: Vec<Duration>,
}

pub struct Report<'a> {
    /// The cases not yet taken, in push order. Emptied by the first read.
    plans: std::sync::Mutex<Vec<CasePlan<'a>>>,
    /// The answers, in the SAME order. Filled once, by whichever reader asks first — a report can
    /// be read through `&self` from four places and none of them may see a report with the cases
    /// missing, because "0 cases, all green" is the one verdict this harness exists to refuse.
    taken: std::sync::OnceLock<Taken>,
    /// Failures that are not about a single case — an unplantable fixture, an unreadable tree.
    infra: Vec<String>,
    /// When the previous case was pushed. The work between two pushes is the next case's prepaid
    /// cost: the overlay it built, and whatever a hand-built case did to produce itself.
    mark: std::time::Instant,
    jobs: usize,
}

impl Default for Report<'_> {
    fn default() -> Self {
        Report {
            plans: std::sync::Mutex::new(Vec::new()),
            taken: std::sync::OnceLock::new(),
            infra: Vec::new(),
            mark: std::time::Instant::now(),
            jobs: default_jobs(),
        }
    }
}

impl<'a> Report<'a> {
    pub fn new() -> Report<'a> {
        Report::default()
    }

    /// The same report, run across `jobs` threads. `0` is read as `1`.
    pub fn with_jobs(mut self, jobs: usize) -> Report<'a> {
        self.jobs = jobs.max(1);
        self
    }

    pub fn jobs(&self) -> usize {
        self.jobs
    }

    pub fn push(&mut self, plan: impl Into<CasePlan<'a>>) {
        let mut plan = plan.into();
        plan.prepaid += self.mark.elapsed();
        self.mark = std::time::Instant::now();
        self.plans
            .get_mut()
            .expect("the plan list is never held across a panic")
            .push(plan);
    }

    /// Fold another report's cases and infra failures into this one, for a gate whose selftest is
    /// assembled from per-rule sub-reports rather than written as one list. The sub-report's cases
    /// keep their order and land after this one's, taken or not.
    pub fn append(&mut self, other: Report<'a>) {
        let Report {
            plans,
            taken,
            infra,
            ..
        } = other;
        let mine = self
            .plans
            .get_mut()
            .expect("the plan list is never held across a panic");
        if let Some(Taken { cases, took, .. }) = taken.into_inner() {
            for (case, took) in cases.into_iter().zip(took) {
                let mut plan = CasePlan::from(case);
                plan.prepaid = took;
                mine.push(plan);
            }
        }
        mine.extend(
            plans
                .into_inner()
                .expect("the plan list is never held across a panic"),
        );
        self.infra.extend(infra);
        self.mark = std::time::Instant::now();
    }

    /// TAKE EVERY CASE NOW AND HAND BACK A REPORT THAT BORROWS NOTHING.
    ///
    /// For a gate whose cases are proven through a gate IT BUILT — the changelog gate's release
    /// arms are the same gate with a flag, and the flag cannot come from the registry — so the
    /// `&dyn Gate` the plans name is a local. Sealing the report where that local still lives is
    /// how those cases are taken in parallel like every other, rather than the whole family being
    /// held serial by one borrow.
    pub fn sealed<'b>(self) -> Report<'b> {
        let taken = std::sync::OnceLock::new();
        let _ = taken.set(match self.taken.into_inner() {
            Some(already) => already,
            None => take_all(
                self.plans
                    .into_inner()
                    .expect("the plan list is never held across a panic"),
                self.jobs,
            ),
        });
        Report {
            plans: std::sync::Mutex::new(Vec::new()),
            taken,
            infra: self.infra,
            mark: self.mark,
            jobs: self.jobs,
        }
    }

    /// TAKE EVERY CASE, ACROSS THE CORES, AND WRITE THE ANSWERS BACK IN PUSH ORDER.
    ///
    /// The workers pull from one queue, so a battery whose cases differ by a factor of fifty in
    /// cost still finishes in about the time of its longest case rather than in the time of its
    /// slowest shard. Each answer is written into the slot its plan was pushed into, so the case
    /// list — and therefore the printed report and every verdict read off it — does not depend on
    /// which thread won.
    ///
    /// THE COST IS SUMMED PER CASE, NOT TAKEN OFF THE WALL CLOCK. [`selftest_budget`] is about a
    /// rule that grew a whole-tree scan per plant, which is a property of the WORK; dividing the
    /// work by the cores would hide exactly that regression behind a bigger box.
    fn resolve(&self) -> &Taken {
        self.taken.get_or_init(|| {
            let plans = std::mem::take(
                &mut *self
                    .plans
                    .lock()
                    .expect("the plan list is never held across a panic"),
            );
            take_all(plans, self.jobs)
        })
    }

    /// What this report cost, in [`work_unit`]s — each case scored against the ruler its own
    /// worker read, never against one taken when the machine was quiet.
    pub fn units(&self) -> f64 {
        self.resolve().units.iter().sum()
    }

    /// The ruler this report's units worked out to, for the message that quotes one.
    pub fn unit(&self) -> std::time::Duration {
        let units = self.units();
        if units <= 0.0 {
            return work_unit();
        }
        std::time::Duration::from_secs_f64(self.total().as_secs_f64() / units)
    }

    pub fn total(&self) -> std::time::Duration {
        self.resolve().took.iter().sum()
    }

    /// WHAT THIS BATTERY SPENT ON ONE THREAD, building its plants. The rest was spread across the
    /// cores; this was not, and this is what a further speed-up has to come out of.
    pub fn planting(&self) -> std::time::Duration {
        self.resolve().prepaid.iter().sum()
    }

    /// The case whose PLANT cost the most — the first name on the list of plants worth making lazy.
    pub fn dearest_plant(&self) -> Option<(&str, std::time::Duration)> {
        let taken = self.resolve();
        taken
            .cases
            .iter()
            .zip(taken.prepaid.iter())
            .max_by_key(|(_, t)| **t)
            .map(|(c, t)| (c.name.as_str(), *t))
    }

    pub fn slowest(&self) -> Option<(&str, std::time::Duration)> {
        let taken = self.resolve();
        taken
            .cases
            .iter()
            .zip(taken.took.iter())
            .max_by_key(|(_, t)| **t)
            .map(|(c, t)| (c.name.as_str(), *t))
    }

    pub fn note_infra_failure(&mut self, msg: impl Into<String>) {
        self.infra.push(msg.into());
    }

    pub fn cases(&self) -> &[Case] {
        &self.resolve().cases
    }

    pub fn skipped(&self) -> usize {
        self.cases()
            .iter()
            .filter(|c| matches!(c.got, Expect::Skipped))
            .count()
    }

    pub fn failures(&self) -> Vec<String> {
        let mut out = self.infra.clone();
        out.extend(self.cases().iter().filter_map(Case::failure));
        out
    }

    pub fn ok(&self) -> bool {
        self.failures().is_empty()
    }
}

/// Take `plans` on `jobs` threads and return the cases IN THE ORDER THE PLANS CAME IN.
///
/// Scoped threads rather than a pool with `'static` work: a plan borrows the `Ctx` and the `&dyn
/// Gate` its gate's selftest was handed, and a scope is how that borrow is proven to outlive the
/// threads instead of being asserted by a comment over an `unsafe impl Send`.
fn take_all(plans: Vec<CasePlan<'_>>, jobs: usize) -> Taken {
    let n = plans.len();
    if n == 0 {
        return Taken {
            cases: Vec::new(),
            took: Vec::new(),
            units: Vec::new(),
            prepaid: Vec::new(),
        };
    }
    let mut queue: Vec<(usize, CasePlan<'_>)> = plans.into_iter().enumerate().collect();
    // Popped from the back, so the cases start in push order.
    queue.reverse();
    let queue = std::sync::Mutex::new(queue);
    #[allow(clippy::type_complexity)]
    let out: Vec<std::sync::Mutex<Option<(Case, Duration, Duration, f64)>>> =
        (0..n).map(|_| std::sync::Mutex::new(None)).collect();
    let out = &out;
    let queue = &queue;
    let workers = jobs.max(1).min(n);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(move || loop {
                let next = queue
                    .lock()
                    .expect("the case queue is never held across a panic")
                    .pop();
                let Some((slot, plan)) = next else { return };
                let prepaid = plan.prepaid;
                let started = std::time::Instant::now();
                let case = (plan.take)();
                let spent = prepaid + started.elapsed();
                // THE RULER, HERE, NOW — with the other workers still at their own cases. See
                // [`work_unit_here`].
                let unit = work_unit_here();
                let units = spent.as_secs_f64() / unit.as_secs_f64();
                *out[slot]
                    .lock()
                    .expect("a case slot is never held across a panic") =
                    Some((case, spent, prepaid, units));
            });
        }
    });

    let mut cases = Vec::with_capacity(n);
    let mut took = Vec::with_capacity(n);
    let mut prepaid = Vec::with_capacity(n);
    let mut units = Vec::with_capacity(n);
    for slot in out {
        let (case, spent, before, scored) = slot
            .lock()
            .expect("a case slot is never held across a panic")
            .take()
            .expect("every plan was taken: the queue is drained before the scope ends");
        cases.push(case);
        took.push(spent);
        prepaid.push(before);
        units.push(scored);
    }
    Taken {
        cases,
        took,
        units,
        prepaid,
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
pub fn verify_report(gate: &dyn Gate, report: &Report<'_>) -> Result<(), Vec<String>> {
    let mut errs = report.failures();

    // THE BUDGET. See [`SELFTEST_BUDGETS`]: an unmeasured selftest is one that grows until the
    // runner kills it, and a killed job is neither green nor red.
    let budget = selftest_budget(gate.name());
    let spent = report.units();
    if spent > budget {
        let slowest = report
            .slowest()
            .map(|(n, t)| format!(" Slowest case: `{n}`, {:.1}s.", t.as_secs_f64()))
            .unwrap_or_default();
        errs.push(format!(
            "{}: this self-test spent {spent:.0} work units against a budget of {budget:.0} (one unit is {:.1}ms on this box right now, so {:.0}s of wall clock here). A self-test that grew a whole-tree scan per plant is how the xtask shard goes from minutes to an hour, and the runner that finds out is the one that cancels the job.{slowest}",
            gate.name(),
            report.unit().as_secs_f64() * 1000.0,
            report.total().as_secs_f64()
        ));
    }

    if !report
        .cases()
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
        .cases()
        .iter()
        .filter(|c| matches!(c.expected, Expect::Red { .. }))
        .flat_map(|c| c.covers.iter().cloned())
        .collect();
    let exercised: BTreeSet<String> = report
        .cases()
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
pub fn prove_red<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    plant: impl Plant<'a>,
    naming: &[&str],
) -> CasePlan<'a> {
    let name = name.into();
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let naming: Vec<String> = naming.iter().map(|s| (*s).to_string()).collect();
    let cx = cx.clone();
    CasePlan::new(move || {
        let planted = cx.with_overlay(plant.build());
        let verdict = execute(gate, &planted);
        let got = narrowed_got(&verdict, &refs(&covers));
        Case {
            name,
            covers,
            expected: Expect::Red { naming },
            got,
        }
    })
}

/// The `&str` view of an owned `covers` list, for the readers that were written against `&[&str]`.
fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The red arm, NARROWED TO THE ROWS THE CASE IS ABOUT — the counterpart of [`prove_rows_green`],
/// and the STRONGER of the two proofs.
///
/// [`prove_red`] accepts any RED that names the planted offender, which is exactly right when the
/// gate has three rows. Over a gate with thirty-six, on a tree that carries real debt in some of
/// them, "the gate went red and something in the report said the word" is satisfiable by a row the
/// case is not about. Reading only the covered rows makes the case say what it means: THIS rule
/// went red, and it named the offender that was planted for it.
pub fn prove_rows_red<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    plant: impl Plant<'a>,
    naming: &[&str],
) -> CasePlan<'a> {
    prove_red(cx, gate, name, covers, plant, naming)
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
pub fn prove_rows_green<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    plant: impl Plant<'a>,
) -> CasePlan<'a> {
    let name = name.into();
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let cx = cx.clone();
    CasePlan::new(move || {
        let planted = cx.with_overlay(plant.build());
        let verdict = execute(gate, &planted);
        let offenders: Vec<String> = verdict
            .rows
            .iter()
            .filter(|r| {
                r.status != crate::ledger::Status::Pass && covers.iter().any(|c| c == &r.id)
            })
            .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
            .collect();
        Case {
            name,
            covers,
            expected: Expect::Green,
            got: if offenders.is_empty() {
                Expect::Green
            } else {
                Expect::Red { naming: offenders }
            },
        }
    })
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
pub fn prove_rows_red_at<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    fixture_rel: &str,
    naming: &[&str],
) -> CasePlan<'a> {
    let name = name.into();
    let expected = Expect::Red {
        naming: naming.iter().map(|s| (*s).to_string()).collect(),
    };
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let fixture_abs = cx.abs(fixture_rel);
    let scratch = cx.scratch().to_path_buf();
    CasePlan::new(move || {
        let Ok(fixture_cx) = Ctx::at(fixture_abs, scratch) else {
            return Case {
                name,
                covers,
                expected,
                got: Expect::Skipped,
            };
        };
        let verdict = execute(gate, &fixture_cx);
        let got = narrowed_got(&verdict, &refs(&covers));
        Case {
            name,
            covers,
            expected,
            got,
        }
    })
}

/// The other arm: the unplanted tree must be GREEN, or every RED above proves only that the gate
/// is broken.
pub fn prove_green<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
) -> CasePlan<'a> {
    let name = name.into();
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let cx = cx.clone();
    CasePlan::new(move || {
        let verdict = execute(gate, &cx);
        Case {
            name,
            covers,
            expected: Expect::Green,
            got: if verdict.red {
                Expect::Red {
                    naming: reported_text(&verdict),
                }
            } else {
                Expect::Green
            },
        }
    })
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
        name: "ship-ready",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(ship_ready::ShipReadyGate),
        summary: "the ship criterion as a row: twin zero, ceilings tight, nothing standing red, \
                  mutants caught",
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

#[cfg(test)]
mod parallel_tests {
    use super::*;
    use crate::ledger::Row;

    /// A gate that reports WHAT IT READ at one path, so a case's verdict names the bytes that case
    /// planted and nothing else.
    struct EchoGate;

    const ECHO_ROW: &str = "echo:read";
    const ECHO_PATH: &str = "qa/zz-selftest-parallel-echo.txt";

    impl Gate for EchoGate {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn owed(&self) -> Vec<String> {
            vec![ECHO_ROW.to_string()]
        }
        fn run(&self, cx: &Ctx) -> Verdict {
            let seen = cx
                .read(ECHO_PATH)
                .unwrap_or_else(|_| "<absent>".to_string());
            // Long enough for a racing case to overwrite a shared plant, if plants were shared.
            std::thread::sleep(Duration::from_millis(40));
            let again = cx
                .read(ECHO_PATH)
                .unwrap_or_else(|_| "<absent>".to_string());
            Verdict::of(vec![Row::fail(
                ECHO_ROW.to_string(),
                "echo".to_string(),
                format!("{seen}|{again}"),
            )])
        }
        fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
            Report::new()
        }
    }

    /// TWO CONFLICTING FIXTURES, PLANTED AT THE SAME PATH, TAKEN AT THE SAME TIME.
    ///
    /// This is the property the whole parallel harness rests on, and it is asserted rather than
    /// argued: each case must see ITS OWN plant, twice, with the other case's plant live on
    /// another thread in between. A harness that planted on disk — the shape
    /// `scripts/construction-gate/plant.py` had, with its `TOUCHED` list and its restore step —
    /// answers this test with one case reading the other's bytes, which is a green case that
    /// proves nothing and a red case that names the wrong offender.
    ///
    /// The gate reads the path TWICE with a sleep between, so a case that merely won a race is not
    /// mistaken for a case that was isolated.
    #[test]
    fn two_cases_planted_at_the_same_path_never_see_each_other() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = EchoGate;
        let mut report = Report::new().with_jobs(2);
        for mine in ["FIXTURE-A", "FIXTURE-B"] {
            let mut ov = Overlay::new();
            ov.set(ECHO_PATH, mine);
            report.push(prove_red(
                &cx,
                &gate,
                format!("the case that planted {mine}"),
                &[ECHO_ROW],
                ov,
                &[&format!("{mine}|{mine}")],
            ));
        }
        let failures = report.failures();
        assert!(
            failures.is_empty(),
            "a case read a plant that was not its own — the cases are not isolated: {failures:#?}"
        );
        let names: Vec<&str> = report.cases().iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "the case that planted FIXTURE-A",
                "the case that planted FIXTURE-B"
            ],
            "the cases must be reported in the order they were pushed, whichever thread finished \
             first"
        );
    }

    /// The order is the PUSH order even when the later case finishes first, which is the only way
    /// a parallel report can be read against a serial one.
    #[test]
    fn the_case_list_is_push_order_not_finish_order() {
        let mut report = Report::new().with_jobs(4);
        for (i, delay) in [40u64, 20, 10, 0].into_iter().enumerate() {
            report.push(CasePlan::new(move || {
                std::thread::sleep(Duration::from_millis(delay));
                Case {
                    name: format!("case {i}"),
                    covers: vec!["r".to_string()],
                    expected: Expect::Green,
                    got: Expect::Green,
                }
            }));
        }
        let names: Vec<&str> = report.cases().iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["case 0", "case 1", "case 2", "case 3"]);
    }

    /// A report whose cases were never taken must not read as a report with no cases. Every reader
    /// goes through the same resolution, so "0 cases, all green" cannot be produced by forgetting
    /// to run them.
    #[test]
    fn an_unresolved_report_is_never_read_as_an_empty_one() {
        let mut report = Report::new();
        report.push(CasePlan::new(|| Case {
            name: "a case nobody asked to take".to_string(),
            covers: vec!["r".to_string()],
            expected: Expect::Green,
            got: Expect::Red {
                naming: vec!["r went red".to_string()],
            },
        }));
        assert_eq!(report.cases().len(), 1);
        assert!(!report.ok(), "the case failed, and the report says so");
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;
    use crate::ledger::Row;

    fn verdict(rows: Vec<Row>) -> Verdict {
        Verdict::of(rows)
    }

    /// The whole point of the narrow excuse: the standing red is excused, and one more red row
    /// about anything else is scored. Without this, `--all` would have gone on being a switch that
    /// is off for every future design-bindings break as well as for the known one.
    #[test]
    fn a_design_binding_that_breaks_for_a_new_reason_is_scored() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let known = Row::fail(
            "PB-0",
            "PB-0 master rule",
            "partly proven; a referenced check settles nothing: \
             gate:scripts/inventory-coverage.sh",
        );
        assert!(
            excused_from_all("design-bindings", &cx, &verdict(vec![known.clone()])).is_some(),
            "the standing red PB-0 names the absent check and is what the entry was written for"
        );
        let fresh = Row::fail(
            "PB-7",
            "PB-7 something else",
            "a binding cites nothing at all",
        );
        assert!(
            excused_from_all("design-bindings", &cx, &verdict(vec![known, fresh])).is_none(),
            "a second red about anything else is a regression, and an excuse that covered it would \
             be a switch nobody could see was off"
        );
    }

    /// The release-time posture is not a name on a list here: it is a lookup into the table that
    /// already knew, and that table's own claim is checked against the tree.
    #[test]
    fn the_release_time_posture_is_read_from_full_gate_and_expires_with_it() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let red = verdict(vec![Row::fail("kind-isolation:shape", "t", "d")]);
        assert!(
            excused_from_all("kind-isolation-ship", &cx, &red).is_some(),
            "verify-1.6.0-done.sh invokes it, which is what full_gate's excuse asserts"
        );
        let mut ov = Overlay::new();
        ov.set(
            "scripts/verify-1.6.0-done.sh",
            "#!/usr/bin/env bash\n# the release script no longer runs it\n",
        );
        assert!(
            excused_from_all("kind-isolation-ship", &cx.with_overlay(ov), &red).is_none(),
            "an excuse whose fact stopped holding excuses nothing"
        );
    }

    /// THE CONSTRUCTION POSTURE, WHICH USED TO BE `Excused::Whole` — no fact-check, no expiry, no
    /// list. `gate --all` exited 0 however red construction got, so a real regression on a keep
    /// branch was indistinguishable from the standing red. All three arms of the replacement:
    #[test]
    fn the_construction_posture_excuses_its_named_rows_and_nothing_else() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let standing: Vec<Row> = CONSTRUCTION_STANDING_REDS
            .iter()
            .map(|id| Row::fail(*id, "t", "the standing red this list was written for"))
            .collect();

        // 1. Red on exactly the named rows: excused.
        assert!(
            excused_from_all("construction", &cx, &verdict(standing.clone())).is_some(),
            "the standing reds are what the entry names, and naming them is the whole entry"
        );

        // 2. One more red about anything else: SCORED. This is the signal `Excused::Whole` threw
        //    away, and the reason this gate can now be a blocking CI job.
        let mut plus = standing.clone();
        plus.push(Row::fail("plane-no-dialect", "t", "a brand new coupling"));
        assert!(
            excused_from_all("construction", &cx, &verdict(plus)).is_none(),
            "a red the list does not name is a regression, and an excuse covering it would be a \
             switch nobody could see was off"
        );

        // 3. A named row that went GREEN: also scored, because the list has gone stale. Without
        //    this the list only ever grows and drifts back into being the blanket it replaced.
        let mut drained = standing;
        drained.pop();
        assert!(
            excused_from_all("construction", &cx, &verdict(drained)).is_none(),
            "a name that is no longer red must be struck, in the commit that drained it"
        );
    }

    /// A row that emitted nothing at all reaches the verdict as a reconciliation PROBLEM, never as
    /// a row. A rule that stopped running is not a rule that is red for a known reason, so a
    /// problem about an id the list does not name must fail the excuse like any new red.
    #[test]
    fn a_row_that_did_not_run_is_not_excused_by_the_standing_list() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let mut v = verdict(
            CONSTRUCTION_STANDING_REDS
                .iter()
                .map(|id| Row::fail(*id, "t", "standing"))
                .collect(),
        );
        v.problems
            .push("ceiling-census: owed but no row was recorded — DID NOT RUN".to_string());
        v.red = true;
        assert!(
            excused_from_all("construction", &cx, &v).is_none(),
            "a rule that vanished is not a rule that is red for a known reason"
        );
    }

    #[test]
    fn a_gate_with_no_posture_entry_is_always_scored() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let red = verdict(vec![Row::fail("x", "t", "d")]);
        assert!(excused_from_all("plane-purity", &cx, &red).is_none());
    }

    /// A budget for a gate that is not registered is a number nobody reads, and a reason too short
    /// to be one is a number nobody argued for.
    #[test]
    fn every_selftest_budget_names_a_registered_gate_with_a_reason() {
        for (name, units, why) in SELFTEST_BUDGETS {
            assert!(
                find(name).is_some(),
                "`{name}` has a self-test budget and is not a registered gate"
            );
            assert!(
                *units > DEFAULT_BUDGET_UNITS,
                "`{name}`'s budget of {units} units is not above the default; strike the entry"
            );
            assert!(
                why.len() > 60,
                "`{name}`'s budget reason is too short to be one"
            );
        }
    }

    /// The ruler must be a ruler: measurable, and the same every time it is asked.
    #[test]
    fn the_work_unit_is_a_positive_memoised_measurement() {
        let a = work_unit();
        assert!(a > std::time::Duration::ZERO);
        assert_eq!(a, work_unit());
    }

    /// Every posture names a registered gate. An entry for a gate that no longer exists is a
    /// waiver that outlived what it excused.
    #[test]
    fn every_posture_names_a_registered_gate() {
        for p in REPORT_ONLY {
            assert!(
                find(p.name).is_some(),
                "`{}` is excused from --all and is not a registered gate",
                p.name
            );
            assert!(
                p.why.len() > 60,
                "`{}`'s reason is too short to be one",
                p.name
            );
        }
    }
}
