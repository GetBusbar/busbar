//! `cargo xtask full-gate` — RUN LOCALLY WHAT CI RUNS, so "green" has one meaning.
//!
//! Ported from `scripts/full-gate.sh`. The discovery (see [`crate::discovery`]) is unchanged: the
//! gate set and the cargo set are DERIVED from `.github/workflows/ci.yml`, never hand-mirrored, and
//! an unclassified cargo invocation is a hard failure rather than a line nobody runs.
//!
//! ## What changed, and why it is stronger
//!
//! `full-gate.sh` protected its discovery with `MIN_GATES=8` — a floor that sat 81 below the real
//! count, so deleting most of CI's gates from `ci.yml` still passed it. A floor was the best a shell
//! script could do, because it had no way to enumerate what OUGHT to be there.
//!
//! In-process, the gate set IS enumerable: [`crate::gates::REGISTRY`] is the list. So the floor is
//! replaced by **SET EQUALITY** — every registered gate must appear in `ci.yml` and every
//! `cargo xtask gate <name>` in `ci.yml` must be registered, modulo [`GATE_SKIP`], whose every entry
//! carries a written reason. A registered gate absent from `ci.yml` is RED, which is the failure
//! `MIN_GATES` could only approximate.
//!
//! The cargo floor moves too. In the shell it lived ONLY inside `--selftest`, never on the run path,
//! so a run whose parser had broken read as a clean tree. Here it is on both.
//!
//! ## Never judge a ledger the run did not write
//!
//! For a gate that runs in-process the verdict is a returned value, so the staleness the shell
//! suffered — a gate dies before writing, and the caller reads the PREVIOUS healthy run's ledger
//! sitting on disk — is unrepresentable. Any gate that still shells out and reads a file back must
//! truncate the file first, which [`crate::ledger::read_leg_after`] does for the caller.

use std::collections::BTreeSet;
use std::process::Command;

use crate::ctx::Ctx;
use crate::discovery;
use crate::gates;

pub const CI_YML: &str = ".github/workflows/ci.yml";

/// The workflow-level `RUSTFLAGS` this runner exports and asserts `ci.yml` agrees with. A local run
/// under different flags is a local green that does not mean a CI green.
pub const RUSTFLAGS: &str = "-D warnings";

/// The DISCOVERY FLOORS, and both are on the run path.
///
/// They are no longer the primary defence — set equality against the registry is — but a parser
/// that has broken entirely still has to be caught before the equality check reads an empty set and
/// finds it consistent with an empty registry.
pub const MIN_GATES: usize = 8;
pub const MIN_CARGO: usize = 10;

/// Where the local skip register and the must-find list live. DATA, not a Rust table: see the
/// file's own header for why, and note that six of its entries name oracle harness scripts —
/// putting them in `xtask/src` would have meant weakening `cargo xtask gate segregation`'s rule
/// against this crate naming a file it does not read as data.
pub const REGISTER_REL: &str = "qa/full-gate.toml";

/// One row of the skip register.
pub struct Skip {
    pub script: String,
    pub reason: String,
}

/// Read the skip register. AN UNREADABLE OR EMPTY REGISTER IS AN ERROR, never zero skips: zero
/// skips would silently promote every release-only gate into the local run and red the whole thing
/// for reasons that are about a missing file.
pub fn load_register(cx: &Ctx) -> Result<(Vec<Skip>, Vec<String>), String> {
    let doc = crate::toml_lite::parse(&cx.abs(REGISTER_REL));
    let skips: Vec<Skip> = doc
        .array_table("skip")
        .iter()
        .map(|t| Skip {
            script: t.get_one("script").unwrap_or_default().to_string(),
            reason: t.get_one("reason").unwrap_or_default().to_string(),
        })
        .collect();
    if skips.is_empty() {
        return Err(format!(
            "{REGISTER_REL} declares no [[skip]] rows. An empty skip register reads exactly like \
             a tree where every gate runs locally; it is not one."
        ));
    }
    let must = doc.table("discovery").get_list("must_find");
    if must.is_empty() {
        return Err(format!(
            "{REGISTER_REL} declares no discovery.must_find entries. The list is what proves the \
             parser still sees each shape it has to see; an empty one proves nothing."
        ));
    }
    Ok((skips, must))
}

/// The cargo invocations this runner RUNS. Every gate conversion adds its two lines here in the
/// same commit that switches the `ci.yml` call site, so the local set and the CI set move together.
pub const CARGO_LOCAL: &[&str] = &[
    "cargo fmt --all -- --check",
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
    "cargo build --workspace --locked",
    "cargo test --workspace --locked",
    "cargo clippy --no-default-features --locked -- -D warnings",
    "cargo build --no-default-features --locked",
    "cargo test --no-default-features --locked",
    "cargo clippy -p busbar -p busbar-core --all-targets --features openapi-schema --locked -- -D warnings",
    "cargo test -p busbar -p busbar-core --features openapi-schema --locked openapi -- --nocapture",
    "cargo build --locked --bin busbar",
    "cargo test -p busbar --test migration_corpus --locked -- --nocapture",
    "cargo test -p busbar-voice --features runtime,test-support -p busbar-streams-codec --features runtime --locked",
    "cargo test -p busbar-llm --features teller-waist --locked --lib unit::",
    "cargo test -p busbar-timing --features timing --locked",
    "cargo build -p xtask --locked",
    "cargo xtask gate kind-isolation --selftest",
    "cargo xtask gate kind-isolation",
    "cargo xtask gate kernel-token-wire-purity --selftest",
    "cargo xtask gate kernel-token-wire-purity",
    "cargo xtask gate no-self-filed-issues --selftest",
    "cargo xtask gate no-self-filed-issues",
    "cargo xtask gate tracing --selftest",
    "cargo xtask gate tracing",
    "cargo xtask gate settings-leak --selftest",
    "cargo xtask gate settings-leak",
    "cargo xtask gate response-header --selftest",
    "cargo xtask gate response-header",
    "cargo xtask gate blocking-ffi --selftest",
    "cargo xtask gate blocking-ffi",
    "cargo xtask gate plane-transport-neutrality --selftest",
    "cargo xtask gate plane-transport-neutrality",
    "cargo xtask gate plane-abi-neutrality --selftest",
    "cargo xtask gate plane-abi-neutrality",
    "cargo xtask gate duplex-ws-default-edge --selftest",
    "cargo xtask gate duplex-ws-default-edge",
    "cargo xtask gate teller-steps --selftest",
    "cargo xtask gate teller-steps",
    "cargo xtask gate changelog --selftest",
    "cargo xtask gate changelog",
    "cargo xtask gate changelog-register --selftest",
    "cargo xtask gate changelog-register",
    "cargo xtask gate ci-umbrella --selftest",
    "cargo xtask gate ci-umbrella",
    "cargo xtask gate config-schema --selftest",
    "cargo xtask gate config-schema",
    "cargo xtask gate construction --selftest",
    "cargo xtask gate construction --report",
    // The POSTURE form, which is what ci.yml and keep-proof.yml now run as a blocking step. It
    // exits 0 while the gate is red on exactly the rows `gates::REPORT_ONLY` names and 1 on any
    // other red, so unlike the bare scored form it is runnable locally without redding the whole
    // local gate on the standing work — which is precisely why CI can block on it.
    "cargo xtask gate construction --posture",
    "cargo xtask gate design-bindings --selftest",
    "cargo xtask gate design-bindings",
    "cargo xtask gate field-inventory --selftest",
    "cargo xtask gate field-inventory",
    "cargo xtask gate inventory-ref --selftest",
    "cargo xtask gate inventory-ref",
    "cargo xtask gate no-deferral --selftest",
    "cargo xtask gate no-deferral",
    "cargo xtask gate plane-purity --selftest",
    "cargo xtask gate plane-purity",
    "cargo xtask gate qa-gate-dispatch --selftest",
    "cargo xtask gate qa-gate-dispatch",
    "cargo xtask gate release-order --selftest",
    "cargo xtask gate release-order",
    "cargo xtask gate service-images --selftest",
    "cargo xtask gate service-images",
    "cargo xtask gate structure-lint --selftest",
    "cargo xtask gate structure-lint",
    "cargo xtask gate workspace-deps --selftest",
    "cargo xtask gate workspace-deps",
    "cargo xtask full-gate --selftest",
    "cargo xtask gate audit-ledger --selftest",
    "cargo xtask gate audit-ledger",
    "cargo xtask gate release-order --format=tsv",
    "cargo xtask teller-steps --root-legs",
    "cargo xtask teller-steps --root-legs-gating",
];

/// The cargo invocations only CI can run, each with a written reason. Windows is the one gap a
/// local run genuinely cannot close: read a green here as "green on this platform".
pub const CARGO_CI_ONLY: &[(&str, &str)] = &[
    ("cargo build --workspace", "the WINDOWS job's build. There is no Windows host here, and the failures it catches are precisely the ones that do not reproduce on this one -- path separators, socket error wording, line endings. Nothing local substitutes for it."),
    ("cargo test --workspace", "the WINDOWS job's test run; same reason. This is the one gap a local run genuinely cannot close: read a green here as 'green on this platform'."),
    ("cargo clippy --workspace --all-targets -- -D warnings", "the WINDOWS job's clippy. It exists to catch the platform-gated code no local run compiles at all -- a #[cfg(unix)] item whose #[cfg(windows)] twin was never written is a warning THERE and nowhere here. A macOS/Linux clippy cannot substitute: it takes the other arm of every cfg. Approximated locally with 'cargo xwin clippy --target x86_64-pc-windows-msvc', which type-checks the Windows arms without a Windows host but still executes nothing."),
    ("cargo test --release --locked timing_gate -- --ignored", "a RELEASE-profile wall-clock gate on a dedicated runner. A debug tree with a compiler and a browser competing for the CPU measures the laptop, not the engine; run it directly when touching the timing path."),
    ("cargo build -p busbar --release --locked", "the RELEASE-profile build that feeds build-provenance-gate.sh (it asserts the shipped binary's optimized posture). The local build mirror is the debug 'cargo build --locked --bin busbar' above; a release build here would re-measure the laptop, not prove anything the debug build does not."),
    ("cargo build -p busbar-core -p busbar-substrate -p busbar-api --no-default-features --features \"$FEATS\" --locked", "the plane-DELETION matrix build. $FEATS is '${{ matrix.features }}', which expands per kept-plane combination -- a CI matrix construct with no single local form, and the literal string is not a runnable command. It is mirrored locally by the delete-test gate (PLANE-DELETE group), which compiles the neutral crates with a plane removed."),
    ("cargo build -p busbar-core -p busbar-substrate -p busbar-api --no-default-features --locked", "the same plane-DELETION matrix build's EMPTY-features arm (every plane removed). Same matrix job, same local mirror in the delete-test gate; listed separately because the step branches on $FEATS and both arms are real invocations."),
    ("cargo test -p busbar-llm --lib alloc_gate -- --nocapture", "the deterministic alloc-count perf gate, invoked BY NAME so a regression reds this one line rather than a 400-test workspace run. The same tests are also executed by 'cargo test --workspace --locked' above, which DOES run locally. (It read '-p busbar-core' here for as long as ci.yml did, matching zero tests in both places — a libtest filter that selects nothing exits 0.)"),
    ("cargo xtask gate construction", "the SCORED-AGAINST-ZERO form of the construction gate, which is RED BY DESIGN on HEAD while the construction work it measures is in flight; running it here would red the whole local gate on a fact nothing scores that way. ci.yml and keep-proof.yml no longer run this form at all: they run 'cargo xtask gate construction --posture' as a BLOCKING step, which is green while the gate is red on exactly the rows gates::REPORT_ONLY names and red on any other row — and that form IS in CARGO_LOCAL and does run locally, alongside '--report'. DELETE this entry when CONSTRUCTION_STANDING_REDS is empty and the bare form is green on HEAD."),
];

/// WHERE AN EXCUSED GATE IS ACTUALLY RUN — the checkable half of a written reason.
///
/// A reason is prose, and prose is not evidence. The `denylist` entry asserted for months that
/// `ci.yml` invoked it under an older spelling and that it "IS run on every push"; the string
/// appeared in no workflow. Nothing noticed, because the excuse list was matched by NAME and its
/// claim was never put to the tree. So every entry now carries the one fact its reason turns on,
/// as a needle in a named file, and [`Excuse::holds`] goes and looks.
#[derive(Debug, Clone, Copy)]
pub enum Excuse {
    /// `cargo test -p xtask` runs it: the needle must appear under `xtask/tests/`. That test run is
    /// part of `cargo test --workspace --locked`, which ci.yml executes on every push.
    XtaskTest(&'static str),
    /// It is a release-time claim: the needle must appear in the named script.
    ReleaseScript(&'static str, &'static str),
}

impl Excuse {
    /// The claim, checked. `Err` carries the sentence a reader needs to act on it.
    pub fn holds(&self, cx: &Ctx) -> Result<(), String> {
        let (where_, needle) = match self {
            Excuse::XtaskTest(needle) => ("xtask/tests", *needle),
            Excuse::ReleaseScript(path, needle) => (*path, *needle),
        };
        let found = match self {
            Excuse::XtaskTest(_) => cx
                .walk(
                    &crate::ctx::WalkSpec::new(["xtask/tests"])
                        .ext("rs")
                        .min_files(1),
                )
                .map_err(|e| format!("{e}"))?
                .iter()
                .any(|f| f.text.contains(needle)),
            Excuse::ReleaseScript(path, _) => cx.read(path)?.contains(needle),
        };
        if found {
            Ok(())
        } else {
            Err(format!(
                "the excuse says it runs there, and `{needle}` appears nowhere in {where_}"
            ))
        }
    }
}

/// Registered gates deliberately NOT invoked by `ci.yml`, each with a written reason AND the fact
/// that reason rests on. This is the escape hatch the set-equality check needs in order to be an
/// equality at all — without it the only way to land a gate CI does not yet run would be to weaken
/// the check for every gate. An entry whose [`Excuse`] no longer holds excuses nothing: the gate is
/// reported, exactly as if the entry had never been written.
pub const REGISTRY_NOT_IN_CI: &[(&str, &str, Excuse)] = &[
    (
        "denylist",
        "no workflow names it — the coverage is `xtask/tests/cli.rs`, which drives the pre-registry \
         `cargo xtask denylist` spelling through the dispatcher and pins its verdict at 0. That test \
         runs under `cargo test --workspace --locked` on every push. (The reason this entry carried \
         until now said ci.yml invoked it under that older spelling. It does not, and never did at \
         this hash: the string is in no workflow. The route that actually covers the gate is the \
         one named here.)",
        Excuse::XtaskTest("run(&[\"denylist\"])"),
    ),
    (
        "segregation",
        "the oracle-vs-runner segregation gate is pinned GREEN by `xtask/tests/cli.rs`, which the \
         workspace test run already executes on every push. Invoking it a second time through \
         the gate runner would run the same assertions in the same process for no extra signal.",
        Excuse::XtaskTest("run(&[\"gate\", \"segregation\"])"),
    ),
    (
        "plane-purity-strict",
        "the ratcheted twin of plane-purity. It is a release-time claim, run by \
         scripts/verify-1.6.0-done.sh (`cargo xtask gate plane-purity-strict`) as part of the DONE \
         oracle, not on every push: its ceilings move with the busbar-core retirement and a per-push \
         red would only restate that the retirement is in flight.",
        Excuse::ReleaseScript(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate plane-purity-strict",
        ),
    ),
    (
        "kind-isolation-ship",
        "the SHIP-criterion twin of kind-isolation. Its four enforceable rows run on every push \
         under `kind-isolation`; the two it adds — one entry surface per kind, one shared \
         conformance battery per kind — are a claim about the SHIP SHA and are RED on HEAD by \
         design (no kind states a `Unit` entry, no plane/transport/unit kind has a shared battery, \
         and the plane and unit skeletons diverge from their exemplars). Run at release time by \
         scripts/verify-1.6.0-done.sh, on the same terms as plane-purity-strict: a per-push red \
         would only restate that the work is in flight, and a gate that is red every push is a \
         gate somebody puts a `|| true` in front of.",
        Excuse::ReleaseScript(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate kind-isolation-ship",
        ),
    ),
    (
        "no-deferral-strict-done",
        "the strict twin of no-deferral. It certifies that nothing is deferred at all, which is the \
         DONE claim scripts/verify-1.6.0-done.sh makes at release time (`cargo xtask gate \
         no-deferral-strict-done`); ci.yml runs the per-push `no-deferral` whose waivers name the \
         tracker rows that retire them.",
        Excuse::ReleaseScript(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate no-deferral-strict-done",
        ),
    ),
];

fn cargo_ci_only_reason(cmd: &str) -> Option<&'static str> {
    CARGO_CI_ONLY
        .iter()
        .find(|(c, _)| *c == cmd)
        .map(|(_, r)| *r)
}

/// The bare script path out of a full invocation (interpreter and flags stripped).
fn bare_script(inv: &str) -> String {
    inv.split_whitespace()
        .find(|t| (t.starts_with("scripts/") || t.starts_with("testing/")) && t.contains('.'))
        .unwrap_or("")
        .to_string()
}

/// How the discovered script gates partition.
pub struct Partition {
    pub run: Vec<String>,
    pub skip: Vec<(String, String)>,
}

/// THE RULE ORDER IS LOAD-BEARING.
///
/// 1. **Any invocation carrying `--selftest` ALWAYS runs**, whatever its script's classification. A
///    gate's self-test is the part that proves the gate can still fail, and it is hermetic by
///    construction — a gate skipped for needing a release artifact still owes its self-test here.
/// 2. `release-order-lint.py` always runs; it is locally runnable and named in the skip table only
///    so a prefix match does not swallow it.
/// 3. Otherwise the bare script path is looked up in the skip table.
pub fn partition(discovered: &[String], skips: &[Skip]) -> Partition {
    let mut run = Vec::new();
    let mut skip = Vec::new();
    for inv in discovered {
        if inv.contains("--selftest") {
            run.push(inv.clone());
            continue;
        }
        let script = bare_script(inv);
        if script == "scripts/release-order-lint.py" {
            run.push(inv.clone());
            continue;
        }
        match skips.iter().find(|s| s.script == script) {
            Some(s) => skip.push((inv.clone(), s.reason.clone())),
            None => run.push(inv.clone()),
        }
    }
    Partition { run, skip }
}

/// Cargo invocations `ci.yml` runs that this runner neither runs nor names as CI-only.
pub fn unclassified_cargo(discovered: &[String]) -> Vec<String> {
    discovered
        .iter()
        .filter(|c| !CARGO_LOCAL.contains(&c.as_str()) && cargo_ci_only_reason(c).is_none())
        .cloned()
        .collect()
}

/// The registry-vs-workflow SET EQUALITY that retires `MIN_GATES`.
pub struct GateSetDiff {
    pub registered_but_absent: Vec<String>,
    pub invoked_but_unregistered: Vec<String>,
    /// Excused gates whose written reason no longer describes this tree. They are reported
    /// SEPARATELY from `registered_but_absent` because the fix is a different one: the gate may be
    /// perfectly well covered by some route nobody wrote down, and the entry is what has to change.
    pub unproven_excuses: Vec<String>,
}

impl GateSetDiff {
    pub fn agrees(&self) -> bool {
        self.registered_but_absent.is_empty()
            && self.invoked_but_unregistered.is_empty()
            && self.unproven_excuses.is_empty()
    }
}

/// Compare `{cargo xtask gate <name> in ci.yml}` against `{REGISTRY names}`, and PUT EACH EXCUSE TO
/// THE TREE.
///
/// An excuse used to be a name on a list. A name cannot be wrong, which is why the `denylist`
/// entry's claim survived being false: nothing it asserted was ever compared with anything. Here an
/// entry excuses its gate only while the fact it rests on is still findable — the test that runs
/// it, the release script that runs it — so the excuse rots loudly instead of quietly.
pub fn gate_set_diff(cx: &Ctx, ci_text: &str) -> GateSetDiff {
    let invoked: BTreeSet<String> = discovery::xtask_gate_names(ci_text).into_iter().collect();
    let registered: BTreeSet<String> = gates::names().into_iter().map(str::to_string).collect();

    let mut registered_but_absent = Vec::new();
    let mut unproven_excuses = Vec::new();
    for name in registered.difference(&invoked) {
        match REGISTRY_NOT_IN_CI.iter().find(|(n, _, _)| n == name) {
            None => registered_but_absent.push(name.clone()),
            Some((_, _, excuse)) => {
                if let Err(why) = excuse.holds(cx) {
                    unproven_excuses.push(format!("{name}: {why}"));
                }
            }
        }
    }

    GateSetDiff {
        registered_but_absent,
        invoked_but_unregistered: invoked.difference(&registered).cloned().collect(),
        unproven_excuses,
    }
}

// ---------------------------------------------------------------------------------------------
// the command
// ---------------------------------------------------------------------------------------------

const USAGE: &str = "\
usage:
  cargo xtask full-gate                 run every locally-runnable gate
  cargo xtask full-gate --list          what it would run, and what it deliberately skips
  cargo xtask full-gate --selftest      prove the discovery, the floors and the skip reasons
  cargo xtask full-gate --dump-gates [FILE]
  cargo xtask full-gate --dump-cargo [FILE]";

/// `die()` — exit 2, and it is 2 rather than 1 on purpose: a missing `ci.yml` or a broken discovery
/// is not a gate that failed, it is a runner that cannot say anything.
fn die(msg: String) -> i32 {
    eprintln!("full-gate: {msg}");
    2
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    let flag = args.first().map(String::as_str).unwrap_or("");
    let ci_rel = match flag {
        "--dump-gates" | "--dump-cargo" => args.get(1).map_or(CI_YML, String::as_str),
        _ => CI_YML,
    };

    let Ok(text) = cx.read(ci_rel) else {
        return die(format!(
            "no {ci_rel} -- run this from the repository root. A gate runner that cannot find CI \
             is not a gate runner."
        ));
    };

    let discovered = discovery::script_gates(&text);
    if discovered.len() < MIN_GATES {
        return die(format!(
            "discovered only {} gate invocation(s) in {ci_rel} (floor {MIN_GATES}). The parser is \
             broken, and a broken discovery reports a clean tree.",
            discovered.len()
        ));
    }
    if flag == "--dump-gates" {
        for inv in &discovered {
            println!("{inv}");
        }
        return 0;
    }

    let cargo_found = discovery::cargo_invocations(&text);
    if flag == "--dump-cargo" {
        for c in &cargo_found {
            println!("{c}");
        }
        return 0;
    }

    // THE CARGO FLOOR IS ON THE RUN PATH. In the shell it lived only inside `--selftest`, so a
    // broken cargo parser produced an empty set and every classification below it was vacuous.
    if cargo_found.len() < MIN_CARGO {
        return die(format!(
            "cargo discovery found only {} invocation(s) in {ci_rel} (floor {MIN_CARGO}) -- the \
             parser missed CI build configurations.",
            cargo_found.len()
        ));
    }

    let unclassified = unclassified_cargo(&cargo_found);
    if !unclassified.is_empty() && flag != "--selftest" {
        eprintln!("full-gate: {ci_rel} runs cargo invocation(s) this runner neither runs nor names as CI-only:");
        for c in &unclassified {
            eprintln!("  {c}");
        }
        return die(
            "add each to CARGO_LOCAL (it runs here) or CARGO_CI_ONLY with a reason (it cannot). \
             An unrun configuration is how a local green stops meaning a CI green."
                .to_string(),
        );
    }

    let (skips, must_find) = match load_register(cx) {
        Ok(r) => r,
        Err(e) => return die(e),
    };
    let p = partition(&discovered, &skips);

    if flag == "--list" {
        println!("== CARGO GATES, WILL RUN ({}) ==", CARGO_LOCAL.len());
        for c in CARGO_LOCAL {
            println!("  {c}");
        }
        println!(
            "\n== CARGO GATES, CI-ONLY WITH REASON ({}) ==",
            CARGO_CI_ONLY.len()
        );
        for (c, r) in CARGO_CI_ONLY {
            println!("  {c:<46} {r}");
        }
        println!("\n== WILL RUN ({}) ==", p.run.len());
        for inv in &p.run {
            println!("  {inv}");
        }
        println!("\n== SKIPPED, WITH REASON ({}) ==", p.skip.len());
        for (inv, r) in &p.skip {
            println!("  {inv:<44} {r}");
        }
        return 0;
    }

    if flag == "--selftest" {
        return selftest(
            cx,
            &text,
            &discovered,
            &cargo_found,
            &unclassified,
            &skips,
            &must_find,
        );
    }
    if !flag.is_empty() && flag != "--run" {
        eprintln!("full-gate: unknown flag `{flag}`");
        eprintln!("{USAGE}");
        return 2;
    }

    run_all(cx, &p)
}

/// Run the cargo set, then the script set, then the equality ledger.
fn run_all(cx: &Ctx, p: &Partition) -> i32 {
    println!(
        "== full gate: {} cargo gate(s) + {} script gate(s), {} + {} skipped with reason ==\n",
        CARGO_LOCAL.len(),
        p.run.len(),
        CARGO_CI_ONLY.len(),
        p.skip.len()
    );
    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for cmd in CARGO_LOCAL {
        if run_one(cx, cmd) {
            passed += 1;
        } else {
            failed.push((*cmd).to_string());
        }
    }
    for inv in &p.run {
        if run_one(cx, inv) {
            passed += 1;
        } else {
            failed.push(inv.clone());
        }
    }

    // THE EQUALITY LEDGER, printed green or red. A capability gap that is never named is a gap on
    // its way to being forgotten, so this runs after the verdict is already decided and adds to it
    // rather than gating it.
    println!("\n== equality ledger ==");
    let eq = Command::new("python3")
        .arg("scripts/capability-equality-summary.py")
        .current_dir(cx.root())
        .status();
    if !matches!(&eq, Ok(s) if s.success()) {
        failed.push(
            "scripts/capability-equality-summary.py (qa/capability-equality.json is unreadable or \
             does not tile -- the gap can no longer be named)"
                .to_string(),
        );
    }

    println!("\n== result ==");
    if failed.is_empty() {
        println!(
            "  {passed} gates ran, all pass -- across {} build configurations, not just the \
             default one.",
            CARGO_LOCAL.len()
        );
        println!(
            "  NOT covered by this green ({} script gate(s) needing a release or the fleet, and):",
            p.skip.len()
        );
        for (c, _) in CARGO_CI_ONLY {
            println!("    {c}");
        }
        println!(
            "  Windows is the real gap: it runs the same tests on a platform this host cannot be."
        );
        return 0;
    }
    println!("  {passed} passed, {} FAILED:", failed.len());
    for f in &failed {
        println!("    {f}");
    }
    1
}

/// One gate, with its output captured and only the last 15 lines shown on failure.
fn run_one(cx: &Ctx, cmd: &str) -> bool {
    print!("  {cmd:<58} ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let Some((program, rest)) = tokens.split_first() else {
        println!("FAILED");
        return false;
    };
    let out = Command::new(program)
        .args(rest)
        .current_dir(cx.root())
        .env("RUSTFLAGS", RUSTFLAGS)
        .output();
    match out {
        Ok(o) if o.status.success() => {
            println!("ok");
            true
        }
        Ok(o) => {
            println!("FAILED");
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            let lines: Vec<&str> = text.lines().collect();
            for l in lines.iter().skip(lines.len().saturating_sub(15)) {
                println!("        {l}");
            }
            false
        }
        Err(e) => {
            println!("FAILED");
            println!("        could not run: {e}");
            false
        }
    }
}

/// Prove the discovery, the floors, the skip reasons and the registry set equality.
fn selftest(
    cx: &Ctx,
    text: &str,
    discovered: &[String],
    cargo_found: &[String],
    unclassified: &[String],
    skips: &[Skip],
    must_find: &[String],
) -> i32 {
    let mut bad = false;
    let mut ok = |cond: bool, good: String, bad_msg: String| {
        if cond {
            println!("  [ok]     {good}");
        } else {
            println!("  [FAILED] {bad_msg}");
            bad = true;
        }
    };

    ok(
        discovered.len() >= MIN_GATES,
        format!(
            "discovery found {} invocations (floor {MIN_GATES})",
            discovered.len()
        ),
        format!("discovery found only {}", discovered.len()),
    );

    // The invocations discovery MUST find, read from the register — one per shape the pattern has
    // to keep. The list is data for the same reason the skips are: four of the eight name oracle
    // harness scripts, and this crate does not name a file under `testing/shadow-oracle/` that is
    // not on the segregation gate's data allowlist.
    for must in must_find {
        ok(
            discovered
                .iter()
                .chain(cargo_found.iter())
                .any(|d| d.contains(must.as_str())),
            format!("{must} is discovered"),
            format!("{must} is in ci.yml but was NOT discovered -- the parser missed a real gate"),
        );
    }

    // THE FLOOR MUST BITE. An empty `ci.yml` must be refused, or a broken parser reads as a clean
    // tree — the failure this whole selftest exists for.
    ok(
        discovery::script_gates("").len() < MIN_GATES,
        "an empty ci.yml is REFUSED, so a broken parser cannot report a clean tree".to_string(),
        "an EMPTY ci.yml was accepted -- the floor does not bite".to_string(),
    );

    // Every skip carries a written reason. A skip without one is a gate quietly dropped.
    let unreasoned: Vec<&str> = skips
        .iter()
        .filter(|s| s.reason.trim().is_empty())
        .map(|s| s.script.as_str())
        .collect();
    ok(
        unreasoned.is_empty(),
        format!("all {} skip entries carry a written reason", skips.len()),
        format!("skip entries carry no reason: {unreasoned:?}"),
    );
    let unreasoned: Vec<&str> = CARGO_CI_ONLY
        .iter()
        .filter(|(_, r)| r.trim().is_empty())
        .map(|(c, _)| *c)
        .collect();
    ok(
        unreasoned.is_empty(),
        format!(
            "all {} CI-only cargo entries carry a written reason",
            CARGO_CI_ONLY.len()
        ),
        format!("CI-only cargo entries carry no reason: {unreasoned:?}"),
    );
    let unreasoned: Vec<&str> = REGISTRY_NOT_IN_CI
        .iter()
        .filter(|(_, r, _)| r.trim().is_empty())
        .map(|(n, _, _)| *n)
        .collect();
    ok(
        unreasoned.is_empty(),
        format!(
            "all {} registered-but-not-in-ci entries carry a written reason",
            REGISTRY_NOT_IN_CI.len()
        ),
        format!("registered-but-not-in-ci entries carry no reason: {unreasoned:?}"),
    );

    ok(
        cargo_found.len() >= MIN_CARGO,
        format!(
            "cargo discovery found {} invocations (floor {MIN_CARGO})",
            cargo_found.len()
        ),
        format!("cargo discovery found only {}", cargo_found.len()),
    );
    ok(
        unclassified.is_empty(),
        "every cargo invocation in ci.yml is classified LOCAL or CI-only".to_string(),
        format!("unclassified cargo invocation(s): {unclassified:?}"),
    );

    // THE SET EQUALITY THAT REPLACES `MIN_GATES` FOR THE CONVERTED GATES.
    let diff = gate_set_diff(cx, text);
    ok(
        diff.unproven_excuses.is_empty(),
        format!(
            "each of the {} registered-but-not-in-ci entries still names a place this tree runs \
             the gate",
            REGISTRY_NOT_IN_CI.len()
        ),
        format!(
            "registered-but-not-in-ci entr{y} whose written reason is no longer true of this tree: \
             {:?} -- an excuse nobody can check is how a gate stops running with nothing red",
            diff.unproven_excuses,
            y = if diff.unproven_excuses.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ),
    );
    ok(
        diff.registered_but_absent.is_empty(),
        format!(
            "every one of the {} registered gates is invoked by ci.yml",
            gates::REGISTRY.len()
        ),
        format!(
            "registered gate(s) absent from ci.yml: {:?} -- a gate nothing runs is a gate that \
             cannot fail",
            diff.registered_but_absent
        ),
    );
    ok(
        diff.invoked_but_unregistered.is_empty(),
        "every `cargo xtask gate` invocation in ci.yml names a registered gate".to_string(),
        format!(
            "ci.yml invokes unregistered gate(s): {:?}",
            diff.invoked_but_unregistered
        ),
    );

    // The continuation fixture's three assertions, verbatim.
    let fixture = "xtask/fixtures/full-gate/continuation-ci.yml";
    match cx.read(fixture) {
        Err(_) => ok(
            false,
            String::new(),
            format!(
                "the continuation fixture {fixture} is missing -- the multi-line shape is unproven"
            ),
        ),
        Ok(ftext) => {
            let found = discovery::cargo_invocations(&ftext);
            let want = "cargo test -p busbar-voice --features runtime,test-support -p busbar-streams-codec --features runtime --locked";
            ok(
                found.iter().any(|c| c == want),
                "a cargo invocation continued over three lines is discovered WHOLE".to_string(),
                format!("a three-line continued cargo invocation was not joined; saw {found:?}"),
            );
            ok(
                !found.iter().any(|c| c.contains("--workspace")),
                "the echo, comment and name: lines quoting cargo commands are NOT discovered"
                    .to_string(),
                format!(
                    "discovery invented an invocation from an echo/comment/name: line: {found:?}"
                ),
            );
            ok(
                found.len() == 2,
                "the fixture yields exactly its 2 real invocations, no fragments".to_string(),
                format!(
                    "the fixture yields {} invocations, expected 2: {found:?}",
                    found.len()
                ),
            );
            let fgates = discovery::script_gates(&ftext);
            ok(
                fgates
                    .iter()
                    .any(|g| g.starts_with("bash testing/planted/gate.sh")),
                "a planted testing/planted/gate.sh invocation IS discovered (nested dirs included)"
                    .to_string(),
                format!("a planted testing/ gate invocation was NOT discovered: {fgates:?}"),
            );
        }
    }

    // Two build configurations that must be RUN locally, or a local green would not mean a CI
    // green for anything but the default feature set.
    for config in ["--no-default-features", "--features openapi-schema"] {
        ok(
            CARGO_LOCAL.iter().any(|c| c.contains(config)),
            format!("the {config} configuration is RUN locally"),
            format!(
                "{config} is a CI build configuration this runner does not run -- a local green \
                 would not mean a CI green"
            ),
        );
    }

    // RUSTFLAGS equality, read out of the REAL workflow, never the `--dump-*` override.
    let real = cx.read(CI_YML).unwrap_or_default();
    let ci_flags = real
        .lines()
        .find(|l| l.trim_start().starts_with("RUSTFLAGS:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    ok(
        !ci_flags.is_empty() && ci_flags == RUSTFLAGS,
        format!("ci.yml RUSTFLAGS ({ci_flags}) matches this runner's exported RUSTFLAGS"),
        format!(
            "ci.yml RUSTFLAGS is \"{ci_flags}\" but this runner exports \"{RUSTFLAGS}\" -- a \
             local green would not enforce what CI enforces"
        ),
    );

    // The closure holds a mutable borrow of `bad`; releasing it here is what lets the verdict below
    // read the flag every assertion above wrote to.
    let _ = &ok;
    #[allow(clippy::drop_non_drop)]
    drop(ok);
    if bad {
        println!("\nSELFTEST FAILED");
        return 1;
    }
    println!(
        "\nfull-gate selftest: discovery, floors, skip-reasons and registry equality all hold"
    );
    0
}
