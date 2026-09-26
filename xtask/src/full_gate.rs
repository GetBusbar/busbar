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
//! `cargo xtask gate <name>` in `ci.yml` must be registered, modulo the skip register at
//! [`REGISTER_REL`], whose every [`Skip`] row carries a written reason. A registered gate absent
//! from `ci.yml` is RED, which is the failure `MIN_GATES` could only approximate.
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
    "cargo clippy -p busbar -p busbar-kernel -p busbar-core-admin --all-targets --features openapi-schema --locked -- -D warnings",
    "cargo test -p busbar -p busbar-kernel -p busbar-core-admin --features openapi-schema --locked openapi -- --nocapture",
    "cargo build --locked --bin busbar",
    "cargo test -p busbar --test migration_corpus --locked -- --nocapture",
    "cargo test -p busbar-voice --features runtime,test-support -p busbar-voice-codec --features runtime --locked",
    "cargo test -p busbar-llm --locked --lib unit::",
    "cargo test -p busbar-timing --features timing --locked",
    "cargo build -p xtask --locked",
    "cargo xtask gate kind-isolation --selftest",
    "cargo xtask gate kind-isolation",
    "cargo xtask gate kernel-token-wire-purity --selftest",
    "cargo xtask gate kernel-token-wire-purity",
    "cargo xtask gate money-invariants --selftest",
    "cargo xtask gate money-invariants --posture",
    "cargo xtask gate seal-witness --selftest",
    "cargo xtask gate seal-witness",
    "cargo xtask gate no-float-money --selftest",
    "cargo xtask gate no-float-money",
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
    "cargo xtask gate kind-abi-lane --selftest",
    "cargo xtask gate kind-abi-lane",
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
    "cargo xtask gate conformance-sync --selftest",
    "cargo xtask gate conformance-sync --posture",
    "cargo xtask gate construction --selftest",
    "cargo xtask gate construction --report",
    // The POSTURE form, which is what ci.yml and keep-proof.yml now run as a blocking step. It
    // exits 0 while the gate is red on exactly the rows `gates::REPORT_ONLY` names and 1 on any
    // other red, so unlike the bare scored form it is runnable locally without redding the whole
    // local gate on the standing work — which is precisely why CI can block on it.
    "cargo xtask gate construction --posture",
    "cargo xtask gate design-bindings --selftest",
    "cargo xtask gate design-bindings",
    // The feature-sets job's plugin cdylibs. `busbar-plugin-example-plane` joined the list in
    // ci.yml at 4e39e1a11 (the kind:plane rider `plane_abi_rider.rs` dlopens) and the local copy
    // was never moved with it, so the CI line went unclassified. One list, both places.
    "cargo build --locked -p busbar-store-example-plugin -p busbar-hook-test-plugin -p busbar-auth-static-plugin -p busbar-export-example-plugin -p busbar-plugin-example-plane",
    "cargo xtask gate feature-sets --selftest",
    "cargo xtask gate feature-sets",
    "cargo xtask gate field-inventory --selftest",
    "cargo xtask gate field-inventory",
    "cargo xtask gate inventory-ref --selftest",
    "cargo xtask gate inventory-ref",
    "cargo xtask gate inventory-coverage --selftest",
    "cargo xtask gate inventory-coverage",
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
    "cargo xtask gate structure-lint --posture",
    "cargo xtask gate no-tracked-ignored --selftest",
    "cargo xtask gate no-tracked-ignored",
    "cargo xtask gate package-selectors --selftest",
    "cargo xtask gate package-selectors",
    "cargo xtask gate qa-names --selftest",
    "cargo xtask gate qa-names --posture",
    "cargo xtask gate workspace-deps --selftest",
    "cargo xtask gate workspace-deps",
    "cargo xtask full-gate --selftest",
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
    ("cargo build -p busbar-hashicorp-vault-plugin", "the plugin-proofs job's build of the SECRET kind's real plugin, GetBusbar/hashicorp-vault, checked out BESIDE this tree (its crates name busbar by the sibling path ../../busbar/crates/...). Its working directory is that sibling repo, which a local run of this tree does not have."),
    ("cargo build -p busbar-auth-github-plugin", "the plugin-proofs job's build of the AUTH kind's real plugin, GetBusbar/auth-github, checked out beside this tree the same way; same reason."),
    ("cargo test --locked -p busbar-plugin-loader --lib plugin_proof_tests -- --ignored", "the plugin-proofs job's dlopen of the two sibling-built cdylibs through the dropped-in door. The tests are #[ignore]d here because the artifacts they load exist only after the two sibling builds above, in that job's target dir (BUSBAR_PLUGIN_PROOF_DIR)."),
    ("cargo build -p busbar-transport-tcp --release --locked --features dropped-in", "the build-release job's second invocation: the tcp transport's DROPPED-IN artifact, whose `#[no_mangle]` door is compiled only under `dropped-in` so the fat-LTO release link above sees the handshake symbols once. It exists to feed the `nm -D` check that the `.so` exports its three door symbols -- an ELF release artifact on the Linux runner. The same reason as the release build above: a local release build would re-measure the laptop, and `nm -D` reads the Linux runner's ELF artifact."),
    ("cargo build -p busbar-kernel -p busbar-substrate-values -p busbar-contract --no-default-features --features \"$FEATS\" --locked", "the plane-DELETION matrix build. $FEATS is '${{ matrix.features }}', which expands per kept-plane combination -- a CI matrix construct with no single local form, and the literal string is not a runnable command. It is mirrored locally by the delete-test gate (PLANE-DELETE group), which compiles the neutral crates with a plane removed."),
    ("cargo build -p busbar-kernel -p busbar-substrate-values -p busbar-contract --no-default-features --locked", "the same plane-DELETION matrix build's EMPTY-features arm (every plane removed). Same matrix job, same local mirror in the delete-test gate; listed separately because the step branches on $FEATS and both arms are real invocations."),
    ("cargo test -p busbar-llm --lib alloc_gate -- --nocapture", "the deterministic alloc-count perf gate, invoked BY NAME so a regression reds this one line rather than a 400-test workspace run. The same tests are also executed by 'cargo test --workspace --locked' above, which DOES run locally. (It read '-p busbar-core' here for as long as ci.yml did, matching zero tests in both places — a libtest filter that selects nothing exits 0.)"),
    ("cargo xtask gate ship-ready --selftest", "the SHIP-criterion gate's self-proof. It drives its own `run()` end to end, which means running the construction gate and the kind-isolation SHIP twin over the whole tree AND asking the GitHub checks API for the mutation verdict. The network read is the reason it is not local: `full-gate` is what an agent runs on a laptop before handing back, and a gate leg that needs an authenticated `gh` would make the local runner red for the operator's credentials rather than for the tree. ci.yml's `ship-ready` job runs it on every push, with a token."),
    ("cargo xtask gate ship-ready", "the SHIP criterion itself, and the integration line is not the ship SHA -- the kind-isolation ship twin is red on HEAD by design and the standing-red list is not empty, so this gate is red here for exactly the reasons `gates::REPORT_ONLY` names it. It is a REQUIRED CHECK on `qa` and `main` (scripts/ci-branch-protection.sh), which is the event it is about; running it as part of a local full-gate would red every dev-line run for being on the dev line. DELETE this entry when CONSTRUCTION_STANDING_REDS is empty and the ship twin is green on HEAD."),
    ("cargo clippy ${{ matrix.scope == 'package' && matrix.tests", "the FEATURE-SETS matrix clippy, as discovery reads it (the line is cut at the `||` of its GitHub expression). Its scope is the row's own package list for a single-plane row and '--workspace' otherwise, and '${{ matrix.features }}' expands per feature set -- a CI matrix construct with no single local form, and the literal string is not a runnable command. Its rows are mirrored locally by 'cargo xtask gate feature-sets', which asserts that every non-default feature in the tree is in that matrix or declared covered: the gate holds the matrix's CONTENTS here, and only CI can run its six expansions."),
    ("cargo test ${{ matrix.tests }} --features \"${{ matrix.features }}\" --locked", "the same FEATURE-SETS matrix's test step; '${{ matrix.tests }}' is the row's own package list. Same reason, same local mirror."),
    ("cargo xtask gate construction", "the SCORED-AGAINST-ZERO form of the construction gate, which is RED BY DESIGN on HEAD while the construction work it measures is in flight; running it here would red the whole local gate on a fact nothing scores that way. ci.yml and keep-proof.yml no longer run this form at all: they run 'cargo xtask gate construction --posture' as a BLOCKING step, which is green while the gate is red on exactly the rows gates::REPORT_ONLY names and red on any other row — and that form IS in CARGO_LOCAL and does run locally, alongside '--report'. DELETE this entry when CONSTRUCTION_STANDING_REDS is empty and the bare form is green on HEAD."),
    ("cargo test --workspace --locked --no-run --message-format=json", "the INPUT to the unix `check` job's collected-vs-ran census. It re-resolves the binaries `cargo test --workspace --locked` (above, run locally) has already built and emits cargo's JSON artifact stream; alone it has no verdict. The verdict is the inline python census and the per-binary `--list` loop that read that stream, which are step logic in ci.yml with no local form. Running the bare line here would rebuild nothing and prove nothing."),
    ("cargo xtask gate unconstructed --selftest", CONTENT_DEBT_GATE),
    ("cargo xtask gate unconstructed", CONTENT_DEBT_GATE),
    ("cargo xtask gate sweep-coverage --selftest", CONTENT_DEBT_GATE),
    ("cargo xtask gate sweep-coverage", CONTENT_DEBT_GATE),
    ("cargo xtask gate map-proof --selftest", CONTENT_DEBT_GATE),
    ("cargo xtask gate map-proof", CONTENT_DEBT_GATE),
    ("cargo xtask gate --all", "run by ci.yml's `gate-all` job, PLAINLY — no --report, no continue-on-error, no `|| true` — which the umbrella waits for and declares `# report-only:` (KICKOFF 13.2: before it, `gate --all` ran in no automatic workflow). It is the whole registry in one run and is RED ON HEAD on the gates later phases drain, so in CARGO_LOCAL it would red every local full-gate run on debt this runner cannot excuse; the gates it runs are each ALSO invoked gate-by-gate in ci.yml and classified one by one above (CARGO_LOCAL, or CI-only with their own reason, or excused in REGISTRY_NOT_IN_CI), so omitting the rollup here leaves no gate unaccounted for. DELETE this entry, move the line to CARGO_LOCAL and give the job a RESULTS row in the same commit, when `cargo xtask gate --all` exits 0 on HEAD."),
];

/// The one reason the three `content-debt-gates` gates share (item 6a). Written once so the six
/// lines cannot drift into six stories.
const CONTENT_DEBT_GATE: &str = "run by ci.yml's `content-debt-gates` job, PLAINLY — no --report, no continue-on-error, no `|| true` — which the umbrella waits for and declares `# report-only:`. All three gates (`unconstructed`, `sweep-coverage`, `map-proof`) are RED ON HEAD, self-test and verdict both, on content item 6b (Phase 5) drains, and none has a gates::REPORT_ONLY posture, so neither a `--posture` form nor a green local form exists. In CARGO_LOCAL they would red every local full-gate run on debt this runner cannot excuse. DELETE the gate's two entries, move them to CARGO_LOCAL and give the job a RESULTS row in the same commit, when that gate is green on HEAD.";

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
    /// A FACT IN A NAMED FILE: the needle must appear on an executed line of it. Used where the
    /// file's content IS the claim — a workflow line (`ci.yml` runs `ship-ready`), a branch
    /// protection context — never to claim that a gate RUNS somewhere; that is [`Excuse::ReleaseRun`].
    ReleaseScript(&'static str, &'static str),
    /// A GATE RUN BY A RELEASE SCRIPT, AND THE SCRIPT RUN BY A WORKFLOW. The needle must appear on
    /// an executed line of the script (as for [`Excuse::ReleaseScript`]) AND some
    /// `.github/workflows/*.yml` must execute that script in a form that runs its gates — not its
    /// `--selftest`, `--help` or `--fast` arm. See [`script_run_site`] for why the second half
    /// exists (item 161).
    ReleaseRun(&'static str, &'static str),
}

/// The arms of a release script that do NOT run the gates it names. `--selftest` proves the
/// script's own plumbing, `--help` prints, and `--fast` is PROVISIONAL by its own contract (it
/// exits 3) — none of them is the DONE run a [`Excuse::ReleaseRun`] entry rests on.
const NOT_A_GATE_RUN: &[&str] = &["--selftest", "--help", "-h", "--fast"];

/// WHERE A WORKFLOW RUNS `script` IN A FORM THAT EXECUTES ITS GATES — `Ok(<file>: <line>)`, or the
/// sentence a reader needs.
///
/// `Excuse::ReleaseScript` used to be the whole claim for five registered gates
/// (`plane-purity-strict`, `kind-isolation-ship`, `no-deferral-strict-done`, `reachability`,
/// `instance-noun-neutrality`): "`scripts/verify-1.6.0-done.sh` runs it". It checked the needle was
/// on an executed line of the script and never that anything ran the SCRIPT — and every workflow
/// mention of it was a `#` comment or its `--selftest`, which runs none of the gates (item 161).
/// Five instruments ran on no automated path while `full-gate --selftest` printed that each still
/// named a place this tree runs it. A script is a place a gate runs only when something runs the
/// script.
///
/// A run site is a logical workflow line (comments, `echo` and step `name:` labels dropped by
/// [`crate::yaml_lite::logical_lines`], trailing `#` comments stripped) on which the script path is
/// the COMMAND — at the start, after `bash`/`sh`, or after a shell separator — and whose first
/// argument is not one of [`NOT_A_GATE_RUN`]. A `grep`, `shellcheck` or `cat` of the path is not a
/// run of it.
pub fn script_run_site(cx: &Ctx, script: &str) -> Result<String, String> {
    let files = cx
        .walk(
            &crate::ctx::WalkSpec::new([".github/workflows"])
                .ext("yml")
                .min_files(1),
        )
        .map_err(|e| format!("{e}"))?;
    let mut partial: Vec<String> = Vec::new();
    for f in &files {
        for line in crate::yaml_lite::logical_lines(&f.text) {
            let line = strip_shell_comment(&line);
            let words: Vec<&str> = line.split_whitespace().collect();
            for (i, w) in words.iter().enumerate() {
                if w.trim_start_matches("./") != script {
                    continue;
                }
                let before = if i == 0 { "" } else { words[i - 1] };
                let is_command = matches!(
                    before,
                    "" | "run:" | "-" | "bash" | "sh" | "&&" | "||" | ";" | "then" | "do" | "exec"
                ) || before.ends_with(';');
                if !is_command {
                    continue;
                }
                let arg = words.get(i + 1).copied().unwrap_or("");
                if NOT_A_GATE_RUN.contains(&arg) {
                    partial.push(format!("{} runs only `{script} {arg}`", f.rel_str()));
                    continue;
                }
                return Ok(format!("{}: {}", f.rel_str(), line.trim()));
            }
        }
    }
    Err(format!(
        "no workflow RUNS {script} in a form that executes its gates{} — a gate named by a script \
         nothing runs is a gate that runs nowhere. Wire the script's full run into a workflow, or \
         strike the entry and let the gate be reported",
        if partial.is_empty() {
            String::new()
        } else {
            format!(" ({})", partial.join("; "))
        }
    ))
}

/// WHAT A COMMENT LOOKS LIKE IN THE FILE AN EXCUSE POINTS AT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comments {
    /// `//` to end of line and `/* … */`, with string literals preserved.
    Rust,
    /// `#` at the start of a word, outside a quoted run, to end of line.
    Shell,
}

/// One shell line with its comment removed, quoting respected.
///
/// A `#` opens a comment only when it starts a WORD — which is what keeps `$#`, `${#v}` and a
/// `#` inside `'…'`/`"…"` out of it. `verify-1.6.0-done.sh` labels every step with a quoted
/// string, so a stripper that cut at the first `#` anywhere would blank the half of the line that
/// carries the invocation and revoke an excuse that was never false.
fn strip_shell_comment(line: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut at_word_start = true;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(open) => {
                out.push(c);
                if c == '\\' && open == '"' {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                    continue;
                }
                if c == open {
                    quote = None;
                }
                at_word_start = false;
            }
            None => {
                if c == '#' && at_word_start {
                    break;
                }
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
                at_word_start = c.is_whitespace();
            }
        }
    }
    out
}

/// THE HALF OF A FILE SOMETHING ACTUALLY RUNS — comments blanked, line structure preserved.
///
/// This is the same rule [`discovery::script_gates`] and [`discovery::cargo_invocations`] have
/// always applied to `ci.yml`, and whose absence here was the defect: `full-gate --selftest`
/// prints `[ok] the echo, comment and name: lines quoting cargo commands are NOT discovered`
/// three hundred lines from a check that accepted exactly such a line as proof. The two halves of
/// one file disagreed about whether a comment is evidence.
fn executed_lines(text: &str, style: Comments) -> String {
    match style {
        Comments::Rust => {
            let mut in_block = false;
            text.lines()
                .map(|l| crate::scan::strip_comment_line(l, &mut in_block))
                .collect::<Vec<_>>()
                .join("\n")
        }
        Comments::Shell => text
            .lines()
            .map(strip_shell_comment)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

impl Excuse {
    /// The claim, checked. `Err` carries the sentence a reader needs to act on it.
    ///
    /// **THE SEARCH IS OVER EXECUTED LINES, NOT OVER TEXT.** This used to be a bare
    /// `text.contains(needle)` and the anti-vacuity mechanism was therefore itself vacuous:
    ///
    /// * comment out the one real call site in `xtask/tests/hot_path_gates.rs`, leaving nothing
    ///   but the spelling, and `full-gate --selftest` still printed *"each of the 10
    ///   registered-but-not-in-ci entries still names a place this tree runs the gate"*;
    /// * delete BOTH real invocations of `no-deferral-strict-done` from `verify-1.6.0-done.sh`
    ///   and the excuse held anyway — on the strength of the script's own header comment, which
    ///   is in the shipped tree and needed no plant at all.
    ///
    /// Three gates — `denylist`, `hot-path-perf`, `hot-path-alloc` — are run by NEITHER `ci.yml`
    /// NOR `verify-1.6.0-done.sh`, so for them this string IS the coverage. A name that cannot be
    /// wrong is what this mechanism was built to end, and a name checked by a grep a comment
    /// satisfies is the same defect wearing the fix.
    pub fn holds(&self, cx: &Ctx) -> Result<(), String> {
        let (where_, needle) = match self {
            Excuse::XtaskTest(needle) => ("xtask/tests", *needle),
            Excuse::ReleaseScript(path, needle) | Excuse::ReleaseRun(path, needle) => {
                (*path, *needle)
            }
        };
        // `in_text` is kept ALONGSIDE the verdict so the refusal can tell the two failures apart.
        // "the call site is gone" and "the call site is now a comment" want different edits, and a
        // gap and a failure must never be the same output.
        let (found, in_text) = match self {
            Excuse::XtaskTest(_) => {
                let files = cx
                    .walk(
                        &crate::ctx::WalkSpec::new(["xtask/tests"])
                            .ext("rs")
                            .min_files(1),
                    )
                    .map_err(|e| format!("{e}"))?;
                (
                    files
                        .iter()
                        .any(|f| executed_lines(&f.text, Comments::Rust).contains(needle)),
                    files.iter().any(|f| f.text.contains(needle)),
                )
            }
            Excuse::ReleaseScript(path, _) | Excuse::ReleaseRun(path, _) => {
                let text = cx.read(path)?;
                (
                    executed_lines(&text, Comments::Shell).contains(needle),
                    text.contains(needle),
                )
            }
        };
        match (found, in_text) {
            (true, _) => match self {
                Excuse::ReleaseRun(path, _) => script_run_site(cx, path).map(|_| ()),
                _ => Ok(()),
            },
            (false, true) => Err(format!(
                "the excuse says it runs there, and `{needle}` appears in {where_} ONLY INSIDE A \
                 COMMENT. A gate named in a comment is documentation, not an invocation — the same \
                 rule this file's ci.yml discovery has always applied to an `echo`, a `#` line and \
                 a step `name:`. Restore the call site, or strike the entry and let the gate be \
                 reported"
            )),
            (false, false) => Err(format!(
                "the excuse says it runs there, and `{needle}` appears on no executed line in \
                 {where_} (comments stripped)"
            )),
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
        Excuse::ReleaseRun(
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
        Excuse::ReleaseRun(
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
        Excuse::ReleaseRun(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate no-deferral-strict-done",
        ),
    ),
    (
        "hot-path-perf",
        "the perf witness, staged on integration/oracle-phase2 ahead of the keystone wave that \
         owns ci.yml (.github is off the plane-extraction touch surface). Its coverage is \
         `xtask/tests/hot_path_gates.rs`, which drives the gate through the dispatcher and pins its \
         verdict at green; that test runs under `cargo test --workspace --locked` on every push, \
         the same route the `segregation` entry above rests on. Wire it into ci.yml by name when the \
         keystone rider lands.",
        Excuse::XtaskTest("run(&[\"gate\", \"hot-path-perf\"])"),
    ),
    (
        "hot-path-alloc",
        "the alloc witness, on the same footing as `hot-path-perf`: covered by \
         `xtask/tests/hot_path_gates.rs`, which drives it through the dispatcher under \
         `cargo test --workspace --locked` on every push, and wired into ci.yml by name when the \
         keystone rider lands.",
        Excuse::XtaskTest("run(&[\"gate\", \"hot-path-alloc\"])"),
    ),
    (
        "reachability",
        "every plane in #48's locked roster is served by a unit path the COMPOSITION ROOT actually \
         reaches from `fn main()`. It is RED on HEAD BY DESIGN and it was built to be: the \
         2026-09-22 a2a money findings sat in `crates/busbar/src/root/units_a2a.rs`, whose unit's \
         only call site in the whole crate is under `#[cfg(test)]`, so no corpus cell and no rig \
         leg could have caught them. The gate reds on that module and on four more nobody had \
         written down — `units_voice.rs` (48 construction sites, every one a test), `units_mcp.rs` \
         (1 884 lines declaring no `impl Units for` at all), `money_book.rs` and `vocabulary.rs` \
         (reached by no chain from main) — and PASSES the llm plane, which is live. That \
         separation is its red-before-green proof. Every unreached path either gets switched onto \
         the serving path or gets a written `[[dormant]]` row in qa/reachability.toml, and a \
         declaration whose subject is reached again is STALE and reds. A release-time DONE question \
         on the exact same footing as plane-purity-strict, kind-isolation-ship and \
         instance-noun-neutrality: run by scripts/verify-1.6.0-done.sh (`cargo xtask gate \
         reachability`), not on every push, because a gate that is red every push is a gate \
         somebody puts a `|| true` in front of. MOVE IT TO ci.yml when qa/reachability.toml's \
         findings are drained to declarations or switch-ons.",
        Excuse::ReleaseRun(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate reachability",
        ),
    ),
    (
        "plane-pricing-blindness",
        "DECISION #43's witness — planes always ledger, and the money acts (resolve a card, price, \
         mint a unit key, arithmetic a hold) are kernel-side. It is RED ON HEAD BY DESIGN, and the \
         #83 roster said so before this gate ever measured it: the SPLIT row for \
         busbar-{llm,mcp,a2a,voice} reads `Session, turn and dialect rules -> 16-20. But \
         unit/{admit,approve,meter,route} and runtime/metering.rs decide admission and price - \
         that is defs 5/6, not a plane.` This gate is that sentence made mechanical. It reds on 11 \
         files across busbar-llm and busbar-voice — including `engine/usage.rs`'s \
         `if host.cost_pricing_enabled(..)`, which is the literal branch #43 outlaws — and is \
         GREEN on all five EXTRACTED busbar-plane-* crates, whose 125 `rate_card|nanos|price|spend` \
         grep hits are prose. That separation is its red-before-green proof. Excused from ci.yml \
         because a gate that is red every push is a gate somebody puts a `|| true` in front of; \
         MOVE IT TO ci.yml when qa/plane-pricing-blindness.toml is empty. Its VERDICT is a \
         release-time question (Tier::Full, item 185) and runs in full on the sha being staged: \
         release-stage.yml's `done-oracle` job runs the gate plainly, on every push to qa, and that \
         run gates the promotion. This entry used to rest on the SELFTEST alone \
         (xtask/tests/plane_pricing_blindness.rs, still run under `cargo test --workspace --locked` \
         on every push) — which proves the scanner can be driven red and ran the verdict nowhere.",
        Excuse::ReleaseScript(
            ".github/workflows/release-stage.yml",
            "run: cargo xtask gate plane-pricing-blindness\n",
        ),
    ),
    (
        "instance-noun-neutrality",
        "the plane/transport instance-noun burndown census. It is GREEN only when NO crate names a \
         concrete instance outside its own crate family, and the plane extraction is in flight, so \
         it is RED on HEAD BY DESIGN — every remaining coupling is a tracked row in \
         qa/instance-noun-neutrality.toml. That is a release-time DONE question on the exact same \
         footing as plane-purity-strict and kind-isolation-ship above: run by \
         scripts/verify-1.6.0-done.sh (`cargo xtask gate instance-noun-neutrality`), not on every \
         push, because a gate that is red every push is a gate somebody puts a `|| true` in front of.",
        Excuse::ReleaseRun(
            "scripts/verify-1.6.0-done.sh",
            "cargo xtask gate instance-noun-neutrality",
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
/// 2. Otherwise the bare script path is looked up in the skip table.
///
/// THERE WAS A RULE 2, AND IT WAS DEAD CODE FOR A YEAR OF COMMITS. It read "`release-order-lint.py`
/// always runs; it is locally runnable and named in the skip table only so a prefix match does not
/// swallow it", and it short-circuited the table for that one path. 378572b3f deleted the script on
/// 2026-09-07 and said so in its own message — "full-gate's SKIP_REASON loses its entry AND THE
/// SPECIAL CASE THAT ENTRY NEEDED ... keeping either would leave a waiver that excuses nothing" —
/// but only the shell runner's copy went; the entry came back when 446d771f3 lifted SKIP_REASON
/// into `qa/full-gate.toml`, and this arm came with it. `ci.yml` names the script exactly once, in
/// a `#` comment that `strip_prose` blanks, so `discovered` has not contained it since; the arm and
/// its register row are struck together, 2026-09-22, and the work is now `cargo xtask gate
/// release-order`, which CI invokes as a gate in its own right.
pub fn partition(discovered: &[String], skips: &[Skip]) -> Partition {
    let mut run = Vec::new();
    let mut skip = Vec::new();
    for inv in discovered {
        if inv.contains("--selftest") {
            run.push(inv.clone());
            continue;
        }
        let script = bare_script(inv);
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
    /// Gate names invoked OUTSIDE ci.yml — any other workflow, a `scripts/**/*.sh`, a dispatcher
    /// test under `xtask/tests/` — that the registry does not know, each as `<name> (<file>)`.
    /// See [`invoked_elsewhere`].
    pub invoked_elsewhere_but_unregistered: Vec<String>,
    /// `Tier::Fast` gates whose only route is not a per-push one. See [`tier_contradictions`].
    pub tier_contradictions: Vec<String>,
}

impl GateSetDiff {
    pub fn agrees(&self) -> bool {
        self.registered_but_absent.is_empty()
            && self.invoked_but_unregistered.is_empty()
            && self.unproven_excuses.is_empty()
            && self.invoked_elsewhere_but_unregistered.is_empty()
            && self.tier_contradictions.is_empty()
    }
}

/// A gate name as the registry spells one: `[a-z0-9][a-z0-9-]*`, after the punctuation a shell or
/// Markdown line leaves stuck to it. A `$var`, a `%s`, a `<name>` or a `[a-z…]` regex is not a name
/// and is not reported as an unregistered one.
fn as_gate_name(token: &str) -> Option<&str> {
    let t =
        token.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ';' | ')' | ',' | '.' | ':'));
    let mut chars = t.chars();
    let first = chars.next()?;
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        .then_some(())
        .filter(|()| {
            t.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        .map(|()| t)
}

/// EVERY `cargo xtask gate <name>` THE TREE RUNS OUTSIDE ci.yml, as `(name, file)`.
///
/// The registry-vs-workflow equality reconciled only against `ci.yml` (item 162). `audit-ledger`
/// was deleted from the registry in 647f2fae9 while `scripts/verify-1.6.0-done.sh` still ran
/// `cargo xtask gate audit-ledger --selftest` as a DONE step and `xtask/tests/cli.rs` still asserted
/// it exited 0 — two live callers of a dead name, and nothing compared either with the registry,
/// although every `Excuse::ReleaseScript` entry already pointed the runner at that very script.
/// The scan set is now every place a gate is invoked:
///
/// * every `.github/workflows/*.yml` (the same [`discovery::xtask_gate_names`] reading as ci.yml);
/// * every `scripts/**/*.sh`, over its EXECUTED lines (`#` comments stripped, quoting respected);
/// * every `xtask/tests/*.rs` dispatcher call ASSERTED TO EXIT 0 — `assert_eq!(run(&["gate",
///   "<name>", …]), 0)` / the same for `"selftest"` — over executed lines (comments stripped).
pub fn invoked_elsewhere(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |name: &str, file: String| {
        if !out.iter().any(|(n, f)| n == name && *f == file) {
            out.push((name.to_string(), file));
        }
    };
    let walk = |root: &str, ext: &str| {
        cx.walk(&crate::ctx::WalkSpec::new([root]).ext(ext).min_files(1))
            .map_err(|e| format!("{e}"))
    };
    for f in walk(".github/workflows", "yml")? {
        for name in discovery::xtask_gate_names(&f.text) {
            if let Some(name) = as_gate_name(&name) {
                push(name, f.rel_str());
            }
        }
    }
    for f in walk("scripts", "sh")? {
        let executed = executed_lines(&f.text, Comments::Shell);
        let mut rest = executed.as_str();
        while let Some(i) = rest.find("cargo xtask gate ") {
            rest = &rest[i + "cargo xtask gate ".len()..];
            let token = rest.split_whitespace().next().unwrap_or("");
            if let Some(name) = as_gate_name(token) {
                push(name, f.rel_str());
            }
        }
    }
    for f in walk("xtask/tests", "rs")? {
        let executed = executed_lines(&f.text, Comments::Rust);
        for lead in ["run(&[\"gate\", \"", "run(&[\"selftest\", \""] {
            let mut rest = executed.as_str();
            while let Some(i) = rest.find(lead) {
                rest = &rest[i + lead.len()..];
                let token = rest.split('"').next().unwrap_or("");
                // Only a call ASSERTED TO SUCCEED claims the gate exists. `cli.rs` drives
                // deliberately unknown names (`denylst`, `no-such-gate`) and pins them at 2; those
                // are the dispatcher's own negative controls, not callers of a gate.
                let statement = rest.split(';').next().unwrap_or("");
                let asserts_green = statement.contains("]), 0)");
                if let (Some(name), true) = (as_gate_name(token), asserts_green) {
                    push(name, f.rel_str());
                }
            }
        }
    }
    Ok(out)
}

/// A `Tier::Fast` GATE IS AN EVERY-PUSH GATE, SO ITS ROUTE MUST BE AN EVERY-PUSH ROUTE (item 185).
///
/// `Registration::tier` was read at exactly one place — the `--list` printout — so the field that
/// exists to say "this is a per-push check" or "this is a release-path claim" was a label nothing
/// acted on. It is acted on here, in the one place that knows where each gate runs. `Tier::Fast`
/// is documented as "every push", and a gate is judged every push exactly when `ci.yml` invokes it
/// or its excuse is an [`Excuse::XtaskTest`] that drives its VERDICT (not only its `--selftest`)
/// under `cargo test --workspace --locked`. A `Fast` gate whose only route is a release script, or
/// a self-test, is either mis-tiered or mis-wired; either way the label is false and is reported.
pub fn tier_contradictions(invoked_by_ci: &BTreeSet<String>) -> Vec<String> {
    let tiers: Vec<(&str, gates::Tier)> =
        gates::REGISTRY.iter().map(|r| (r.name, r.tier)).collect();
    tier_contradictions_in(&tiers, REGISTRY_NOT_IN_CI, invoked_by_ci)
}

/// [`tier_contradictions`] over an explicit registry and excuse list, so the rule can be put to a
/// synthetic population whose right answer is known.
fn tier_contradictions_in(
    tiers: &[(&str, gates::Tier)],
    excuses: &[(&str, &str, Excuse)],
    invoked_by_ci: &BTreeSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for &(name, tier) in tiers {
        if tier != gates::Tier::Fast || invoked_by_ci.contains(name) {
            continue;
        }
        let per_push = excuses.iter().find(|(n, _, _)| *n == name).is_some_and(
            |(_, _, e)| matches!(e, Excuse::XtaskTest(needle) if !needle.contains("--selftest")),
        );
        if !per_push {
            out.push(format!(
                "{name}: Tier::Fast (every push) but ci.yml does not invoke it and its only route \
                 is not a per-push run of its verdict"
            ));
        }
    }
    out
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

    let invoked_elsewhere_but_unregistered = match invoked_elsewhere(cx) {
        Ok(found) => found
            .into_iter()
            .filter(|(n, _)| !registered.contains(n))
            .map(|(n, f)| format!("{n} ({f})"))
            .collect(),
        // A scan that could not read is not a scan that found nothing.
        Err(e) => vec![format!("the scan outside ci.yml could not run: {e}")],
    };

    GateSetDiff {
        registered_but_absent,
        invoked_but_unregistered: invoked.difference(&registered).cloned().collect(),
        unproven_excuses,
        invoked_elsewhere_but_unregistered,
        tier_contradictions: tier_contradictions(&invoked),
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
    // to keep. The list is data for the same reason the skips are: it names paths under `testing/`,
    // and this crate does not name a file under `testing/shadow-oracle/` that is not on the
    // segregation gate's data allowlist. (It said "four of the eight name oracle harness scripts"
    // until 2026-09-22; the list holds six entries and the oracle harness left this tree in
    // c73ae4f66, so the sentence counted two things that were both already untrue.)
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
    ok(
        diff.invoked_elsewhere_but_unregistered.is_empty(),
        "every `cargo xtask gate` invocation in the other workflows, scripts/**/*.sh and \
         xtask/tests names a registered gate"
            .to_string(),
        format!(
            "invoked outside ci.yml but not registered: {:?} -- a dead gate name exits 2 at \
             whatever runs it, which is an argument error standing where a verdict should be",
            diff.invoked_elsewhere_but_unregistered
        ),
    );
    ok(
        diff.tier_contradictions.is_empty(),
        "every Tier::Fast gate is judged on every push".to_string(),
        format!(
            "Tier::Fast gate(s) with no per-push route: {:?} -- re-tier the gate in \
             xtask/src/gates/mod.rs or wire its verdict into ci.yml",
            diff.tier_contradictions
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
            let want = "cargo test -p busbar-voice --features runtime,test-support -p busbar-voice-codec --features runtime --locked";
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

// ---------------------------------------------------------------------------------------------
// THE EXCUSE MECHANISM, PUT TO ITSELF
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::{Overlay, WalkSpec};

    fn tree() -> Ctx {
        Ctx::workspace().expect("a workspace context")
    }

    fn excuse_for(gate: &str) -> Excuse {
        REGISTRY_NOT_IN_CI
            .iter()
            .find(|(n, _, _)| *n == gate)
            .map(|(_, _, e)| *e)
            .unwrap_or_else(|| panic!("{gate} is not in REGISTRY_NOT_IN_CI"))
    }

    fn needle_of(e: &Excuse) -> &'static str {
        match e {
            Excuse::XtaskTest(n) => n,
            Excuse::ReleaseScript(_, n) | Excuse::ReleaseRun(_, n) => n,
        }
    }

    /// THE WORKFLOW HALF OF A `ReleaseRun` EXCUSE, PLANTED. `overlay` gets a job appended to
    /// ci.yml whose one step RUNS `script` in full — the shape a release workflow would carry — so
    /// the shell plants below have a baseline where the excuse HOLDS, whatever today's workflows
    /// say. Without it those plants would move a row that is already red (item 89's PROOF
    /// IMPOSSIBLE): no workflow on this tree runs `verify-1.6.0-done.sh` in full (item 161).
    fn plant_full_run(cx: &Ctx, ov: &mut Overlay, script: &str) {
        let ci = cx.read(CI_YML).expect("ci.yml");
        ov.set(
            CI_YML,
            format!(
                "{ci}\n  planted-release-run:\n    runs-on: ubuntu-latest\n    steps:\n      \
                 - run: bash {script}\n"
            ),
        );
    }

    /// Every workflow line that names `script` rewritten to its `--selftest` arm: the baseline in
    /// which no workflow runs the script's gates, independent of what today's workflows carry.
    fn only_selftest_runs(cx: &Ctx, ov: &mut Overlay, script: &str) {
        let files = cx
            .walk(&WalkSpec::new([".github/workflows"]).ext("yml").min_files(1))
            .expect("workflows");
        for f in &files {
            if !f.text.contains(script) {
                continue;
            }
            let out: String = f
                .text
                .lines()
                .map(|l| match l.find(script) {
                    Some(i) if !l.trim_start().starts_with('#') => {
                        format!("{}{script} --selftest\n", &l[..i])
                    }
                    _ => format!("{l}\n"),
                })
                .collect();
            ov.set(&f.rel, out);
        }
    }

    /// ITEM 161: A RELEASE SCRIPT NOTHING RUNS IS NOT A PLACE A GATE RUNS. With every workflow
    /// running the script only as `--selftest` — which is this tree — each of the five
    /// release-script excuses must FAIL, naming that no workflow runs the script; plant one full
    /// run and the same excuses hold. A `grep` or `shellcheck` of the path is not a run of it.
    #[test]
    fn a_release_script_excuse_holds_only_while_a_workflow_runs_the_script() {
        let cx = tree();
        let release: Vec<(&str, Excuse)> = REGISTRY_NOT_IN_CI
            .iter()
            .filter(|(_, _, e)| matches!(e, Excuse::ReleaseRun(..)))
            .map(|(n, _, e)| (*n, *e))
            .collect();
        assert_eq!(
            release.len(),
            5,
            "the five release-script gates: {:?}",
            release.iter().map(|r| r.0).collect::<Vec<_>>()
        );
        let script = "scripts/verify-1.6.0-done.sh";

        let mut ov = Overlay::new();
        only_selftest_runs(&cx, &mut ov, script);
        let base = cx.with_overlay(ov.clone()).read(CI_YML).expect("ci.yml");
        ov.set(
            CI_YML,
            format!(
                "{base}\n  not-a-run:\n    runs-on: ubuntu-latest\n    steps:\n      \
                 - run: shellcheck {script}\n      - run: grep -c gate {script}\n"
            ),
        );
        let unrun = cx.with_overlay(ov.clone());
        for (name, e) in &release {
            let why = e.holds(&unrun).expect_err(&format!(
                "{name}: a script no workflow runs still excused the gate"
            ));
            assert!(why.contains("no workflow RUNS"), "{name}: {why}");
        }

        plant_full_run(&unrun, &mut ov, script);
        let run = cx.with_overlay(ov);
        for (name, e) in &release {
            assert!(e.holds(&run).is_ok(), "{name}: {:?}", e.holds(&run));
        }
    }

    /// ITEM 162: A DEAD GATE NAME IN THE RELEASE ORACLE IS REPORTED. The exact shape the audit
    /// measured — `cargo xtask gate audit-ledger --selftest` on an executed line of
    /// `verify-1.6.0-done.sh`, after the registry dropped `audit-ledger` — plus the same name in
    /// another workflow and in a dispatcher test asserted green. The same name inside a `#` comment
    /// or pinned at exit 2 is NOT a caller.
    #[test]
    fn a_gate_name_the_registry_dropped_is_reported_wherever_it_is_still_invoked() {
        let cx = tree();
        let before: Vec<String> = gate_set_diff(&cx, &cx.read(CI_YML).expect("ci.yml"))
            .invoked_elsewhere_but_unregistered;
        assert!(before.is_empty(), "the control is already red: {before:?}");

        let script = "scripts/verify-1.6.0-done.sh";
        let mut ov = Overlay::new();
        let text = cx.read(script).expect(script);
        ov.set(
            script,
            format!(
                "{text}\n# cargo xtask gate commented-dead-gate\nstep audit cargo xtask gate \
                 audit-ledger --selftest\n"
            ),
        );
        let wf = ".github/workflows/sched-oracle-store-cells.yml";
        let wtext = cx.read(wf).expect(wf);
        ov.set(
            wf,
            format!(
                "{wtext}\n  dead:\n    steps:\n      - run: cargo xtask gate workflow-dead-gate\n"
            ),
        );
        let t = "xtask/tests/cli.rs";
        let ttext = cx.read(t).expect(t);
        ov.set(
            t,
            format!(
                "{ttext}\n#[test]\nfn planted() {{\n    assert_eq!(run(&[\"gate\", \"test-dead-gate\"]), 0);\n    \
                 assert_eq!(run(&[\"gate\", \"negative-control\"]), 2);\n}}\n"
            ),
        );
        let planted = cx.with_overlay(ov);
        let diff = gate_set_diff(&planted, &planted.read(CI_YML).expect("ci.yml"));
        let got = diff.invoked_elsewhere_but_unregistered.join(" | ");
        for want in [
            "audit-ledger (scripts/verify-1.6.0-done.sh)",
            "workflow-dead-gate (.github/workflows/sched-oracle-store-cells.yml)",
            "test-dead-gate (xtask/tests/cli.rs)",
        ] {
            assert!(got.contains(want), "missing {want}: {got}");
        }
        for not in ["commented-dead-gate", "negative-control"] {
            assert!(!got.contains(not), "{not} is not a caller: {got}");
        }
        assert!(!diff.agrees());
    }

    /// ITEM 185: `Tier::Fast` is ACTED ON. A Fast gate is judged every push only when ci.yml runs
    /// it or an `XtaskTest` excuse drives its verdict; a Fast gate whose route is a release script
    /// or a self-test alone is a contradiction, and a Full/Release gate on a release route is not.
    #[test]
    fn a_fast_gate_without_a_per_push_route_is_a_tier_contradiction() {
        use crate::gates::Tier;
        let tiers = [
            ("in-ci", Tier::Fast),
            ("test-verdict", Tier::Fast),
            ("test-selftest-only", Tier::Fast),
            ("release-only", Tier::Fast),
            ("unexcused", Tier::Fast),
            ("release-full", Tier::Full),
            ("release-release", Tier::Release),
        ];
        let excuses: [(&str, &str, Excuse); 5] = [
            (
                "test-verdict",
                "r",
                Excuse::XtaskTest("run(&[\"gate\", \"test-verdict\"])"),
            ),
            (
                "test-selftest-only",
                "r",
                Excuse::XtaskTest("run(&[\"gate\", \"test-selftest-only\", \"--selftest\"])"),
            ),
            (
                "release-only",
                "r",
                Excuse::ReleaseRun("scripts/x.sh", "cargo xtask gate release-only"),
            ),
            (
                "release-full",
                "r",
                Excuse::ReleaseRun("scripts/x.sh", "cargo xtask gate release-full"),
            ),
            (
                "release-release",
                "r",
                Excuse::ReleaseRun("scripts/x.sh", "cargo xtask gate release-release"),
            ),
        ];
        let ci: BTreeSet<String> = ["in-ci".to_string()].into_iter().collect();
        let got: Vec<String> = tier_contradictions_in(&tiers, &excuses, &ci)
            .into_iter()
            .map(|l| l.split(':').next().unwrap_or("").to_string())
            .collect();
        assert_eq!(got, ["test-selftest-only", "release-only", "unexcused"]);
    }

    /// THE CONTROL. Every excuse on the register still holds over the tree as it stands — which is
    /// what makes the two plants below evidence rather than noise. If this one fails, the plants
    /// prove nothing, because a needle that is already absent would "not hold" for the wrong reason.
    #[test]
    fn every_registered_excuse_holds_on_this_tree() {
        let cx = tree();
        let bad: Vec<String> = REGISTRY_NOT_IN_CI
            .iter()
            .filter_map(|(n, _, e)| e.holds(&cx).err().map(|w| format!("{n}: {w}")))
            .collect();
        assert!(
            bad.is_empty(),
            "an excuse on the register no longer names a place this tree runs the gate:\n{bad:#?}"
        );
    }

    /// PLANT A — RUST. Comment out the one real call site, leave the SPELLING behind. This is the
    /// exact shape the instrument audit measured passing: `full-gate --selftest` printed
    /// `[ok] each of the 10 registered-but-not-in-ci entries still names a place this tree runs the
    /// gate` over a test that had been reduced to `assert!(true)`.
    #[test]
    fn a_rust_call_site_that_is_only_a_comment_does_not_hold() {
        let cx = tree();
        let excuse = excuse_for("hot-path-perf");
        let needle = needle_of(&excuse);
        assert!(
            excuse.holds(&cx).is_ok(),
            "the control failed BEFORE the plant, so the plant would prove nothing: {:?}",
            excuse.holds(&cx)
        );

        let files = cx
            .walk(&WalkSpec::new(["xtask/tests"]).ext("rs").min_files(1))
            .expect("xtask/tests");
        let mut ov = Overlay::new();
        let (mut commented_out, mut survives_as_text) = (0usize, 0usize);
        for f in &files {
            if !f.text.contains(needle) {
                continue;
            }
            let mut out = String::new();
            for line in f.text.lines() {
                if line.contains(needle) {
                    commented_out += 1;
                    out.push_str(&format!(
                        "    // PLANTED: the real call is gone; only the SPELLING {} remains.\n",
                        line.trim()
                    ));
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            survives_as_text += out.matches(needle).count();
            ov.set(&f.rel, out);
        }

        // THE PLANT LANDED, PROVEN BEFORE THE VERDICT IS BELIEVED. A plant that silently failed to
        // plant is indistinguishable from an instrument that cannot see; and a plant that DELETED
        // the needle rather than commenting it out would make the assertion below pass for a
        // reason that has nothing to do with comments.
        assert!(
            commented_out >= 1,
            "the needle {needle:?} sits on no line under xtask/tests — nothing was planted"
        );
        assert!(
            survives_as_text >= commented_out,
            "the plant DELETED the needle instead of commenting it out; \
             {survives_as_text} occurrence(s) survive, {commented_out} line(s) were commented"
        );

        let why = excuse
            .holds(&cx.with_overlay(ov))
            .expect_err("a needle surviving only inside a `//` comment still satisfied the excuse");
        assert!(
            why.contains("ONLY INSIDE A COMMENT"),
            "the refusal does not say WHY: {why}"
        );
    }

    /// PLANT B — SHELL, and the audit needed no plant at all for the second half of it: the needle
    /// `cargo xtask gate no-deferral-strict-done` survives inside `verify-1.6.0-done.sh`'s own
    /// header comment on line 30. Deleting both real invocations left the excuse holding.
    #[test]
    fn a_shell_call_site_that_is_only_a_comment_does_not_hold() {
        let tree_cx = tree();
        let excuse = excuse_for("no-deferral-strict-done");
        let (path, needle) = match excuse {
            Excuse::ReleaseRun(p, n) => (p, n),
            _ => panic!("no-deferral-strict-done is a release-script excuse"),
        };
        // THE BASELINE WHERE THE WORKFLOW HALF HOLDS, so the plant moves only the script half.
        let mut base = Overlay::new();
        plant_full_run(&tree_cx, &mut base, path);
        let cx = tree_cx.with_overlay(base.clone());
        assert!(
            excuse.holds(&cx).is_ok(),
            "the control failed BEFORE the plant: {:?}",
            excuse.holds(&cx)
        );

        let text = cx.read(path).expect(path);
        let mut out = String::new();
        let (mut deleted, mut left_in_comments) = (0usize, 0usize);
        for line in text.lines() {
            let is_comment = line.trim_start().starts_with('#');
            if line.contains(needle) {
                if is_comment {
                    left_in_comments += 1;
                } else {
                    deleted += 1;
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        assert!(
            deleted >= 1,
            "the needle {needle:?} is on no executed line of {path} — nothing was planted"
        );
        if left_in_comments == 0 {
            // The shipped header comment is what made this real; if it ever goes, the plant states
            // the condition itself rather than quietly becoming a different test.
            out.push_str(&format!(
                "#   no-deferral      {needle} (nothing deferred).\n"
            ));
            left_in_comments = 1;
        }
        assert!(left_in_comments >= 1);
        assert!(
            out.contains(needle),
            "read-back: the needle must SURVIVE in the planted text, in a comment"
        );

        let mut ov = base;
        ov.set(path, out);
        let why = excuse
            .holds(&tree_cx.with_overlay(ov))
            .expect_err("a needle surviving only inside a `#` comment still satisfied the excuse");
        assert!(
            why.contains("ONLY INSIDE A COMMENT"),
            "the refusal does not say WHY: {why}"
        );
    }

    /// THE OTHER DIRECTION — the stripper must not over-reach. A real call site that happens to
    /// carry a trailing comment is still a real call site, in both languages. Without this, a
    /// tighter grep would read as a fix while quietly revoking excuses that were never false.
    #[test]
    fn a_trailing_comment_on_an_executed_line_still_holds() {
        let tree_cx = tree();
        // The workflow half of `reachability`'s ReleaseRun excuse, planted, so this case judges
        // only the comment stripper (item 161: no workflow on this tree runs the script in full).
        let mut base = Overlay::new();
        plant_full_run(&tree_cx, &mut base, "scripts/verify-1.6.0-done.sh");
        let cx = tree_cx.with_overlay(base.clone());

        let rust = excuse_for("hot-path-alloc");
        let rust_needle = needle_of(&rust);
        let files = cx
            .walk(&WalkSpec::new(["xtask/tests"]).ext("rs").min_files(1))
            .expect("xtask/tests");
        let mut ov = base.clone();
        let mut touched = 0usize;
        for f in &files {
            if !f.text.contains(rust_needle) {
                continue;
            }
            let mut out = String::new();
            for line in f.text.lines() {
                if line.contains(rust_needle) {
                    touched += 1;
                    out.push_str(line);
                    out.push_str(" // still executed, and the needle is before this comment\n");
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            ov.set(&f.rel, out);
        }
        assert!(touched >= 1, "nothing was planted for the Rust half");

        let shell = excuse_for("reachability");
        let (path, shell_needle) = match shell {
            Excuse::ReleaseRun(p, n) => (p, n),
            _ => panic!("reachability is a release-script excuse"),
        };
        let text = cx.read(path).expect(path);
        let mut out = String::new();
        let mut shell_touched = 0usize;
        for line in text.lines() {
            if line.contains(shell_needle) && !line.trim_start().starts_with('#') {
                shell_touched += 1;
                out.push_str(line);
                out.push_str("   # still executed\n");
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        assert!(shell_touched >= 1, "nothing was planted for the shell half");
        ov.set(path, out);

        let planted = tree_cx.with_overlay(ov);
        assert!(
            rust.holds(&planted).is_ok(),
            "a Rust call site with a trailing comment stopped counting: {:?}",
            rust.holds(&planted)
        );
        assert!(
            shell.holds(&planted).is_ok(),
            "a shell call site with a trailing comment stopped counting: {:?}",
            shell.holds(&planted)
        );
    }

    /// A `#` inside a quoted run is not a comment. `verify-1.6.0-done.sh` labels its steps with
    /// quoted strings, and a stripper that cut at the first `#` anywhere would blank the half of
    /// the line that carries the invocation.
    #[test]
    fn a_hash_inside_quotes_is_not_a_shell_comment() {
        assert_eq!(
            strip_shell_comment(
                "step \"no-deferral #84\" cargo xtask gate no-deferral-strict-done"
            ),
            "step \"no-deferral #84\" cargo xtask gate no-deferral-strict-done"
        );
        assert_eq!(strip_shell_comment("#   cargo xtask gate x"), "");
        assert_eq!(
            strip_shell_comment("run_it    # cargo xtask gate x"),
            "run_it    "
        );
        // `$#` and `${#v}` are parameter expansions, not comments.
        assert_eq!(strip_shell_comment("echo $# ${#v}"), "echo $# ${#v}");
    }
}
