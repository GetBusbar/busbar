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
pub mod config_schema;
pub mod conformance_sync;
pub mod construction;
pub mod denylist_gate;
pub mod design_bindings;
pub mod duplex_ws_default_edge;
pub mod feature_sets;
pub mod field_inventory;
pub mod hot_path_alloc;
pub mod hot_path_perf;
pub mod instance_noun_neutrality;
pub mod inventory_coverage;
pub mod inventory_ref;
pub mod kernel_token_wire_purity;
pub mod kind_abi_lane;
pub mod kind_isolation;
pub mod map_proof;
pub mod money_invariants;
pub mod no_deferral;
pub mod no_float_money;
pub mod no_self_filed_issues;
pub mod no_tracked_ignored;
pub mod package_selectors;
pub mod plane_abi_neutrality;
pub mod plane_pricing_blindness;
pub mod plane_purity;
pub mod plane_transport_neutrality;
pub mod population;
pub mod qa_gate_dispatch;
pub mod qa_names;
pub mod reachability;
pub mod release_order;
pub mod response_header;
pub mod seal_witness;
pub mod segregation;
pub mod service_images;
pub mod settings_leak;
pub mod ship_ready;
pub mod structure_lint;
pub mod sweep_coverage;
pub mod teller_steps;
pub mod tracing;
pub mod unconstructed;
pub mod workspace_deps;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
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
/// kind-isolation-ship` — because both are red on HEAD for reasons nothing here knew about. The
/// workflow that ran it then (`keep-proof.yml`, now the dispatch-only `manual-keep-proof.yml`) was
/// the only judge of an agent hand-back, and its gate job was permanently red: a real regression
/// was indistinguishable from the standing red. The runner this vocabulary serves TODAY is
/// [`ALL_RUNNER`] — ci.yml's `gate-all` job, `cargo xtask gate --all` on every push — and a test
/// (`posture_tests::the_all_runner_this_vocabulary_serves_is_invoked`) holds that it still is, so
/// this paragraph cannot outlive its workflow a second time. Two excuse vocabularies existed — this one, and
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
/// WHERE `cargo xtask gate --all` RUNS, which is the whole reason [`REPORT_ONLY`] exists: the file
/// and the needle, checked over executed lines by `full_gate::Excuse::holds`.
pub const ALL_RUNNER: crate::full_gate::Excuse = crate::full_gate::Excuse::ReleaseScript(
    ".github/workflows/ci.yml",
    "run: cargo xtask gate --all\n",
);

pub const REPORT_ONLY: &[Posture] = &[
    Posture {
        name: "construction",
        why: "RED BY DESIGN on HEAD while the construction work it measures is in flight — but \
              red about a NAMED, FINITE list of rows and nothing else",
        excuse: Excused::OnlyRows(StandingReds {
            rows: CONSTRUCTION_STANDING_REDS,
            list: "CONSTRUCTION_STANDING_REDS",
            mirror: Some("land_construction_standing_reds in scripts/land.sh"),
        }),
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
        name: "instance-noun-neutrality",
        why: "THE WHOLE-APP KIND-NEUTRALITY WITNESS, and it is RED BY DESIGN on HEAD: real \
              cross-family couplings exist today (the composition root names every plane, auth \
              schemes are DECISION #3 internal-unit debt in core, sibling planes reference one \
              another) and each is recorded in qa/instance-noun-neutrality.toml as a KNOWN-DEBT \
              burndown row. It goes green only as those rows are drained. Every per-noun census \
              row names the needle below; the `:undocumented` and `:stale-baseline` rows do NOT, \
              so a NEW coupling or a stale ledger row is scored under `--all` exactly like any \
              other regression.",
        excuse: Excused::OnlyAbout("tracked known-debt"),
    },
    Posture {
        name: "plane-pricing-blindness",
        why: "DECISION #43's WITNESS — planes always ledger, and the money acts are kernel-side. \
              RED BY DESIGN on HEAD: the #83 roster's own SPLIT row says of busbar-{llm,mcp,a2a,\
              voice} that `unit/{admit,approve,meter,route}` and `runtime/metering.rs` decide \
              admission and price, `that is defs 5/6, not a plane` — so the debt is named in the \
              roster before this gate ever measured it, and every live file is a row in \
              qa/plane-pricing-blindness.toml. The five EXTRACTED busbar-plane-* crates are \
              already clean and the gate is what keeps them that way. It goes green when the \
              baseline is empty. Every census row names the needle below; the `:undocumented` and \
              `:stale-baseline` rows do NOT, so a NEW money reference landing in a plane, or a \
              ledger row that outlived its debt, is scored under `--all` like any regression.",
        excuse: Excused::OnlyAbout("tracked money debt"),
    },
    Posture {
        name: "reachability",
        why:
            "THE PLANE-ROSTER REACHABILITY WITNESS, and it is RED BY DESIGN on HEAD: it was built \
              on 2026-09-22 to red on `crates/busbar/src/root/units_a2a.rs`, which ships three \
              money faults in a module whose unit's only construction site in the crate is under \
              `#[cfg(test)]`. A gate that did not red there would not work. It also reds on four \
              more nobody had written down (units_voice, units_mcp, money_book, vocabulary) and \
              PASSES units_llm, which is live. It is a release-time claim — \
              scripts/verify-1.6.0-done.sh runs it, full_gate's own excuse table is where that is \
              written down and checked — and every row it is red about is printed in full on every \
              run, so a red that is not counted here is never a red that was not mentioned. DELETE \
              THIS POSTURE when qa/reachability.toml's findings are drained (each either switched \
              on or declared) and the gate is green on HEAD.",
        excuse: Excused::ReleaseTime,
    },
    Posture {
        name: "qa-names",
        why:
            "GREEN, AND HELD THERE BY NAME. This entry once said the list was empty and the gate \
              green outright while the gate was red, so the blocking `cargo xtask gate qa-names \
              --posture` step in ci.yml exited 1 on a tree nobody had touched (item 176). Its one \
              red, `qa-names:path-names-a-live-path` on xtask/src/audit.rs's `REGISTER_REL`, is \
              drained by a written declaration beside the const and QA_NAMES_STANDING_REDS is \
              empty again. Every row of this gate is scored like any gate's: a new dead name, a \
              kind that names no key, a scan that collapsed or a stale declaration reds `--all` \
              and `--posture` alike, and a name added to the list that is not red is STALE and \
              reds them too. `posture_tests::the_qa_names_posture_holds_on_the_tree` runs the real gate \
              and holds this entry to what it says.",
        excuse: Excused::OnlyRows(StandingReds {
            rows: QA_NAMES_STANDING_REDS,
            list: "QA_NAMES_STANDING_REDS",
            mirror: None,
        }),
    },
    Posture {
        name: "money-invariants",
        why: "GREEN, AND EVERY ROW IS SCORED. Item 9 pointed this gate at the record production \
              actually journals — busbar-kernel-audit/src/record.rs — and \
              `money-invariants:no-stored-price` went red on three stored priced figures there: \
              `AuditRecord.amount`, `Amount.priced` and `HookApplied.priced_delta` (#77(3): price \
              is never stored). DRAINED in Phase 2 (W2.12): the record carries `usage: Usage` — \
              counts plus the tier, fee count and card version a read-time price takes — and the \
              digest recipe became `busbar.audit.digest.v2`, published beside v1, so \
              MONEY_INVARIANTS_STANDING_REDS is empty. The currency field in the SIGNED audit \
              digest is item 34, owner-owed. A stored price, a plugin-keyed money field or a seal \
              outside core reds `--all` and `--posture` alike, and a name added to the list that \
              is not red is STALE and reds them too. \
              `posture_tests::the_money_invariants_posture_holds_on_the_tree` runs the real gate \
              and holds this entry to what it says.",
        excuse: Excused::OnlyRows(StandingReds {
            rows: MONEY_INVARIANTS_STANDING_REDS,
            list: "MONEY_INVARIANTS_STANDING_REDS",
            mirror: None,
        }),
    },
    Posture {
        name: "conformance-sync",
        why: "RED ON ONE NAMED ROW, AND IT IS THE TRUE FINDING. `conformance:freshness` honours a \
              pass only if its verdict commit IS the commit under judgement (item 165), and \
              KICKOFF 7.3 rules that every commit to predev invalidates every conformance pass: \
              STALE is normal in flight, shown on every push and not blocking it. DRAIN: KICKOFF \
              7.4, Phase 5, on the release sha, where the suites are re-run on that sha and the \
              row goes green; strike the name from CONFORMANCE_SYNC_STANDING_REDS in that commit. \
              Every OTHER row of this gate (registry, manifest-drift, coverage, readme-drift, \
              no-orphan-claim) is scored like any gate's, so a drifted manifest or a hand-added \
              claim reds `--all` and `--posture` alike. \
              `posture_tests::the_conformance_sync_posture_holds_on_the_tree` runs the real gate \
              and holds this entry to what it says.",
        excuse: Excused::OnlyRows(StandingReds {
            rows: CONFORMANCE_SYNC_STANDING_REDS,
            list: "CONFORMANCE_SYNC_STANDING_REDS",
            mirror: None,
        }),
    },
    Posture {
        name: "structure-lint",
        why: "RED ON FOUR NAMED ROWS, AND THEY ARE TRUE FINDINGS. be9c473f5 derived the plane set, \
              the protocol crates and the tree-wide scope from the tree instead of from lists that \
              had gone stale, and the lint then saw what it had been blind to: \
              `plane-dup:unledgered` (24 plane-local reimplementations of a shared concern), \
              `plane-dup:stale-ledger` (3 ledger rows that outlived their duplication), \
              `axis:purity` (4 places the agnostic core asks an axis its identity) and \
              `census:count` (3 shared words with a second spelling). DRAIN: Phase 4, when the \
              plane owners dedupe or sign ledger rows; strike each name from \
              STRUCTURE_LINT_STANDING_REDS in the commit that turns its row green. Every OTHER row \
              of this gate is scored like any gate's, so a new red anywhere else reds `--all` and \
              the blocking `--posture` step in ci.yml alike, and a listed row that goes green \
              without its strike is STALE and reds them too. \
              `posture_tests::the_structure_lint_posture_holds_on_the_tree` runs the real gate and \
              holds this entry to what it says.",
        excuse: Excused::OnlyRows(StandingReds {
            rows: STRUCTURE_LINT_STANDING_REDS,
            list: "STRUCTURE_LINT_STANDING_REDS",
            mirror: None,
        }),
    },
    Posture {
        name: "ship-ready",
        why: "THE SHIP CRITERION, and the integration line is not the ship SHA. Every one of its \
              rows is a claim about a tree that is ready to promote — the twin at zero, the \
              ceilings tight, nothing standing red, the mutants caught — and this tree is \
              deliberately none of those things yet. It is a REQUIRED CHECK on `qa` and `main`, \
              which is where the claim is meant to bite and where branch protection scores it; \
              `--all` on the dev line is not. It cannot be `ReleaseTime`: ci.yml DOES invoke it, so \
              it has no `full_gate::REGISTRY_NOT_IN_CI` entry for that arm to read, and the arm \
              excused nothing. The excuse is the two facts the promotion claim turns on.",
        excuse: Excused::RequiredAtPromotion(&[
            crate::full_gate::Excuse::ReleaseScript(
                ".github/workflows/ci.yml",
                "run: cargo xtask gate ship-ready\n",
            ),
            crate::full_gate::Excuse::ReleaseScript(
                "scripts/ci-branch-protection.sh",
                "\"ship-ready\"",
            ),
        ]),
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
/// `land_construction_standing_reds` in scripts/land.sh subtracts the same rows so that every
/// landing can run the gate over EVERY row instead of a caller-chosen few. The two lists are held
/// EQUAL by `posture_tests::land_sh_subtracts_exactly_the_construction_standing_reds`: an edit to
/// either alone reds `cargo test -p xtask`.
pub const CONSTRUCTION_STANDING_REDS: &[&str] = &[
    // The scan-set floor added 2026-09-09 scores an absent subject RED instead of PASS, and this
    // row is what it caught: a rule claiming "a cancellation-token check precedes every `.await` in
    // the route step" that found no `.await` in scope at all, and passed on that basis.
    "hold-discipline:cancellation-before-await",
    // SEVEN ROWS THAT RUN AND ARE RED ON THEIR MANIFESTS. Until item 120 the allowlist rule did not
    // read the `transport` kind, so these were "owed but no row was recorded — DID NOT RUN". It
    // reads it now, and every one of the seven FAILS for a real reason, measured: each names
    // third-party crates no review has recorded (tokio, futures, rustls, hyper, ...), and three name
    // a crate the rule scores as an automatic RED — `busbar-transport-tls` path-depends on
    // `busbar-unit-transport-key` (a unit crate; #36/#40 kernel-side machinery), and `-grpc` and
    // `-sse` on `busbar-transport-http` (a transport). Drain: the owner reviews the third-party
    // deps into `[rules.manifest-allowlist.reviewed_extra]` and the #40 opaque-handle work removes
    // the tls → unit edge; each name is struck here AND in scripts/land.sh as its row goes green.
    "manifest-allowlist:busbar-transport-grpc",
    "manifest-allowlist:busbar-transport-http",
    "manifest-allowlist:busbar-transport-sse",
    "manifest-allowlist:busbar-transport-stdio",
    "manifest-allowlist:busbar-transport-tcp",
    "manifest-allowlist:busbar-transport-tls",
    "manifest-allowlist:busbar-transport-ws",
    // Four production call sites of `pick_among(` against a ceiling of 2: the kernel-egress exhaustion
    // and walk sites beside busbar-llm's fallback and pipeline. DRAIN: Phase 4, when the plane's own
    // pick moves behind the kernel loop and only the loop and the fallback re-entry remain.
    "one-pick-site",
    // RE-DERIVED 2026-09-24 FROM A REAL RUN (P1 integration). `cargo xtask gate construction` on a
    // clean checkout of b7200b496, base pinned to origin/predev, is red on exactly the rows on this
    // list. Three names were STALE and are struck here and in scripts/land.sh in the same commit:
    // `ports-only-tests:busbar-llm`, `request-path-fn-size` and `terminal-doors-in-audit-step` are
    // PASS on that run. `ceiling-rose` is green again because the ten expired kind-isolation raises
    // in qa/construction.toml were struck in the same commit (each cell already reads its `to` at
    // the base). The rows below were red and on no list, so `--posture` scored them NEW; each is a
    // true finding, named with what it measures and the phase that drains it.
    //
    // MONEY — DRAIN: Phase 2.
    // `plane-no-money`: `priced_from_ms` at crates/busbar-llm/src/unit/meter.rs — a plane module
    // naming a price (#43/#71). (Item 208 recorded that an earlier comment claimed this row was on
    // the list while it was not; it is on it now, by name.)
    "plane-no-money",
    // `one-pricing-site`: `busbar_kernel_ledger::cost::price` called from
    // crates/busbar-core-admin/src/v1/service.rs, outside the reviewed homes — an admin read that
    // prices on its own path (the BUDGET row: the enforcement path is not the invoice path).
    "one-pricing-site",
    // `no-test-doubles-in-production:doubles`: 7 reviewed doubles in the shipped binary against a
    // ratchet of 5 — the voice governed-call node in crates/busbar/src/main.rs, built with
    // `NullShipper`, `RecordingRows`, `without_directory(` and `Pricer::flat(` (a zero rate card
    // where the deployment's card belongs).
    "no-test-doubles-in-production:doubles",
    // `token-sealed` and its three named mints: the Teller's tokens, `KernelSeal::acquire_for_kernel(`,
    // the arrival-hold mint and `SecretOnce::mint(` are spelled outside their one home crate (266,
    // 136, 49 and 5 sites). Item 317: the one deliberate cross-crate hole in the capability model is
    // held by nothing while these are red. The arrival hold is a money hold, so this drains with it.
    "token-sealed",
    "token-sealed:admit-token-mint",
    "token-sealed:kernel-seal",
    "token-sealed:secret-once-mint",
    //
    // C1 / THE FOLD — DRAIN: Phase 4.
    // `lean-core`: 14 string literals in the kernel and busbar-kernel-* crates naming a dialect or a
    // section 1.3 pinned word (config/mod.rs, appbuild.rs). Item 379 widened the scan to the eight
    // kernel crates the units became, which is what made it visible.
    "lean-core",
    // `neutral-no-dialect`: 27 DIALECT/KEY hits in the neutral crates per plane-purity-lint.sh
    // (busbar-kernel-identity egress_auth tests, busbar-kernel config) — the 59/60 dialect and
    // strict-purity drains.
    "neutral-no-dialect",
    // `loc-ceilings:caps-contract` and `surface-ceiling:contract`: busbar-contract measures 6840
    // against the ARCHITECTURE.md 1.1 ceiling of 5652 (caps folded in, #37/#38). `loc-ceilings:union`
    // is the same breach one level up — 58644 against 57456, over by 1188, which the union had been
    // absorbing while it read its members' slack (item 378 made it read their ceilings). A TRUE
    // red: the contract surface a plugin author reads is 1188 lines over the owner's number.
    "loc-ceilings:caps-contract",
    "loc-ceilings:union",
    "surface-ceiling:contract",
];

/// THE `qa-names` GATE'S STANDING REDS, BY NAME.
///
/// Three rows, each red about dead names in `qa/*.toml` that were already there when the gate was
/// written and each of which belongs to a change that is not this one. Same contract as
/// [`CONSTRUCTION_STANDING_REDS`]: a red this list does not name is scored, and a name on this list
/// that has gone green is STALE and is scored too, so the list cannot outlive its facts and cannot
/// quietly become a blanket.
pub const QA_NAMES_STANDING_REDS: &[&str] = &[
    // DRAINED 2026-09-24 (item 176, re-opened the same day): `qa-names:path-names-a-live-path`
    // stood here for `xtask/src/audit.rs`'s `REGISTER_REL = "qa/audit-ledger.json"`. The register
    // was deleted in 647f2fae9 while `cargo xtask ledger` was kept on purpose, so the const is the
    // DEFAULT home a fresh register is written to -- not moved, not obsolete -- and it now carries
    // a `// qa-names:` declaration beside it saying so, which reds the day the file exists again.
    // HISTORY. It was EMPTIED 2026-09-22 as the drain below finished -- but not the whole drain.
    //
    // It held three row ids covering twenty-five dead names in `qa/*.toml`. Each was decided by the
    // same question -- did the SUBJECT move, or is it gone? -- and the two answers have different
    // edits, because repointing a row at a subject it never covered launders debt nobody reviewed:
    //
    //   * `qa-names:crate-names-a-live-package` (5). `[rules.loc-ceilings].caps_crate =
    //     "busbar-caps"` STRUCK: the crate folded into busbar-contract and there is
    //     nowhere to repoint it, because `contract_crate` already counts those lines and naming the
    //     crate twice would double-count it. The row's measurement (6837), its ceiling (5652) and
    //     its standing red are unchanged. Four `qa/kind-isolation.toml` `[[cell]]` rows naming
    //     `busbar-plugin-pack`/`busbar-plugin-sign` STRUCK on the owning gate's own instruction:
    //     it reported each as `dead-cell ... the cell measures 0. Strike it`. (`busbar-plugin-pack`
    //     went to busbar-plugin-SDK in 38db9d48e, not the loader; `busbar-plugin-sign` went to the
    //     loader in d81a76f7f. Both destinations are measured under their own names already.)
    //
    //   * `qa-names:path-names-a-live-path` (17). Nine `qa/construction.toml` entries under the
    //     deleted `busbar-core`/`busbar-substrate` and the renamed `busbar-plane-admin` REPOINTED.
    //     Six `qa/full-gate.toml` skip rows STRUCK -- all six were BORN DEAD, because 446d771f3
    //     (which created that file) is a descendant of c73ae4f66 (deleted the five shadow-oracle
    //     harness scripts) and 378572b3f (deleted release-order-lint.py, saying in its own message
    //     that the skip entry and its special case both had to go). `cargo xtask full-gate --list`
    //     shows the six invocations actually skipped, and not one of the struck rows was among
    //     them. Two `qa/instance-noun-neutrality.toml` rows: `crates/plugin-sign/src/tests/
    //     lib_tests.rs` REPOINTED to `crates/plugin-loader/src/tests/sign_tests.rs` (a real `git
    //     mv` in d81a76f7f, and the freshly measured baseline gives the destination the SAME count
    //     36 and the same wave, so the ratchet moved with the file); `crates/busbar-plane-voice/
    //     src/claims.rs` STRUCK, because fbead1a31 says in as many words "NOT A RELOCATION, SO NOT
    //     AN R" -- voice was the losing duplicate and the survivor
    //     `crates/busbar-plane-streaming/src/claims.rs` already carries its own identical row.
    //
    //   * `qa-names:glob-matches-something` (3). `[rules.plane-no-money].scope_globs` named
    //     `crates/busbar-{mcp,a2a,voice}/src/unit/*`. `git log --all` returns ZERO commits for all
    //     three: those directories have never existed here, and all three crates already had their
    //     real layouts at ae307a648, the commit that wrote the globs. Not stale -- never resolved.
    //     REPOINTED at the crates' real `src` roots, AND THE REPOINT IS THE FINDING: a rule
    //     asserting that a plane names no price went from 1 money symbol to 113, having been green
    //     over three of its four planes (and, since #39 dissolved busbar-mcp-codec and
    //     busbar-a2a-codec INTO those crates, over two codec halves as well). Nothing is
    //     allowlisted. `plane-no-money` was then NOT a member of the construction standing-red
    //     list (a line here once said it was, and never was), so `--posture` scored it NEW. It
    //     became a member on 2026-09-24, by name and with its Phase 2 drain, when the list was
    //     re-derived from a real run — see CONSTRUCTION_STANDING_REDS.
];

/// THE MONEY-INVARIANTS GATE'S STANDING REDS, BY NAME. Same contract as
/// [`QA_NAMES_STANDING_REDS`]: a red this list does not name is scored, and a name on this list that
/// has gone green is STALE and is scored too.
pub const MONEY_INVARIANTS_STANDING_REDS: &[&str] = &[
    // DRAINED 2026-09-24 (W2.12, Phase 2): `money-invariants:no-stored-price` stood here for three
    // stored priced figures on the journalled audit record (item 9) — `AuditRecord.amount`,
    // `Amount.priced`, `HookApplied.priced_delta`. The record now carries `usage: Usage` (counts
    // and the inputs a read-time price takes, never a price) under the digest recipe
    // `busbar.audit.digest.v2`, published beside v1. Struck in the commit that turned it green.
];

/// THE CONFORMANCE-SYNC GATE'S STANDING REDS, BY NAME. Same contract as
/// [`QA_NAMES_STANDING_REDS`]: a red this list does not name is scored, and a name on this list that
/// has gone green is STALE and is scored too.
pub const CONFORMANCE_SYNC_STANDING_REDS: &[&str] = &[
    // Item 165 (2026-09-24): freshness is judged against the checkout's own commit, so every
    // carried-over pass is STALE on the dev line (KICKOFF 7.3). Drained in Phase 5 on the release
    // sha (KICKOFF 7.4). Strike this line in the commit that turns the row green.
    "conformance:freshness",
];

/// THE STRUCTURE-LINT GATE'S STANDING REDS, BY NAME. Same contract as
/// [`MONEY_INVARIANTS_STANDING_REDS`]: a red this list does not name is scored, and a name on this
/// list that has gone green is STALE and is scored too.
pub const STRUCTURE_LINT_STANDING_REDS: &[&str] = &[
    // be9c473f5 (W1.2, items 183/184/222-224/236) made the lint derive its plane set, protocol
    // crates and scope from the tree, and these four rows went red on what it could now see.
    // Measured 2026-09-24 on a clean checkout of 4be7fd3b5: red on exactly these four, green on the
    // other 33. DRAIN: Phase 4 — the plane owners dedupe each plane-local copy or sign its ledger
    // row, prune the stale ledger rows, take the axis identity questions out of the agnostic core
    // and collapse each second spelling. Strike each line in the commit that turns its row green.
    "structure-lint:axis:purity",
    "structure-lint:census:count",
    "structure-lint:plane-dup:stale-ledger",
    "structure-lint:plane-dup:unledgered",
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
    OnlyRows(StandingReds),
    /// The gate is a REQUIRED CHECK at promotion and is red on the dev line by design. Every fact
    /// listed must hold — the workflow still runs it, and branch protection still requires it — or
    /// the gate is scored like any other.
    RequiredAtPromotion(&'static [crate::full_gate::Excuse]),
}

/// An [`Excused::OnlyRows`] list, with the names an operator is told to edit when it goes stale.
/// The diagnostics read these, so a `qa-names` red is never answered with the construction list.
pub struct StandingReds {
    pub rows: &'static [&'static str],
    /// The Rust constant that holds `rows`.
    pub list: &'static str,
    /// Any other place that must be struck in the same commit, or `None`.
    pub mirror: Option<&'static str>,
}

/// The constant an operator edits to carry (or strike) a standing red of gate `name`, if the gate
/// has an [`Excused::OnlyRows`] posture.
pub fn standing_list_of(name: &str) -> Option<&'static str> {
    match &REPORT_ONLY.iter().find(|p| p.name == name)?.excuse {
        Excused::OnlyRows(sr) => Some(sr.list),
        _ => None,
    }
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
        Excused::RequiredAtPromotion(facts) => {
            for fact in facts.iter() {
                if let Err(why) = fact.holds(cx) {
                    eprintln!("  {name} posture: the promotion excuse no longer holds: {why}");
                    return None;
                }
            }
            Some(format!(
                "{} — ci.yml still runs it and branch protection still requires it",
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
        Excused::OnlyRows(sr) => {
            let unexplained = only_rows_unexplained(sr, verdict);
            if unexplained.is_empty() {
                Some(format!(
                    "{} — red on exactly the {} named standing row(s) and nothing else",
                    p.why,
                    sr.rows.len()
                ))
            } else {
                for u in &unexplained {
                    eprintln!("  {name} posture: {u}");
                }
                None
            }
        }
    }
}

/// Every reason an [`Excused::OnlyRows`] posture does NOT hold over `verdict`: each NEW red, and
/// each STALE name. Empty means the excuse holds.
///
/// A row that emitted nothing at all reaches the verdict as a reconciliation problem
/// (`"<id>: … DID NOT RUN"`), never as a row, so the named ids are matched against both. A rule
/// that stopped running is not a rule that is red for a known reason: a problem about an id the
/// list does not name fails the excuse exactly like a new red row.
fn only_rows_unexplained(sr: &StandingReds, verdict: &Verdict) -> Vec<String> {
    let named = sr.rows;
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
    let also = sr
        .mirror
        .map(|m| format!(" (and from {m})"))
        .unwrap_or_default();
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
                    "STALE `{id}` is named as a standing red and is not red any more — strike it \
                     from {}{also}",
                    sr.list
                )
            }),
    );
    unexplained
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
/// WHEN AND ON WHAT EVERY MEASUREMENT BELOW WAS TAKEN. One constant, because they were taken in one
/// sitting on one tree — and because a re-baseline that moves the numbers and not the date is the
/// failure this whole shape exists to make impossible.
const TAKEN: &str = "2026-09-10 b6f66e929";

// THE MEASUREMENTS. Each is `work units at --jobs 1` on the tree named in [`TAKEN`], read off the
// self-test's own cost line. Constants rather than literals inside the table so that a re-baseline
// is a diff a reviewer can read as a list of numbers that moved.
const MEASURED_PLANE_PURITY: f64 = 27_923.0; // 16 cases, 298.0 s
const MEASURED_PLANE_PURITY_STRICT: f64 = 19_435.0; // 12 cases, 202.1 s
const MEASURED_STRUCTURE_LINT: f64 = 7_938.0; // 39 cases, 88.4 s
const MEASURED_CONSTRUCTION: f64 = 33_096.0; // 36 cases, 352.4 s
const MEASURED_KIND_ISOLATION: f64 = 128_034.0; // 152 cases, 1360.9 s
const MEASURED_KIND_ISOLATION_SHIP: f64 = 120_208.0; // 122 cases, 1290.7 s

// `audit-ledger` IS STRUCK AGAIN, AND THE EXPLANATION IT WAS RE-BASELINED ON WAS WRONG.
//
// The history: it measured 4 433 units (14 cases, 46.5 s) at 2026-09-10 b6f66e929 and was struck as
// below the default; it grew back to 8 779 (same 14 cases, 99.4 s) at 2026-09-15 abf8e9ce8 and was
// re-baselined at 8 779 x 1.6 = 14 046; it then blew THAT, at 15 405 units / 190 s, which is the
// "FUTURE doubling past ~14 000" the re-baseline said would be a red row rather than minutes nobody
// attributes. It was. This is the attribution.
//
// THE RECORDED CAUSE WAS FALSE AND IS RETIRED. The note here and the entry's `why` both blamed
// the register: "the 1.6.0 register gained the whole drain, so the same 14 cases now scan a
// bigger history". Measured at abf8e9ce8 against HEAD, `qa/audit-ledger.json` went 247 201 ->
// 251 865 bytes (+1.9%) over 23 -> 25 distinct commits. A 1.9% input cannot produce a 75% cost,
// and the count that actually drives the work went DOWN: 133 -> 128 scopes carrying an
// `audited_at`. Reachability was never the driver either — `Git::reachable` resolves ONE
// `rev-list` per process behind a `OnceLock` and `Ctx::workspace()` is shared by all 14 cases, so
// that cost is paid once, not per case. Nor was it scope hashing against a grown tree:
// `tree_hash` over all 170 scopes measured 0.179 s of a 6.076 s `check`, under 3%.
//
// WHAT IT ACTUALLY WAS: `audit::rows` filled in `age` with a `rev-list --count <audited_at>..HEAD`
// PER SCOPE — 128 git processes per `check`, inside the very function whose doc said it avoided
// "144 scopes times a process each". Those 128 scopes name only SEVENTEEN distinct commits, so 111
// of the processes re-asked an answered question. At ~24 ms each (16 ms of it bare fork/exec) that
// was 6.2 s of a 6.076 s `check` — effectively all of it — and the battery pays it FOURTEEN TIMES,
// once per planted case: 1 792 git processes for a field no rule reads (`age` is printed by `ledger
// report`/`next` and by nothing else). It grew on its own without the register changing at all,
// because every commit that lands on HEAD lengthens every `audited_at..HEAD` walk; 605 commits
// landed between abf8e9ce8 and HEAD.
//
// FIXED, NOT RE-BASELINED. `Git::commits_between` now memoises on the WHOLE INPUT `(old, new)` —
// see its note for why that key cannot serve a plant a stale reading. Measured at 2026-09-22
// ee930eac8, at `--jobs 1`: 128 -> 17 processes, `commits_between` 6.216 s -> 0.637 s, `check`
// 6.076 s -> 3.143 s, and the battery 8 779 -> 2 865 units (14 cases, 43.1 s), holding within 3.5%
// across a box load that swung from 30 to 62. Under the whole `cargo test -p xtask --lib` shard it
// reads 4 702 units / 107 s at load ~50, against the 15 405 / 190 s at load ~22 that opened this.
//
// 2 865 x 1.6 = 4 584, which is BELOW the default, so the entry is struck rather than lowered —
// `every_selftest_budget_names_a_registered_gate_with_a_reason` refuses an entry that is not above
// it. The default 9 000 is now the guard, at 3.1x the serial measurement and 1.9x the worst
// contended reading. If it grows back past 9 000 the default is what says so, exactly as the first
// struck note said — and the thing to measure first is the git PROCESS COUNT per `check`, not the
// size of the register.

/// ONE BUDGETED SELF-TEST: WHAT IT MEASURED, WHEN, ON WHAT, AND WHAT IT IS ALLOWED.
///
/// A STRUCT AND NOT A TUPLE OF PROSE, because the thing that went wrong here was prose. The
/// `construction` entry's note said "about 15 600 units"; the tree measured three times that, under
/// a budget it was within seven per cent of blowing. A number a reader cannot check against a
/// measurement is not a guard, it is a number — and every arm below is now checked by
/// `every_budget_carries_the_measurement_it_was_set_from`.
pub struct Budget {
    /// The registered gate this is about.
    pub gate: &'static str,
    /// WHAT IT MEASURED, at `--jobs 1`, on the tree and date in `taken`. The entry IS this number;
    /// `allowed` is derived from it.
    pub measured: f64,
    /// What the self-test may spend before it is RED: `measured` times [`BUDGET_SLACK`].
    pub allowed: f64,
    /// WHEN AND ON WHAT, as `YYYY-MM-DD <sha>` — so a reader can re-take the measurement on the
    /// same tree, and so an entry whose tree is long gone is visibly old rather than quietly wrong.
    pub taken: &'static str,
    /// What the gate is doing with the time. Not the budget's justification — the slack is that,
    /// and it is declared once for all of them — but what a reader needs in order to act on a
    /// regression.
    pub why: &'static str,
}

/// THE SLACK OVER THE MEASUREMENT, DECLARED ONCE AND MEASURED RATHER THAN GUESSED.
///
/// It used to be "about three times what the gate measured", for two reasons: the ruler drifts with
/// the machine, and the failure being caught is a factor of ten. The first half is now a number
/// instead of an adjective. With the ruler read on the worker between cases (see
/// [`work_unit_here`]), `structure-lint` measured, on one box, in one sitting:
///
/// ```text
/// jobs    summed     units    vs serial
///    1     96.0 s     7934      1.00x
///    4     99.1 s     7980      1.01x
///    8    116.5 s     8330      1.05x
///   12    142.1 s     9323      1.18x
///   18    179.7 s    11367      1.43x
/// ```
///
/// So the ruler's own spread, between the serial figure written into an entry and the worst reading
/// the harness's DEFAULT job count produces, is 1.43x. THE SLACK IS 1.6x: that measured worst case
/// with a little room, and nothing else. It still catches what the budget is for — a rule that grew
/// a whole-tree scan per plant, a factor of ten — with a margin of six.
///
/// It is deliberately TIGHTER than the three it replaces. Three times a measurement that was itself
/// three times stale is how `construction` came to sit at 93 per cent of a budget its own note said
/// it used a third of.
pub const BUDGET_SLACK: f64 = 1.6;

// THE SLACK IS CHECKED WHERE IT IS WRITTEN, at compile time, because it is a constant and a
// constant that is wrong should not build. Below the ruler's measured spread it would red a battery
// for the box it ran on; at the size of the regression it is catching nothing.
const _: () = assert!(BUDGET_SLACK >= 1.43);
const _: () = assert!(BUDGET_SLACK < 10.0);

/// The gates whose self-tests legitimately cost more than [`DEFAULT_BUDGET_UNITS`], each with the
/// measurement it was set from. An entry for a gate that is no longer registered is refused by
/// `gates::posture_tests`, and so is an entry whose `allowed` is not its `measured` times the
/// declared slack, or whose measurement does not say when and on what it was taken.
const SELFTEST_BUDGETS: &[Budget] = &[
    Budget {
        gate: "plane-purity",
        measured: MEASURED_PLANE_PURITY,
        allowed: MEASURED_PLANE_PURITY * BUDGET_SLACK,
        taken: TAKEN,
        why: "The dearest self-test in the registry after the two kind-isolation batteries, and a name on the shard's own drain list. Not analysed here; the entry is the measurement, written down so that a doubling is a red row rather than minutes nobody attributes.",
    },
    Budget {
        gate: "plane-purity-strict",
        measured: MEASURED_PLANE_PURITY_STRICT,
        allowed: MEASURED_PLANE_PURITY_STRICT * BUDGET_SLACK,
        taken: TAKEN,
        why: "The ratcheted twin of plane-purity and the second name on the same drain list. Not analysed here either.",
    },
    Budget {
        gate: "structure-lint",
        measured: MEASURED_STRUCTURE_LINT,
        allowed: MEASURED_STRUCTURE_LINT * BUDGET_SLACK,
        taken: TAKEN,
        why: "One gate over a dozen rule families, each with its own planted tree, and the census walks the whole workspace.",
    },
    Budget {
        gate: "construction",
        measured: MEASURED_CONSTRUCTION,
        allowed: MEASURED_CONSTRUCTION * BUDGET_SLACK,
        taken: TAKEN,
        why: "Thirty-six rules over a 660k-line tree, the plants grouped by family so one case carries every edit a family needs. The file scan is memoised; what is left is the rules themselves. THIS IS THE ENTRY THAT PROVED THE OLD SHAPE WRONG: its note claimed `about 15 600 units` while the tree measured three times that, under a budget it was within seven per cent of blowing.",
    },
    Budget {
        gate: "kind-isolation",
        measured: MEASURED_KIND_ISOLATION,
        allowed: MEASURED_KIND_ISOLATION * BUDGET_SLACK,
        taken: TAKEN,
        why: "The dearest battery in the registry: every case plants an overlay and drives the whole gate over a 660k-line tree. The per-file compiled set and the matrix scan are memoised on (path, bytes) and the merge-base is read once per process; what is left is the plants and the rules. A plant that ADDS OR REMOVES A CRATE changes the derived vocabulary and invalidates the matrix memo, which many cases do, because a census that walks the whole repository is proven by planting crates in it.",
    },
    Budget {
        gate: "kind-isolation-ship",
        measured: MEASURED_KIND_ISOLATION_SHIP,
        allowed: MEASURED_KIND_ISOLATION_SHIP * BUDGET_SLACK,
        taken: TAKEN,
        why: "The ship twin of the battery above: the same shape held to a ceiling of zero, plus the derivations with a degenerate answer and the floors whose subject is the size of their own input.",
    },
    // `audit-ledger` HAS NO ENTRY HERE. It had one, set from 8 779 units and justified by a
    // register-growth story that measurement refuted; the cost was 128 `rev-list` processes per
    // `check` where 17 answer the same questions. Memoised, it measures 2 865, which is under the
    // default. The struck note sits above, where the measurement constants are.
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
        .find(|b| b.gate == gate)
        .map(|b| b.allowed)
        .unwrap_or(DEFAULT_BUDGET_UNITS)
}

/// `Sync`, because a self-test's cases are taken across the cores and every one of them reaches
/// its gate through `&dyn Gate`. Nothing here has interior mutability — the gates are unit structs
/// and flag-carrying structs read through `&self` — so this is a bound that says what was already
/// true rather than a constraint anything had to be changed to meet.
pub trait Gate: Sync {
    fn name(&self) -> &'static str;

    /// A STABLE NAME FOR "THIS GATE, WITH THIS CONFIGURATION" — the cache key under which
    /// [`prove_red`] remembers the UNPLANTED baseline it must compare every plant against.
    ///
    /// WHY THE BASELINE IS CACHED AT ALL. `prove_red` runs the gate twice: once clean, once
    /// planted, because a red that predates the plant is not the plant's red. The clean half is
    /// identical for every case in a gate's battery, and the two `kind-isolation` batteries take
    /// three figures of seconds each — paying for it once per case would double the dearest leg of
    /// the release to re-measure the same answer a hundred times.
    ///
    /// WHY IT IS A GATE'S OWN ANSWER AND NOT ITS `name`. Most gates are unit structs and their name
    /// says everything. Six carry configuration, and for them the name is NOT the whole identity:
    /// `KindIsolationGate`'s `write` arm and its `check` arm are both called `kind-isolation`, and
    /// serving one's baseline to the other would be exactly the mis-attribution this whole
    /// mechanism exists to stop. A gate whose configuration cannot be written down returns `None`,
    /// which means "measure my baseline fresh every time" — slower and always right.
    fn baseline_key(&self) -> Option<String> {
        Some(self.name().to_string())
    }

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
    /// THE PLANT CHANGED NOTHING. Every claim the overlay makes is a claim the tree already
    /// satisfies — most often `Overlay::remove` over a path that is ALREADY ABSENT, which removes
    /// nothing at all. The gate then reads the same tree it would have read unplanted, so whatever
    /// the run reports is about the tree and not about the plant.
    ///
    /// It is its own outcome because "the plant did nothing" and "the rule did nothing" are two
    /// different findings and only one of them is about the gate.
    ///
    /// `scored` is WHAT THE OLD SINGLE-RUN HARNESS MADE OF IT — the planted run, read exactly as it
    /// was read before the baseline existed. It costs nothing (that run happened either way) and it
    /// is the whole audit trail: a case reported INERT whose `scored` is `Red` is a case that was
    /// PASSING, vacuously, for as long as it has existed.
    Inert {
        why: Vec<String>,
        scored: Box<Expect>,
    },
    /// THE PROOF IS IMPOSSIBLE ON THIS TREE: the rows this case covers were ALREADY RED before the
    /// plant went in, so no red the planted run produces can be attributed to the plant.
    ///
    /// Never success, and never the same thing as a failed proof. A failed proof says the rule did
    /// not fire; this says the question could not be asked — the row has lost its own
    /// falsifiability and cannot get it back until its standing red is cleared.
    ///
    /// `scored` is the same audit trail [`Expect::Inert`] carries, for the same reason.
    Impossible {
        baseline: Vec<String>,
        scored: Box<Expect>,
    },
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
            (_, Expect::Inert { why, scored }) => Some(format!(
                "{}: THE PLANT CHANGED NOTHING — {why:?}. A run over an unchanged tree cannot \
                 attribute anything it reports to a plant that planted nothing, so this case \
                 proves nothing whichever colour it came back. {}",
                self.name,
                scored_note(scored)
            )),
            (_, Expect::Impossible { baseline, scored }) => Some(format!(
                "{}: THE PROOF IS IMPOSSIBLE — the rows this case covers were ALREADY RED on the \
                 unplanted tree ({baseline:?}), so the planted run's red is not the plant's. The \
                 row has lost its own falsifiability: clear its standing red and this case can be \
                 asked again. Weakening this rule to make the case pass restores nothing but the \
                 green. {}",
                self.name,
                scored_note(scored)
            )),
            (want, got) => Some(format!("{}: expected {want:?}, got {got:?}", self.name)),
        }
    }
}

/// WHAT THE SINGLE-RUN HARNESS MADE OF A CASE THAT PROVES NOTHING — the sentence that says whether
/// this finding is a proof that just broke or a pass that was never a proof.
fn scored_note(scored: &Expect) -> String {
    match scored {
        Expect::Red { .. } => "THE SINGLE-RUN HARNESS SCORED THIS A PASS: the planted run went RED              naming what the case asked for, and the case has therefore been reporting a proof it              never had."
            .to_string(),
        other => format!(
            "The single-run harness scored it {other:?} too, so this case was already failing —              what is new is the reason."
        ),
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
    // The work-unit budgets and the calibration ruler are measured at --jobs 18 (see TAKEN and
    // BUDGET); above that the ruler under-normalises contention and a battery reads spuriously over
    // budget on a box with more cores (measured: construction 33k units at 18-way, 54k at 32-way for
    // the same work). Cap the DEFAULT at the calibrated width so an unattended `cargo xtask selftest`
    // on a 32-core fleet box runs in the ruler's valid range; an explicit --jobs N still overrides.
    const CALIBRATED_JOBS: usize = 18;
    std::thread::available_parallelism()
        .map(|n| n.get().min(CALIBRATED_JOBS))
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

    /// Per-case timing rows `(name, took, units, prepaid)` for `XTASK_SELFTEST_TIMING`,
    /// the diagnostic that surfaces which case is spending the self-test's work-unit budget.
    pub fn timings(&self) -> Vec<(String, std::time::Duration, f64, std::time::Duration)> {
        let t = self.resolve();
        t.cases
            .iter()
            .zip(t.took.iter())
            .zip(t.units.iter())
            .zip(t.prepaid.iter())
            .map(|(((c, d), u), p)| (c.name.clone(), *d, *u, *p))
            .collect()
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

/// A BATTERY IS NOT A GATE RUN, AND MUST NOT BE HELD TO A GATE RUN'S CEILING.
///
/// `kind-isolation`'s self-test drives the whole gate over a planted tree ONE HUNDRED AND
/// SEVENTY-SIX TIMES. Five minutes is the right number for "this gate has stopped making progress";
/// it is plainly the wrong number for a hundred and seventy-six of them, and holding a battery to
/// it means the ceiling fires on a self-test that is working perfectly — which is a runner killing
/// the one job that would have told it what was wrong.
///
/// IT WAS ONLY EVER MASKED. Before the cases became plans, a battery ran inside `gate.selftest(cx)`
/// with the watchdog armed over it, and a serial `construction --selftest` — 617 s measured — was
/// killed at 300 s exactly like this. The lazy report hid it for one commit (the work happened
/// after the watchdog was dropped) and resolving under the watchdog put it back. It is a real
/// finding either way, and the answer is a ceiling that knows what it is bounding.
///
/// THIRTY MINUTES, and it is still a ceiling rather than a budget: the dearest battery in the
/// registry takes about three and a half at the default job count, so this is an order of magnitude
/// of headroom and anything that reaches it is wedged, not slow. The REGRESSION guard is
/// [`selftest_budget`], which is denominated in work units and is the thing that notices a battery
/// that merely grew. `XTASK_SELFTEST_CEILING_SECS` moves it; `0` disables it; an unreadable value
/// is the default, never "no ceiling".
pub const DEFAULT_SELFTEST_CEILING: Duration = Duration::from_secs(1800);

/// The ceiling for one BATTERY, read from the environment the same way [`ceiling_for`] reads a
/// gate's. A gate-specific `XTASK_GATE_CEILING_SECS_<GATE>` still wins, because a caller who named
/// one gate meant that gate.
pub fn selftest_ceiling_for(name: &str, env: impl Fn(&str) -> Option<String>) -> Option<Duration> {
    let per_gate = format!(
        "XTASK_GATE_CEILING_SECS_{}",
        name.to_uppercase().replace(['-', '.', '/'], "_")
    );
    let raw = env(&per_gate).or_else(|| env("XTASK_SELFTEST_CEILING_SECS"));
    match raw {
        None => Some(DEFAULT_SELFTEST_CEILING),
        Some(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(Duration::from_secs(n)),
            Err(_) => Some(DEFAULT_SELFTEST_CEILING),
        },
    }
}

/// The battery ceiling as the runner reads it, from the real process environment.
pub fn selftest_ceiling_from_env(name: &str) -> Option<Duration> {
    selftest_ceiling_for(name, |k| std::env::var(k).ok())
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

/// A PROOF IS A TRANSITION, NOT A COLOUR. Plant an overlay, run the gate THROUGH `execute` TWICE —
/// once clean, once planted — and require the covered rows to go GREEN -> RED naming every string
/// in `naming`. The only way a gate's selftest touches its gate.
///
/// THE RED IS READ OFF THE COVERED ROWS ONLY. It used to be enough that the gate went red and
/// that something anywhere in its report said the word: over a gate with thirty-six rows, on a tree
/// that carries real debt in some of them, that is satisfiable by a row the case is not about — so a
/// case could "prove" rule X while rule Y was what went red, and X was then deletable with `cargo
/// xtask selftest` still green. Now every id in `covers` must itself be red, which makes this
/// function and [`prove_rows_red`] the same proof; the latter survives as the name that says so at
/// the call site.
///
/// AND THE RED MUST BE THE PLANT'S. This ran the planted tree AND NOTHING ELSE for as long as it
/// existed, which made it unable to tell a rule that fired from a row that was already red when the
/// case arrived. Two cases in `kind-isolation` proved it: each planted `Overlay::remove` over a
/// `Cargo.toml` THAT IS NOT IN THE TREE — a literal no-op — against `kind-isolation:registry`,
/// which is standing RED naming `dead-kind grammar` and `alias-retired busbar-plane-voice`, the
/// exact two tokens the cases assert. Both passed. Both had planted nothing and proved nothing, and
/// the instrument reported success, for months.
///
/// So there are FOUR outcomes now and only one of them is a proof:
///
/// * **GREEN -> RED naming the offender** — the proof. The plant moved the row and the row said why.
/// * **GREEN -> GREEN** — a failed proof. The rule did not fire on a violation it is meant to catch.
/// * **[`Expect::Inert`]** — the plant changed nothing about the tree the gate reads, so the run is
///   not evidence about anything. Caught BEFORE the runs, by reading the overlay against the tree.
/// * **[`Expect::Impossible`]** — the covered rows were already RED unplanted. The question cannot
///   be asked on this tree at all, which is a finding about the row rather than about the rule, and
///   is reported as its own outcome so nobody can mistake it for either of the other three.
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
        let expected = Expect::Red { naming };
        let overlay = plant.build();
        let ids = refs(&covers);

        // THE THREE MEASUREMENTS, IN THE ORDER THEY COST. The plant is read against the tree for
        // free; the baseline is one run per gate however many cases there are; the planted run is
        // the one this function always made. Nothing here is a run the old shape did not pay for
        // except the shared baseline.
        let dead = inert_plant(&cx, &overlay);
        let before = narrowed_got(&baseline_verdict(gate, &cx), &ids);
        let scored = narrowed_got(&execute(gate, &cx.with_overlay(overlay)), &ids);

        // 1. THE PLANT MUST BITE. A run over an unchanged tree is not evidence about a plant.
        if let Err(why) = dead {
            return Case {
                name,
                covers,
                expected,
                got: Expect::Inert {
                    why,
                    scored: Box::new(scored),
                },
            };
        }

        // 2. THE BASELINE MUST BE GREEN ON THE ROWS THIS CASE IS ABOUT. A row that is already red
        //    cannot be proven red-able BY ANYTHING, and saying so is the finding.
        if let Expect::Red { naming: baseline } = before {
            return Case {
                name,
                covers,
                expected,
                got: Expect::Impossible {
                    baseline,
                    scored: Box::new(scored),
                },
            };
        }

        // 3. AND ONLY THEN IS THE PLANTED RUN THE PLANT'S. GREEN -> RED is the proof; GREEN ->
        //    GREEN is a rule that did not fire on a violation it is meant to catch.
        Case {
            name,
            covers,
            expected,
            got: scored,
        }
    })
}

/// THE OTHER PLANT: THE GATE'S OWN CONFIGURATION, over a tree nobody touched.
///
/// A handful of rules have a subject an overlay cannot reach. `structure-lint`'s table rules judge
/// a table that is SOURCE, not tree; `qa-gate-dispatch`'s default-branch arm judges a ref that has
/// to be unreadable to real `git`. For those the violation is planted by BUILDING THE GATE
/// DIFFERENTLY, and the overlay is empty because there is nothing in the tree to change.
///
/// [`prove_red`] must refuse an empty overlay — a case that plants nothing and runs one gate is
/// the vacuous shape this whole mechanism exists to catch — so these cases say what they are
/// instead. THE PROOF IS THE SAME PROOF: the gate AS THE TREE SHIPS IT must be GREEN on the covered
/// rows, the mis-configured twin must be RED, and one tree with two configurations is a transition
/// exactly as one configuration with two trees is.
pub fn prove_red_by_configuration<'a>(
    cx: &Ctx,
    shipped: &'a dyn Gate,
    planted: &'a dyn Gate,
    name: impl Into<String>,
    covers: &[&str],
    naming: &[&str],
) -> CasePlan<'a> {
    let name = name.into();
    let covers: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let naming: Vec<String> = naming.iter().map(|s| (*s).to_string()).collect();
    let cx = cx.clone();
    CasePlan::new(move || {
        let expected = Expect::Red { naming };
        let ids = refs(&covers);
        let scored = narrowed_got(&execute(planted, &cx), &ids);

        // THE CONFIGURATION MUST ACTUALLY DIFFER. Two identical gates over one tree are one run
        // written twice, which is the empty-overlay vacuity wearing a different hat. A gate that
        // cannot write its own configuration down answers `None`, and two `None`s are taken at
        // their word rather than assumed equal.
        if let (Some(a), Some(b)) = (shipped.baseline_key(), planted.baseline_key()) {
            if a == b {
                return Case {
                    name,
                    covers,
                    expected,
                    got: Expect::Inert {
                        why: vec![format!(
                            "both halves of this case are the SAME configuration of `{}` over the \
                             same tree ({a}), so there is no change for the row to answer",
                            shipped.name()
                        )],
                        scored: Box::new(scored),
                    },
                };
            }
        }

        if let Expect::Red { naming: baseline } =
            narrowed_got(&baseline_verdict(shipped, &cx), &ids)
        {
            return Case {
                name,
                covers,
                expected,
                got: Expect::Impossible {
                    baseline,
                    scored: Box::new(scored),
                },
            };
        }

        Case {
            name,
            covers,
            expected,
            got: scored,
        }
    })
}

/// WHAT THIS PLANT ACTUALLY CHANGES ABOUT THE TREE THE GATE WILL READ — `Ok` if anything, and the
/// reasons it changes NOTHING otherwise.
///
/// The overlay is compared against the context the gate would otherwise have read, which is the
/// only place the question can be answered: an `Overlay` on its own knows what it claims and not
/// whether the tree already agreed.
///
/// A `Change::Absent` over a path the tree has not got is refused ON ITS OWN, even beside claims
/// that do bite, because it is never anything but a mistake: it is a plant whose author believed
/// they were deleting something. That is the exact shape of both no-ops found in `kind-isolation`,
/// and `Edit::Delete` has refused it at the other door since it was written — this closes the door
/// `Overlay::remove` left open.
fn inert_plant(cx: &Ctx, overlay: &crate::ctx::Overlay) -> Result<(), Vec<String>> {
    use crate::ctx::Change;

    if overlay.is_empty() {
        return Err(vec![
            "the plant is an EMPTY overlay: it claims nothing about any path and cans no derived \
             input, so the planted run and the clean run are the same run"
                .to_string(),
        ]);
    }

    let mut phantom = Vec::new();
    let mut dead = Vec::new();
    let mut bites = overlay.has_commands();
    for (path, change) in overlay.changes() {
        let rel = path.to_string_lossy().replace('\\', "/");
        match change {
            Change::Absent if !cx.exists(path) => phantom.push(format!(
                "{rel}: the plant REMOVES A PATH THAT IS ALREADY ABSENT, so it removes nothing — \
                 whatever the run reports, it is not about this plant"
            )),
            Change::Content(want) if cx.read(path).ok().as_ref() == Some(want) => dead.push(
                format!("{rel}: the plant writes back the bytes the tree already has"),
            ),
            _ => bites = true,
        }
    }

    if !phantom.is_empty() {
        return Err(phantom);
    }
    if !bites {
        return Err(dead);
    }
    Ok(())
}

/// ONE BASELINE, HANDED OUT UNDER THE MAP'S LOCK AND FILLED OUTSIDE IT. The `OnceLock` is what
/// makes eighteen workers arriving at once take ONE unplanted run between them: the first fills it
/// and the rest wait on that answer instead of measuring the same tree seventeen more times.
type BaselineCell = Arc<OnceLock<Arc<Verdict>>>;

/// THE GATE'S VERDICT OVER THE UNPLANTED TREE, measured once per gate-and-context rather than once
/// per case. See [`Gate::baseline_key`] for why it is keyed the way it is, and why a gate that
/// cannot name its own configuration pays for a fresh run instead of risking a wrong one.
fn baseline_verdict(gate: &dyn Gate, cx: &Ctx) -> Arc<Verdict> {
    static BASELINES: Mutex<Option<BTreeMap<String, BaselineCell>>> = Mutex::new(None);

    let Some(gate_key) = gate.baseline_key() else {
        return Arc::new(execute(gate, cx));
    };
    let key = format!(
        "{gate_key}\u{3}{}\u{3}{}",
        cx.root().to_string_lossy(),
        cx.overlay().map(|o| o.fingerprint()).unwrap_or_default()
    );

    // The map is held only long enough to hand back the cell. The RUN happens outside the lock, or
    // the first case into a battery would hold every other gate's baseline hostage to its own.
    let cell = {
        let mut guard = BASELINES.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get_or_insert_with(BTreeMap::new)
            .entry(key)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone()
    };
    cell.get_or_init(|| Arc::new(execute(gate, cx))).clone()
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
        let overlay = plant.build();
        // A GREEN PROOF OVER A PLANT THAT CHANGED NOTHING IS A CLAIM ABOUT THE UNPLANTED TREE. The
        // red arm has refused that since `inert_plant` was written; the green arm is the proof
        // that a gate does NOT fire on a legitimate shape, and it needs the same door shut.
        //
        // An EMPTY overlay is the one exception, and it is not a plant: it is the CONTROL case —
        // "the unplanted tree is green on these rows" — which claims nothing it did not do. A
        // non-empty overlay claims to have changed the tree, and must have.
        let checked = if overlay.is_empty() {
            Ok(())
        } else {
            inert_plant(&cx, &overlay)
        };
        if let Err(why) = checked {
            let verdict = execute(gate, &cx.with_overlay(overlay));
            return Case {
                name,
                covers: covers.clone(),
                expected: Expect::Green,
                got: Expect::Inert {
                    why,
                    scored: Box::new(narrowed_got(&verdict, &refs(&covers))),
                },
            };
        }
        let planted = cx.with_overlay(overlay);
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
        name: "feature-sets",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(feature_sets::FeatureSetsGate),
        summary: "every non-default cargo feature is built by a CI job that names it",
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
        name: "reachability",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(reachability::ReachabilityGate),
        summary: "every plane in the #48 roster is served by a unit path the root constructs",
    },
    Registration {
        name: "unconstructed",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(unconstructed::UnconstructedGate),
        summary: "every capability declared in qa/unconstructed.toml has a production construction site",
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
        name: "no-float-money",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(no_float_money::NoFloatMoneyGate),
        summary: "no floating point past a declared money-intake boundary on the money runtime path (#77.8/#44)",
    },
    Registration {
        name: "seal-witness",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(seal_witness::SealWitnessGate),
        summary: "capability proofs are exactly Pass<stage> + Grant<capability> + one kernel minter (#65/#73)",
    },
    Registration {
        name: "sweep-coverage",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(sweep_coverage::SweepCoverageGate),
        summary: "every tracked file carries a sweep verdict; the denominator is git's, not the sweep's",
    },
    Registration {
        name: "map-proof",
        batch: 2,
        tier: Tier::Full,
        build: || Box::new(map_proof::MapProofGate),
        summary: "every command the map-proof corpus prints is re-run and every printed figure \
                  re-derived; unrunnable and unbound figures are verdicts of their own",
    },
    Registration {
        name: "money-invariants",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(money_invariants::MoneyInvariantsGate),
        summary: "money records hold no plugin/plane field, store no price, seal one facts-line per unit (#77)",
    },
    Registration {
        name: "kind-abi-lane",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(kind_abi_lane::KindAbiLaneGate),
        summary: "each kind declares the ONE ABI lane #30 binds it to by heat (plane/transport=hot, \
                  store/secret/auth/hook/export=cold); the per-token loop is {plane,transport} only",
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
        name: "instance-noun-neutrality",
        batch: 1,
        // RELEASE-TIME, NOT PER-PUSH (item 185): red by design on a tracked burndown baseline, run
        // in full by release-stage.yml's `done-oracle` job on the sha being staged, on the same
        // footing as its Tier::Full siblings (reachability, plane-purity-strict, kind-isolation-ship).
        tier: Tier::Full,
        build: || Box::new(instance_noun_neutrality::InstanceNounNeutralityGate),
        summary:
            "no crate names a concrete plugin instance outside that instance's own crate family",
    },
    Registration {
        name: "plane-pricing-blindness",
        batch: 1,
        // RELEASE-TIME, NOT PER-PUSH (item 185): red by design on a tracked burndown baseline, run
        // in full by release-stage.yml's `done-oracle` job on the sha being staged, on the same
        // footing as its Tier::Full siblings (reachability, plane-purity-strict, kind-isolation-ship).
        tier: Tier::Full,
        build: || Box::new(plane_pricing_blindness::PlanePricingBlindnessGate),
        summary:
            "no plane crate resolves a card, prices, mints a unit key or arithmetics a hold (#43/#71)",
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
        name: "hot-path-perf",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(hot_path_perf::HotPathPerfGate),
        summary:
            "the perf instrument measures the vtable crossing < 1µs (p50+p99) and 0 per-token \
                  host calls",
    },
    Registration {
        name: "hot-path-alloc",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(hot_path_alloc::HotPathAllocGate),
        summary: "the alloc instrument asserts 0 global allocations across the isolated POD \
                  host-call batch",
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
        name: "conformance-sync",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(conformance_sync::ConformanceSyncGate),
        summary:
            "the conformance manifest, README badges and claims never drift from the real verdicts",
    },
    Registration {
        name: "inventory-coverage",
        batch: 2,
        tier: Tier::Fast,
        build: || Box::new(inventory_coverage::InventoryCoverageGate),
        summary: "every docs/design/inventory/*.md id is a named coverage claim or a named gap",
    },
    Registration {
        name: "no-tracked-ignored",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(no_tracked_ignored::NoTrackedIgnoredGate),
        summary: "no tracked path matches a .gitignore rule of this tree (git ls-files -ci \
                  --exclude-standard)",
    },
    Registration {
        name: "package-selectors",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(package_selectors::PackageSelectorsGate),
        summary: "every `-p`/`--package`, matrix cell and xtask cargo string names a live package",
    },
    Registration {
        name: "qa-names",
        batch: 1,
        tier: Tier::Fast,
        build: || Box::new(qa_names::QaNamesGate),
        summary: "every kind, crate, path and glob named in qa/*.toml resolves to something here",
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

/// THE FALSIFICATION OF THE FALSIFIER — the three outcomes `prove_red` must be able to produce on
/// demand, each driven over a gate built to be steered into it.
///
/// WHY THIS MODULE EXISTS. `prove_red` ran the gate ONCE, with the plant, and never established
/// that the rows it covers were green before it. A row that was already red for an unrelated reason
/// therefore scored a PASS with the plant having done nothing at all, and two cases in
/// `kind-isolation` were living proof: each removed a `Cargo.toml` that is not in the tree, against
/// `kind-isolation:registry`, which is standing red naming the very tokens they assert.
///
/// An instrument that cannot produce a NO is not a check — and that is as true of this one as of
/// anything it measures. So the three NOs are produced here, on purpose, every `cargo test`.
#[cfg(test)]
mod falsification_tests {
    use super::*;
    use crate::ledger::Row;

    /// A gate with TWO rows and a steering wheel: one row is GREEN until a marker is planted, the
    /// other is RED whatever the tree says. Between them they reach every outcome `prove_red` has.
    struct ProbeGate;

    /// GREEN on the unplanted tree, RED when the marker is there. The row a proof is possible about.
    const PROBE_GREENABLE: &str = "probe:greenable";
    /// RED ALWAYS. The row that has lost its own falsifiability — `kind-isolation:registry` in
    /// miniature.
    const PROBE_STUCK: &str = "probe:stuck";
    /// Not in the tree, and never written: the gate reads its ABSENCE, and a test that wrote it
    /// would be a plant left behind.
    const PROBE_MARKER: &str = "qa/zz-falsification-marker.txt";
    /// Also not in the tree. Planting `Overlay::remove` here removes nothing.
    const PROBE_PHANTOM: &str = "crates/zz-not-a-crate/Cargo.toml";

    impl Gate for ProbeGate {
        fn name(&self) -> &'static str {
            "probe"
        }
        fn owed(&self) -> Vec<String> {
            vec![PROBE_GREENABLE.to_string(), PROBE_STUCK.to_string()]
        }
        fn run(&self, cx: &Ctx) -> Verdict {
            let greenable = if cx.exists(PROBE_MARKER) {
                Row::fail(
                    PROBE_GREENABLE,
                    "the greenable row",
                    "planted-marker: the marker is in the tree",
                )
            } else {
                Row::pass(PROBE_GREENABLE, "the greenable row", "no marker")
            };
            Verdict::of(vec![
                greenable,
                Row::fail(
                    PROBE_STUCK,
                    "the stuck row",
                    "standing-red: this row is red on every tree there is",
                ),
            ])
        }
        fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
            Report::new()
        }
    }

    fn took(plan: CasePlan<'_>) -> Case {
        plan.take()
    }

    /// OUTCOME ONE: a genuine plant on a green row IS a proof. GREEN -> RED, naming the offender.
    #[test]
    fn a_genuine_plant_on_a_green_row_proves_the_row_red_able() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = ProbeGate;
        let mut ov = Overlay::new();
        ov.set(PROBE_MARKER, "planted\n");
        let case = took(prove_red(
            &cx,
            &gate,
            "the marker turns the greenable row red",
            &[PROBE_GREENABLE],
            ov,
            &["planted-marker"],
        ));
        assert!(
            matches!(case.got, Expect::Red { .. }),
            "a real plant on a green row must come back RED, got {:?}",
            case.got
        );
        assert_eq!(
            case.failure(),
            None,
            "GREEN -> RED naming the offender is the proof and must pass"
        );
    }

    /// OUTCOME TWO, THE SHAPE THAT WAS BROKEN: a NO-OP plant on a green row must FAIL.
    ///
    /// `Overlay::remove` over a path that is already absent removes nothing. It used to be a shrug
    /// — the map simply recorded `Absent` for a path that was absent anyway — and the run that
    /// followed was a run over the untouched tree.
    #[test]
    fn a_no_op_removal_is_refused_before_the_gate_is_ever_run() {
        let cx = Ctx::workspace().expect("the workspace opens");
        assert!(
            !cx.exists(PROBE_PHANTOM),
            "this test's whole point is that {PROBE_PHANTOM} is not in the tree"
        );
        let gate = ProbeGate;
        let mut ov = Overlay::new();
        ov.remove(PROBE_PHANTOM);
        let case = took(prove_red(
            &cx,
            &gate,
            "removing a crate that is not there",
            &[PROBE_GREENABLE],
            ov,
            &["planted-marker"],
        ));
        let Expect::Inert { scored, .. } = &case.got else {
            panic!(
                "a plant that removes an absent path changed nothing and must be reported INERT, \
                 got {:?}",
                case.got
            );
        };
        assert!(
            matches!(**scored, Expect::Green),
            "THE CONTRAST THIS CASE EXISTS FOR: the single-run harness saw GREEN and failed the \
             case for the WRONG reason — 'the rule did not fire' — when the truth is that nothing \
             was ever planted for it to fire on: {scored:?}"
        );
        let why = case.failure().expect("an inert plant is never a pass");
        assert!(
            why.contains("ALREADY ABSENT"),
            "the finding must name what the plant failed to remove: {why}"
        );
    }

    /// ITEM 209: THE GREEN ARM SHUTS THE SAME DOOR. A green case over a plant that changed nothing
    /// is a claim about the unplanted tree, and `prove_rows_green` used to score it a pass.
    #[test]
    fn a_green_case_over_a_no_op_plant_is_refused_too() {
        let cx = Ctx::workspace().expect("the workspace opens");
        assert!(!cx.exists(PROBE_PHANTOM));
        let gate = ProbeGate;
        let mut ov = Overlay::new();
        ov.remove(PROBE_PHANTOM);
        let case = took(prove_rows_green(
            &cx,
            &gate,
            "removing a crate that is not there leaves the row green",
            &[PROBE_GREENABLE],
            ov,
        ));
        let why = case
            .failure()
            .expect("a green case whose plant changed nothing is never a pass");
        assert!(
            why.contains("ALREADY ABSENT"),
            "the finding must name what the plant failed to remove: {why}"
        );
    }

    /// The other no-op: an overlay that writes back the bytes the tree already has.
    #[test]
    fn a_plant_that_writes_the_bytes_the_tree_already_has_is_refused() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = ProbeGate;
        let same = cx
            .read("Cargo.toml")
            .expect("the workspace manifest is readable");
        let mut ov = Overlay::new();
        ov.set("Cargo.toml", same);
        let case = took(prove_red(
            &cx,
            &gate,
            "planting the file the tree already had",
            &[PROBE_GREENABLE],
            ov,
            &["planted-marker"],
        ));
        assert!(
            matches!(case.got, Expect::Inert { .. }),
            "writing back identical bytes changes nothing, got {:?}",
            case.got
        );
    }

    /// OUTCOME THREE: any plant on an ALREADY-RED row is IMPOSSIBLE, never success — and the case
    /// says, in the same breath, that the single-run harness scored it a PASS.
    ///
    /// THIS IS THE REGRESSION ITSELF. The plant is real, the row goes red, the red names the token
    /// the case asked for — and none of it is the plant's doing, because the row was red before the
    /// plant existed.
    #[test]
    fn a_plant_against_a_row_that_is_already_red_reports_impossible_not_success() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = ProbeGate;
        let mut ov = Overlay::new();
        ov.set(PROBE_MARKER, "planted\n");
        let case = took(prove_red(
            &cx,
            &gate,
            "proving the stuck row red-able",
            &[PROBE_STUCK],
            ov,
            &["standing-red"],
        ));
        let Expect::Impossible { baseline, scored } = &case.got else {
            panic!(
                "a row that is red before the plant cannot be proven red-able and must say so, \
                 got {:?}",
                case.got
            );
        };
        assert!(
            baseline.iter().any(|b| b.contains("standing-red")),
            "the finding must quote the red that was already there: {baseline:?}"
        );
        assert!(
            matches!(**scored, Expect::Red { .. }),
            "the single-run harness scored this a PASS, and the case must record that it did: \
             {scored:?}"
        );
        let why = case.failure().expect("an impossible proof is never a pass");
        assert!(
            why.contains("ALREADY RED") && why.contains("SCORED THIS A PASS"),
            "the finding must name both halves — the standing red and the pass it was handing \
             out: {why}"
        );
    }

    /// AND THE FOURTH: a real plant that the rule simply does not catch is still a failed proof.
    /// GREEN -> GREEN was always a failure and must stay one; the new rule adds outcomes, it does
    /// not trade one away.
    #[test]
    fn a_real_plant_the_rule_ignores_is_still_a_failed_proof() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = ProbeGate;
        let mut ov = Overlay::new();
        // A real edit to a real file that `ProbeGate` does not read at all.
        ov.set("README.md", "a real change this gate has no rule about\n");
        let case = took(prove_red(
            &cx,
            &gate,
            "a plant the rule does not look at",
            &[PROBE_GREENABLE],
            ov,
            &["planted-marker"],
        ));
        assert!(
            matches!(case.got, Expect::Green),
            "the rule did not fire, so the case is GREEN and fails, got {:?}",
            case.got
        );
        assert!(
            case.failure().is_some(),
            "GREEN -> GREEN proves the rule did not fire and is never a pass"
        );
    }

    /// THE BASELINE IS MEASURED ONCE PER GATE, not once per case — the property the whole
    /// mechanism's affordability rests on, asserted rather than assumed.
    #[test]
    fn the_baseline_is_shared_across_the_cases_of_one_gate() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static RUNS: AtomicUsize = AtomicUsize::new(0);
        struct CountingGate;
        impl Gate for CountingGate {
            fn name(&self) -> &'static str {
                "counting"
            }
            fn owed(&self) -> Vec<String> {
                vec!["counting:row".to_string()]
            }
            fn run(&self, cx: &Ctx) -> Verdict {
                if cx.overlay().is_none() {
                    RUNS.fetch_add(1, Ordering::SeqCst);
                }
                let row = if cx.exists(PROBE_MARKER) {
                    Row::fail("counting:row", "counting", "planted-marker")
                } else {
                    Row::pass("counting:row", "counting", "no marker")
                };
                Verdict::of(vec![row])
            }
            fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
                Report::new()
            }
        }

        let cx = Ctx::workspace().expect("the workspace opens");
        let gate = CountingGate;
        for i in 0..4 {
            let mut ov = Overlay::new();
            ov.set(PROBE_MARKER, format!("planted {i}\n"));
            let case = took(prove_red(
                &cx,
                &gate,
                format!("case {i}"),
                &["counting:row"],
                ov,
                &["planted-marker"],
            ));
            assert_eq!(case.failure(), None, "case {i} is a plain proof");
        }
        assert_eq!(
            RUNS.load(Ordering::SeqCst),
            1,
            "four cases over one gate and one context must share ONE unplanted run: a baseline \
             paid per case would double the dearest batteries in the registry"
        );
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
            let seen = cx.read(ECHO_PATH).ok();
            // Long enough for a racing case to overwrite a shared plant, if plants were shared.
            std::thread::sleep(Duration::from_millis(40));
            let again = cx.read(ECHO_PATH).ok();
            // GREEN ON THE UNPLANTED TREE, and only then red on what a case planted. It reported
            // the path unconditionally as FAIL once, which made its own baseline permanently red —
            // the exact shape `prove_red` now refuses, in the harness's own fixture.
            let row = match (seen, again) {
                (None, None) => Row::pass(
                    ECHO_ROW.to_string(),
                    "echo".to_string(),
                    "nothing is planted at the echo path".to_string(),
                ),
                (seen, again) => Row::fail(
                    ECHO_ROW.to_string(),
                    "echo".to_string(),
                    format!(
                        "{}|{}",
                        seen.unwrap_or_else(|| "<absent>".to_string()),
                        again.unwrap_or_else(|| "<absent>".to_string())
                    ),
                ),
            };
            Verdict::of(vec![row])
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

    /// A BATTERY GETS THE BATTERY'S CEILING, and a gate named on the command line still wins.
    ///
    /// Red first, in the shape that bit: a serial `construction --selftest` measured 617 s and the
    /// gate-run ceiling is 300 s, so the runner killed a self-test that was working.
    #[test]
    fn a_battery_is_not_held_to_one_gate_runs_ceiling() {
        let none = |_: &str| None;
        assert_eq!(
            selftest_ceiling_for("construction", none),
            Some(DEFAULT_SELFTEST_CEILING),
            "a battery's default ceiling is the battery's, not the gate run's"
        );
        assert!(
            DEFAULT_SELFTEST_CEILING > Duration::from_secs(617),
            "the measured serial `construction` battery must fit under it, or the ceiling is \
             killing working self-tests"
        );
        assert_eq!(
            ceiling_for("construction", none),
            Some(DEFAULT_GATE_CEILING),
            "one gate RUN keeps the five minutes it always had"
        );

        // The env forms, and the precedence between them.
        let per_gate =
            |k: &str| (k == "XTASK_GATE_CEILING_SECS_CONSTRUCTION").then(|| "42".to_string());
        assert_eq!(
            selftest_ceiling_for("construction", per_gate),
            Some(Duration::from_secs(42)),
            "a caller who named one gate meant that gate"
        );
        let all = |k: &str| (k == "XTASK_SELFTEST_CEILING_SECS").then(|| "7".to_string());
        assert_eq!(
            selftest_ceiling_for("construction", all),
            Some(Duration::from_secs(7))
        );
        let off = |k: &str| (k == "XTASK_SELFTEST_CEILING_SECS").then(|| "0".to_string());
        assert_eq!(selftest_ceiling_for("construction", off), None, "0 is off");
        // AND A TYPO IS THE DEFAULT, NEVER "NO CEILING".
        let typo = |k: &str| (k == "XTASK_SELFTEST_CEILING_SECS").then(|| "ten".to_string());
        assert_eq!(
            selftest_ceiling_for("construction", typo),
            Some(DEFAULT_SELFTEST_CEILING),
            "an unreadable override must not be the thing that lets a wedged battery hang forever"
        );
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

    /// DESIGN-BINDINGS HAS NO EXCUSE AT ALL ANY MORE, WHICH IS THE STRONGEST FORM OF THE OLD ONE.
    ///
    /// The entry that used to sit here excused the gate while every non-PASS row named
    /// `scripts/inventory-coverage.sh` -- a file the tree did not have, cited by PB-0, because the
    /// shell retired without its gate being converted. `cargo xtask gate inventory-coverage` is
    /// registered and PB-0 cites it, so there is no standing red left to forgive and the entry is
    /// struck rather than reworded. This test pins the consequence: the KNOWN red is now scored
    /// exactly like the unknown one, because neither is excused.
    #[test]
    fn a_design_binding_that_breaks_is_scored_however_it_broke() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let known = Row::fail(
            "PB-0",
            "PB-0 master rule",
            "partly proven; a referenced check settles nothing: \
             gate:scripts/inventory-coverage.sh",
        );
        assert!(
            excused_from_all("design-bindings", &cx, &verdict(vec![known.clone()])).is_none(),
            "the red the struck excuse was written for is scored like any other now that the \
             check it named exists"
        );
        let fresh = Row::fail(
            "PB-7",
            "PB-7 something else",
            "a binding cites nothing at all",
        );
        assert!(
            excused_from_all("design-bindings", &cx, &verdict(vec![known, fresh])).is_none(),
            "a red about anything else was never excused and still is not"
        );
    }

    /// The release-time posture is not a name on a list here: it is a lookup into the table that
    /// already knew, and that table's own claim is checked against the tree.
    #[test]
    fn the_release_time_posture_is_read_from_full_gate_and_expires_with_it() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let red = verdict(vec![Row::fail("kind-isolation:shape", "t", "d")]);
        // THE BASELINE IS PLANTED, NOT BORROWED. The excuse holds only while the script names the
        // gate AND some workflow runs the script in full (item 161). The control used to read that
        // second half off whatever the real workflows carried, so on a tree where no workflow ran
        // the script it failed before the plant, and the plant below proved nothing (item 89's
        // PROOF IMPOSSIBLE). A workflow job running the script in full is planted here, so the
        // green -> red transition is the script edit and nothing else.
        let ci = ".github/workflows/ci.yml";
        let mut ov = Overlay::new();
        ov.set(
            ci,
            format!(
                "{}\n  planted-release-run:\n    runs-on: ubuntu-latest\n    steps:\n      \
                 - run: bash scripts/verify-1.6.0-done.sh\n",
                cx.read(ci).expect("ci.yml")
            ),
        );
        let base = cx.with_overlay(ov.clone());
        assert!(
            excused_from_all("kind-isolation-ship", &base, &red).is_some(),
            "verify-1.6.0-done.sh invokes it and a workflow runs the script, which is what \
             full_gate's excuse asserts: {:?}",
            crate::full_gate::REGISTRY_NOT_IN_CI
                .iter()
                .find(|(n, _, _)| *n == "kind-isolation-ship")
                .map(|(_, _, e)| e.holds(&base))
        );
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
        for b in SELFTEST_BUDGETS {
            let name = b.gate;
            assert!(
                find(name).is_some(),
                "`{name}` has a self-test budget and is not a registered gate"
            );
            assert!(
                b.allowed > DEFAULT_BUDGET_UNITS,
                "`{name}`'s budget of {} units is not above the default; strike the entry",
                b.allowed
            );
            assert!(
                b.why.len() > 60,
                "`{name}`'s budget reason is too short to be one"
            );
        }
    }

    /// A BUDGET WITHOUT A WRITTEN MEASUREMENT IS REFUSED, and so is one whose measurement no longer
    /// explains it.
    ///
    /// THE BUG THIS IS THE FIX FOR. `construction`'s entry allowed 50 000 work units and its note
    /// said the gate measured "about 15 600". The tree measured three times that — so the entry read
    /// as a guard with two-thirds of its room to spare while it was in fact a few per cent from
    /// firing, and the first thing that pushed it over would have been read as a regression in
    /// whatever touched it last. A number whose written provenance is prose is a number nobody can
    /// check.
    ///
    /// Every arm here is about that: the measurement is a NUMBER and not a sentence, the budget is
    /// DERIVED from it by one declared slack rather than chosen per entry, and the date and the tree
    /// it was taken on are written down so a reader can take it again.
    #[test]
    fn every_budget_carries_the_measurement_it_was_set_from() {
        for b in SELFTEST_BUDGETS {
            let name = b.gate;
            assert!(
                b.measured > 0.0,
                "`{name}` has a budget and no measurement. The entry IS the measurement; a budget \
                 set from nothing cannot be checked, re-taken, or argued with."
            );
            // THE BUDGET IS THE MEASUREMENT TIMES THE ONE DECLARED SLACK, not a number somebody
            // liked. Compared with a tolerance because it is written as a product of two floats.
            let want = b.measured * BUDGET_SLACK;
            assert!(
                (b.allowed - want).abs() < 1.0,
                "`{name}`'s budget is {} against a measurement of {} — that is {:.2}x, and the \
                 declared slack is {BUDGET_SLACK}x. A budget that drifted from its own measurement \
                 is the shape `construction` was in when it sat a few per cent under a budget its \
                 note said it used a third of.",
                b.allowed,
                b.measured,
                b.allowed / b.measured
            );
            // WHEN, AND ON WHAT. `YYYY-MM-DD <sha>`, both halves present and both readable.
            let (date, sha) = b
                .taken
                .split_once(' ')
                .unwrap_or_else(|| panic!("`{name}`'s measurement does not say when it was taken"));
            assert!(
                date.len() == 10 && date.split('-').count() == 3,
                "`{name}`'s measurement date `{date}` is not a YYYY-MM-DD"
            );
            assert!(
                sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "`{name}`'s measurement names no tree: `{sha}` is not a commit sha, so nobody can \
                 re-take it"
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
    /// ITEM 205: the runner the REPORT_ONLY header says this vocabulary serves is still invoked.
    #[test]
    fn the_all_runner_this_vocabulary_serves_is_invoked() {
        let cx = Ctx::workspace().expect("the workspace opens");
        if let Err(why) = ALL_RUNNER.holds(&cx) {
            panic!("REPORT_ONLY's header rests on `cargo xtask gate --all` running in CI: {why}");
        }
    }

    /// ITEM 177: `ReleaseTime` reads `full_gate::REGISTRY_NOT_IN_CI` and excuses nothing without
    /// an entry there, so a `ReleaseTime` posture without one is a posture that can never apply.
    #[test]
    fn every_release_time_posture_has_the_full_gate_entry_it_reads() {
        for p in REPORT_ONLY {
            if matches!(p.excuse, Excused::ReleaseTime) {
                assert!(
                    crate::full_gate::REGISTRY_NOT_IN_CI
                        .iter()
                        .any(|(n, _, _)| *n == p.name),
                    "`{}` is excused as ReleaseTime and has no REGISTRY_NOT_IN_CI entry, so the \
                     excuse can never hold and `--all` scores it on every run",
                    p.name
                );
            }
        }
    }

    /// ITEM 177: ship-ready's red is excused under `--all` while ci.yml runs it and branch
    /// protection requires it, and scored the moment either stops being true.
    #[test]
    fn the_ship_ready_posture_holds_while_its_promotion_facts_do() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let red = verdict(vec![Row::fail("ship-ready:standing-reds", "t", "d")]);
        assert!(
            excused_from_all("ship-ready", &cx, &red).is_some(),
            "ship-ready is red on the dev line by design and --all must not count it"
        );
        let ci = cx.read(".github/workflows/ci.yml").expect("ci.yml reads");
        let mut ov = Overlay::new();
        ov.set(
            ".github/workflows/ci.yml",
            ci.replace("run: cargo xtask gate ship-ready\n", "run: true\n"),
        );
        assert!(
            excused_from_all("ship-ready", &cx.with_overlay(ov), &red).is_none(),
            "a ship-ready ci.yml no longer runs is a gate nothing runs, and is scored"
        );
        let bp = cx
            .read("scripts/ci-branch-protection.sh")
            .expect("ci-branch-protection.sh reads");
        let mut ov = Overlay::new();
        ov.set(
            "scripts/ci-branch-protection.sh",
            bp.replace("\"ship-ready\"", "\"not-required\""),
        );
        assert!(
            excused_from_all("ship-ready", &cx.with_overlay(ov), &red).is_none(),
            "a ship-ready branch protection no longer requires is not a promotion check"
        );
    }

    /// The names in `land_construction_standing_reds`'s heredoc in scripts/land.sh.
    fn land_sh_standing_reds(text: &str) -> Vec<String> {
        let body = text
            .split("land_construction_standing_reds() {")
            .nth(1)
            .expect("land.sh defines land_construction_standing_reds");
        let heredoc = body
            .split("<<'EOF'\n")
            .nth(1)
            .expect("the function reads its list from a quoted heredoc")
            .split("\nEOF\n")
            .next()
            .expect("the heredoc closes");
        heredoc
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// ITEM 206: land.sh subtracts EXACTLY the rows `--posture` excuses. They differed by four
    /// rows, so a landing on the dev line was allowed a red `--all` and ship-ready then scored.
    #[test]
    fn land_sh_subtracts_exactly_the_construction_standing_reds() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let land = cx.read("scripts/land.sh").expect("scripts/land.sh reads");
        let shell: BTreeSet<String> = land_sh_standing_reds(&land).into_iter().collect();
        let rust: BTreeSet<String> = CONSTRUCTION_STANDING_REDS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            shell.difference(&rust).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "land.sh excuses rows CONSTRUCTION_STANDING_REDS does not"
        );
        assert_eq!(
            rust.difference(&shell).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "CONSTRUCTION_STANDING_REDS excuses rows land.sh does not"
        );
    }

    /// ITEMS 207, 208: prose in this file that says a row is CARRIED on a standing-red list names a
    /// row that list carries. Two sentences said so of ceiling-rose and plane-no-money, neither was
    /// a member, and a maintainer was told a live red was excused.
    #[test]
    fn prose_that_says_a_row_is_carried_names_a_member() {
        // Comment text only, joined into one line so a sentence that wraps is still one sentence.
        let prose: String = include_str!("mod.rs")
            .lines()
            .map(str::trim_start)
            .filter_map(|l| {
                l.strip_prefix("///")
                    .or_else(|| l.strip_prefix("//"))
                    .map(str::trim)
            })
            .collect::<Vec<_>>()
            .join(" ");
        let lists: [(&str, &[&str]); 5] = [
            ("CONSTRUCTION_STANDING_REDS", CONSTRUCTION_STANDING_REDS),
            ("STRUCTURE_LINT_STANDING_REDS", STRUCTURE_LINT_STANDING_REDS),
            ("QA_NAMES_STANDING_REDS", QA_NAMES_STANDING_REDS),
            (
                "MONEY_INVARIANTS_STANDING_REDS",
                MONEY_INVARIANTS_STANDING_REDS,
            ),
            (
                "CONFORMANCE_SYNC_STANDING_REDS",
                CONFORMANCE_SYNC_STANDING_REDS,
            ),
        ];
        let mut offenders = Vec::new();
        // An id, backticked, followed by "is on this list" (said in a list's own doc block).
        let mut rest = prose.as_str();
        while let Some(at) = rest.find("` is on this list") {
            let id = rest[..at].rsplit('`').next().unwrap_or_default();
            if !lists.iter().any(|(_, rows)| rows.contains(&id)) {
                offenders.push(format!("`{id}` is on this list"));
            }
            rest = &rest[at + 1..];
        }
        // A sentence naming a backticked id and ending "on" or "onto" a backticked list name.
        for (list, rows) in lists {
            for verb in [" on `", " onto `"] {
                let needle = format!("{verb}{list}`");
                let mut rest = prose.as_str();
                while let Some(at) = rest.find(&needle) {
                    // The sentence the claim is in, back to its start.
                    let sentence = rest[..at].rsplit(['.', ';']).next().unwrap_or_default();
                    let ids: Vec<&str> = sentence.split('`').skip(1).step_by(2).collect();
                    if let Some(id) = ids
                        .iter()
                        .rev()
                        .find(|i| i.contains('-') && !i.contains(' ') && !i.contains('/'))
                    {
                        if !rows.contains(id) {
                            offenders.push(format!("`{id}` ... on `{list}`"));
                        }
                    }
                    rest = &rest[at + needle.len()..];
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "prose says these rows are carried as standing reds, and the list does not carry \
             them: {offenders:?}"
        );
    }

    /// ITEM 235: a stale `OnlyRows` name is answered with the list that governs THAT gate, and a
    /// list with no mirror names none.
    #[test]
    fn a_stale_standing_red_names_the_list_that_governs_it() {
        let sr = StandingReds {
            rows: &["qa-names:path-names-a-live-path"],
            list: "QA_NAMES_STANDING_REDS",
            mirror: None,
        };
        let lines = only_rows_unexplained(&sr, &verdict(vec![]));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("QA_NAMES_STANDING_REDS"), "{lines:?}");
        assert!(!lines[0].contains("CONSTRUCTION"), "{lines:?}");
        assert!(!lines[0].contains("land.sh"), "{lines:?}");
        assert_eq!(standing_list_of("qa-names"), Some("QA_NAMES_STANDING_REDS"));
        assert_eq!(
            standing_list_of("construction"),
            Some("CONSTRUCTION_STANDING_REDS")
        );
    }

    /// ITEM 176: the qa-names posture holds on the tree — the exact check ci.yml's blocking
    /// `cargo xtask gate qa-names --posture` step makes. The entry said "green outright" over a
    /// gate that was red, with an empty list that could excuse nothing.
    #[test]
    fn the_qa_names_posture_holds_on_the_tree() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = find("qa-names").expect("qa-names is registered");
        let v = execute(&*(reg.build)(), &cx);
        if v.red {
            assert!(
                excused_from_all("qa-names", &cx, &v).is_some(),
                "qa-names is red beyond QA_NAMES_STANDING_REDS: {:?} {:?}",
                v.rows
                    .iter()
                    .filter(|r| r.status != crate::ledger::Status::Pass)
                    .map(|r| format!("{} {}", r.id, r.detail))
                    .collect::<Vec<_>>(),
                v.problems
            );
        }
    }

    /// ITEM 9 (posture): the money-invariants posture holds on the tree — the exact check ci.yml's
    /// blocking `cargo xtask gate money-invariants --posture` step makes — and the standing list
    /// names exactly the rows that are red (none, since W2.12 drained `no-stored-price`).
    #[test]
    fn the_money_invariants_posture_holds_on_the_tree() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = find("money-invariants").expect("money-invariants is registered");
        let v = execute(&*(reg.build)(), &cx);
        assert!(
            excused_from_all("money-invariants", &cx, &v).is_some() || !v.red,
            "money-invariants is red beyond MONEY_INVARIANTS_STANDING_REDS: {:?} {:?}",
            v.rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .map(|r| format!("{} {}", r.id, r.detail))
                .collect::<Vec<_>>(),
            v.problems
        );
        let sr = StandingReds {
            rows: MONEY_INVARIANTS_STANDING_REDS,
            list: "MONEY_INVARIANTS_STANDING_REDS",
            mirror: None,
        };
        assert!(
            only_rows_unexplained(&sr, &v).is_empty(),
            "MONEY_INVARIANTS_STANDING_REDS carries a row that is not red (stale) or misses one \
             that is: {:?}",
            only_rows_unexplained(&sr, &v)
        );
    }

    /// ITEM 165 (posture): the conformance-sync posture holds on the tree — the exact check
    /// ci.yml's blocking `cargo xtask gate conformance-sync --posture` step makes — and the
    /// standing list names exactly the rows that are red: a NEW red on any other row, or a
    /// freshness row that has gone green without its name being struck, fails here.
    #[test]
    fn the_conformance_sync_posture_holds_on_the_tree() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = find("conformance-sync").expect("conformance-sync is registered");
        let v = execute(&*(reg.build)(), &cx);
        assert!(
            excused_from_all("conformance-sync", &cx, &v).is_some() || !v.red,
            "conformance-sync is red beyond CONFORMANCE_SYNC_STANDING_REDS: {:?} {:?}",
            v.rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .map(|r| format!("{} {}", r.id, r.detail))
                .collect::<Vec<_>>(),
            v.problems
        );
        let sr = StandingReds {
            rows: CONFORMANCE_SYNC_STANDING_REDS,
            list: "CONFORMANCE_SYNC_STANDING_REDS",
            mirror: None,
        };
        assert!(
            only_rows_unexplained(&sr, &v).is_empty(),
            "CONFORMANCE_SYNC_STANDING_REDS carries a row that is not red (stale) or misses one \
             that is: {:?}",
            only_rows_unexplained(&sr, &v)
        );
    }

    /// The structure-lint posture holds on the tree it runs over — the same fact ci.yml's blocking
    /// `cargo xtask gate structure-lint --posture` step asserts — and the standing list names
    /// exactly the rows that are red: a NEW red on any other row, or a listed row that has gone
    /// green without its name being struck, fails here.
    #[test]
    fn the_structure_lint_posture_holds_on_the_tree() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let reg = find("structure-lint").expect("structure-lint is registered");
        let v = execute(&*(reg.build)(), &cx);
        assert!(
            excused_from_all("structure-lint", &cx, &v).is_some() || !v.red,
            "structure-lint is red beyond STRUCTURE_LINT_STANDING_REDS: {:?} {:?}",
            v.rows
                .iter()
                .filter(|r| r.status != crate::ledger::Status::Pass)
                .map(|r| format!("{} {}", r.id, r.detail))
                .collect::<Vec<_>>(),
            v.problems
        );
        let sr = StandingReds {
            rows: STRUCTURE_LINT_STANDING_REDS,
            list: "STRUCTURE_LINT_STANDING_REDS",
            mirror: None,
        };
        assert!(
            only_rows_unexplained(&sr, &v).is_empty(),
            "STRUCTURE_LINT_STANDING_REDS carries a row that is not red (stale) or misses one \
             that is: {:?}",
            only_rows_unexplained(&sr, &v)
        );
    }

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
