//! `cargo xtask gate kind-isolation` — THE PLUGIN KINDS NEVER CROSS-CONTAMINATE.
//!
//! > "busbar = core + plugins. We have ~10 plugin kinds. They can never cross-contaminate. Never a
//! > plane-transport; we have planes, we have transports. If we ever need something new we make a
//! > new plugin kind." — owner, 2026-09-07
//!
//! A proposal to create `busbar-transport-a2a` was ruled catastrophic: it fuses a KIND
//! (`transport`) with another kind's INSTANCE (`a2a`), and merges back exactly what the plane/
//! transport split is tearing apart. The ruling is not advice; this gate is the place it becomes a
//! machine fact, so the fusion is impossible in code, at compile, and in CI.
//!
//! ## THE KIND TABLE IS DERIVED FROM THE TREE, NOT ASSERTED BESIDE IT
//!
//! [`KINDS`] is a table of MATCHERS, not a list of crates. Which crates exist, which planes exist,
//! and which transports exist are all read off `crates/*/Cargo.toml` on every run. That matters for
//! the instance vocabulary in particular: the words `a2a`, `mcp`, `voice`, `llm`, `admin` are known
//! to be PLANE INSTANCES because `crates/busbar-plane-*` says so, and `tcp`, `tls`, `http`, `sse`,
//! `ws`, `grpc`, `stdio` are known to be TRANSPORT INSTANCES because `crates/busbar-transport-*`
//! says so. Adding a plane teaches this gate a new banned word in every other kind, for free, on
//! the same commit — which is the only way a vocabulary rule survives a growing tree.
//!
//! ## FOUR ROWS
//!
//! * `kind-isolation:name` — a crate name resolves to EXACTLY ONE kind, its remainder never names
//!   another kind's instance, and its remainder never OPENS with another kind's marker word.
//!   `busbar-transport-a2a`, `busbar-plane-http`, `busbar-unit-mcp` and `busbar-plane-transport`
//!   are all refused.
//! * `kind-isolation:deps` — the kind-to-kind edge CLASSES in the manifests are the ones measured
//!   into [`REGISTRY_FILE`]'s `[[dep]]` rows. EVERY SHIPPED DEPENDENCY TABLE IS A MANIFEST EDGE —
//!   `[dependencies]`, `[build-dependencies]` and the per-target forms of both, with
//!   `package = "…"` and `[workspace.dependencies]` renames resolved to the package they name;
//!   see [`crate::manifest`] for the five spellings the one-section reader could not see, every
//!   one of which was proven to carry a plane into a transport with this row green.
//!   A NEW class is refused; a class that no longer exists is refused as a
//!   dead allowance. The measured graph is printed in the row's detail so the owner can tighten it
//!   by deleting lines rather than by re-deriving it. Inside the plane family a crate may only
//!   name its OWN instance, so `busbar-plane-llm` naming `busbar-llm-codec` is refused.
//! * `kind-isolation:test-deps` — THE OTHER HALF OF THE BUILD GRAPH. `[dev-dependencies]` was read
//!   by the battery rule and by nothing else, on the sentence "a test edge is not a shipped edge" —
//!   which is true, and is not a reason to leave it unmeasured. A plane declared in a transport's
//!   `[dev-dependencies]` is a plane compiled into that transport's test binary, and a red team
//!   walked one in through that table with every gate green. Its own row, its own graph: folding it
//!   into `:deps` would grant the shipped artifact the same edge.
//! * `kind-isolation:vocab` — non-comment, literal-blanked source of a kind-X crate never names
//!   another kind's instance identifiers: a transport never says `a2a`/`mcp`/`voice`/`llm`/`admin`,
//!   a plane never says `axum`/`hyper`/`tonic`/`tungstenite`/`tokio::net`, and neither a plane nor
//!   a codec ever names a transport crate.
//! * `kind-isolation:registry` — every crate in the census resolves to a kind IN THE TABLE. One
//!   that does not is refused with the owner's own instruction: **make a new plugin kind, do not
//!   fuse two.** THE CENSUS IS EVERY `Cargo.toml` IN THE REPOSITORY, and where a manifest sits is a
//!   finding rather than a filter: `off-tree-crate` for a crate of a kind living outside
//!   `crates/<dir>`, `nested-crate` for one buried inside another crate's directory, `unmembered`
//!   for one on disk and off `[workspace.members]`. All three were walked through by a red team
//!   with every gate green. The row also holds the census floor, the dead-kind rule, the
//!   `qa/construction.toml [gate.plugin_kinds]` cross-check, the [`OFF_TREE_MANIFESTS`] expiry and
//!   the LEGACY RATCHET.
//! * `kind-isolation:matrix` — the rows above hold the line for the WIRES, and none of them looked
//!   at `crates/busbar`, the COMPOSITION ROOT, where the tree hand-wires one file per plane and
//!   where a plane-named accept loop was landed on a sibling branch, all of it green because
//!   nothing counted it. This row counts, for EVERY kind and EVERY crate, how many times that crate
//!   names that kind's derived vocabulary — every `.rs` and `.toml` under it, WHOLE TEXT, comments
//!   and tests and Cargo features and filenames included — against per-cell ceilings in
//!   [`REGISTRY_FILE`]'s `[[edge]]`, `[[cell]]` and `[[disagreement]]` tables, exact in both
//!   directions. See [`matrix`].
//!
//! ## THE TARGET NAMING SCHEME IS `busbar-<kind>-<name>`, AND THE GATE ACCEPTS BOTH
//!
//! The owner's scheme (2026-09-07) is `busbar-<kind>-<name>`: SEGMENT TWO IS THE KIND. The tree is
//! not renamed yet, so the kinds whose crates predate it — `busbar-caps`, `busbar-kernel`,
//! `busbar-contract`, `busbar-grammar`,
//! the `*-codec` halves and the `busbar-plugin-*` tooling — reach their kind through
//! the EXPLICIT TABLE below rather than through segment two. That table is the whole of the
//! exception: a name that is neither in it nor `busbar-<kind>-…` for a kind IN it is refused, in
//! the owner's own words. Nothing is grandfathered by silence, and a FIVE-segment name is refused
//! outright — the scheme has three segments, four only for a dialect.
//!
//! ## DIALECT IS NOT A KIND
//!
//! A DIALECT is a thing INSIDE a plane (llm 6, mcp 1, a2a 1, streaming N) — DECISIONS #4. It is not
//! a plugin and not a kind: there are no per-dialect crates, no Dialect trait, no `dialect` row in
//! the table, and no four-segment `busbar-plane-<plane>-<dialect>` crate to resolve into one.
//! Today's `*-codec` crates are the codec halves of their plane (`busbar-llm-codec` belongs to
//! `llm`), which is why the plane-to-codec edge is in the measured graph.
//!
//! ## VOICE AND STREAMS ARE THE STREAMING PLANE
//!
//! The fourth plane is STREAMING (DECISIONS #18): `busbar-plane-streaming`, whose `PlaneMeta::KEY`
//! is `"streaming"`. `voice` is one dialect inside it, still spelled by `busbar-voice-codec` until
//! the #19 codec rename, and `streams` is its config section (`streams:`). [`PLANE_ALIASES`] holds
//! the three spellings together so they are one instance for every rule here — canonical on the
//! plane's DECLARED key, which `:registry` reads off the plane's own source — and holds each on a
//! ratchet: an alias is RED once the crate that spells it is gone.
//!
//! ## THE LEGACY CRATES ARE EXEMPT UNTIL THEY ARE DELETED, AND THE EXEMPTION RATCHETS
//!
//! `busbar-core`, `busbar-llm`, `busbar-mcp`, `busbar-a2a` and `busbar-voice` are the retiring
//! 1.5.x crates. They are their own kind (`legacy`), exempt as a dependency SOURCE and from the
//! vocabulary rule, because they predate the split and reporting them would only restate that the
//! retirement is in flight. The exemption cannot outlive them: a name on [`LEGACY_CRATES`] that is
//! no longer in the tree is RED, so the last delete forces the row to be struck rather than left
//! standing as a permanent hole. Nothing new may join that list without an owner edit, and no
//! non-legacy crate may grow an edge INTO one — that edge class is not in the measured graph.
//!
//! ## THE DRAIN IS NOT COVERED BY THAT EXEMPTION — IT IS NAMED, EDGE BY EDGE, IN `qa/`
//!
//! > "while busbar-core drains, it MAY depend on unit crates … the row must be a NAMED TRANSITIONAL
//! > EXEMPTION that is empty on the ship sha." — owner, 2026-09-08
//!
//! The blanket `legacy`-as-source exemption is about the edges the 1.5.x crates ALREADY had. The
//! drain creates new ones, pointing the other way: `busbar-core -> busbar-unit-audit` is the
//! retirement in progress, and `busbar-core -> busbar-transport-ws` would be the fusion. Nothing in
//! "legacy is unscored" can tell those apart, so the edges INTO the kinds the drain targets
//! ([`DRAIN_TARGET_KINDS`]) leave the blanket exemption and are read off [`REGISTRY_FILE`]'s
//! `[[transitional]]` table instead: an edge a row names is accepted, an edge no row names is RED.
//!
//! The table is DATA, in `qa/`, because it is a statement about this week and not a rule; a row
//! naming a non-legacy source crate is REFUSED AT LOAD, because a table that could exempt anything
//! is not an exemption. And its expiry is not "the edge went away" — the drain lands edge by edge
//! across branches — but the SHIP SHA: the `kind-isolation-ship` twin is RED for any row whose
//! `from` crate still exists, so the table is empty at the tag or the tag does not happen.
//!
//! ## A CRATE THAT IS LANDING IS ANNOUNCED, NOT DISCOVERED
//!
//! The registry row refuses a crate that resolves to no kind, which is correct and which bites the
//! wrong way on the day a crate lands: the agent adding `crates/busbar-<kind>-<name>` would red a
//! gate they never touched. So the kind is taught FIRST — the kind is in the table below — and
//! [`REGISTRY_FILE`]'s `[[announced]]` table is what keeps that teaching from being scored as a dead
//! kind row (and its accepted name as a dead waiver) in the window before the crates exist. Landing
//! them is GREEN on the per-push gate, which is the entire purpose; the ship twin is what refuses an
//! announcement that has outlived its landing.
//!
//! The table is EMPTY today: its two rows (`busbar-core-config`, `busbar-core-hooks`) were struck on
//! 2026-09-22 when DECISIONS #37 killed both crates. The RULES did not go with them — the selftest
//! plants its own announcement ([`registry_announcing`]) rather than borrowing a live row, because a
//! case whose subject is a live row goes dark the day that row lands or dies.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_rows_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::manifest::{self, DepDecl};
use crate::scan;

mod base;
mod closure;
mod debt_free;
mod inputs;
mod matrix;
mod truths;

pub use closure::ROW_CLOSURE;
pub use inputs::ROW_INPUTS;
pub use matrix::ROW_MATRIX;
pub use truths::ROW_TRUTHS;

pub const ROW_NAME: &str = "kind-isolation:name";
pub const ROW_DEPS: &str = "kind-isolation:deps";
/// THE TEST HALF OF THE BUILD GRAPH, on its own row. `[dev-dependencies]` was read by the battery
/// rule and by nothing else, on the sentence "a test edge is not a shipped edge" — which is true,
/// and is not a reason to leave it unmeasured: a plane declared in a transport's `[dev-dependencies]`
/// is a plane compiled into that transport's test binary, and the red team walked a plane in
/// through this table with every gate green.
pub const ROW_TEST_DEPS: &str = "kind-isolation:test-deps";
pub const ROW_VOCAB: &str = "kind-isolation:vocab";
pub const ROW_REGISTRY: &str = "kind-isolation:registry";
/// THE SHIP-CRITERION ROWS. Owed only by the `kind-isolation-ship` registration — see the twin's
/// note in [`KindIsolationGate`].
pub const ROW_SHAPE: &str = "kind-isolation:shape";
pub const ROW_TESTKIT: &str = "kind-isolation:testkit";
/// NO CRATE IMPLEMENTS ANOTHER KIND'S ENTRY FACE. Per-push, because a wire that implements `Plane`
/// is a wire that IS a plane at the type level, whatever its manifest says.
pub const ROW_FACES: &str = "kind-isolation:faces";
/// THE LEGACY DRAIN'S EXPIRY. Ship-only: a `[[transitional]]` row exists because a 1.5.x crate is
/// retiring, and the tag is where "it retired" is checked.
pub const ROW_DRAIN: &str = "kind-isolation:legacy-drain";
/// Every data plane runs the WHOLE strict step list.
pub const ROW_STEPS: &str = "kind-isolation:plane-steps";
/// One wire, one registration.
pub const ROW_WIRES: &str = "kind-isolation:transport-registration";
/// THE CONTROL KIND'S CANNOT LIST, on the ship twin because the tree does not meet it yet.
pub const ROW_CONTROL: &str = "kind-isolation:control-path";

/// THE OWNER'S OWN INSTRUCTION, quoted verbatim wherever a crate does not resolve to a kind.
const MAKE_A_NEW_KIND: &str = "make a new plugin kind, do not fuse two";

/// THE GATE'S OWN DATA FILE: the `[[transitional]]` drain exemptions and the `[[announced]]`
/// landings. Read through [`Ctx::read`] like every other input, so a selftest can plant it.
pub const REGISTRY_FILE: &str = "qa/kind-isolation.toml";

/// A crate census below this is not a tree this gate can be a gate over.
///
/// 30, not 50 (item F0b, same shape as F0's `workspace-deps` `MIN_CRATE_MANIFESTS`, `98434a220`).
/// The Phase 4 fold's planned end state is 35 crates under `crates/`, 34 if `busbar-core-connsec`
/// folds, and the roster's 33 (docs/design/1.6.0-TODO.md "THE FOLD"; docs/design/BUSBAR-1.6.0.md
/// crate roster) — at 50 this row was already standing at its own floor pre-fold ("the tree sits
/// EXACTLY at MIN_MANIFESTS") and would have reddened `:registry` at fold #1. The floor guards
/// against a BLIND census (an emptied or unreadable `crates/`, a walk that stopped matching), which
/// finds a handful or nothing; it is not a ratchet on the roster. 30 sits three under the smallest
/// planned roster variant, so no planned fold trips it, while any walk that loses more than a
/// third of today's census is still RED.
const MIN_MANIFESTS: usize = 30;
/// Likewise for the source walk the vocabulary rule reads.
const MIN_SOURCES: usize = 600;

// ------------------------------------------------------------------------------------------------
// the kind table
// ------------------------------------------------------------------------------------------------

/// Which instance vocabulary a kind draws its names from.
///
/// `Plane` covers the plane crates, their pure `-codec` halves and the retiring legacy crates,
/// because a codec IS a plane's other half and is named after it by design. `Transport`
/// covers the transports. `Neutral` is every kind with no instance vocabulary of its own — and a
/// neutral crate may carry NEITHER vocabulary in its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Plane,
    Transport,
    Neutral,
}

/// One kind: its name, its instance family, and the matchers that recognise it.
///
/// A matcher is `=name` (exact), `name-` (prefix) or `*-name` (suffix). Precedence is exact, then
/// prefix, then suffix, and TWO KINDS MATCHING AT ONE PRECEDENCE IS THE FUSION REFUSAL rather than
/// a tie broken by table order.
struct KindDef {
    kind: &'static str,
    family: Family,
    matchers: &'static [&'static str],
}

/// THE KIND TABLE. The SEVEN plugin kinds (DECISIONS #3: store, secret, auth, hook, export, plane,
/// transport), the infra crate families that are NOT plugin kinds (unit, kernel, contract,
/// substrate, api, the plugin-abi/plugin-tooling TCB, the `core` neutral spine and
/// the `cleanliness` compiled-in surfaces), the composition root, and the retiring legacy crates.
///
/// `control` and `dialect` are NOT kinds (DECISIONS #4/#5): a dialect is a thing INSIDE a plane
/// (llm 6, mcp 1, a2a 1, streaming N) with no crate of its own, and admin/oauth2 are compiled-in
/// CLEANLINESS crates, one-way dep on core, off the hot path — not a `control` plugin kind. They
/// resolve here as the `cleanliness` infra family, never as one of the seven plugin kinds.
static KINDS: &[KindDef] = &[
    KindDef {
        kind: "root",
        family: Family::Neutral,
        matchers: &["=busbar"],
    },
    KindDef {
        kind: "plane",
        family: Family::Plane,
        matchers: &["busbar-plane-"],
    },
    // A DIALECT IS NOT A KIND (DECISIONS #4). It is a thing INSIDE a plane — no per-dialect crate,
    // no Dialect trait/kind — so there is no `dialect` row here and no four-segment
    // `busbar-plane-<plane>-<dialect>` crate to refine into one.
    // THE PRE-SPLIT DIALECTS. `busbar-llm-codec` is the `llm` plane's other half; the rename turns
    // it into a `busbar-plane-llm-<dialect>`. Until then it is its own kind, and the day the last
    // one goes the dead-kind rule below demands this row be struck.
    KindDef {
        kind: "codec",
        family: Family::Plane,
        matchers: &["*-codec"],
    },
    // CLEANLINESS SURFACES — admin & oauth2, and NOT a `control` plugin kind (DECISIONS #5).
    //
    // > "admin & oauth2 are NOT plugins. They are compiled-in cleanliness crates, one-way dep on
    // > core, off the hot path. There is no `control` plugin kind." — DECISIONS #5
    //
    // These are compiled-in served surfaces, never loaded over the ABI and never one of the seven
    // plugin kinds. They resolve here so the registry recognises `busbar-admin` and `busbar-oauth2`
    // without demanding a plugin kind; `busbar-plane-admin`, the retiring pre-rename spelling, is
    // held to the same family by a `[[registered]]` row until it is deleted. The FAMILY is `Neutral`
    // — a cleanliness crate carries no plane or transport INSTANCE in its NAME — while its source's
    // naming of other kinds' vocabulary is measured by the matrix like every other crate's.
    KindDef {
        kind: "cleanliness",
        family: Family::Neutral,
        matchers: &["=busbar-admin", "=busbar-oauth2"],
    },
    KindDef {
        kind: "transport",
        family: Family::Transport,
        matchers: &["busbar-transport-"],
    },
    KindDef {
        kind: "unit",
        family: Family::Neutral,
        matchers: &["busbar-unit-"],
    },
    // THE ENGINE + THE 8 WORKFLOW CRATES (DECISIONS #36). `busbar-kernel` is the loop/registry/
    // teller/sessions; `busbar-kernel-<name>` are the 8 workflow crates the 14 `busbar-unit-*` folded
    // into (identity, scope, budget, ledger, egress, breaker, wal, audit). One kind, matched by the
    // exact loop name AND the `busbar-kernel-` prefix — the same shape the `core` kind uses. A kernel
    // crate is NEUTRAL: it may carry no plane and no transport instance in its name, and its external
    // deps are the neutral spine ({contract, plugin-sdk} and other kernel crates), so an edge to a
    // plane, a dialect, a transport or a unit is a NEW class and is refused like any other.
    KindDef {
        kind: "kernel",
        family: Family::Neutral,
        matchers: &["=busbar-kernel", "busbar-kernel-"],
    },
    // THE COMPILED-IN SCAFFOLDING AROUND THE LOOP — `busbar-core-admin`, `busbar-core-oauth2`,
    // `busbar-core-substrate` (DECISIONS #37's core-3), plus `busbar-core-connsec`. A `core` crate
    // is NEUTRAL on exactly the terms `kernel` and `caps` are: it may carry no plane and no
    // transport instance in its name, and it reaches only the neutral spine ([`PENDING_EDGES`]), so
    // an edge to a plane, a dialect, a transport or a unit is a NEW class and is refused like any
    // other.
    //
    // NO `busbar-core-<kind>` EVER (#37: "a kind is a plugin, never a core crate"). That rule is
    // what killed `busbar-core-hooks` — deleted 2026-09-22 along with `busbar-core-config`, whose
    // one landed helper folded back into `busbar-kernel::config::parse`.
    //
    // A PREFIX, not a list of exact names: an exact matcher yields an EMPTY remainder, which would
    // mean `busbar-core-mcp` was never read for a plane instance at all — the kind would be a hole
    // the shape of every name it accepted. The prefix now costs NOTHING: it buys the name rule over
    // every future member and no core crate is waived past it.
    //
    // It used to cost one `ACCEPTED_NAMES` entry, for `busbar-core-transport` — a reviewed sentence
    // arguing that its `transport` remainder was the kind WORD (what the opaque `ConnectionSecurity`
    // wrap is FOR) rather than a transport INSTANCE. OWNER RULING R2 (2026-09-22, "AGREED") refused
    // that distinction: #37 says "no `busbar-core-<kind>` ever", transport is one of the seven kinds
    // (#3), and the ban is on the FORM, so no remainder-reading rescues it. The crate is renamed
    // `busbar-core-connsec` — named for the `ConnectionSecurity` type it builds, which is not a kind
    // word — and the waiver is deleted with it. A waiver that argues a rule does not mean what it
    // says is the thing the rule exists to stop.
    KindDef {
        kind: "core",
        family: Family::Neutral,
        matchers: &["busbar-core-"],
    },
    // `busbar-caps` is KILLED/folded into `busbar-contract` (DECISIONS #37/#38, W2.c): the capability
    // vocabulary is neutral ABI and lands in the one contract crate. There is no `caps` kind.
    KindDef {
        kind: "contract",
        family: Family::Neutral,
        matchers: &["=busbar-contract"],
    },
    // There is no `grammar` kind: `busbar-grammar` folded into `busbar-contract` (#40) and its
    // manifest is gone from the tree, so the row matched no crate and scored `dead-kind`.
    KindDef {
        kind: "substrate",
        family: Family::Neutral,
        matchers: &["=busbar-substrate", "=busbar-substrate-values"],
    },
    // There is no `api` kind: `busbar-api` retired in fold F4 — its last pieces went to
    // the homes their definitions name — so the row matched no crate and scored `dead-kind`.
    // There is no `timing` kind: busbar-timing folded into busbar-kernel as its feature-gated
    // `timing` module (OWNER Q70), so its lines are the kernel's and the row would name no crate.
    KindDef {
        kind: "plugin-abi",
        family: Family::Neutral,
        matchers: &["=busbar-plugin"],
    },
    KindDef {
        kind: "plugin-tooling",
        family: Family::Neutral,
        matchers: &["busbar-plugin-"],
    },
    KindDef {
        kind: "store",
        family: Family::Neutral,
        matchers: &["busbar-store-"],
    },
    KindDef {
        kind: "auth",
        family: Family::Neutral,
        matchers: &["busbar-auth-"],
    },
    KindDef {
        kind: "secret",
        family: Family::Neutral,
        matchers: &["busbar-secret-"],
    },
    KindDef {
        kind: "hooks",
        family: Family::Neutral,
        matchers: &["busbar-hook-", "busbar-hooks-"],
    },
    KindDef {
        kind: "export",
        family: Family::Neutral,
        matchers: &["busbar-export-"],
    },
    KindDef {
        kind: "legacy",
        family: Family::Plane,
        matchers: &["=busbar-llm", "=busbar-mcp", "=busbar-a2a", "=busbar-voice"],
    },
];

/// The naming scheme is `busbar-<kind>-<name>`, four segments only for a dialect. A fifth segment
/// is a name that has stopped saying what the crate IS.
const MAX_NAME_SEGMENTS: usize = 4;

/// PLANE SPELLINGS HELD TOGETHER: `(spelling, canonical, the crate that forces the spelling)`.
///
/// The CANONICAL side is the plane's DECLARED key — `busbar-plane-streaming`'s `PlaneMeta::KEY`,
/// `"streaming"` (DECISIONS #18: the fourth plane is STREAMING). `:registry` reads every plane
/// crate's declared key off its `impl PlaneMeta` and refuses an alias whose canonical side no plane
/// declares (`alias-undeclared`), so this table cannot drift from the plane it names.
///
/// * `voice` is one DIALECT inside the streaming plane, and `busbar-voice-codec` still spells it
///   until the #19 wave renames it `busbar-streaming-codec` (byte-identical). `busbar-plane-voice`
///   was the crate this entry used to key on; #18/#83 deleted it into `busbar-plane-streaming`,
///   and the codec is the one crate left whose name forces the alias. Canonicalising
///   `voice` onto `streaming` is what lets `busbar-plane-streaming -> busbar-voice-codec` read as a
///   plane naming ITS OWN codec rather than a cross-instance reach.
/// * `streams` is the plane's CONFIG SECTION (`streams:`, frozen 1.5.x wire), so it is the plane's
///   word in every other crate's source; it expires with the plane.
///
/// All three spellings are one instance for every rule here and banned vocabulary in every other
/// kind, and an entry is RED once the crate it names is gone.
const PLANE_ALIASES: &[(&str, &str, &str)] = &[
    ("voice", "streaming", "busbar-voice-codec"),
    ("streams", "streaming", "busbar-plane-streaming"),
];

/// Kinds the target scheme defines that the tree does not carry YET, each with its reason. The
/// dead-kind rule skips these — and the ratchet runs the other way: the day a crate of one of them
/// exists, the entry must be struck, or a kind would be both pending and live.
///
/// `dialect` was a pending kind and it is not a kind at all (DECISIONS #4). `secret` is pending
/// because its instances live OUTSIDE this repo: the owner deleted the in-tree fixture ("FIXTURES",
/// docs/design/1.6.0-QUESTIONS.md) and the kind is proven by the real plugin repo.
const PENDING_KINDS: &[(&str, &str)] = &[(
    "secret",
    "every plugin lives in its own repo (owner, 1.6.0-QUESTIONS.md \"PLUGIN HOME\"); the in-tree \
     secret fixture is deleted (\"FIXTURES\") and the kind is proven by GetBusbar/hashicorp-vault \
     through crates/plugin-loader/src/tests/plugin_proof_tests.rs (ci.yml `plugin-proofs`)",
)];

/// Edge classes the TARGET scheme has and the tree does not yet. They are allowed without being
/// scored as dead — a class that cannot exist until the rename lands cannot be a stale allowance.
const PENDING_EDGES: &[(&str, &str)] = &[
    // THE `core` KIND'S NEUTRAL SPINE, and deliberately nothing else. The crates being carved out
    // of `busbar-core` land branch by branch, so their edges cannot be measured yet; what CAN be
    // stated in advance is the same sink set `kernel` has. A `core` crate that reaches
    // a plane, a dialect, a transport or a unit is not on this list, so it is a NEW edge class and
    // is refused — which is the machine form of "a core crate names no plane, dialect, transport or
    // unit". A core crate that needs a sink not listed here adds the line and says why; the gate
    // names the missing class for it.
    //
    // `(core, caps)` and `(core, grammar)` are struck: neither `caps` nor `grammar` is a kind (both
    // crates folded into `busbar-contract`, W2.c and #40), so they granted nothing (`dead-grant`).
    // `(core, timing)` is struck the same way: busbar-timing folded into busbar-kernel (OWNER Q70).
    ("core", "contract"),
    ("core", "kernel"),
    ("core", "substrate"),
];

/// The retiring 1.5.x crates, named so the ratchet can check they still exist.
const LEGACY_CRATES: &[&str] = &["busbar-llm", "busbar-mcp", "busbar-a2a", "busbar-voice"];

/// THE MANIFESTS IN THIS REPOSITORY THAT ARE NOT CRATES OF THE TREE, each with the sentence that
/// says why, and each on the expiry ratchet every allowance in this file lives under: an entry that
/// covers no manifest is RED, so the list cannot become a set of holes nobody re-reads.
///
/// An entry ending in `/` covers a directory; anything else is one exact path. THIS IS THE WHOLE
/// EXEMPTION. Every other `Cargo.toml` in the repository is a crate of this tree, is censused, is
/// resolved to a kind, has its edges scored, and owes a `[workspace.members]` entry — which is what
/// closes the hole a plane-kind crate at `vendor/` walked through.
const OFF_TREE_MANIFESTS: &[(&str, &str)] = &[
    (
        "xtask/Cargo.toml",
        "the gate RUNNER. It is a workspace member and it is not a crate of the product tree: it \
         has no kind, it ships in no artifact, and every rule here is a rule it enforces rather \
         than one it is subject to.",
    ),
    (
        "xtask/fixtures/",
        "the gate self-tests' throwaway workspaces. Each one is a whole fake tree a rule is run \
         over — `dirty-plane/crates/busbar-plane-demo` exists precisely so a plane rule can be \
         proven RED — so they are inputs to the gates, never crates of the tree. They are outside \
         `[workspace.members]` by design and nothing in the product build reaches them.",
    ),
    (
        "examples/smart-router/rust-hook/Cargo.toml",
        "a documentation example: a standalone crate a READER of the docs compiles on their own \
         machine against the published plugin ABI. It is deliberately not a workspace member — \
         building it here would pin it to this tree's paths, which is the opposite of what the \
         example demonstrates.",
    ),
    (
        "fuzz/Cargo.toml",
        "the coverage-guided fuzz harnesses over the codec parse surface: a SELF-CONTAINED \
         workspace (its own empty `[workspace]` table), deliberately not a member of the root \
         workspace so a normal `cargo build`/`cargo test` never sees it and it adds zero cost to \
         per-push CI. It only builds when `cargo fuzz` invokes it (qa-fuzz.yml, at the qa \
         promotion boundary). It path-deps target crates by their sanctioned `test-support` \
         feature and modifies no crate source, so it is an input to fuzzing rather than a crate of \
         the product tree.",
    ),
    (
        "testing/ws-conformance/subject/Cargo.toml",
        "the Autobahn|Testsuite SUBJECT: a testkit binary that composes the same \
         `WsTransport::over(TcpTransport)` chain a transport battery test composes, so the \
         fuzzingclient has a real busbar wire to point at. It is a workspace member so \
         `testing/ws-conformance/scripts/run.sh` can build it with `-p ws-conformance-subject`, and \
         it is not a crate of the product tree: it ships in no artifact, `cargo build --bin busbar` \
         never builds it, and it carries no kind and no plane or transport instance of its own. It \
         is an input to the conformance leg, never a crate a rule here is written about.",
    ),
];

/// `qa/construction.toml`'s `[gate.plugin_kinds]` keys, each mapped onto the kind it names here.
/// A key that maps onto nothing in [`KINDS`] is a second kind vocabulary drifting beside this one.
///
/// The seven plugin kinds get a construction scope (`plane`, `transport`, `store`, `secret`,
/// `hook`, `auth`, `export`); `unit` scopes the core governance steps; `loader`/`abi` scope the TCB
/// crates the design excuses by name. `control` and `dialect` are gone (DECISIONS #4/#5), and the
/// old `pure_auth`/`egress_auth` split is collapsed into one `auth` key: outbound-sign is an
/// OPERATION of the auth kind, not a second kind (DECISIONS #3).
const CONSTRUCTION_KIND_KEYS: &[(&str, &str)] = &[
    ("plane", "plane"),
    ("unit", "unit"),
    ("transport", "transport"),
    ("store", "store"),
    ("hook", "hooks"),
    ("auth", "auth"),
    ("secret", "secret"),
    ("export", "export"),
    ("loader", "plugin-tooling"),
    ("abi", "contract"),
];

/// The crate names whose remainder trips a naming rule for a reason the owner has read.
///
/// Every one is a REVIEWED sentence, not a shrug, and every one EXPIRES: a waiver whose crate is
/// gone is RED, so the list cannot become a set of holes nobody re-reads.
///
/// It was TWO until OWNER RULING R2 (2026-09-22): `busbar-core-transport`'s entry is deleted, not
/// re-worded, because the crate it waived no longer exists — #37 bans the FORM `busbar-core-<kind>`
/// and the fix was the rename to `busbar-core-connsec`, not a better sentence. The one survivor is
/// a `busbar-unit-*` crate, which #36 retires on its own schedule.
const ACCEPTED_NAMES: &[(&str, &str)] = &[(
    "busbar-unit-transport-key",
    "the unit that holds TRANSPORT KEYS. `transport` here is the kind word describing what the \
         unit's keys are for, never a transport instance — no transport is named, and the crate \
         depends on busbar-contract (contract-transport folded into it) as every unit on that path \
         does.",
)];

// ------------------------------------------------------------------------------------------------
// the measured dependency graph
// ------------------------------------------------------------------------------------------------

/// THE EDGE CLASSES THE ARCHITECTURE GRANTS, and the whole of what the SHIP twin permits.
///
/// This is not a measurement and it is not a ratchet. It is the read of `ARCHITECTURE.md` 1.1 and
/// 3.1 that an audit of all 220 workspace-internal edges produced: 105 of them land in one of these
/// classes and 87 land nowhere the architecture speaks. The per-push rows hold the tree to the
/// EXACT edges it has today, instance by instance, so the debt cannot grow; the ship twin holds it
/// to THIS, because the criterion for a tag is not "no worse than yesterday".
///
/// [`PENDING_EDGES`] joins it: those are classes the DESIGN grants ahead of the tree, which is the
/// same kind of statement made about a crate that does not exist yet.
const ARCHITECTURE_ALLOWED: &[(&str, &str)] = &[
    // `(api, contract)` WAS HERE, a transitional grant for `busbar-api`'s re-export of the record
    // SHAPES (#83/#84). #84's end state retired the crate (fold F4), the `api` kind lost
    // its only member, and the grant went with it, as its own paragraph said it would.
    // THE #40 WALL, GRANTED FOR ALL SEVEN PLUGIN KINDS AT ONCE. DECISIONS #40(a), OWNER-LOCKED:
    // "a plugin crate's entire workspace dependency closure = `busbar-contract` and nothing else".
    // So a plugin-kind crate's edge to the contract is not a coupling this gate ratchets: it is the
    // ONE edge the architecture leaves a plugin, and `:closure` measures everything past it.
    // It is stated here for every kind in `truths::PLUGIN_KINDS`, not kind by kind as each one's
    // first crate happened to reach the contract — `store`, `plane` and `transport` were granted
    // that way and `auth`, `hooks`, `secret` and `export` were not, so the day the dependency-wall
    // wave repointed `busbar-hooks-ranking` at the contract, the plugin DOING what #40 asks was
    // scored `new-forbidden-edge`. `the_wall_is_granted_for_every_plugin_kind` holds this block to
    // the seven; [`is_the_wall`] is the same rule where an edge or a vocabulary cell is judged.
    ("auth", "contract"),
    ("export", "contract"),
    ("hooks", "contract"),
    ("plane", "contract"),
    ("secret", "contract"),
    ("store", "contract"),
    ("transport", "contract"),
    // No `(codec, grammar)`, `(contract, grammar)` or `(kernel, grammar)` grant: the closed span
    // grammar is `busbar-contract`'s own surface since `busbar-grammar` folded into it (#40), so a
    // codec or the loop reaching it is the `-> contract` edge, and a grant naming a kind the table
    // does not have is a `dead-grant`.
    ("kernel", "contract"),
    // The loop naming a `core` crate — a compiled-in cleanliness surface on the neutral spine — is
    // the same shape as `kernel` naming `contract`. The instance that produced this
    // grant (`busbar-kernel` -> `busbar-core-config`) is GONE: #37 killed that crate and its one
    // helper came home to `busbar_kernel::config::parse`, so the class currently has no edge under
    // it. The grant stays because this list is the READ OF THE ARCHITECTURE, not a measurement of
    // the tree (see this const's own doc) — striking it would be an architecture change.
    ("kernel", "core"),
    // A kernel workflow crate may depend on other kernel crates (DECISIONS #36 group structure, e.g.
    // budget -> ledger); intra-tier edges are allowed structure, not a widening.
    ("kernel", "kernel"),
    // A kernel crate may name the author-side plugin machinery face (the dep-wall admits plugin-sdk).
    ("kernel", "plugin-tooling"),
    ("legacy", "contract"),
    // A PLANE ADAPTER PATH-DEPS ITS OWN CODEC (DECISIONS #6/#18/#21). The codec crate is stateful
    // (entropy pools, streaming accumulators, feature `#[cfg]`) and so cannot live in the pure
    // `busbar-plane-<x>` adapter's `src/`; #21 states in its own words that "the codec crate REMAINS
    // a pure path-dep of its plane adapter". So `busbar-plane-<x> -> busbar-<x>-codec` is the
    // architecture's intended PERMANENT shape, not grandfathered debt. This grants the CLASS; the
    // instance seal below (the cross-instance witness) still refuses a plane naming a DIFFERENT
    // plane's codec — a plane may path-dep ITS OWN codec and nothing else.
    ("plane", "codec"),
    // The composition root is the one thing that names all three axes — that is what a root IS.
    //
    // ROOT -> EVERY PLUGIN KIND IT LINKS IS ONE GRANTED CLASS, not a list that grew kind by kind.
    // Roster definition 1 (ARCHITECTURE.md 1.1): the composition root is "the only place that names
    // which crates exist and wires them at boot" — naming a plugin crate and folding it onto its
    // axis IS the root's job, so the edge is the architecture, not debt (ARCHITECT ruling
    // 2026-09-25 "K5d residue"). `plane`, `store` and `transport` were granted as the first crate
    // of each landed; `export` (the built-in sinks, #3 / item 141) and `hooks` (the ranking hooks
    // K5d moved onto the root's linked tables) were left out, so the root doing its job was scored
    // `not-allowed` and the K5d edge `new-forbidden-edge`. `auth` and `secret` are absent because
    // the root links no crate of either kind; a grant with no edge under it is a sentence about a
    // tree that does not exist. `the_root_is_granted_every_plugin_kind_it_links` measures the
    // root's shipped edges and refuses a plugin kind the root links without a grant here. The
    // grant is the ROOT's: a non-root crate reaching a plugin crate is still refused (selftest).
    ("root", "cleanliness"),
    ("root", "contract"),
    ("root", "export"),
    ("root", "hooks"),
    ("root", "kernel"),
    ("root", "legacy"),
    ("root", "plane"),
    ("root", "plugin-tooling"),
    ("root", "store"),
    ("root", "substrate"),
    ("root", "transport"),
    ("root", "unit"),
    ("substrate", "contract"),
    // `("transport", "transport")` WAS HERE, AND IT IS STRUCK.
    //
    // It granted the CLASS `transport -> transport` — eight live edges (`grpc -> http`,
    // `grpc -> tcp`, `http -> tcp`, `http -> tls`, `sse -> http`, `tls -> tcp`, `ws -> http`,
    // `ws -> tcp`) — on the citation *"ARCHITECTURE.md 3.4 `COMPOSES_OVER`: a wire composed over
    // a lower wire; THE ROOT SUPPLIES THE LAYER."*
    //
    // THE CITATION ARGUES AGAINST ITS OWN VERDICT. If the root supplies the layer, the transport
    // crate does not need to name the lower transport at COMPILE time; `COMPOSES_OVER` is an
    // associated const on `TransportMeta` (ARCHITECTURE.md:669) — a RUNTIME registry string, not a
    // crate edge — and ARCHITECTURE.md §5's composition table is a table of wire layering, not of manifests. What
    // the cited document actually says about manifests is ARCHITECTURE.md:119 §1.2: *"any
    // dependency on … another plane or A TRANSPORT is a CI failure"*, with exactly one exception,
    // a dialect crate naming its own plane. BUSBAR-1.6.0.md:364 #40(a) is flatter still:
    // `closure ∩ {… any other plugin} = ∅`, and a transport is one of the seven plugin kinds.
    //
    // It was also the ONE surviving member of a shape this file may not carry: a blanket grant of
    // a plugin kind to ITSELF. A granted class is a rule that cannot fail, and #40(a) is not a
    // rule this gate may be unable to fail. If one of the eight edges is legitimate it owes a
    // REVIEWED ROW naming those two crates and the sentence that admits them — not a class grant
    // that admits every transport pair the tree will ever have. `closure::rule_closure` refuses
    // the shape outright so it cannot come back by way of the citation.
    //
    // `("kernel", "kernel")`, `("unit", "unit")` and the TCB's `("plugin-tooling",
    // "plugin-tooling")` are NOT this shape and stay: none of the three is one of the seven plugin
    // kinds, and #36's group structure grants intra-tier edges inside the kernel by name.
    ("unit", "contract"),
    ("unit", "unit"),
    // A CLEANLINESS SURFACE (admin/oauth2) is compiled-in with a one-way dep on core (DECISIONS #5).
    // The ship twin permits its contract edge here; its core/substrate/api/loader edges are
    // measured in the `[[dep]]` ledger like every other Neutral kind's.
    ("cleanliness", "contract"),
];

/// The kind `busbar-contract` resolves to — the one sink #40 leaves a plugin.
pub(super) const CONTRACT_KIND: &str = "contract";

/// THE #40 WALL AS A RULE: a crate of one of the seven plugin kinds naming `busbar-contract`.
///
/// That edge is the rule itself, not an instance of debt, so it owes NO per-crate row: `:deps` and
/// `:test-deps` do not ask for a `[[dep]]` row for it, and `:matrix` does not measure a plugin
/// crate's contract column (a plugin names the face it is written against on every `use` line). A
/// row that still records one is reported as a per-crate exception to a rule that excepts nothing.
/// Everything a plugin reaches PAST the contract is still judged — here as an ungranted class, and
/// by `:closure` as a breach of the wall.
pub(super) fn is_the_wall(from: &str, to: &str) -> bool {
    to == CONTRACT_KIND && truths::PLUGIN_KINDS.contains(&from)
}

/// THE TRUSTED COMPUTING BASE: the loader and the plugin tooling, which `ARCHITECTURE.md` 1.4 says
/// in its own words are NOT kinds. Their edges are neither granted nor refused by the kind rules,
/// because the kind rules are not about them — so they carry their own verdict, they are still
/// written down instance by instance, and the ship twin still refuses them: a tag's criterion is
/// the architecture's own graph, and the TCB is a hole in that graph rather than a clause of it.
const ARCHITECTURE_TCB: &[(&str, &str)] = &[
    // The loader's store adapter names the folded capability vocabulary at its new home in
    // `busbar-contract` (formerly `busbar-caps`, W2.c).
    ("plugin-tooling", "contract"),
    ("plugin-tooling", "kernel"),
    ("plugin-tooling", "plugin-abi"),
    ("plugin-tooling", "plugin-tooling"),
    ("plugin-tooling", "secret"),
    ("plugin-tooling", "unit"),
];

/// The verdict a `[[dep]]` row must carry, and the whole vocabulary of them.
const DEP_VERDICTS: &[&str] = &["allowed", "tcb", "not-allowed", "owner-ruling-pending"];

/// The two halves of the build graph a `[[dep]]` or `[[question]]` row can be about.
const DEP_HALVES: &[&str] = &["shipped", "test"];

/// THE KINDS THE LEGACY DRAIN TARGETS — the ones a 1.5.x crate reaches only because its contents
/// are being moved OUT into them.
///
/// An edge from a legacy crate into one of these leaves the blanket `legacy`-as-source exemption
/// and must be named by a `[[transitional]]` row. Everything else a legacy crate names (the
/// contract, the api, the substrate, its own codec half, the plugin tooling) is a 1.5.x edge that
/// predates the split and dies with the crate; reporting those would restate the retirement rather
/// than gate it. These four are different: `busbar-core -> busbar-unit-audit` is the drain in
/// flight and `busbar-core -> busbar-transport-ws` is the fusion, and nothing about "legacy is
/// unscored" can tell them apart. A NAME can.
const DRAIN_TARGET_KINDS: &[&str] = &["unit", "plane", "transport", CLEANLINESS];

/// THE KIND THE CONTROL-PATH RULES READ. `control` is not a kind (DECISIONS #5); admin and oauth2
/// resolve as `cleanliness`, and every rule that asks about a served control surface asks about
/// this word. One spelling, so a rule cannot go on filtering for the retired one after the rest of
/// the file has moved: two did, and each compared nothing on every tree.
const CLEANLINESS: &str = "cleanliness";

// A CLEANLINESS SURFACE (admin/oauth2) is compiled-in with a one-way dep on core (DECISIONS #5).
// Unlike the retired `control` kind, its edges are NOT a closed sink set: admin/oauth2 legitimately
// name core, substrate, api and the plugin-loader TCB, so their dependency edges are recorded in
// the measured graph (the `[[dep]]` rows and [`PENDING_EDGES`]) like every other Neutral kind's.

// ------------------------------------------------------------------------------------------------
// the shape and the battery
// ------------------------------------------------------------------------------------------------

/// THE CLEANEST SIBLING PER KIND — the crate whose SINGLE ENTRY IMPLEMENTATION is what every
/// sibling of that kind owes. It is no longer the source of the kind's SKELETON: see
/// [`kind_skeleton`].
const EXEMPLARS: &[(&str, &str)] = &[
    ("plane", "busbar-plane-a2a"),
    ("transport", "busbar-transport-http"),
    ("unit", "busbar-unit-auth"),
];

/// THE KIND SKELETON IS THE SPEC'S, NEVER THE EXEMPLAR'S FILE LIST (`PLUGIN-TREE.md` §3).
///
/// It was the exemplar's top-level module set, which reads every DOMAIN module of one crate as part
/// of its kind's shape: `busbar-unit-wal` was charged with missing `challenge`, `carrier`,
/// `principal`, `chain`, `exchange`, `detect`, `cache`, `admin` and `module` — the auth unit's
/// subject matter, which the WAL unit has no business carrying — and all six sibling transports
/// were charged with missing `raw`, which is `busbar-transport-http`'s own body-reader. A shape
/// rule that grows a row every time the exemplar grows a file is not measuring shape; it is
/// measuring one crate's domain, and the only way to go green is to copy it.
///
/// PLUGIN-TREE.md §3 names the intersection instead, and it is small on purpose: `src/lib.rs` (the single `pub`
/// entry — checked as `no-lib`), `src/meta.rs` (the associated consts), `src/claims.rs` for the
/// kinds that CLAIM, the kind's own entry file (`unit.rs` / `plane.rs` / `transport.rs`), and
/// `src/tests/conformance.rs` (checked by the battery rule). Everything else is `src/<verb>.rs` —
/// "one file per declared responsibility" — which is per-crate by definition and is not skeleton.
fn kind_skeleton(kind: &str) -> BTreeSet<String> {
    let mut want: BTreeSet<String> = BTreeSet::new();
    want.insert("meta".to_string());
    // The entry file is named for the kind: a sibling's reader finds the same file in each.
    want.insert(kind.to_string());
    if CLAIMING_KINDS.contains(&kind) {
        want.insert("claims".to_string());
    }
    want
}

/// THE KINDS WHOSE ENTRY TRAIT IS A FACE A PLUGIN IMPLEMENTS.
///
/// `entry_trait` turns a kind word into its trait — `plane` into `Plane`, `transport` into
/// `Transport` — and this is the set that has one. It is deliberately not every kind in the table:
/// `Api`, `Caps`, `Grammar` and `Timing` are not faces anything implements, and reading a crate's
/// `impl Caps for …` as a kind claim would report a type name rather than a kind.
///
/// The `:faces` rule reads it in the direction `:shape` never did. `:shape` asks "does this crate
/// implement ITS OWN kind's trait exactly once", so a red team's `impl Plane for Wire` inside a
/// transport, and `impl Transport for P` inside a plane, produced a byte-identical row in both
/// directions: the rule never asked whether a crate implements SOMEBODY ELSE'S face.
const ENTRY_TRAIT_KINDS: &[&str] = &[
    "plane",
    "transport",
    "unit",
    "store",
    "auth",
    "secret",
    "hooks",
    "export",
];

/// The kinds that declare CLAIMS (`PLUGIN-TREE.md` §3): what the crate answers for.
/// An AUTH plugin is here for the reason the planes are: it declares what it answers for as DATA —
/// the same claim-table shape — rather than deciding it inside a handler. `control` and `dialect`
/// are gone (DECISIONS #4/#5); a `cleanliness` crate is compiled-in and declares no plugin claims.
const CLAIMING_KINDS: &[&str] = &["plane", "transport", "auth"];

/// The kinds that owe a shared conformance battery. The plugin kinds are here because a plugin is
/// exactly the thing whose contract is checked from outside; the exemplar kinds are here because the
/// ship criterion says every kind runs its kind's battery, with no exceptions. `cleanliness` owes
/// none — it is compiled-in, not a plugin whose contract is checked from outside (DECISIONS #5).
const BATTERY_KINDS: &[&str] = &[
    "plane",
    "transport",
    "unit",
    "store",
    "auth",
    "secret",
    "hooks",
    "export",
];

/// A crate whose name carries this is a shared battery rather than a product crate.
const BATTERY_MARKER: &str = "testkit";

/// A per-crate battery file matches this, under the crate's own `tests/`.
const CONFORMANCE_MARKER: &str = "conformance";

// ------------------------------------------------------------------------------------------------
// the vocabulary bans
// ------------------------------------------------------------------------------------------------

/// The transport LIBRARIES a plane crate may never name. A plane speaks the plane ABI; the moment
/// it names the crate that moves the bytes it has stopped being a plane.
const TRANSPORT_LIBS: &[&str] = &["axum", "hyper", "tonic", "tungstenite"];

/// A transport crate NAMED as a dependency path, in either spelling. Neither a plane nor a codec
/// may say it.
const TRANSPORT_CRATE_PATHS: &[&str] = &["busbar_transport_", "busbar-transport-"];

/// The one `tokio` submodule a plane may not reach: sockets are the transport's, not the plane's.
const TOKIO_NET: &str = "tokio::net";

// ------------------------------------------------------------------------------------------------
// the registry file — the two tables that are true of this week and false of the ship sha
// ------------------------------------------------------------------------------------------------

/// One `[[transitional]]` row: a NAMED edge the legacy drain is allowed to carry.
#[derive(Debug, Clone)]
struct Transitional {
    from: String,
    to: String,
    reason: String,
}

impl Transitional {
    /// Does this row name the edge `from -> dep`?
    ///
    /// `to` is an exact crate name or a `prefix*` glob. The glob is what lets ONE reviewed row cover
    /// `busbar-unit-*`: the drain lands audit, then scope, then auth, then cost, each on its own
    /// branch, and a table that had to be edited on every one of those branches would be edited
    /// without being read.
    fn covers(&self, from: &str, dep: &str) -> bool {
        if self.from != from {
            return false;
        }
        match self.to.strip_suffix('*') {
            Some(prefix) => dep.starts_with(prefix),
            None => self.to == dep,
        }
    }
}

/// One `[[announced]]` row: a crate that is being created right now.
#[derive(Debug, Clone)]
struct Announced {
    name: String,
    kind: String,
    reason: String,
}

/// One `[[registered]]` row: a crate whose KIND its name does not yet say.
///
/// The one exception to "a crate reaches its kind through its name", and it exists for one
/// situation: a kind has been created and the crate that is its first member has not been renamed
/// yet. `busbar-plane-admin` is kind `control` today and `busbar-control-admin` after R7.
#[derive(Debug, Clone)]
struct Registered {
    name: String,
    kind: String,
    reason: String,
}

/// One `[[edge]]` row: a KIND-TO-KIND vocabulary class the `:matrix` row measures, and the sentences
/// a reader needs to judge it. The prose belongs to the CLASS because that is what is being read —
/// the same split `[[transitional]]` already makes between the rule and the week.
#[derive(Debug, Clone)]
struct MatrixEdge {
    from: String,
    to: String,
    cite: String,
    why: String,
    drain: String,
}

/// One `[[cell]]` row: what one crate's naming of one kind MEASURES TODAY, exactly.
#[derive(Debug, Clone)]
struct MatrixCell {
    krate: String,
    kind: String,
    count: i64,
}

/// One `[[disagreement]]` row: a cell whose two scanners return different totals, and why.
///
/// Its own table rather than an optional field on `[[cell]]`, because every other row in this file
/// is a fixed set of required fields and an optional one would be the first thing a reader has to
/// remember. A disagreement is also its own fact: it says a spelling exists that one scanner cannot
/// see, which is a finding about the MEASUREMENT and not about the count.
#[derive(Debug, Clone)]
struct MatrixDisagreement {
    krate: String,
    kind: String,
    note: String,
}

/// One `[[dep]]` row: one crate's dependency on one other crate, in one half of the build graph,
/// at the EXACT number of declarations that state it today.
///
/// The `:deps` row held the manifests to a table of kind-to-kind CLASSES in Rust source, and a
/// class ratchet has unlimited slack INSIDE a class: `transport -> unit` was one measured line, so a
/// SECOND transport growing a dependency on a unit was green, and so was a third. An audit of all
/// 220 workspace-internal edges found 105 the architecture grants, 87 it does not, 15 in the
/// loader/ABI trusted base and 13 it never rules on at all — every one of them held by 38 lines
/// recording which pairs of kind WORDS had ever appeared together. So the row is the INSTANCE, and
/// the ratchet moves one edge at a time, exactly in both directions.
#[derive(Debug, Clone)]
struct DepEdge {
    from: String,
    to: String,
    /// `shipped` — `[dependencies]`, `[build-dependencies]` and their per-target forms — or `test`,
    /// which is `[dev-dependencies]`. Two halves and not one, because they are two claims: what the
    /// artifact links, and what the test binary links.
    half: String,
    count: i64,
    /// `allowed` | `tcb` | `not-allowed` | `owner-ruling-pending`. The first two are READINGS of
    /// [`ARCHITECTURE_ALLOWED`] and [`ARCHITECTURE_TCB`], not opinions a row is entitled to hold.
    verdict: String,
    cite: String,
    why: String,
    drain: String,
}

/// One `[[question]]` row: the question an `owner-ruling-pending` edge is asking.
///
/// Its own table rather than an optional field, on exactly the terms `[[disagreement]]` is: every
/// row in this file is a fixed set of required fields, and an optional one would be the first thing
/// a reader has to remember. A question is also its own fact — it says the architecture has not
/// ruled, which is a statement about the DESIGN and not about the count.
#[derive(Debug, Clone)]
struct DepQuestion {
    from: String,
    to: String,
    half: String,
    question: String,
}

/// One `[[face]]` row: a crate that implements ANOTHER kind's entry face today, at the exact number
/// of implementations, with the sentence that says why it is still here.
///
/// Four exist. `busbar-plane-admin` implements `Plane` and is kind `control` — the R7 rename is
/// what ends that; `busbar-a2a` implements `Transport` and is a retiring 1.5.x crate; the loader
/// implements `Store` because bridging the ABI is what a loader does; and the composition root
/// implements `Store` twice for its own assembly. Every one is DEBT with a number on it, and the
/// ship twin owes zero of them.
#[derive(Debug, Clone)]
struct FaceDebt {
    krate: String,
    face: String,
    count: i64,
    cite: String,
    why: String,
    drain: String,
}

/// [`REGISTRY_FILE`], read.
#[derive(Debug, Default)]
struct KindRegistry {
    transitional: Vec<Transitional>,
    announced: Vec<Announced>,
    registered: Vec<Registered>,
    /// The `:deps` and `:test-deps` rows' two tables — one row per edge instance, one question per
    /// unruled one.
    dep_edges: Vec<DepEdge>,
    dep_questions: Vec<DepQuestion>,
    /// The `:faces` row's table — one row per crate that implements another kind's entry face.
    faces: Vec<FaceDebt>,
    /// The `:matrix` row's three tables. They live in this reader rather than in a second one
    /// because there is ONE registry file and a file read twice is a file two rules can disagree
    /// about.
    matrix_edges: Vec<MatrixEdge>,
    matrix_cells: Vec<MatrixCell>,
    matrix_disagreements: Vec<MatrixDisagreement>,
    /// The `[[instance]]` table: the five plugin-instance axes C1 was never measured over (item
    /// 118). Same row shape as `[[cell]]` — crate, kind, today's exact count. See
    /// `matrix::instances`.
    instance_cells: Vec<MatrixCell>,
    /// Every named `[patch]`/`[replace]`/`[source]` allowance. See [`PatchAllow`].
    patch_allows: Vec<PatchAllow>,
    /// Rows REFUSED AT LOAD. A malformed or over-broad row is not skipped and it is not tolerated:
    /// it is reported, because a table that quietly drops what it cannot understand is a table that
    /// says yes to it.
    errors: Vec<String>,
}

impl KindRegistry {
    /// The kinds an announced row names, so the dead-kind rule can tell "no crate is one" from
    /// "no crate is one YET".
    fn announced_kinds(&self) -> BTreeSet<&str> {
        self.announced.iter().map(|a| a.kind.as_str()).collect()
    }

    /// The crate names an announced row names, for the same reason on the waiver side.
    fn announced_names(&self) -> BTreeSet<&str> {
        self.announced.iter().map(|a| a.name.as_str()).collect()
    }

    /// crate name -> the kind a `[[registered]]` row assigns it, as the kind table's own `&'static
    /// str` so an override and a resolved kind are the same value downstream.
    fn overrides(&self) -> BTreeMap<&str, &'static str> {
        self.registered
            .iter()
            .filter_map(|r| {
                KINDS
                    .iter()
                    .find(|d| d.kind == r.kind)
                    .map(|d| (r.name.as_str(), d.kind))
            })
            .collect()
    }
}

/// One `key = "value"` line, unquoted.
fn kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once('=')?;
    Some((
        k.trim().to_string(),
        v.trim().trim_matches('"').trim().to_string(),
    ))
}

/// The value of `key` in a parsed row, and the keys that were not asked for.
fn take_row(
    fields: &[(String, String)],
    want: &[&str],
    table: &str,
    at: usize,
    errors: &mut Vec<String>,
) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for key in want {
        match fields.iter().find(|(k, _)| k == key) {
            Some((_, v)) if !v.is_empty() => out.push(v.clone()),
            Some(_) => {
                errors.push(format!(
                    "empty-field\t{REGISTRY_FILE}:{at}\t`[[{table}]]` declares `{key}` with an \
                     empty value; every field of a row is part of the reason a human re-reads it"
                ));
                return None;
            }
            None => {
                errors.push(format!(
                    "missing-field\t{REGISTRY_FILE}:{at}\t`[[{table}]]` is missing `{key}`; the row \
                     is not readable and a row nobody can read is not an exemption"
                ));
                return None;
            }
        }
    }
    for (k, _) in fields {
        if !want.contains(&k.as_str()) {
            errors.push(format!(
                "unknown-field\t{REGISTRY_FILE}:{at}\t`[[{table}]]` declares `{k}`, which this \
                 table has no meaning for — a field the gate does not read is a field that says \
                 nothing"
            ));
            return None;
        }
    }
    Some(out)
}

/// Validate one accumulated row into the registry.
/// Why a `[[transitional]] to = "…*"` glob is not one kind's prefix, or `None` when it is.
///
/// The kind word is resolved through [`kind_head_words`], which is derived from the kind table's
/// own matchers — so a kind added tomorrow is a legal prefix tomorrow, and a word that is no kind
/// at all is refused today.
fn bad_transitional_prefix(to: &str) -> Option<String> {
    let prefix = to.strip_suffix('*').unwrap_or(to);
    if prefix.is_empty() {
        return Some(
            "covers EVERY crate in the tree — `dep.starts_with(\"\")` is true of all of them"
                .to_string(),
        );
    }
    let segs: Vec<&str> = prefix.split('-').collect();
    if segs.len() != 3 || segs[0] != "busbar" || !segs[2].is_empty() {
        return Some(format!(
            "is not of the form `busbar-<kind>-*` (it reads as {} segment(s) before the star)",
            segs.len()
        ));
    }
    let heads = kind_head_words();
    if !heads.contains_key(segs[1]) {
        return Some(format!(
            "names `{}`, which is no kind in the table ({})",
            segs[1],
            heads.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    None
}

/// ONE NAMED ALLOWANCE for a `[patch]`, `[replace]` or `[source]` redirect: the exact file, the
/// exact entry, and the sentence that says why the tree compiles something other than what its
/// manifests declare.
#[derive(Debug, Clone)]
pub struct PatchAllow {
    pub file: String,
    pub entry: String,
    pub reason: String,
}

fn push_row(reg: &mut KindRegistry, table: &str, fields: &[(String, String)], at: usize) {
    match table {
        "transitional" => {
            let Some(v) = take_row(fields, &["from", "to", "reason"], table, at, &mut reg.errors)
            else {
                return;
            };
            let (from, to, reason) = (v[0].clone(), v[1].clone(), v[2].clone());
            // REFUSED AT LOAD. This table is the LEGACY DRAIN's exemption; a row naming any other
            // source would let a live, non-retiring crate reach a unit or a plane through a
            // ratchet built for crates that are on their way out. That is the ruling being edited
            // rather than applied, so the row does not load at all.
            if !LEGACY_CRATES.contains(&from.as_str()) {
                reg.errors.push(format!(
                    "not-legacy\t{REGISTRY_FILE}:{at}\t`[[transitional]] from = \"{from}\"` is not \
                     a legacy crate ({}). This table exempts the DRAIN and nothing else; a \
                     non-legacy source reaching a unit or a plane through it is the fusion wearing \
                     the drain's name — {MAKE_A_NEW_KIND}",
                    LEGACY_CRATES.join(", ")
                ));
                return;
            }
            if let Some(i) = to.find('*') {
                if i + 1 != to.len() {
                    reg.errors.push(format!(
                        "bad-glob\t{REGISTRY_FILE}:{at}\t`to = \"{to}\"` — the only glob a row may \
                         carry is a trailing `*`, so what a row covers can be read off it"
                    ));
                    return;
                }
                // A TRAILING `*` IS NOT ENOUGH: WHAT IT COVERS MUST BE ONE KIND'S PREFIX.
                //
                // `to = "*"` passes the test above — the star IS trailing — and `covers` then does
                // `dep.starts_with("")`, which is true of every crate in the tree. One character
                // turns the drain's exemption into a blanket amnesty for every legacy -> unit,
                // legacy -> plane, legacy -> dialect and legacy -> transport edge there will ever
                // be, and nothing downstream says a word, because the row that granted it is a row
                // the reader accepted. `busbar-*` is the same hole one character longer.
                //
                // So the prefix must be `busbar-<kind>-`: the crate scheme's own first two
                // segments, with the kind word read off the KIND TABLE rather than a list beside
                // it. That is a glob a reader can price — every crate it covers is one kind — and
                // it is the only glob the real file uses.
                if let Some(reason) = bad_transitional_prefix(&to) {
                    reg.errors.push(format!(
                        "bad-glob\t{REGISTRY_FILE}:{at}\t`to = \"{to}\"` {reason}. A \
                         `[[transitional]]` glob must be `busbar-<kind>-*` — one kind's prefix, so \
                         a reader can price what the exemption covers by reading it. An exemption \
                         that spans more than one kind is the ruling being deleted rather than \
                         drained; {MAKE_A_NEW_KIND}"
                    ));
                    return;
                }
            }
            reg.transitional.push(Transitional { from, to, reason });
        }
        "announced" => {
            let Some(v) = take_row(
                fields,
                &["crate", "kind", "reason"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            let (name, kind, reason) = (v[0].clone(), v[1].clone(), v[2].clone());
            if !KINDS.iter().any(|d| d.kind == kind) {
                reg.errors.push(format!(
                    "unknown-kind\t{REGISTRY_FILE}:{at}\t`[[announced]] kind = \"{kind}\"` is in no \
                     kind table row. An announcement teaches the census a crate that is landing; it \
                     cannot invent the kind it lands as — {MAKE_A_NEW_KIND}"
                ));
                return;
            }
            reg.announced.push(Announced { name, kind, reason });
        }
        "registered" => {
            let Some(v) = take_row(
                fields,
                &["crate", "kind", "reason"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            let (name, kind, reason) = (v[0].clone(), v[1].clone(), v[2].clone());
            if !KINDS.iter().any(|d| d.kind == kind) {
                reg.errors.push(format!(
                    "unknown-kind\t{REGISTRY_FILE}:{at}\t`[[registered]] kind = \"{kind}\"` is in \
                     no kind table row. A registration says which of the table's kinds a crate is, \
                     against what its name says; it cannot invent a kind — {MAKE_A_NEW_KIND}"
                ));
                return;
            }
            reg.registered.push(Registered { name, kind, reason });
        }
        // THE `:matrix` ROW'S THREE TABLES. Same reader, same refusals: an unknown field is
        // refused, an empty one is refused, and a missing one is refused, because a ceiling with
        // half a sentence is a budget.
        "edge" => {
            let Some(v) = take_row(
                fields,
                &["from", "to", "cite", "why", "drain"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            reg.matrix_edges.push(MatrixEdge {
                from: v[0].clone(),
                to: v[1].clone(),
                cite: v[2].clone(),
                why: v[3].clone(),
                drain: v[4].clone(),
            });
        }
        "cell" => {
            let Some(v) = take_row(fields, &["crate", "kind", "count"], table, at, &mut reg.errors)
            else {
                return;
            };
            let Ok(count) = v[2].parse::<i64>() else {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[cell]] count = \"{}\"` is not a number. A \
                     ceiling that cannot be compared to a measurement is not a ceiling",
                    v[2]
                ));
                return;
            };
            // A NEGATIVE CEILING IS A PER-CELL OFF SWITCH, and it is refused HERE rather than
            // tolerated downstream. `count = "-1"` parses, so every load-time refusal let it
            // through; the exact-both-directions comparison then skipped the cell entirely,
            // `dead-cell` keys on the MEASURED count so it never fired, and one character turned
            // the ratchet off for one crate × kind with nothing anywhere saying so. A number no
            // measurement can ever equal is not a ceiling — it is the absence of one, spelled to
            // look like a reviewed figure.
            if count < 0 {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[cell]] count = \"{}\"` is negative. No \
                     measurement is ever below zero, so a negative ceiling is not a ceiling this \
                     rule can compare against — it is this cell's ratchet switched off in a value \
                     that reads like a reviewed figure. Write the count the tree measures, or \
                     strike the row",
                    v[2]
                ));
                return;
            }
            reg.matrix_cells.push(MatrixCell {
                krate: v[0].clone(),
                kind: v[1].clone(),
                count,
            });
        }
        // `[patch]` AND `[replace]` REDIRECT WHAT CARGO COMPILES, AND NOTHING IN THIS GATE READ
        // THEM. A `[patch.crates-io] busbar-plane-llm = { path = "…" }`, or a
        // `[source] replace-with` in `.cargo/config.toml`, substitutes one crate for another after
        // every manifest in the tree has been read and agreed with — the census, the edge ledger,
        // the matrix and the lock cross-check are all downstream of a decision none of them see.
        // So every one of them is REFUSED unless a row here names the exact file and the exact
        // entry and says why.
        "patch" => {
            let Some(v) = take_row(fields, &["file", "entry", "reason"], table, at, &mut reg.errors)
            else {
                return;
            };
            reg.patch_allows.push(PatchAllow {
                file: v[0].clone(),
                entry: v[1].clone(),
                reason: v[2].clone(),
            });
        }
        // THE FIVE INSTANCE AXES' CEILINGS (item 118). The same refusals as `[[cell]]`, plus one:
        // a row naming a kind that is not one of the five axes would be a ceiling no measurement
        // ever produces, so it is refused at load rather than scored dead forever.
        "instance" => {
            let Some(v) = take_row(fields, &["crate", "kind", "count"], table, at, &mut reg.errors)
            else {
                return;
            };
            let count = match v[2].parse::<i64>() {
                Ok(n) if n >= 0 => n,
                _ => {
                    reg.errors.push(format!(
                        "bad-count\t{REGISTRY_FILE}:{at}\t`[[instance]] count = \"{}\"` is not a \
                         non-negative number. A ceiling no measurement can equal is not a ceiling",
                        v[2]
                    ));
                    return;
                }
            };
            if !matrix::instance_axes().contains(&v[1].as_str()) {
                reg.errors.push(format!(
                    "bad-instance-kind\t{REGISTRY_FILE}:{at}\t`[[instance]] kind = \"{}\"` is not \
                     one of the instance axes ({}). A ceiling for an axis nothing measures is never \
                     compared to anything",
                    v[1],
                    matrix::instance_axes().join(", ")
                ));
                return;
            }
            reg.instance_cells.push(MatrixCell {
                krate: v[0].clone(),
                kind: v[1].clone(),
                count,
            });
        }
        "disagreement" => {
            let Some(v) = take_row(fields, &["crate", "kind", "note"], table, at, &mut reg.errors)
            else {
                return;
            };
            reg.matrix_disagreements.push(MatrixDisagreement {
                krate: v[0].clone(),
                kind: v[1].clone(),
                note: v[2].clone(),
            });
        }
        // THE `:deps` AND `:test-deps` ROWS' TWO TABLES. Same reader, same refusals — and two more
        // of its own, because a row whose `half` or whose `verdict` is a word this gate has no
        // meaning for is a row that would be silently scored against nothing.
        "dep" => {
            let Some(v) = take_row(
                fields,
                &["from", "to", "half", "count", "verdict", "cite", "why", "drain"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            if !DEP_HALVES.contains(&v[2].as_str()) {
                reg.errors.push(format!(
                    "bad-half\t{REGISTRY_FILE}:{at}\t`[[dep]] half = \"{}\"` is not one of {}. The \
                     shipped graph is what the artifact links and the test graph is what `cargo \
                     test` links; a row that names neither is scored against neither",
                    v[2],
                    DEP_HALVES.join(", ")
                ));
                return;
            }
            let Ok(count) = v[3].parse::<i64>() else {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[dep]] count = \"{}\"` is not a number. A \
                     ratchet that cannot be compared to a measurement is not a ratchet",
                    v[3]
                ));
                return;
            };
            if !DEP_VERDICTS.contains(&v[4].as_str()) {
                reg.errors.push(format!(
                    "bad-verdict\t{REGISTRY_FILE}:{at}\t`[[dep]] verdict = \"{}\"` is not one of \
                     {}. A row whose verdict this gate has no meaning for is a row that says \
                     nothing about the edge it names",
                    v[4],
                    DEP_VERDICTS.join(", ")
                ));
                return;
            }
            reg.dep_edges.push(DepEdge {
                from: v[0].clone(),
                to: v[1].clone(),
                half: v[2].clone(),
                count,
                verdict: v[4].clone(),
                cite: v[5].clone(),
                why: v[6].clone(),
                drain: v[7].clone(),
            });
        }
        "face" => {
            let Some(v) = take_row(
                fields,
                &["crate", "face", "count", "cite", "why", "drain"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            let Ok(count) = v[2].parse::<i64>() else {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[face]] count = \"{}\"` is not a number. A \
                     ratchet that cannot be compared to a measurement is not a ratchet",
                    v[2]
                ));
                return;
            };
            reg.faces.push(FaceDebt {
                krate: v[0].clone(),
                face: v[1].clone(),
                count,
                cite: v[3].clone(),
                why: v[4].clone(),
                drain: v[5].clone(),
            });
        }
        "question" => {
            let Some(v) = take_row(
                fields,
                &["from", "to", "half", "question"],
                table,
                at,
                &mut reg.errors,
            ) else {
                return;
            };
            if !DEP_HALVES.contains(&v[2].as_str()) {
                reg.errors.push(format!(
                    "bad-half\t{REGISTRY_FILE}:{at}\t`[[question]] half = \"{}\"` is not one of {}",
                    v[2],
                    DEP_HALVES.join(", ")
                ));
                return;
            }
            reg.dep_questions.push(DepQuestion {
                from: v[0].clone(),
                to: v[1].clone(),
                half: v[2].clone(),
                question: v[3].clone(),
            });
        }
        other => reg.errors.push(format!(
            "unknown-table\t{REGISTRY_FILE}:{at}\t`[[{other}]]` is not a table this gate reads; the \
             file holds `[[transitional]]`, `[[registered]]`, `[[announced]]`, `[[dep]]`, \
             `[[question]]`, `[[face]]`, `[[edge]]`, `[[cell]]` and `[[disagreement]]` rows and \
             nothing else"
        )),
    }
}

/// [`REGISTRY_FILE`], parsed. Hand-read on exactly the terms every other manifest in this gate is:
/// the shape is two array-of-tables of three string fields, and a TOML dependency in the crate whose
/// whole job is auditing dependencies is one worth not adding (see `xtask/Cargo.toml`).
fn parse_registry(text: &str) -> KindRegistry {
    let mut reg = KindRegistry::default();
    let mut table: Option<String> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut at = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(head) = t.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            if let Some(open) = table.take() {
                push_row(&mut reg, &open, &fields, at);
            }
            fields.clear();
            table = Some(head.trim().to_string());
            at = i + 1;
            continue;
        }
        if t.starts_with('[') {
            if let Some(open) = table.take() {
                push_row(&mut reg, &open, &fields, at);
            }
            fields.clear();
            reg.errors.push(format!(
                "unknown-table\t{REGISTRY_FILE}:{}\t`{t}` — the file holds `[[transitional]]`, \
                 `[[registered]]`, `[[announced]]`, `[[dep]]`, `[[question]]`, `[[face]]`, \
                 `[[edge]]`, `[[cell]]`, `[[disagreement]]` and `[[patch]]` rows and nothing else",
                i + 1
            ));
            continue;
        }
        let Some(pair) = kv(t) else {
            reg.errors.push(format!(
                "unreadable-line\t{REGISTRY_FILE}:{}\t`{t}` is not a `key = \"value\"` line",
                i + 1
            ));
            continue;
        };
        if table.is_none() {
            reg.errors.push(format!(
                "orphan-field\t{REGISTRY_FILE}:{}\t`{t}` sits under no `[[table]]` header, so it \
                 belongs to no row",
                i + 1
            ));
            continue;
        }
        fields.push(pair);
    }
    if let Some(open) = table.take() {
        push_row(&mut reg, &open, &fields, at);
    }
    reg
}

// ------------------------------------------------------------------------------------------------
// the census
// ------------------------------------------------------------------------------------------------

/// One crate, as this gate sees it.
#[derive(Debug, Clone)]
struct CrateInfo {
    /// The directory the manifest governs — `crates/<dir>` for a crate of this tree, and whatever
    /// directory an OFF-TREE manifest happens to sit in for one that is not.
    dir: String,
    /// The manifest's own path, so a finding about WHERE a crate lives can name the file.
    manifest: String,
    /// The package name from `[package] name = …`.
    name: String,
    /// `None` when the name matches no kind, or matches two at one precedence.
    kind: Option<&'static str>,
    family: Family,
    /// The name segments after the matched marker.
    remainder: Vec<String>,
    /// The instance this crate is an instance OF, when its remainder names one.
    instance: Option<String>,
    /// THE KEYS A TRANSPORT CRATE DECLARES (#50): every `const KEY: &'static str = "…";` in an
    /// `impl TransportMeta for …` under its `src/`. One crate may carry several wires — `http`
    /// holds `grpc` and `sse`, which it absorbed as modules — and each declared key is transport
    /// vocabulary exactly as a crate named for it would be. Empty for every other kind.
    declared_keys: Vec<String>,
    /// THE SHIPPED DEPENDENCY DECLARATIONS — `[dependencies]`, `[build-dependencies]` and both of
    /// their per-target forms, with `package = …` and `[workspace.dependencies]` renames resolved.
    /// See [`crate::manifest`] for the five spellings the one-section reader could not see.
    deps: Vec<DepDecl>,
    /// `[dev-dependencies]`, likewise. A test edge is not a SHIPPED edge — which is why it is
    /// scored on its own row rather than folded into the shipped graph, so a shared fixture does
    /// not read as a kind learning about another kind — but it is a real edge of the `cargo test`
    /// build graph and it is scored.
    dev_deps: Vec<DepDecl>,
    /// Two kinds claimed this name at one precedence — the fusion refusal.
    ambiguous: Vec<&'static str>,
}

/// Every kind's marker HEAD WORD — `plane`, `transport`, `unit`, `store`, `codec`, … — derived from
/// the table's own matchers rather than restated beside it.
fn kind_head_words() -> BTreeMap<String, &'static str> {
    let mut out = BTreeMap::new();
    for def in KINDS {
        for m in def.matchers {
            let head = if let Some(sfx) = m.strip_prefix('*') {
                sfx.trim_start_matches('-').to_string()
            } else if let Some(pfx) = m.strip_suffix('-') {
                match pfx.rsplit_once('-') {
                    Some((_, last)) => last.to_string(),
                    None => pfx.to_string(),
                }
            } else {
                continue;
            };
            out.insert(head, def.kind);
        }
    }
    out
}

/// Match `name` against one matcher, answering the remainder segments on a hit.
fn matcher_hit(name: &str, matcher: &str) -> Option<Vec<String>> {
    if let Some(exact) = matcher.strip_prefix('=') {
        return (name == exact).then(Vec::new);
    }
    if let Some(suffix) = matcher.strip_prefix('*') {
        let head = name.strip_suffix(suffix)?;
        return Some(segments(head));
    }
    let rest = name.strip_prefix(matcher)?;
    Some(segments(rest))
}

fn segments(s: &str) -> Vec<String> {
    s.split('-')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Which precedence band a matcher sits in: 0 exact, 1 prefix, 2 suffix.
fn precedence(matcher: &str) -> u8 {
    if matcher.starts_with('=') {
        0
    } else if matcher.starts_with('*') {
        2
    } else {
        1
    }
}

/// Resolve a crate name to its kind. THE MOST SPECIFIC BAND WINS, and two kinds in that band is the
/// fusion refusal rather than a coin toss.
fn resolve_kind(name: &str) -> (Option<&'static str>, Vec<String>, Vec<&'static str>) {
    let mut best: Option<u8> = None;
    let mut hits: Vec<(&'static str, Vec<String>)> = Vec::new();
    for def in KINDS {
        for m in def.matchers {
            let Some(remainder) = matcher_hit(name, m) else {
                continue;
            };
            let band = precedence(m);
            match best {
                Some(b) if b < band => continue,
                Some(b) if b > band => {
                    hits.clear();
                    best = Some(band);
                }
                Some(_) => {}
                None => best = Some(band),
            }
            if !hits.iter().any(|(k, _)| *k == def.kind) {
                hits.push((def.kind, remainder));
            }
        }
    }
    match hits.len() {
        0 => (None, Vec::new(), Vec::new()),
        1 => {
            let (kind, remainder) = hits.into_iter().next().expect("len == 1");
            (Some(kind), remainder, Vec::new())
        }
        _ => (None, Vec::new(), hits.into_iter().map(|(k, _)| k).collect()),
    }
}

/// A DIALECT IS NOT A KIND (DECISIONS #4): it is a thing INSIDE a plane, with no crate of its own,
/// so a name resolves to exactly the kind its matcher gives it and nothing is refined into a
/// separate `dialect` kind. Kept as a seam so callers need not change if a later refinement returns.
fn refine(kind: Option<&'static str>, _remainder: &[String]) -> Option<&'static str> {
    kind
}

/// The canonical spelling of a plane instance, through [`PLANE_ALIASES`].
fn canon_plane(name: &str) -> String {
    PLANE_ALIASES
        .iter()
        .find(|(from, _, _)| *from == name)
        .map_or_else(|| name.to_string(), |(_, to, _)| (*to).to_string())
}

/// The kind table's own names. Handed to [`truths::rule_truths`] rather than read there, so the
/// reconciliation cannot drift from the table it reconciles.
fn kind_names() -> Vec<&'static str> {
    KINDS.iter().map(|d| d.kind).collect()
}

fn family_of(kind: Option<&str>) -> Family {
    KINDS
        .iter()
        .find(|d| Some(d.kind) == kind)
        .map(|d| d.family)
        .unwrap_or(Family::Neutral)
}

/// `[package] name = "…"`, read without a TOML parser because that is the only key needed and a
/// planted manifest must be read on exactly the same terms as a real one.
fn package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw in text.lines() {
        let t = normalise_header_line(raw);
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        if k.trim() == "name" {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// ONE MANIFEST LINE, NORMALISED, so a header is judged on what Cargo reads and not on its bytes.
///
/// `in_package = t == "[package]"` was a five-byte equality, and a red team took the whole census
/// with it twice: `[package] # internal` and a UTF-8 BOM in front of `[package]` each deleted a
/// crate from this gate's world entirely — no kind, no needles, no cells, and, worst, no entry in
/// `by_name`, which is the filter the `Cargo.lock` cross-check is itself keyed on. A planted
/// `crates/busbar-plane-shadow`, listed in `[workspace.members]`, path-depended by
/// `busbar-transport-tcp` and confirmed by `cargo metadata` to be in the wire's shipped graph,
/// produced `kind-isolation: 11 row(s), green`. Twice, once per spelling. An editor can write the
/// BOM without being asked.
///
/// So: the BOM is stripped, a trailing `#` comment is cut, and CRLF's carriage return goes with the
/// trim. Cargo ignores all three; this reader now ignores them on exactly the same terms.
fn normalise_header_line(raw: &str) -> &str {
    let t = raw.trim_start_matches('\u{feff}').trim();
    match t.find('#') {
        Some(at) => t[..at].trim(),
        None => t,
    }
}

/// EVERY DEPENDENCY DECLARATION OF ONE MANIFEST, split into the shipped half and the test half.
///
/// It read ONE section (`dependencies`) and recorded the manifest KEY, which is five blind spots in
/// four lines: `[build-dependencies]`, `[target.'cfg(…)'.dependencies]`, `[dev-dependencies]`,
/// `package = "…"` and `[workspace.dependencies]` renames. Every one of them was proven to carry a
/// plane into a transport with this row green. The reading is now [`crate::manifest`]'s, which is
/// the SAME reader `construction`'s tree rule calls, so the two gates cannot drift back apart.
fn deps_of(text: &str, renames: &BTreeMap<String, String>) -> (Vec<DepDecl>, Vec<DepDecl>) {
    let mut decls = manifest::dep_decls(text);
    manifest::resolve_inherited(&mut decls, renames);
    decls.into_iter().partition(|d| d.table.shipped())
}

/// The crate census, read through the context so a planted manifest counts exactly as a real one.
/// The one legacy crate in the PLANE family that is not plane-kind SOURCE: `busbar-core` is in the
/// legacy row so the naming and vocabulary rules read it as plane-side, and it is the NEUTRAL half
/// of the plane ABI for every scan. One crate cannot be both populations, and `plane-purity` scans
/// it as neutral ([`crate::planes::neutral_src_roots`]).
const NEUTRAL_LEGACY: &str = "busbar-core";

/// THE PLANE-KIND SOURCE ROOTS, DERIVED FROM THE KIND TABLE rather than spelled out.
///
/// `planes::plane_src_roots` was a literal list — the four `busbar-<key>/src` plus the four
/// `busbar-<key>-codec/src` — which is a list somebody has to remember to add to. It was already
/// one crate short of the tree (`busbar-plane-*` is plane-kind and was in no scan), and the whole
/// point of the dialect split is that `busbar-plane-<p>-<d>` crates arrive in numbers: every one of
/// them would have to be added here by hand, and a plane crate nobody added is a plane crate the
/// backwards-reach rule scans zero files of — which is the passing answer to a ban.
///
/// The kind table already answers "is this crate plane-kind": [`Family::Plane`] covers the planes,
/// the dialects, the pre-split `-codec` halves and the retiring legacy plane crates. So the
/// population comes from there, and a crate named tomorrow is scanned tomorrow.
pub fn plane_kind_src_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = census(cx)?
        .into_iter()
        .filter(|c| c.family == Family::Plane && c.name != NEUTRAL_LEGACY)
        .map(|c| format!("{}/src", c.dir))
        .collect();
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(
            "no crate under crates/ resolves to a plane-family kind — the plane population is \
             empty, and an empty population is the passing answer to every ban"
                .to_string(),
        );
    }
    Ok(out)
}

/// [`REGISTRY_FILE`], read and parsed. A read failure is fatal in [`Gate::run`], which is where it
/// is reported; the census takes the empty registry so that one failure is reported once.
fn load_registry(cx: &Ctx) -> Result<KindRegistry, String> {
    cx.read(REGISTRY_FILE).map(|t| parse_registry(&t))
}

/// EVERY `Cargo.toml` IN THE REPOSITORY, and its text.
///
/// The census read `crates/<dir>/Cargo.toml` and nothing else, on the comment "a manifest one level
/// deeper belongs to a fixture" — and that comment WAS the hole. A red team put a plane-kind crate
/// at `vendor/busbar-plane-shim/`, path-depended it from a transport, and every gate in this tree
/// stayed green; the same crate one level deeper, at `crates/busbar-transport-tcp/internal/shim/`,
/// was equally invisible; and a live crate could be struck from `[workspace.members]` with nothing
/// red at all. A census that recognises almost everything is the passing answer to a rule about
/// everything.
///
/// So the walk is the WHOLE TREE, and WHERE a manifest sits is a FINDING rather than a filter.
fn manifests(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    let files = cx
        .walk(&WalkSpec::new(["."]).ext("toml"))
        .map_err(|e| e.to_string())?;
    Ok(files
        .iter()
        .map(|f| (f.rel_str(), f.text.clone()))
        .filter(|(rel, _)| rel == "Cargo.toml" || rel.ends_with("/Cargo.toml"))
        .collect())
}

/// A relative path DECLARED BY a manifest, resolved against the directory that manifest governs and
/// normalised — `crates/busbar-transport-tcp` + `../../xtask/fixtures/wire-bridge` reads as
/// `xtask/fixtures/wire-bridge`, which is the spelling every other path in this gate is in.
fn join_rel(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = if dir.is_empty() {
        Vec::new()
    } else {
        dir.split('/').collect()
    };
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// The directory a manifest governs. The workspace root's is the empty string.
fn manifest_dir(rel: &str) -> String {
    rel.strip_suffix("/Cargo.toml").unwrap_or("").to_string()
}

/// Is `rel` exactly `crates/<dir>/Cargo.toml` — the layout every crate of this tree has?
fn is_tree_crate(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    parts.len() == 3 && parts[0] == "crates" && parts[2] == "Cargo.toml"
}

/// THE ONE OFF-TREE LIST, for the sibling gate that asks the same question.
///
/// `workspace-deps:set-equality` compares the DECLARED member list against the manifests actually
/// on disk, and it owes the same answer this gate does about which of them are not crates of the
/// tree. Two lists would be two answers.
pub fn off_tree_manifest_reason(rel: &str) -> Option<&'static str> {
    off_tree_entry(rel).map(|(_, why)| *why)
}

/// Which reviewed off-tree entry, if any, covers `rel`.
fn off_tree_entry(rel: &str) -> Option<&'static (&'static str, &'static str)> {
    OFF_TREE_MANIFESTS.iter().find(|(path, _)| {
        path.strip_suffix('/').map_or(rel == *path, |prefix| {
            rel.starts_with(&format!("{prefix}/"))
        })
    })
}

fn census(cx: &Ctx) -> Result<Vec<CrateInfo>, String> {
    let reg = load_registry(cx).unwrap_or_default();
    let overrides = reg.overrides();
    // THE WORKSPACE'S OWN RENAMES, read once: a member that inherits reaches the package the
    // workspace named, not the word the member spelled.
    let renames = manifest::workspace_renames(&cx.read("Cargo.toml").unwrap_or_default());
    let mut out = Vec::new();
    for (rel, text) in manifests(cx)? {
        // A manifest a reviewed entry covers is not a crate of this tree — see
        // [`OFF_TREE_MANIFESTS`], whose entries expire on the registry row.
        if off_tree_entry(&rel).is_some() {
            continue;
        }
        let Some(name) = package_name(&text) else {
            continue;
        };
        let (kind, remainder, ambiguous) = resolve_kind(&name);
        let kind = refine(kind, &remainder);
        // A `[[registered]]` row is the ONE thing that outranks the name, and it outranks it here
        // rather than rule by rule: a crate is one kind for every row, or the rows are talking
        // about different crates. `busbar-plane-admin` is `control` for the edge graph, the
        // vocabulary, the skeleton and the battery alike, and its remainder (`admin`) is still read
        // off the marker its name carries — which is why the served-surface vocabulary is unchanged
        // by the registration.
        let kind = overrides.get(name.as_str()).copied().or(kind);
        let (deps, dev_deps) = deps_of(&text, &renames);
        let dir = manifest_dir(&rel);
        let declared_keys = match kind {
            Some("transport") => declared_meta_keys(cx, &dir, "TransportMeta"),
            Some("plane") => declared_meta_keys(cx, &dir, "PlaneMeta"),
            _ => Vec::new(),
        };
        out.push(CrateInfo {
            dir,
            manifest: rel,
            name,
            kind,
            family: family_of(kind),
            remainder,
            instance: None,
            declared_keys,
            deps,
            dev_deps,
            ambiguous,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.dir.cmp(&b.dir)));
    Ok(out)
}

/// The registry keys a transport or plane crate DECLARES: each `const KEY` inside an
/// `impl <meta> for …` block (`TransportMeta`, `PlaneMeta`) of a `.rs` file under `<dir>/src`.
/// Read off the source, never typed here, so a wire folded into a sibling crate stays a transport
/// word on the commit that folds it, a wire added as a module teaches this gate its name the way a
/// new crate would, and [`PLANE_ALIASES`]' canonical side is checked against the key the plane
/// itself registers under.
fn declared_meta_keys(cx: &Ctx, dir: &str, meta: &str) -> Vec<String> {
    let needle = format!("{meta} for ");
    let spec = WalkSpec::new([format!("{dir}/src")])
        .ext("rs")
        .allow_empty();
    let Ok(files) = cx.walk(&spec) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for f in files {
        let mut in_meta = false;
        for line in f.text.lines() {
            let t = line.trim();
            if t.starts_with("impl ") && t.contains(&needle) {
                in_meta = true;
            } else if in_meta && t.starts_with("const KEY: &'static str = \"") {
                if let Some(key) = t
                    .strip_prefix("const KEY: &'static str = \"")
                    .and_then(|r| r.strip_suffix("\";"))
                {
                    keys.push(key.to_string());
                }
                in_meta = false;
            } else if t == "}" && !line.starts_with(' ') {
                in_meta = false;
            }
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// The instance vocabularies, DERIVED: plane instances are the plane crates' names, transport
/// instances are the transport crates' names AND every key a transport crate declares.
fn vocabularies(crates: &[CrateInfo]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut planes = BTreeSet::new();
    let mut transports = BTreeSet::new();
    for c in crates {
        match c.kind {
            // The plane instance vocabulary is the plane crates' own remainder. `dialect` and
            // `control` are not kinds (DECISIONS #4/#5); `cleanliness` (admin/oauth2) is a Neutral
            // compiled-in family with no instance vocabulary of its own.
            Some("plane") => {
                if let Some(first) = c.remainder.first() {
                    planes.insert(first.clone());
                }
            }
            Some("transport") => {
                transports.insert(c.remainder.join("-"));
                transports.extend(c.declared_keys.iter().cloned());
            }
            _ => {}
        }
    }
    // EVERY SPELLING OF A PLANE IS VOCABULARY. `busbar-transport-streams` has to be refused on the
    // day the alias lands, not on the day the rename does — and `voice` stays the streaming plane's
    // word after `busbar-plane-voice` is gone, for as long as `busbar-voice-codec` spells it.
    for (from, to, _) in PLANE_ALIASES {
        if planes.contains(*from) || planes.contains(*to) {
            planes.insert((*from).to_string());
            planes.insert((*to).to_string());
        }
    }
    (planes, transports)
}

/// Fill in each crate's own instance, once the vocabularies are known.
fn assign_instances(crates: &mut [CrateInfo], planes: &BTreeSet<String>, ports: &BTreeSet<String>) {
    for c in crates.iter_mut() {
        let vocab = match c.family {
            Family::Plane => planes,
            Family::Transport => ports,
            Family::Neutral => continue,
        };
        c.instance = c
            .remainder
            .iter()
            .rev()
            .find(|seg| vocab.contains(seg.as_str()))
            .map(|s| match c.family {
                Family::Plane => canon_plane(s),
                _ => s.clone(),
            });
    }
}

// ------------------------------------------------------------------------------------------------
// rule 1 — the name
// ------------------------------------------------------------------------------------------------

fn rule_name(
    crates: &[CrateInfo],
    planes: &BTreeSet<String>,
    ports: &BTreeSet<String>,
    reg: &KindRegistry,
) -> Row {
    let heads = kind_head_words();
    let mut offenders: Vec<String> = Vec::new();
    let mut fired: BTreeSet<&str> = BTreeSet::new();
    let accepted: BTreeMap<&str, &str> = ACCEPTED_NAMES.iter().copied().collect();

    // A WORD THAT IS BOTH A PLANE INSTANCE AND A TRANSPORT INSTANCE is the fusion itself, one level
    // above any single crate: `busbar-plane-http` beside `busbar-transport-http` means the tree can
    // no longer say what `http` names. Reported once, naming every claimant.
    let fused: BTreeSet<&str> = planes
        .intersection(ports)
        .map(std::string::String::as_str)
        .collect();
    for word in &fused {
        let claimants: Vec<&str> = crates
            .iter()
            .filter(|c| c.remainder.iter().any(|s| s == word))
            .map(|c| c.name.as_str())
            .collect();
        offenders.push(format!(
            "fused-instance\tcrates/\t`{word}` is claimed as an instance by both a plane and a \
             transport ({}) — one word cannot name two kinds; {MAKE_A_NEW_KIND}",
            claimants.join(", ")
        ));
    }

    // A CRATE NAMED `busbar-<kind>-<another kind's instance>` IS THE FUSION, AND NO WAIVER REACHES
    // IT.
    //
    // `fused-instance` above already refuses the owner's own example, `busbar-transport-a2a` — but
    // only because `transport` HAS an instance vocabulary, so the crate's own name makes `a2a` a
    // transport instance as well as a plane one and the collision is visible one level up. A
    // NEUTRAL kind creates no collision: `busbar-unit-llm` is a unit named after the llm plane
    // instance, `unit` contributes no instance vocabulary, nothing collides — and a red team landed
    // exactly that crate with ONE `ACCEPTED_NAMES` line and got `kind-isolation: green` and
    // `--selftest: the gate is proven RED-able` in the same breath. The waiver list was protecting
    // only the six names the battery happened to plant.
    //
    // So the refusal is structural and sits outside the waiver loop, on the same terms
    // `fused-instance` does. WHAT IT REFUSES IS THE NAME THAT *IS* THE INSTANCE: a remainder of
    // exactly one segment, and that segment another kind's instance id. That is the fusion —
    // "the llm unit", "the mcp store" — and it is what the ruling refuses by name. It is not the
    // same shape as a QUALIFIER: `busbar-auth-admin-tokens` is the admin surface's TOKEN issuer,
    // its last segment says what it is, and its reviewed sentence is a sentence about a qualifier.
    // A waiver may still excuse that; it may never excuse a crate whose whole remainder is another
    // kind's instance.
    for c in crates {
        let [only] = &c.remainder[..] else { continue };
        if fused.contains(only.as_str()) {
            continue;
        }
        for (owner, label, vocab) in [
            (Family::Plane, "a PLANE", planes),
            (Family::Transport, "a TRANSPORT", ports),
        ] {
            if vocab.contains(only.as_str()) && owner != c.family {
                offenders.push(format!(
                    "fused-instance-name\t{}\t`{}` IS {label} instance wearing a `{}` marker: its \
                     whole remainder is `{only}`, so the crate is named for another kind's \
                     instance rather than for what it does. No reviewed sentence reaches this — a \
                     waiver excuses a QUALIFIER, never a fusion; {MAKE_A_NEW_KIND}",
                    c.dir,
                    c.name,
                    c.kind.unwrap_or("?")
                ));
            }
        }
    }

    for c in crates {
        let mut findings: Vec<String> = Vec::new();

        // THE SCHEME HAS THREE SEGMENTS, FOUR FOR A DIALECT. A fifth is a name that has stopped
        // saying which kind the crate is and started describing it instead.
        let width = segments(&c.name).len();
        if width > MAX_NAME_SEGMENTS {
            findings.push(format!(
                "is {width} segments wide; the scheme is `busbar-<kind>-<name>` \
                 ({MAX_NAME_SEGMENTS} only for a dialect, `busbar-plane-<plane>-<dialect>`)"
            ));
        }

        if !c.ambiguous.is_empty() {
            findings.push(format!(
                "resolves to {} kinds at once ({}) — {MAKE_A_NEW_KIND}",
                c.ambiguous.len(),
                c.ambiguous.join(" + ")
            ));
        }

        // ANOTHER KIND'S INSTANCE IN THE NAME. This is the ruling, spelled as a predicate.
        //
        // BOTH VOCABULARIES ARE CONSULTED, never one-then-the-other. A word claimed by a plane AND
        // by a transport is itself the fusion — reported below as `fused-instance` — and reading
        // only the first match would let the crate that CAUSED the collision look clean because it
        // matched the vocabulary it had just poisoned.
        for seg in &c.remainder {
            if fused.contains(seg.as_str()) {
                continue;
            }
            for (owner, label, vocab) in [
                (Family::Plane, "a PLANE", planes),
                (Family::Transport, "a TRANSPORT", ports),
            ] {
                if vocab.contains(seg.as_str()) && owner != c.family {
                    findings.push(format!(
                        "carries `{seg}`, which is {label} instance — a kind may never be named \
                         after another kind's instance"
                    ));
                }
            }
        }

        // ANOTHER KIND'S MARKER WORD OPENING THE REMAINDER. `busbar-plane-transport` is the
        // "plane-transport" the ruling names by name, and it carries no instance at all.
        if let Some(first) = c.remainder.first() {
            if let Some(other) = heads.get(first.as_str()) {
                if Some(*other) != c.kind {
                    findings.push(format!(
                        "opens its remainder with `{first}`, the marker word of kind `{other}` — \
                         {MAKE_A_NEW_KIND}"
                    ));
                }
            }
        }

        if findings.is_empty() {
            continue;
        }
        match accepted.get(c.name.as_str()) {
            Some(_) => {
                fired.insert(c.name.as_str());
            }
            None => offenders.push(format!("{}\t{}\t{}", c.name, c.dir, findings.join("; "))),
        }
    }

    // AN ACCEPTED NAME THAT NO LONGER EXISTS IS A DEAD WAIVER. The same rule every allow-list in
    // this crate lives under: a carve-out cannot outlive the thing it excused.
    //
    // The one thing it distinguishes is a waiver that has not started YET from one that has ended.
    // A crate named by an `[[announced]]` row is being written right now, so its reviewed sentence
    // is not a hole nobody re-reads — it is the review, arriving before the crate rather than after
    // it. The announcement is what carries that claim, and the ship twin is what refuses it once
    // the crate has landed.
    let announced_names = reg.announced_names();
    for (name, _) in ACCEPTED_NAMES {
        if !fired.contains(name) && !announced_names.contains(name) {
            offenders.push(format!(
                "dead-waiver\t{name}\tthe accepted-name entry for `{name}` no longer covers a live \
                 crate, so it is a permanent hole nobody re-reads. Strike it."
            ));
        }
    }

    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_NAME,
            "every crate name carries one kind and never another kind's instance",
            format!(
                "{} crate(s); plane instances {{{}}}; transport instances {{{}}}; {} reviewed \
                 accepted name(s)",
                crates.len(),
                planes.iter().cloned().collect::<Vec<_>>().join(", "),
                ports.iter().cloned().collect::<Vec<_>>().join(", "),
                ACCEPTED_NAMES.len()
            ),
        );
    }
    Row::fail(
        ROW_NAME,
        "a crate name fuses two plugin kinds",
        format!(
            "{} finding(s): {} — {MAKE_A_NEW_KIND}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 2 — the dependency ledger, instance by instance
// ------------------------------------------------------------------------------------------------

/// WHICH HALF OF THE BUILD GRAPH a run of the edge rule is reading.
///
/// The split is not an exemption, it is two claims: the SHIPPED graph is what the artifact links,
/// the TEST graph is what `cargo test` links. Folding the second into the first would grant the
/// shipped artifact every edge a fixture has; dropping it — which is what reading only
/// `[dependencies]` did — leaves a plane wired into a transport with the gate green, and a red team
/// walked straight through that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Half {
    Shipped,
    Test,
}

impl Half {
    fn row(self) -> &'static str {
        match self {
            Half::Shipped => ROW_DEPS,
            Half::Test => ROW_TEST_DEPS,
        }
    }

    fn decls(self, c: &CrateInfo) -> &[DepDecl] {
        match self {
            Half::Shipped => &c.deps,
            Half::Test => &c.dev_deps,
        }
    }

    /// The word a `[[dep]]` row's `half` field carries.
    fn word(self) -> &'static str {
        match self {
            Half::Shipped => "shipped",
            Half::Test => "test",
        }
    }
}

/// One measured edge INSTANCE: one crate naming one other crate, and how many declarations say so.
struct DepInstance {
    from: String,
    to: String,
    class: (String, String),
    count: usize,
    /// The sections those declarations came from, so a finding names the table it read.
    sections: Vec<String>,
}

/// The verdict the architecture implies for a class, before anybody writes a sentence about it.
fn verdict_for(class: &(String, String)) -> &'static str {
    let pair = (class.0.as_str(), class.1.as_str());
    if ARCHITECTURE_ALLOWED.contains(&pair) || PENDING_EDGES.contains(&pair) {
        "allowed"
    } else if ARCHITECTURE_TCB.contains(&pair) {
        "tcb"
    } else {
        "not-allowed"
    }
}

/// Every edge instance one half of the build graph has, measured.
fn measure_edges(crates: &[CrateInfo], half: Half) -> Vec<DepInstance> {
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let mut acc: BTreeMap<(String, String), DepInstance> = BTreeMap::new();
    for c in crates {
        let Some(from) = c.kind else { continue };
        for decl in half.decls(c) {
            let Some(target) = by_name.get(decl.pkg.as_str()) else {
                continue;
            };
            let Some(to) = target.kind else { continue };
            let e = acc
                .entry((c.name.clone(), decl.pkg.clone()))
                .or_insert_with(|| DepInstance {
                    from: c.name.clone(),
                    to: decl.pkg.clone(),
                    class: (from.to_string(), to.to_string()),
                    count: 0,
                    sections: Vec::new(),
                });
            e.count += 1;
            e.sections.push(decl.section.clone());
        }
    }
    acc.into_values().collect()
}

/// The row `--report` prints for an edge nobody wrote down: ready to paste, with the verdict the
/// architecture already implies filled in, so the reader writes the SENTENCES and not the facts.
fn dep_row_scaffold(half: Half, e: &DepInstance) -> String {
    format!(
        "[[dep]]\nfrom    = \"{}\"\nto      = \"{}\"\nhalf    = \"{}\"\ncount   = \"{}\"\n\
         verdict = \"{}\"\ncite    = \"\"\nwhy     = \"\"\ndrain   = \"\"\n",
        e.from,
        e.to,
        half.word(),
        e.count,
        verdict_for(&e.class)
    )
}

/// THE DRAIN'S OWN EXPIRY, on its own row and owed by the ship twin alone.
///
/// It sat inside `:deps`, and that stopped being readable the day `:deps` began owing the
/// ARCHITECTURE'S graph on the ship sha: the row is red there for every edge the design does not
/// grant, so "the drain finished" and "the graph is the architecture's" became one verdict and
/// neither could be proven without the other. They are two claims.
///
/// This one is: every `[[transitional]]` exemption is for a crate that is RETIRING, and the expiry
/// is deliberately NOT "the edge went away" — the drain lands edge by edge, branch after branch,
/// and a row scored dead in the week between two branches would teach everyone to delete the
/// ratchet instead of the debt. The expiry is the CRATE. If it still exists on the ship sha the
/// retirement did not happen, and this is where the tag is refused, by name.
fn rule_drain(crates: &[CrateInfo], reg: &KindRegistry) -> Row {
    let present: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    let mut offenders: Vec<String> = Vec::new();
    for t in &reg.transitional {
        if present.contains(t.from.as_str()) {
            offenders.push(format!(
                "transitional-live\t{REGISTRY_FILE}\t`{} -> {}` ({}) is a TRANSITIONAL exemption \
                 for the legacy drain and `{}` still exists at ship time. The exemption's expiry \
                 rule is that the crate must not exist on the ship sha: finish the drain and \
                 delete the crate, or the table is a permanent hole under a temporary name",
                t.from, t.to, t.reason, t.from
            ));
        }
    }
    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_DRAIN,
            "the legacy drain is finished: no transitional exemption outlives its crate",
            format!(
                "{} transitional row(s) in {REGISTRY_FILE}, 0 whose crate is still in the tree",
                reg.transitional.len()
            ),
        );
    }
    Row::fail(
        ROW_DRAIN,
        "a transitional exemption's crate is still in the tree at ship time",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

fn rule_deps(cx: &Ctx, crates: &[CrateInfo], reg: &KindRegistry, half: Half, ship: bool) -> Row {
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let drain_targets: BTreeSet<&str> = DRAIN_TARGET_KINDS.iter().copied().collect();
    let measured = measure_edges(crates, half);
    // A ROW REFUSED AT LOAD IS REPORTED, NOT DROPPED. A table that quietly skips what it cannot
    // understand is a table that says yes to it, and the row it skipped is the one somebody wrote
    // to get an edge past this rule. Only the shipped row carries them, so one bad row is one
    // finding rather than two.
    let mut offenders: Vec<String> = match half {
        Half::Shipped => reg.errors.clone(),
        Half::Test => Vec::new(),
    };

    // A SECTION HEADER THIS READER COULD NOT PARSE IS A REFUSAL, NOT A SKIP.
    //
    // The reader's blind spots are the only ones that matter, because a dependency table missing
    // from its answer is indistinguishable from a dependency table missing from the build. Two were
    // proven: `[target.'cfg(all())'.dependencies] # extra` failed the "ends in `]`" test, so the
    // parser stayed in the PREVIOUS section and filed a plane into a wire as a dev-dependency; and
    // `target."cfg(unix)".dependencies.wire = { workspace = true }` is a top-level dotted key under
    // no section at all, which `:deps` never saw — only the `Cargo.lock` cross-check caught it, and
    // that cross-check is itself census-gated. Both are now reported by name.
    if half == Half::Shipped {
        for c in crates {
            let Ok(text) = cx.read(&c.manifest) else {
                continue;
            };
            for why in manifest::unreadable(&text) {
                offenders.push(format!(
                    "unreadable-manifest\t{}\t{why}. A table this reader cannot place is a table \
                     whose edges are not scored, and an unscored edge is the one thing this row \
                     exists to make impossible.",
                    c.manifest
                ));
            }
        }
    }

    // THE STRUCTURAL REFUSALS, which no ledger row can waive: they are not about how MANY
    // declarations a pair has, they are about the pair existing at all.
    for c in crates {
        let Some(from) = c.kind else { continue };
        for decl in half.decls(c) {
            let dep = decl.cite();
            let Some(target) = by_name.get(decl.pkg.as_str()) else {
                continue;
            };
            let Some(to) = target.kind else { continue };

            // THE PLANE FAMILY IS INSTANCE-SEALED. A plane's own codec is the intended shape; any
            // other instance is one plane reaching into another's vocabulary.
            if c.family == Family::Plane && target.family == Family::Plane {
                if let (Some(mine), Some(theirs)) = (&c.instance, &target.instance) {
                    if mine != theirs {
                        offenders.push(format!(
                            "cross-instance\t{}\t{} depends on {dep}, another instance ({theirs} \
                             vs {mine}) of its own family — a dialect names ITS OWN plane and \
                             nothing else",
                            c.dir, c.name
                        ));
                    }
                }
            }

            // DIALECT and CONTROL are not kinds (DECISIONS #4/#5), so the plane-names-dialect,
            // control-sink and plane-control refusals are gone with them: admin/oauth2 are
            // `cleanliness` crates whose one-way deps (core, substrate, api, the plugin-loader TCB)
            // are recorded in the measured graph like every other Neutral kind's, not held to a
            // closed sink set.

            // THE DRAIN, EDGE BY EDGE. A `legacy` source is no longer unscored — its edges are rows
            // like everything else — and this is the refusal that survives that: an edge into a
            // kind the drain TARGETS is accepted only if a `[[transitional]]` row names it, so
            // `busbar-core -> busbar-unit-audit` reads as the drain and
            // `busbar-core -> busbar-transport-ws` reads as the fusion.
            if from == "legacy"
                && drain_targets.contains(to)
                && !reg
                    .transitional
                    .iter()
                    .any(|t| t.covers(&c.name, decl.pkg.as_str()))
            {
                offenders.push(format!(
                    "unlisted-transitional\t{}\t{} depends on {dep}, a `{to}` crate. While the \
                     1.5.x crates drain they MAY name the kinds they are draining into — but only \
                     through a row in {REGISTRY_FILE} that names the edge and says why. An \
                     UNLISTED legacy -> {to} edge is indistinguishable from the fusion; \
                     {MAKE_A_NEW_KIND}",
                    c.dir, c.name
                ));
            }
        }
    }

    // AN ANNOUNCED CRATE IS SCORED AT THE CLASS LEVEL, NOT AGAINST THE INSTANCE LEDGER.
    //
    // A `[[announced]]` row exists for the window before a crate is on disk, and its whole purpose
    // is that the agent who lands the crate does not red a gate they never touched — the rows for
    // its edges land WITH it. What does not wait is the design's own promise about the class: an
    // announced crate that reaches a kind the architecture grants it nothing to is refused here and
    // now, which is the machine form of "a core crate names no plane, dialect, transport or unit".
    // The window closes on its own: the ship twin collects a spent announcement by name.
    let announced = reg.announced_names();
    for e in &measured {
        if !announced.contains(e.from.as_str()) && !announced.contains(e.to.as_str()) {
            continue;
        }
        if verdict_for(&e.class) == "not-allowed" {
            offenders.push(format!(
                "announced-edge-class\t{} -> {}\t{} -> {} names a kind the architecture grants \
                 {} nothing to. An ANNOUNCED crate is not yet in the instance ledger — its rows \
                 land with it — but the class it reaches is a design decision that was made \
                 before the crate was written; {MAKE_A_NEW_KIND}",
                e.class.0, e.class.1, e.from, e.to, e.class.0
            ));
        }
    }

    // THE SHIP TWIN OWES THE ARCHITECTURE'S OWN GRAPH, and owes it without reading the ledger:
    // what is written there is what 1.6.0 still has to delete, not a shape the tag may keep.
    if ship {
        for e in &measured {
            let verdict = verdict_for(&e.class);
            if verdict != "allowed" {
                offenders.push(format!(
                    "ship-edge\t{} -> {}\t{} -> {} is `{verdict}`: the architecture grants no {} \
                     -> {} edge, and the ship criterion is the architecture's graph rather than \
                     yesterday's measurement. {} declaration(s), in {}.",
                    e.class.0,
                    e.class.1,
                    e.from,
                    e.to,
                    e.class.0,
                    e.class.1,
                    e.count,
                    e.sections.join(", ")
                ));
            }
        }
        offenders.sort();
        offenders.dedup();
        if offenders.is_empty() {
            return Row::pass(
                half.row(),
                "every dependency in the graph is one the architecture grants",
                format!("{} {} edge(s), all ALLOWED", measured.len(), half.word()),
            );
        }
        return Row::fail(
            half.row(),
            "a dependency the architecture does not grant is still in the graph",
            format!(
                "{} finding(s) over {} {} edge(s): {}",
                offenders.len(),
                measured.len(),
                half.word(),
                offenders.join(" | ")
            ),
        );
    }

    // THE LEDGER IS THE EVIDENCE, NEVER THE JUDGE — and this is the rule that makes that true.
    //
    // Everything BELOW this point reads `qa/kind-isolation.toml` and compares a measurement against
    // a number a human wrote. A red team proved what that is worth on its own: a real
    // `busbar-transport-tcp -> busbar-plane-llm` path dependency — a plane compiled into a wire,
    // the fusion this whole gate exists to make impossible — went GREEN by appending nine lines
    // that say out loud `verdict = "not-allowed"`, because every rule below is satisfied by a row
    // that MATCHES. The row was honest. The gate agreed with it. Nothing asked where it came from.
    //
    // So the subject here is the EDGE and not the row: an edge the architecture does not grant may
    // exist only if it ALREADY EXISTED at the merge-base with the integration line. A row records
    // a pre-existing debt; it does not authorise a new one, and no verdict word, count or citation
    // changes the answer, because none of them are read. It runs on the per-push half alone — the
    // ship twin already reds every edge the architecture withholds, whatever its history.
    //
    // See [`base`] for why a base that cannot be established is RED rather than green.
    match base::read(cx) {
        Ok(base) => {
            for e in &measured {
                let implied = verdict_for(&e.class);
                if implied == "allowed" || implied == "tcb" {
                    continue;
                }
                if base.has_edge(&e.from, &e.to, half.word()) {
                    continue;
                }
                // THE DRAIN IS THE ONE EDGE THAT IS SUPPOSED TO BE NEW.
                //
                // A `[[transitional]]` row is not a `[[dep]]` row wearing a different hat, and the
                // difference is the whole reason the two tables exist. `[[dep]]` describes what the
                // graph HAS; `[[transitional]]` describes a RETIREMENT IN PROGRESS, and a
                // retirement lands edge by edge, branch after branch — `busbar-core` reaching one
                // more unit is the 1.5.x crates draining into the kinds that replace them, which is
                // the movement this gate was built to permit while refusing the fusion beside it.
                //
                // It is safe to exempt because the transitional table is the most refused table in
                // the file: `from` must be a LEGACY crate or the row does not load at all
                // (`not-legacy`), `to` must be one kind's prefix (`bad-glob`), the edge is scored
                // against a count like every other, and the ship twin reds every transitional row
                // whose crate still exists (`transitional-live`). The exemption cannot outlive the
                // drain, because the tag refuses it.
                if reg
                    .transitional
                    .iter()
                    .any(|t| t.covers(&e.from, e.to.as_str()))
                {
                    continue;
                }
                offenders.push(format!(
                    "new-forbidden-edge\t{} -> {}\t{} -> {} is `{implied}` and it is NOT in the \
                     merge-base {}'s manifests: this branch INTRODUCED it. A `[[dep]]` row may \
                     record a PRE-EXISTING not-allowed edge, never introduce one — the row is the \
                     evidence and not the judge, so no verdict, count or citation makes this edge \
                     admissible. Delete the dependency, or {MAKE_A_NEW_KIND}. {} declaration(s), \
                     in {}.",
                    e.class.0,
                    e.class.1,
                    e.from,
                    e.to,
                    &base.commit[..8.min(base.commit.len())],
                    e.count,
                    e.sections.join(", ")
                ));
            }
        }
        Err(why) => offenders.push(format!(
            "no-base\t{REGISTRY_FILE}\tno merge-base could be read, so no `not-allowed` edge could \
             be shown to pre-date this branch ({why}). A ratchet that cannot read its own history \
             reports nothing, and reporting nothing is not passing."
        )),
    }

    // THE LEDGER, ROW BY ROW. A duplicate row is refused before anything is compared: two rows for
    // one edge is two numbers for one measurement, and whichever the reader believes is the one
    // that is not checked.
    let mut listed: BTreeMap<(&str, &str), &DepEdge> = BTreeMap::new();
    for row in reg.dep_edges.iter().filter(|d| d.half == half.word()) {
        if listed
            .insert((row.from.as_str(), row.to.as_str()), row)
            .is_some()
        {
            offenders.push(format!(
                "duplicate-dep\t{} -> {}\ttwo `[[dep]]` rows name the same {} edge. Two rows are \
                 two numbers for one measurement, and the one a reader believes is the one nobody \
                 checked.",
                row.from,
                row.to,
                half.word()
            ));
        }
    }
    let mut questions: BTreeSet<(&str, &str)> = BTreeSet::new();
    for q in reg.dep_questions.iter().filter(|q| q.half == half.word()) {
        if !questions.insert((q.from.as_str(), q.to.as_str())) {
            offenders.push(format!(
                "duplicate-dep\t{} -> {}\ttwo `[[question]]` rows ask about the same {} edge",
                q.from,
                q.to,
                half.word()
            ));
        }
    }

    let mut scaffolds: Vec<String> = Vec::new();
    for e in &measured {
        // The announced window, above.
        if announced.contains(e.from.as_str()) || announced.contains(e.to.as_str()) {
            continue;
        }
        // THE WALL OWES NO ROW. A plugin-kind crate naming `busbar-contract` is #40(a) itself, not
        // an instance of debt ([`is_the_wall`]); asking for a `[[dep]]` row for it is asking for a
        // per-crate exception to a rule that has none. A row that still records one is reported,
        // so the ledger does not carry a line that reads like a decision and is not one.
        if is_the_wall(&e.class.0, &e.class.1) {
            if listed.contains_key(&(e.from.as_str(), e.to.as_str())) {
                offenders.push(format!(
                    "rule-granted-row\t{} -> {}\tthe `[[dep]]` row records a {} -> {} edge, and #40(a) \
                     grants every plugin kind its edge to busbar-contract as the RULE: a per-crate \
                     row for it is an exception to a rule that excepts nothing. Strike the row.",
                    e.from, e.to, e.class.0, e.class.1
                ));
            }
            continue;
        }
        let Some(row) = listed.get(&(e.from.as_str(), e.to.as_str())) else {
            scaffolds.push(dep_row_scaffold(half, e));
            offenders.push(format!(
                "unlisted-dep-edge\t{} -> {}\t{} -> {} is a {} edge with no `[[dep]]` row in \
                 {REGISTRY_FILE}. An edge nobody wrote down is an edge nobody reviewed: add the \
                 row with `count = \"{}\"` and its citation, or delete the dependency. {} \
                 declaration(s), in {}.",
                e.class.0,
                e.class.1,
                e.from,
                e.to,
                half.word(),
                e.count,
                e.count,
                e.sections.join(", ")
            ));
            continue;
        };
        if row.count != e.count as i64 {
            let verb = if row.count < e.count as i64 {
                "RAISED — this landing grew the coupling"
            } else {
                "STALE SLACK — the count fell and the row did not; slack is how drift hides"
            };
            offenders.push(format!(
                "dep-ratchet\t{} -> {}\trow {} vs measured {} ({verb}). The row must equal the \
                 count, exactly. Declarations: {}.",
                e.from,
                e.to,
                row.count,
                e.count,
                e.sections.join(", ")
            ));
        }
        // A ROW MAY NOT GRANT ITSELF AN EDGE THE ARCHITECTURE DOES NOT. `allowed` and `tcb` are
        // readings of the architecture, not opinions a row is entitled to hold: the class tables
        // are in this file precisely so the ledger cannot edit them.
        let implied = verdict_for(&e.class);
        match row.verdict.as_str() {
            "allowed" if implied != "allowed" => offenders.push(format!(
                "unsupported-verdict\t{} -> {}\tthe row claims `allowed`, and the architecture \
                 grants no {} -> {} edge (it implies `{implied}`). A ledger row cannot grant an \
                 edge the architecture withholds.",
                e.from, e.to, e.class.0, e.class.1
            )),
            "tcb" if implied != "tcb" => offenders.push(format!(
                "unsupported-verdict\t{} -> {}\tthe row claims `tcb`, and {} -> {} is not a \
                 loader/tooling class (the architecture implies `{implied}`).",
                e.from, e.to, e.class.0, e.class.1
            )),
            "not-allowed" if implied == "allowed" => offenders.push(format!(
                "unsupported-verdict\t{} -> {}\tthe row calls a granted edge `not-allowed`. The \
                 architecture grants {} -> {}; a row that refuses it is a row somebody will \
                 tighten by deleting a dependency the design asks for.",
                e.from, e.to, e.class.0, e.class.1
            )),
            // AN UNRULED EDGE OWES ITS QUESTION, in full, so a ruling can be given by reading this
            // file and nothing else. A pending row with no question has stopped asking.
            "owner-ruling-pending" if !questions.contains(&(e.from.as_str(), e.to.as_str())) => {
                offenders.push(format!(
                    "unasked-question\t{} -> {}\tthe row is `owner-ruling-pending` and no \
                     `[[question]]` row asks about it. An edge nobody ruled on and nobody asked \
                     about is an edge that passes by being unreadable.",
                    e.from, e.to
                ))
            }
            _ => {}
        }
    }

    // A ROW WHOSE EDGE IS GONE IS A DEAD ALLOWANCE, and that is how this ratchet tightens: the
    // landing that deletes the dependency is the landing that must delete the row.
    for (from, to) in listed.keys() {
        if announced.contains(*from) || announced.contains(*to) {
            continue;
        }
        if !measured.iter().any(|e| e.from == *from && e.to == *to) {
            offenders.push(format!(
                "dead-dep-edge\t{from} -> {to}\tthe `[[dep]]` row covers nothing: no {} dependency \
                 from {from} on {to} exists any more. Strike the row.",
                half.word()
            ));
        }
    }
    for (from, to) in &questions {
        let pending = listed
            .get(&(*from, *to))
            .is_some_and(|r| r.verdict == "owner-ruling-pending");
        if !pending {
            offenders.push(format!(
                "dead-question\t{from} -> {to}\tthe `[[question]]` row asks about a {} edge that is \
                 not `owner-ruling-pending` any more. The ruling landed, or the edge did not: \
                 strike the question.",
                half.word()
            ));
        }
    }

    // `--report` PRINTS the rows to paste, and only `--report`. The whole point of a ledger a human
    // writes is that the gate hands them the facts and asks only for the sentences — but this row
    // runs once per planted case in the self-test, and printing it there buried the battery's own
    // verdict under eleven thousand lines of scaffold.
    if cx.env().report_only && !scaffolds.is_empty() {
        println!(
            "\nTHE {} EDGES WITH NO ROW, ready to paste into {REGISTRY_FILE}:\n{}",
            half.word().to_uppercase(),
            scaffolds.join("\n")
        );
    }

    // `--report` PRINTS THE OPEN DEBT WHERE A READER IS. A ledger of 220 rows is not something a
    // FAIL detail can carry — `Row::tsv` flattens every newline in it to one line, and a PASS row's
    // detail is not printed at all — but the whole reason each row owes a `drain` is that somebody
    // can be handed the deleting line rather than re-deriving it. So in report mode the not-allowed
    // rows and the unruled questions go to stdout, grouped, with their sentences.
    if cx.env().report_only {
        let mut debt: Vec<&DepEdge> = listed
            .values()
            .copied()
            .filter(|r| r.verdict == "not-allowed" || r.verdict == "owner-ruling-pending")
            .collect();
        debt.sort_by(|a, b| (&a.verdict, &a.from, &a.to).cmp(&(&b.verdict, &b.from, &b.to)));
        println!(
            "\nTHE {} DEPENDENCY DEBT ({} row(s) of {}):",
            half.word().to_uppercase(),
            debt.len(),
            listed.len()
        );
        for r in &debt {
            println!(
                "--- {} -> {} ({}, count {})\n    cite : {}\n    why  : {}\n    drain: {}",
                r.from, r.to, r.verdict, r.count, r.cite, r.why, r.drain
            );
        }
        let mut asked: Vec<&DepQuestion> = reg
            .dep_questions
            .iter()
            .filter(|q| q.half == half.word())
            .collect();
        asked.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
        if !asked.is_empty() {
            println!(
                "\nTHE {} EDGES AWAITING AN OWNER RULING ({}):",
                half.word().to_uppercase(),
                asked.len()
            );
            for q in asked {
                println!("--- {} -> {}\n    {}", q.from, q.to, q.question);
            }
        }
    }

    let mut classes: BTreeSet<(String, String)> = BTreeSet::new();
    for e in &measured {
        classes.insert(e.class.clone());
    }
    let headline = format!(
        "{} {} edge instance(s) over {} class(es), {} declaration(s); {} `[[dep]]` row(s), {} \
         question(s)",
        measured.len(),
        half.word(),
        classes.len(),
        measured.iter().map(|e| e.count).sum::<usize>(),
        listed.len(),
        questions.len()
    );

    offenders.sort();
    offenders.dedup();
    if offenders.is_empty() {
        return Row::pass(
            half.row(),
            match half {
                Half::Shipped => {
                    "every dependency edge is at the exact count its ledger row states"
                }
                Half::Test => {
                    "every TEST dependency edge is at the exact count its ledger row states"
                }
            },
            headline,
        );
    }
    Row::fail(
        half.row(),
        match half {
            Half::Shipped => "a dependency edge is not the edge the ledger has written down",
            Half::Test => "a TEST dependency edge is not the edge the ledger has written down",
        },
        format!(
            "{} finding(s), {headline}: {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 3 — the vocabulary
// ------------------------------------------------------------------------------------------------

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// A whole-word, case-insensitive hit where `_` IS a boundary — the same rule
/// `plane-transport-neutrality` settled on, for the same reason: `_` is the joint in every
/// snake_case name, so exempting it exempts `a2a_session` and `mcp_frame` too.
fn word_ci(lower: &str, needle: &str) -> bool {
    let hay: Vec<char> = lower.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || n.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - n.len()) {
        if hay[i..i + n.len()] != n[..] {
            continue;
        }
        let before = i == 0 || !is_word_char(hay[i - 1]);
        let after = i + n.len() == hay.len() || !is_word_char(hay[i + n.len()]);
        if before && after {
            return true;
        }
    }
    false
}

/// A LIBRARY API SPELLING that happens to collide with a plane's instance noun, but names no
/// plane: `tonic`'s own gRPC vocabulary spells its bidirectional-stream type `Streaming<T>`, its
/// server builder method `.streaming(...)`, and its HTTP/2 concurrency knob
/// `max_concurrent_streams`/`MAX_CONCURRENT_STREAMS` — none of which name the `busbar-plane-streaming`
/// plane instance. This is not a blanket exemption for the word: it matches the EXACT library
/// spellings tonic ships, so a source line that genuinely names the plane (`busbar_plane_streaming`,
/// `busbar-streaming-codec`, a bare `streaming::` module path) still trips the ban.
const GRPC_LIBRARY_VOCAB: &[&str] = &["tonic::streaming", ".streaming(", "max_concurrent_streams"];

/// Whether a hit on `needle` at this source line is tonic's own gRPC API surface rather than a
/// reach into the `streaming` plane's instance vocabulary.
fn is_grpc_library_vocab(needle: &str, lower_code: &str) -> bool {
    (needle == "streaming" || needle == "streams")
        && GRPC_LIBRARY_VOCAB
            .iter()
            .any(|pat| lower_code.contains(pat))
}

/// Which crate directory a source file belongs to.
fn owning_dir(rel: &str) -> Option<String> {
    let parts: Vec<&str> = rel.split('/').collect();
    (parts.len() >= 3 && parts[0] == "crates").then(|| format!("crates/{}", parts[1]))
}

/// The words a crate of this kind may not name, and why.
fn banned_for(kind: &str, planes: &BTreeSet<String>) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    match kind {
        "transport" => {
            for p in planes {
                out.push((p.clone(), "a PLANE instance named inside a transport"));
            }
        }
        // A PLANE SPEAKS THE PLANE ABI, NEVER THE WIRE. `dialect` is not a kind (DECISIONS #4); its
        // pre-split codec halves carry the codec ban below. There is no `control` arm — admin/oauth2
        // are `cleanliness` crates, served surfaces that legitimately reference transports over the
        // kernel, so they carry no transport ban (DECISIONS #5).
        "plane" => {
            for lib in TRANSPORT_LIBS {
                out.push((
                    (*lib).to_string(),
                    "a transport LIBRARY named inside a plane",
                ));
            }
            out.push((
                TOKIO_NET.to_string(),
                "a socket module named inside a plane",
            ));
            for p in TRANSPORT_CRATE_PATHS {
                out.push(((*p).to_string(), "a TRANSPORT CRATE named inside a plane"));
            }
        }
        "codec" => {
            for p in TRANSPORT_CRATE_PATHS {
                out.push(((*p).to_string(), "a TRANSPORT CRATE named inside a codec"));
            }
        }
        _ => {}
    }
    out
}

// How many per-file READINGS this thread has actually performed (a memo miss in [`vocab_lines`] or
// [`source_facts`]) — the exit tests' probe for "an unchanged file is read once". Thread-local, so
// parallel tests cannot see each other's reads.
#[cfg(test)]
thread_local! {
    static READINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// ONE PRODUCTION LINE AS [`rule_vocab`] READS IT: literals blanked, lowercased, and the crate-path
/// tokens it carries.
struct VocabLine {
    lineno: usize,
    /// The line with its literals blanked — what a finding quotes.
    code: String,
    /// `code`, lowercased — what every needle is put to.
    lower: String,
    /// Every maximal `[a-z0-9_-]` run that ends immediately before a `::` in `lower`.
    toks: Vec<String>,
}

impl VocabLine {
    fn new(lineno: usize, code: String) -> VocabLine {
        let lower = code.to_lowercase();
        let b = lower.as_bytes();
        let mut toks = Vec::new();
        let mut p = 0usize;
        while p + 1 < b.len() {
            if b[p] == b':' && b[p + 1] == b':' {
                let mut s = p;
                while s > 0 && path_byte(b[s - 1]) {
                    s -= 1;
                }
                if s < p {
                    toks.push(lower[s..p].to_string());
                }
            }
            p += 1;
        }
        VocabLine {
            lineno,
            code,
            lower,
            toks,
        }
    }
}

/// The crate name of a `name::` path when asking a [`VocabLine`]'s tokens about it is EXACTLY
/// `line.lower.contains(path)`; `None` when only the substring search will do.
///
/// Such a path occurs in a line iff some `::` in it is preceded by the name, and when the name is
/// made only of `[a-z0-9_-]` that is iff the name is a SUFFIX of the maximal run of those bytes
/// ending at that `::` — which is what [`VocabLine::toks`] holds. A name with any other byte (or no
/// trailing `::`) is put to the line the long way, so the answer is the same for every input.
fn simple_path_name(path: &str) -> Option<&str> {
    let name = path.strip_suffix("::")?;
    (!name.is_empty() && name.bytes().all(path_byte)).then_some(name)
}

fn path_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'
}

/// [`rule_vocab`]'s reading of one file, MEMOISED on its path and bytes.
///
/// The rule used to re-read every production line of every kind-bearing source file — blank the
/// literals, lowercase, and put ~140 crate paths to each line by substring search — on every gate
/// run. A self-test case is a gate run over a tree one plant away from the last, so that was 727 s
/// of the `kind-isolation` battery spent re-reading files no case had touched. The reading is a
/// pure function of `(path, bytes)`; the verdict over it is still taken fresh on every run, against
/// that run's own crates, dependencies and kind.
static VOCAB_LINES_MEMO: std::sync::OnceLock<
    std::sync::Mutex<BTreeMap<u64, std::sync::Arc<Vec<VocabLine>>>>,
> = std::sync::OnceLock::new();

fn vocab_key(rel: &str, text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    text.hash(&mut h);
    h.finish()
}

fn vocab_lines(rel: &str, text: &str) -> std::sync::Arc<Vec<VocabLine>> {
    let key = vocab_key(rel, text);
    let memo = VOCAB_LINES_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the vocab memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }
    #[cfg(test)]
    READINGS.with(|n| n.set(n.get() + 1));
    let lines: Vec<VocabLine> = scan::production_lines(text)
        .into_iter()
        .map(|(lineno, code)| VocabLine::new(lineno, scan::blank_literals(&code)))
        .collect();
    let lines = std::sync::Arc::new(lines);
    memo.lock()
        .expect("the vocab memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&lines));
    lines
}

/// Every `(line index, needle index)` where a BANNED needle names itself in the file, memoised on
/// the path, the bytes and the banned list — everything the answer reads.
static VOCAB_BANNED_MEMO: std::sync::OnceLock<BannedMemo> = std::sync::OnceLock::new();

/// key -> every `(line index, needle index)` hit.
type BannedMemo = std::sync::Mutex<BTreeMap<u64, std::sync::Arc<Vec<(usize, usize)>>>>;

fn vocab_banned_hits(
    rel: &str,
    text: &str,
    lines: &[VocabLine],
    banned: &[(String, &'static str)],
) -> std::sync::Arc<Vec<(usize, usize)>> {
    if banned.is_empty() {
        return std::sync::Arc::new(Vec::new());
    }
    let key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        vocab_key(rel, text).hash(&mut h);
        banned.hash(&mut h);
        h.finish()
    };
    let memo = VOCAB_BANNED_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the vocab memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }
    let mut hits = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let lower = &line.lower;
        for (n, (needle, _)) in banned.iter().enumerate() {
            let hit = if needle.contains(':') || needle.ends_with('_') || needle.ends_with('-') {
                lower.contains(needle.as_str())
            } else {
                word_ci(lower, needle)
            };
            if hit && is_grpc_library_vocab(needle, lower) {
                continue;
            }
            if hit {
                hits.push((at, n));
            }
        }
    }
    let hits = std::sync::Arc::new(hits);
    memo.lock()
        .expect("the vocab memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&hits));
    hits
}

fn rule_vocab(cx: &Ctx, crates: &[CrateInfo], planes: &BTreeSet<String>) -> Row {
    let kind_of: BTreeMap<&str, &'static str> = crates
        .iter()
        .filter_map(|c| c.kind.map(|k| (c.dir.as_str(), k)))
        .collect();

    let files = match cx.walk(&WalkSpec::new(["crates"]).ext("rs").min_files(MIN_SOURCES)) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_VOCAB,
                "the crate source walk could not run or collapsed below its floor",
                format!(
                    "{e} — a scan of no files names no leak, which is indistinguishable from a \
                     clean tree."
                ),
            )
        }
    };

    // The money-vocabulary ban was a CONTROL-kind rule; `control` is not a kind (DECISIONS #5) and
    // its `cleanliness` successor (admin/oauth2) is a served surface that legitimately reports on
    // cost/usage, so no crate carries the money ban in this rule any more.

    // EVERY WORKSPACE CRATE'S PATH SPELLING, so a source line that names one can be asked whether
    // its own manifest declares the edge. Both spellings, because `busbar_plane_llm::` and
    // `busbar-plane-llm` are one crate and a rule that reads one of them reads half the tree.
    let by_dir: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.dir.as_str(), c)).collect();
    //
    // Each path carries its name when the name is SIMPLE (see [`simple_path_name`]), so a line can
    // be asked about it through the `::` tokens it carries instead of by a substring search.
    let crate_paths: Vec<(String, String, Option<String>)> = crates
        .iter()
        .flat_map(|c| {
            [
                (format!("{}::", c.name.replace('-', "_")), c.name.clone()),
                (format!("{}::", c.name), c.name.clone()),
            ]
        })
        .map(|(path, owner)| {
            let simple = simple_path_name(&path).map(str::to_string);
            (path, owner, simple)
        })
        .collect();
    let every_path_simple = crate_paths.iter().all(|(_, _, simple)| simple.is_some());

    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        let rel = f.rel_str();
        // Fixtures are not the kind's shipped surface, on the same terms every sibling gate uses.
        if rel.contains("/tests/") || rel.ends_with("_test.rs") || rel.ends_with("_tests.rs") {
            continue;
        }
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        let Some(kind) = kind_of.get(dir.as_str()) else {
            continue;
        };
        let Some(me) = by_dir.get(dir.as_str()) else {
            continue;
        };
        let banned = banned_for(kind, planes);
        scanned += 1;
        let lines = vocab_lines(&rel, &f.text);
        for line in lines.iter() {
            if every_path_simple && line.toks.is_empty() {
                continue;
            }
            let lineno = line.lineno;
            let code = &line.code;

            // NO CRATE NAMES A CRATE IT DOES NOT DEPEND ON, whatever kind either of them is.
            //
            // `banned_for` had an arm for four kind words, so `store`, `auth`, `secret`, `hooks`,
            // `export`, `unit`, `kernel` and `substrate` source could name ANY other kind freely —
            // a red team put `busbar_plane_llm::VERSION` and `busbar_transport_http::Client` in
            // `crates/store-memory/src` and this row scanned zero files of it. The generalisation
            // is not a longer list of kind words: it is that naming a crate path you declare no
            // dependency on is a reach with no edge to score, in EVERY direction at once. Where the
            // dependency exists the edge is in the ledger, at its exact count, with its verdict.
            for (path, owner, simple) in &crate_paths {
                if owner.as_str() == me.name {
                    continue;
                }
                let named = match simple {
                    // A line with no `name::` token names no simple crate path at all, which is
                    // most lines: they are skipped without putting a single path to them.
                    Some(name) => line.toks.iter().any(|t| t.ends_with(name.as_str())),
                    None => line.lower.contains(path.as_str()),
                };
                if !named {
                    continue;
                }
                if me
                    .deps
                    .iter()
                    .chain(me.dev_deps.iter())
                    .any(|d| &d.pkg == owner)
                {
                    continue;
                }
                offenders.push(format!(
                    "undeclared-crate-path\t{rel}:{lineno}\t{} ({kind} crate) names `{owner}` and \
                     declares no dependency on it in any table: {}",
                    me.name,
                    code.trim()
                ));
            }
        }
        for &(at, n) in vocab_banned_hits(&rel, &f.text, &lines, &banned).iter() {
            let line = &lines[at];
            let (needle, why) = &banned[n];
            offenders.push(format!(
                "{needle}\t{rel}:{}\t{why} ({kind} crate): {}",
                line.lineno,
                line.code.trim()
            ));
        }
    }

    if scanned == 0 {
        return Row::fail(
            ROW_VOCAB,
            "no crate source was scanned at all",
            "0 file(s) reached the vocabulary rule. Zero files name zero leaks, which reads exactly \
             like a clean tree and is not one."
                .to_string(),
        );
    }

    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_VOCAB,
            "no kind's source names another kind's instance vocabulary",
            format!(
                "{scanned} source file(s) scanned over {} crate(s), 0 findings",
                crates.len()
            ),
        );
    }
    Row::fail(
        ROW_VOCAB,
        "a kind's source names another kind's instance vocabulary",
        format!(
            "{} finding(s) over {scanned} file(s): {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 4 — the registry
// ------------------------------------------------------------------------------------------------

fn rule_registry(cx: &Ctx, crates: &[CrateInfo], reg: &KindRegistry, ship: bool) -> Row {
    // The same refused-at-load rows the edge rule reports: both readings are poisoned by a table
    // that did not parse, and neither may read a short table as a clean one.
    let mut offenders: Vec<String> = reg.errors.clone();

    if crates.len() < MIN_MANIFESTS {
        return Row::fail(
            ROW_REGISTRY,
            "the crate census collapsed below its floor",
            format!(
                "{} crate(s) under crates/ (floor {MIN_MANIFESTS}). A census that finds almost \
                 nothing recognises almost everything.",
                crates.len()
            ),
        );
    }

    // WHERE A CRATE LIVES IS A FINDING, NOT A FILTER. The census walks every `Cargo.toml` in the
    // repository; these three arms say what it found.
    let root_manifest = cx.read("Cargo.toml").unwrap_or_default();
    let members: BTreeSet<String> = manifest::workspace_members(&root_manifest)
        .into_iter()
        .collect();
    let dirs: BTreeSet<&str> = crates.iter().map(|c| c.dir.as_str()).collect();
    let announced_names = reg.announced_names();
    for c in crates {
        // 1. OFF-TREE. A crate of a kind, living somewhere `crates/<dir>` is not, reached by a path
        //    dependency and compiled into the artifact all the same.
        if !is_tree_crate(&c.manifest) {
            // 2. NESTED. A manifest INSIDE another crate's directory. "A manifest one level deeper
            //    belongs to a fixture" was the census's own comment, and it was the hole.
            let host = dirs
                .iter()
                .filter(|d| !d.is_empty() && c.dir.starts_with(&format!("{d}/")))
                .max_by_key(|d| d.len());
            match host {
                Some(host) => offenders.push(format!(
                    "nested-crate\t{}\t`{}` is a whole crate nested inside `{host}`. A manifest \
                     under another crate's directory is a crate `--workspace` does not see and a \
                     path dependency reaches anyway; move it to crates/<dir> or delete it.",
                    c.manifest, c.name
                )),
                None => offenders.push(format!(
                    "off-tree-crate\t{}\t`{}` resolves to kind `{}` and does not live at \
                     crates/<dir>/Cargo.toml. Every crate of a kind is a crate of the tree, in the \
                     tree's own layout, on the member list — or it is a kind nobody censuses, \
                     nobody scans and nobody scores.",
                    c.manifest,
                    c.name,
                    c.kind.unwrap_or("?")
                )),
            }
        }
        // 3. UNMEMBERED. On disk, off `[workspace.members]`: `--workspace` never compiles it,
        //    never tests it, never clippies it and never denies it, and a path dependency ships it
        //    regardless. Deleting one line is the whole of the manoeuvre.
        //
        //    AN `[[announced]]` CRATE IS EXEMPT, and only while its announcement stands. An
        //    announcement is the reviewed sentence that says this crate is landing right now, and
        //    the member line arrives with the rest of it; the announcement's own expiry — struck
        //    when the crate is real, RED on the ship sha — is what stops that from becoming a way
        //    to keep a crate out of `--workspace` indefinitely.
        if !members.contains(&c.dir) && !announced_names.contains(c.name.as_str()) {
            let reached: Vec<&str> = crates
                .iter()
                .filter(|o| {
                    o.deps
                        .iter()
                        .chain(o.dev_deps.iter())
                        .any(|d| d.pkg == c.name)
                })
                .map(|o| o.name.as_str())
                .collect();
            offenders.push(format!(
                "unmembered\t{}\t`{}` is on disk and not in [workspace.members], so --workspace \
                 compiles, tests, clippies and denies everything BUT it{}",
                c.dir,
                c.name,
                if reached.is_empty() {
                    ". Add it to the member list or delete the crate.".to_string()
                } else {
                    format!(
                        " — and it is still path-depended by {}, so it ships uncovered. Add it to \
                         the member list.",
                        reached.join(", ")
                    )
                }
            ));
        }
    }

    // A REVIEWED OFF-TREE ENTRY THAT COVERS NOTHING IS A DEAD ALLOWANCE.
    let all_manifests = manifests(cx);

    // A MANIFEST THE CENSUS COULD NOT NAME IS A FINDING, NEVER A `continue`.
    //
    // The census skipped any `Cargo.toml` it could not read a `[package] name` out of, and that
    // skip was the whole door: everything downstream keys off the census, so a manifest that is not
    // in it has no kind, contributes no needles, moves no cell, and is not in `by_name` — which is
    // the filter the `Cargo.lock` cross-check is itself keyed on. Two spellings of a non-byte-exact
    // header are now normalised away (see [`normalise_header_line`]), but normalising is a fix for
    // the spellings somebody has already thought of. This is the fix for the ones they have not: a
    // file that DECLARES DEPENDENCIES and yields no package name is a crate this gate cannot score,
    // and a crate this gate cannot score is reported rather than dropped.
    //
    // The condition is the dependency tables and not merely the file, because `Cargo.toml` files
    // with no `[package]` are ordinary — the workspace root is one — and a virtual manifest that
    // declares no edges is nothing this rule is about.
    if let Ok(seen) = &all_manifests {
        for (rel, text) in seen {
            if off_tree_entry(rel).is_some() || package_name(text).is_some() {
                continue;
            }
            let decls = manifest::dep_decls(text);
            if decls.is_empty() {
                continue;
            }
            offenders.push(format!(
                "nameless-manifest\t{rel}\tthis manifest declares {} dependency(ies) and no \
                 `[package] name` this reader can find, so the census cannot score it — no kind, \
                 no vocabulary, no cell, and no entry in the name index the `Cargo.lock` \
                 cross-check is keyed on. A crate that cannot be named is not a crate that was \
                 found clean. Give it a `[package] name`, or delete the dependency tables.",
                decls.len()
            ));
        }
    }

    // AN OFF-TREE MANIFEST IS OFF THE TREE, AND A PRODUCT CRATE MAY NOT REACH ONE.
    //
    // [`OFF_TREE_MANIFESTS`] excuses fixtures from the census — one entry is the whole
    // `xtask/fixtures/` DIRECTORY — and "excused from the census" was read by every rule as
    // "invisible". A red team put a live crate there (`xtask/fixtures/wire-bridge`, whose `lib.rs`
    // is `pub use busbar_plane_llm::*;`), path-depended it from a transport, and six gates stayed
    // green: the bridge is not in the census, so it has no kind, so the edge it carries has no
    // class, so no `[[dep]]` row is owed for it and no cell moves. A fixture directory became a
    // place to keep a plane.
    //
    // The exemption is therefore one-directional from here on. A manifest may be off the tree; what
    // it may NOT be is in a product crate's build graph.
    if let Ok(seen) = &all_manifests {
        // KEYED ON THE DIRECTORY, NOT THE PACKAGE NAME. A fixture is reachable through its PATH,
        // and a fixture whose package name collides with a real crates.io crate is ordinary:
        // `xtask/fixtures/dirty-dep-hyphenated/hyper-util` declares `hyper-util`, which is also the
        // registry crate five product crates legitimately depend on. Name-matching reported all
        // five; path-matching reports the one thing this rule is about.
        let off_tree_dirs: BTreeMap<String, &str> = seen
            .iter()
            .filter(|(rel, _)| off_tree_entry(rel).is_some())
            .map(|(rel, _)| (manifest_dir(rel), rel.as_str()))
            .collect();
        for c in crates {
            for decl in c.deps.iter().chain(c.dev_deps.iter()) {
                let Some(p) = &decl.path else { continue };
                let Some(at) = off_tree_dirs.get(&join_rel(&c.dir, p)) else {
                    continue;
                };
                offenders.push(format!(
                    "off-tree-reached\t{at}\t{} path-depends on `{}`, whose manifest is covered by \
                     a reviewed OFF-TREE entry ({}). An off-tree manifest is excused from the \
                     CENSUS — it has no kind, so its edges have no class, no `[[dep]]` row is owed \
                     for them and no cell moves — and that exemption is one-directional: a product \
                     crate may not reach one. Move the crate under crates/<dir> and let it be \
                     scored, or delete the dependency.",
                    c.name,
                    decl.cite(),
                    off_tree_manifest_reason(at).unwrap_or("reviewed")
                ));
            }
        }
    }

    let seen_manifests: Vec<String> = match all_manifests {
        Ok(m) => m.into_iter().map(|(rel, _)| rel).collect(),
        Err(e) => {
            offenders.push(format!(
                "unreadable\tCargo.toml\t{e} — the manifest walk is this row's own input, and a \
                 walk that did not read is not a walk that found nothing."
            ));
            Vec::new()
        }
    };
    for (path, _) in OFF_TREE_MANIFESTS {
        let covered = seen_manifests
            .iter()
            .any(|rel| off_tree_entry(rel).map(|(p, _)| *p) == Some(*path));
        if !covered {
            offenders.push(format!(
                "dead-off-tree\t{path}\tthe off-tree entry for `{path}` covers no manifest any \
                 more. Strike it — an exemption that outlives what it excused is a hole nobody \
                 re-reads."
            ));
        }
    }

    // EVERY CRATE RESOLVES TO A KIND IN THE TABLE. This is the row the ruling is written on.
    for c in crates {
        if c.kind.is_none() {
            offenders.push(format!(
                "unknown-kind\t{}\t`{}` matches no kind in the table — {MAKE_A_NEW_KIND}",
                c.dir, c.name
            ));
        }
    }

    // A KIND NOBODY INSTANTIATES IS A DEAD ROW in the table, not a kind — unless it is DECLARED
    // pending, and then the ratchet runs the other way: the first crate of it retires the pending
    // entry, so a kind can never be both pending and live.
    //
    // An ANNOUNCED kind is the third case, and it is the one that keeps this rule from biting the
    // wrong way: the crate is being written right now, so the kind is neither dead nor pending —
    // it is arriving, and the announcement is the claim that it is. Landing it must be GREEN here.
    let live: BTreeSet<&str> = crates.iter().filter_map(|c| c.kind).collect();
    let pending: BTreeSet<&str> = PENDING_KINDS.iter().map(|(k, _)| *k).collect();
    let announced_kinds = reg.announced_kinds();
    for def in KINDS {
        if !live.contains(def.kind)
            && !pending.contains(def.kind)
            && !announced_kinds.contains(def.kind)
        {
            offenders.push(format!(
                "dead-kind\tKINDS\t`{}` is in the kind table and no crate is one; strike it or \
                 build one",
                def.kind
            ));
        }
    }
    for (kind, _) in PENDING_KINDS {
        if live.contains(kind) {
            offenders.push(format!(
                "kind-arrived\tPENDING_KINDS\t`{kind}` now has crates in the tree; strike its \
                 pending entry so the dead-kind rule watches it like every other kind"
            ));
        }
    }

    let present: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();

    // THE RENAME ALIASES EXPIRE WITH THE CRATE THEY TRANSLATE.
    for (from, to, crate_name) in PLANE_ALIASES {
        if !present.contains(crate_name) {
            offenders.push(format!(
                "alias-retired\t{crate_name}\tthe `{from}` -> `{to}` plane alias outlived \
                 `{crate_name}`. The rename has landed; strike the alias."
            ));
        }
    }

    // …AND THEIR CANONICAL SIDE IS A KEY A PLANE DECLARES. The alias table is typed here; the
    // plane's own key is not — it is read off the plane's `impl PlaneMeta`. An alias onto a word no
    // plane registers under is two spellings joined onto nothing: the rename it anticipated either
    // landed under another key or never happened.
    let plane_keys: BTreeSet<&str> = crates
        .iter()
        .filter(|c| c.kind == Some("plane"))
        .flat_map(|c| c.declared_keys.iter().map(String::as_str))
        .collect();
    for (from, to, _) in PLANE_ALIASES {
        if !plane_keys.contains(to) {
            offenders.push(format!(
                "alias-undeclared\t{to}\tthe `{from}` -> `{to}` plane alias canonicalises onto \
                 `{to}`, and no plane crate declares `const KEY: &'static str = \"{to}\"` in its \
                 `impl PlaneMeta`. Point the alias at the key the plane registers under."
            ));
        }
    }

    // A GRANT THAT NAMES A KIND THE TABLE DOES NOT HAVE CAN NEVER MATCH AN EDGE — AND SO CAN
    // NEVER BE SCORED DEAD EITHER.
    //
    // Every other allowance in this file expires: a `[[dep]]` row whose edge is gone is
    // `dead-dep-edge`, a `[[cell]]` that measures zero is `dead-cell`, a kind with no crates is
    // `dead-kind`, an accepted name whose crate is gone is `dead-waiver`. The three CLASS tables
    // had no such rule, and a class naming a kind that is not in [`KINDS`] falls through every one
    // of them: `verdict_for` only ever asks whether a MEASURED class is in the list, and a class
    // that cannot be measured is never asked about. `("core", "caps")` was one — `caps` folded into
    // `busbar-contract` under W2.c — and it sat in [`PENDING_EDGES`] granting nothing to nothing
    // until this rule named it and it was struck. A rule aimed at a crate that does not exist can never fire, and a grant
    // aimed at a kind that does not exist can never be read.
    let table_kinds: BTreeSet<&str> = KINDS.iter().map(|d| d.kind).collect();
    for (table, rows) in [
        ("ARCHITECTURE_ALLOWED", ARCHITECTURE_ALLOWED),
        ("PENDING_EDGES", PENDING_EDGES),
        ("ARCHITECTURE_TCB", ARCHITECTURE_TCB),
    ] {
        for (from, to) in rows {
            for (side, k) in [("from", from), ("to", to)] {
                if !table_kinds.contains(k) {
                    offenders.push(format!(
                        "dead-grant	{table}	`({from}, {to})` names `{k}` in the `{side}`                          position and `{k}` is not a kind in the table. A grant for a kind that                          does not exist matches no edge, so it grants nothing and it is never                          scored dead — it is a line that reads like a decision and is not one.                          Strike it, or add the kind."
                    ));
                }
            }
        }
    }

    // A TRANSITIONAL EXEMPTION FOR AN EDGE THAT CANNOT BE TAKEN IS NOT AN EXEMPTION.
    //
    // The drain's expiry rule keys on the `from` crate and runs at the SHIP sha (`rule_drain`), so
    // a row whose `to` crate was absorbed rather than renamed reds at the tag FOR THE WRONG
    // REASON — "the legacy crate still exists" — and until then exempts an edge to a crate that is
    // not there. `busbar-a2a -> busbar-admin` and `busbar-mcp -> busbar-admin` are both: `busbar-
    // admin` folded into `busbar-core-admin` under #37. The `to` may be a `busbar-<kind>-*` GLOB,
    // which is a claim about a kind rather than a crate and is checked at load (`bad-glob`); only
    // an exact name is asked for here.
    for t in &reg.transitional {
        let dead_from = !present.contains(t.from.as_str());
        let dead_to = !t.to.ends_with('*') && !present.contains(t.to.as_str());
        if dead_from || dead_to {
            let which = match (dead_from, dead_to) {
                (true, true) => "neither crate is".to_string(),
                (true, false) => format!("`{}` is not", t.from),
                _ => format!("`{}` is not", t.to),
            };
            offenders.push(format!(
                "dead-transitional	{REGISTRY_FILE}	`[[transitional]] {} -> {}` ({}) exempts an                  edge that cannot be taken: {which} in the tree. The drain's own expiry runs on                  the `from` crate at the ship sha, so a row whose subject was ABSORBED rather than                  renamed reds at the tag for the wrong reason and exempts nothing until then.                  Strike it.",
                t.from, t.to, t.reason
            ));
        }
    }

    // THE LEGACY RATCHET. The exemption expires with the crate it excuses.
    for name in LEGACY_CRATES {
        if !present.contains(name) {
            offenders.push(format!(
                "legacy-retired\t{name}\tthe legacy exemption for `{name}` outlived the crate. \
                 Strike it from LEGACY_CRATES and from the kind table's `legacy` matchers — an \
                 exemption for a crate that no longer exists is a hole with no floor under it."
            ));
        }
    }

    // A REGISTRATION NAMES A CRATE THAT EXISTS, AND EXPIRES THE DAY ITS NAME CATCHES UP.
    //
    // Two ratchets, both automatic. A row naming a crate that is not in the tree is a kind
    // assignment for nothing — the crate was renamed or deleted and the row was not. And a row
    // whose crate ALREADY resolves to the registered kind through its own name is redundant: the
    // rename it was written for has landed, and leaving it standing means the tree carries a list
    // that says what the name already says, which is how a list stops being read.
    for r in &reg.registered {
        if !present.contains(r.name.as_str()) {
            offenders.push(format!(
                "dead-registration\t{REGISTRY_FILE}\t`{}` is registered as kind `{}` ({}) and is \
                 not in the tree. A kind assignment for a crate that does not exist is a row \
                 nobody re-reads; strike it",
                r.name, r.kind, r.reason
            ));
            continue;
        }
        let (by_name, remainder, _) = resolve_kind(&r.name);
        if refine(by_name, &remainder) == Some(r.kind.as_str()) {
            offenders.push(format!(
                "redundant-registration\t{REGISTRY_FILE}\t`{}` resolves to kind `{}` through its \
                 own NAME now, so the registration says what the name says. The rename this row \
                 was written for has landed; strike the row",
                r.name, r.kind
            ));
        }
    }

    // TWO CONTROL SURFACES NEVER SERVE THE SAME ROUTE.
    //
    // A control crate declares its routes as DATA — a claim table — and that is what makes this
    // checkable at all: the prefix each surface answers for is a list of literal segments in its
    // own source, not a string built at runtime inside a handler. Two crates claiming the same one
    // is an ambiguity the registry cannot resolve, and it is worse here than between planes: a
    // control surface is unmetered and privileged, so "which crate answered" is a security answer.
    //
    // The surfaces are the `cleanliness` kind's (DECISIONS #5). This read `kind == "control"`, a
    // kind no table row defines and no crate resolves to, so the loop ran over nothing on every
    // tree and the arm could not fire — the same re-point `rule_control` already made.
    let mut routes: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for c in crates.iter().filter(|c| c.kind == Some(CLEANLINESS)) {
        for route in control_routes(cx, &c.dir) {
            routes.entry(route).or_default().push(c.name.as_str());
        }
    }
    for (route, owners) in &routes {
        if owners.len() > 1 {
            offenders.push(format!(
                "shared-route\tcrates/\tthe control route `{route}` is claimed by {} crates ({}). \
                 A control surface answers for its own routes and no one else's; two claimants is \
                 an ambiguity the registry cannot resolve — {MAKE_A_NEW_KIND}",
                owners.len(),
                owners.join(", ")
            ));
        }
    }

    // AN ANNOUNCEMENT DOES NOT SURVIVE ITS OWN LANDING — but it is the ship twin, not the per-push
    // gate, that says so. The whole purpose of the row is that the agent who lands the crate does
    // not red a gate they never touched; the moment the crate exists, the row has done its work and
    // the ordinary dead-kind and dead-waiver ratchets watch that crate like every other. The DONE
    // oracle is where the spent row is collected, so it cannot ride into a release.
    if ship {
        for a in &reg.announced {
            if present.contains(a.name.as_str()) {
                offenders.push(format!(
                    "announced-landed\t{REGISTRY_FILE}\t`{}` ({}) is announced as kind `{}` and has \
                     LANDED. The announcement was the window before the crate existed; strike the \
                     row so the census speaks for the crate",
                    a.name, a.reason, a.kind
                ));
            }
        }
    }

    // ONE KIND VOCABULARY, NOT TWO. `qa/construction.toml` names plugin kinds too; a key there
    // that maps onto nothing here is the second vocabulary starting to drift from this one.
    match cx.read("qa/construction.toml") {
        Ok(text) => {
            let keys = plugin_kind_keys(&text);
            if keys.is_empty() {
                offenders.push(
                    "no-construction-kinds\tqa/construction.toml\t[gate.plugin_kinds] is empty or \
                     was renamed away; the cross-check between the two kind vocabularies is now \
                     reading nothing"
                        .to_string(),
                );
            }
            let mapped: BTreeMap<&str, &str> = CONSTRUCTION_KIND_KEYS.iter().copied().collect();
            for key in &keys {
                match mapped.get(key.as_str()) {
                    Some(kind) if KINDS.iter().any(|d| d.kind == *kind) => {}
                    _ => offenders.push(format!(
                        "unmapped-kind\tqa/construction.toml\t[gate.plugin_kinds] declares `{key}`, \
                         which maps onto no kind in this table — {MAKE_A_NEW_KIND}"
                    )),
                }
            }
        }
        Err(e) => offenders.push(format!(
            "unreadable\tqa/construction.toml\t{e} — the kind vocabularies cannot be compared"
        )),
    }

    offenders.sort();
    if offenders.is_empty() {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for c in crates {
            *counts.entry(c.kind.unwrap_or("?")).or_default() += 1;
        }
        return Row::pass(
            ROW_REGISTRY,
            "every crate in the census is exactly one of the table's kinds",
            format!(
                "{} crate(s), {} kind(s), {} announced landing(s): {}",
                crates.len(),
                counts.len(),
                reg.announced.len(),
                counts
                    .iter()
                    .map(|(k, n)| format!("{k}={n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        );
    }
    Row::fail(
        ROW_REGISTRY,
        "the kind registry does not recognise what the tree contains",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

/// THE ROUTES ONE CONTROL CRATE CLAIMS, read off its claim table as DATA.
///
/// The kind's contract says a control surface declares its routes as data, and this is the rule
/// that makes that a fact rather than a preference: the routes are the literal path segments in
/// `src/claims.rs`, so a surface whose claim is assembled somewhere a reader cannot see declares
/// NO route here and shares none — which is a different finding (`no-claim`), not a pass.
fn control_routes(cx: &Ctx, dir: &str) -> Vec<String> {
    let Ok(text) = cx.read(format!("{dir}/src/claims.rs")) else {
        return Vec::new();
    };
    let mut segs: Vec<String> = Vec::new();
    for (_, code) in scan::production_lines(&text) {
        let mut rest = code.as_str();
        while let Some(i) = rest.find("Lit(") {
            rest = &rest[i + 4..];
            let Some(open) = rest.find('"') else { break };
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            segs.push(after[..close].to_string());
            rest = &after[close + 1..];
        }
    }
    if segs.is_empty() {
        Vec::new()
    } else {
        vec![format!("/{}", segs.join("/"))]
    }
}

/// The keys of `qa/construction.toml`'s `[gate.plugin_kinds]` table.
fn plugin_kind_keys(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') {
            inside = t == "[gate.plugin_kinds]";
            continue;
        }
        if !inside || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((k, _)) = t.split_once('=') {
            out.push(k.trim().to_string());
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------
// rule 5 — the shape (ship criterion)
// ------------------------------------------------------------------------------------------------

/// The kind's ENTRY TRAIT, derived from the kind's own name rather than tabled beside it:
/// `plane` → `Plane`, `transport` → `Transport`, `unit` → `Unit`.
///
/// ONE KIND IS NOT DERIVABLE, and the reason is a NAME COLLISION rather than an exception.
///
/// `export` → `Export` picks `busbar_contract::kinds::Export`, which is **a different kind of
/// thing wearing the same word**: it is WAL/JOURNAL shipping — `ExportItem::{JournalEntry, Content,
/// Segment}` acknowledged at-least-once with an `Ack` — and has nothing to do with telemetry
/// export. It also has ZERO implementors anywhere in the tree, including its own crate's tests, so
/// deriving the name pointed this rule at a trait no loadable plugin could ever satisfy while the
/// trait a loadable export MUST implement (`busbar_plugin_sdk::ExportHandler`: `streams` /
/// `deliver` / `routes` / `handle_http` / `drain_observations`, behind the six C symbols, the signed
/// manifest and the loader's `[2, 3]` window) went unchecked.
///
/// Spelled here so the false friend does not come back: two kinds, one word, and the one with the
/// riders wins. `kinds::Export` is an unimplemented specification slated for deletion.
fn entry_trait(kind: &str) -> String {
    if kind == "export" {
        return "ExportHandler".to_string();
    }
    let mut c = kind.chars();
    match c.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), c.as_str()),
        None => String::new(),
    }
}

/// Is `rel` shipped source of `dir`, as opposed to a fixture?
fn is_shipped_source(rel: &str) -> bool {
    !rel.contains("/tests/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

/// Everything the shape and battery rules read off the tree in one walk.
struct SourceIndex {
    /// dir -> the `mod`/`pub mod` names declared in its `src/lib.rs`.
    skeleton: BTreeMap<String, BTreeSet<String>>,
    /// dir -> how many times each trait is implemented in its shipped source.
    impls: BTreeMap<String, BTreeMap<String, usize>>,
    /// dir -> whether it has a `src/lib.rs` at all.
    has_lib: BTreeSet<String>,
    /// dir -> it carries a `tests/*conformance*.rs` battery file WITH AT LEAST ONE LIVE ENTRY.
    conformance: BTreeSet<String>,
    /// dir -> it carries a battery file whose every entry is `#[ignore]`d, or which has no entry at
    /// all. A file, not a battery: see [`live_battery_entries`].
    conformance_dead: BTreeSet<String>,
}

/// `(live, ignored)` `#[test]` entries in a battery file.
///
/// A BATTERY THAT DOES NOT RUN IS NOT A BATTERY. The rule keyed on the file EXISTING and on a
/// `testkit` dev-dependency being declared, neither of which executes anything: a conformance file
/// whose every entry is `#[ignore = "not yet on busbar-contract: …"]` satisfied both, and its crate
/// read as green while `cargo test` ran none of it. The reason in the ignore string is exactly the
/// work the battery is supposed to be gating.
///
/// Attributes are read off the BLANKED line, so `#[ignore]` inside a string in the file's own prose
/// is not an attribute, and an entry's attribute block is the contiguous run of `#[…]` lines around
/// it — which is where rustfmt puts `#[ignore]`, above or below the `#[test]`.
fn live_battery_entries(text: &str) -> (usize, usize) {
    let mut lex = scan::LexState::default();
    let lines: Vec<String> = text
        .lines()
        .map(|l| scan::blank_code(l, &mut lex))
        .collect();
    let is_attr = |l: &String| l.trim_start().starts_with("#[");
    let (mut live, mut ignored) = (0usize, 0usize);
    for (i, l) in lines.iter().enumerate() {
        if !l.trim_start().starts_with("#[test]") {
            continue;
        }
        let mut lo = i;
        while lo > 0 && is_attr(&lines[lo - 1]) {
            lo -= 1;
        }
        let mut hi = i;
        while hi + 1 < lines.len() && is_attr(&lines[hi + 1]) {
            hi += 1;
        }
        if lines[lo..=hi].iter().any(|a| a.contains("#[ignore")) {
            ignored += 1;
        } else {
            live += 1;
        }
    }
    (live, ignored)
}

/// The `<…>` immediately after `impl`, skipped as a BALANCED group: `impl<S: CellStore>` and
/// `impl<'a, T: Into<Vec<u8>>>` both end at the `>` that closes the one this opened, not at the
/// first `>` in the line.
fn skip_generic_params(s: &str) -> Option<&str> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i + c.len_utf8()..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// A `use path::Trait as Alias;` — the RENAME, as `(trait, alias)`.
///
/// `use busbar_contract::plane::Plane as Metered; impl Metered for Wire {}` is a transport
/// implementing the plane entry face, and it went green: `impl_trait_on` answers by the LAST PATH
/// SEGMENT, by name, and nothing in this gate resolved a rename. One keystroke, and the face rule
/// is looking at a word the tree does not use.
fn use_alias(code: &str) -> Option<(String, String)> {
    let t = code.trim();
    let t = t.strip_prefix("pub ").map(str::trim_start).unwrap_or(t);
    let rest = t.strip_prefix("use ")?;
    let rest = rest.trim_end().strip_suffix(';')?;
    let (path, alias) = rest.rsplit_once(" as ")?;
    let alias = alias
        .trim()
        .trim_matches(|c| c == '}' || c == ',' || c == ' ');
    let last = path
        .trim()
        .rsplit("::")
        .next()?
        .trim()
        .trim_start_matches('{')
        .trim();
    if last.is_empty() || alias.is_empty() {
        return None;
    }
    if !alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if !last.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((last.to_string(), alias.to_string()))
}

/// THE HEAD OF THE TRAIT-IMPL STATEMENT, wherever the tokens fall.
///
/// `impl_trait_on` reads the head of ONE LINE, and its own doc comment already said the qualified
/// spelling "is a bypass of any rule written on this function, in one keystroke". Two more
/// keystrokes were still there when a red team looked:
///
/// * `use busbar_contract::plane::Plane as Metered;` + `impl Metered for Wire {}` — the trait under
///   a name of the author's choosing.
/// * `impl\n    busbar_contract::plane::Plane\n    for Wire2` — what `cargo fmt` itself writes when
///   the header is long, and no LINE of it holds both `impl` and ` for `.
///
/// So the statement is read as TOKENS rather than as a line: the production lines are joined, the
/// renames of the file are resolved, and an `impl` is found wherever its three parts sit. A head
/// that is not a single path (it carries a brace, a paren, a semicolon, a comma) is not a trait
/// impl and is refused, which is what keeps `impl Foo { … for x in y … }` out of the count.
fn impl_heads(text: &str) -> Vec<String> {
    let mut aliases: BTreeMap<String, String> = BTreeMap::new();
    let mut joined = String::new();
    for (_, code) in scan::production_lines(text) {
        let code = scan::blank_literals(&code);
        if let Some((tr, alias)) = use_alias(&code) {
            aliases.insert(alias, tr);
        }
        joined.push_str(&code);
        joined.push(' ');
    }
    let b = joined.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(p) = joined[i..].find("impl") {
        let at = i + p;
        i = at + 4;
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let Some(head) = head_after_impl(&joined[at + 4..]) else {
            continue;
        };
        out.push(aliases.get(&head).cloned().unwrap_or(head));
    }
    out
}

/// The trait named between an `impl` and its ` for `, when what sits there really is one.
fn head_after_impl(rest: &str) -> Option<String> {
    // THE GENERIC HEAD IS PARSED, NOT REFUSED, and the BOUND inside it is not an impl:
    // `impl<T: Plane> Meter for T` implements `Meter`, and the `Plane` in the bound says only which
    // types it is written over. Skipping the `<…>` as the balanced group it is answers both.
    let rest = if rest.starts_with('<') {
        skip_generic_params(rest)?
    } else if rest.starts_with(' ') || rest.starts_with('\t') {
        rest
    } else {
        // `impl_of(…)`, `implement`, … — `impl` has to be the keyword, not a prefix.
        return None;
    };
    let (head, _) = rest.split_once(" for ")?;
    let head = head.trim();
    if head.is_empty()
        || head.contains([
            '<', '&', '{', '}', '(', ')', ';', ',', '=', '[', ']', '!', '"', '#',
        ])
    {
        return None;
    }
    // THE QUALIFIED SPELLING IS THE SAME IMPLEMENTATION. `impl busbar_contract::Plane for Wire`
    // begins with a lowercase crate segment, so a head-first check answered `None` and the trait
    // was implemented in plain sight. The trait is the LAST path segment; the qualification says
    // where it lives.
    let head = head.rsplit("::").next().unwrap_or(head).trim();
    if head.is_empty() || head.contains(':') || head.contains(' ') {
        return None;
    }
    head.chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase())
        .then(|| head.to_string())
}

fn index_sources(cx: &Ctx) -> Result<SourceIndex, String> {
    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(MIN_SOURCES))
        .map_err(|e| e.to_string())?;
    let mut idx = SourceIndex {
        skeleton: BTreeMap::new(),
        impls: BTreeMap::new(),
        has_lib: BTreeSet::new(),
        conformance: BTreeSet::new(),
        conformance_dead: BTreeSet::new(),
    };
    for f in &files {
        let rel = f.rel_str();
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        let facts = source_facts(&rel, &dir, &f.text);
        if let Some(live) = facts.live {
            if live > 0 {
                idx.conformance.insert(dir.clone());
                idx.conformance_dead.remove(&dir);
            } else if !idx.conformance.contains(&dir) {
                idx.conformance_dead.insert(dir.clone());
            }
        }
        if !facts.shipped {
            continue;
        }
        if let Some(found) = &facts.mods {
            idx.has_lib.insert(dir.clone());
            idx.skeleton
                .entry(dir.clone())
                .or_default()
                .extend(found.iter().cloned());
        }
        let counts = idx.impls.entry(dir.clone()).or_default();
        for t in &facts.heads {
            *counts.entry(t.clone()).or_default() += 1;
        }
    }
    Ok(idx)
}

/// WHAT ONE FILE CONTRIBUTES TO THE SOURCE INDEX — a pure function of its path and its bytes.
///
/// [`index_sources`] used to re-derive all of it for every one of the ~1 700 source files on every
/// gate run, and a self-test case IS a gate run over a tree that differs from the last one by a
/// plant or two: 365 s of the `kind-isolation` battery went on re-reading `impl` heads out of files
/// no case had touched. The fold over the files is unchanged; only the per-file reading is
/// remembered, keyed on everything it reads (see [`SOURCE_FACTS_MEMO`]).
struct SourceFacts {
    /// `Some(live entries)` when the file is a `tests/*conformance*` battery of its crate.
    live: Option<usize>,
    /// Whether the file is shipped source at all.
    shipped: bool,
    /// `Some(mod names)` when the file is its crate's `src/lib.rs` (and shipped).
    mods: Option<Vec<String>>,
    /// Every trait-impl head in it, when shipped; empty otherwise.
    heads: Vec<String>,
}

/// The per-file memo behind [`source_facts`]. The key hashes the path, the owning directory and the
/// bytes — every input the reading has — so a hit is a memo and never a stale reading, and a plant
/// that changes a file changes its key.
static SOURCE_FACTS_MEMO: std::sync::OnceLock<
    std::sync::Mutex<BTreeMap<u64, std::sync::Arc<SourceFacts>>>,
> = std::sync::OnceLock::new();

fn source_facts(rel: &str, dir: &str, text: &str) -> std::sync::Arc<SourceFacts> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    dir.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    let memo = SOURCE_FACTS_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the source-facts memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }
    #[cfg(test)]
    READINGS.with(|n| n.set(n.get() + 1));
    let live = (rel.starts_with(&format!("{dir}/tests/")) && rel.contains(CONFORMANCE_MARKER))
        .then(|| live_battery_entries(text).0);
    let shipped = is_shipped_source(rel);
    let mut mods = None;
    let mut heads = Vec::new();
    if shipped {
        if rel == format!("{dir}/src/lib.rs") {
            let mut found = Vec::new();
            for (_, code) in scan::production_lines(text) {
                let t = code.trim();
                let body = t
                    .strip_prefix("pub mod ")
                    .or_else(|| t.strip_prefix("mod "));
                if let Some(name) = body.and_then(|b| b.split(&[';', ' ', '{'][..]).next()) {
                    if !name.is_empty() {
                        found.push(name.to_string());
                    }
                }
            }
            mods = Some(found);
        }
        heads = impl_heads(text);
    }
    let facts = std::sync::Arc::new(SourceFacts {
        live,
        shipped,
        mods,
        heads,
    });
    memo.lock()
        .expect("the source-facts memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&facts));
    facts
}

fn rule_shape(crates: &[CrateInfo], idx: &SourceIndex) -> Row {
    let dir_of: BTreeMap<&str, &str> = crates
        .iter()
        .map(|c| (c.name.as_str(), c.dir.as_str()))
        .collect();
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (kind, exemplar) in EXEMPLARS {
        let want_trait = entry_trait(kind);
        // A MISSING EXEMPLAR IS A FINDING, NOT A REASON TO LOOK AWAY FROM THE KIND. This arm used
        // to `continue`, so the day the unit exemplar was absorbed every unit crate stopped being
        // checked for a lib, an entry or a skeleton — and the row went red about the exemplar and
        // never about a member. None of the three member checks is derived from the exemplar: the
        // skeleton is the spec's ([`kind_skeleton`]) and "exactly one entry" is the kind's rule. The
        // exemplar only VOUCHES for the entry trait; with none to vouch, the members are held to
        // the rule as written.
        let ex_entries = match dir_of.get(exemplar) {
            Some(ex_dir) => {
                let ex_impls = idx.impls.get(*ex_dir).cloned().unwrap_or_default();
                let n = ex_impls.get(&want_trait).copied().unwrap_or(0);
                if n != 1 {
                    offenders.push(format!(
                        "no-entry\t{ex_dir}\tkind `{kind}` states no single entry: the exemplar \
                         implements `{want_trait}` {n} time(s) in shipped source, so there is no \
                         one declaration every crate of the kind owes"
                    ));
                }
                n
            }
            None => {
                offenders.push(format!(
                    "no-exemplar\t{exemplar}\tthe canonical sibling for kind `{kind}` is not in \
                     the tree, so no crate models this kind's entry; its members are still held \
                     to the kind's skeleton and single entry below"
                ));
                1
            }
        };
        let skeleton = kind_skeleton(kind);

        for c in crates.iter().filter(|c| c.kind == Some(*kind)) {
            checked += 1;
            if !idx.has_lib.contains(&c.dir) {
                offenders.push(format!(
                    "no-lib\t{}/src/lib.rs\t{} has no lib.rs; a kind's crate is a library and \
                     nothing else",
                    c.dir, c.name
                ));
                continue;
            }
            if ex_entries == 1 {
                let n = idx
                    .impls
                    .get(&c.dir)
                    .and_then(|m| m.get(&want_trait))
                    .copied()
                    .unwrap_or(0);
                if n != 1 {
                    offenders.push(format!(
                        "entry-count\t{}\t{} implements `{want_trait}` {n} time(s) in shipped \
                         source; every crate of kind `{kind}` states EXACTLY ONE",
                        c.dir, c.name
                    ));
                }
            }
            // THE EXEMPLAR IS NOT EXEMPT. It was skipped because the skeleton was its own file
            // list, which made the comparison vacuous for it; the skeleton is now the spec's, and a
            // spec applies to the crate that models it first of all.
            let mine = idx.skeleton.get(&c.dir).cloned().unwrap_or_default();
            let missing: Vec<&String> = skeleton.difference(&mine).collect();
            if !missing.is_empty() {
                offenders.push(format!(
                    "skeleton\t{}/src/lib.rs\t{} is missing {} of the `{kind}` skeleton \
                     (PLUGIN-TREE.md §3): {}",
                    c.dir,
                    c.name,
                    missing.len(),
                    missing
                        .iter()
                        .map(|m| m.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }

    if checked == 0 {
        return Row::fail(
            ROW_SHAPE,
            "no crate of any exemplar kind was read",
            "0 crate(s) reached the shape rule, and zero crates deviate from every skeleton."
                .to_string(),
        );
    }
    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_SHAPE,
            "every crate of a kind exposes its kind's surface and skeleton",
            format!(
                "{checked} crate(s) over {} exemplar kind(s)",
                EXEMPLARS.len()
            ),
        );
    }
    Row::fail(
        ROW_SHAPE,
        "a crate of a kind does not expose its kind's surface",
        format!(
            "{} deviation(s) over {checked} crate(s): {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 6 — the shared battery (ship criterion)
// ------------------------------------------------------------------------------------------------

/// NO CRATE IMPLEMENTS ANOTHER KIND'S ENTRY FACE.
///
/// A crate's KIND is a claim about what it is, and a trait implementation is the same claim made to
/// the compiler. When the two disagree, the compiler's is the one that runs: `impl Plane for Wire`
/// inside `busbar-transport-sse` is a plane, registered as a plane, reached as a plane, whatever
/// the manifest and the name say. `:shape` counts a crate's implementations of its OWN kind's
/// trait, so both directions of that swap left its row byte-identical — the rule never asked the
/// question this one asks.
///
/// A DIALECT MAY IMPLEMENT ITS PLANE'S FACE, and nothing else may. That is what a dialect IS: the
/// plane's other half, written against the plane's own face; the split is about where the code
/// lives, not about which trait it satisfies.
fn rule_faces(crates: &[CrateInfo], idx: &SourceIndex, reg: &KindRegistry, ship: bool) -> Row {
    let faces: BTreeMap<String, &'static str> = ENTRY_TRAIT_KINDS
        .iter()
        .filter_map(|k| KINDS.iter().find(|d| d.kind == *k).map(|d| d.kind))
        .map(|k| (entry_trait(k), k))
        .collect();
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    for c in crates {
        let Some(mine) = c.kind else { continue };
        let Some(impls) = idx.impls.get(&c.dir) else {
            continue;
        };
        checked += 1;
        for (trait_name, n) in impls {
            let Some(owner) = faces.get(trait_name) else {
                continue;
            };
            if *owner == mine {
                continue;
            }
            seen.insert((c.name.clone(), trait_name.clone()));
            // THE SHIP TWIN OWES ZERO. Per-push the four that exist are held at their exact count
            // by a `[[face]]` row; at the tag there is no such thing as a reviewed one.
            let listed = (!ship)
                .then(|| {
                    reg.faces
                        .iter()
                        .find(|f| f.krate == c.name && f.face == *trait_name)
                })
                .flatten();
            match listed {
                Some(f) if f.count == *n as i64 => {}
                Some(f) => offenders.push(format!(
                    "face-ratchet\t{}\t{} implements `{trait_name}` {n} time(s) and its `[[face]]` \
                     row says {}. The row is TODAY'S MEASUREMENT, exact in both directions: above \
                     it is the landing that grew the coupling, below it is stale slack. What the \
                     number is made of: {} — and the line that deletes it: {}",
                    c.dir, c.name, f.count, f.why, f.drain
                )),
                None => offenders.push(format!(
                    "foreign-entry\t{}\t{} is kind `{mine}` and implements `{trait_name}` {n} \
                     time(s) in shipped source — the entry face of kind `{owner}`. A trait \
                     implementation is a claim made to the COMPILER, and when it disagrees with \
                     the crate's kind the compiler's claim is the one that runs; {MAKE_A_NEW_KIND}",
                    c.dir, c.name
                )),
            }
        }
    }

    // A ROW WHOSE IMPLEMENTATION IS GONE IS A DEAD ALLOWANCE, on the same terms every other
    // ratchet here lives under: the landing that deletes the impl is the landing that deletes the
    // row, and the gate is red until it does.
    if !ship {
        for f in &reg.faces {
            if !seen.contains(&(f.krate.clone(), f.face.clone())) {
                offenders.push(format!(
                    "dead-face\t{REGISTRY_FILE}\t`[[face]] {} / {}` covers nothing: that crate \
                     implements that face nowhere in shipped source any more ({}). Strike the row.",
                    f.krate, f.face, f.cite
                ));
            }
        }
    }

    if checked == 0 {
        return Row::fail(
            ROW_FACES,
            "no crate reached the entry-face rule",
            "0 crate(s) were indexed, and zero crates implement zero foreign faces.".to_string(),
        );
    }
    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_FACES,
            "no crate implements another kind's entry face",
            format!(
                "{checked} crate(s) indexed against {} entry face(s): {}; {} reviewed [[face]] \
                 row(s)",
                faces.len(),
                faces.keys().cloned().collect::<Vec<_>>().join(", "),
                reg.faces.len()
            ),
        );
    }
    Row::fail(
        ROW_FACES,
        "a crate implements another kind's entry face",
        format!(
            "{} finding(s) over {checked} crate(s): {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

fn rule_testkit(crates: &[CrateInfo], idx: &SourceIndex) -> Row {
    let batteries: Vec<&str> = crates
        .iter()
        .map(|c| c.name.as_str())
        .filter(|n| n.contains(BATTERY_MARKER))
        .collect();
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for kind in BATTERY_KINDS {
        let members: Vec<&CrateInfo> = crates.iter().filter(|c| c.kind == Some(*kind)).collect();
        if members.is_empty() {
            continue;
        }
        // WHICH BATTERY IS THIS KIND'S? The one every member of the kind already runs. A kind whose
        // members run no shared battery at all has none, and that is the finding — named, not
        // guessed at and not silently skipped.
        let runners: Vec<&CrateInfo> = members
            .iter()
            .copied()
            .filter(|c| {
                idx.conformance.contains(&c.dir)
                    || c.dev_deps.iter().any(|d| d.pkg.contains(BATTERY_MARKER))
            })
            .collect();
        checked += members.len();
        let want_trait = entry_trait(kind);
        let no_battery = runners.is_empty();
        if no_battery {
            offenders.push(format!(
                "no-battery\tkind:{kind}\tno battery for kind {kind} — none of its {} crate(s) \
                 runs a shared conformance battery (no `{BATTERY_MARKER}` dev-dependency, no \
                 tests/*{CONFORMANCE_MARKER}*.rs). Candidates in the tree: {}",
                members.len(),
                if batteries.is_empty() {
                    "none".to_string()
                } else {
                    batteries.join(", ")
                }
            ));
        }
        for c in members {
            // A BATTERY WITH NO SUBJECT PROVES NOTHING. The battery's whole content is the kind's
            // trait exercised through the crate's own implementor (`PLUGIN-TREE.md` §3: `let _: &dyn
            // <KindTrait> = &P;`), so a crate of the kind that implements the trait ZERO times has
            // nothing for its battery to be about — and a file that compiles anyway is a file that
            // asserts about something else. Read off the same trait-impl index `:shape` counts with.
            let implementors = idx
                .impls
                .get(&c.dir)
                .and_then(|m| m.get(&want_trait))
                .copied()
                .unwrap_or(0);
            if implementors == 0 {
                offenders.push(format!(
                    "no-implementor\t{}\t{} is kind `{kind}` and implements `{want_trait}` nowhere \
                     in shipped source, so its battery has no subject — a conformance file that \
                     passes over no implementor is not evidence about this crate",
                    c.dir, c.name
                ));
            }
            if idx.conformance_dead.contains(&c.dir) {
                offenders.push(format!(
                    "battery-ignored\t{}\t{} carries a tests/*{CONFORMANCE_MARKER}*.rs whose every \
                     entry is `#[ignore]`d (or which has none). `cargo test` runs nothing of it; \
                     the file exists and the battery does not.",
                    c.dir, c.name
                ));
                continue;
            }
            if !no_battery && !runners.iter().any(|r| r.name == c.name) {
                offenders.push(format!(
                    "not-run\t{}\t{} does not run kind `{kind}`'s shared battery, which {} of its \
                     siblings do",
                    c.dir,
                    c.name,
                    runners.len()
                ));
            }
        }
    }

    if checked == 0 {
        return Row::fail(
            ROW_TESTKIT,
            "no crate of any battery kind was read",
            "0 crate(s) reached the battery rule; zero crates skip every battery.".to_string(),
        );
    }
    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_TESTKIT,
            "every crate of a kind runs its kind's shared conformance battery",
            format!(
                "{checked} crate(s) over {} kind(s); batteries: {}",
                BATTERY_KINDS.len(),
                batteries.join(", ")
            ),
        );
    }
    Row::fail(
        ROW_TESTKIT,
        "a kind has no shared conformance battery, or a crate does not run it",
        format!(
            "{} finding(s) over {checked} crate(s): {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 7 — the step list
// ------------------------------------------------------------------------------------------------

/// The kernel's OWN step table, and the plane trait it is run through. Both are read; neither is
/// restated here, because a hand-written step list is a list that goes stale the first time a step
/// is added and nothing says so.
const STEP_TABLE_FILE: &str = "crates/busbar-contract/src/caps/step.rs";
const PLANE_TRAIT_FILE: &str = "crates/busbar-contract/src/plane.rs";

/// A tree with fewer than this many plane-owned steps has not been read; the loop is ten steps long
/// and the planes own seven of them.
const MIN_PLANE_STEPS: usize = 5;

/// THE STEPS A PLANE OWNS: the kernel's step table, intersected with the plane trait's methods.
///
/// Neither source alone is the answer. The step table holds `Arrival`, `Decode` and `Encode`, which
/// are the KERNEL's three and which no plane implements; the plane trait holds the codec halves
/// (`decode_ingress`, `encode_refusal`, …) and the fact reporters, which are not steps of the loop.
/// What both name is exactly the strict step list a data plane runs, and reading it off the two
/// files means a step added to the loop is owed by every plane on the same commit.
fn plane_owned_steps(cx: &Ctx) -> Result<Vec<String>, String> {
    let steps = cx.read(STEP_TABLE_FILE).map_err(|e| e.to_string())?;
    let mut table: Vec<String> = Vec::new();
    let mut inside = false;
    for (_, code) in scan::production_lines(&steps) {
        let t = code.trim();
        if t.contains("const ALL") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if t.starts_with(']') {
            break;
        }
        if let Some(name) = t.strip_prefix("StepName::") {
            let name: String = name
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            if !name.is_empty() {
                table.push(name.to_lowercase());
            }
        }
    }

    let plane = cx.read(PLANE_TRAIT_FILE).map_err(|e| e.to_string())?;
    let mut methods: BTreeSet<String> = BTreeSet::new();
    for (_, code) in scan::production_lines(&plane) {
        if let Some(rest) = code.trim().strip_prefix("fn ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                methods.insert(name);
            }
        }
    }

    let owned: Vec<String> = table.into_iter().filter(|s| methods.contains(s)).collect();
    if owned.len() < MIN_PLANE_STEPS {
        return Err(format!(
            "{} plane-owned step(s) read from {STEP_TABLE_FILE} × {PLANE_TRAIT_FILE} (floor \
             {MIN_PLANE_STEPS}); a step list that did not read is not a plane that runs every step",
            owned.len()
        ));
    }
    Ok(owned)
}

/// THE DATA-PATH STEPS a control surface may not run: the ones that reach an upstream or turn a
/// response into usage. A control surface answers out of node state; it dials nothing and it meters
/// nothing, which is what "unmetered" means when it is a fact rather than a policy.
const DATA_PATH_STEPS: &[&str] = &["route", "meter"];

/// The UPSTREAM vocabulary a control surface may not name at all — the words that only make sense
/// when there is something on the other side of the request.
const UPSTREAM_WORDS: &[&str] = &[
    "egress", "pool", "routing", "failover", "breaker", "provider",
];

/// Every `fn <name>` in a crate's shipped source, with the file, line and the body's blanked text.
struct FnBody {
    file: String,
    line: usize,
    body: String,
}

/// The shipped-source function bodies of one crate, keyed by function name. Brace-counted over
/// BLANKED code, so a `}` inside a string or a comment does not end a body.
fn fn_bodies(cx: &Ctx, dir: &str) -> BTreeMap<String, Vec<FnBody>> {
    let mut out: BTreeMap<String, Vec<FnBody>> = BTreeMap::new();
    let Ok(files) = cx.walk(&WalkSpec::new([dir]).ext("rs")) else {
        return out;
    };
    for f in &files {
        let rel = f.rel_str();
        if !is_shipped_source(&rel) {
            continue;
        }
        let mut lex = scan::LexState::default();
        let lines: Vec<String> = f
            .text
            .lines()
            .map(|l| scan::blank_code(l, &mut lex))
            .collect();
        for (i, l) in lines.iter().enumerate() {
            let Some(rest) = l.trim_start().strip_prefix("fn ") else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let mut depth = 0i32;
            let mut body = String::new();
            let mut started = false;
            for l in &lines[i..] {
                for ch in l.chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            started = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if started {
                    body.push_str(l);
                    body.push(' ');
                }
                if started && depth <= 0 {
                    break;
                }
            }
            out.entry(name).or_default().push(FnBody {
                file: rel.clone(),
                line: i + 1,
                body,
            });
        }
    }
    out
}

/// A body that states nothing. `todo!`, `unimplemented!` and `unreachable!` are the three ways a
/// step is declared and not run — the compiler is satisfied, the trait is implemented, and the loop
/// the plane is supposed to be running stops there.
const SHORT_CIRCUITS: &[&str] = &["todo!", "unimplemented!", "unreachable!"];

fn rule_steps(cx: &Ctx, crates: &[CrateInfo]) -> Row {
    let steps = match plane_owned_steps(cx) {
        Ok(s) => s,
        Err(e) => {
            return Row::fail(
                ROW_STEPS,
                "the strict step list could not be read",
                format!(
                    "{e} — the step list is this row's own input, and a plane measured against no \
                     steps runs all of them."
                ),
            )
        }
    };
    let planes: Vec<&CrateInfo> = crates.iter().filter(|c| c.kind == Some("plane")).collect();
    if planes.is_empty() {
        return Row::fail(
            ROW_STEPS,
            "no plane crate reached the step rule",
            "0 plane crate(s); zero planes skip every step, which reads exactly like every plane \
             running all of them."
                .to_string(),
        );
    }

    let mut offenders: Vec<String> = Vec::new();
    for c in &planes {
        let bodies = fn_bodies(cx, &c.dir);
        for step in &steps {
            let Some(found) = bodies.get(step) else {
                offenders.push(format!(
                    "missing-step\t{}\t{} is a data plane and implements no `{step}` — the strict \
                     step list is the whole loop, and a plane that runs part of it is a plane the \
                     kernel cannot audit at the step that did not run",
                    c.dir, c.name
                ));
                continue;
            };
            for b in found {
                if let Some(marker) = SHORT_CIRCUITS.iter().find(|m| b.body.contains(**m)) {
                    offenders.push(format!(
                        "short-circuit\t{}:{}\t{}'s `{step}` is `{marker}` — the step is declared \
                         and not run, which satisfies the compiler and states nothing",
                        b.file, b.line, c.name
                    ));
                }
            }
        }
    }

    offenders.sort();
    if offenders.is_empty() {
        return Row::pass(
            ROW_STEPS,
            "every data plane implements the whole strict step list",
            format!(
                "{} plane(s) × {} step(s) read off {STEP_TABLE_FILE} and {PLANE_TRAIT_FILE}: {}",
                planes.len(),
                steps.len(),
                steps.join(", ")
            ),
        );
    }
    Row::fail(
        ROW_STEPS,
        "a data plane does not run the whole strict step list",
        format!(
            "{} finding(s) over {} plane(s): {}",
            offenders.len(),
            planes.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 8 — the control path (ship criterion)
// ------------------------------------------------------------------------------------------------

fn rule_control(cx: &Ctx, crates: &[CrateInfo]) -> Row {
    let controls: Vec<&CrateInfo> = crates
        .iter()
        .filter(|c| c.kind == Some(CLEANLINESS))
        .collect();
    if controls.is_empty() {
        return Row::fail(
            ROW_CONTROL,
            "no control surface reached the control-path rule",
            "0 control crate(s); zero surfaces run zero data-path steps, which reads exactly like a \
             control kind that keeps to its own path."
                .to_string(),
        );
    }
    let mut offenders: Vec<String> = Vec::new();
    for c in &controls {
        let bodies = fn_bodies(cx, &c.dir);
        for step in DATA_PATH_STEPS {
            if let Some(found) = bodies.get(*step) {
                for b in found {
                    offenders.push(format!(
                        "data-path-step\t{}:{}\t{} is a CONTROL surface and implements `{step}`, a \
                         data-path step. A control surface reaches no upstream and meters nothing; \
                         the steps it runs are the control path (verify, admit, audit, answer)",
                        b.file, b.line, c.name
                    ));
                }
            }
        }
        let Ok(files) = cx.walk(&WalkSpec::new([c.dir.as_str()]).ext("rs")) else {
            continue;
        };
        for f in &files {
            let rel = f.rel_str();
            if !is_shipped_source(&rel) {
                continue;
            }
            for (lineno, code) in scan::production_lines(&f.text) {
                let lower = scan::blank_literals(&code).to_lowercase();
                for w in UPSTREAM_WORDS {
                    if word_ci(&lower, w) {
                        offenders.push(format!(
                            "upstream\t{rel}:{lineno}\t{} names `{w}` — a control surface has no \
                             upstream to reach, so the vocabulary of reaching one has no meaning \
                             on this path",
                            c.name
                        ));
                    }
                }
            }
        }
    }
    offenders.sort();
    offenders.dedup();
    if offenders.is_empty() {
        return Row::pass(
            ROW_CONTROL,
            "every control surface keeps to the control path",
            format!("{} control surface(s), 0 finding(s)", controls.len()),
        );
    }
    Row::fail(
        ROW_CONTROL,
        "a control surface runs the data path or names an upstream",
        format!(
            "{} finding(s) over {} control surface(s): {}",
            offenders.len(),
            controls.len(),
            offenders.join(" | ")
        ),
    )
}

// ------------------------------------------------------------------------------------------------
// rule 9 — one wire, one registration
// ------------------------------------------------------------------------------------------------

/// The two kinds that MAY name a transport crate. Everything else may not, and the rule is spelled
/// as the exception rather than the list for the reason every list in this file is spelled that way.
///
/// It WAS a list — `["plane", "dialect", "control", "unit", "codec"]` — and a red team walked
/// through the gap in one line: `store-memory`, a store plugin, took a `[dependencies]` edge on
/// `busbar-transport-tcp` and this row PASSED, reporting "no plugin links one", because `store` was
/// not on the list. Nor were `auth`, `secret`, `hooks` or `export` — four more plugin kinds, and
/// every kind added after the list was written. A list is the thing the next kind forgets to join.
///
/// A transport naming a transport is that kind's own layering (`ws` over `http` over `tcp`), which
/// the measured graph already carries and the instance rules already govern; the composition root
/// names them by definition. Every other kind in the table — plugin, library, contract or legacy —
/// is something that would be choosing its own wire, and if one of them legitimately must, that is
/// an entry HERE, in a commit that says why.
const WIRE_PERMITTED_KINDS: &[&str] = &["root", "transport"];

/// THE ONE TEST EDGE A NON-WIRE CRATE MAY TAKE ON A WIRE: the loader's both-ways witness of the
/// transport kind (ARCHITECT (K8 residue): both-ways fixture dev-edge, #2 (4)/(5), K5 precedent; #3
/// makes transport a swappable kind like any other). A `plugin-tooling` crate's `[dev-dependencies]`
/// edge to EXACTLY the crate its own `[package.metadata.busbar.both-ways]` names for kind `transport`
/// is the fixture both doors of that witness load — the linked rlib and the dropped-in cdylib — and
/// not a plugin choosing its wire. Nothing else is excused: a NORMAL edge, a dev-edge to any other
/// wire, or a crate of any other kind is the finding it always was.
const WIRE_FIXTURE_KIND: &str = "plugin-tooling";

/// The crate a manifest's `[package.metadata.busbar.both-ways]` table names for kind `transport`,
/// read line by line exactly as the loader's own `build.rs` reads that table.
fn both_ways_transport_fixture(manifest: &str) -> Option<String> {
    let mut in_table = false;
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.both-ways]";
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some((kind, krate)) = code.split_once('=') {
            if kind.trim().trim_matches('"') == "transport" {
                return Some(krate.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// The registration symbol a wire is composed under: `busbar-transport-http` -> `HttpTransport`.
fn wire_symbol(instance: &str) -> String {
    let mut out = String::new();
    for part in instance.split('-') {
        let mut cs = part.chars();
        if let Some(f) = cs.next() {
            out.push(f.to_ascii_uppercase());
            out.push_str(cs.as_str());
        }
    }
    out.push_str("Transport");
    out
}

/// THE PER-FILE REGISTRATION SCAN, MEMOISED — the same device `:matrix` already uses, for the same
/// reason: every self-test case re-runs the whole gate over a tree that differs from the last one by
/// a single file.
///
/// The key is everything the answer depends on: the file's path, its bytes, and the needle set (so
/// a plant that registers a transport invalidates every entry). The scan is a pure function of those
/// three, so a hit is a memo and never a stale reading.
type WireHits = std::sync::Arc<BTreeSet<String>>;

static WIRE_MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, WireHits>>> =
    std::sync::OnceLock::new();

fn wires_named_in(rel: &str, text: &str, needles: &[(String, String, String)]) -> WireHits {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    text.hash(&mut h);
    for (n, p, s) in needles {
        n.hash(&mut h);
        p.hash(&mut h);
        s.hash(&mut h);
    }
    let key = h.finish();
    let memo = WIRE_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the wire memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }
    let mut hit: BTreeSet<String> = BTreeSet::new();
    for (_, code) in scan::production_lines(text) {
        if hit.len() == needles.len() {
            break;
        }
        let lower = scan::blank_literals(&code).to_lowercase();
        for (name, path, sym) in needles {
            if !hit.contains(name) && lower.contains(path.as_str()) && word_ci(&lower, sym) {
                hit.insert(name.clone());
            }
        }
    }
    let entry = std::sync::Arc::new(hit);
    memo.lock()
        .expect("the wire memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&entry));
    entry
}

/// THE MANIFEST TABLE A ROOT LINKS ITS PLUGINS THROUGH, AS DATA.
///
/// A root whose build script turns `<feature> = "<crate>"` rows into the tables it folds names the
/// crates it links HERE and nowhere in source — so a wire linked by a row is registered by that
/// row, and the manifest is the one place however many rows it carries.
const LINKED_TABLE: &str = "[package.metadata.busbar.linked]";

/// The crate each `LINKED_TABLE` row names, in file order. One row per line, the value optionally
/// quoted — the same reading the root's build script gives the table.
fn linked_crates(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == LINKED_TABLE;
            continue;
        }
        if let (true, Some((_, value))) = (in_table, code.split_once('=')) {
            out.push(value.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn rule_wires(cx: &Ctx, crates: &[CrateInfo]) -> Row {
    let wires: Vec<&CrateInfo> = crates
        .iter()
        .filter(|c| c.kind == Some("transport"))
        .collect();
    if wires.is_empty() {
        return Row::fail(
            ROW_WIRES,
            "no transport crate reached the registration rule",
            "0 wire(s); zero wires are registered twice.".to_string(),
        );
    }
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let permitted: BTreeSet<&str> = WIRE_PERMITTED_KINDS.iter().copied().collect();
    let mut offenders: Vec<String> = Vec::new();

    // A PLUGIN NEVER CHOOSES ITS WIRE. The manifest edge is the same reach spelled where no source
    // scan would see it, so it is read here rather than left to the edge-class graph — which
    // ratchets on what the tree HAS and would have accepted the first such edge on the commit that
    // added its allowance.
    for c in crates {
        let Some(kind) = c.kind else { continue };
        if permitted.contains(kind) {
            continue;
        }
        // THE TEST HALF IS READ TOO. `cargo test` links a dev-dependency, and a plugin whose test
        // binary picks a wire is a plugin whose author has already decided which wire it is for —
        // the shape reaches production one refactor later, and the row that would have said so was
        // reading one of the two dependency tables.
        // The both-ways witness's fixture, when this crate is plugin tooling that declares one.
        let fixture = (kind == WIRE_FIXTURE_KIND)
            .then(|| cx.read(&c.manifest).ok())
            .flatten()
            .and_then(|m| both_ways_transport_fixture(&m));
        let witness = |dep: &crate::manifest::DepDecl| fixture.as_deref() == Some(dep.pkg.as_str());
        for dep in c
            .deps
            .iter()
            .chain(c.dev_deps.iter().filter(|d| !witness(d)))
        {
            if by_name.get(dep.pkg.as_str()).and_then(|t| t.kind) == Some("transport") {
                let dep = dep.cite();
                offenders.push(format!(
                    "wire-dependency\t{}\t{} is kind `{kind}` and depends on the wire crate {dep}. \
                     Only a `root` or another `transport` names one: a plugin declares WHICH \
                     transport it claims, as data, and never links the crate that moves the bytes \
                     — {MAKE_A_NEW_KIND}",
                    c.dir, c.name
                ));
            }
        }
    }

    // ONE WIRE, ONE REGISTRATION.
    //
    // A REGISTRATION IS THE WIRE'S OWN TYPE, REACHED THROUGH THE WIRE'S OWN CRATE PATH — both, and
    // that pairing is the whole precision of this rule. The type alone matched `HttpTransport` in
    // `busbar-mcp`'s legacy client, which is that crate's own struct of the same name and composes
    // nothing; the crate path alone matched `busbar_transport_http::ClientSettings` in the root's
    // policy module, which reads a setting and registers no wire. A rule that reported either would
    // be a rule somebody waived, and a waived rule is not a rule.
    //
    // Another WIRE naming a wire is skipped for the reason `transport -> transport` stays in the
    // measured graph: `ws` over `http` over `tcp` is one kind's own layering, not a second registry.
    let Ok(files) = cx.walk(&WalkSpec::new(["crates"]).ext("rs").min_files(MIN_SOURCES)) else {
        return Row::fail(
            ROW_WIRES,
            "the source walk for the registration rule could not run",
            "a scan of no files finds no second registration, which is indistinguishable from one \
             registration."
                .to_string(),
        );
    };
    let kind_of: BTreeMap<&str, &'static str> = crates
        .iter()
        .filter_map(|c| c.kind.map(|k| (c.dir.as_str(), k)))
        .collect();
    // THE NEEDLES ARE DERIVED ONCE, and the file is read ONCE. Both halves were per-wire before:
    // the scan re-ran `production_lines` and `blank_literals` over the whole file for each of the
    // seven wires, so a 1 500-file tree was lexed ten thousand times per run — 8.2 of the gate's
    // 12.6 seconds, on every one of the fifty-eight self-test cases.
    let needles: Vec<(String, String, String)> = wires
        .iter()
        .map(|w| {
            let instance = w.remainder.join("-");
            (
                w.name.clone(),
                format!("busbar_transport_{}::", instance.replace('-', "_")),
                wire_symbol(&instance).to_lowercase(),
            )
        })
        .collect();
    let mut sites: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in &files {
        let rel = f.rel_str();
        if !is_shipped_source(&rel) {
            continue;
        }
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        if kind_of.get(dir.as_str()) == Some(&"transport") {
            continue;
        }
        for name in wires_named_in(&rel, &f.text, &needles).iter() {
            sites.entry(name.clone()).or_default().insert(rel.clone());
        }
    }
    // …AND THE ROOT'S MANIFEST ROW. A root that links a wire as data registers it in its
    // `LINKED_TABLE` row, which is one place: the row and a source line naming the same wire are
    // two registries, exactly as two source files are.
    for c in crates.iter().filter(|c| c.kind == Some("root")) {
        let Ok(text) = cx.read(&c.manifest) else {
            continue;
        };
        for krate in linked_crates(&text) {
            if wires.iter().any(|w| w.name == krate) {
                sites
                    .entry(krate)
                    .or_default()
                    .insert(format!("{} {LINKED_TABLE}", c.manifest));
            }
        }
    }
    for w in &wires {
        let here = sites.get(&w.name).cloned().unwrap_or_default();
        // EXACTLY ONE HAS TWO SIDES. A wire composed nowhere is a member of the tree — built,
        // tested and shipped — that no registry reaches, so a client asking for it gets no
        // transport at runtime. The row's title promised "exactly one place" while its only
        // predicate was `> 1`, and it printed `<wire>=unregistered` in its own PASS detail.
        if here.is_empty() {
            offenders.push(format!(
                "unregistered-wire\t{}\tthe wire {} is composed in NO place: no root's \
                 {LINKED_TABLE} row names it and no shipped source outside a transport names `{}` \
                 through its own crate path. A wire is registered in exactly ONE place — the \
                 transport registry the root composes — and a wire in none is a crate the tree \
                 ships and nothing can reach",
                w.dir,
                w.name,
                wire_symbol(&w.remainder.join("-"))
            ));
        }
        if here.len() > 1 {
            offenders.push(format!(
                "second-registration\t{}\tthe wire {} is composed in {} places ({}). A wire is \
                 registered in exactly ONE place — the transport registry the root composes — or \
                 two registries disagree about what `{}` is and nothing says which one ran",
                w.dir,
                w.name,
                here.len(),
                here.iter().cloned().collect::<Vec<_>>().join(", "),
                w.remainder.join("-")
            ));
        }
    }

    offenders.sort();
    if offenders.is_empty() {
        let placed: Vec<String> = wires
            .iter()
            .map(|w| {
                format!(
                    "{}={}",
                    w.remainder.join("-"),
                    sites
                        .get(&w.name)
                        .and_then(|s| s.iter().next().cloned())
                        .unwrap_or_else(|| "unregistered".to_string())
                )
            })
            .collect();
        return Row::pass(
            ROW_WIRES,
            "each wire is composed in exactly one place and no plugin links one",
            format!("{} wire(s): {}", wires.len(), placed.join(" ")),
        );
    }
    Row::fail(
        ROW_WIRES,
        "a wire is registered twice or nowhere, or a plugin links the crate that moves the bytes",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

// ------------------------------------------------------------------------------------------------
// `--write` — THE RE-PIN, AND IT ONLY EVER GOES DOWN
// ------------------------------------------------------------------------------------------------

/// The row `--write` reports on. Owed by neither registration: it exists only in write mode, and
/// [`KindIsolationGate::run`] returns it INSTEAD of the ordinary rows when the flag is set.
pub const ROW_WRITE: &str = "kind-isolation:write";

/// One row of the registry whose number this run would move.
struct Repin {
    /// `[[cell]] busbar × plane`, `[[dep]] a -> b (shipped)`, `[[face]] c / Plane` — what a reader
    /// is looking at.
    label: String,
    /// The lines that identify the row in the file, so the rewrite cannot move the wrong one.
    keys: Vec<(String, String)>,
    table: &'static str,
    was: i64,
    now: i64,
}

/// EVERY EXACT-COUNT ROW IN THE REGISTRY, MEASURED, and which way each one would have to move.
fn repins(cx: &Ctx, crates: &[CrateInfo], reg: &KindRegistry) -> Result<Vec<Repin>, String> {
    let mut out: Vec<Repin> = Vec::new();

    let cells = matrix::measured_cells(cx, crates)?;
    for c in &reg.matrix_cells {
        let now = cells
            .get(&(c.krate.clone(), c.kind.clone()))
            .copied()
            .unwrap_or(0) as i64;
        if now != c.count {
            out.push(Repin {
                label: format!("[[cell]] {} × {}", c.krate, c.kind),
                keys: vec![
                    ("crate".to_string(), c.krate.clone()),
                    ("kind".to_string(), c.kind.clone()),
                ],
                table: "cell",
                was: c.count,
                now,
            });
        }
    }

    let inst = matrix::measured_instances(cx, crates)?;
    for c in &reg.instance_cells {
        let now = inst
            .get(&(c.krate.clone(), c.kind.clone()))
            .copied()
            .unwrap_or(0) as i64;
        if now != c.count {
            out.push(Repin {
                label: format!("[[instance]] {} × {}", c.krate, c.kind),
                keys: vec![
                    ("crate".to_string(), c.krate.clone()),
                    ("kind".to_string(), c.kind.clone()),
                ],
                table: "instance",
                was: c.count,
                now,
            });
        }
    }

    for half in [Half::Shipped, Half::Test] {
        let measured = measure_edges(crates, half);
        for row in reg.dep_edges.iter().filter(|d| d.half == half.word()) {
            let now = measured
                .iter()
                .find(|e| e.from == row.from && e.to == row.to)
                .map_or(0, |e| e.count) as i64;
            if now != row.count {
                out.push(Repin {
                    label: format!("[[dep]] {} -> {} ({})", row.from, row.to, half.word()),
                    keys: vec![
                        ("from".to_string(), row.from.clone()),
                        ("to".to_string(), row.to.clone()),
                        ("half".to_string(), row.half.clone()),
                    ],
                    table: "dep",
                    was: row.count,
                    now,
                });
            }
        }
    }

    let idx = index_sources(cx)?;
    for f in &reg.faces {
        let now = crates
            .iter()
            .find(|c| c.name == f.krate)
            .and_then(|c| idx.impls.get(&c.dir))
            .and_then(|m| m.get(&f.face))
            .copied()
            .unwrap_or(0) as i64;
        if now != f.count {
            out.push(Repin {
                label: format!("[[face]] {} / {}", f.krate, f.face),
                keys: vec![
                    ("crate".to_string(), f.krate.clone()),
                    ("face".to_string(), f.face.clone()),
                ],
                table: "face",
                was: f.count,
                now,
            });
        }
    }
    Ok(out)
}

/// The registry file with each named row's `count` rewritten, and nothing else touched.
///
/// A line-by-line rewrite rather than a re-render, and that is the point: this file is written by
/// hand, its comments ARE the reasoning, and a generator that re-emitted it would quietly delete
/// every sentence a reviewer wrote. What `--write` edits is one number per row.
fn rewrite_counts(text: &str, repins: &[Repin]) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        let t = lines[i].trim();
        let Some(head) = t.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) else {
            out.push(lines[i].to_string());
            i += 1;
            continue;
        };
        // Buffer the whole row, so it can be identified before any of it is written.
        let head = head.trim().to_string();
        let start = i;
        i += 1;
        while i < lines.len() && !lines[i].trim().starts_with('[') {
            i += 1;
        }
        let row = &lines[start..i];
        let field = |key: &str| -> Option<String> {
            row.iter().find_map(|l| {
                let (k, v) = l.trim().split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let hit = repins.iter().find(|r| {
            r.table == head
                && r.keys
                    .iter()
                    .all(|(k, v)| field(k).as_deref() == Some(v.as_str()))
        });
        for l in row {
            match (hit, l.trim().split_once('=')) {
                (Some(r), Some((k, _))) if k.trim() == "count" => {
                    out.push(format!("count = \"{}\"", r.now));
                }
                _ => out.push((*l).to_string()),
            }
        }
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// `cargo xtask gate kind-isolation --write` — RE-PIN DOWN, NEVER UP.
///
/// The ratchet is exact in both directions, and that is what makes it a ratchet: a count above its
/// row is the landing that grew the coupling, and a count BELOW it is stale slack nobody drained on
/// the commit that drained the edge. Exactness has one cost, though, and it lands on the landing
/// that does the RIGHT thing: a cut that removes two of a crate's plane hits leaves the row three
/// too high, and the gate is red until somebody edits a number by hand. That is a tax on draining,
/// which is the opposite of what the ratchet is for.
///
/// So the flag exists, and it does exactly one thing: it lowers a row to what the tree measures.
///
/// IT REFUSES TO RUN IF ANY COUNT WOULD RISE, and it refuses WHOLESALE — not "writes the ones that
/// fell and complains about the rest". A run that grew a coupling is a landing that has to be read,
/// and a tool that quietly re-pinned the falls in the same breath would hand it a file that looks
/// reviewed. The refusal names every row that would rise.
fn rule_write(cx: &Ctx, crates: &[CrateInfo], reg: &KindRegistry) -> Row {
    let repins = match repins(cx, crates, reg) {
        Ok(r) => r,
        Err(e) => {
            return Row::fail(
                ROW_WRITE,
                "the measurement --write would re-pin to could not be taken",
                format!("{e} — a re-pin to a number nobody measured is a number nobody measured."),
            )
        }
    };
    let (up, down): (Vec<&Repin>, Vec<&Repin>) = repins.iter().partition(|r| r.now > r.was);
    if !up.is_empty() {
        return Row::fail(
            ROW_WRITE,
            "--write refuses: a count would RISE, and this flag only ever lowers one",
            format!(
                "{} row(s) would rise and {} would fall; NOTHING was written. A count above its \
                 row is the landing that grew the coupling, and it is read by a person, never \
                 re-pinned by a tool. Rising: {}",
                up.len(),
                down.len(),
                up.iter()
                    .map(|r| format!("{} {} -> {}", r.label, r.was, r.now))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    // …AND IT MEASURES THE WHOLE GATE BEFORE IT WRITES ANYTHING.
    //
    // It did not, and that was a bypass sitting in the binary: `owed()` returns one row in write
    // mode and `run` returned one row, so `gate kind-isolation --write` ran the re-pin and NOTHING
    // ELSE. A red team put plane words into a transport's `lib.rs` — a tree the ordinary run reds
    // three ways — and got `PASS kind-isolation:write … 1 row(s), green` and `EXIT=0` out of the
    // same binary in the same tree. Every rule this gate has, one flag away. The reason the rise
    // refusal above did not save it is exact: `repins` only visits rows that ALREADY EXIST, and the
    // cell the plant grew had no row, so there was nothing to rise.
    //
    // The check sits AFTER the rise refusal and BEFORE the write, in that order for a reason. A
    // count that would rise is the more specific finding and the one a reader can act on, so it
    // keeps its own message; everything else that is red is reported here, wholesale, and nothing
    // is written. The twin is `check()` rather than the write build, which would ask this branch
    // again.
    let ordinary = KindIsolationGate::check().run(cx);
    let red: Vec<String> = ordinary
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass)
        .map(|r| format!("{} ({})", r.id, r.title))
        .collect();
    if !red.is_empty() {
        return Row::fail(
            ROW_WRITE,
            "--write refuses: the gate is RED, and this flag does not re-pin a red tree",
            format!(
                "{} row(s) of the ordinary run are red; NOTHING was written. A count re-pinned \
                 while another rule is failing is a ledger that LOOKS reviewed and is not — and \
                 the row that would be lowered is not necessarily the row that is wrong. Fix the \
                 tree, then re-pin. Red: {}. Run `cargo xtask gate kind-isolation` for the \
                 findings themselves.",
                red.len(),
                red.join(", ")
            ),
        );
    }
    if down.is_empty() {
        return Row::pass(
            ROW_WRITE,
            "every count in the registry already equals what the tree measures",
            format!("{REGISTRY_FILE} is at the measurement; nothing to re-pin"),
        );
    }
    let text = match cx.read(REGISTRY_FILE) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_WRITE,
                "the registry file could not be read",
                format!("{e} — there is nothing to re-pin."),
            )
        }
    };
    let rewritten = rewrite_counts(&text, &repins);
    match std::fs::write(cx.abs(REGISTRY_FILE), &rewritten) {
        Ok(()) => Row::pass(
            ROW_WRITE,
            "every count that fell is re-pinned to what the tree measures",
            format!(
                "{} row(s) lowered in {REGISTRY_FILE}: {}",
                down.len(),
                down.iter()
                    .map(|r| format!("{} {} -> {}", r.label, r.was, r.now))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Err(e) => Row::fail(
            ROW_WRITE,
            "the registry file could not be written",
            format!("{e} — the re-pin was measured and not committed."),
        ),
    }
}

// ------------------------------------------------------------------------------------------------
// the gate
// ------------------------------------------------------------------------------------------------

/// The gate, in its two registrations.
///
/// `kind-isolation` owes the four rows the tree already satisfies — the name, the edge graph, the
/// vocabulary, the registry — and is BLOCKING on every push. `kind-isolation-ship` owes those four
/// AND the two SHIP-CRITERION rows: the per-kind surface and the per-kind conformance battery.
///
/// Two registrations rather than one gate with a `--strict` flag, and rather than one gate that is
/// red on every push: the ship criterion is a claim about the SHIP SHA, and the tree does not meet
/// it today (no kind states a `Unit` entry, no plane or transport kind has a shared battery, and
/// the plane skeletons diverge). A gate that is red on every push for a reason nobody can fix this
/// week is a gate somebody puts a `|| true` in front of, and then the four rows that ARE
/// enforceable stop being enforced too. So the ship rows are run by the release DONE oracle, on the
/// same terms as `plane-purity-strict` and `no-deferral-strict-done`, and the ratchet is that they
/// must reach zero before the tag.
pub struct KindIsolationGate {
    /// Owe and evaluate the two ship-criterion rows.
    ship: bool,
    /// `--write`: re-pin the registry's exact counts DOWNWARD, and refuse if any would rise.
    write: bool,
    /// THE SELF-TEST'S SUBJECT: this same gate with the unplanted tree's findings out of view,
    /// measured once, on the first `selftest` that asks. See [`debt_free`] — it is how a red case
    /// over a row that carries owned debt stays a proof rather than PROOF IMPOSSIBLE (item 89).
    twin: std::sync::OnceLock<Box<debt_free::DebtFree>>,
}

impl KindIsolationGate {
    /// The per-push gate: the four rows the tree holds today.
    pub fn check() -> KindIsolationGate {
        KindIsolationGate {
            ship: false,
            write: false,
            twin: std::sync::OnceLock::new(),
        }
    }

    /// The write arm. It is a SEPARATE construction rather than a flag read off the context inside
    /// `run`, so `owed` — which the reconciliation is written against — can say what this run emits.
    pub fn write() -> KindIsolationGate {
        KindIsolationGate {
            ship: false,
            write: true,
            twin: std::sync::OnceLock::new(),
        }
    }

    /// The release-time twin: the same four, plus the surface and battery criteria.
    pub fn ship() -> KindIsolationGate {
        KindIsolationGate {
            ship: true,
            write: false,
            twin: std::sync::OnceLock::new(),
        }
    }

    /// THE DEBT-FREE SUBJECT every planted case in [`Gate::selftest`] runs against — this gate, same
    /// configuration, with the findings the unplanted tree ALREADY reports taken out of view. The
    /// debt is measured once per gate value, on first use, so a battery pays for one extra run.
    fn debt_free(&self, cx: &Ctx) -> &debt_free::DebtFree {
        self.twin.get_or_init(|| {
            Box::new(debt_free::DebtFree::measure(
                KindIsolationGate {
                    ship: self.ship,
                    write: self.write,
                    twin: std::sync::OnceLock::new(),
                },
                cx,
            ))
        })
    }
}

impl Gate for KindIsolationGate {
    fn name(&self) -> &'static str {
        if self.ship {
            "kind-isolation-ship"
        } else {
            "kind-isolation"
        }
    }

    /// `write` DOES NOT SHOW IN THE NAME and it changes both the owed set and the verdict, so the
    /// baseline cache must be told about it or one arm would be handed the other's clean run.
    fn baseline_key(&self) -> Option<String> {
        Some(format!("{}:write={}", self.name(), self.write))
    }

    fn owed(&self) -> Vec<String> {
        // IN WRITE MODE THE GATE OWES ONE ROW AND EMITS ONE ROW. `--write` is not a verdict about
        // the tree, it is an edit to the ledger, and reconciling it against the ordinary owed set
        // would demand every rule re-run against a file this run is in the middle of moving.
        if self.write {
            return vec![ROW_WRITE.to_string()];
        }
        let mut owed = vec![
            ROW_NAME.to_string(),
            ROW_DEPS.to_string(),
            ROW_TEST_DEPS.to_string(),
            ROW_CLOSURE.to_string(),
            ROW_INPUTS.to_string(),
            ROW_FACES.to_string(),
            ROW_VOCAB.to_string(),
            ROW_REGISTRY.to_string(),
            ROW_STEPS.to_string(),
            ROW_WIRES.to_string(),
            ROW_TRUTHS.to_string(),
            ROW_MATRIX.to_string(),
        ];
        if self.ship {
            owed.push(ROW_DRAIN.to_string());
            owed.push(ROW_SHAPE.to_string());
            owed.push(ROW_TESTKIT.to_string());
            owed.push(ROW_CONTROL.to_string());
        }
        owed
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut crates = match census(cx) {
            Ok(c) => c,
            Err(e) => {
                let why = format!(
                    "{e} — the crate census is this gate's own input, and a census that did not \
                     read is not a census that found nothing wrong."
                );
                return Verdict::of(
                    self.owed()
                        .into_iter()
                        .map(|id| Row::fail(id, "the census did not run", why.clone()))
                        .collect(),
                );
            }
        };
        let (planes, ports) = vocabularies(&crates);
        assign_instances(&mut crates, &planes, &ports);

        // THE REGISTRY FILE IS AN INPUT, NOT AN OPTION. Three of the four rows read it, and a file
        // that did not read is not a file with nothing in it: an unreadable table would silently
        // turn the drain exemption into "every legacy edge is fine" and the announcement into
        // "every kind may be dead". So a read failure fails those three rows outright.
        let reg = match load_registry(cx) {
            Ok(reg) => reg,
            Err(e) => {
                let why = format!(
                    "{e} — {REGISTRY_FILE} holds the transitional drain exemptions and the \
                     announced landings, and a table that did not read is not a table that \
                     exempted nothing."
                );
                let mut rows: Vec<Row> =
                    [ROW_NAME, ROW_DEPS, ROW_CLOSURE, ROW_REGISTRY, ROW_MATRIX]
                        .into_iter()
                        .map(|id| Row::fail(id, "the kind registry file did not read", why.clone()))
                        .collect();
                rows.push(rule_vocab(cx, &crates, &planes));
                rows.push(rule_steps(cx, &crates));
                rows.push(rule_wires(cx, &crates));
                if self.ship {
                    rows.push(rule_control(cx, &crates));
                    rows.push(Row::fail(
                        ROW_SHAPE,
                        "the kind registry file did not read",
                        why.clone(),
                    ));
                    rows.push(Row::fail(
                        ROW_TESTKIT,
                        "the kind registry file did not read",
                        why,
                    ));
                }
                return Verdict::of(rows);
            }
        };

        if self.write {
            return Verdict::of(vec![rule_write(cx, &crates, &reg)]);
        }

        let mut rows = vec![
            rule_name(&crates, &planes, &ports, &reg),
            rule_deps(cx, &crates, &reg, Half::Shipped, self.ship),
            rule_deps(cx, &crates, &reg, Half::Test, self.ship),
            // #40(a) IS A CLOSURE, AND UNTIL THIS ROW NOTHING HERE COMPUTED ONE. See [`closure`].
            closure::rule_closure(cx, &crates),
            inputs::rule_inputs(cx, &crates, &planes, &reg),
            rule_vocab(cx, &crates, &planes),
            rule_registry(cx, &crates, &reg, self.ship),
            rule_steps(cx, &crates),
            rule_wires(cx, &crates),
            truths::rule_truths(cx, &kind_names(), &crates),
            matrix::rule_matrix(cx, &crates, &reg, self.ship),
        ];
        // THE SOURCE INDEX IS BUILT FOR BOTH REGISTRATIONS NOW. It was the ship twin's private
        // input, because the two rows that read it are ship criteria — but `:faces` is not a ship
        // criterion. A wire that implements `Plane` is a plane at the type level on the commit that
        // lands it, and a rule that only says so at release time is a rule that says so too late.
        match index_sources(cx) {
            Ok(idx) => {
                rows.push(rule_faces(&crates, &idx, &reg, self.ship));
                if self.ship {
                    rows.push(rule_shape(&crates, &idx));
                    rows.push(rule_testkit(&crates, &idx));
                }
            }
            Err(e) => {
                let why = format!(
                    "{e} — the source index is these rows' own input, and an index that did not \
                     read is not an index that found nothing wrong."
                );
                rows.push(Row::fail(
                    ROW_FACES,
                    "the source index did not run",
                    why.clone(),
                ));
                if self.ship {
                    rows.push(Row::fail(
                        ROW_SHAPE,
                        "the source index did not run",
                        why.clone(),
                    ));
                    rows.push(Row::fail(ROW_TESTKIT, "the source index did not run", why));
                }
            }
        }
        if self.ship {
            rows.push(rule_drain(&crates, &reg));
            rows.push(rule_control(cx, &crates));
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE WRITE ARM PROVES ITSELF WITHOUT WRITING ANYTHING, and that is not a compromise: the
        // two claims it makes are exactly the two paths that write nothing. "Already at the
        // measurement" returns before the file is opened, and "a count would RISE" is a REFUSAL —
        // wholesale, so a run that grew a coupling cannot be handed back a file that looks
        // reviewed. The third path, the one that lowers, is the one a self-test must not take over
        // the real tree, because a battery that edits the ledger it is proving is a battery that
        // makes itself pass.
        if self.write {
            report.push(prove_rows_green(
                cx,
                self,
                "every count already equals the measurement, so --write writes nothing",
                &[ROW_WRITE],
                Overlay::new(),
            ));
            report.push(plant_registry(
                cx,
                self,
                "--write refuses wholesale when any count would RISE",
                &[ROW_WRITE],
                matrix::cell_subst(cx, "busbar-kernel", "plane", "0"),
                &[
                    "would RISE",
                    "NOTHING was written",
                    // THE CELL AND THE CEILING THIS PLANT WROTE, not the measurement beside them.
                    // A fixture cannot know what the tree measures without running the gate, and
                    // the number that used to be here (`0 -> 1`) was a measurement copied out of a
                    // ratchet that has since re-pinned it to four figures.
                    "busbar-kernel × plane 0 ->",
                ],
            ));
            // …AND THE WRITE ARM MEASURES THE WHOLE GATE BEFORE IT WRITES ANYTHING. It did not:
            // `owed()` returned one row in write mode and `run` returned one row, so
            // `gate kind-isolation --write` ran the re-pin and NOTHING ELSE. A red team put plane
            // words in a transport's `lib.rs` — a tree the ordinary run reds three ways — and got
            // `PASS kind-isolation:write … 1 row(s), green` and `EXIT=0` out of the same binary.
            // Every rule this gate has, one flag away. The plant is that tree.
            report.push(plant_registry(
                cx,
                self,
                "--write refuses on a tree the ordinary run reds, whatever the counts would do",
                &[ROW_WRITE],
                verdict_subst(cx, "busbar-transport-tls", "busbar-unit-transport-key"),
                &[
                    "the gate is RED",
                    "NOTHING was written",
                    "kind-isolation:deps",
                ],
            ));
            return report;
        }

        // THE UNPLANTED ARM, ON THE REAL GATE AND THE REAL TREE — narrowed to the rows that are
        // green on it. The rows in [`STANDING_DEBT_ROWS`] carry owned debt today (stale ledger rows,
        // unlisted edges, closure breaches, the kind table's dead entries — drained in Phase 4,
        // items 92/94) and stay RED on `cargo xtask gate kind-isolation`; asserting them green here
        // was a case that could only fail, and it failed on every run. Their proofs moved onto the
        // DEBT-FREE subject below instead, which is where a green -> red transition CAN be asked.
        //
        // On the ship twin the rows red BY DESIGN leave this arm too (`:deps`, `:shape`, `:testkit`
        // carry the transitional/ship criteria whose whole claim is about the ship SHA).
        let unplanted: &[&str] = if self.ship {
            &[ROW_NAME, ROW_VOCAB, ROW_STEPS, ROW_WIRES]
        } else {
            &[
                ROW_NAME, ROW_INPUTS, ROW_VOCAB, ROW_STEPS, ROW_WIRES, ROW_TRUTHS, ROW_FACES,
            ]
        };
        debug_assert!(unplanted.iter().all(|r| !STANDING_DEBT_ROWS.contains(r)));
        report.push(prove_rows_green(
            cx,
            self,
            if self.ship {
                "the real tree keeps its plugin kinds apart (the enforceable rows)"
            } else {
                "the real tree keeps its plugin kinds apart (every row not carrying owned debt)"
            },
            unplanted,
            Overlay::new(),
        ));

        // EVERY CASE BELOW RUNS AGAINST THE DEBT-FREE SUBJECT. See [`debt_free`]: the shipped gate,
        // unchanged, with the findings the unplanted tree already reports taken out of view under
        // both halves of each proof. On a row with no debt it is the shipped gate exactly.
        let subject: &'a dyn Gate = self.debt_free(cx);

        // THE RULING ITSELF, PLANTED. `busbar-transport-a2a` is the crate the owner refused, and
        // this is the fixture that proves the refusal is mechanical.
        report.push(prove_rows_red(
            cx,
            subject,
            "the refused `busbar-transport-a2a` — a kind fused with another kind's instance",
            &[ROW_NAME],
            manifest_plant("crates/busbar-transport-a2a", "busbar-transport-a2a", &[]),
            &["busbar-transport-a2a", "a2a", MAKE_A_NEW_KIND],
        ));

        // THE OTHER TWO DIRECTIONS of the same rule.
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane named after a transport instance (`busbar-plane-http`)",
            &[ROW_NAME],
            manifest_plant("crates/busbar-plane-http", "busbar-plane-http", &[]),
            &["busbar-plane-http", "http"],
        ));
        report.push(prove_rows_red(
            cx,
            subject,
            "a unit named after a plane instance (`busbar-unit-mcp`)",
            &[ROW_NAME],
            manifest_plant("crates/busbar-unit-mcp", "busbar-unit-mcp", &[]),
            &["fused-instance-name", "busbar-unit-mcp", "mcp"],
        ));

        // THE WAIVER LIST CANNOT REACH THE FUSION, and this is the case a red team landed against
        // the old rule: `crates/busbar-unit-llm` plus ONE `ACCEPTED_NAMES` line produced
        // `kind-isolation: green` AND `--selftest: the gate is proven RED-able` in the same breath,
        // because the waiver loop protected only the six names the battery happened to plant.
        // `busbar-transport-a2a` was safe for a reason that does not generalise — `transport` HAS
        // an instance vocabulary, so that crate's own name made `a2a` a transport instance and the
        // collision was visible one level up as `fused-instance`. `unit` is NEUTRAL and collides
        // with nothing.
        //
        // The refusal is now structural: a remainder that IS another kind's instance is reported
        // before the waiver map is consulted, so no reviewed sentence — existing or added — reaches
        // it. What a waiver may still excuse is a QUALIFIER: `busbar-auth-admin-tokens` is the
        // admin surface's token issuer, its last segment says what it is, and the unplanted green
        // arm above holds that distinction on the real tree.
        report.push(prove_rows_red(
            cx,
            subject,
            "no reviewed sentence can waive a crate whose whole name is another kind's instance",
            &[ROW_NAME],
            manifest_plant("crates/busbar-unit-llm", "busbar-unit-llm", &[]),
            &[
                "fused-instance-name",
                "busbar-unit-llm",
                "a waiver excuses a QUALIFIER, never a fusion",
            ],
        ));

        // A WAIVER EXCUSES ITS OWN NAME, NOT THE SHORTER ONE. Shorten the one reviewed name,
        // `busbar-unit-transport-key`, to `busbar-unit-transport` and the qualifier is gone: what is
        // left is a unit named for another kind's marker and nothing else. The waiver beside it does
        // not move — the waived crate stays in the tree, its sentence stays in `ACCEPTED_NAMES` —
        // and the shortened crate is refused anyway.
        //
        // RE-TARGETED (item 89): this case used to shorten `busbar-auth-admin-tokens` to
        // `busbar-auth-admin`, whose `admin` was a PLANE instance while `busbar-plane-admin`
        // existed. That crate folded into `busbar-core-admin`, `admin` names no instance any more,
        // `busbar-auth-admin-tokens` carries no waiver any more, and the plant came back GREEN — a
        // proof about a tree that is gone. The claim is the same; the subject is the waiver that
        // still stands.
        report.push(prove_rows_red(
            cx,
            subject,
            "shortening a waived name to the fusion form is refused with the waiver still standing",
            &[ROW_NAME],
            manifest_plant("crates/busbar-unit-transport", "busbar-unit-transport", &[]),
            &[
                "busbar-unit-transport\tcrates/busbar-unit-transport",
                "the marker word of kind `transport`",
            ],
        ));

        // THE PLANE-TRANSPORT the ruling names by name: two KIND words, no instance at all.
        report.push(prove_rows_red(
            cx,
            subject,
            "`busbar-plane-transport` — two kind words in one name",
            &[ROW_NAME],
            manifest_plant(
                "crates/busbar-plane-transport",
                "busbar-plane-transport",
                &[],
            ),
            &["busbar-plane-transport", "transport"],
        ));

        // THE SCHEME'S OWN WIDTH. Five segments is a name describing the crate instead of naming
        // its kind (four segments is the widest an accepted name reaches, e.g.
        // `busbar-unit-transport-key`).
        report.push(prove_rows_red(
            cx,
            subject,
            "a five-segment name is refused whatever kind it claims",
            &[ROW_NAME],
            manifest_plant(
                "crates/busbar-plane-llm-openai-chat",
                "busbar-plane-llm-openai-chat",
                &[],
            ),
            &["5 segments", "busbar-<kind>-<name>"],
        ));

        // A WAIVER THAT COVERS NOTHING IS RED.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-unit-transport-key/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            subject,
            "an accepted-name waiver whose crate is gone is reported dead",
            &[ROW_NAME],
            ov,
            &["dead-waiver", "busbar-unit-transport-key"],
        ));

        // AN EDGE NOBODY WROTE DOWN. A plane reaching a transport is the fusion done through
        // Cargo instead of through a name — and the row it needs is the INSTANCE, so the finding
        // names both crates and not only the pair of kind words.
        //
        // The case is asked of the PER-PUSH gate only: the ship twin does not read the ledger, and
        // `:deps` is red there whatever this plant does.
        if !self.ship {
            report.push(prove_rows_red(
                cx,
                subject,
                "a plane growing a dependency on a transport is an edge nobody wrote down",
                &[ROW_DEPS],
                manifest_plant(
                    "crates/busbar-plane-mcp",
                    "busbar-plane-mcp",
                    &["busbar-contract", "busbar-transport-http"],
                ),
                &[
                    "unlisted-dep-edge",
                    "plane -> transport",
                    "busbar-plane-mcp -> busbar-transport-http",
                ],
            ));
        }

        // THE SAME REACH OUT OF A CLEANLINESS SURFACE, AND INTO ONE — scored by the measured graph.
        //
        // These two cases asserted `control-sink` and `plane-control`, two refusals that went with
        // the `control` kind (DECISIONS #4/#5; see the note in `rule_deps`). Nothing emits either
        // needle, so both cases proved a rule that is not there. What REPLACED them is that a
        // `cleanliness` crate's edges are rows of the measured graph like every other Neutral
        // kind's: an edge between a cleanliness surface and a wire or a plane that no `[[dep]]` row
        // names is `unlisted-dep-edge`, and that is the behaviour these cases now prove. Per-push
        // only, for the reason on the case above.
        if !self.ship {
            report.push(prove_rows_red(
                cx,
                subject,
                "a cleanliness surface depending on a transport crate is an edge nobody wrote down",
                &[ROW_DEPS],
                cleanliness_reaches_wire(),
                &[
                    "unlisted-dep-edge",
                    "cleanliness -> transport",
                    "busbar-oauth2 -> busbar-transport-http",
                ],
            ));
            report.push(prove_rows_red(
                cx,
                subject,
                "a plane depending on a cleanliness surface is an edge nobody wrote down",
                &[ROW_DEPS],
                plane_reaches_cleanliness(),
                &[
                    "unlisted-dep-edge",
                    "plane -> cleanliness",
                    "busbar-plane-mcp -> busbar-oauth2",
                ],
            ));
        }

        // A CLEANLINESS SURFACE MAY NAME A PRICE. The money-vocabulary ban was a `control`-kind
        // rule and it retired with the kind (DECISIONS #5, and the note in `rule_vocab`): admin and
        // oauth2 are served surfaces that legitimately report on cost and usage. The red case that
        // asserted a `MONEY` finding here could never fire; the behaviour that replaced it is the
        // ABSENCE of the ban, and that is what is proven — a cleanliness crate naming the
        // plane-no-money vocabulary leaves `:vocab` green.
        report.push(prove_rows_green(
            cx,
            subject,
            "a cleanliness surface naming money symbols is not a vocabulary finding",
            &[ROW_VOCAB],
            cleanliness_names_money(),
        ));

        // TWO CLEANLINESS SURFACES, ONE ROUTE. The claim table is DATA, which is the only reason
        // this is checkable at all: each surface's prefix is a list of literal segments in its own
        // `src/claims.rs`, not a string a handler builds. The rule read the retired `control` kind,
        // which no crate resolves to, so it compared nothing; it reads the kind that succeeded it.
        report.push(prove_rows_red(
            cx,
            subject,
            "two cleanliness surfaces claiming the same route",
            &[ROW_REGISTRY],
            cleanliness_shared_route(),
            &["shared-route", "busbar-admin", "busbar-oauth2"],
        ));

        // THE REGISTRATION EXPIRES WITH THE RENAME IT WAS WRITTEN FOR. Land `busbar-admin` and a
        // `[[registered]]` row saying it is `cleanliness` says what the name already says; the gate
        // asks for it to be struck in the same commit rather than left standing as a list nobody
        // reads. The row's kind is one the table HAS: a `control` row is refused at load as
        // `unknown-kind`, one layer before this arm, which is why the arm had no working proof.
        report.push(prove_rows_red(
            cx,
            subject,
            "a registration whose crate name already says its kind is redundant",
            &[ROW_REGISTRY],
            redundant_registration(),
            &["redundant-registration", "busbar-admin"],
        ));

        // A MANIFEST WHOSE `[package]` HEADER IS NOT BYTE-EXACT IS STILL A CRATE.
        //
        // `in_package = t == "[package]"` was a five-byte equality, and a red team took the whole
        // census with it TWICE. `crates/busbar-plane-shadow` with `[package] # internal`, listed in
        // `[workspace.members]`, path-depended by `busbar-transport-tcp` and confirmed by
        // `cargo metadata` to be in the wire's shipped graph, produced `kind-isolation: 11 row(s),
        // green`. Then the same crate again with a UTF-8 BOM instead of the comment — a byte an
        // editor writes without being asked. Nothing downstream saw either: no kind, no needles, no
        // cell, and no entry in `by_name`, which is the filter the `Cargo.lock` cross-check is
        // itself keyed on. Both spellings are now normalised, and both are proven here.
        for (label, header) in [
            ("a trailing comment", "[package] # internal"),
            ("a UTF-8 BOM", "\u{feff}[package]"),
        ] {
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-plane-shadow/Cargo.toml",
                format!("{header}\nname = \"busbar-plane-shadow\"\nversion = \"0.0.0\"\n"),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                format!("a `[package]` header carrying {label} is still a crate of the census"),
                &[ROW_REGISTRY],
                ov,
                &["busbar-plane-shadow", "unmembered"],
            ));
        }

        // …AND A MANIFEST THE CENSUS CANNOT NAME IS A FINDING, NEVER A `continue`. Normalising the
        // two spellings above fixes the spellings somebody has already thought of; this is the
        // refusal for the ones they have not. A file that declares dependencies and yields no
        // package name is a crate this gate cannot score, and a crate it cannot score is reported.
        let mut ov = Overlay::new();
        ov.set(
            "crates/zz-planted-nameless/Cargo.toml",
            "[pack age]\nname = \"busbar-plane-nameless\"\n\n[dependencies]\nbusbar-plane-llm = \
             { path = \"../busbar-plane-llm\" }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a manifest with dependency tables and no readable package name is a FINDING",
            &[ROW_REGISTRY],
            ov,
            &[
                "nameless-manifest",
                "crates/zz-planted-nameless/Cargo.toml",
                "cannot be named is not a crate that was found clean",
            ],
        ));

        // A FIXTURE DIRECTORY IS NOT A PLACE TO KEEP A LIVE CRATE. `OFF_TREE_MANIFESTS` carries a
        // whole-directory entry for `xtask/fixtures/`, and "excused from the census" was read by
        // every rule as "invisible": a red team put `xtask/fixtures/wire-bridge`, whose `lib.rs` is
        // `pub use busbar_plane_llm::*;`, into a transport's `[dependencies]` and SIX gates stayed
        // green. The exemption is one-directional from here on.
        let mut ov = Overlay::new();
        ov.set(
            "xtask/fixtures/wire-bridge/Cargo.toml",
            "[package]\nname = \"wire-bridge\"\nversion = \"0.0.0\"\n\n[dependencies]\n\
             busbar-plane-llm = { path = \"../../../crates/busbar-plane-llm\" }\n",
        );
        ov.set(
            "crates/busbar-transport-tcp/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-transport-tcp/Cargo.toml",
                "[dependencies]\nwire-bridge = { path = \"../../xtask/fixtures/wire-bridge\" }\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a product crate path-depending on an OFF-TREE manifest is refused",
            &[ROW_REGISTRY],
            ov,
            &[
                "off-tree-reached",
                "xtask/fixtures/wire-bridge",
                "busbar-transport-tcp",
            ],
        ));

        // …AND A REGISTRATION FOR A CRATE THAT IS NOT THERE IS A KIND ASSIGNMENT FOR NOTHING. The
        // row names a kind the table HAS: a `control` row is refused at load as `unknown-kind`
        // before this arm reads it, so a plant spelled that way names the kind and never the crate.
        report.push(prove_rows_red(
            cx,
            subject,
            "a registration naming a crate the tree does not have",
            &[ROW_REGISTRY],
            dead_registration(),
            &["dead-registration", "busbar-ghost-registered"],
        ));

        // ONE PLANE REACHING INTO ANOTHER PLANE'S HALF.
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane depending on another plane's codec is cross-instance",
            &[ROW_DEPS],
            // RE-TARGETED (item 89): this planted `busbar-plane-llm -> busbar-llm-codec`, which is
            // the llm plane reaching its OWN codec — the same instance, never cross-instance — and
            // the plant came back GREEN once the row's standing debt stopped hiding it. The claim
            // is one plane reaching ANOTHER plane's half, so the plane is `mcp`.
            manifest_plant(
                "crates/busbar-plane-mcp",
                "busbar-plane-mcp",
                &["busbar-contract", "busbar-llm-codec"],
            ),
            &["cross-instance", "busbar-plane-mcp"],
        ));

        // #40(a) IS A CLOSURE, AND THE PROOF OF THAT IS A CRATE THAT NAMES NOTHING WRONG.
        //
        // The plant is TWO HOPS: `busbar-transport-ws` grows an edge on `busbar-transport-http`,
        // and `busbar-transport-http` grows one on `busbar-kernel-ledger`. NO MANIFEST OF
        // `busbar-transport-ws` NAMES THE LEDGER. `:deps` is per-declaration and reports only what
        // each manifest wrote, so the one thing it cannot say is the thing #40(a) is about, and
        // `closure-breach busbar-transport-ws -> busbar-kernel-ledger` is that thing said.
        //
        // THIS CASE USED TO REPORT `Impossible`: `:closure` is STANDING RED here (plugin crates
        // breach the wall today) and the transition could not be shown while the tree carried the
        // debt. It runs against the DEBT-FREE subject now (item 89), where the breaches the tree
        // already has are out of view and only the planted two-hop breach can turn the row. The
        // rule is unchanged; DO NOT weaken it to make the real tree green.
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate two hops away is in the closure, and no manifest of the plugin names it",
            &[closure::ROW_CLOSURE],
            {
                let mut ov = manifest_plant(
                    "crates/busbar-transport-ws",
                    "busbar-transport-ws",
                    &["busbar-contract", "busbar-transport-http"],
                );
                ov.set(
                    "crates/busbar-transport-http/Cargo.toml",
                    "[package]\nname = \"busbar-transport-http\"\nversion = \"0.0.0\"\n\n                     [dependencies]\nbusbar-contract = { workspace = true }\n                     busbar-kernel-ledger = { workspace = true }\n",
                );
                ov
            },
            &[
                "closure-breach",
                "busbar-transport-ws -> busbar-kernel-ledger",
                "TRANSITIVE, 2 hops",
                "busbar-transport-ws -> busbar-transport-http | busbar-transport-http -> busbar-kernel-ledger",
            ],
        ));

        // The dialect-direction case retired with the `dialect` kind (DECISIONS #4): a dialect is a
        // thing inside a plane, not a crate, so there is no `busbar-plane-<plane>-<dialect>` edge for
        // a plane to name back and no `plane-names-dialect` refusal to prove.

        // THE LEDGER CASES BELONG TO THE PER-PUSH GATE ALONE. Every one is about the `[[dep]]`
        // rows in the registry file, and the SHIP twin does not read them: it owes the
        // ARCHITECTURE'S graph, so planting a raised row against it would produce the same red it
        // already produces, and "the gate went red" is the answer this battery exists to refuse.
        // The twin owes its own two cases, which make NAMED, NEW deviations — see below.
        if !self.ship {
            // A DEAD ROW. Strip the edges `busbar-contract` declares and every row that covered one
            // is reported as the line it has become. This is the half of the ratchet that TIGHTENS:
            // the landing that deletes the dependency is the landing that deletes the row, and the
            // gate is red until it does.
            report.push(prove_rows_red(
                cx,
                subject,
                "an edge instance no crate has any more is reported as a dead allowance",
                &[ROW_DEPS],
                // RE-TARGETED (item 89): the subject was `busbar-contract -> busbar-grammar`, a row
                // that is ALREADY dead on this tree (the grammar crate folded away) — so the plant
                // produced the tree's own standing finding and proved nothing. `busbar-kernel ->
                // busbar-contract` is a live row; stripping the kernel's edges kills it.
                manifest_plant("crates/busbar-kernel", "busbar-kernel", &[]),
                &[
                    "dead-dep-edge",
                    "busbar-kernel -> busbar-contract",
                    "Strike the row",
                ],
            ));

            // A SECTION HEADER THIS READER CANNOT PARSE IS A REFUSAL, NOT A SKIP. The dotted-key
            // form sits under no `[section]` at all: `:deps` never saw it, and the only net that
            // did was the `Cargo.lock` cross-check, which is itself census-gated.
            report.push(prove_rows_red(
                cx,
                subject,
                "a dotted-key dependency table is reported, not skipped",
                &[ROW_DEPS],
                {
                    let mut ov = Overlay::new();
                    ov.set(
                        "crates/busbar-transport-tcp/Cargo.toml",
                        manifest_plus(
                            cx,
                            "crates/busbar-transport-tcp/Cargo.toml",
                            "target.\"cfg(unix)\".dependencies.wire = { path = \
                             \"../busbar-plane-llm\" }\n",
                        ),
                    );
                    ov
                },
                &["unreadable-manifest", "DOTTED KEY", "busbar-transport-tcp"],
            ));

            // …AND A COMMENTED HEADER IS THE HEADER IT SAYS IT IS. `[target.'cfg(all())'
            // .dependencies] # extra` did not end in `]`, so the reader stayed in the PREVIOUS
            // section and filed a plane linked into a wire as a DEV-dependency — the wrong half of
            // the build graph, on the strength of a comment. The needle is `shipped`.
            report.push(prove_rows_red(
                cx,
                subject,
                "a table header with a trailing comment is the table it names, in the right half",
                &[ROW_DEPS],
                {
                    let mut ov = Overlay::new();
                    ov.set(
                        "crates/busbar-transport-tcp/Cargo.toml",
                        manifest_plus(
                            cx,
                            "crates/busbar-transport-tcp/Cargo.toml",
                            "[target.'cfg(all())'.dependencies] # extra\nbusbar-plane-llm = { path \
                             = \"../busbar-plane-llm\" }\n",
                        ),
                    );
                    ov
                },
                &[
                    "busbar-transport-tcp -> busbar-plane-llm",
                    "is a shipped edge",
                ],
            ));

            // THE LEDGER IS THE EVIDENCE, NEVER THE JUDGE — the case the red team landed.
            //
            // A real `busbar-transport-tcp -> busbar-plane-llm` path dependency, which is a plane
            // compiled into a wire and the exact fusion this gate exists to make impossible, plus
            // nine ledger lines that say out loud `verdict = "not-allowed"` and one `[[cell]]`
            // count, produced `kind-isolation: 10 row(s), green`. Every rule was satisfied, because
            // every rule's question was "does a row match?" and a row did. The row was honest and
            // it was still the bypass.
            //
            // The plant here is exactly that: the edge AND the row that describes it perfectly.
            // What it must not buy is admissibility.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tcp/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tcp/Cargo.toml",
                    "[dependencies]\nbusbar-plane-llm = { path = \"../busbar-plane-llm\" }\n",
                ),
            );
            ov.set(
                REGISTRY_FILE,
                format!(
                    "{}\n\n[[dep]]\nfrom    = \"busbar-transport-tcp\"\nto      = \
                     \"busbar-plane-llm\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \
                     \"not-allowed\"\ncite    = \"planted by the self-test\"\nwhy     = \"the wire \
                     needs the plane's frame type\"\ndrain   = \"move the frame type into the \
                     contract\"\n",
                    cx.read(REGISTRY_FILE).unwrap_or_default().trim_end()
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a `[[dep]]` row may RECORD a not-allowed edge, never INTRODUCE one",
                &[ROW_DEPS],
                ov,
                &[
                    "new-forbidden-edge",
                    "busbar-transport-tcp -> busbar-plane-llm",
                    "never introduce one",
                ],
            ));

            // A NEGATIVE COUNT IS A PER-CELL OFF SWITCH, and it is refused where every other
            // unreadable value is: at load. `-1` parses as a number, so `bad-count` let it through,
            // and the exact-both-directions comparison then SKIPPED the cell — one character
            // turning off one crate × kind's ratchet, with nothing anywhere saying so.
            report.push(plant_registry(
                cx,
                subject,
                "a negative `[[cell]]` count is refused at load — it is not a ceiling, it is the \
                 absence of one",
                &[ROW_DEPS],
                matrix::cell_subst(cx, "busbar", "contract", "-1"),
                &[
                    "bad-count",
                    "is negative",
                    "No measurement is ever below zero",
                ],
            ));

            // `to = "*"` IS A LEGAL TRAILING GLOB AND A BLANKET AMNESTY. `covers` does
            // `dep.starts_with("")`, which is true of every crate in the tree: one character turns
            // the drain's exemption into permission for every legacy -> unit, legacy -> plane,
            // legacy -> dialect and legacy -> transport edge there will ever be.
            report.push(plant_registry(
                cx,
                subject,
                "a `[[transitional]]` glob that covers more than one kind's prefix is refused",
                &[ROW_DEPS],
                transitional_anchor(cx)
                    .map(|(from, to)| (format!("{from}\n{to}"), format!("{from}\nto = \"*\""))),
                &[
                    "bad-glob",
                    "covers EVERY crate in the tree",
                    "busbar-<kind>-*",
                ],
            ));

            // A ROW THAT LEFT SLACK. The other half of the ratchet, and the one a class table could
            // never hold: a count BELOW the measurement is drift nobody drained on the commit that
            // drained the edge.
            report.push(plant_registry(
                cx,
                subject,
                "a dependency row left above the count it measures — stale slack is how drift hides",
                &[ROW_DEPS],
                dep_subst(cx, "busbar-kernel", "busbar-contract", "9"),
                &[
                    "dep-ratchet",
                    "busbar-kernel -> busbar-contract",
                    "STALE SLACK",
                ],
            ));

            // A ROW THAT GRANTED ITSELF AN EDGE THE ARCHITECTURE WITHHOLDS. `allowed` is a READING
            // of ARCHITECTURE.md, not an opinion a ledger row is entitled to hold — otherwise the
            // ledger IS the architecture and the ratchet loosens by editing one word.
            report.push(plant_registry(
                cx,
                subject,
                "a ledger row cannot grant itself an edge the architecture withholds",
                &[ROW_DEPS],
                verdict_subst(cx, "busbar-transport-tls", "busbar-unit-transport-key"),
                &[
                    "unsupported-verdict",
                    "busbar-transport-tls -> busbar-unit-transport-key",
                    "cannot grant an edge the architecture withholds",
                ],
            ));

            // AN UNRULED EDGE OWES ITS QUESTION. Thirteen edges match no clause in either
            // direction; they are neither granted nor refused today, and the whole point of writing
            // them down is that the owner can rule by reading this file. A pending row whose
            // question is gone has stopped asking, and an unruled edge that has stopped asking is
            // an edge that passes by being unreadable.
            report.push(plant_registry(
                cx,
                subject,
                "an unruled edge whose question was struck out has stopped asking",
                &[ROW_DEPS],
                Ok((
                    "from     = \"busbar-substrate-values\"\nto       = \"busbar-plugin\"\n"
                        .to_string(),
                    "from     = \"busbar-substrate-values\"\nto       = \"busbar-plugin-struck\"\n"
                        .to_string(),
                )),
                &[
                    "unasked-question",
                    "busbar-substrate-values -> busbar-plugin",
                ],
            ));

            // TWO ROWS FOR ONE EDGE. Two numbers for one measurement, and the one a reader believes
            // is the one nobody checked.
            report.push(plant_registry(
                cx,
                subject,
                "two rows for one edge is two numbers for one measurement",
                &[ROW_DEPS],
                dep_anchor(cx, "busbar-kernel", "busbar-contract").map(|anchor| {
                    (
                        "[[dep]]\nfrom    = \"busbar-kernel\"\nto      = \"busbar-contract\""
                            .to_string(),
                        format!(
                            "[[dep]]\n{anchor}\nverdict = \"allowed\"\ncite    = \"x\"\nwhy     = \"x\"\ndrain   = \"x\"\n\n[[dep]]\nfrom    = \"busbar-kernel\"\nto      = \"busbar-contract\""
                        ),
                    )
                }),
                &["duplicate-dep", "busbar-kernel -> busbar-contract"],
            ));

            // A ROW WITH A NUMBER AND NO SENTENCE IS A BUDGET — refused at LOAD, by the same reader
            // that refuses a `[[cell]]` with half a sentence.
            report.push(plant_registry(
                cx,
                subject,
                "a dependency row whose citation was emptied is refused at load",
                &[ROW_DEPS],
                dep_anchor(cx, "busbar-kernel", "busbar-contract").map(|anchor| {
                    (
                        format!("{anchor}\nverdict = \"allowed\"\ncite    = \""),
                        format!("{anchor}\nverdict = \"allowed\"\ncite    = \"\"\nunused  = \""),
                    )
                }),
                &["empty-field", "cite"],
            ));
        }

        // A GRANTED EDGE IS STILL AN EDGE THAT MUST BE WRITTEN DOWN — outside the #40 wall.
        //
        // RE-TARGETED (SHA-KI): the subject was `busbar-export-planted -> busbar-contract`, and that
        // edge is no longer a ledger instance at all — #40(a) grants every plugin kind its contract
        // edge as the RULE ([`is_the_wall`]), so the case proved a finding the architecture forbids
        // the gate to make. The claim it carried is unchanged and still true of every OTHER granted
        // class, so it is asked of one: a kernel workflow crate naming the contract (`kernel ->
        // contract`, granted) still owes its `[[dep]]` row.
        //
        // The case is asked of the PER-PUSH gate only, for the reason the ship twin's own arm is
        // narrowed: on the ship sha `:deps` also carries the transitional ratchet, and every legacy
        // crate is still here, so the row is red there whatever this plant does.
        if !self.ship {
            report.push(prove_rows_red(
                cx,
                subject,
                "an edge the architecture grants is still an edge that must be written down",
                &[ROW_DEPS],
                manifest_plant(
                    "crates/busbar-kernel-planted",
                    "busbar-kernel-planted",
                    &["busbar-contract"],
                ),
                &[
                    "unlisted-dep-edge",
                    "busbar-kernel-planted -> busbar-contract",
                    "kernel -> contract",
                ],
            ));

            // THE #40 WALL, BOTH WAYS. A plugin-kind crate whose one dependency is busbar-contract
            // IS DECISIONS #40(a) — `hooks -> contract` was scored `new-forbidden-edge` plus an
            // unlisted `[[dep]]`, `[[cell]]` and `[[edge]]` the day `busbar-hooks-ranking` was
            // repointed at the contract, for doing exactly what the wall asks. GREEN on the shipped
            // graph, the test graph and the vocabulary matrix alike, with a source file that names
            // the contract the way every plugin does. And the same crate reaching `busbar-plugin` is
            // RED: the wall is one crate wide, not "the contract plus whatever else".
            report.push(prove_rows_green(
                cx,
                subject,
                "a plugin-kind crate whose one dependency is busbar-contract is the #40 wall, not \
                 an edge to write down",
                &[ROW_DEPS, ROW_TEST_DEPS, ROW_MATRIX],
                the_wall_plant(&[]),
            ));
            report.push(prove_rows_red(
                cx,
                subject,
                "a plugin-kind crate reaching busbar-plugin reaches past the #40 wall",
                &[ROW_DEPS],
                the_wall_plant(&["busbar-plugin"]),
                &[
                    "busbar-hooks-planted -> busbar-plugin",
                    "hooks -> plugin-abi",
                ],
            ));

            // THE ROOT LINKS A PLUGIN, AND THAT IS ROSTER DEFINITION 1, NOT A COUPLING. The
            // composition root is "the only place that names which crates exist and wires them at
            // boot" (ARCHITECT 2026-09-25 "K5d residue"), so `root -> <plugin kind>` is a granted
            // class: K5d moved the ranking hooks onto the root's linked tables and the edge was
            // scored `new-forbidden-edge`, the root doing its job. A fresh hooks plugin (the #40
            // wall plant) linked by `busbar`, with the `[[dep]]` row every granted edge still owes,
            // is GREEN on `:deps` — no forbidden-edge, no unsupported verdict.
            let mut ov = the_wall_plant(&[]);
            ov.set(
                "crates/busbar/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar/Cargo.toml",
                    "[dependencies.busbar-hooks-planted]\npath = \"../busbar-hooks-planted\"\n",
                ),
            );
            ov.set(
                REGISTRY_FILE,
                planted_dep_row(cx, "busbar", "busbar-hooks-planted"),
            );
            report.push(prove_rows_green(
                cx,
                subject,
                "the composition root linking a plugin-kind crate is a granted class (roster def 1)",
                &[ROW_DEPS],
                ov,
            ));

            // …AND THE GRANT IS THE ROOT'S ALONE. A NON-root crate naming a plugin crate, with a
            // row that borrows the root's citation and says `allowed`, is still refused: the class
            // `kernel -> hooks` is granted nowhere, so the row's verdict is unsupported and the
            // edge is new. Roster def 1 names ONE place that wires plugins; a second is a fusion.
            let mut ov = manifest_plant(
                "crates/busbar-kernel-planted",
                "busbar-kernel-planted",
                &["busbar-hooks-ranking"],
            );
            ov.set(
                REGISTRY_FILE,
                planted_dep_row(cx, "busbar-kernel-planted", "busbar-hooks-ranking"),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a non-root crate reaching a plugin crate is refused whatever its row claims",
                &[ROW_DEPS],
                ov,
                &[
                    "unsupported-verdict",
                    "busbar-kernel-planted -> busbar-hooks-ranking",
                    "kernel -> hooks",
                ],
            ));
        }

        // THE MANIFEST-SPELLING CASES READ THE LEDGER TOO — every one asks for the finding a
        // MISSING `[[dep]]` row produces — so they belong to the per-push gate, on the same
        // terms as the rest of the ledger battery.
        if !self.ship {
            // THE FIVE SPELLINGS THE ONE-SECTION READER COULD NOT SEE. Every one of these was planted
            // in the real tree by a red-team pass and left every gate GREEN; every one is a plane
            // linked into a transport. See [`crate::manifest`] for the reading that closes them.

            // A BUILD-DEPENDENCY IS A SHIPPED EDGE: the build script runs, and what it links is
            // compiled into the making of the artifact.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tls/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tls/Cargo.toml",
                    "\n[build-dependencies]\nbusbar-plane-llm = { workspace = true }\n",
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a build-dependency is a shipped edge",
                &[ROW_DEPS],
                ov,
                &[
                    "unlisted-dep-edge",
                    "transport -> plane",
                    "build-dependencies",
                ],
            ));

            // A PER-TARGET DEPENDENCY IS A DEPENDENCY, and `cfg(unix)` is true on every runner this
            // tree builds on, so the edge is not even conditional.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tls/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tls/Cargo.toml",
                    "\n[target.'cfg(unix)'.dependencies]\nbusbar-plane-mcp = { workspace = true }\n",
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a per-target dependency is a dependency",
                &[ROW_DEPS],
                ov,
                &["unlisted-dep-edge", "transport -> plane", "target."],
            ));

            // A RENAMED PACKAGE IS THE PACKAGE IT RENAMES. The needle list names the PLANE, because the
            // finding that says only `wire` is a finding about a crate that resolves to no kind at all.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tls/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tls/Cargo.toml",
                    "\n[dependencies.wire]\npackage = \"busbar-plane-llm\"\npath = \"../busbar-plane-llm\"\n",
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a renamed package is the package it renames",
                &[ROW_DEPS],
                ov,
                &[
                    "unlisted-dep-edge",
                    "transport -> plane",
                    "busbar-transport-tls -> busbar-plane-llm",
                ],
            ));

            // THE SAME RENAME, STATED ONE FILE AWAY. `[workspace.dependencies]` renames it and the
            // member says only `workspace = true`, so neither the member's manifest nor its source ever
            // spells a plane word.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tls/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tls/Cargo.toml",
                    "\n[dependencies]\nwire-shim = { workspace = true }\n",
                ),
            );
            ov.set(
                "Cargo.toml",
                cx.read("Cargo.toml").unwrap_or_default().replacen(
                    "[workspace.dependencies]\n",
                    "[workspace.dependencies]\nwire-shim = { package = \"busbar-plane-llm\", path = \
                     \"crates/busbar-plane-llm\" }\n",
                    1,
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a workspace-inherited rename reaches the package the workspace named",
                &[ROW_DEPS],
                ov,
                &[
                    "unlisted-dep-edge",
                    "transport -> plane",
                    "busbar-plane-llm",
                ],
            ));

            // A DEV-DEPENDENCY IS A REAL EDGE OF THE `cargo test` BUILD GRAPH. It is not a SHIPPED
            // edge, which is why it is on its own row and why THIS case requires `:deps` to stay green
            // in the same breath — a rule that folded the two together would make every shared fixture
            // read as a kind learning about another kind.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-tls/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-transport-tls/Cargo.toml",
                    "\n[dev-dependencies]\nbusbar-plane-llm = { workspace = true }\n",
                ),
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a dev-dependency crossing a kind is named on the test graph's own row",
                &[ROW_TEST_DEPS],
                ov,
                &[
                    "unlisted-dep-edge",
                    "transport -> plane",
                    "dev-dependencies",
                ],
            ));
        }

        // NO KIND NAMES ANOTHER KIND'S CRATE PATH. `banned_for` had an arm for four kind words, so
        // `store`, `auth`, `secret`, `hooks`, `export`, `unit`, `kernel` and `substrate` source
        // could name any other kind freely — and this row scanned ZERO files of them.
        let mut ov = Overlay::new();
        ov.set(
            "crates/store-memory/src/planted_leak.rs",
            "pub fn leak() { let _ = busbar_plane_llm::VERSION; let _ = \
             busbar_transport_http::Client::default(); }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "no kind names another kind's crate path",
            &[ROW_VOCAB],
            ov,
            &[
                "undeclared-crate-path",
                "busbar_plane_llm",
                "busbar-store-memory",
            ],
        ));

        // ── THE REGISTRY ROW'S SUB-CHECKS, ONE PLANT EACH ────────────────────────────────────────
        //
        // A GUTTED SUB-CHECK IS NOT A DELETED ROW. The battery proved `:registry` RED-able through
        // two of its arms, and an audit gutted `unmapped-kind` — replaced its body with nothing —
        // and got `kind-isolation: green` and `17 case(s), 0 skipped — the gate is proven RED-able`
        // in the same breath, because the row was still emitted and still red-able through its
        // neighbours. Eight arms had no plant of their own. These are those eight.

        // A KIND NOBODY INSTANTIATES IS A DEAD ROW IN THE TABLE.
        //
        // THE SUBJECT IS `contract` (after `timing`), AND IT USED TO BE `grammar`, WHICH PROVED
        // NOTHING. The plant was
        // `Overlay::remove("crates/busbar-grammar/Cargo.toml")` — a path that has not been in this
        // tree for as long as the case has existed, so it removed nothing — against a row that is
        // STANDING RED naming `dead-kind KINDS \`grammar\``, the exact two tokens the case
        // asserts. A no-op plant, a red that predates it, and a green case: the rule could have
        // been deleted outright with this case still passing. `prove_red` refuses both halves now.
        //
        // `contract` is the kind to plant because its matcher is `=busbar-contract`, one crate and
        // no other, so removing that manifest takes the whole kind out of `live` — which is what the
        // rule reads. A kind with a prefix matcher would need every crate of it removed at once.
        // (It was `timing`, `=busbar-timing`, until OWNER Q70 folded that crate into the kernel.)
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-contract/Cargo.toml");
        hold_census_floor(&mut ov, 1);
        report.push(prove_rows_red(
            cx,
            subject,
            "a kind in the table that no crate is any more",
            &[ROW_REGISTRY],
            ov,
            &["dead-kind", "contract"],
        ));

        // THE PENDING-KIND RATCHET: a crate of a pending kind retires the pending entry. `secret`
        // is pending (its instances live in their own repos), so a planted `busbar-secret-*`
        // manifest makes the kind live while the entry still says pending — the one state the
        // ratchet exists to refuse.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-secret-planted/Cargo.toml",
            "[package]\nname = \"busbar-secret-planted\"\nversion = \"0.0.0\"\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a pending kind that now has a crate",
            &[ROW_REGISTRY],
            ov,
            &["kind-arrived", "secret"],
        ));

        // THE RENAME ALIAS EXPIRES WITH THE CRATE IT TRANSLATES.
        //
        // THE SUBJECT IS `busbar-voice-codec`, AND IT USED TO BE `busbar-plane-voice`, the twin of
        // the no-op above and for the same reason: `crates/busbar-plane-voice/Cargo.toml` is not in
        // the tree, so removing it removed nothing. The `voice` alias itself now keys on the codec,
        // the one crate left that spells the dialect as a plane id, so removing it is a violation
        // the tree does not already have.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-voice-codec/Cargo.toml");
        hold_census_floor(&mut ov, 1);
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane alias that outlived the crate it translates",
            &[ROW_REGISTRY],
            ov,
            &["alias-retired", "busbar-voice-codec"],
        ));

        // AN ALIAS ONTO A KEY NO PLANE DECLARES. The canonical side of `PLANE_ALIASES` is checked
        // against the key `busbar-plane-streaming` registers under, read off its `impl PlaneMeta`;
        // re-keying the plane leaves both aliases pointing at a word nothing registers.
        let meta = "crates/busbar-plane-streaming/src/meta.rs";
        let key_line = "const KEY: &'static str = \"streaming\";";
        match cx.read(meta) {
            Ok(text) if text.contains(key_line) => {
                let mut ov = Overlay::new();
                ov.set(
                    meta,
                    text.replacen(key_line, "const KEY: &'static str = \"rekeyed\";", 1),
                );
                report.push(prove_rows_red(
                    cx,
                    subject,
                    "a plane alias whose canonical side is a key no plane declares",
                    &[ROW_REGISTRY],
                    ov,
                    &["alias-undeclared", "streaming"],
                ));
            }
            other => report.push(unplantable(
                "a plane alias whose canonical side is a key no plane declares",
                &[ROW_REGISTRY],
                &["alias-undeclared"],
                format!(
                    "{meta} does not carry `{key_line}` to re-key ({:?})",
                    other.err()
                ),
            )),
        }

        // THE SECOND KIND VOCABULARY, GONE. `qa/construction.toml`'s `[gate.plugin_kinds]` renamed
        // away leaves the cross-check reading nothing, which is not the same as agreeing.
        let mut ov = Overlay::new();
        ov.set(
            "qa/construction.toml",
            cx.read("qa/construction.toml")
                .unwrap_or_default()
                .replacen("[gate.plugin_kinds]", "[gate.plugin_kinds_renamed]", 1),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "the second kind vocabulary renamed away leaves the cross-check reading nothing",
            &[ROW_REGISTRY],
            ov,
            &["no-construction-kinds", "qa/construction.toml"],
        ));

        // …AND A KEY IN IT THAT MAPS ONTO NOTHING HERE IS THE TWO VOCABULARIES DRIFTING APART.
        let mut ov = Overlay::new();
        ov.set(
            "qa/construction.toml",
            cx.read("qa/construction.toml")
                .unwrap_or_default()
                .replacen(
                    "[gate.plugin_kinds]\n",
                    "[gate.plugin_kinds]\nfrobnicator = [\"crates/busbar-frobnicator-*\"]\n",
                    1,
                ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a kind key in the second vocabulary that maps onto no kind here",
            &[ROW_REGISTRY],
            ov,
            &["unmapped-kind", "frobnicator"],
        ));

        // AND THE FILE ABSENT IS A REFUSAL, NEVER AN AGREEMENT.
        let mut ov = Overlay::new();
        ov.remove("qa/construction.toml");
        report.push(prove_rows_red(
            cx,
            subject,
            "the second kind vocabulary absent is a refusal, never an agreement",
            &[ROW_REGISTRY],
            ov,
            &["unreadable", "qa/construction.toml"],
        ));

        // THE TWO FLOORS, AND THEY FAIL APART. A census that finds almost nothing recognises almost
        // everything, and a scan of no files names no leak — both read exactly like a clean tree.
        report.push(prove_rows_red(
            cx,
            subject,
            "the crate census collapsed below its floor",
            &[ROW_REGISTRY],
            move || all_but(cx, "toml", 4),
            &["floor", &MIN_MANIFESTS.to_string()],
        ));
        report.push(prove_rows_red(
            cx,
            subject,
            "the source walk collapsed below its floor",
            &[ROW_VOCAB],
            move || all_but(cx, "rs", 4),
            &["floor", &MIN_SOURCES.to_string()],
        ));

        // …AND THE REST OF THE FLOORS, one case each. EVERY ONE OF THESE IS A RULE WHOSE SUBJECT IS
        // THE SIZE OF ITS OWN INPUT, and a mutation campaign found that not one of them was proven:
        // `if false && scanned == 0`, `.min_files(0)` and `if false && planes.is_empty()` all left
        // the battery green. A floor nothing proves is a floor somebody deletes as dead code, and
        // the tree it then reads as clean is the tree that has nothing in it.

        // NO FILE REACHED THE VOCABULARY RULE. The walk is over its floor and every file it found
        // belongs to no crate the census knows, so the rule looked at nothing and found nothing.
        report.push(prove_rows_red(
            cx,
            subject,
            "a :vocab scan that reached zero kind-bearing files is refused, not read as clean",
            &[ROW_VOCAB],
            move || all_but(cx, "toml", 0),
            &["0 file(s) reached the vocabulary rule"],
        ));

        // The money-vocabulary case retired with the `control` kind (DECISIONS #5): a `cleanliness`
        // surface is a served admin surface that legitimately reports on cost/usage, so this rule no
        // longer carries a money ban to prove RED-able.

        // A STEP LIST THAT READ TWO STEPS IS NOT A PLANE THAT RUNS EVERY STEP.
        let mut ov = Overlay::new();
        ov.set(
            STEP_TABLE_FILE,
            "pub const ALL: [StepName; 2] = [\n    StepName::Route,\n    StepName::Meter,\n];\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a step list that read fewer than five plane-owned steps is refused",
            &[ROW_STEPS],
            ov,
            &["floor", &MIN_PLANE_STEPS.to_string()],
        ));

        // A TREE WITH NO PLANE IN IT. Zero planes skip every step.
        report.push(prove_rows_red(
            cx,
            subject,
            "a tree with no plane crate at all is refused by the step rule",
            &[ROW_STEPS],
            move || kind_gone(cx, "busbar-plane-"),
            &["0 plane crate(s)"],
        ));

        // A TREE WITH NO WIRE IN IT. Zero wires are registered twice.
        report.push(prove_rows_red(
            cx,
            subject,
            "a tree with no transport crate at all is refused by the registration rule",
            &[ROW_WIRES],
            move || kind_gone(cx, "busbar-transport-"),
            &["0 wire(s)"],
        ));

        // THE REGISTRATION RULE'S OWN WALK HAS A FLOOR TOO, and it is a different walk from
        // `:vocab`'s: the wires are read off the census, so the manifests survive and the rule
        // reaches its source scan with nothing to scan.
        report.push(prove_rows_red(
            cx,
            subject,
            "the registration rule's source walk below its floor is refused",
            &[ROW_WIRES],
            move || all_but(cx, "rs", 4),
            &["a scan of no files finds no second registration"],
        ));

        // THE CENSUS ITSELF FAILING IS OWED BY EVERY ROW. Not "absent" — UNREADABLE: a manifest the
        // walk lists and cannot read is the one input state that is neither a crate nor no crate,
        // and a gate that reads it as no crate is a gate that goes green on a corrupt tree.
        let mut ov = Overlay::new();
        ov.unreadable(
            "crates/busbar-caps/Cargo.toml",
            "Input/output error (os error 5)",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "the crate census failing is refused on every row this gate owes, not on one",
            &[
                ROW_NAME,
                ROW_VOCAB,
                ROW_REGISTRY,
                ROW_STEPS,
                ROW_WIRES,
                ROW_MATRIX,
            ],
            ov,
            &["the census did not run"],
        ));

        // ── THE ENTRY FACES ──────────────────────────────────────────────────────────────────────
        //
        // `:shape` counts a crate's implementations of ITS OWN kind's face, so a red team's
        // `impl Plane for Wire` in a transport and `impl Transport for P` in a plane produced a
        // BYTE-IDENTICAL row in both directions. The rule never asked whether a crate implements
        // somebody else's face. `:faces` is that question, in both directions and in both
        // spellings.

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-http/src/planted_plane_impl.rs",
            "pub struct Wire;\nimpl Plane for Wire {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a wire implementing a plane face",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-transport-http", "Plane"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-llm/src/planted_wire_impl.rs",
            "pub struct P;\nimpl Transport for P {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane implementing a wire face",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-plane-llm", "Transport"],
        ));

        // THE QUALIFIED SPELLING IS THE SAME IMPLEMENTATION, and without this case the rule above
        // is bypassed in one keystroke: `impl_trait_on` read the head of the line and refused
        // anything that did not start with a capital, so `impl busbar_contract::Plane for Wire`
        // answered `None` and the trait was implemented in plain sight.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-ws/src/planted_qualified.rs",
            "pub struct Wire;\nimpl busbar_contract::Plane for Wire {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a wire implementing a plane face in the QUALIFIED spelling",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-transport-ws", "Plane"],
        ));

        // …AND THE SAME IMPLEMENTATION UNDER A NAME OF THE AUTHOR'S CHOOSING. The face rule
        // answers by the LAST PATH SEGMENT, and nothing resolved a rename — so
        // `use busbar_contract::plane::Plane as Metered;` renamed the entry face out of the rule's
        // sight in one line, and a red team walked a transport through it green.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-ws/src/planted_alias.rs",
            "use busbar_contract::plane::Plane as Metered;\npub struct WireA;\nimpl Metered for \
             WireA {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a wire implementing a plane face under a `use … as` rename",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-transport-ws", "Plane"],
        ));

        // …AND WHAT `cargo fmt` ITSELF WRITES. A long header wraps, and no LINE of a wrapped one
        // holds both `impl` and ` for ` — so the line-based reader saw nothing at all. The
        // statement is read as tokens now, and this is the fixture that says so.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-ws/src/planted_wrapped.rs",
            "pub struct WireB;\nimpl\n    busbar_contract::plane::Plane\n    for WireB\n{\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a wire implementing a plane face across a rustfmt-wrapped header",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-transport-ws", "Plane"],
        ));

        // …AND A BOUND IS NOT AN IMPLEMENTATION. `impl<T: Plane> Local for T` implements `Local`
        // and names `Plane` only to say which types it is written over. The green arm is what stops
        // the token reader above from being a rule that reds on the word.
        //
        // NOT ON THE SHIP TWIN, for the reason the two ratchet cases below are not: `:faces` is RED
        // on the real tree at ship time BY DESIGN — the twin owes zero foreign faces and four are
        // still standing — so a green assertion there would be asserting that the debt is drained,
        // which is the opposite of what the criterion is for.
        if !self.ship {
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-transport-ws/src/planted_bound.rs",
                "pub trait Local {}\nimpl<T: busbar_contract::plane::Plane> Local for T {}\n",
            );
            report.push(prove_rows_green(
                cx,
                subject,
                "a trait named only in an `impl<T: Trait>` bound is not an implementation of it",
                &[ROW_FACES],
                ov,
            ));
        }

        // THE RATCHET, BOTH WAYS. The four faces that exist today are held at their exact count:
        // a SECOND one in the same crate is a landing that grew the coupling.
        if !self.ship {
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-a2a/src/planted_second_transport.rs",
                "pub struct Second;\nimpl Transport for Second {}\n",
            );
            report.push(prove_rows_red(
                cx,
                subject,
                "a second implementation of a reviewed foreign face is a landing that grew it",
                &[ROW_FACES],
                ov,
                &["face-ratchet", "busbar-a2a", "Transport"],
            ));

            // AND A ROW WHOSE IMPLEMENTATION IS GONE IS A DEAD ALLOWANCE.
            report.push(plant_registry(
                cx,
                subject,
                "a reviewed face row that covers no implementation any more is struck",
                &[ROW_FACES],
                Ok((
                    "crate = \"busbar-a2a\"\nface = \"Transport\"".to_string(),
                    "crate = \"busbar-a2a-planted\"\nface = \"Transport\"".to_string(),
                )),
                &["dead-face", "busbar-a2a-planted", "Strike the row"],
            ));
        }

        // ── THE WAYS IN THAT ARE NOT A DEPENDENCY ────────────────────────────────────────────────
        //
        // Five plants, each proven by a red team to carry a whole plane into a transport with every
        // gate in the tree green. See [`inputs`] for the rule.

        // A CROSS-CRATE `#[path]` MODULE IS A DUAL COMPILE. The path is a STRING LITERAL, and
        // `:vocab` blanks literals before it reads — which is exactly why this one was invisible
        // there and is read off the RAW line here.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-http/src/planted_smuggle.rs",
            "#[path = \"../../busbar-plane-llm/src/meta.rs\"]\npub mod smuggled;\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a cross-crate #[path] module is a dual compile, not a dependency",
            &[ROW_INPUTS],
            ov,
            &["path-include", "busbar-plane-llm", "busbar-transport-http"],
        ));

        // NOTHING REDIRECTS WHAT CARGO COMPILES. `[patch]` substitutes one crate for another
        // AFTER every manifest in this tree has been read and agreed with, so the census, the edge
        // ledger, the matrix and the lock cross-check are all downstream of a decision none of them
        // can see. Nothing in this gate read the table at all until today.
        let mut ov = Overlay::new();
        ov.set(
            "Cargo.toml",
            manifest_plus(
                cx,
                "Cargo.toml",
                "\n[patch.crates-io]\nbusbar-plane-llm = { path = \"crates/busbar-plane-mcp\" }\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a `[patch]` table redirects what cargo compiles and is refused unless a row names it",
            &[ROW_INPUTS],
            ov,
            &["redirect", "patch.crates-io", "Cargo.toml"],
        ));

        // THE SAME CLAIM IN `.cargo/config.toml`, which is not a manifest at all and which no rule
        // in this gate had ever opened.
        let mut ov = Overlay::new();
        ov.set(
            ".cargo/config.toml",
            format!(
                "{}\n[source.crates-io]\nreplace-with = \"vendored\"\n",
                cx.read(".cargo/config.toml").unwrap_or_default().trim_end()
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a `[source] replace-with` in .cargo/config.toml is the same redirect, in a file no \
             rule opened",
            &[ROW_INPUTS],
            ov,
            &["redirect", "source.crates-io", ".cargo/config.toml"],
        ));

        // A NAMED ROW IS THE ONE WAY THROUGH, AND IT EXPIRES WITH THE TABLE IT NAMES.
        let mut ov = Overlay::new();
        ov.set(
            REGISTRY_FILE,
            format!(
                "{}\n\n[[patch]]\nfile = \"Cargo.toml\"\nentry = \"patch.crates-io\"\nreason = \"planted\"\n",
                cx.read(REGISTRY_FILE).unwrap_or_default().trim_end()
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a `[[patch]]` row whose table is not in the tree is a standing hole, and is struck",
            &[ROW_INPUTS],
            ov,
            &["dead-patch-row", "patch.crates-io"],
        ));

        // A LIB TARGET POINTING INTO ANOTHER KIND. The transport IS the plane at link time, with
        // zero dependencies and zero source of its own — and unlike a `#[path]` read, no dependency
        // edge could make this a reach rather than an identity.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-transport-tcp/Cargo.toml",
                "\n[lib]\npath = \"../busbar-plane-llm/src/lib.rs\"\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a lib target pointing into another kind's source",
            &[ROW_INPUTS],
            ov,
            &[
                "foreign-lib-path",
                "busbar-transport-tcp",
                "busbar-plane-llm",
            ],
        ));

        // A BUILD SCRIPT READING ANOTHER KIND'S SOURCE. Nothing scanned `build.rs` for this, and
        // the only incidental noise it produced was `audit-ledger:missing-scopes` naming the new
        // FILE PATH — never its content.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tls/build.rs",
            "fn main() { let _ = include_str!(\"../busbar-plane-mcp/src/lib.rs\"); }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a build script reading another kind's source",
            &[ROW_INPUTS],
            ov,
            &[
                "build-script-reach",
                "busbar-transport-tls",
                "busbar-plane-mcp",
            ],
        ));

        // …AND A BUILD SCRIPT THAT READS ITS SIBLINGS BY DIRECTORY WALK RATHER THAN BY NAME. The
        // marker loop reports a path that lands in another CENSUSED CRATE, which is the right
        // narrowing for a library file and the wrong one for a build script: `read_dir("..")` names
        // no crate, lands outside every one of them, and was green everywhere while compiling the
        // whole tree's plane sources into a transport's generated output. A build script is held to
        // the DIRECTORY instead.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/build.rs",
            "fn main() {\n    for e in std::fs::read_dir(\"..\").unwrap() {\n        let f = \
             e.unwrap().path().join(\"src\").join(\"plane.rs\");\n        if f.exists() { let _ = \
             std::fs::read_to_string(&f); }\n    }\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a build script that reads its siblings by directory walk, not by name",
            &[ROW_INPUTS],
            ov,
            &[
                "build-script-reach",
                "busbar-transport-tcp",
                "outside its own crate directory",
            ],
        ));

        // `include!` IS A DUAL COMPILE TOO, and it was not on the marker list at all. `#[path]` at
        // least declares a module; this splices another crate's source into this one's body with no
        // module, no dependency and no name.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_include.rs",
            "pub mod smuggled {\n    include!(\"../../busbar-plane-llm/src/meta.rs\");\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an `include!` of another kind's source is a dual compile",
            &[ROW_INPUTS],
            ov,
            &["path-include", "busbar-plane-llm", "busbar-transport-tcp"],
        ));

        // …AND A `CARGO_MANIFEST_DIR` SPLICE IS RESOLVED, NOT GUESSED AT. `quoted_after` took the
        // FIRST literal, so `include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        // "/../busbar-plane-mcp/src/lib.rs"))` resolved to a path INSIDE the crate and the finding
        // was dropped — the softest possible failure of the rule that matters most. That variable
        // is exactly the crate directory, so the path is resolved against it, which is strictly
        // stronger than refusing the spelling: the tree already uses this idiom eight times.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_spliced.rs",
            "pub const S: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \
             \"/../busbar-plane-mcp/src/lib.rs\"));\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an include path spliced from CARGO_MANIFEST_DIR is resolved against the crate \
             directory",
            &[ROW_INPUTS],
            ov,
            &[
                "build-script-reach",
                "busbar-plane-mcp",
                "busbar-transport-tcp",
            ],
        ));

        // …AND EVERY OTHER SPLICE IS REFUSED. `include!(concat!("../../busbar-p", "lane-l", …))`
        // spells the name in pieces no scanner reads and resolves to a path no reader here can
        // derive. An input this gate cannot resolve is an input it cannot score, so it fails closed.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_pieces.rs",
            "include!(concat!(\"../../busbar-p\", \"lane-l\", \"lm/src/me\", \"ta.rs\"));\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an include path spliced out of pieces is refused, not resolved",
            &[ROW_INPUTS],
            ov,
            &["unresolvable-include", "concat", "busbar-transport-tcp"],
        ));

        // `OUT_DIR` IS RESOLVED ONLY WHERE A BUILD SCRIPT WROTE IT. A crate with no `build.rs` has
        // no writer for the file, so an `OUT_DIR` splice there names an input nothing scored.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_out_dir.rs",
            "include!(concat!(env!(\"OUT_DIR\"), \"/linked.rs\"));\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an OUT_DIR include in a crate with no build script is refused",
            &[ROW_INPUTS],
            ov,
            &["unresolvable-include", "concat", "busbar-transport-tcp"],
        ));

        // …AND AN `OUT_DIR` TAIL THAT CLIMBS IS REFUSED EVEN WHERE ONE EXISTS: `..` out of the build
        // output is a path this gate cannot place, whatever the build script wrote.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar/src/planted_out_dir.rs",
            "include!(concat!(env!(\"OUT_DIR\"), \"/../../x.rs\"));\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an OUT_DIR include that climbs out with `..` is refused",
            &[ROW_INPUTS],
            ov,
            &[
                "unresolvable-include",
                "concat",
                "crates/busbar/src/planted_out_dir.rs",
            ],
        ));

        // THE CONTROL: the same splice, not climbing, in a crate whose build script wrote it, is the
        // crate's own file and stays green.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar/src/planted_out_dir.rs",
            "include!(concat!(env!(\"OUT_DIR\"), \"/linked.rs\"));\n",
        );
        report.push(prove_rows_green(
            cx,
            subject,
            "an OUT_DIR include in a crate with a build script is its own build output",
            &[ROW_INPUTS],
            ov,
        ));

        // A LOCK FILE NAMING AN EDGE NO MANIFEST HAS. Nothing in the tree read `Cargo.lock` at all,
        // so the file that says what cargo COMPILES was never compared with the files that say what
        // was asked for.
        report.push(prove_rows_red(
            cx,
            subject,
            "a lock file naming an edge no manifest has",
            &[ROW_INPUTS],
            lock_plus(cx, "busbar-transport-tcp", "busbar-plane-llm"),
            &["lock-drift", "Cargo.lock", "busbar-transport-tcp"],
        ));

        // A REGISTRY ENTRY FILED UNDER THE WRONG KIND. `plugins.yaml` is what the loader believes,
        // and a store plugin filed as `auth` is a store handed the auth ABI.
        let mut ov = Overlay::new();
        ov.set(
            "plugins.yaml",
            cx.read("plugins.yaml").unwrap_or_default().replacen(
                "  - repo: store-mysql\n    kind: store\n",
                "  - repo: store-mysql\n    kind: auth\n",
                1,
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a registry entry filed under the wrong kind",
            &[ROW_INPUTS],
            ov,
            &[
                "registry-kind-mismatch",
                "busbar-store-mysql-plugin",
                "store",
            ],
        ));

        // A FEATURE NAME IS VOCABULARY TOO. `[features]` was the one part of a manifest no rule
        // read.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-transport-tcp/Cargo.toml",
                "\n[features]\nllm-serve = []\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a feature name is vocabulary too",
            &[ROW_INPUTS],
            ov,
            &["feature-vocab", "llm-serve", "busbar-transport-tcp"],
        ));

        // …AND THE COMPOSITION ROOT'S `root-*` FEATURES ARE THE WRITTEN EXEMPTION. The root is the
        // one place the tree assembles a plane, so a feature that switches one on is the root doing
        // its job — and it is an exemption WITH A NUMBER ATTACHED, because `:matrix` counts every
        // one of those words against the root's own cell at an exact ceiling. Without this case the
        // exemption would be silence, which is what it was on a transport too.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar/Cargo.toml",
                "\n[features]\nroot-llm-planted = []\n",
            ),
        );
        report.push(prove_rows_green(
            cx,
            subject,
            "the composition root's own `root-*` plane features are the written exemption",
            &[ROW_INPUTS],
            ov,
        ));

        // ── THE COMPILED SET IS THE SCANNED SET ─────────────────────────────────────────────────
        //
        // THE WORST MISS A RED TEAM LANDED, and it went around every scanner rather than through
        // one: `crates/store-memory/src/target/leak.rs`, naming `busbar-plane-llm` and defining
        // `fn mcp_hook`, reached by `#[path = "target/leak.rs"] pub mod leak;` in the store's own
        // `lib.rs`. Live, linked, SHIPPED code naming another kind's instance, with all six gates
        // green — because the walker skips any directory called `target` and `.gitignore` carries a
        // bare `target/`, so the file was invisible twice over. The plant is that file.
        let mut ov = Overlay::new();
        ov.set(
            "crates/store-memory/src/target/leak.rs",
            "pub const P: &str = \"busbar-plane-llm\";\npub fn mcp_hook() {}\n",
        );
        ov.set(
            "crates/store-memory/src/lib.rs",
            format!(
                "{}\n#[path = \"target/leak.rs\"]\npub mod leak;\n",
                cx.read("crates/store-memory/src/lib.rs")
                    .unwrap_or_default()
                    .trim_end()
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a compiled source in a walker-skipped, gitignored directory is source no rule has read",
            &[ROW_INPUTS],
            ov,
            &[
                "hidden-source",
                "crates/store-memory/src/target/leak.rs",
                "git check-ignore",
            ],
        ));

        // …AND THE SAME REFUSAL WITHOUT AN ATTRIBUTE. A plain `mod x;` whose file the scan set does
        // not carry is the same hole reached by the shortest spelling there is, and it is the arm
        // that would go quiet the day the walker gains one more skipped directory name.
        let mut ov = Overlay::new();
        ov.set(
            "crates/store-memory/src/lib.rs",
            format!(
                "{}\npub mod planted_ghost;\n",
                cx.read("crates/store-memory/src/lib.rs")
                    .unwrap_or_default()
                    .trim_end()
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a `mod` whose file is in no scan this gate runs is refused",
            &[ROW_INPUTS],
            ov,
            &[
                "hidden-source",
                "planted_ghost",
                "crates/store-memory/src/planted_ghost.rs",
            ],
        ));

        // THE VOCABULARY, BOTH DIRECTIONS.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_leak.rs",
            "pub fn route(a2a_session: u8) -> u8 { let mcp = a2a_session; mcp }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a transport source naming a plane instance",
            &[ROW_VOCAB],
            ov,
            &["a2a", "mcp", "planted_leak.rs"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-mcp/src/planted_axum.rs",
            "use axum::Router;\npub fn bind() { let _ = tokio::net::TcpListener::bind; }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane source naming a transport library and a socket module",
            &[ROW_VOCAB],
            ov,
            &["axum", "tokio::net"],
        ));

        // THE HOLE THAT OPENS ON THE RENAME. `banned_for` is written against kind words and
        // `dialect` was not one of them, so the first `busbar-plane-<plane>-<dialect>` crate could
        // have named a transport library and a transport crate with this row silent — on the day
        // D36 lands, which is exactly when nobody is looking. The plant is a whole dialect crate,
        // manifest and source, because a dialect that does not exist is scanned zero files of.
        let mut ov = manifest_plant(
            "crates/busbar-plane-llm-openai",
            "busbar-plane-llm-openai",
            &["busbar-contract", "busbar-plane-llm"],
        );
        ov.set(
            "crates/busbar-plane-llm-openai/src/planted_transport.rs",
            "use axum::Router;\nuse busbar_transport_http::Client;\npub fn go(_: Router) {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a DIALECT naming a transport library and a transport crate — the plane's own ban",
            &[ROW_VOCAB],
            ov,
            &["axum", "busbar_transport_http", "busbar-plane-llm-openai"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-llm-codec/src/planted_transport.rs",
            "use busbar_transport_http::Client;\npub fn go() { let _ = Client::default(); }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a codec naming a transport crate",
            &[ROW_VOCAB],
            ov,
            &["busbar_transport_", "planted_transport.rs"],
        ));

        // THE CONTROL. A gate its own prose fails is a gate people learn to skip — and without
        // this case the three reds above would equally be produced by a scanner that flags every
        // line it reads.
        //
        // IT IS A CLAIM ABOUT `:vocab` AND ABOUT NOTHING ELSE, and the distinction is the whole of
        // the owner's 2026-09-08 ruling. `:vocab` blanks literals and reads only production lines
        // because its findings are IDENTIFIERS — a ban that would equally match its own explanation
        // in a `format!` is a ban that reds on documentation. What that scoping is NOT is a
        // statement that a plane named in a comment of a wire is fine: the exact plant below is
        // COUNTED by `:matrix`, which strips nothing, excludes no tests, and holds the number at an
        // exact ceiling. Two rows, two questions; this case answers the narrower one.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_prose.rs",
            "// this comment names a2a and mcp and voice and llm and admin freely\n\
             /* and so does this block comment: a2a mcp voice */\n\
             pub fn note() -> &'static str { \"a2a mcp voice llm admin\" }\n\
             #[cfg(test)]\nmod tests {\n    fn t() { let a2a = 1; let _ = a2a; }\n}\n",
        );
        report.push(prove_rows_green(
            cx,
            subject,
            "comments, literals and cfg(test) scope name nothing TO `:vocab` (`:matrix` counts them)",
            &[ROW_VOCAB],
            ov,
        ));

        // A CRATE OF NO KIND AT ALL, answered in the owner's own words.
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate whose kind is not in the table is refused with the owner's instruction",
            &[ROW_REGISTRY],
            manifest_plant("crates/busbar-frobnicator", "busbar-frobnicator", &[]),
            &["unknown-kind", MAKE_A_NEW_KIND],
        ));

        // WHERE A CRATE LIVES. The census read `crates/<dir>/Cargo.toml` and nothing else, and the
        // three plants below are the three shapes that walked past it.

        // A CRATE OUTSIDE `crates/` IS STILL A CRATE OF A KIND. The red team's own plant: a
        // plane-kind crate under `vendor/`, path-depended by a transport. Every gate was green.
        let mut ov = manifest_plant(
            "vendor/busbar-plane-shim",
            "busbar-plane-shim",
            &["busbar-plane-llm"],
        );
        ov.set(
            "crates/busbar-transport-tls/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-transport-tls/Cargo.toml",
                "\n[dependencies]\nbusbar-plane-shim = { path = \"../../vendor/busbar-plane-shim\" }\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate outside crates/ is still a crate of a kind",
            &[ROW_REGISTRY, ROW_DEPS],
            ov,
            &[
                "off-tree-crate",
                "vendor/busbar-plane-shim",
                "transport -> plane",
            ],
        ));

        // A CRATE NESTED UNDER ANOTHER CRATE IS NOT A FIXTURE. "A manifest one level deeper belongs
        // to a fixture" was the census's own comment, and it was the hole: `--workspace` never
        // compiles this crate and a path dependency reaches it anyway.
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate nested under another crate is not a fixture",
            &[ROW_REGISTRY],
            manifest_plant(
                "crates/busbar-transport-tcp/internal/shim",
                "busbar-plane-shim2",
                &[],
            ),
            &["nested-crate", "crates/busbar-transport-tcp/internal/shim"],
        ));

        // A CRATE ON DISK AND OFF THE MEMBERS LIST. One deleted line drops a live, path-depended
        // crate out of every `--workspace` test, clippy and deny run, and the crate still ships.
        let mut ov = Overlay::new();
        ov.set(
            "Cargo.toml",
            cx.read("Cargo.toml").unwrap_or_default().replacen(
                "    \"crates/busbar-plane-llm\",\n",
                "",
                1,
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate on disk and off the members list",
            &[ROW_REGISTRY],
            ov,
            &["unmembered", "busbar-plane-llm", "still path-depended"],
        ));

        // AN OFF-TREE ENTRY THAT COVERS NOTHING IS A DEAD ALLOWANCE, on the same ratchet as every
        // other exemption in this file.
        let mut ov = Overlay::new();
        ov.remove("examples/smart-router/rust-hook/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            subject,
            "an off-tree exemption that outlived its manifest is refused",
            &[ROW_REGISTRY],
            ov,
            &["dead-off-tree", "examples/smart-router/rust-hook"],
        ));

        // THE LEGACY RATCHET, proven by retiring one.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-a2a/Cargo.toml");
        hold_census_floor(&mut ov, 1);
        report.push(prove_rows_red(
            cx,
            subject,
            "a legacy exemption that outlived its crate is refused",
            &[ROW_REGISTRY],
            ov,
            &["legacy-retired", "busbar-a2a"],
        ));

        // THE THREE TRUTHS, each planted in the file that carries it.
        truths::selftest(cx, subject, &mut report);

        // ── THE LEGACY DRAIN, NAMED ──────────────────────────────────────────────────────────────

        // AN UNLISTED DRAIN EDGE IS RED. `busbar-llm` is a legacy crate and [`PLANTED_UNIT`] is a
        // unit, so this is exactly the shape the owner's ruling permits — and no row names it.
        // Before the transitional table this edge was invisible: `legacy` was an unscored source,
        // so every legacy edge into every kind was allowed by silence.
        //
        // THE TARGET IS A CRATE THE TREE HAS. It was `busbar-unit-audit`, folded into
        // `busbar-kernel-audit`: the refusal and `measure_edges` both skip a declaration whose
        // package is not in the census, so the edge was never scored and the case could not bite.
        report.push(prove_rows_red(
            cx,
            subject,
            "a legacy crate reaching a unit with no transitional row naming the edge",
            &[ROW_DEPS],
            manifest_plant("crates/busbar-llm", "busbar-llm", &[PLANTED_UNIT]),
            &["unlisted-transitional", "busbar-llm", PLANTED_UNIT],
        ));

        // THE TABLE CANNOT EXEMPT A CRATE THAT IS NOT RETIRING. A row whose source is a live,
        // non-legacy crate is REFUSED AT LOAD — not skipped, not tolerated — because a table that
        // can name any source is not the drain's exemption, it is a hole with a reason field.
        let ov = registry_plant(
            "[[transitional]]\nfrom = \"busbar-unit-audit\"\nto = \"busbar-plane-admin\"\nreason = \
             \"planted\"\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a transitional row naming a non-legacy source crate is refused at load",
            &[ROW_DEPS],
            ov,
            &["not-legacy", "busbar-unit-audit"],
        ));

        // ── THE READER'S OWN REFUSALS, EACH WITH A CASE ──────────────────────────────────────────
        //
        // A MUTATION CAMPAIGN STUBBED EVERY REFUSAL IN THIS PARSER AND THE BATTERY STAYED GREEN for
        // nine of the ten: `errors.push(format!(…))` became `drop(format!(…))`, the row loaded
        // anyway, and 107 cases said nothing. `not-legacy` above was the only one anybody had
        // written a fixture for. A refusal nothing proves is a refusal the next edit deletes by
        // accident, so each of them gets the smallest plant that reaches it — one `registry_plant`
        // per case, so what a case proves is what its own row said.
        for (name, rows, needles) in [
            (
                "a [[transitional]] row with an empty field is refused at load",
                "[[transitional]]\nfrom = \"\"\nto = \"busbar-unit-*\"\nreason = \"planted\"\n",
                &["empty-field", "transitional", "from"][..],
            ),
            (
                "a [[transitional]] row missing a field is refused at load",
                "[[transitional]]\nfrom = \"busbar-core\"\nto = \"busbar-unit-*\"\n",
                &["missing-field", "transitional", "reason"][..],
            ),
            (
                "a row declaring a field this gate does not read is refused, not ignored",
                "[[transitional]]\nfrom = \"busbar-core\"\nto = \"busbar-unit-*\"\nreason = \
                 \"planted\"\nowner = \"someone\"\n",
                &["unknown-field", "transitional", "owner"][..],
            ),
            (
                "a [[transitional]] glob that is not a trailing `*` is refused",
                "[[transitional]]\nfrom = \"busbar-llm\"\nto = \"busbar-unit-*-x\"\nreason = \
                 \"planted\"\n",
                &["bad-glob", "busbar-unit-*-x"][..],
            ),
            (
                "an [[announced]] row naming a kind the table does not have is refused",
                "[[announced]]\ncrate = \"busbar-nosuch-x\"\nkind = \"nosuchkind\"\nreason = \
                 \"planted\"\n",
                &["unknown-kind", "announced", "nosuchkind"][..],
            ),
            (
                "a [[registered]] row naming a kind the table does not have is refused",
                "[[registered]]\ncrate = \"busbar-nosuch-x\"\nkind = \"nosuchkind\"\nreason = \
                 \"planted\"\n",
                &["unknown-kind", "registered", "nosuchkind"][..],
            ),
            (
                "a [[cell]] count that is not a number is refused",
                "[[cell]]\ncrate = \"busbar-kernel\"\nkind = \"plane\"\ncount = \"lots\"\n",
                &["bad-count", "lots", "not a number"][..],
            ),
            (
                "a [[table]] this gate does not read is refused, not skipped",
                "[[ceilings]]\nx = \"1\"\n",
                &["unknown-table", "ceilings"][..],
            ),
            (
                "a line that is not `key = \"value\"` is refused",
                "[[transitional]]\nfrom busbar-core\n",
                &["unreadable-line", "from busbar-core"][..],
            ),
            (
                "a field sitting under no [[table]] header is refused",
                "from = \"busbar-core\"\n",
                &["orphan-field", "from"][..],
            ),
        ] {
            report.push(prove_rows_red(
                cx,
                subject,
                name,
                &[ROW_REGISTRY],
                registry_plant(rows),
                needles,
            ));
        }

        // THE TABLE IS AN INPUT. Without it there is no drain exemption to read and no announcement
        // to read, and a gate that treats a missing input as an empty one is a gate that goes green
        // when its own data file is deleted.
        let mut ov = Overlay::new();
        ov.remove(REGISTRY_FILE);
        report.push(prove_rows_red(
            cx,
            subject,
            "the kind registry file being absent is refused, not read as an empty table",
            &[ROW_DEPS],
            ov,
            &[REGISTRY_FILE],
        ));

        // ── THE ANNOUNCED CORE CRATES ────────────────────────────────────────────────────────────

        // THE `core` KIND IS NOT A HOLE. It accepts `busbar-core-<name>` by PREFIX, so the name rule
        // reads the remainder of every member — and `busbar-core-mcp` carries a plane instance.
        // An exact-matcher kind would have yielded an empty remainder and accepted this name in
        // silence, which is the difference this case exists to hold.
        report.push(prove_rows_red(
            cx,
            subject,
            "a core crate named after a plane instance (`busbar-core-mcp`)",
            &[ROW_NAME],
            manifest_plant("crates/busbar-core-mcp", "busbar-core-mcp", &[]),
            &["busbar-core-mcp", "mcp"],
        ));

        // A CORE CRATE REACHES THE NEUTRAL SPINE AND NOTHING ELSE — the same sink set `kernel` and
        // `caps` have. A unit is not on it, so the edge is a new class.
        //
        // THE ANNOUNCEMENT IS PLANTED, not borrowed. This case used to lean on the real
        // `[[announced]] busbar-core-config` row; that row and its crate were struck on 2026-09-22
        // when DECISIONS #37 killed `busbar-core-{config,hooks}`. A case whose subject is a live row
        // goes dark the day that row lands or dies, so it plants its own: `busbar-core-planted`
        // exists nowhere but here.
        //
        // BOTH DEPENDENCIES ARE CRATES THE TREE HAS. They were `busbar-substrate` (renamed
        // `busbar-substrate-values`) and `busbar-unit-audit` (folded into `busbar-kernel-audit`),
        // and an edge onto a package the census does not know is never measured — so the class
        // this case is about was never formed.
        report.push(prove_rows_red(
            cx,
            subject,
            "a core crate reaching a unit is a class the architecture grants nothing to",
            &[ROW_DEPS],
            core_announced_reaching_unit(cx),
            &["announced-edge-class", "core -> unit"],
        ));

        // THE ANNOUNCEMENT IS WHAT HOLDS THE KIND ROW OPEN, not silence. Strike the rows while the
        // crates are still absent and the `core` kind is a dead row in the table — which is what
        // the dead-kind rule is for, and what it would have said the day the kind was added if the
        // announcement had not been made with it.
        report.push(prove_rows_red(
            cx,
            subject,
            "the `core` kind row with neither a crate nor an announcement is a dead kind",
            &[ROW_REGISTRY],
            // RE-TARGETED (item 89): `core` HAS crates now (`busbar-core-admin`,
            // `busbar-core-connsec`), so an empty registry alone left the kind alive and the case
            // GREEN. "Neither a crate nor an announcement" is the plant: every core manifest gone
            // and no `[[announced]]` row.
            move || {
                let mut ov = kinds_gone(cx, &["core"]);
                let gone = ov.paths().count();
                hold_census_floor(&mut ov, gone);
                ov.set(REGISTRY_FILE, String::new());
                ov
            },
            &["dead-kind", "core"],
        ));

        // …and the same on the waiver side. This case named `busbar-core-hooks`: a reviewed
        // sentence that arrived BEFORE its crate, where the announcement was the only thing
        // distinguishing it from a hole nobody re-reads. DECISIONS #37 deleted that crate on
        // 2026-09-22 ("a kind is a plugin, never a core crate") and its waiver went with it, so the
        // pairing has no subject left in the tree. The RULE keeps its proof: the dead-waiver case
        // above (`busbar-unit-transport-key`, reached by removing the crate rather than the
        // announcement) is the one that fires it, and it is unchanged.

        // ── THE STRICT STEP LIST, AND THE WIRE REGISTRY ──────────────────────────────────────────

        // A PLANE THAT DOES NOT RUN A STEP. The plant removes one step's implementation from a data
        // plane by replacing the file that holds it; the step list is read off the kernel's own
        // table, so the finding names the step the loop expected.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-plane-mcp/src/plane.rs");
        report.push(prove_rows_red(
            cx,
            subject,
            "a data plane that implements none of the strict step list",
            &[ROW_STEPS],
            ov,
            &["missing-step", "busbar-plane-mcp"],
        ));

        // A STEP THAT IS DECLARED AND NOT RUN. The compiler is satisfied and the loop stops there,
        // which is the case the presence check alone cannot see.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-mcp/src/planted_step.rs",
            "impl Foo {\n    fn route(&self) -> RoutePlan {\n        todo!()\n    }\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane step whose body is a short circuit is not a step that runs",
            &[ROW_STEPS],
            ov,
            &["short-circuit", "todo!", "planted_step.rs"],
        ));

        // THE STEP LIST IS AN INPUT. Measured against no steps, every plane runs all of them.
        let mut ov = Overlay::new();
        ov.remove(STEP_TABLE_FILE);
        report.push(prove_rows_red(
            cx,
            subject,
            "the strict step list being unreadable is refused, not read as no steps",
            &[ROW_STEPS],
            ov,
            &[STEP_TABLE_FILE],
        ));

        // A PLUGIN LINKING THE CRATE THAT MOVES THE BYTES. A plane declares WHICH transport it
        // claims, as data; the moment it links the wire it has chosen one.
        report.push(prove_rows_red(
            cx,
            subject,
            "a plane crate depending on a wire crate",
            &[ROW_WIRES],
            manifest_plant(
                "crates/busbar-plane-voice",
                "busbar-plane-voice",
                &["busbar-contract", "busbar-transport-ws"],
            ),
            &[
                "wire-dependency",
                "busbar-plane-voice",
                "busbar-transport-ws",
            ],
        ));

        // …AND EVERY KIND IS A KIND THAT DOES NOT LINK A WIRE. The rule read a LIST of five kinds,
        // and `store` was not on it — nor `auth`, `secret`, `hooks` or `export`. A red team gave
        // `store-memory` a `[dependencies]` edge on `busbar-transport-tcp` and this row PASSED,
        // reporting "no plugin links one". The list is now the exception (`root`, `transport`), so
        // a kind added tomorrow is covered tomorrow.
        report.push(prove_rows_red(
            cx,
            subject,
            "a STORE plugin depending on a wire crate — every kind but root and transport",
            &[ROW_WIRES],
            manifest_plant(
                "crates/store-memory",
                "busbar-store-memory",
                &["busbar-contract", "busbar-transport-tcp"],
            ),
            &[
                "wire-dependency",
                "busbar-store-memory",
                "busbar-transport-tcp",
            ],
        ));

        // …AND THE TEST HALF IS READ TOO. `cargo test` links a dev-dependency, and a plugin whose
        // test binary picks a wire has already decided which wire it is for.
        let mut ov = Overlay::new();
        ov.set(
            "crates/store-memory/Cargo.toml",
            "[package]\nname = \"busbar-store-memory\"\nversion = \"0.0.0\"\n\n[dependencies]\n\
             busbar-contract = { workspace = true }\n\n[dev-dependencies]\n\
             busbar-transport-tcp = { path = \"../busbar-transport-tcp\" }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a plugin whose TEST binary links a wire has chosen one just the same",
            &[ROW_WIRES],
            ov,
            &["wire-dependency", "busbar-store-memory", "dev-dependencies"],
        ));

        // THE BOTH-WAYS WITNESS'S FIXTURE (ARCHITECT (K8 residue)). The loader's `[dev-dependencies]`
        // edge to the crate its own `[package.metadata.busbar.both-ways]` names for `transport` is
        // the fixture both doors load, and is not a plugin choosing a wire…
        let loader = |deps: &str, dev: &str, fixture: &str| {
            let mut ov = Overlay::new();
            ov.set(
                "crates/plugin-loader/Cargo.toml",
                format!(
                    "[package]\nname = \"busbar-plugin-loader\"\nversion = \"0.0.0\"\n\n\
                     [dependencies]\nbusbar-contract = {{ path = \"../busbar-contract\" }}\n{deps}\n\
                     [dev-dependencies]\n{dev}\n\
                     [package.metadata.busbar.both-ways]\ntransport = \"{fixture}\"\n"
                ),
            );
            ov
        };
        report.push(prove_rows_green(
            cx,
            subject,
            "the loader's dev-edge to its declared transport both-ways fixture is the witness, not a wire choice",
            &[ROW_WIRES],
            loader(
                "",
                "busbar-transport-tcp = { path = \"../busbar-transport-tcp\" }",
                "busbar-transport-tcp",
            ),
        ));
        // …but the SAME crate as a NORMAL dependency is a wire the loader links into the product…
        report.push(prove_rows_red(
            cx,
            subject,
            "plugin tooling taking a NORMAL edge on its declared fixture wire",
            &[ROW_WIRES],
            loader(
                "busbar-transport-tcp = { path = \"../busbar-transport-tcp\" }",
                "",
                "busbar-transport-tcp",
            ),
            &[
                "wire-dependency",
                "busbar-plugin-loader",
                "busbar-transport-tcp [dependencies]",
            ],
        ));
        // …and a dev-edge to a wire the table does NOT name is a wire chosen, not a fixture.
        report.push(prove_rows_red(
            cx,
            subject,
            "plugin tooling's dev-edge to a wire its both-ways table does not name",
            &[ROW_WIRES],
            loader(
                "",
                "busbar-transport-stdio = { path = \"../busbar-transport-stdio\" }",
                "busbar-transport-tcp",
            ),
            &[
                "wire-dependency",
                "busbar-plugin-loader",
                "busbar-transport-stdio [dev-dependencies]",
            ],
        ));

        // A SECOND REGISTRY. Two places compose the same wire, and nothing says which one ran.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_second_registry.rs",
            "use busbar_transport_http::HttpTransport;\npub fn compose() { let _ = \
             HttpTransport::default(); }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a wire composed in a second place",
            &[ROW_WIRES],
            ov,
            &["second-registration", "busbar-transport-http"],
        ));

        // …AND A WIRE COMPOSED IN NO PLACE. "Exactly one" has two sides and the rule read one:
        // `> 1` passed a wire that is a member, built and shipped, and reachable from no registry —
        // and printed `stdio=unregistered` inside the green row's own detail. The plant takes the
        // one line that composes the wire out of the root.
        let name = "a wire composed in no place at all";
        let naming = ["unregistered-wire", "busbar-transport-stdio"];
        match wire_unregistered(cx, "stdio") {
            Ok(ov) => report.push(prove_rows_red(cx, self, name, &[ROW_WIRES], ov, &naming)),
            Err(why) => report.push(unplantable(name, &[ROW_WIRES], &naming, why)),
        }

        // THE ROOT'S MANIFEST ROW IS THE ONE REGISTRATION. A root that links a wire as data — a
        // `[package.metadata.busbar.linked]` row its build script folds — names it in no source
        // file, and the row is the one place. GREEN: the row alone registers the wire. RED: the
        // same row beside a source file composing the wire is two registries, the row one of them.
        let name = "a wire linked by the root's manifest row alone is registered once";
        match wire_linked_by_row(cx, "stdio") {
            Ok(ov) => report.push(prove_rows_green(cx, self, name, &[ROW_WIRES], ov)),
            Err(why) => report.push(unplantable(name, &[ROW_WIRES], &[], why)),
        }
        let name = "a manifest row and a source file registering one wire are two registrations";
        let naming = [
            "second-registration",
            "busbar-transport-stdio",
            LINKED_TABLE,
            "planted_wire_registry.rs",
        ];
        match wire_row_and_source(cx, "stdio") {
            Ok(ov) => report.push(prove_rows_red(cx, self, name, &[ROW_WIRES], ov, &naming)),
            Err(why) => report.push(unplantable(name, &[ROW_WIRES], &naming, why)),
        }

        // THE MATRIX ROW'S OWN CASES, owed by BOTH registrations: the per-push gate holds the
        // ceilings and the ship twin holds zero, and neither is a claim the other proves.
        matrix::selftest(cx, subject, self.ship, &mut report);

        if !self.ship {
            // A LISTED DRAIN EDGE IS GREEN. The owner's ruling, as the per-push gate reads it:
            // while a legacy crate drains it MAY name a unit, because a `[[transitional]]` row
            // names the edge.
            //
            // IT OWES ITS `[[dep]]` ROW TOO, and both halves of that are the point. The
            // transitional row says the EDGE CLASS is the drain rather than the fusion; the `[[dep]]`
            // row says how many declarations there are, exactly, so the drain cannot quietly grow a
            // second one. The plant APPENDS to the real manifest rather than rewriting it, because
            // a rewrite would strike busbar-llm's real edges and the dead-row findings that
            // produced are the ones a reader would mistake for this case's own. The transitional row
            // itself is planted alongside it, on `busbar-llm` — still a live LEGACY_CRATES member —
            // rather than on the now-retired `busbar-core`.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-llm/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-llm/Cargo.toml",
                    &format!("\n[dependencies]\n{PLANTED_UNIT} = {{ workspace = true }}\n"),
                ),
            );
            ov.set(
                REGISTRY_FILE,
                format!(
                    "{}\n\n[[transitional]]\nfrom = \"busbar-llm\"\nto = \"busbar-unit-*\"\n\
                     reason = \"planted\"\n\n[[dep]]\nfrom    = \"busbar-llm\"\n\
                     to      = \"{PLANTED_UNIT}\"\nhalf    = \"shipped\"\ncount   = \"1\"\n\
                     verdict = \"not-allowed\"\ncite    = \"the legacy drain: ARCHITECTURE.md 1.1 \
                     grants a legacy crate no unit edge, and the [[transitional]] row above names \
                     this one as the retirement in flight.\"\nwhy     = \"planted: proves the drain \
                     row and its own dep count both being present is green.\"\ndrain   = \"planted \
                     fixture; strike when the real drain lands.\"\n",
                    cx.read(REGISTRY_FILE).unwrap_or_default().trim_end()
                ),
            );
            report.push(prove_rows_green(
                cx,
                subject,
                "a legacy crate reaching a unit through a named transitional row and its own count",
                &[ROW_DEPS],
                ov,
            ));

            // AN ANNOUNCED CRATE LANDING IS GREEN — no unknown kind, no dead kind, no new edge
            // class. This is the case the announcement exists to make true: the agent who lands it
            // reds nothing. Planted, not borrowed, for the reason on the edge-class case above.
            let mut ov = registry_announcing(cx, "busbar-core-planted", "core");
            ov.set(
                "crates/busbar-core-planted/Cargo.toml",
                "[package]\nname = \"busbar-core-planted\"\nversion = \"0.0.0\"\n\n\
                 [dependencies]\nbusbar-substrate = { workspace = true }\n",
            );
            report.push(prove_rows_green(
                cx,
                subject,
                "an announced core crate landing reds nothing",
                &[ROW_NAME, ROW_DEPS, ROW_REGISTRY],
                ov,
            ));
            return report;
        }

        // ── THE SHIP TWIN'S RATCHETS ─────────────────────────────────────────────────────────────

        // THE CONTROL PATH IS A SHIP CRITERION, and the row is red on this tree on purpose:
        // `busbar-plane-admin` still implements the `Plane` trait, so it still declares `route` and
        // `meter` and still names `encode_egress`. That is the R7 work, not a defect somebody can
        // fix this week, so it is owed by the DONE oracle on the same terms as `:shape` — and each
        // case below plants a NAMED, NEW deviation, because "the row went red" would be satisfied
        // by the debt the criterion is about.
        //
        // RE-TARGETED (item 89): the plants were a `busbar-control-planted` crate — but `control`
        // is not a kind (DECISIONS #5) and that name resolves to none, so the rule, which reads the
        // `cleanliness` surfaces, never saw it: both cases came back GREEN once the row's standing
        // debt stopped hiding them. The surface is a real cleanliness crate, `busbar-oauth2`.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-oauth2/src/planted_route.rs",
            "pub struct P;\nimpl P {\n    fn route(&self) -> u8 { 0 }\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a control surface implementing a data-path step",
            &[ROW_CONTROL],
            ov,
            &[
                "data-path-step",
                "planted_route.rs",
                "busbar-oauth2",
                "route",
            ],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-oauth2/src/planted_pool.rs",
            "pub fn pick(pool: u8) -> u8 { let failover = pool; failover }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a control surface naming the vocabulary of reaching an upstream",
            &[ROW_CONTROL],
            ov,
            &["upstream", "busbar-oauth2", "pool"],
        ));

        // A TRANSITIONAL ROW WHOSE CRATE IS STILL HERE AT SHIP TIME IS RED. The exemption's expiry
        // rule is the crate, not the edge.
        //
        // PROVEN AS A TRANSITION, FROM A SCRATCH TREE WHERE THE ROW IS GREEN. The real tree cannot
        // be the baseline: every legacy crate is still in it, so `:legacy-drain` is red there BY
        // DESIGN and no plant against it can be told apart from that standing red. This case used
        // to plant an EMPTY overlay — which the harness refuses before the gate runs — and assert
        // `busbar-core`, a crate absorbed into `busbar-kernel` that is the `from` of no row. So the
        // baseline is a table with no rows (green: nothing to expire), and the plant is ONE row for
        // a legacy crate that really is on disk. The row goes red and names that crate.
        //
        // THE SHIPPED GATE, NOT THE DEBT-FREE SUBJECT: this case already brings its own green base
        // (the empty table), and the subject's debt — measured over the REAL table, whose
        // `busbar-voice` row is exactly this plant's row — would take the planted finding out of
        // view as if it were the tree's. The pair below is the same transition read the other way.
        report.push(prove_rows_red(
            &cx.with_overlay(registry_plant("")),
            self,
            "a transitional row is red at ship time while its legacy crate still exists",
            &[ROW_DRAIN],
            drain_row_plant(),
            &["transitional-live", DRAIN_PLANT_FROM, "ship"],
        ));

        // …AND GREEN WHEN THE DRAIN IS ACTUALLY DONE: the SAME row, over a tree whose crate is
        // gone. The pair differs in exactly one thing — whether the row's `from` crate exists — so
        // together they prove the expiry is the crate. Without this case the row above would
        // equally be produced by a ratchet that is simply red for ever. Every path this removes is
        // one the tree has (the removal of the absorbed `busbar-core` was a no-op).
        let mut ov = drain_row_plant();
        ov.remove(format!("crates/{DRAIN_PLANT_FROM}/Cargo.toml"));
        report.push(prove_rows_green(
            cx,
            self,
            "a transitional row whose legacy crate is gone is not held against the ship",
            &[ROW_DRAIN],
            ov,
        ));

        // AN ANNOUNCEMENT DOES NOT SURVIVE ITS LANDING PAST A RELEASE. Landing an announced crate
        // is green on the per-push gate (proven above); on the ship sha the spent row is collected.
        // Planted, not borrowed, for the reason on the edge-class case above.
        let mut ov = registry_announcing(cx, "busbar-core-planted", "core");
        ov.set(
            "crates/busbar-core-planted/Cargo.toml",
            "[package]\nname = \"busbar-core-planted\"\nversion = \"0.0.0\"\n\n\
             [dependencies]\nbusbar-substrate = { workspace = true }\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an announcement whose crate has landed is collected at ship time",
            &[ROW_REGISTRY],
            ov,
            &["announced-landed", "busbar-core-planted"],
        ));

        // THE SHIP ROWS. Each plant makes a NAMED, NEW deviation, because both rows are already
        // red on this tree: "the gate went red" would be satisfied by the debt the criterion is
        // about, and would prove nothing about the rule.
        // THE SHIP TWIN'S OWN DEPENDENCY PROOF, both halves. It does not read the ledger, so every
        // ledger case above would produce the red it already produces; these two make a NAMED, NEW
        // deviation instead — a class the architecture grants nowhere, between two crates that have
        // no edge at all today.
        report.push(prove_rows_red(
            cx,
            subject,
            "at the architecture's own graph, a transport reaching a plane is a NEW refusal",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-transport-stdio",
                "busbar-transport-stdio",
                &["busbar-contract", "busbar-plane-llm"],
            ),
            &[
                "ship-edge",
                "busbar-transport-stdio -> busbar-plane-llm",
                "the architecture grants no transport -> plane edge",
            ],
        ));

        // AND THE SAME IN THE TEST GRAPH. The two halves are two claims and each owes its own
        // proof: a `test-deps` row nothing plants against is a row that could be deleted with this
        // battery still green.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-stdio/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-transport-stdio/Cargo.toml",
                "\n[dev-dependencies]\nbusbar-plane-llm = { workspace = true }\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "at the architecture's own graph, a transport TEST-reaching a plane is refused too",
            &[ROW_TEST_DEPS],
            ov,
            &[
                "ship-edge",
                "busbar-transport-stdio -> busbar-plane-llm",
                "dev-dependencies",
            ],
        ));

        report.push(prove_rows_red(
            cx,
            subject,
            "a crate of a kind with no lib.rs at all",
            &[ROW_SHAPE],
            manifest_plant(
                "crates/busbar-transport-planted",
                "busbar-transport-planted",
                &[],
            ),
            &["no-lib", "busbar-transport-planted"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_second_entry.rs",
            "pub struct Second;\nimpl Transport for Second {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a second entry implementation in one crate of a kind",
            &[ROW_SHAPE],
            ov,
            &["entry-count", "busbar-transport-tcp"],
        ));

        // A GENERIC ENTRY IMPL IS AN ENTRY IMPL. `impl_trait_on` read `impl ` and stopped, so
        // `impl<S: CellStore> Unit for AdmissionUnit<'_, S>` — the shape three unit crates are
        // written in — counted ZERO, and those crates reported an entry count of 0 forever while
        // implementing their trait in plain sight. This plant adds a SECOND entry implementation in
        // the generic spelling and nothing else: with the generic parameter list parsed the count is
        // 2 and the rule fires; without it the count is 1, the rule is silent, and this case is
        // GREEN. That is the whole difference, and it is what the case is here to hold.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_generic_entry.rs",
            "pub struct Generic<'a, S>(&'a S);\n\
             impl<'a, S: Send + Sync> Transport for Generic<'a, S> {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "an entry implementation written with generic parameters is counted",
            &[ROW_SHAPE],
            ov,
            &["entry-count", "busbar-transport-tcp", "2 time(s)"],
        ));

        // THE SKELETON IS THE SPEC'S, NOT THE EXEMPLAR'S FILE LIST. This crate declares `meta` and
        // nothing else, so it is missing EXACTLY ONE thing: its kind's entry file. Under the old
        // rule — the exemplar's own top-level modules — it would have been charged with ten,
        // `busbar-unit-auth`'s domain among them (`carrier`, `challenge`, `principal`, …), and the
        // only way to go green would have been to copy another crate's subject matter. The count in
        // the naming is what pins the difference.
        let mut ov = manifest_plant("crates/busbar-unit-planted", "busbar-unit-planted", &[]);
        ov.set("crates/busbar-unit-planted/src/lib.rs", "pub mod meta;\n");
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate of a kind is judged against its kind's skeleton, not the exemplar's file list",
            &[ROW_SHAPE],
            ov,
            &[
                "busbar-unit-planted",
                "is missing 1 of the `unit` skeleton",
                "PLUGIN-TREE.md §3): unit",
            ],
        ));

        report.push(prove_rows_red(
            cx,
            subject,
            "a crate of a kind that does not run its kind's shared battery",
            &[ROW_TESTKIT],
            manifest_plant("crates/busbar-store-planted", "busbar-store-planted", &[]),
            &["not-run", "busbar-store-planted"],
        ));

        // A BATTERY FILE IS NOT A BATTERY. This crate carries `tests/conformance.rs` and a `testkit`
        // dev-dependency — everything the rule used to ask — and every entry in it is `#[ignore]`d,
        // so `cargo test` runs none of it. The rule detected the FILE and the DEV-DEPENDENCY, and
        // neither of those executes; a whole kind's conformance can be switched off with one
        // attribute per test and a reason that names the very work being gated.
        let mut ov = manifest_plant(
            "crates/busbar-store-ignored",
            "busbar-store-ignored",
            &["busbar-contract"],
        );
        ov.set(
            "crates/busbar-store-ignored/src/lib.rs",
            "pub struct P;\nimpl Store for P {}\n",
        );
        ov.set(
            "crates/busbar-store-ignored/tests/conformance.rs",
            "#[test]\n#[ignore = \"not yet on busbar-contract: the battery is owed\"]\n\
             fn kind_is_declared_once() {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a conformance battery whose every entry is ignored is not a battery",
            &[ROW_TESTKIT],
            ov,
            &["battery-ignored", "busbar-store-ignored"],
        ));

        // A BATTERY WITH NO SUBJECT. The same crate, with a live battery and no implementor of its
        // kind's trait anywhere in shipped source: the file compiles, the battery passes, and it is
        // evidence about nothing this crate ships.
        let mut ov = manifest_plant(
            "crates/busbar-store-subjectless",
            "busbar-store-subjectless",
            &["busbar-contract"],
        );
        ov.set(
            "crates/busbar-store-subjectless/src/lib.rs",
            "pub struct P;\n",
        );
        ov.set(
            "crates/busbar-store-subjectless/tests/conformance.rs",
            "#[test]\nfn kind_is_declared_once() {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a crate of a kind that implements its kind's trait nowhere has no subject to conform",
            &[ROW_TESTKIT],
            ov,
            &["no-implementor", "busbar-store-subjectless", "Store"],
        ));

        // ── THE THREE SHIP FINDINGS WITH NO CASE ─────────────────────────────────────────────────
        //
        // `:shape` and `:testkit` derive what they demand: the skeleton and the single entry come
        // from the kind's EXEMPLAR, and the battery is whichever one the kind's members already run.
        // Both derivations have a degenerate answer — no exemplar, no entry, no battery — and in
        // each of them the rule keeps going and judges every crate of the kind against nothing. A
        // mutation campaign found all three unproven.

        // THE EXEMPLAR ITSELF IS NOT IN THE TREE. `busbar-plane-a2a` is the canonical plane; without
        // it the `plane` skeleton is derived from an empty file list and every plane in the tree
        // passes a comparison against nothing.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-plane-a2a/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            subject,
            "a kind whose canonical exemplar is not in the tree derives its skeleton from nothing",
            &[ROW_SHAPE],
            ov,
            &["no-exemplar", "busbar-plane-a2a"],
        ));

        // THE EXEMPLAR STATES NO SINGLE ENTRY. A second `impl Plane for …` in the canonical plane
        // makes the kind's entry count TWO, and `entry-count` — the rule that holds every other
        // plane to exactly one — is guarded on the exemplar stating exactly one, so it goes quiet
        // for the whole kind. The finding is that the spec stopped saying anything, and it is a
        // finding rather than a silence.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-a2a/src/planted_second_entry.rs",
            "pub struct Second;\nimpl Plane for Second {}\n",
        );
        report.push(prove_rows_red(
            cx,
            subject,
            "a kind whose exemplar states no single entry states nothing every member owes",
            &[ROW_SHAPE],
            ov,
            &["no-entry", "busbar-plane-a2a", "2 time(s)"],
        ));

        // A KIND WITH NO SHARED BATTERY AT ALL. The `plane` kind's battery is the one its members
        // already run — `tests/conformance.rs` in `busbar-plane-a2a` and `busbar-plane-mcp`. Take
        // both away and the kind has no battery to be judged against, so `not-run` (which is
        // guarded on there being one) says nothing about the other planes at all.
        //
        // EVERY plane's battery file, read off the tree (item 89): the case named two, and two more
        // planes (`decision`, `streaming`) have run it since — so removing two left a battery the
        // kind still had, and the row said `not-run` instead of `no-battery`.
        let ov = move || {
            let mut ov = Overlay::new();
            if let Ok(rels) = cx.list(&WalkSpec::new(["crates"]).ext("rs")) {
                for rel in rels {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if rel.starts_with("crates/busbar-plane-")
                        && rel.ends_with("/tests/conformance.rs")
                    {
                        ov.remove(rel);
                    }
                }
            }
            ov
        };
        report.push(prove_rows_red(
            cx,
            subject,
            "a kind no member of which runs any shared battery has no battery, and is told so",
            &[ROW_TESTKIT],
            ov,
            &["no-battery", "kind:plane"],
        ));

        // ── THE SHIP TWIN'S OWN FLOORS: ZERO IS A REFUSAL, NOT A CLEAN TREE ──────────────────────
        //
        // Four rules on this twin have the size of their own input as their subject, and a mutation
        // campaign found not one of them proven: `if false && checked == 0`, `if false &&
        // controls.is_empty()` and `.min_files(0)` each left the battery green. Every one of them
        // reads, when starved, EXACTLY like the tree the criterion is asking for — no crate deviates
        // from a skeleton nobody compared, no crate skips a battery nobody looked for, no surface
        // strays off a path nobody walked — which is why a floor nothing proves is a floor somebody
        // deletes as dead code and a criterion that then passes on an empty tree.

        // NO CRATE OF ANY EXEMPLAR KIND REACHED `:shape`. The census is intact and readable; what it
        // no longer holds is a single crate of the three kinds that HAVE an exemplar, so the rule
        // compared every crate of a kind against its skeleton and found nothing to compare.
        report.push(prove_rows_red(
            cx,
            subject,
            "no crate of any exemplar kind reached the shape rule is refused, not read as clean",
            &[ROW_SHAPE],
            move || kinds_gone(cx, &["plane", "transport", "unit"]),
            &["0 crate(s) reached the shape rule"],
        ));

        // NO CRATE OF ANY BATTERY KIND REACHED `:testkit` — the same starvation over the nine kinds
        // that owe a shared conformance battery. Zero crates skip every battery.
        report.push(prove_rows_red(
            cx,
            subject,
            "no crate of any battery kind reached the battery rule is refused, not read as clean",
            &[ROW_TESTKIT],
            move || kinds_gone(cx, BATTERY_KINDS),
            &["0 crate(s) reached the battery rule"],
        ));

        // NO CONTROL SURFACE REACHED `:control-path`. The rule reads the `cleanliness` kind
        // (admin/oauth2, DECISIONS #5), so the honest fixture for "this rule looked at no surface
        // at all" is every crate of THAT kind out of the census. Zero surfaces run zero data-path
        // steps and name zero upstreams, which reads exactly like a control kind that keeps to its
        // own path.
        //
        // It asked for `kinds_gone(["control"])`, a kind no crate resolves to: the overlay was
        // empty, the harness refused it, and the floor had no proof. And it cannot be proven from
        // the real tree either, whose `:control-path` is red today on the surfaces' own findings —
        // so the baseline is the same tree with those surfaces' sources blanked (green over the
        // surfaces that remain), and the plant takes the surfaces out of the census.
        let clean = control_surfaces_clean(cx);
        let base = cx.with_overlay(clean);
        report.push(prove_rows_red(
            &base,
            subject,
            "no control surface reached the control-path rule is refused, not read as clean",
            &[ROW_CONTROL],
            kinds_gone(&base, &[CLEANLINESS]),
            &["0 control crate(s)"],
        ));

        // THE SOURCE INDEX IS THESE TWO ROWS' OWN INPUT, and it has a floor of its own. An index
        // built over four files knows of no lib.rs, no entry implementation and no battery anywhere
        // — which is the same silence as a tree in which every crate of every kind is correct. Both
        // ship rows owe the refusal, and they owe it together, because they read ONE index.
        report.push(prove_rows_red(
            cx,
            subject,
            "the source index below its floor is refused on both ship rows, not read as no findings",
            &[ROW_SHAPE, ROW_TESTKIT],
            move || all_but(cx, "rs", 4),
            &["the source index did not run", &MIN_SOURCES.to_string()],
        ));

        report
    }
}

/// THE ROWS THAT CARRY OWNED DEBT ON TODAY'S TREE, and so cannot sit in the self-test's unplanted
/// green arm (item 89). This is not an exemption: every one of them is RED on `gate kind-isolation`,
/// and every one of them is proven RED-able by planted cases run against the debt-free subject.
/// When Phase 4 drains a row it comes off this list and back into the green arm.
const STANDING_DEBT_ROWS: &[&str] = &[
    ROW_DEPS,
    ROW_TEST_DEPS,
    ROW_CLOSURE,
    ROW_REGISTRY,
    ROW_MATRIX,
];

/// A planted [`REGISTRY_FILE`], holding `rows` and nothing else. The real file's comments carry the
/// reasoning; a plant carries only the rows under test, so what a case proves is what it wrote.
fn registry_plant(rows: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(REGISTRY_FILE, rows.to_string());
    ov
}

/// THE UNIT AND THE SUBSTRATE CRATE THE DRAIN AND EDGE-CLASS CASES PLANT A DEPENDENCY ON. Each
/// must be a package the census knows: `measure_edges` and the drain refusal both skip a
/// declaration whose package is absent, so an edge onto a name the tree does not have is an edge
/// that is never scored — the two cases that named `busbar-unit-audit` and `busbar-substrate`
/// (both folded away) planted exactly that. The exit test holds both to the census.
const PLANTED_UNIT: &str = "busbar-unit-transport-key";
const PLANTED_SUBSTRATE: &str = "busbar-substrate-values";

/// An announced `core` crate landing with a dependency on the substrate and on a unit.
fn core_announced_reaching_unit(cx: &Ctx) -> Overlay {
    let mut ov = registry_announcing(cx, "busbar-core-planted", "core");
    ov.set(
        "crates/busbar-core-planted/Cargo.toml",
        format!(
            "[package]\nname = \"busbar-core-planted\"\nversion = \"0.0.0\"\n\n\
             [dependencies]\n{PLANTED_SUBSTRATE} = {{ workspace = true }}\n\
             {PLANTED_UNIT} = {{ workspace = true }}\n"
        ),
    );
    ov
}

/// THE LEGACY CRATE THE DRAIN PAIR IS ABOUT. It must be a `legacy` crate that is really on disk,
/// or the red case plants a row for nothing and the green case removes a manifest that is not there.
const DRAIN_PLANT_FROM: &str = "busbar-voice";

/// ONE `[[transitional]]` row for [`DRAIN_PLANT_FROM`], and no other row — the red case's plant
/// and, with the crate removed, the green case's.
fn drain_row_plant() -> Overlay {
    registry_plant(&format!(
        "[[transitional]]\nfrom = \"{DRAIN_PLANT_FROM}\"\nto = \"busbar-plane-streaming\"\nreason = \
         \"legacy drain\"\n"
    ))
}

/// `busbar-oauth2` — a `cleanliness` crate — declaring a wire.
fn cleanliness_reaches_wire() -> Overlay {
    manifest_plant(
        "crates/busbar-oauth2",
        "busbar-oauth2",
        &["busbar-contract", "busbar-transport-http"],
    )
}

/// A plane declaring the `cleanliness` crate `busbar-oauth2`.
fn plane_reaches_cleanliness() -> Overlay {
    manifest_plant(
        "crates/busbar-plane-mcp",
        "busbar-plane-mcp",
        &["busbar-contract", "busbar-oauth2"],
    )
}

/// A `cleanliness` crate's source naming the plane-no-money vocabulary.
fn cleanliness_names_money() -> Overlay {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-oauth2/src/planted_money.rs",
        "pub fn charge(card: u32) -> u32 { let rate_card = card; let fee_cents = rate_card; \
         fee_cents }\n",
    );
    ov
}

/// The route one planted `cleanliness` surface and the real one both claim.
const PLANTED_ROUTE: &str =
    "pub const P: &[PathSeg] = &[PathSeg::Lit(\"api\"), PathSeg::Lit(\"v1\"), \
                             PathSeg::Lit(\"admin\"), PathSeg::Tail];\n";

/// `busbar-admin` landed beside `busbar-oauth2` — both `cleanliness` by NAME (the kind's matchers
/// are exact) — and both claiming [`PLANTED_ROUTE`].
fn cleanliness_shared_route() -> Overlay {
    let mut ov = manifest_plant("crates/busbar-admin", "busbar-admin", &["busbar-contract"]);
    ov.set("crates/busbar-admin/src/claims.rs", PLANTED_ROUTE);
    ov.set("crates/busbar-oauth2/src/claims.rs", PLANTED_ROUTE);
    ov
}

/// `busbar-admin` landed, and a `[[registered]]` row still saying it is `cleanliness` — which its
/// name already resolves it to.
fn redundant_registration() -> Overlay {
    let mut ov = manifest_plant("crates/busbar-admin", "busbar-admin", &["busbar-contract"]);
    ov.set(
        REGISTRY_FILE,
        format!(
            "[[registered]]\ncrate = \"busbar-admin\"\nkind = \"{CLEANLINESS}\"\nreason = \
             \"planted\"\n"
        ),
    );
    ov
}

/// A `[[registered]]` row, of a kind the table has, for a crate the tree does not have.
fn dead_registration() -> Overlay {
    registry_plant(
        "[[registered]]\ncrate = \"busbar-ghost-registered\"\nkind = \"store\"\nreason = \
         \"planted\"\n",
    )
}

/// THE CONTROL-PATH RULE'S SCRATCH BASELINE: the real tree with every source file of every
/// `cleanliness` crate emptied, so the surfaces stay in the census and name nothing. The row is
/// green over them, which is the state the starvation floor's transition is measured from.
fn control_surfaces_clean(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    let Ok(crates) = census(cx) else {
        return ov;
    };
    for c in crates.iter().filter(|c| c.kind == Some(CLEANLINESS)) {
        let Ok(files) = cx.walk(&WalkSpec::new([c.dir.as_str()]).ext("rs")) else {
            continue;
        };
        for f in &files {
            ov.set(f.rel_str(), "\n".to_string());
        }
    }
    ov
}

/// The composition root with the one line that composes `wire` taken out — the wire is then a
/// member of the tree, built and shipped, and registered NOWHERE.
fn wire_unregistered(cx: &Ctx, wire: &str) -> Result<Overlay, String> {
    let (source, manifest) = (wire_source_unnamed(cx, wire)?, wire_row(cx, wire, false)?);
    if source.is_none() && manifest.is_none() {
        return Err(format!(
            "neither {WIRE_ROOT_SOURCE} nor a {LINKED_TABLE} row in {WIRE_ROOT_MANIFEST} registers \
             `{wire}` to plant over"
        ));
    }
    let mut ov = Overlay::new();
    for (path, text) in source.into_iter().chain(manifest) {
        ov.set(path, text);
    }
    Ok(ov)
}

/// The root source file and manifest the wire-registration plants edit.
const WIRE_ROOT_SOURCE: &str = "crates/busbar/src/root/registry.rs";
const WIRE_ROOT_MANIFEST: &str = "crates/busbar/Cargo.toml";

/// The root source with its `use busbar_transport_<wire>::<Wire>Transport;` line taken out, or
/// `None` when it names no such line.
fn wire_source_unnamed(cx: &Ctx, wire: &str) -> Result<Option<(String, String)>, String> {
    let text = cx.read(WIRE_ROOT_SOURCE)?;
    let line = format!(
        "use busbar_transport_{}::{};\n",
        wire.replace('-', "_"),
        wire_symbol(wire)
    );
    Ok(text
        .contains(&line)
        .then(|| (WIRE_ROOT_SOURCE.to_string(), text.replacen(&line, "", 1))))
}

/// The root manifest with a `LINKED_TABLE` row for `busbar-transport-<wire>` put in (`present`) or
/// taken out, or `None` when it already reads that way.
fn wire_row(cx: &Ctx, wire: &str, present: bool) -> Result<Option<(String, String)>, String> {
    let text = cx.read(WIRE_ROOT_MANIFEST)?;
    let krate = format!("busbar-transport-{wire}");
    if linked_crates(&text).contains(&krate) == present {
        return Ok(None);
    }
    let header = text
        .find(LINKED_TABLE)
        .ok_or_else(|| format!("{WIRE_ROOT_MANIFEST} has no {LINKED_TABLE} to plant into"))?;
    let edited = if present {
        let at = header + LINKED_TABLE.len();
        format!(
            "{}\nplanted-{wire} = \"{krate}\"{}",
            &text[..at],
            &text[at..]
        )
    } else {
        let row = format!("= \"{krate}\"");
        text.lines()
            .filter(|l| !l.trim_end().ends_with(&row))
            .map(|l| format!("{l}\n"))
            .collect()
    };
    Ok(Some((WIRE_ROOT_MANIFEST.to_string(), edited)))
}

/// THE WIRE REGISTERED BY ITS MANIFEST ROW ALONE: the row is in, the root source names it nowhere.
fn wire_linked_by_row(cx: &Ctx, wire: &str) -> Result<Overlay, String> {
    let mut ov = Overlay::new();
    for (path, text) in wire_source_unnamed(cx, wire)?
        .into_iter()
        .chain(wire_row(cx, wire, true)?)
    {
        ov.set(path, text);
    }
    Ok(ov)
}

/// …AND THE SAME ROW BESIDE A SOURCE FILE THAT COMPOSES THE WIRE: two registries.
fn wire_row_and_source(cx: &Ctx, wire: &str) -> Result<Overlay, String> {
    let mut ov = wire_linked_by_row(cx, wire)?;
    ov.set(
        "crates/busbar/src/root/planted_wire_registry.rs",
        format!(
            "use busbar_transport_{}::{};\n",
            wire.replace('-', "_"),
            wire_symbol(wire)
        ),
    );
    Ok(ov)
}

/// THE TREE WITH ALMOST EVERY FILE OF ONE EXTENSION REMOVED, for the two floors.
///
/// A floor is the only rule whose subject is the SIZE of its own input, so the only honest fixture
/// for one is a tree that really is that small. `keep` files survive, which is what makes the two
/// floors fail APART: four manifests is under the census floor and nowhere near the source floor,
/// and four sources are the mirror.
fn all_but(cx: &Ctx, ext: &str, keep: usize) -> Overlay {
    let mut ov = Overlay::new();
    let Ok(files) = cx.walk(&WalkSpec::new(["crates"]).ext(ext)) else {
        return ov;
    };
    for f in files.iter().skip(keep) {
        ov.remove(f.rel_str());
    }
    ov
}

/// THE CENSUS HELD AT EXACTLY `n` MANIFESTS — item F0b's boundary fixture.
///
/// `all_but` thins the `crates/` walk, but [`census`] also reads root/`xtask`/`examples`/`testing`
/// manifests the registry's off-tree table does not cover, so "keep 29 files under `crates/`" and
/// "the census is 29" are not the same claim near the new, much lower floor — they were 24 apart at
/// the old floor of 50 and nobody had to tell them apart. This removes exactly enough CENSUSED
/// `crates/` manifests, and only those, to land the real census at `n`, so a boundary case can plant
/// the number the floor actually reads rather than a number of files that merely implies it.
///
/// A `#[cfg(test)]`-only fixture: unlike `all_but`, its only caller is the two boundary cases in
/// `plant_tests`, run through `cargo test`, not the `prove_rows_red` battery `cargo xtask selftest`
/// runs (item 89's IMPOSS rule is why — see those cases' own comment).
#[cfg(test)]
fn census_holding(cx: &Ctx, n: usize) -> Overlay {
    let full = census(cx).unwrap_or_default();
    let excess = full.len().saturating_sub(n);
    let mut ov = Overlay::new();
    for c in full
        .iter()
        .filter(|c| c.manifest.starts_with("crates/"))
        .take(excess)
    {
        ov.remove(c.manifest.clone());
    }
    ov
}

/// THE TREE WITH EVERY CRATE OF THE NAMED KINDS OUT OF THE CENSUS — the floors' own fixture.
///
/// A rule whose subject is "no crate of any of these kinds reached me" cannot be proven by a plant
/// that adds one, and it cannot be proven by a path prefix either: a crate's KIND is what the
/// census resolves its PACKAGE NAME to (and what a `[[registered]]` row may override), not what its
/// directory is spelled. `crates/store-memory` is `busbar-store-memory`, `crates/busbar-plane-admin`
/// is registered `control` — a marker over paths would miss the first and mis-file the second. So
/// this reads the same census the rule reads and removes the manifest of every crate it resolves to
/// one of `kinds`, which is what makes a crate leave a census.
fn kinds_gone(cx: &Ctx, kinds: &[&str]) -> Overlay {
    let mut ov = Overlay::new();
    let Ok(crates) = census(cx) else {
        return ov;
    };
    for c in &crates {
        if c.kind.is_some_and(|k| kinds.contains(&k)) {
            ov.remove(&c.manifest);
        }
    }
    ov
}

/// THE CENSUS HELD AWAY FROM ITS FLOOR under a plant that removes `removed` manifests.
///
/// [`MIN_MANIFESTS`] is 30 (item F0b); the Phase 4 fold walks the real census down toward that
/// number one commit at a time, so a plant elsewhere in this battery that removes a manifest for a
/// reason of its own — a dead kind, a retired alias, a struck legacy row — can, late in the fold,
/// land close enough to the floor that the removal ALSO drops the census below it. When that
/// happens the floor refusal, its own proven case, answers for the whole `:registry` row: `the
/// crate census collapsed below its floor`, and never the rule the case is about. The floor is not
/// lowered. Each removed manifest is replaced by one inert kernel-kind filler crate, so the census
/// stays a census and the row judges what was planted.
fn hold_census_floor(ov: &mut Overlay, removed: usize) {
    for i in 0..removed {
        ov.set(
            format!("crates/busbar-kernel-censusfill{i}/Cargo.toml"),
            format!("[package]\nname = \"busbar-kernel-censusfill{i}\"\nversion = \"0.0.0\"\n"),
        );
    }
}

/// THE TREE WITH EVERY MANIFEST UNDER `crates/<marker>*` REMOVED — a whole KIND deleted.
///
/// A rule whose subject is "this tree has no crate of kind K at all" cannot be proven by a plant
/// that adds one; the only honest fixture is a census that really has none, and a crate leaves the
/// census when its manifest does.
fn kind_gone(cx: &Ctx, marker: &str) -> Overlay {
    let mut ov = Overlay::new();
    let Ok(files) = cx.walk(&WalkSpec::new(["crates"]).ext("toml")) else {
        return ov;
    };
    for f in files.iter() {
        let rel = f.rel_str();
        if rel.starts_with(&format!("crates/{marker}")) && rel.ends_with("/Cargo.toml") {
            ov.remove(rel);
        }
    }
    ov
}

/// The REAL registry file with one `[[announced]]` row APPENDED — the landing window, planted.
///
/// The two real announcements (`busbar-core-config`, `busbar-core-hooks`) were struck on 2026-09-22
/// when DECISIONS #37 killed both crates, leaving the table empty. The announcement RULES did not go
/// with them, so the cases that exercise them plant their own row instead of borrowing whatever the
/// tree happens to be announcing that week — which is the more honest fixture either way: a case
/// whose subject is a live row goes dark the day that row lands or dies, and says nothing while it
/// does.
///
/// Appended to the whole file rather than planted alone, for the same reason [`registry_subst`] gives:
/// a ledger of 220 rows is not something a plant of one row can stand in for.
fn registry_announcing(cx: &Ctx, name: &str, kind: &str) -> Overlay {
    let text = cx.read(REGISTRY_FILE).unwrap_or_default();
    let mut ov = Overlay::new();
    ov.set(
        REGISTRY_FILE,
        format!(
            "{}\n\n[[announced]]\ncrate = \"{name}\"\nkind = \"{kind}\"\nreason = \"planted by \
             the kind-isolation selftest: the announcement window, owning no real crate\"\n",
            text.trim_end()
        ),
    );
    ov
}

/// The REAL registry file with one run of text rewritten, so a case can leave slack in a row, grant
/// it an edge the architecture withholds, strike a question or double a row — against the whole
/// file rather than a synthetic one, because a ledger of 220 rows is exactly the thing a plant of
/// three rows cannot stand in for.
///
/// A NEEDLE THAT IS NO LONGER IN THE FILE IS AN UNPLANTABLE CASE, NEVER A QUIET NO-OP. This was a
/// bare `replacen` with no needle check for as long as it existed, and `replacen` over a needle
/// that is not there returns the string it was given: the overlay then wrote the ledger back
/// BYTE-FOR-BYTE, the gate read the tree it would have read unplanted, and the case scored
/// whatever that tree scores. Nine cases in this battery were doing exactly that — every one of
/// them anchored on a `count = "…"` the ratchet had since re-pinned or a crate the tree had since
/// renamed — and every one of them was PASSING, because the row they cover is red on this tree
/// either way. `Expect::Inert` names that shape now, and this refuses to produce it.
fn registry_subst(cx: &Ctx, from: &str, to: &str) -> Result<Overlay, String> {
    let text = cx.read(REGISTRY_FILE)?;
    if !text.contains(from) {
        return Err(format!(
            "`{}` is not in {REGISTRY_FILE} to plant over",
            from.replace('\n', " / ")
        ));
    }
    let mut ov = Overlay::new();
    ov.set(REGISTRY_FILE, text.replacen(from, to, 1));
    Ok(ov)
}

/// NOTHING TO PLANT IS A VISIBLE CASE, counted as unproven — never a silent green. The shape
/// `ci_umbrella` and `service_images` already use at the same door.
pub(super) fn unplantable(
    name: &str,
    covers: &[&str],
    naming: &[&str],
    why: String,
) -> crate::gates::Case {
    crate::gates::Case {
        name: format!("{name} ({why})"),
        covers: covers.iter().map(|s| (*s).to_string()).collect(),
        expected: crate::gates::Expect::Red {
            naming: naming.iter().map(|s| (*s).to_string()).collect(),
        },
        got: crate::gates::Expect::Skipped,
    }
}

/// [`prove_rows_red`] over a ONE-SUBSTITUTION plant into the real registry, with the substitution
/// given as the `(anchor, replacement)` the caller worked out — `Err` when the anchor could not be
/// read off the ledger at all, which is the case saying so rather than planting nothing.
fn plant_registry<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    subst: Result<(String, String), String>,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    match subst.and_then(|(from, to)| registry_subst(cx, &from, &to)) {
        Ok(ov) => prove_rows_red(cx, gate, name, covers, ov, naming),
        Err(why) => unplantable(name, covers, naming, why).into(),
    }
}

/// The four lines that open the SHIPPED `[[dep]]` row for `from -> to`, down to the opening quote
/// of its count.
fn dep_head(from: &str, to: &str) -> String {
    format!("from    = \"{from}\"\nto      = \"{to}\"\nhalf    = \"shipped\"\ncount   = \"")
}

/// The same four lines with a count written into them.
fn dep_row(from: &str, to: &str, count: &str) -> String {
    format!("{}{count}\"", dep_head(from, to))
}

/// THE SHIPPED `[[dep]]` ROW FOR `from -> to` AS THE LEDGER SPELLS IT TODAY, count included.
///
/// A FIXTURE MAY NOT HARD-CODE A RATCHET VALUE. `count` is TODAY'S MEASUREMENT by construction and
/// is re-pinned by every landing that moves the edge; a plant that quotes one is a plant with an
/// expiry date nobody diarised, and the three `[[dep]]` cases below spent that expiry silently.
/// The crate names are NOT derived — those move only when a landing renames a crate, and
/// [`registry_subst`] now makes that loud — but the number is read off the file every run.
fn dep_anchor(cx: &Ctx, from: &str, to: &str) -> Result<String, String> {
    let text = cx.read(REGISTRY_FILE)?;
    let head = dep_head(from, to);
    let at = text.find(&head).ok_or_else(|| {
        format!("no shipped `[[dep]]` row for {from} -> {to} in {REGISTRY_FILE} to plant over")
    })?;
    let rest = &text[at + head.len()..];
    let end = rest.find('"').ok_or_else(|| {
        format!("the shipped `[[dep]]` row for {from} -> {to} has an unterminated `count`")
    })?;
    Ok(format!("{head}{}\"", &rest[..end]))
}

/// That row, and the same row with `count` moved to `count`.
fn dep_subst(cx: &Ctx, from: &str, to: &str, count: &str) -> Result<(String, String), String> {
    Ok((dep_anchor(cx, from, to)?, dep_row(from, to, count)))
}

/// That row, with its `verdict` flipped from `not-allowed` to `allowed` — the ledger granting
/// itself an edge the architecture withholds, with the count read off the file rather than copied
/// into the fixture.
fn verdict_subst(cx: &Ctx, from: &str, to: &str) -> Result<(String, String), String> {
    let anchor = dep_anchor(cx, from, to)?;
    Ok((
        format!("{anchor}\nverdict = \"not-allowed\""),
        format!("{anchor}\nverdict = \"allowed\""),
    ))
}

/// THE `from`/`to` PAIR OF THE FIRST `[[transitional]]` ROW, exactly as the ledger spells it.
///
/// Two lines rather than one because `to = "…"` is not unique in a file that also carries an
/// `[[edge]]` table, and derived rather than written out because this table IS THE DRAIN: every row
/// in it is there to be deleted, so a fixture that names one names a row whose whole purpose is to
/// stop existing. The case that used to name `to = "busbar-unit-*"` outlived the last glob in the
/// table by however long it has been since one was written.
fn transitional_anchor(cx: &Ctx) -> Result<(String, String), String> {
    let text = cx.read(REGISTRY_FILE)?;
    let at = text
        .find("\n[[transitional]]\n")
        .ok_or_else(|| format!("no `[[transitional]]` row in {REGISTRY_FILE} to plant over"))?;
    let mut from = None;
    for line in text[at + 1..].lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if line.starts_with("from = \"") {
            from = Some(line.to_string());
        }
        if let (Some(from), true) = (&from, line.starts_with("to = \"")) {
            return Ok((from.clone(), line.to_string()));
        }
    }
    Err(format!(
        "the first `[[transitional]]` row in {REGISTRY_FILE} has no `from`/`to` pair to plant over"
    ))
}

/// The real `Cargo.lock` with one workspace-internal name added to a package's dependency list —
/// the edge that lives in the lock and in no manifest.
fn lock_plus(cx: &Ctx, package: &str, dep: &str) -> Overlay {
    let text = cx.read("Cargo.lock").unwrap_or_default();
    let head = format!("name = \"{package}\"");
    let body = match text.find(&head) {
        Some(at) => match text[at..].find("dependencies = [\n") {
            Some(rel) => {
                let cut = at + rel + "dependencies = [\n".len();
                format!(
                    "{}{}{}",
                    &text[..cut],
                    format_args!(" \"{dep}\",\n"),
                    &text[cut..]
                )
            }
            None => text.clone(),
        },
        None => text.clone(),
    };
    let mut ov = Overlay::new();
    ov.set("Cargo.lock", body);
    ov
}

/// A planted HOOKS-kind crate standing on the #40 wall: `busbar-contract` in both halves of the
/// build graph, a source file that names it the way every plugin does, plus `extra` shipped deps.
fn the_wall_plant(extra: &[&str]) -> Overlay {
    let mut body = "[package]\nname = \"busbar-hooks-planted\"\nversion = \"0.0.0\"\n\n\
                    [dependencies]\nbusbar-contract = { workspace = true }\n"
        .to_string();
    for d in extra {
        body.push_str(&format!("{d} = {{ workspace = true }}\n"));
    }
    body.push_str("\n[dev-dependencies]\nbusbar-contract = { workspace = true }\n");
    let mut ov = Overlay::new();
    ov.set("crates/busbar-hooks-planted/Cargo.toml", body);
    ov.set(
        "crates/busbar-hooks-planted/src/lib.rs",
        "//! A hooks plugin written against busbar_contract alone.\n\
         pub use busbar_contract::Plugin;\n",
    );
    ov
}

/// A real manifest with a section APPENDED, so a plant adds one edge and takes none away: a plant
/// that rewrote the whole file would strike the crate's real edges too, and the dead-allowance
/// findings that produced would be the ones a reader mistook for the case's own.
fn manifest_plus(cx: &Ctx, rel: &str, extra: &str) -> String {
    format!("{}\n{extra}", cx.read(rel).unwrap_or_default().trim_end())
}

/// A planted `Cargo.toml` for `dir`, declaring `name` and depending on `deps`. `set` rather than an
/// `Edit::Create` so the same helper serves both a brand-new crate and a rewrite of a real one.
fn manifest_plant(dir: &str, name: &str, deps: &[&str]) -> Overlay {
    let mut body = format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n\n[dependencies]\n");
    for d in deps {
        body.push_str(&format!("{d} = {{ workspace = true }}\n"));
    }
    let mut ov = Overlay::new();
    ov.set(format!("{dir}/Cargo.toml"), body);
    ov
}

/// The real ledger with one shipped `[[dep]]` row APPENDED for `from -> to`, `count = "1"`, claiming
/// `allowed` on roster definition 1 — the row a root-linked plugin owes, and the row a non-root crate
/// may not borrow.
fn planted_dep_row(cx: &Ctx, from: &str, to: &str) -> String {
    format!(
        "{}\n\n[[dep]]\nfrom    = \"{from}\"\nto      = \"{to}\"\nhalf    = \"shipped\"\ncount   = \
         \"1\"\nverdict = \"allowed\"\ncite    = \"roster def 1: the composition root is the only \
         place that names which crates exist and wires them at boot\"\nwhy     = \"planted by the \
         self-test\"\ndrain   = \"none: the root links the plugin\"\n",
        cx.read(REGISTRY_FILE).unwrap_or_default().trim_end()
    )
}

/// THE SELFTEST PLANTS, HELD TO THEIR OWN RULES DIRECTLY.
///
/// A `prove_rows_red` case over a row that is RED on the real tree is `Impossible` by construction
/// — the harness cannot tell the plant's red from the standing one — and several of this gate's
/// rows are red today on tree debt that is not the rule's. So the question "can this plant bite,
/// and does the rule it is aimed at emit the needle it asserts" is asked here, rule by rule, where
/// no other row's debt can answer it. Each test fails on a plant that names a crate the census does
/// not have, a kind the table does not have, or a needle no rule emits.
#[cfg(test)]
mod plant_tests {
    use super::*;
    use crate::ctx::Change;
    use crate::ledger::Status;

    fn ws() -> Ctx {
        Ctx::workspace().expect("the workspace opens")
    }

    /// The census exactly as [`KindIsolationGate::run`] builds it.
    fn crates_of(cx: &Ctx) -> (Vec<CrateInfo>, BTreeSet<String>) {
        let mut crates = census(cx).expect("the census reads");
        let (planes, ports) = vocabularies(&crates);
        assign_instances(&mut crates, &planes, &ports);
        (crates, planes)
    }

    fn reg_of(cx: &Ctx) -> KindRegistry {
        load_registry(cx).expect("the registry reads")
    }

    /// A WIRE A TRANSPORT CRATE DECLARES IS TRANSPORT VOCABULARY (#50), read off its
    /// `impl TransportMeta` rather than off its crate name, so a wire folded into a sibling crate
    /// (as `grpc` and `sse` are folded into `http`) stays a transport word. Every transport crate declares its own id,
    /// and a key declared by a module planted inside another transport crate joins the vocabulary.
    #[test]
    fn a_declared_transport_key_is_transport_vocabulary() {
        let cx = ws();
        let crates = census(&cx).expect("the census reads");
        let transports: Vec<&CrateInfo> = crates
            .iter()
            .filter(|c| c.kind == Some("transport"))
            .collect();
        assert!(
            !transports.is_empty(),
            "the census found no transport crate"
        );
        for c in &transports {
            let id = c.remainder.join("-");
            assert!(
                c.declared_keys.contains(&id),
                "{} declares {:?}, not its own id `{id}`",
                c.name,
                c.declared_keys
            );
        }
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-transport-tcp/src/planted_wire/meta.rs",
            "impl TransportMeta for PlantedWire {\n    const KEY: &'static str = \"plantedwire\";\n}\n",
        );
        let planted = cx.with_overlay(ov);
        let (_, ports) = vocabularies(&census(&planted).expect("the planted census reads"));
        assert!(
            ports.contains("plantedwire"),
            "a declared key did not join the transport vocabulary: {ports:?}"
        );
    }

    /// THE PLANT MUST BITE against the tree it is planted over: no removal of a path that tree has
    /// not got, and at least one change it does not already carry.
    fn assert_bites(base: &Ctx, ov: &Overlay) {
        assert!(!ov.is_empty(), "an empty overlay plants nothing");
        let mut bites = false;
        for (path, change) in ov.changes() {
            match change {
                Change::Absent => {
                    assert!(
                        base.exists(path),
                        "{} is removed by the plant and is not in the tree",
                        path.display()
                    );
                    bites = true;
                }
                Change::Content(want) => {
                    if base.read(path).ok().as_ref() != Some(want) {
                        bites = true;
                    }
                }
                _ => bites = true,
            }
        }
        assert!(
            bites,
            "every change the plant makes is one the tree already has"
        );
    }

    fn assert_red_naming(row: &Row, naming: &[&str]) {
        assert_ne!(
            row.status,
            Status::Pass,
            "{} stayed green: {}",
            row.id,
            row.detail
        );
        for n in naming {
            assert!(
                row.detail.contains(n),
                "{} went red without naming `{n}`: {}",
                row.id,
                row.detail
            );
        }
    }

    fn assert_green(row: &Row) {
        assert_eq!(
            row.status,
            Status::Pass,
            "{} is red: {}",
            row.id,
            row.detail
        );
    }

    // ── items 173 / 233: the legacy-drain pair ──────────────────────────────────────────────────

    #[test]
    fn the_drain_pair_turns_on_whether_the_rows_crate_exists() {
        let cx = ws();
        let (crates, _) = crates_of(&cx);
        assert!(
            crates
                .iter()
                .any(|c| c.name == DRAIN_PLANT_FROM && c.kind == Some("legacy")),
            "{DRAIN_PLANT_FROM} must be a legacy crate the census has"
        );

        // The red case's baseline: a table with no rows, green.
        let base = cx.with_overlay(registry_plant(""));
        assert_green(&rule_drain(&crates_of(&base).0, &reg_of(&base)));

        // The red case's plant bites against that baseline and names the live crate.
        let plant = drain_row_plant();
        assert_bites(&base, &plant);
        let red = cx.with_overlay(plant);
        assert_red_naming(
            &rule_drain(&crates_of(&red).0, &reg_of(&red)),
            &["transitional-live", DRAIN_PLANT_FROM, "ship"],
        );

        // The green case: the same row, its crate gone — every removal a path the tree has.
        let mut ov = drain_row_plant();
        ov.remove(format!("crates/{DRAIN_PLANT_FROM}/Cargo.toml"));
        assert_bites(&cx, &ov);
        let done = cx.with_overlay(ov);
        assert_green(&rule_drain(&crates_of(&done).0, &reg_of(&done)));
    }

    // ── item 174: the control-path starvation floor ─────────────────────────────────────────────

    #[test]
    fn the_control_path_floor_is_proven_from_a_green_baseline_over_the_cleanliness_kind() {
        let cx = ws();
        let base = cx.with_overlay(control_surfaces_clean(&cx));
        let (crates, _) = crates_of(&base);
        assert!(
            crates.iter().any(|c| c.kind == Some(CLEANLINESS)),
            "the tree carries no cleanliness surface to take away"
        );
        assert_green(&rule_control(&base, &crates));

        let plant = kinds_gone(&base, &[CLEANLINESS]);
        assert_bites(&base, &plant);
        let gone = cx.with_overlay(plant);
        assert_red_naming(
            &rule_control(&gone, &crates_of(&gone).0),
            &["0 control crate(s)"],
        );
    }

    // ── item 171: the retired control-kind block ────────────────────────────────────────────────

    fn deps_over(ov: Overlay) -> Row {
        let cx = ws().with_overlay(ov);
        let (crates, _) = crates_of(&cx);
        rule_deps(&cx, &crates, &reg_of(&cx), Half::Shipped, false)
    }

    fn registry_over(ov: Overlay) -> Row {
        let cx = ws().with_overlay(ov);
        let (crates, _) = crates_of(&cx);
        rule_registry(&cx, &crates, &reg_of(&cx), false)
    }

    // ── item F0b: the two crate-count floors, lowered to 30, proven at their new boundary ────────
    //
    // `MIN_MANIFESTS` and `closure::MIN_GRAPH_CRATES` moved 50 -> 30 and 40 -> 30 (same shape as
    // F0's `workspace-deps` `MIN_CRATE_MANIFESTS`, `98434a220`) so the Phase 4 fold's planned end
    // state (35 crates, 34 / 33 in the roster variants) clears both. The coarse collapse cases
    // above (`all_but(cx, "toml", 4)`, `all_but(cx, "rs", 4)`) already prove each floor fires on a
    // genuine collapse; these two prove the LOWERED floor fires exactly one manifest under itself
    // and admits the real, un-planted tree — which sits well over 30 today, before the fold has
    // touched a single crate. `:registry` and `:closure` both carry unrelated standing debt on the
    // real tree right now (dead-kind/dead-transitional findings, a two-hop breach), so a
    // `prove_rows_green` case asking either row to be wholly clean would be Impossible by
    // construction (item 89); these read the FLOOR arm's own detail instead of the row's overall
    // status, which is provable on the real tree regardless of that other debt.
    #[test]
    fn the_registry_census_floor_reds_one_below_thirty_and_admits_the_real_tree() {
        assert_eq!(
            MIN_MANIFESTS, 30,
            "this case is pinned to the lowered floor"
        );
        let cx = ws();

        let plant = census_holding(&cx, MIN_MANIFESTS - 1);
        assert_bites(&cx, &plant);
        let planted = cx.with_overlay(plant);
        assert_eq!(
            crates_of(&planted).0.len(),
            MIN_MANIFESTS - 1,
            "the fixture must land the census exactly one under the floor"
        );
        assert_red_naming(
            &registry_over(census_holding(&cx, MIN_MANIFESTS - 1)),
            &["floor", &MIN_MANIFESTS.to_string()],
        );

        let real = registry_over(Overlay::new());
        assert!(
            !real.detail.contains("collapsed below its floor"),
            "the real tree's census must clear the lowered floor of {MIN_MANIFESTS}: {}",
            real.detail
        );
    }

    #[test]
    fn the_closure_graph_floor_reds_one_below_thirty_and_admits_the_real_tree() {
        const MIN_GRAPH_CRATES: usize = 30;
        let cx = ws();

        let plant = census_holding(&cx, MIN_GRAPH_CRATES - 1);
        assert_bites(&cx, &plant);
        let planted = cx.with_overlay(plant);
        let (planted_crates, _) = crates_of(&planted);
        assert_eq!(
            planted_crates.len(),
            MIN_GRAPH_CRATES - 1,
            "the fixture must land the census exactly one under the floor"
        );
        assert_red_naming(
            &closure::rule_closure(&planted, &planted_crates),
            &["floor", &MIN_GRAPH_CRATES.to_string()],
        );

        let (real_crates, _) = crates_of(&cx);
        let real = closure::rule_closure(&cx, &real_crates);
        assert!(
            !real.detail.contains("under the floor")
                && !real.detail.contains("could not be walked over this tree"),
            "the real tree's census must clear the lowered floor of {MIN_GRAPH_CRATES}: {}",
            real.detail
        );
    }

    #[test]
    fn a_cleanliness_surface_reaching_a_wire_is_an_unlisted_edge() {
        assert_bites(&ws(), &cleanliness_reaches_wire());
        assert_red_naming(
            &deps_over(cleanliness_reaches_wire()),
            &[
                "unlisted-dep-edge",
                "cleanliness -> transport",
                "busbar-oauth2 -> busbar-transport-http",
            ],
        );
    }

    #[test]
    fn a_plane_reaching_a_cleanliness_surface_is_an_unlisted_edge() {
        assert_bites(&ws(), &plane_reaches_cleanliness());
        assert_red_naming(
            &deps_over(plane_reaches_cleanliness()),
            &[
                "unlisted-dep-edge",
                "plane -> cleanliness",
                "busbar-plane-mcp -> busbar-oauth2",
            ],
        );
    }

    // ── roster def 1: root -> every plugin kind it links is granted, and only the root (KI-ROOT) ──

    /// Every shipped edge the composition root has onto a plugin-kind crate is a granted class, and
    /// no kind but the root is granted a plugin kind (the #40 wall's `-> contract` is the other way
    /// round). A plugin kind the root starts linking without a grant turns this red here, before
    /// the ledger is asked.
    #[test]
    fn the_root_is_granted_every_plugin_kind_it_links() {
        let cx = ws();
        let (crates, _) = crates_of(&cx);
        let edges = measure_edges(&crates, Half::Shipped);
        let linked: BTreeSet<&str> = edges
            .iter()
            .filter(|e| e.class.0 == "root" && truths::PLUGIN_KINDS.contains(&e.class.1.as_str()))
            .map(|e| {
                assert_eq!(
                    verdict_for(&e.class),
                    "allowed",
                    "{} -> {} is the composition root linking a `{}` plugin (roster def 1) and \
                     ARCHITECTURE_ALLOWED does not grant `root -> {}`",
                    e.from,
                    e.to,
                    e.class.1,
                    e.class.1
                );
                e.class.1.as_str()
            })
            .collect();
        for k in ["hooks", "store", "export", "transport", "plane"] {
            assert!(
                linked.contains(k),
                "the root no longer links a `{k}` crate — the census is not the tree this test \
                 was written against"
            );
        }
        for (from, to) in ARCHITECTURE_ALLOWED {
            if truths::PLUGIN_KINDS.contains(to) {
                assert_eq!(
                    *from, "root",
                    "`({from}, {to})` grants a non-root kind a plugin kind: roster def 1 names ONE \
                     place that wires plugins"
                );
            }
        }
    }

    // ── the #40 wall: every plugin kind -> busbar-contract is the rule (SHA-KI) ──────────────────

    /// The class table grants the wall for EVERY plugin kind, and the rule the edge and matrix
    /// judges read is that one pair shape and no other.
    #[test]
    fn the_wall_is_granted_for_every_plugin_kind() {
        for k in truths::PLUGIN_KINDS {
            assert!(
                ARCHITECTURE_ALLOWED.contains(&(k, CONTRACT_KIND)),
                "ARCHITECTURE_ALLOWED does not grant `{k} -> contract`, the one edge #40(a) leaves \
                 a plugin"
            );
            assert!(is_the_wall(k, CONTRACT_KIND), "{k} -> contract is the wall");
            assert_eq!(
                verdict_for(&(k.to_string(), CONTRACT_KIND.to_string())),
                "allowed"
            );
            assert!(
                !is_the_wall(k, "plugin-abi"),
                "{k} -> plugin-abi is past the wall"
            );
            assert!(!is_the_wall(k, "kernel"), "{k} -> kernel is past the wall");
        }
        for neutral in ["kernel", "core", "root", "unit", "legacy", "plugin-tooling"] {
            assert!(
                !is_the_wall(neutral, CONTRACT_KIND),
                "`{neutral}` is not a plugin kind; its contract edge is an ordinary ledger row"
            );
        }
    }

    /// Asked of the rule directly, finding by finding, so no standing debt on the real tree can
    /// answer it: the planted crate on the wall draws NO finding on either half of the graph, and
    /// the same crate reaching busbar-plugin draws one that names the plugin-abi edge.
    #[test]
    fn a_plugin_crate_on_the_wall_draws_no_finding_and_one_past_it_is_red() {
        let green = the_wall_plant(&[]);
        assert_bites(&ws(), &green);
        let cx = ws().with_overlay(green);
        let (crates, _) = crates_of(&cx);
        assert!(
            crates
                .iter()
                .any(|c| c.name == "busbar-hooks-planted" && c.kind == Some("hooks")),
            "the plant must resolve to the hooks kind"
        );
        for half in [Half::Shipped, Half::Test] {
            let row = rule_deps(&cx, &crates, &reg_of(&cx), half, false);
            assert!(
                !row.detail.contains("busbar-hooks-planted"),
                "a hooks crate naming only busbar-contract drew a {} finding: {}",
                half.word(),
                row.detail
            );
        }

        let red = deps_over(the_wall_plant(&["busbar-plugin"]));
        assert_red_naming(
            &red,
            &[
                "busbar-hooks-planted -> busbar-plugin",
                "hooks -> plugin-abi",
            ],
        );
        assert!(
            !red.detail
                .contains("busbar-hooks-planted -> busbar-contract"),
            "the contract half of the plant must stay unreported: {}",
            red.detail
        );
    }

    #[test]
    fn a_cleanliness_surface_naming_money_is_not_a_vocab_finding() {
        let cx = ws().with_overlay(cleanliness_names_money());
        let (crates, planes) = crates_of(&cx);
        assert!(crates
            .iter()
            .any(|c| c.name == "busbar-oauth2" && c.kind == Some(CLEANLINESS)));
        assert_green(&rule_vocab(&cx, &crates, &planes));
    }

    #[test]
    fn two_cleanliness_surfaces_claiming_one_route_is_a_shared_route() {
        assert_bites(&ws(), &cleanliness_shared_route());
        assert_red_naming(
            &registry_over(cleanliness_shared_route()),
            &["shared-route", "busbar-admin", "busbar-oauth2"],
        );
    }

    // ── items 171 / 202: both arms of the registration ratchet ──────────────────────────────────

    #[test]
    fn a_registration_its_crate_name_already_says_is_redundant() {
        assert_bites(&ws(), &redundant_registration());
        let row = registry_over(redundant_registration());
        assert_red_naming(&row, &["redundant-registration", "busbar-admin"]);
        assert!(
            !row.detail.contains("`[[registered]] kind"),
            "{}",
            row.detail
        );
    }

    #[test]
    fn a_registration_for_a_crate_the_tree_lacks_is_dead() {
        assert_bites(&ws(), &dead_registration());
        let row = registry_over(dead_registration());
        assert_red_naming(&row, &["dead-registration", "busbar-ghost-registered"]);
        assert!(
            !row.detail.contains("`[[registered]] kind"),
            "{}",
            row.detail
        );
    }

    // ── item 172: planted edges land on packages the census has ─────────────────────────────────

    #[test]
    fn the_drain_and_edge_class_plants_name_packages_the_census_has() {
        let (crates, _) = crates_of(&ws());
        for (name, kind) in [(PLANTED_UNIT, "unit"), (PLANTED_SUBSTRATE, "substrate")] {
            assert!(
                crates.iter().any(|c| c.name == name && c.kind == Some(kind)),
                "{name} is not a `{kind}` crate of the census, so an edge onto it is never measured"
            );
        }
        assert_red_naming(
            &deps_over(manifest_plant(
                "crates/busbar-llm",
                "busbar-llm",
                &[PLANTED_UNIT],
            )),
            &["unlisted-transitional", "busbar-llm", PLANTED_UNIT],
        );
        assert_red_naming(
            &deps_over(core_announced_reaching_unit(&ws())),
            &["announced-edge-class", "core -> unit"],
        );
    }

    // ── item 200: a missing exemplar does not excuse the kind's members ─────────────────────────

    fn unit_crate(name: &str) -> CrateInfo {
        CrateInfo {
            dir: format!("crates/{name}"),
            manifest: format!("crates/{name}/Cargo.toml"),
            name: name.to_string(),
            kind: Some("unit"),
            family: Family::Neutral,
            remainder: Vec::new(),
            instance: None,
            declared_keys: Vec::new(),
            deps: Vec::new(),
            dev_deps: Vec::new(),
            ambiguous: Vec::new(),
        }
    }

    fn empty_index() -> SourceIndex {
        SourceIndex {
            skeleton: BTreeMap::new(),
            impls: BTreeMap::new(),
            has_lib: BTreeSet::new(),
            conformance: BTreeSet::new(),
            conformance_dead: BTreeSet::new(),
        }
    }

    #[test]
    fn a_unit_crate_is_checked_although_the_unit_exemplar_is_absent() {
        let (_, exemplar) = EXEMPLARS
            .iter()
            .find(|(k, _)| *k == "unit")
            .expect("the unit kind has an exemplar row");
        let no_lib = unit_crate("busbar-unit-planted-nolib");
        let bare = unit_crate("busbar-unit-planted-bare");
        assert_ne!(&no_lib.name, exemplar);
        let mut idx = empty_index();
        idx.has_lib.insert(bare.dir.clone());
        let row = rule_shape(&[no_lib, bare], &idx);
        assert_red_naming(
            &row,
            &[
                "no-exemplar",
                "no-lib\tcrates/busbar-unit-planted-nolib/src/lib.rs",
                "entry-count\tcrates/busbar-unit-planted-bare",
                "skeleton\tcrates/busbar-unit-planted-bare/src/lib.rs",
            ],
        );
    }

    // ── item 201: a wire composed nowhere ───────────────────────────────────────────────────────

    #[test]
    fn a_wire_composed_in_no_place_is_red_and_the_real_tree_has_none() {
        let cx = ws();
        let (crates, _) = crates_of(&cx);
        let real = rule_wires(&cx, &crates);
        assert_green(&real);
        assert!(!real.detail.contains("unregistered"), "{}", real.detail);

        let plant = wire_unregistered(&cx, "stdio").expect("the root composes stdio");
        assert_bites(&cx, &plant);
        let planted = cx.with_overlay(plant);
        assert_red_naming(
            &rule_wires(&planted, &crates_of(&planted).0),
            &["unregistered-wire", "busbar-transport-stdio"],
        );
    }

    /// THE ROOT'S MANIFEST ROW IS THE WIRE'S ONE REGISTRATION: the row alone is green, and the
    /// row beside a source file composing the same wire is two registrations, the row named.
    #[test]
    fn a_manifest_row_is_the_wires_one_registration() {
        let cx = ws();
        let alone = cx.with_overlay(wire_linked_by_row(&cx, "stdio").expect("plantable"));
        assert_green(&rule_wires(&alone, &crates_of(&alone).0));

        let plant = wire_row_and_source(&cx, "stdio").expect("plantable");
        assert_bites(&cx, &plant);
        let planted = cx.with_overlay(plant);
        assert_red_naming(
            &rule_wires(&planted, &crates_of(&planted).0),
            &[
                "second-registration",
                "busbar-transport-stdio",
                LINKED_TABLE,
            ],
        );
    }
}

#[cfg(test)]
mod memo_tests {
    use super::*;

    fn reads() -> usize {
        READINGS.with(|n| n.get())
    }

    /// `:vocab` READS AN UNCHANGED FILE ONCE. It used to re-read every production line of every
    /// kind-bearing source file on every gate run — 727 s of a 2 393 s `kind-isolation` battery,
    /// re-reading files no case had touched.
    #[test]
    fn the_vocabulary_rule_reads_an_unchanged_file_once() {
        let rel = "crates/zz-vocab-probe/src/lib.rs";
        let text = "use busbar_plane_llm::X;\nfn f() {}\n";
        let start = reads();
        let a = vocab_lines(rel, text);
        let b = vocab_lines(rel, text);
        assert_eq!(
            reads() - start,
            1,
            "the second ask is answered from the memo"
        );
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        let _ = vocab_lines(rel, "use busbar_plane_mcp::X;\n");
        assert_eq!(
            reads() - start,
            2,
            "changed bytes are a new reading, never a stale one"
        );
    }

    /// `:faces`' SOURCE INDEX READS AN UNCHANGED FILE ONCE — 365 s of the same battery.
    #[test]
    fn the_source_index_reads_an_unchanged_file_once() {
        let dir = "crates/zz-index-probe";
        let rel = "crates/zz-index-probe/src/lib.rs";
        let text = "pub mod wire;\nimpl busbar_contract::Plane for Wire {}\n";
        let start = reads();
        let a = source_facts(rel, dir, text);
        let b = source_facts(rel, dir, text);
        assert_eq!(
            reads() - start,
            1,
            "the second ask is answered from the memo"
        );
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(a.mods.as_deref(), Some(&["wire".to_string()][..]));
        assert_eq!(a.heads, vec!["Plane".to_string()]);
        let _ = source_facts(rel, dir, "pub mod other;\n");
        assert_eq!(
            reads() - start,
            2,
            "changed bytes are a new reading, never a stale one"
        );
    }

    /// THE TOKEN READING OF A CRATE PATH IS THE SUBSTRING READING, for every line and every name
    /// here — including the ones that must fall back to the substring search. `:vocab` asks ~140
    /// crate paths of every line; asking them through the `name::` tokens a line carries is the
    /// same question only if this holds.
    #[test]
    fn a_crate_path_read_off_the_tokens_is_the_substring_reading() {
        let lines = [
            "use busbar_plane_llm::Thing;",
            "let x = xbusbar_plane_llm::y;",
            "busbar-plane-llm::",
            "a::b::c::busbar_plane_llm",
            ":::busbar_x:::y",
            "Busbar_Plane_LLM::x",
            "é::busbar_x::é",
            "busbar_x :: y",
            "plane_llm::x and llm::y",
            "::",
            "",
            "busbar_plane_llm:: busbar_plane_mcp::",
            "<busbar_x as T>::f",
            "r#busbar_x::y",
        ];
        let paths = [
            "busbar_plane_llm::",
            "busbar-plane-llm::",
            "plane_llm::",
            "llm::",
            "busbar_x::",
            "x::",
            "busbar_plane_mcp::",
            "Busbar_X::",
            "é::",
            "::",
        ];
        for raw in lines {
            let line = VocabLine::new(1, raw.to_string());
            for path in paths {
                let want = line.lower.contains(path);
                let got = match simple_path_name(path) {
                    Some(name) => line.toks.iter().any(|t| t.ends_with(name)),
                    None => line.lower.contains(path),
                };
                assert_eq!(got, want, "line {raw:?}, path {path:?}");
            }
        }
    }
}
