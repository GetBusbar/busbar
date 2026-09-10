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
//!   in [`MEASURED_EDGES`]. EVERY SHIPPED DEPENDENCY TABLE IS A MANIFEST EDGE — `[dependencies]`,
//!   `[build-dependencies]` and the per-target forms of both, with `package = "…"` and
//!   `[workspace.dependencies]` renames resolved to the package they name; see [`crate::manifest`]
//!   for the five spellings the one-section reader could not see, every one of which was proven to
//!   carry a plane into a transport with this row green.
//!   A NEW class is refused; a class that no longer exists is refused as a
//!   dead allowance. The measured graph is printed in the row's detail so the owner can tighten it
//!   by deleting lines rather than by re-deriving it. Inside the plane family a crate may only
//!   name its OWN instance, so `busbar-plane-llm` naming `busbar-mcp-codec` is refused.
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
//! `busbar-contract`, `busbar-contract-transport`, `busbar-grammar`, `busbar-timing`,
//! `busbar-api`, the `*-codec` halves and the `busbar-plugin-*` tooling — reach their kind through
//! the EXPLICIT TABLE below rather than through segment two. That table is the whole of the
//! exception: a name that is neither in it nor `busbar-<kind>-…` for a kind IN it is refused, in
//! the owner's own words. Nothing is grandfathered by silence, and a FIVE-segment name is refused
//! outright — the scheme has three segments, four only for a dialect.
//!
//! ## DIALECT IS A PLUGIN KIND
//!
//! A four-segment plane name — `busbar-plane-<plane>-<dialect>`, e.g. `busbar-plane-llm-openai`,
//! `busbar-plane-mcp-mcpv2`, `busbar-plane-streams-voice` — is a DIALECT of that plane, and the
//! direction is fixed: **the dialect names its plane; the plane never names a dialect.** A dialect
//! reaching a SIBLING plane is the same fusion one level down and is refused too. Today's `*-codec`
//! crates are the PRE-SPLIT dialects and are read as belonging to their plane (`busbar-llm-codec`
//! is a dialect half of `llm`), which is why the plane-to-codec edge is in the measured graph and
//! the plane-to-dialect edge never can be: the split is what the rename is FOR.
//!
//! ## VOICE IS THE STREAMS PLANE
//!
//! The plane the tree spells `voice` is the STREAMS plane (config section `streams:`). Until
//! `busbar-plane-voice` and `busbar-voice-codec` are renamed, [`PLANE_ALIASES`] holds the two
//! spellings together so both are one instance for every rule here — and holds them on a ratchet:
//! the alias is RED once the crate it translates is gone.
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
//! wrong way on the day a crate lands: the agent adding `crates/busbar-core-config` would red a gate
//! it never touched. So the kind is taught FIRST — `core` is in the table below — and
//! [`REGISTRY_FILE`]'s `[[announced]]` table is what keeps that teaching from being scored as a dead
//! kind row (and its accepted name as a dead waiver) in the window before the crates exist. Landing
//! them is GREEN on the per-push gate, which is the entire purpose; the ship twin is what refuses an
//! announcement that has outlived its landing.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::manifest::{self, DepDecl};
use crate::scan;

mod base;
mod inputs;
mod matrix;
mod truths;

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
const MIN_MANIFESTS: usize = 50;
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

/// THE KIND TABLE. Ten plugin kinds, the contract crates they are written against, the composition
/// root, and the retiring legacy crates.
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
    // A DIALECT OF A PLANE — `busbar-plane-<plane>-<dialect>`. It has no matcher of its own: it IS
    // the plane marker with a second remainder segment, and [`refine`] is what tells the two apart.
    KindDef {
        kind: "dialect",
        family: Family::Plane,
        matchers: &[],
    },
    // THE PRE-SPLIT DIALECTS. `busbar-llm-codec` is the `llm` plane's other half; the rename turns
    // it into a `busbar-plane-llm-<dialect>`. Until then it is its own kind, and the day the last
    // one goes the dead-kind rule below demands this row be struck.
    KindDef {
        kind: "codec",
        family: Family::Plane,
        matchers: &["*-codec"],
    },
    // A CONTROL SURFACE — a full plugin kind, and a new branch of the tree.
    //
    // > "CONTROL is a full plugin KIND … busbar-control-admin (today busbar-plane-admin) and
    // > busbar-control-oauth2. The verifier plugins stay the AUTH kind." — owner, 2026-09-08
    //
    // A control crate is an UNMETERED served surface: it declares its routes as data the way a plane
    // does, owns its own bodies, and runs the control path (verified by the auth kind, admitted,
    // audited, answered). What makes it a separate kind rather than a quiet plane is everything it
    // may NOT do — no money vocabulary, no upstream, no plane may call it and it may call no plane,
    // and its only dependency is the contract. Those are the rows below, not a comment here.
    //
    // The FAMILY is `Plane` and that is deliberate: family in this gate is about the instance
    // VOCABULARY and the served/neutral split `plane-purity` scans, not about metering. `admin` is
    // a served-surface instance word no transport and no unit may carry, and a control crate's
    // source is served source that the backwards-reach scan must read. The KIND is what differs.
    KindDef {
        kind: "control",
        family: Family::Plane,
        matchers: &["busbar-control-"],
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
    KindDef {
        kind: "kernel",
        family: Family::Neutral,
        matchers: &["=busbar-kernel"],
    },
    // THE ENGINE SURFACES BEING CARVED OUT OF `busbar-core` — `busbar-core-config`,
    // `busbar-core-hooks`, and whatever the drain names next. A `core` crate is NEUTRAL on exactly
    // the terms `kernel` and `caps` are: it may carry no plane and no transport instance in its
    // name, and it reaches only the neutral spine ([`PENDING_EDGES`]), so an edge to a plane, a
    // dialect, a transport or a unit is a NEW class and is refused like any other.
    //
    // A PREFIX, not two exact names: an exact matcher yields an EMPTY remainder, which would mean
    // `busbar-core-mcp` was never read for a plane instance at all — the kind would be a hole the
    // shape of every name it accepted. The prefix costs one reviewed accepted-name entry
    // (`busbar-core-hooks`, below) and buys the name rule over every future member.
    KindDef {
        kind: "core",
        family: Family::Neutral,
        matchers: &["busbar-core-"],
    },
    KindDef {
        kind: "caps",
        family: Family::Neutral,
        matchers: &["=busbar-caps"],
    },
    KindDef {
        kind: "contract",
        family: Family::Neutral,
        matchers: &["=busbar-contract"],
    },
    KindDef {
        kind: "contract-transport",
        family: Family::Neutral,
        matchers: &["=busbar-contract-transport"],
    },
    KindDef {
        kind: "grammar",
        family: Family::Neutral,
        matchers: &["=busbar-grammar"],
    },
    KindDef {
        kind: "substrate",
        family: Family::Neutral,
        matchers: &["=busbar-substrate", "=busbar-substrate-values"],
    },
    KindDef {
        kind: "api",
        family: Family::Neutral,
        matchers: &["=busbar-api"],
    },
    KindDef {
        kind: "timing",
        family: Family::Neutral,
        matchers: &["=busbar-timing"],
    },
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
        matchers: &[
            "=busbar-core",
            "=busbar-llm",
            "=busbar-mcp",
            "=busbar-a2a",
            "=busbar-voice",
        ],
    },
];

/// The naming scheme is `busbar-<kind>-<name>`, four segments only for a dialect. A fifth segment
/// is a name that has stopped saying what the crate IS.
const MAX_NAME_SEGMENTS: usize = 4;

/// PLANE SPELLINGS HELD TOGETHER UNTIL THE RENAME LANDS. `voice` is the STREAMS plane (config
/// section `streams:`); both spellings are one instance for every rule here, both are banned
/// vocabulary in every other kind, and the entry is RED once the crate it translates is gone.
const PLANE_ALIASES: &[(&str, &str, &str)] = &[("voice", "streams", "busbar-plane-voice")];

/// Kinds the target scheme defines that the tree does not carry YET, each with its reason. The
/// dead-kind rule skips these — and the ratchet runs the other way: the day a crate of one of them
/// exists, the entry must be struck, or a kind would be both pending and live.
const PENDING_KINDS: &[(&str, &str)] = &[(
    "dialect",
    "the four-segment `busbar-plane-<plane>-<dialect>` form. The pre-split dialects are today's \
     `*-codec` crates; the rename that splits them is what creates the first crate of this kind.",
)];

/// Edge classes the TARGET scheme has and the tree does not yet. They are allowed without being
/// scored as dead — a class that cannot exist until the rename lands cannot be a stale allowance.
const PENDING_EDGES: &[(&str, &str)] = &[
    ("dialect", "plane"),
    ("dialect", "grammar"),
    ("dialect", "substrate"),
    ("dialect", "api"),
    ("dialect", "timing"),
    // THE `core` KIND'S NEUTRAL SPINE, and deliberately nothing else. The crates being carved out
    // of `busbar-core` land branch by branch, so their edges cannot be measured yet; what CAN be
    // stated in advance is the same sink set `kernel` and `caps` have. A `core` crate that reaches
    // a plane, a dialect, a transport or a unit is not on this list, so it is a NEW edge class and
    // is refused — which is the machine form of "a core crate names no plane, dialect, transport or
    // unit". A core crate that needs a sink not listed here adds the line and says why; the gate
    // names the missing class for it.
    ("core", "api"),
    ("core", "caps"),
    ("core", "grammar"),
    ("core", "kernel"),
    ("core", "substrate"),
    ("core", "timing"),
    // THE COMPOSITION ROOT NAMES EVERY AXIS — that is what a root IS, and the list above already
    // says so eleven times over in `ARCHITECTURE_ALLOWED`. `core` is missing from it for one
    // reason: the kind has no crates yet. So the class is stated HERE, with the rest of the carve-
    // out, rather than in the measured table: `busbar-core-config` is cut out of `busbar-core`,
    // which the root already names as `legacy`, and the day the carve-out lands the root's
    // dependency simply moves from the old crate to the new one. Without this line the root cannot
    // name the crate at all and the carve-out has nowhere to land; with it, the class is granted
    // and nothing else about `core` moves — its own sinks are the six above and no more.
    ("root", "core"),
    // The one sink `CONTROL_SINKS` grants beside the contract. No control crate has taken it yet —
    // and a control crate that does must not read as a kind learning about another kind, because
    // the design granted it before the tree grew it.
    ("control", "caps"),
];

/// The retiring 1.5.x crates, named so the ratchet can check they still exist.
const LEGACY_CRATES: &[&str] = &[
    "busbar-core",
    "busbar-llm",
    "busbar-mcp",
    "busbar-a2a",
    "busbar-voice",
];

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
];

/// `qa/construction.toml`'s `[gate.plugin_kinds]` keys, each mapped onto the kind it names here.
/// A key that maps onto nothing in [`KINDS`] is a second kind vocabulary drifting beside this one.
const CONSTRUCTION_KIND_KEYS: &[(&str, &str)] = &[
    ("plane", "plane"),
    ("dialect", "dialect"),
    ("control", "control"),
    ("unit", "unit"),
    ("transport", "transport"),
    ("store", "store"),
    ("hook", "hooks"),
    ("pure_auth", "auth"),
    ("egress_auth", "auth"),
    ("secret", "secret"),
    ("export", "export"),
    ("loader", "plugin-tooling"),
    ("abi", "contract"),
];

/// The three crate names whose remainder trips a naming rule for a reason the owner has read.
///
/// Every one is a REVIEWED sentence, not a shrug, and every one EXPIRES: a waiver whose crate is
/// gone is RED, so the list cannot become a set of holes nobody re-reads.
const ACCEPTED_NAMES: &[(&str, &str)] = &[
    (
        "busbar-unit-transport-key",
        "the unit that holds TRANSPORT KEYS. `transport` here is the kind word describing what the \
         unit's keys are for, never a transport instance — no transport is named, and the crate \
         depends on busbar-contract-transport as every unit on that path does.",
    ),
    (
        "busbar-unit-auth",
        "the ingress AUTH unit. `auth` here is the step of the Teller loop this unit runs, not the \
         auth-plugin kind: the unit calls auth plugins, it is not one.",
    ),
    (
        "busbar-auth-admin-tokens",
        "the ADMIN API's token issuer, an auth plugin. `admin` here is the administrative surface \
         whose tokens it mints, not the admin PLANE instance — it carries no plane edge and no \
         plane vocabulary.",
    ),
    (
        "busbar-core-hooks",
        "the engine's HOOK DISPATCH, carved out of busbar-core. `hooks` here is the thing core \
         dispatches, not the hooks-plugin kind: a hook plugin is `busbar-hook-<name>` and \
         implements the hook ABI, while this crate is the neutral caller that runs them. It is \
         `core` kind on the same terms as kernel and caps, and reaches only the neutral spine.",
    ),
];

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
    ("caps", "contract"),
    // The pre-split dialects: a codec is written on the closed span grammar the contract re-exports.
    ("codec", "grammar"),
    ("contract", "contract-transport"),
    ("contract", "grammar"),
    ("kernel", "caps"),
    ("kernel", "contract"),
    ("kernel", "grammar"),
    ("legacy", "contract"),
    ("plane", "contract"),
    // The composition root is the one thing that names all three axes — that is what a root IS.
    ("root", "api"),
    ("root", "caps"),
    ("root", "contract"),
    ("root", "control"),
    ("root", "kernel"),
    ("root", "legacy"),
    ("root", "plane"),
    ("root", "plugin-tooling"),
    ("root", "store"),
    ("root", "substrate"),
    ("root", "transport"),
    ("root", "unit"),
    ("store", "contract"),
    ("substrate", "contract"),
    ("transport", "contract"),
    ("transport", "contract-transport"),
    ("transport", "transport"),
    ("unit", "caps"),
    ("unit", "contract"),
    ("unit", "unit"),
    // A CONTROL SURFACE NAMES THE CONTRACT AND NOTHING ELSE — the closed sink set the owner ruled,
    // already stated in [`CONTROL_SINKS`] and repeated here because this table is what the ship
    // twin reads.
    ("control", "contract"),
];

/// THE TRUSTED COMPUTING BASE: the loader and the plugin tooling, which `ARCHITECTURE.md` 1.4 says
/// in its own words are NOT kinds. Their edges are neither granted nor refused by the kind rules,
/// because the kind rules are not about them — so they carry their own verdict, they are still
/// written down instance by instance, and the ship twin still refuses them: a tag's criterion is
/// the architecture's own graph, and the TCB is a hole in that graph rather than a clause of it.
const ARCHITECTURE_TCB: &[(&str, &str)] = &[
    ("plugin-tooling", "api"),
    ("plugin-tooling", "caps"),
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
const DRAIN_TARGET_KINDS: &[&str] = &["unit", "plane", "dialect", "transport", "control"];

/// THE ONLY CRATES A CONTROL SURFACE MAY NAME.
///
/// > "depend on a transport, plane, dialect, unit or another control crate — CANNOT. Only
/// > busbar-contract, +busbar-caps if the contract needs it." — owner, 2026-09-08
///
/// This is a CLOSED set rather than a line in the measured graph, and the difference matters: the
/// measured graph ratchets on what the tree HAS, so a control crate that grew an edge on the same
/// commit as its allowance would be green. A control crate's dependency list is a design decision
/// that was made once, so it is written once, and anything else is refused whether or not the tree
/// has grown it.
const CONTROL_SINKS: &[&str] = &["contract", "caps"];

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
    "dialect",
    "transport",
    "unit",
    "control",
    "store",
    "auth",
    "secret",
    "hooks",
    "export",
];

/// The kinds that declare CLAIMS (`PLUGIN-TREE.md` §3): what the crate answers for.
/// A CONTROL surface and an AUTH plugin are here for the reason the planes are: both declare what
/// they answer for as DATA — the same claim-table shape — rather than deciding it inside a handler.
const CLAIMING_KINDS: &[&str] = &["plane", "dialect", "transport", "control", "auth"];

/// The kinds that owe a shared conformance battery. The plugin kinds are here because a plugin is
/// exactly the thing whose contract is checked from outside; the three exemplar kinds are here
/// because the ship criterion says every kind runs its kind's battery, with no exceptions.
const BATTERY_KINDS: &[&str] = &[
    "plane",
    "control",
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

/// One `[[minted]]` row: THE ONE THING THAT LETS A NEW CRATE'S LEDGER ROWS EXIST.
///
/// `minted-row` refuses any `[[cell]]`, `[[edge]]` or `[[disagreement]]` key the merge-base's copy
/// of the ledger does not carry, because a new row is a `0 -> N` raise wearing the clothes of a
/// first measurement. That refusal is right about every row EXCEPT the ones a crate that does not
/// exist yet must bring with it: the first crate of a kind — `busbar-core-config`, the dialect
/// crates, a secret plugin — has no rows at any base, so under that rule it could never land at
/// all, and the only way through was to weaken the ratchet.
///
/// So the admission is DATA, and its subject is the ANNOUNCEMENT rather than the row: a crate the
/// base's own `[[announced]]` table already names may mint its row set ONCE, in a row that says
/// which crate, at which commit, and HOW MANY cells. Everything about that is checkable against
/// history and nothing about it is checkable against the branch's own good intentions:
///
/// * `crate` must be in the BASE's `[[announced]]` table. A crate this branch announced in the same
///   commit as the rows it wanted admitted announces nothing — that is the forgery the whole
///   provenance module exists to refuse.
/// * ONCE. A `[[minted]]` row the base already carries admits nothing more: the crate's rows are
///   history now, and a second mint under the same row is how a landed crate would grow new
///   ceilings for free.
/// * `cells` is EXACT. The row records the size of the set it minted; a branch that mints one more
///   cell than the number it wrote down has to write the number down again.
/// * `moved_from` is the ceiling for a CARVE-OUT. `busbar-core-config` is cut out of `busbar-core`,
///   so its cells are the old crate's cells under a new name — and a minted cell may not exceed the
///   same-kind count the base pinned for the crate it was moved from. A move cannot raise the union
///   of the two rows; if it does, it is not a move.
#[derive(Debug, Clone)]
struct Minted {
    krate: String,
    commit: String,
    cells: i64,
    /// The crate this one was carved out of, when it was carved out of one.
    moved_from: Option<String>,
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
    /// The `:matrix` row's admission table — see [`Minted`].
    minted: Vec<Minted>,
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
        // THE ADMISSION TABLE — the one row a NEW crate's ledger rows arrive under. Every field is
        // checked against something OUTSIDE this branch (the base's `[[announced]]` table, the
        // base's own `[[cell]]` counts) over in `matrix`; what is checked HERE is only that the row
        // is readable, because a row nobody can read is not an admission.
        "minted" => {
            // `moved_from` is the one OPTIONAL field in this file, so it is lifted out before
            // `take_row` — which refuses a field it was not asked for, correctly, for every other
            // table. A row without it is a crate that was written rather than carved.
            let moved_from = fields
                .iter()
                .find(|(k, _)| k == "moved_from")
                .map(|(_, v)| v.clone());
            if moved_from.as_deref() == Some("") {
                reg.errors.push(format!(
                    "empty-field\t{REGISTRY_FILE}:{at}\t`[[minted]]` declares `moved_from` with an \
                     empty value; a carve-out that names no source crate has no ceiling over it"
                ));
                return;
            }
            let rest: Vec<(String, String)> = fields
                .iter()
                .filter(|(k, _)| k != "moved_from")
                .cloned()
                .collect();
            let Some(v) = take_row(&rest, &["crate", "commit", "cells"], table, at, &mut reg.errors)
            else {
                return;
            };
            let Ok(cells) = v[2].parse::<i64>() else {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[minted]] cells = \"{}\"` is not a number. \
                     An admission that cannot be counted admits any number of rows",
                    v[2]
                ));
                return;
            };
            if cells < 0 {
                reg.errors.push(format!(
                    "bad-count\t{REGISTRY_FILE}:{at}\t`[[minted]] cells = \"{}\"` is negative. No \
                     row set has a negative size, so a negative admission is not an admission — it \
                     is this crate's mint ratchet switched off in a value that reads like a \
                     reviewed figure",
                    v[2]
                ));
                return;
            }
            reg.minted.push(Minted {
                krate: v[0].clone(),
                commit: v[1].clone(),
                cells,
                moved_from,
            });
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
             `[[question]]`, `[[face]]`, `[[edge]]`, `[[cell]]`, `[[disagreement]]` and \
             `[[minted]]` rows and nothing else"
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
                 `[[edge]]`, `[[cell]]`, `[[disagreement]]`, `[[patch]]` and `[[minted]]` rows \
                 and nothing else",
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

/// THE BASE'S OWN COPY OF THE LEDGER, in the two shapes the mint admission needs: which crate the
/// BASE announced as which kind, and which `[[cell]]` count the BASE pinned for each crate × kind.
///
/// Both are read out of git by the caller and parsed here, and that is the whole point of them: a
/// `[[minted]]` row is checked against numbers and names this branch cannot edit. Load errors in
/// the base's copy are dropped rather than reported — the base's file is history, this branch is
/// not being asked to fix it, and a row that did not parse simply is not there to admit anything.
pub(super) fn ledger_at(
    text: &str,
) -> (
    BTreeMap<String, String>,
    BTreeMap<(String, String), i64>,
    BTreeSet<String>,
) {
    let reg = parse_registry(text);
    (
        reg.announced
            .iter()
            .map(|a| (a.name.clone(), a.kind.clone()))
            .collect(),
        reg.matrix_cells
            .iter()
            .map(|c| ((c.krate.clone(), c.kind.clone()), c.count))
            .collect(),
        reg.minted.iter().map(|m| m.krate.clone()).collect(),
    )
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

/// THE PLANE/DIALECT SPLIT. `busbar-plane-llm` is a plane; `busbar-plane-llm-openai` is a DIALECT
/// of it. One remainder segment or two is the whole of the difference, which is exactly why the
/// scheme puts the dialect in segment four rather than inventing a second prefix.
fn refine(kind: Option<&'static str>, remainder: &[String]) -> Option<&'static str> {
    match kind {
        Some("plane") if remainder.len() >= 2 => Some("dialect"),
        other => other,
    }
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
        out.push(CrateInfo {
            dir: manifest_dir(&rel),
            manifest: rel,
            name,
            kind,
            family: family_of(kind),
            remainder,
            instance: None,
            deps,
            dev_deps,
            ambiguous,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.dir.cmp(&b.dir)));
    Ok(out)
}

/// The instance vocabularies, DERIVED: plane instances are the plane crates' names, transport
/// instances are the transport crates' names.
fn vocabularies(crates: &[CrateInfo]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut planes = BTreeSet::new();
    let mut transports = BTreeSet::new();
    for c in crates {
        match c.kind {
            // A CONTROL SURFACE CARRIES A SERVED-SURFACE INSTANCE WORD, like a plane does: `admin`
            // is claimed here, so no transport and no unit may be named after it. Dropping control
            // out of this harvest would have quietly RETIRED `admin` from the vocabulary on the
            // same commit that made admin a control crate.
            Some("plane") | Some("dialect") | Some("control") => {
                if let Some(first) = c.remainder.first() {
                    planes.insert(first.clone());
                }
            }
            Some("transport") => {
                transports.insert(c.remainder.join("-"));
            }
            _ => {}
        }
    }
    // BOTH SPELLINGS OF A RENAMED PLANE ARE VOCABULARY. `busbar-transport-streams` has to be
    // refused on the day the alias lands, not on the day the rename does.
    for (from, to, _) in PLANE_ALIASES {
        if planes.contains(*from) {
            planes.insert((*to).to_string());
        }
    }
    (planes, transports)
}

/// Fill in each crate's own instance, once the vocabularies are known.
fn assign_instances(crates: &mut [CrateInfo], planes: &BTreeSet<String>, ports: &BTreeSet<String>) {
    for c in crates.iter_mut() {
        // A DIALECT'S INSTANCE IS THE PLANE IT IS A DIALECT OF — segment three, never the dialect
        // word in segment four. `busbar-plane-streams-voice` belongs to `streams`, not to `voice`.
        if c.kind == Some("dialect") {
            c.instance = c.remainder.first().map(|p| canon_plane(p));
            continue;
        }
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

            // THE DIALECT DIRECTION IS FIXED, and it is fixed the way the split needs: the dialect
            // names its plane, the plane never names a dialect. A plane that reaches back into a
            // dialect has re-fused the two halves the rename exists to separate.
            if from == "plane" && to == "dialect" {
                offenders.push(format!(
                    "plane-names-dialect\t{}\t{} depends on {dep}. A DIALECT names its plane; a \
                     plane never names a dialect — {MAKE_A_NEW_KIND}",
                    c.dir, c.name
                ));
            }

            // A CONTROL SURFACE NAMES THE CONTRACT AND NOTHING ELSE.
            //
            // The closed sink set, not a measured line: a control crate reaching a transport, a
            // plane, a dialect, a unit or ANOTHER CONTROL crate is refused whether or not the tree
            // has grown that edge yet. `control -> control` is in the refusal on purpose — two
            // control surfaces that know about each other are one surface with a seam drawn
            // through it, and the next thing they share is state.
            if from == "control" && !CONTROL_SINKS.contains(&to) {
                offenders.push(format!(
                    "control-sink\t{}\t{} is a CONTROL surface and depends on {dep} (kind {to}). A \
                     control crate names {} and nothing else: not a transport, not a plane, not a \
                     dialect, not a unit, not another control crate",
                    c.dir,
                    c.name,
                    CONTROL_SINKS.join(" and ")
                ));
            }

            // NO PLANE CALLS A CONTROL SURFACE, AND NO CONTROL SURFACE CALLS A PLANE. A control
            // surface does not appear in a plane's step list; the two paths meet at the kernel or
            // they do not meet. Both directions, because either one alone is the fusion.
            if (from == "plane" && to == "control") || (from == "control" && to == "plane") {
                offenders.push(format!(
                    "plane-control\t{}\t{} depends on {dep}: {from} -> {to}. A control surface \
                     never appears in a plane's step list and never reaches into one — the metered \
                     path and the control path are two kinds, {MAKE_A_NEW_KIND}",
                    c.dir, c.name
                ));
            }

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
        // A DIALECT IS A PLANE'S OTHER HALF AND IS BOUND BY THE PLANE'S OWN BAN. It had no arm at
        // all, so on the day D36 lands and the first `busbar-plane-<p>-<d>` crate exists, that
        // crate could `use axum` and name `busbar_transport_http` with this row silent — the ban is
        // written against the kind word, and `dialect` was not one of the four spelled here. The
        // hole opens on the rename rather than today, which is exactly when nobody is looking.
        "plane" | "dialect" => {
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
        // A CONTROL SURFACE IS SERVED SOURCE: it carries every ban a plane carries, for the same
        // reason a plane does — it speaks its own ABI and never the wire. The money vocabulary it
        // additionally may not name is read off `plane-no-money`'s own list rather than restated
        // here; see [`money_vocabulary`].
        "control" => {
            for lib in TRANSPORT_LIBS {
                out.push((
                    (*lib).to_string(),
                    "a transport LIBRARY named inside a control surface",
                ));
            }
            out.push((
                TOKIO_NET.to_string(),
                "a socket module named inside a control surface",
            ));
            for p in TRANSPORT_CRATE_PATHS {
                out.push((
                    (*p).to_string(),
                    "a TRANSPORT CRATE named inside a control surface",
                ));
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

/// `qa/construction.toml`'s own file, so the two lists are ONE list.
const MONEY_LIST_FILE: &str = "qa/construction.toml";
/// …and the rule inside it whose vocabulary a control surface inherits VERBATIM.
const MONEY_LIST_RULE: &str = "[rules.plane-no-money]";

/// One `key = [ … ]` array of quoted strings inside `section`, however many lines it spans.
fn toml_string_list(text: &str, section: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut collecting = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && !collecting {
            inside = t == section;
            continue;
        }
        if !inside {
            continue;
        }
        let body = if collecting {
            t
        } else if let Some((k, v)) = t.split_once('=') {
            if k.trim() != key {
                continue;
            }
            collecting = true;
            v.trim()
        } else {
            continue;
        };
        let mut rest = body;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            out.push(after[..close].to_string());
            rest = &after[close + 1..];
        }
        if body.contains(']') {
            break;
        }
    }
    out
}

/// THE MONEY VOCABULARY, TAKEN FROM `plane-no-money` RATHER THAN RESTATED.
///
/// > "name any money/fee/rate/posting vocabulary (plane-no-money list VERBATIM)" — owner
///
/// Two copies of a banned-word list are two lists, and the day somebody adds a word to one of them
/// is the day they diverge without either gate noticing. So there is one list, it lives where the
/// rule that argued for it lives, and this reads it. A list that does not read is FATAL rather than
/// empty: a ban over no words bans nothing and reads exactly like a clean surface.
fn money_vocabulary(cx: &Ctx) -> Result<(Vec<String>, BTreeSet<String>), String> {
    let text = cx.read(MONEY_LIST_FILE).map_err(|e| e.to_string())?;
    let symbols = toml_string_list(&text, MONEY_LIST_RULE, "symbols");
    if symbols.is_empty() {
        return Err(format!(
            "{MONEY_LIST_FILE} {MONEY_LIST_RULE} declares no `symbols`"
        ));
    }
    let allowed = toml_string_list(&text, MONEY_LIST_RULE, "allowed_vocabulary")
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();
    Ok((symbols, allowed))
}

/// The identifiers on one line, lowercased — the unit a money symbol is judged as, so a needle that
/// lands inside a longer name is read as the name a reader sees (`as_nanos`, not `_nanos`).
fn identifiers(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in code.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Does `ident` carry money symbol `needle`? A `_`-fixed entry is a fragment, everything else is the
/// whole name — the same reading `plane-no-money` gives its own list.
fn money_hit(ident: &str, needle: &str) -> bool {
    if needle.starts_with('_') || needle.ends_with('_') {
        ident.contains(needle)
    } else {
        ident == needle
    }
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

    // THE MONEY LIST IS AN INPUT, AND A MISSING ONE IS FATAL. A control surface's money ban is
    // `plane-no-money`'s own vocabulary; if that list cannot be read there is no ban, and no ban
    // over a privileged unmetered surface reads exactly like a surface that names no price.
    let (money, money_allowed) = match money_vocabulary(cx) {
        Ok(v) => v,
        Err(e) => {
            return Row::fail(
                ROW_VOCAB,
                "the control surface's money vocabulary could not be read",
                format!(
                    "{e} — a control crate may name no money vocabulary, and the list is \
                     `plane-no-money`'s so the two are one list. A ban over no words bans nothing."
                ),
            )
        }
    };

    // EVERY WORKSPACE CRATE'S PATH SPELLING, so a source line that names one can be asked whether
    // its own manifest declares the edge. Both spellings, because `busbar_plane_llm::` and
    // `busbar-plane-llm` are one crate and a rule that reads one of them reads half the tree.
    let by_dir: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.dir.as_str(), c)).collect();
    let crate_paths: Vec<(String, String)> = crates
        .iter()
        .flat_map(|c| {
            [
                (format!("{}::", c.name.replace('-', "_")), c.name.clone()),
                (format!("{}::", c.name), c.name.clone()),
            ]
        })
        .collect();

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
        if *kind == "control" {
            for (lineno, code) in scan::production_lines(&f.text) {
                let code = scan::blank_literals(&code);
                for ident in identifiers(&code) {
                    if money_allowed.contains(&ident) {
                        continue;
                    }
                    if let Some(sym) = money.iter().find(|s| money_hit(&ident, &s.to_lowercase())) {
                        offenders.push(format!(
                            "{sym}\t{rel}:{lineno}\ta MONEY symbol named inside a control surface \
                             (`{ident}`). A control surface is UNMETERED: it never names an \
                             amount, a rate, a fee, a card or a posting — the vocabulary is \
                             `plane-no-money`'s, verbatim"
                        ));
                    }
                }
            }
        }
        for (lineno, code) in scan::production_lines(&f.text) {
            // BLANK THE LITERALS FIRST. A ban on an identifier that would equally match its own
            // prose in a `format!` is a ban that reds on documentation.
            let code = scan::blank_literals(&code);
            let lower = code.to_lowercase();

            // NO CRATE NAMES A CRATE IT DOES NOT DEPEND ON, whatever kind either of them is.
            //
            // `banned_for` had an arm for four kind words, so `store`, `auth`, `secret`, `hooks`,
            // `export`, `unit`, `kernel` and `substrate` source could name ANY other kind freely —
            // a red team put `busbar_plane_llm::VERSION` and `busbar_transport_http::Client` in
            // `crates/store-memory/src` and this row scanned zero files of it. The generalisation
            // is not a longer list of kind words: it is that naming a crate path you declare no
            // dependency on is a reach with no edge to score, in EVERY direction at once. Where the
            // dependency exists the edge is in the ledger, at its exact count, with its verdict.
            for (path, owner) in &crate_paths {
                if owner.as_str() == me.name || !lower.contains(path.as_str()) {
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

            for (needle, why) in &banned {
                let hit = if needle.contains(':') || needle.ends_with('_') || needle.ends_with('-')
                {
                    lower.contains(needle.as_str())
                } else {
                    word_ci(&lower, needle)
                };
                if hit {
                    offenders.push(format!(
                        "{needle}\t{rel}:{lineno}\t{why} ({kind} crate): {}",
                        code.trim()
                    ));
                }
            }
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
    let mut routes: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for c in crates.iter().filter(|c| c.kind == Some("control")) {
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
fn entry_trait(kind: &str) -> String {
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
        if rel.starts_with(&format!("{dir}/tests/")) && rel.contains(CONFORMANCE_MARKER) {
            let (live, _ignored) = live_battery_entries(&f.text);
            if live > 0 {
                idx.conformance.insert(dir.clone());
                idx.conformance_dead.remove(&dir);
            } else if !idx.conformance.contains(&dir) {
                idx.conformance_dead.insert(dir.clone());
            }
        }
        if !is_shipped_source(&rel) {
            continue;
        }
        if rel == format!("{dir}/src/lib.rs") {
            idx.has_lib.insert(dir.clone());
            let mods = idx.skeleton.entry(dir.clone()).or_default();
            for (_, code) in scan::production_lines(&f.text) {
                let t = code.trim();
                let body = t
                    .strip_prefix("pub mod ")
                    .or_else(|| t.strip_prefix("mod "));
                if let Some(name) = body.and_then(|b| b.split(&[';', ' ', '{'][..]).next()) {
                    if !name.is_empty() {
                        mods.insert(name.to_string());
                    }
                }
            }
        }
        let counts = idx.impls.entry(dir.clone()).or_default();
        for t in impl_heads(&f.text) {
            *counts.entry(t).or_default() += 1;
        }
    }
    Ok(idx)
}

fn rule_shape(crates: &[CrateInfo], idx: &SourceIndex) -> Row {
    let dir_of: BTreeMap<&str, &str> = crates
        .iter()
        .map(|c| (c.name.as_str(), c.dir.as_str()))
        .collect();
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (kind, exemplar) in EXEMPLARS {
        let Some(ex_dir) = dir_of.get(exemplar) else {
            offenders.push(format!(
                "no-exemplar\t{exemplar}\tthe canonical sibling for kind `{kind}` is not in the \
                 tree, so this kind's skeleton is derived from nothing"
            ));
            continue;
        };
        let want_trait = entry_trait(kind);
        let ex_impls = idx.impls.get(*ex_dir).cloned().unwrap_or_default();
        let ex_entries = ex_impls.get(&want_trait).copied().unwrap_or(0);
        if ex_entries != 1 {
            offenders.push(format!(
                "no-entry\t{ex_dir}\tkind `{kind}` states no single entry: the exemplar implements \
                 `{want_trait}` {ex_entries} time(s) in shipped source, so there is no one \
                 declaration every crate of the kind owes"
            ));
        }
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
            // The dialect and its plane are one face by design.
            if mine == "dialect" && *owner == "plane" {
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
const STEP_TABLE_FILE: &str = "crates/busbar-caps/src/step.rs";
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
        .filter(|c| c.kind == Some("control"))
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
        for dep in c.deps.iter().chain(c.dev_deps.iter()) {
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
    for w in &wires {
        let here = sites.get(&w.name).cloned().unwrap_or_default();
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
        "a wire is registered twice, or a plugin links the crate that moves the bytes",
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
///
/// AND IT REFUSES IF THE GATE WOULD STILL BE RED ONCE IT HAD WRITTEN — which is a different tree
/// from the one on disk, and the only one the question is about. Measuring the disk was a
/// CATCH-22 with a laundering path at the end of it: every deletion reds the ordinary run on
/// exactly the stale slack this flag exists to drain, so the flag refused every landing it was
/// built for and the drainers edited the ledger by hand instead. See the note in the body.
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
    //
    // THE CATCH-22 THIS ARM USED TO BE, AND THE LAUNDERING PATH IT OPENED. The refusal measured the
    // tree AS IT STANDS ON DISK — and every DELETION makes that tree red on exactly the stale slack
    // `--write` exists to drain. The ratchet is exact in BOTH directions, so a cut that removes two
    // of a crate's plane hits leaves the row two too high and `:matrix` says so, by name, as
    // "STALE SLACK". The flag built to lower that number refused to run because the number was not
    // lowered yet. So `--write` refused every landing it was built for, and the drainers reached
    // for the ledger by hand instead — which is the laundering path this gate closed at the front
    // door and left standing at the back.
    //
    // So the measurement is taken against the RE-PINNED FILE, in memory, before a byte reaches the
    // disk. The question a re-pin has to answer was never "is the tree clean?" — it is "is the tree
    // this write would produce clean?", and only the second one can be answered before the write.
    //
    // NOTHING IS LOOSENED BY THAT, and the exactness of the ratchet is what guarantees it. The
    // overlay carries one edit and one only: each EXISTING row's count set to what this same run
    // measured, downward (a rise returned above). A row whose only finding is that slack is green
    // against it and stops refusing. Everything else is untouched and still red there — a raise, an
    // UNLISTED cell (`repins` never invents a row, so a cell with no `[[cell]]` is not re-pinned
    // and stays unlisted), a minted row, a dead allowance, an unlisted edge, a measurement
    // disagreement, a plane word in a transport — and any one of them still refuses WHOLESALE.
    //
    // The overlay is layered ON the context's own, so a planted tree in the self-test is measured
    // as the plant left it and not as the disk stands.
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
    let mut overlay = cx.overlay().cloned().unwrap_or_default();
    overlay.set(REGISTRY_FILE, rewritten.clone());
    let ordinary = KindIsolationGate::check().run(&cx.with_overlay(overlay));
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
                "{} row(s) would STILL be red once every count this run would lower had been \
                 lowered; NOTHING was written. A count re-pinned while another rule is failing is \
                 a ledger that LOOKS reviewed and is not — and the row that would be lowered is \
                 not necessarily the row that is wrong. Fix the tree, then re-pin. Red: {}. Run \
                 `cargo xtask gate kind-isolation` for the findings themselves.",
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
    // A MEASUREMENT TAKEN THROUGH AN OVERLAY DESCRIBES NO TREE ON DISK, so it is never written to
    // one. The self-test plants its trees that way, and a `--write` that committed a planted
    // tree's counts to the real `qa/kind-isolation.toml` would be a battery that edits the ledger
    // it is proving — the exact thing the arm's own note says a self-test must not do. The re-pin
    // is measured, reported in full, and left in memory.
    if cx.overlay().is_some() {
        return Row::pass(
            ROW_WRITE,
            "every count that fell is re-pinned to what the tree measures",
            format!(
                "{} row(s) would be lowered in {REGISTRY_FILE} and the gate is green once they \
                 are; the tree was read through an overlay, which describes no file on disk, so \
                 nothing was written: {}",
                down.len(),
                down.iter()
                    .map(|r| format!("{} {} -> {}", r.label, r.was, r.now))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
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
}

impl KindIsolationGate {
    /// The per-push gate: the four rows the tree holds today.
    pub fn check() -> KindIsolationGate {
        KindIsolationGate {
            ship: false,
            write: false,
        }
    }

    /// The write arm. It is a SEPARATE construction rather than a flag read off the context inside
    /// `run`, so `owed` — which the reconciliation is written against — can say what this run emits.
    pub fn write() -> KindIsolationGate {
        KindIsolationGate {
            ship: false,
            write: true,
        }
    }

    /// The release-time twin: the same four, plus the surface and battery criteria.
    pub fn ship() -> KindIsolationGate {
        KindIsolationGate {
            ship: true,
            write: false,
        }
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
                let mut rows: Vec<Row> = [ROW_NAME, ROW_DEPS, ROW_REGISTRY, ROW_MATRIX]
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

        // THE WRITE ARM PROVES ITSELF WITHOUT WRITING ANYTHING, and that is not a compromise:
        // every case here is planted through an overlay, and a measurement taken through an
        // overlay describes no file on disk, so `rule_write` reports the re-pin and declines to
        // commit it. A battery that edited the ledger it is proving would be a battery that makes
        // itself pass; the refusal to write a planted tree's counts is in the rule, not in the
        // restraint of the cases.
        if self.write {
            report.push(prove_rows_green(
                cx,
                self,
                "every count already equals the measurement, so --write writes nothing",
                &[ROW_WRITE],
                Overlay::new(),
            ));
            report.push(prove_rows_red(
                cx,
                self,
                "--write refuses wholesale when any count would RISE",
                &[ROW_WRITE],
                registry_with(
                    cx,
                    "crate = \"busbar-kernel\"\nkind = \"plane\"\ncount = \"1\"",
                    "crate = \"busbar-kernel\"\nkind = \"plane\"\ncount = \"0\"",
                ),
                &[
                    "would RISE",
                    "NOTHING was written",
                    "busbar-kernel × plane 0 -> 1",
                ],
            ));
            // …AND THE WRITE ARM MEASURES THE WHOLE GATE BEFORE IT WRITES ANYTHING. It did not:
            // `owed()` returned one row in write mode and `run` returned one row, so
            // `gate kind-isolation --write` ran the re-pin and NOTHING ELSE. A red team put plane
            // words in a transport's `lib.rs` — a tree the ordinary run reds three ways — and got
            // `PASS kind-isolation:write … 1 row(s), green` and `EXIT=0` out of the same binary.
            // Every rule this gate has, one flag away. The plant is that tree.
            report.push(prove_rows_red(
                cx,
                self,
                "--write refuses on a tree the ordinary run reds, whatever the counts would do",
                &[ROW_WRITE],
                registry_with(
                    cx,
                    "from    = \"busbar-transport-tls\"\nto      = \"busbar-unit-transport-key\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"not-allowed\"",
                    "from    = \"busbar-transport-tls\"\nto      = \"busbar-unit-transport-key\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"allowed\"",
                ),
                &[
                    "the gate is RED",
                    "NOTHING was written",
                    "kind-isolation:deps",
                ],
            ));

            // …AND THE TREE IT MEASURES IS THE ONE THIS WRITE WOULD PRODUCE, NOT THE ONE ON DISK.
            //
            // The refusal above measured the disk, and that made this flag refuse every landing it
            // was built for. The ratchet is exact in BOTH directions, so a DELETION — the landing
            // the whole mechanism exists to make cheap — leaves the row it drained too high and
            // `:matrix` reds on it as STALE SLACK. `--write` then declined to lower the number
            // because the number was not lowered yet, and the drainers reached for the ledger by
            // hand instead: the laundering path this gate closed at the front door.
            //
            // THE PLANT IS A DRAINED CELL. A count above its measurement is what a cut leaves
            // behind, and it is the one finding the re-pin itself answers, so the tree this write
            // would produce is green and the write goes through.
            report.push(prove_rows_green(
                cx,
                self,
                "--write re-pins a tree whose ONLY finding is the stale slack it would lower",
                &[ROW_WRITE],
                registry_with(
                    cx,
                    "crate = \"busbar\"\nkind = \"api\"\ncount = \"122\"",
                    "crate = \"busbar\"\nkind = \"api\"\ncount = \"222\"",
                ),
            ));

            // AND NOTHING ELSE IS LET THROUGH WITH IT. These two are the exclusion's own edges: a
            // finding the re-pin does NOT answer still refuses wholesale, whether it is a cell the
            // ledger never listed — `repins` visits rows that already exist, so an unlisted cell is
            // not re-pinned and is exactly as red against the re-pinned file as against the disk —
            // or a cell that ROSE, which is the landing that grew the coupling and is read by a
            // person.
            report.push(prove_rows_red(
                cx,
                self,
                "--write still refuses wholesale on an UNLISTED cell, which no re-pin answers",
                &[ROW_WRITE],
                registry_with(
                    cx,
                    "[[cell]]\ncrate = \"busbar\"\nkind = \"api\"\ncount = \"122\"\n",
                    "",
                ),
                &[
                    "the gate is RED",
                    "NOTHING was written",
                    "kind-isolation:matrix",
                ],
            ));
            report.push(prove_rows_red(
                cx,
                self,
                "--write still refuses wholesale on a RAISED cell, even beside slack it would lower",
                &[ROW_WRITE],
                {
                    let mut ov = Overlay::new();
                    ov.set(
                        REGISTRY_FILE,
                        cx.read(REGISTRY_FILE)
                            .unwrap_or_default()
                            .replacen(
                                "crate = \"busbar\"\nkind = \"api\"\ncount = \"122\"",
                                "crate = \"busbar\"\nkind = \"api\"\ncount = \"222\"",
                                1,
                            )
                            .replacen(
                                "crate = \"busbar\"\nkind = \"caps\"\ncount = \"302\"",
                                "crate = \"busbar\"\nkind = \"caps\"\ncount = \"3\"",
                                1,
                            ),
                    );
                    ov
                },
                &[
                    "would RISE",
                    "NOTHING was written",
                    "busbar × caps 3 -> 302",
                ],
            ));
            return report;
        }

        // THE UNPLANTED ARM. It is narrowed to the four enforceable rows in the ship twin, and
        // that narrowing is the honest form of the claim: the two ship rows are RED on this tree
        // ON PURPOSE (the criterion is about the ship SHA), so asserting them green here would be
        // asserting the opposite of what the gate is for.
        if self.ship {
            // `:deps` leaves this arm on the ship twin for the same reason `:shape` and `:testkit`
            // were never in it: it now carries the TRANSITIONAL ratchet, whose whole claim is about
            // the ship SHA. Every legacy crate is still in the tree today, so every transitional
            // row is red here BY DESIGN, and asserting the row green would be asserting that the
            // drain has finished. The row's ship behaviour is proven by the two planted cases
            // below instead — one for the drain unfinished, one for a scratch tree where it is.
            report.push(prove_rows_green(
                cx,
                self,
                "the real tree keeps its plugin kinds apart (the enforceable rows)",
                &[ROW_NAME, ROW_VOCAB, ROW_REGISTRY, ROW_STEPS, ROW_WIRES],
                Overlay::new(),
            ));
        } else {
            report.push(prove_green(
                cx,
                self,
                "the real tree keeps its plugin kinds apart",
                &[
                    ROW_NAME,
                    ROW_DEPS,
                    ROW_TEST_DEPS,
                    ROW_VOCAB,
                    ROW_REGISTRY,
                    ROW_STEPS,
                    ROW_WIRES,
                ],
            ));
        }

        // THE RULING ITSELF, PLANTED. `busbar-transport-a2a` is the crate the owner refused, and
        // this is the fixture that proves the refusal is mechanical.
        report.push(prove_rows_red(
            cx,
            self,
            "the refused `busbar-transport-a2a` — a kind fused with another kind's instance",
            &[ROW_NAME],
            manifest_plant("crates/busbar-transport-a2a", "busbar-transport-a2a", &[]),
            &["busbar-transport-a2a", "a2a", MAKE_A_NEW_KIND],
        ));

        // THE OTHER TWO DIRECTIONS of the same rule.
        report.push(prove_rows_red(
            cx,
            self,
            "a plane named after a transport instance (`busbar-plane-http`)",
            &[ROW_NAME],
            manifest_plant("crates/busbar-plane-http", "busbar-plane-http", &[]),
            &["busbar-plane-http", "http"],
        ));
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
            "no reviewed sentence can waive a crate whose whole name is another kind's instance",
            &[ROW_NAME],
            manifest_plant("crates/busbar-unit-llm", "busbar-unit-llm", &[]),
            &[
                "fused-instance-name",
                "busbar-unit-llm",
                "a waiver excuses a QUALIFIER, never a fusion",
            ],
        ));

        // THE SAME FUSION IN A KIND THAT ALREADY CARRIES A WAIVER. Shorten the reviewed
        // `busbar-auth-admin-tokens` to `busbar-auth-admin` and the qualifier is gone: what is left
        // is an auth plugin named for the control surface's instance. The waiver beside it does not
        // move, and the crate is refused anyway.
        report.push(prove_rows_red(
            cx,
            self,
            "shortening a waived name to the fusion form is refused with the waiver still standing",
            &[ROW_NAME],
            manifest_plant("crates/auth-admin-tokens", "busbar-auth-admin", &[]),
            &["fused-instance-name", "busbar-auth-admin", "admin"],
        ));

        // THE PLANE-TRANSPORT the ruling names by name: two KIND words, no instance at all.
        report.push(prove_rows_red(
            cx,
            self,
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
        // its kind, and a dialect is the ONLY four-segment form.
        report.push(prove_rows_red(
            cx,
            self,
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
        ov.remove("crates/auth-admin-tokens/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            self,
            "an accepted-name waiver whose crate is gone is reported dead",
            &[ROW_NAME],
            ov,
            &["dead-waiver", "busbar-auth-admin-tokens"],
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
                self,
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

        // THE SAME REACH OUT OF A CONTROL SURFACE, refused by its own closed sink set rather than
        // by the measured graph — a control crate names the contract and nothing else, whether or
        // not the tree has ever grown the edge.
        report.push(prove_rows_red(
            cx,
            self,
            "a control surface depending on a transport crate",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-plane-admin",
                "busbar-plane-admin",
                &["busbar-contract", "busbar-transport-http"],
            ),
            &[
                "control-sink",
                "busbar-plane-admin",
                "busbar-transport-http",
            ],
        ));

        // A PLANE REACHING A CONTROL SURFACE. The metered path and the control path are two kinds;
        // a control surface never appears in a plane's step list.
        report.push(prove_rows_red(
            cx,
            self,
            "a plane depending on a control surface",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-plane-mcp",
                "busbar-plane-mcp",
                &["busbar-contract", "busbar-plane-admin"],
            ),
            &["plane-control", "busbar-plane-mcp"],
        ));

        // A CONTROL SURFACE NAMING A PRICE. The vocabulary is `plane-no-money`'s, verbatim: one
        // list, read off the file that argued for it, so the two rules cannot drift apart.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-admin/src/planted_money.rs",
            "pub fn charge(card: u32) -> u32 { let rate_card = card; let fee_cents = rate_card; \
             fee_cents }\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a control surface naming a money symbol from the plane-no-money list",
            &[ROW_VOCAB],
            ov,
            &["fee_cents", "planted_money.rs", "MONEY"],
        ));

        // TWO CONTROL SURFACES, ONE ROUTE. The claim table is DATA, which is the only reason this
        // is checkable at all: the second surface's prefix is a list of literal segments in its own
        // source, not a string a handler builds.
        let mut ov = manifest_plant(
            "crates/busbar-control-planted",
            "busbar-control-planted",
            &["busbar-contract"],
        );
        ov.set(
            "crates/busbar-control-planted/src/claims.rs",
            "pub const P: &[PathSeg] = &[PathSeg::Lit(\"api\"), PathSeg::Lit(\"v1\"), \
             PathSeg::Lit(\"admin\"), PathSeg::Tail];\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "two control surfaces claiming the same route",
            &[ROW_REGISTRY],
            ov,
            &[
                "shared-route",
                "busbar-control-planted",
                "busbar-plane-admin",
            ],
        ));

        // THE REGISTRATION EXPIRES WITH THE RENAME IT WAS WRITTEN FOR. Land `busbar-control-admin`
        // and the row says what the name already says; the gate asks for it to be struck in the
        // same commit rather than left standing as a list nobody reads.
        let mut ov = manifest_plant(
            "crates/busbar-control-admin",
            "busbar-control-admin",
            &["busbar-contract"],
        );
        ov.set(
            REGISTRY_FILE,
            "[[registered]]\ncrate = \"busbar-control-admin\"\nkind = \"control\"\nreason = \
             \"planted\"\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a registration whose crate name already says its kind is redundant",
            &[ROW_REGISTRY],
            ov,
            &["redundant-registration", "busbar-control-admin"],
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
                self,
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
            self,
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
            self,
            "a product crate path-depending on an OFF-TREE manifest is refused",
            &[ROW_REGISTRY],
            ov,
            &[
                "off-tree-reached",
                "xtask/fixtures/wire-bridge",
                "busbar-transport-tcp",
            ],
        ));

        // …AND A REGISTRATION FOR A CRATE THAT IS NOT THERE IS A KIND ASSIGNMENT FOR NOTHING.
        report.push(prove_rows_red(
            cx,
            self,
            "a registration naming a crate the tree does not have",
            &[ROW_REGISTRY],
            registry_plant(
                "[[registered]]\ncrate = \"busbar-control-ghost\"\nkind = \"control\"\nreason = \
                 \"planted\"\n",
            ),
            &["dead-registration", "busbar-control-ghost"],
        ));

        // ONE PLANE REACHING INTO ANOTHER PLANE'S HALF.
        report.push(prove_rows_red(
            cx,
            self,
            "a plane depending on another plane's codec is cross-instance",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-plane-llm",
                "busbar-plane-llm",
                &["busbar-contract", "busbar-mcp-codec"],
            ),
            &["cross-instance", "busbar-plane-llm"],
        ));

        // …AND THE DIALECT DIRECTION, WHICH IS THE ONE THE SPLIT DEPENDS ON. `cross-instance` reads
        // the two crates' INSTANCES and says nothing when they match, so a plane reaching back into
        // its OWN dialect walked through it: same instance, same family, no finding. That edge is
        // the re-fusion the `busbar-plane-<plane>-<dialect>` rename exists to undo — a dialect names
        // its plane, a plane never names a dialect — and a mutation campaign found nothing proving
        // it. The plant is the first crate of the pending `dialect` kind plus the edge back.
        let mut ov = manifest_plant(
            "crates/busbar-plane-llm-openai",
            "busbar-plane-llm-openai",
            &["busbar-plane-llm"],
        );
        ov.set(
            "crates/busbar-plane-llm/Cargo.toml",
            manifest_plus(
                cx,
                "crates/busbar-plane-llm/Cargo.toml",
                "\n[dependencies]\nbusbar-plane-llm-openai = { workspace = true }\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a plane depending on its own dialect is the re-fusion the rename exists to undo",
            &[ROW_DEPS],
            ov,
            &["plane-names-dialect", "busbar-plane-llm-openai"],
        ));

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
                self,
                "an edge instance no crate has any more is reported as a dead allowance",
                &[ROW_DEPS],
                manifest_plant("crates/busbar-contract", "busbar-contract", &[]),
                &[
                    "dead-dep-edge",
                    "busbar-contract -> busbar-grammar",
                    "Strike the row",
                ],
            ));

            // A SECTION HEADER THIS READER CANNOT PARSE IS A REFUSAL, NOT A SKIP. The dotted-key
            // form sits under no `[section]` at all: `:deps` never saw it, and the only net that
            // did was the `Cargo.lock` cross-check, which is itself census-gated.
            report.push(prove_rows_red(
                cx,
                self,
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
                self,
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
                self,
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
            report.push(prove_rows_red(
                cx,
                self,
                "a negative `[[cell]]` count is refused at load — it is not a ceiling, it is the \
                 absence of one",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "crate = \"busbar\"\nkind = \"api\"\ncount = \"122\"",
                    "crate = \"busbar\"\nkind = \"api\"\ncount = \"-1\"",
                ),
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
            report.push(prove_rows_red(
                cx,
                self,
                "a `[[transitional]]` glob that covers more than one kind's prefix is refused",
                &[ROW_DEPS],
                registry_with(cx, "to = \"busbar-unit-*\"", "to = \"*\""),
                &[
                    "bad-glob",
                    "covers EVERY crate in the tree",
                    "busbar-<kind>-*",
                ],
            ));

            // A ROW THAT LEFT SLACK. The other half of the ratchet, and the one a class table could
            // never hold: a count BELOW the measurement is drift nobody drained on the commit that
            // drained the edge.
            report.push(prove_rows_red(
                cx,
                self,
                "a dependency row left above the count it measures — stale slack is how drift hides",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "from    = \"busbar-kernel\"\nto      = \"busbar-caps\"\nhalf    = \"shipped\"\ncount   = \"1\"",
                    "from    = \"busbar-kernel\"\nto      = \"busbar-caps\"\nhalf    = \"shipped\"\ncount   = \"9\"",
                ),
                &[
                    "dep-ratchet",
                    "busbar-kernel -> busbar-caps",
                    "STALE SLACK",
                ],
            ));

            // A ROW THAT GRANTED ITSELF AN EDGE THE ARCHITECTURE WITHHOLDS. `allowed` is a READING
            // of ARCHITECTURE.md, not an opinion a ledger row is entitled to hold — otherwise the
            // ledger IS the architecture and the ratchet loosens by editing one word.
            report.push(prove_rows_red(
                cx,
                self,
                "a ledger row cannot grant itself an edge the architecture withholds",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "from    = \"busbar-transport-tls\"\nto      = \"busbar-unit-transport-key\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"not-allowed\"",
                    "from    = \"busbar-transport-tls\"\nto      = \"busbar-unit-transport-key\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"allowed\"",
                ),
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
            report.push(prove_rows_red(
                cx,
                self,
                "an unruled edge whose question was struck out has stopped asking",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "[[question]]\nfrom     = \"busbar-substrate\"\nto       = \"busbar-api\"",
                    "[[question]]\nfrom     = \"busbar-substrate-values\"\nto       = \"busbar-api\"",
                ),
                &["unasked-question", "busbar-substrate -> busbar-api"],
            ));

            // TWO ROWS FOR ONE EDGE. Two numbers for one measurement, and the one a reader believes
            // is the one nobody checked.
            report.push(prove_rows_red(
                cx,
                self,
                "two rows for one edge is two numbers for one measurement",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "[[dep]]\nfrom    = \"busbar-kernel\"\nto      = \"busbar-caps\"",
                    "[[dep]]\nfrom    = \"busbar-kernel\"\nto      = \"busbar-caps\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"allowed\"\ncite    = \"x\"\nwhy     = \"x\"\ndrain   = \"x\"\n\n[[dep]]\nfrom    = \"busbar-kernel\"\nto      = \"busbar-caps\"",
                ),
                &["duplicate-dep", "busbar-kernel -> busbar-caps"],
            ));

            // A ROW WITH A NUMBER AND NO SENTENCE IS A BUDGET — refused at LOAD, by the same reader
            // that refuses a `[[cell]]` with half a sentence.
            report.push(prove_rows_red(
                cx,
                self,
                "a dependency row whose citation was emptied is refused at load",
                &[ROW_DEPS],
                registry_with(
                    cx,
                    "from    = \"busbar-kernel\"\nto      = \"busbar-caps\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"allowed\"\ncite    = \"",
                    "from    = \"busbar-kernel\"\nto      = \"busbar-caps\"\nhalf    = \"shipped\"\ncount   = \"1\"\nverdict = \"allowed\"\ncite    = \"\"\nunused  = \"",
                ),
                &["empty-field", "cite"],
            ));
        }

        // THE CONTRACT SINK IS THE SPEC'S, NOT A MEASUREMENT. `hooks -> contract` is in no snapshot
        // and never was; PLUGIN-TREE.md §4 grants it, as it grants every kind the contract. This case plants that
        // dependency and requires the row to stay GREEN — it was RED before the sink was read off
        // the spec, which is what made `store -> contract` a "new kind-to-kind edge class" the day
        // busbar-store-memory implemented the record contract, and failed the green baseline on the
        // real tree.
        //
        // The case is asked of the PER-PUSH gate only, for the reason the ship twin's own arm is
        // narrowed: on the ship sha `:deps` also carries the transitional ratchet, and every legacy
        // crate is still here, so the row is red there whatever this plant does.
        if !self.ship {
            report.push(prove_rows_red(
                cx,
                self,
                "an edge the architecture grants is still an edge that must be written down",
                &[ROW_DEPS],
                manifest_plant(
                    "crates/busbar-export-planted",
                    "busbar-export-planted",
                    &["busbar-contract"],
                ),
                &[
                    "unlisted-dep-edge",
                    "busbar-export-planted -> busbar-contract",
                    "export -> contract",
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
                self,
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
                self,
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
                self,
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
                self,
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
                self,
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
            self,
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
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-grammar/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            self,
            "a kind in the table that no crate is any more",
            &[ROW_REGISTRY],
            ov,
            &["dead-kind", "grammar"],
        ));

        // …AND THE RATCHET RUNS THE OTHER WAY FOR A PENDING ONE: the first crate of a pending kind
        // retires its entry, so a kind can never be both pending and live.
        report.push(prove_rows_red(
            cx,
            self,
            "a pending kind that now has crates must have its entry struck",
            &[ROW_REGISTRY],
            manifest_plant(
                "crates/busbar-plane-llm-openai",
                "busbar-plane-llm-openai",
                &["busbar-contract"],
            ),
            &["kind-arrived", "dialect"],
        ));

        // THE RENAME ALIAS EXPIRES WITH THE CRATE IT TRANSLATES.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-plane-voice/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            self,
            "a plane alias that outlived the crate it translates",
            &[ROW_REGISTRY],
            ov,
            &["alias-retired", "busbar-plane-voice"],
        ));

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
            self,
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
            self,
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
            self,
            "the second kind vocabulary absent is a refusal, never an agreement",
            &[ROW_REGISTRY],
            ov,
            &["unreadable", "qa/construction.toml"],
        ));

        // THE TWO FLOORS, AND THEY FAIL APART. A census that finds almost nothing recognises almost
        // everything, and a scan of no files names no leak — both read exactly like a clean tree.
        report.push(prove_rows_red(
            cx,
            self,
            "the crate census collapsed below its floor",
            &[ROW_REGISTRY],
            move || all_but(cx, "toml", 4),
            &["floor", &MIN_MANIFESTS.to_string()],
        ));
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
            "a :vocab scan that reached zero kind-bearing files is refused, not read as clean",
            &[ROW_VOCAB],
            move || all_but(cx, "toml", 0),
            &["0 file(s) reached the vocabulary rule"],
        ));

        // THE MONEY LIST IS THE CONTROL SURFACE'S BAN, and a ban over no words bans nothing.
        let mut ov = Overlay::new();
        ov.remove(MONEY_LIST_FILE);
        report.push(prove_rows_red(
            cx,
            self,
            "the money vocabulary unreadable is a refusal, never a surface that names no price",
            &[ROW_VOCAB],
            ov,
            &["A ban over no words bans nothing"],
        ));

        // A STEP LIST THAT READ TWO STEPS IS NOT A PLANE THAT RUNS EVERY STEP.
        let mut ov = Overlay::new();
        ov.set(
            STEP_TABLE_FILE,
            "pub const ALL: [StepName; 2] = [\n    StepName::Route,\n    StepName::Meter,\n];\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a step list that read fewer than five plane-owned steps is refused",
            &[ROW_STEPS],
            ov,
            &["floor", &MIN_PLANE_STEPS.to_string()],
        ));

        // A TREE WITH NO PLANE IN IT. Zero planes skip every step.
        report.push(prove_rows_red(
            cx,
            self,
            "a tree with no plane crate at all is refused by the step rule",
            &[ROW_STEPS],
            move || kind_gone(cx, "busbar-plane-"),
            &["0 plane crate(s)"],
        ));

        // A TREE WITH NO WIRE IN IT. Zero wires are registered twice.
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
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
            "crates/busbar-transport-sse/src/planted_plane_impl.rs",
            "pub struct Wire;\nimpl Plane for Wire {}\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a wire implementing a plane face",
            &[ROW_FACES],
            ov,
            &["foreign-entry", "busbar-transport-sse", "Plane"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-llm/src/planted_wire_impl.rs",
            "pub struct P;\nimpl Transport for P {}\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
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
            self,
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
                self,
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
                "crates/busbar-plane-admin/src/planted_second_plane.rs",
                "pub struct Second;\nimpl Plane for Second {}\n",
            );
            report.push(prove_rows_red(
                cx,
                self,
                "a second implementation of a reviewed foreign face is a landing that grew it",
                &[ROW_FACES],
                ov,
                &["face-ratchet", "busbar-plane-admin", "Plane"],
            ));

            // AND A ROW WHOSE IMPLEMENTATION IS GONE IS A DEAD ALLOWANCE.
            report.push(prove_rows_red(
                cx,
                self,
                "a reviewed face row that covers no implementation any more is struck",
                &[ROW_FACES],
                registry_with(
                    cx,
                    "crate = \"busbar-a2a\"\nface = \"Transport\"",
                    "crate = \"busbar-a2a-planted\"\nface = \"Transport\"",
                ),
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
            "an include path spliced out of pieces is refused, not resolved",
            &[ROW_INPUTS],
            ov,
            &["unresolvable-include", "concat", "busbar-transport-tcp"],
        ));

        // A LOCK FILE NAMING AN EDGE NO MANIFEST HAS. Nothing in the tree read `Cargo.lock` at all,
        // so the file that says what cargo COMPILES was never compared with the files that say what
        // was asked for.
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
            "a transport source naming a plane instance",
            &[ROW_VOCAB],
            ov,
            &["a2a", "mcp", "planted_leak.rs"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-admin/src/planted_axum.rs",
            "use axum::Router;\npub fn bind() { let _ = tokio::net::TcpListener::bind; }\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
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
            self,
            "comments, literals and cfg(test) scope name nothing TO `:vocab` (`:matrix` counts them)",
            &[ROW_VOCAB],
            ov,
        ));

        // A CRATE OF NO KIND AT ALL, answered in the owner's own words.
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
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
            self,
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
            self,
            "an off-tree exemption that outlived its manifest is refused",
            &[ROW_REGISTRY],
            ov,
            &["dead-off-tree", "examples/smart-router/rust-hook"],
        ));

        // THE LEGACY RATCHET, proven by retiring one.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-core/Cargo.toml");
        report.push(prove_rows_red(
            cx,
            self,
            "a legacy exemption that outlived its crate is refused",
            &[ROW_REGISTRY],
            ov,
            &["legacy-retired", "busbar-core"],
        ));

        // THE THREE TRUTHS, each planted in the file that carries it.
        truths::selftest(cx, self, &mut report);

        // ── THE LEGACY DRAIN, NAMED ──────────────────────────────────────────────────────────────

        // AN UNLISTED DRAIN EDGE IS RED. `busbar-llm` is a legacy crate and `busbar-unit-audit` is
        // a unit, so this is exactly the shape the owner's ruling permits — and no row names it.
        // Before the transitional table this edge was invisible: `legacy` was an unscored source,
        // so every legacy edge into every kind was allowed by silence.
        report.push(prove_rows_red(
            cx,
            self,
            "a legacy crate reaching a unit with no transitional row naming the edge",
            &[ROW_DEPS],
            manifest_plant("crates/busbar-llm", "busbar-llm", &["busbar-unit-audit"]),
            &["unlisted-transitional", "busbar-llm", "busbar-unit-audit"],
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
            self,
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
                "[[transitional]]\nfrom = \"busbar-core\"\nto = \"busbar-unit-*-x\"\nreason = \
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
                self,
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
            self,
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
            self,
            "a core crate named after a plane instance (`busbar-core-mcp`)",
            &[ROW_NAME],
            manifest_plant("crates/busbar-core-mcp", "busbar-core-mcp", &[]),
            &["busbar-core-mcp", "mcp"],
        ));

        // A CORE CRATE REACHES THE NEUTRAL SPINE AND NOTHING ELSE — the same sink set `kernel` and
        // `caps` have. A unit is not on it, so the edge is a new class.
        report.push(prove_rows_red(
            cx,
            self,
            "a core crate reaching a unit is a class the architecture grants nothing to",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-core-config",
                "busbar-core-config",
                &["busbar-substrate", "busbar-unit-audit"],
            ),
            &["announced-edge-class", "core -> unit"],
        ));

        // THE ANNOUNCEMENT IS WHAT HOLDS THE KIND ROW OPEN, not silence. Strike the rows while the
        // crates are still absent and the `core` kind is a dead row in the table — which is what
        // the dead-kind rule is for, and what it would have said the day the kind was added if the
        // announcement had not been made with it.
        report.push(prove_rows_red(
            cx,
            self,
            "the `core` kind row with neither a crate nor an announcement is a dead kind",
            &[ROW_REGISTRY],
            registry_plant(""),
            &["dead-kind", "core"],
        ));

        // …and the same on the waiver side: `busbar-core-hooks`'s reviewed sentence is a review
        // arriving BEFORE its crate, and the announcement is the only thing that distinguishes that
        // from a hole nobody re-reads.
        report.push(prove_rows_red(
            cx,
            self,
            "an accepted name for an unannounced crate that does not exist is a dead waiver",
            &[ROW_NAME],
            registry_plant(""),
            &["dead-waiver", "busbar-core-hooks"],
        ));

        // ── THE STRICT STEP LIST, AND THE WIRE REGISTRY ──────────────────────────────────────────

        // A PLANE THAT DOES NOT RUN A STEP. The plant removes one step's implementation from a data
        // plane by replacing the file that holds it; the step list is read off the kernel's own
        // table, so the finding names the step the loop expected.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-plane-mcp/src/plane.rs");
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
            "the strict step list being unreadable is refused, not read as no steps",
            &[ROW_STEPS],
            ov,
            &[STEP_TABLE_FILE],
        ));

        // A PLUGIN LINKING THE CRATE THAT MOVES THE BYTES. A plane declares WHICH transport it
        // claims, as data; the moment it links the wire it has chosen one.
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
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
            self,
            "a plugin whose TEST binary links a wire has chosen one just the same",
            &[ROW_WIRES],
            ov,
            &["wire-dependency", "busbar-store-memory", "dev-dependencies"],
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
            self,
            "a wire composed in a second place",
            &[ROW_WIRES],
            ov,
            &["second-registration", "busbar-transport-http"],
        ));

        // THE MATRIX ROW'S OWN CASES, owed by BOTH registrations: the per-push gate holds the
        // ceilings and the ship twin holds zero, and neither is a claim the other proves.
        matrix::selftest(cx, self, self.ship, &mut report);

        if !self.ship {
            // A LISTED DRAIN EDGE IS GREEN. The owner's ruling, as the per-push gate reads it:
            // while busbar-core drains it MAY name a unit, because a `[[transitional]]` row names
            // the edge.
            //
            // IT OWES ITS `[[dep]]` ROW TOO, and both halves of that are the point. The
            // transitional row says the EDGE CLASS is the drain rather than the fusion; the `[[dep]]`
            // row says how many declarations there are, exactly, so the drain cannot quietly grow a
            // second one. The plant APPENDS to the real manifest rather than rewriting it, because
            // a rewrite would strike busbar-core's real edges and the dead-row findings that
            // produced are the ones a reader would mistake for this case's own.
            let mut ov = Overlay::new();
            ov.set(
                "crates/busbar-core/Cargo.toml",
                manifest_plus(
                    cx,
                    "crates/busbar-core/Cargo.toml",
                    "\n[dependencies]\nbusbar-unit-audit = { workspace = true }\n",
                ),
            );
            ov.set(
                REGISTRY_FILE,
                format!(
                    "{}\n\n[[dep]]\nfrom    = \"busbar-core\"\nto      = \"busbar-unit-audit\"\n\
                     half    = \"shipped\"\ncount   = \"1\"\nverdict = \"not-allowed\"\n\
                     cite    = \"the legacy drain: ARCHITECTURE.md 1.1 grants a legacy crate no unit \
                     edge, and the [[transitional]] row above names this one as the retirement in \
                     flight.\"\nwhy     = \"busbar-core is moving the audit step out into \
                     busbar-unit-audit; one shipped declaration states it.\"\ndrain   = \"finish \
                     the move and delete busbar-core.\"\n",
                    cx.read(REGISTRY_FILE).unwrap_or_default().trim_end()
                ),
            );
            report.push(prove_rows_green(
                cx,
                self,
                "a legacy crate reaching a unit through a named transitional row and its own count",
                &[ROW_DEPS],
                ov,
            ));

            // THE TWO CORE CRATES LANDING IS GREEN — no unknown kind, no dead kind, no dead waiver,
            // no new edge class. This is the case the announcement exists to make true: the agent
            // who lands them reds nothing.
            let mut ov = manifest_plant(
                "crates/busbar-core-config",
                "busbar-core-config",
                &["busbar-substrate"],
            );
            ov.set(
                "crates/busbar-core-hooks/Cargo.toml",
                "[package]\nname = \"busbar-core-hooks\"\nversion = \"0.0.0\"\n\n[dependencies]\n\
                 busbar-api = { workspace = true }\n",
            );
            report.push(prove_rows_green(
                cx,
                self,
                "the two announced core crates landing red nothing",
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
        let mut ov = manifest_plant(
            "crates/busbar-control-planted",
            "busbar-control-planted",
            &["busbar-contract"],
        );
        ov.set(
            "crates/busbar-control-planted/src/lib.rs",
            "pub struct P;\nimpl P {\n    fn route(&self) -> u8 { 0 }\n}\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a control surface implementing a data-path step",
            &[ROW_CONTROL],
            ov,
            &["data-path-step", "busbar-control-planted", "route"],
        ));

        let mut ov = manifest_plant(
            "crates/busbar-control-planted",
            "busbar-control-planted",
            &["busbar-contract"],
        );
        ov.set(
            "crates/busbar-control-planted/src/lib.rs",
            "pub fn pick(pool: u8) -> u8 { let failover = pool; failover }\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a control surface naming the vocabulary of reaching an upstream",
            &[ROW_CONTROL],
            ov,
            &["upstream", "busbar-control-planted", "pool"],
        ));

        // A TRANSITIONAL ROW WHOSE CRATE IS STILL HERE AT SHIP TIME IS RED, and this is the real
        // tree: `busbar-core` exists, so the DONE oracle refuses the tag and names the crate. The
        // exemption's expiry rule is the crate, not the edge.
        report.push(prove_rows_red(
            cx,
            self,
            "a transitional row is red at ship time while its legacy crate still exists",
            &[ROW_DRAIN],
            Overlay::new(),
            &["transitional-live", "busbar-core", "ship"],
        ));

        // …AND GREEN WHEN THE DRAIN IS ACTUALLY DONE. The scratch tree the criterion is about: the
        // table is empty and the crates it excused are gone. Without this case the row above would
        // equally be produced by a ratchet that is simply red for ever.
        let mut ov = registry_plant("");
        ov.remove("crates/busbar-core/Cargo.toml");
        ov.remove("crates/busbar-voice/Cargo.toml");
        report.push(prove_rows_green(
            cx,
            self,
            "an empty transitional table over a tree whose legacy crates are gone",
            &[ROW_DRAIN],
            ov,
        ));

        // AN ANNOUNCEMENT DOES NOT SURVIVE ITS LANDING PAST A RELEASE. Landing the two core crates
        // is green on the per-push gate (proven above); on the ship sha the spent row is collected.
        let mut ov = manifest_plant(
            "crates/busbar-core-config",
            "busbar-core-config",
            &["busbar-substrate"],
        );
        ov.set(
            "crates/busbar-core-hooks/Cargo.toml",
            "[package]\nname = \"busbar-core-hooks\"\nversion = \"0.0.0\"\n\n[dependencies]\n\
             busbar-api = { workspace = true }\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "an announcement whose crate has landed is collected at ship time",
            &[ROW_REGISTRY],
            ov,
            &["announced-landed", "busbar-core-config"],
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
            self,
            "at the architecture's own graph, a transport reaching a plane is a NEW refusal",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-transport-stdio",
                "busbar-transport-stdio",
                &["busbar-contract-transport", "busbar-plane-llm"],
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
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
            self,
            "a kind whose exemplar states no single entry states nothing every member owes",
            &[ROW_SHAPE],
            ov,
            &["no-entry", "busbar-plane-a2a", "2 time(s)"],
        ));

        // A KIND WITH NO SHARED BATTERY AT ALL. The `plane` kind's battery is the one its members
        // already run — `tests/conformance.rs` in `busbar-plane-a2a` and `busbar-plane-mcp`. Take
        // both away and the kind has no battery to be judged against, so `not-run` (which is
        // guarded on there being one) says nothing about the other planes at all.
        let mut ov = Overlay::new();
        ov.remove("crates/busbar-plane-a2a/tests/conformance.rs");
        ov.remove("crates/busbar-plane-mcp/tests/conformance.rs");
        report.push(prove_rows_red(
            cx,
            self,
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
            self,
            "no crate of any exemplar kind reached the shape rule is refused, not read as clean",
            &[ROW_SHAPE],
            move || kinds_gone(cx, &["plane", "transport", "unit"]),
            &["0 crate(s) reached the shape rule"],
        ));

        // NO CRATE OF ANY BATTERY KIND REACHED `:testkit` — the same starvation over the nine kinds
        // that owe a shared conformance battery. Zero crates skip every battery.
        report.push(prove_rows_red(
            cx,
            self,
            "no crate of any battery kind reached the battery rule is refused, not read as clean",
            &[ROW_TESTKIT],
            move || kinds_gone(cx, BATTERY_KINDS),
            &["0 crate(s) reached the battery rule"],
        ));

        // NO CONTROL SURFACE REACHED `:control-path`. The tree carries exactly one control crate —
        // `busbar-plane-admin`, which is `control` by its `[[registered]]` row and not by its name —
        // so the honest fixture for "this rule looked at no surface at all" is that row's crate out
        // of the census. Zero surfaces run zero data-path steps and name zero upstreams, which reads
        // exactly like a control kind that keeps to its own path.
        report.push(prove_rows_red(
            cx,
            self,
            "no control surface reached the control-path rule is refused, not read as clean",
            &[ROW_CONTROL],
            move || kinds_gone(cx, &["control"]),
            &["0 control crate(s)"],
        ));

        // THE SOURCE INDEX IS THESE TWO ROWS' OWN INPUT, and it has a floor of its own. An index
        // built over four files knows of no lib.rs, no entry implementation and no battery anywhere
        // — which is the same silence as a tree in which every crate of every kind is correct. Both
        // ship rows owe the refusal, and they owe it together, because they read ONE index.
        report.push(prove_rows_red(
            cx,
            self,
            "the source index below its floor is refused on both ship rows, not read as no findings",
            &[ROW_SHAPE, ROW_TESTKIT],
            move || all_but(cx, "rs", 4),
            &["the source index did not run", &MIN_SOURCES.to_string()],
        ));

        report
    }
}

/// A planted [`REGISTRY_FILE`], holding `rows` and nothing else. The real file's comments carry the
/// reasoning; a plant carries only the rows under test, so what a case proves is what it wrote.
fn registry_plant(rows: &str) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(REGISTRY_FILE, rows.to_string());
    ov
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

/// The REAL registry file with one run of text rewritten, so a case can leave slack in a row, grant
/// it an edge the architecture withholds, strike a question or double a row — against the whole
/// file rather than a synthetic one, because a ledger of 220 rows is exactly the thing a plant of
/// three rows cannot stand in for.
fn registry_with(cx: &Ctx, from: &str, to: &str) -> Overlay {
    let text = cx.read(REGISTRY_FILE).unwrap_or_default();
    let mut ov = Overlay::new();
    ov.set(REGISTRY_FILE, text.replacen(from, to, 1));
    ov
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
