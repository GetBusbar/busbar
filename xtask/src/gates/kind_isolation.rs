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
//!   in [`MEASURED_EDGES`]. A NEW class is refused; a class that no longer exists is refused as a
//!   dead allowance. The measured graph is printed in the row's detail so the owner can tighten it
//!   by deleting lines rather than by re-deriving it. Inside the plane family a crate may only
//!   name its OWN instance, so `busbar-plane-llm` naming `busbar-mcp-codec` is refused.
//! * `kind-isolation:vocab` — non-comment, literal-blanked source of a kind-X crate never names
//!   another kind's instance identifiers: a transport never says `a2a`/`mcp`/`voice`/`llm`/`admin`,
//!   a plane never says `axum`/`hyper`/`tonic`/`tungstenite`/`tokio::net`, and neither a plane nor
//!   a codec ever names a transport crate.
//! * `kind-isolation:registry` — every crate in the census resolves to a kind IN THE TABLE. One
//!   that does not is refused with the owner's own instruction: **make a new plugin kind, do not
//!   fuse two.** The row also holds the census floor, the dead-kind rule, the
//!   `qa/construction.toml [gate.plugin_kinds]` cross-check and the LEGACY RATCHET.
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
use crate::scan;

mod matrix;
mod truths;

pub use matrix::ROW_MATRIX;
pub use truths::ROW_TRUTHS;

pub const ROW_NAME: &str = "kind-isolation:name";
pub const ROW_DEPS: &str = "kind-isolation:deps";
pub const ROW_VOCAB: &str = "kind-isolation:vocab";
pub const ROW_REGISTRY: &str = "kind-isolation:registry";
/// THE SHIP-CRITERION ROWS. Owed only by the `kind-isolation-ship` registration — see the twin's
/// note in [`KindIsolationGate`].
pub const ROW_SHAPE: &str = "kind-isolation:shape";
pub const ROW_TESTKIT: &str = "kind-isolation:testkit";
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

/// THE SINK EVERY KIND MAY NAME, BY SPEC AND NOT BY MEASUREMENT (`PLUGIN-TREE.md` §4).
///
/// Every row of the PLUGIN-TREE.md §4 table gives its kind `busbar-core-contract`: the contract IS the thing a
/// plugin is written against, and a kind that may not name it cannot be a plugin. Keeping those
/// edges in the measured snapshot below made them look like nine separate observations that
/// happened to be true, so the day `busbar-store-memory` became the first implementor of the record
/// contract the gate reported `store -> contract` as a NEW kind-to-kind edge class — a kind
/// learning about another kind — over a dependency the spec grants outright, and the green baseline
/// failed on the real tree. An edge to this sink is therefore never a new class and never a dead
/// allowance. The snapshot keeps what is genuinely a measurement: the non-contract edges.
const SPEC_SINK: &str = "contract";

/// THE KIND-TO-KIND EDGE CLASSES THIS TREE HAS TODAY, measured and then written down.
///
/// This is deliberately a MEASUREMENT rather than the narrower ideal graph the design calls for. The ideal is
/// narrower — planes reach the contract and their own codec, transports reach the transport
/// contract, units reach the contract and caps — and the tree is not all the way there. A gate that
/// asserted the ideal today would be red for reasons nobody can fix this week, and a gate that is
/// red for unfixable reasons is a gate somebody adds a `|| true` to. So the rule is the RATCHET
/// instead: THIS IS THE GRAPH, and a NEW edge class is refused. Tightening is deleting a line here
/// once the last edge in that class is gone — and the gate is red until the line goes, so the
/// tightening cannot be forgotten.
///
/// `root` is not a source: the composition root exists to depend on everything by design, so an edge
/// out of it is not news. `legacy` is not a source either — see the module header's ratchet.
///
/// The one sink it does NOT hold is `contract`: that edge is the spec's, not a measurement — see
/// [`SPEC_SINK`].
const MEASURED_EDGES: &[(&str, &str)] = &[
    ("api", "secret"),
    ("auth", "api"),
    ("auth", "plugin-tooling"),
    ("codec", "api"),
    ("codec", "grammar"),
    ("codec", "substrate"),
    ("codec", "timing"),
    ("contract", "contract-transport"),
    ("contract", "grammar"),
    ("export", "plugin-tooling"),
    ("hooks", "api"),
    ("hooks", "plugin-tooling"),
    ("kernel", "caps"),
    ("kernel", "grammar"),
    ("plane", "codec"),
    ("plugin-abi", "api"),
    ("plugin-tooling", "api"),
    ("plugin-tooling", "caps"),
    ("plugin-tooling", "kernel"),
    ("plugin-tooling", "plugin-abi"),
    ("plugin-tooling", "plugin-tooling"),
    ("plugin-tooling", "secret"),
    ("plugin-tooling", "unit"),
    ("secret", "api"),
    ("secret", "plugin-tooling"),
    // A store plugin implements the contract's record sink: the spec edge every plugin kind
    // carries, first taken by store-memory when the kernel record store landed.
    ("store", "contract"),
    ("store", "api"),
    ("store", "plugin-tooling"),
    ("substrate", "api"),
    ("substrate", "plugin-abi"),
    ("substrate", "substrate"),
    ("substrate", "timing"),
    ("transport", "contract-transport"),
    ("transport", "transport"),
    ("transport", "unit"),
    ("unit", "caps"),
    ("unit", "contract-transport"),
    ("unit", "unit"),
];

/// Kinds whose edges are not scored: the composition root, and the retiring legacy crates.
const UNSCORED_SOURCES: &[&str] = &["root", "legacy"];

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

/// [`REGISTRY_FILE`], read.
#[derive(Debug, Default)]
struct KindRegistry {
    transitional: Vec<Transitional>,
    announced: Vec<Announced>,
    registered: Vec<Registered>,
    /// The `:matrix` row's three tables. They live in this reader rather than in a second one
    /// because there is ONE registry file and a file read twice is a file two rules can disagree
    /// about.
    matrix_edges: Vec<MatrixEdge>,
    matrix_cells: Vec<MatrixCell>,
    matrix_disagreements: Vec<MatrixDisagreement>,
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
            reg.matrix_cells.push(MatrixCell {
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
        other => reg.errors.push(format!(
            "unknown-table\t{REGISTRY_FILE}:{at}\t`[[{other}]]` is not a table this gate reads; the \
             file holds `[[transitional]]`, `[[registered]]`, `[[announced]]`, `[[edge]]`, \
             `[[cell]]` and `[[disagreement]]` rows and nothing else"
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
                 `[[registered]]`, `[[announced]]`, `[[edge]]`, `[[cell]]` and `[[disagreement]]` \
                 rows and nothing else",
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
    /// `crates/<dir>`.
    dir: String,
    /// The package name from `[package] name = …`.
    name: String,
    /// `None` when the name matches no kind, or matches two at one precedence.
    kind: Option<&'static str>,
    family: Family,
    /// The name segments after the matched marker.
    remainder: Vec<String>,
    /// The instance this crate is an instance OF, when its remainder names one.
    instance: Option<String>,
    /// Normal (`[dependencies]`) dependency names, workspace crates only.
    deps: Vec<String>,
    /// `[dev-dependencies]` names. Scored by the battery rule and by NOTHING else: a test edge is
    /// not a shipped edge, and folding it into the kind graph would make every shared fixture read
    /// as a kind learning about another kind.
    dev_deps: Vec<String>,
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
        let t = raw.trim();
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

/// Every key of `[<section>]` and every `[<section>.<name>]` sub-table of one dependency section.
/// The kind graph reads `dependencies` — a dev-dependency is a test edge and the graph is a claim
/// about what SHIPS — and the battery rule reads `dev-dependencies`.
fn deps_of(text: &str, want: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let sub = format!("{want}.");
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(section) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let section = section.trim();
            in_deps = section == want;
            if let Some(name) = section.strip_prefix(sub.as_str()) {
                out.push(name.trim().to_string());
            }
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, _)) = t.split_once('=') else {
            continue;
        };
        let k = k.trim().trim_matches('"');
        if !k.is_empty() && !k.contains(' ') {
            out.push(k.to_string());
        }
    }
    out
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

fn census(cx: &Ctx) -> Result<Vec<CrateInfo>, String> {
    let reg = load_registry(cx).unwrap_or_default();
    let overrides = reg.overrides();
    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("toml"))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        // Exactly `crates/<dir>/Cargo.toml` — a manifest one level deeper belongs to a fixture.
        let parts: Vec<&str> = rel.split('/').collect();
        if parts.len() != 3 || parts[2] != "Cargo.toml" {
            continue;
        }
        let Some(name) = package_name(&f.text) else {
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
        out.push(CrateInfo {
            dir: format!("crates/{}", parts[1]),
            name,
            kind,
            family: family_of(kind),
            remainder,
            instance: None,
            deps: deps_of(&f.text, "dependencies"),
            dev_deps: deps_of(&f.text, "dev-dependencies"),
            ambiguous,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
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
// rule 2 — the dependency graph
// ------------------------------------------------------------------------------------------------

/// The measured graph, as the report prints it, so tightening is a delete rather than a re-derive.
fn render_graph(edges: &BTreeSet<(String, String)>) -> String {
    edges
        .iter()
        .map(|(a, b)| format!("{a}->{b}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn rule_deps(crates: &[CrateInfo], reg: &KindRegistry, ship: bool) -> Row {
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let drain_targets: BTreeSet<&str> = DRAIN_TARGET_KINDS.iter().copied().collect();
    let measured: BTreeSet<(String, String)> = MEASURED_EDGES
        .iter()
        .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
        .collect();
    let mut allowed = measured.clone();
    allowed.extend(
        PENDING_EDGES
            .iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string())),
    );
    let unscored: BTreeSet<&str> = UNSCORED_SOURCES.iter().copied().collect();

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    // A ROW REFUSED AT LOAD IS REPORTED, NOT DROPPED. A table that quietly skips what it cannot
    // understand is a table that says yes to it, and the row it skipped is the one somebody wrote
    // to get an edge past this rule.
    let mut offenders: Vec<String> = reg.errors.clone();

    for c in crates {
        let Some(from) = c.kind else { continue };
        for dep in &c.deps {
            let Some(target) = by_name.get(dep.as_str()) else {
                continue;
            };
            let Some(to) = target.kind else { continue };

            // THE PLANE FAMILY IS INSTANCE-SEALED. A plane's own codec is the intended shape; any
            // other instance is one plane reaching into another's vocabulary.
            if c.family == Family::Plane
                && target.family == Family::Plane
                && !unscored.contains(from)
            {
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

            // THE DRAIN, EDGE BY EDGE. `legacy` is an unscored SOURCE for the edges it always had;
            // it is not unscored for the edges the retirement CREATES. An edge into a kind the
            // drain targets is accepted only if a `[[transitional]]` row names it, so
            // `busbar-core -> busbar-unit-audit` reads as the drain and
            // `busbar-core -> busbar-transport-ws` reads as the fusion — which is the entire
            // difference the blanket exemption could not express.
            if from == "legacy"
                && drain_targets.contains(to)
                && !reg
                    .transitional
                    .iter()
                    .any(|t| t.covers(&c.name, dep.as_str()))
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

            if unscored.contains(from) {
                continue;
            }
            let edge = (from.to_string(), to.to_string());
            seen.insert(edge.clone());
            // The one edge the SPEC grants every kind, so it is never a new class and never a dead
            // allowance: see [`SPEC_SINK`].
            if to == SPEC_SINK {
                continue;
            }
            if !allowed.contains(&edge) {
                offenders.push(format!(
                    "new-edge-class\t{}\t{from} -> {to} ({} -> {dep}) is not in the measured graph \
                     — a NEW kind-to-kind edge class is a kind learning about another kind",
                    c.dir, c.name
                ));
            }
        }
    }

    // THE TRANSITIONAL TABLE IS EMPTY ON THE SHIP SHA, AND THIS IS WHERE THAT IS MEASURED.
    //
    // The row's expiry is deliberately NOT "its edge went away": the drain lands edge by edge,
    // branch after branch, and a row scored dead in the week between two branches would teach
    // everyone to delete the ratchet instead of the debt. The expiry is the crate. A transitional
    // row exists because a 1.5.x crate is retiring; if that crate is still in the tree at ship time
    // then the retirement did not happen, and the row is where the tag is refused, by name.
    if ship {
        for t in &reg.transitional {
            if by_name.contains_key(t.from.as_str()) {
                offenders.push(format!(
                    "transitional-live\t{REGISTRY_FILE}\t`{} -> {}` ({}) is a TRANSITIONAL \
                     exemption for the legacy drain and `{}` still exists at ship time. The \
                     exemption's expiry rule is that the crate must not exist on the ship sha: \
                     finish the drain and delete the crate, or the table is a permanent hole under \
                     a temporary name",
                    t.from, t.to, t.reason, t.from
                ));
            }
        }
    }

    // A DEAD ALLOWANCE IS RED, and that is how this ratchet tightens: the last edge in a class
    // going away makes the gate demand the line be struck.
    for edge in measured.difference(&seen) {
        offenders.push(format!(
            "dead-edge-class\tMEASURED_EDGES\t{} -> {} no longer exists in the tree; strike the \
             line so the graph the gate enforces is the graph the tree has",
            edge.0, edge.1
        ));
    }

    offenders.sort();
    offenders.dedup();
    if offenders.is_empty() {
        return Row::pass(
            ROW_DEPS,
            "every kind-to-kind dependency edge is one the measured graph already has",
            format!(
                "{} edge class(es): {} || {} transitional drain row(s) in {REGISTRY_FILE}",
                seen.len(),
                render_graph(&seen),
                reg.transitional.len()
            ),
        );
    }
    // THE MESSAGE AND THE TABLE AGREE. The failure detail used to print `seen` — the graph OBSERVED
    // in the tree — under the label "measured graph", so a finding could read `store -> contract is
    // not in the measured graph` directly above a "measured graph" listing `store->contract`. The
    // ratchet a reader has to edit is `MEASURED_EDGES`, so that is what is printed under its own
    // name; the observed set is printed beside it, labelled as what it is.
    Row::fail(
        ROW_DEPS,
        "a dependency crosses a kind boundary the measured graph does not have",
        format!(
            "{} finding(s): {} || MEASURED_EDGES ({}): {} || observed in the tree ({}): {}",
            offenders.len(),
            offenders.join(" | "),
            measured.len(),
            render_graph(&measured),
            seen.len(),
            render_graph(&seen)
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
        let banned = banned_for(kind, planes);
        if banned.is_empty() {
            continue;
        }
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
            "no plane, transport or codec source was scanned at all",
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
            format!("{scanned} plane/transport/codec source file(s) scanned, 0 findings"),
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

/// `impl <Ident> for` at the head of a production line, with literals blanked first.
///
/// THE GENERIC HEAD IS PARSED, NOT REFUSED. `strip_prefix("impl ")` could not see
/// `impl<S: CellStore> Unit for AdmissionUnit<'_, S>` — the space is a `<` — so three unit crates
/// implemented their kind's entry trait and were reported as implementing it ZERO times, forever.
/// The generic parameter list says nothing about WHICH trait is implemented, which is the only
/// thing this function is asked, so it is skipped as the balanced group it is.
fn impl_trait_on(code: &str) -> Option<String> {
    let t = code.trim_start();
    let rest = t.strip_prefix("impl")?;
    let rest = if rest.starts_with('<') {
        skip_generic_params(rest)?
    } else if rest.starts_with(' ') {
        rest
    } else {
        // `impl_of(…)`, `implement`, … — `impl` has to be the keyword, not a prefix.
        return None;
    };
    let (head, _) = rest.split_once(" for ")?;
    let head = head.trim();
    if head.is_empty() || head.contains('<') || head.contains(':') || head.contains('&') {
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
        for (_, code) in scan::production_lines(&f.text) {
            if let Some(t) = impl_trait_on(&scan::blank_literals(&code)) {
                *counts.entry(t).or_default() += 1;
            }
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
                    || c.dev_deps.iter().any(|d| d.contains(BATTERY_MARKER))
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

/// The kinds that may never name a transport crate. A transport naming a transport is that kind's
/// own layering (`ws` over `http` over `tcp`), which the measured graph already carries and the
/// instance rules already govern; the composition root names them by definition. Everything else on
/// this list is a plugin that would be choosing its own wire.
const WIRE_FORBIDDEN_KINDS: &[&str] = &["plane", "dialect", "control", "unit", "codec"];

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
    let forbidden: BTreeSet<&str> = WIRE_FORBIDDEN_KINDS.iter().copied().collect();
    let mut offenders: Vec<String> = Vec::new();

    // A PLUGIN NEVER CHOOSES ITS WIRE. The manifest edge is the same reach spelled where no source
    // scan would see it, so it is read here rather than left to the edge-class graph — which
    // ratchets on what the tree HAS and would have accepted the first such edge on the commit that
    // added its allowance.
    for c in crates {
        let Some(kind) = c.kind else { continue };
        if !forbidden.contains(kind) {
            continue;
        }
        for dep in &c.deps {
            if by_name.get(dep.as_str()).and_then(|t| t.kind) == Some("transport") {
                offenders.push(format!(
                    "wire-dependency\t{}\t{} is kind `{kind}` and depends on the wire crate {dep}. \
                     A plugin declares WHICH transport it claims, as data; it never links the crate \
                     that moves the bytes — {MAKE_A_NEW_KIND}",
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
        for w in &wires {
            let instance = w.remainder.join("-");
            let path = format!("busbar_transport_{}::", instance.replace('-', "_"));
            let sym = wire_symbol(&instance).to_lowercase();
            for (_, code) in scan::production_lines(&f.text) {
                let lower = scan::blank_literals(&code).to_lowercase();
                if lower.contains(&path) && word_ci(&lower, &sym) {
                    sites.entry(w.name.clone()).or_default().insert(rel.clone());
                    break;
                }
            }
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
}

impl KindIsolationGate {
    /// The per-push gate: the four rows the tree holds today.
    pub fn check() -> KindIsolationGate {
        KindIsolationGate { ship: false }
    }

    /// The release-time twin: the same four, plus the surface and battery criteria.
    pub fn ship() -> KindIsolationGate {
        KindIsolationGate { ship: true }
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
        let mut owed = vec![
            ROW_NAME.to_string(),
            ROW_DEPS.to_string(),
            ROW_VOCAB.to_string(),
            ROW_REGISTRY.to_string(),
            ROW_STEPS.to_string(),
            ROW_WIRES.to_string(),
            ROW_TRUTHS.to_string(),
            ROW_MATRIX.to_string(),
        ];
        if self.ship {
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

        let mut rows = vec![
            rule_name(&crates, &planes, &ports, &reg),
            rule_deps(&crates, &reg, self.ship),
            rule_vocab(cx, &crates, &planes),
            rule_registry(cx, &crates, &reg, self.ship),
            rule_steps(cx, &crates),
            rule_wires(cx, &crates),
            truths::rule_truths(cx, &kind_names(), &crates),
            matrix::rule_matrix(cx, &crates, &reg, self.ship),
        ];
        if self.ship {
            rows.push(rule_control(cx, &crates));
            match index_sources(cx) {
                Ok(idx) => {
                    rows.push(rule_shape(&crates, &idx));
                    rows.push(rule_testkit(&crates, &idx));
                }
                Err(e) => {
                    let why = format!(
                        "{e} — the source index is the ship rows' own input, and an index that did \
                         not read is not an index that found nothing wrong."
                    );
                    rows.push(Row::fail(
                        ROW_SHAPE,
                        "the source index did not run",
                        why.clone(),
                    ));
                    rows.push(Row::fail(ROW_TESTKIT, "the source index did not run", why));
                }
            }
        }
        Verdict::of(rows)
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
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
            &["busbar-unit-mcp", "mcp"],
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

        // A NEW EDGE CLASS. A plane reaching a transport is the fusion done through Cargo instead
        // of through a name.
        report.push(prove_rows_red(
            cx,
            self,
            "a plane growing a dependency on a transport is a new edge class",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-plane-mcp",
                "busbar-plane-mcp",
                &["busbar-contract", "busbar-transport-http"],
            ),
            &["new-edge-class", "plane -> transport"],
        ));

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

        // A DEAD EDGE CLASS: strip the only crate that carries `contract -> grammar` and the
        // allowance must be reported as the line it has become. (It read `caps -> contract` until
        // the contract sink stopped being a measured line — see `SPEC_SINK`; an edge the spec
        // grants can never be a dead allowance, so it can no longer prove this rule.)
        report.push(prove_rows_red(
            cx,
            self,
            "an edge class no crate has any more is reported as a dead allowance",
            &[ROW_DEPS],
            manifest_plant("crates/busbar-contract", "busbar-contract", &[]),
            &["dead-edge-class", "contract -> grammar"],
        ));

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
            report.push(prove_rows_green(
                cx,
                self,
                "a kind naming the contract is the spec's edge, not a new class",
                &[ROW_DEPS],
                manifest_plant(
                    "crates/busbar-export-planted",
                    "busbar-export-planted",
                    &["busbar-contract"],
                ),
            ));
        }

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
            "a core crate reaching a unit is a new edge class",
            &[ROW_DEPS],
            manifest_plant(
                "crates/busbar-core-config",
                "busbar-core-config",
                &["busbar-substrate", "busbar-unit-audit"],
            ),
            &["new-edge-class", "core -> unit"],
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
            // while busbar-core drains it MAY name a unit, because a row names the edge.
            report.push(prove_rows_green(
                cx,
                self,
                "a legacy crate reaching a unit through a named transitional row",
                &[ROW_DEPS],
                manifest_plant("crates/busbar-core", "busbar-core", &["busbar-unit-audit"]),
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
            &[ROW_DEPS],
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
            &[ROW_DEPS],
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
