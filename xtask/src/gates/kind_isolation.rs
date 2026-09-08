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

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_NAME: &str = "kind-isolation:name";
pub const ROW_DEPS: &str = "kind-isolation:deps";
pub const ROW_VOCAB: &str = "kind-isolation:vocab";
pub const ROW_REGISTRY: &str = "kind-isolation:registry";
/// THE SHIP-CRITERION ROWS. Owed only by the `kind-isolation-ship` registration — see the twin's
/// note in [`KindIsolationGate`].
pub const ROW_SHAPE: &str = "kind-isolation:shape";
pub const ROW_TESTKIT: &str = "kind-isolation:testkit";

/// THE OWNER'S OWN INSTRUCTION, quoted verbatim wherever a crate does not resolve to a kind.
const MAKE_A_NEW_KIND: &str = "make a new plugin kind, do not fuse two";

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
/// because a codec IS a plane's other half and is named after it by design (§3.1). `Transport`
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
        kind: "spike",
        family: Family::Neutral,
        matchers: &["=plane-abi-spike", "=plane-abi-spike-plugin"],
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
    ("transport", "transport"),
    ("hook", "hooks"),
    ("pure_auth", "auth"),
    ("egress_auth", "auth"),
    ("secret", "secret"),
    ("store", "store"),
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
];

// ------------------------------------------------------------------------------------------------
// the measured dependency graph
// ------------------------------------------------------------------------------------------------

/// THE SINK EVERY KIND MAY NAME, BY SPEC AND NOT BY MEASUREMENT (`PLUGIN-TREE.md` §4).
///
/// Every row of the §4 table gives its kind `busbar-core-contract`: the contract IS the thing a
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
/// This is deliberately a MEASUREMENT rather than the ideal graph §3.1 describes. The ideal is
/// narrower — planes reach the contract and their own codec, transports reach the transport
/// contract, units reach the contract and caps — and the tree is not all the way there. A gate that
/// asserted the ideal today would be red for reasons nobody can fix this week, and a gate that is
/// red for unfixable reasons is a gate somebody adds a `|| true` to. So the rule is the RATCHET
/// instead: THIS IS THE GRAPH, and a NEW edge class is refused. Tightening is deleting a line here
/// once the last edge in that class is gone — and the gate is red until the line goes, so the
/// tightening cannot be forgotten.
///
/// `root` is not a source: the composition root exists to depend on everything (§3.1), so an edge
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
    ("store", "api"),
    ("store", "plugin-tooling"),
    ("store", "store"),
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
/// §3 names the intersection instead, and it is small on purpose: `src/lib.rs` (the single `pub`
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
const CLAIMING_KINDS: &[&str] = &["plane", "dialect", "transport"];

/// The kinds that owe a shared conformance battery. The plugin kinds are here because a plugin is
/// exactly the thing whose contract is checked from outside; the three exemplar kinds are here
/// because the ship criterion says every kind runs its kind's battery, with no exceptions.
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

fn census(cx: &Ctx) -> Result<Vec<CrateInfo>, String> {
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
            Some("plane") | Some("dialect") => {
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

fn rule_name(crates: &[CrateInfo], planes: &BTreeSet<String>, ports: &BTreeSet<String>) -> Row {
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
    for (name, _) in ACCEPTED_NAMES {
        if !fired.contains(name) {
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

fn rule_deps(crates: &[CrateInfo]) -> Row {
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
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
    let mut offenders: Vec<String> = Vec::new();

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
            format!("{} edge class(es): {}", seen.len(), render_graph(&seen)),
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

fn rule_registry(cx: &Ctx, crates: &[CrateInfo]) -> Row {
    let mut offenders: Vec<String> = Vec::new();

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
    let live: BTreeSet<&str> = crates.iter().filter_map(|c| c.kind).collect();
    let pending: BTreeSet<&str> = PENDING_KINDS.iter().map(|(k, _)| *k).collect();
    for def in KINDS {
        if !live.contains(def.kind) && !pending.contains(def.kind) {
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
                "{} crate(s), {} kind(s): {}",
                crates.len(),
                counts.len(),
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
        ];
        if self.ship {
            owed.push(ROW_SHAPE.to_string());
            owed.push(ROW_TESTKIT.to_string());
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

        let mut rows = vec![
            rule_name(&crates, &planes, &ports),
            rule_deps(&crates),
            rule_vocab(cx, &crates, &planes),
            rule_registry(cx, &crates),
        ];
        if self.ship {
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
            report.push(prove_rows_green(
                cx,
                self,
                "the real tree keeps its plugin kinds apart (the four enforceable rows)",
                &[ROW_NAME, ROW_DEPS, ROW_VOCAB, ROW_REGISTRY],
                Overlay::new(),
            ));
        } else {
            report.push(prove_green(
                cx,
                self,
                "the real tree keeps its plugin kinds apart",
                &[ROW_NAME, ROW_DEPS, ROW_VOCAB, ROW_REGISTRY],
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
                "crates/busbar-plane-admin",
                "busbar-plane-admin",
                &["busbar-contract", "busbar-transport-http"],
            ),
            &["new-edge-class", "plane -> transport"],
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
        // and never was; §4 grants it, as it grants every kind the contract. This case plants that
        // dependency and requires the row to stay GREEN — it was RED before the sink was read off
        // the spec, which is what made `store -> contract` a "new kind-to-kind edge class" the day
        // busbar-store-memory implemented the record contract, and failed the green baseline on the
        // real tree.
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
            "comments, string literals and cfg(test) scope name nothing",
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

        if !self.ship {
            return report;
        }

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
                "§3): unit",
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
