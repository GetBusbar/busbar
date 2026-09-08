// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSSED READS — the operations of the sixty-six whose answer the composition root's LOOP
//! produces, and the seam it produces them from.
//!
//! ## Why this is a file of its own
//!
//! Not size. The admin leg's file holds the twelve steps, the ledger views and the mount, and every
//! one of those is about how an operation is WALKED. This is about who ANSWERS one — a different
//! question, with its own closed set, its own binding and its own renderers — and the migration it
//! belongs to adds a member to that set at a time. Keeping it beside the steps meant a reader
//! looking for "which operations has the loop taken over" had to find it inside a file about
//! something else, and meant every crossing edited the same file for two unrelated reasons.
//!
//! ## What is here, and the rules it keeps
//!
//! [`NodeFacts`] is the seam: what is true of the node this composition is the root of, read at
//! request time off whichever generation the handle currently holds. [`CROSSED_VERBS`] is the closed
//! set. [`render_crossed_view`] is the one match over it, and the renderers under it write the
//! retired handlers' bytes by hand — field for field, in their order — because this crate carries no
//! serializer on the request path.
//!
//! Everything crossing the seam is NEUTRAL: names, counts, words, flags and numbers. No core view
//! struct and no config type reaches this crate, which is what lets an operation cross without its
//! shape crossing with it.

use std::sync::Arc;

use busbar_unit_verbs::KernelVerb;

use super::{json_string, AdminAnswer};

// ── the node's own facts, read at request time ──────────────────────────────────────────────────

/// The facts about THIS NODE that a crossed administrative read answers from.
///
/// The second kind of seam this file holds, and it is a different kind from the ledger's on purpose.
/// The ledger views read figures the previous release never kept, so they had nowhere else to reach.
/// A crossed read is the opposite: the answer has always existed, it was produced by a handler on
/// the surface underneath, and what CROSSES is which side produces it — the loop reads the fact
/// itself and renders, and the route the handler was mounted on is deleted in the same commit.
///
/// **Facts, not topology.** It began as the two routing-table reads and it is named for what it
/// actually carries, because the reads that cross after them are not all about the tables: the
/// node's door, its admin-plane guard and its own boot epoch are facts about the same node, asked at
/// the same moment, through the same binding. One seam for "what is true of the node this
/// composition is the root of" is one place to bind and one place to fake; a second seam per kind of
/// fact would be four bindings that can each be forgotten separately.
///
/// **Read at request time, never captured.** A node's tables and its config are replaced wholesale
/// by a config apply: the handle swaps in a new generation and the old one retires. A seam that had
/// taken an `Arc<App>` at boot would go on answering off the retired generation for the life of the
/// process — an operator would apply a pool and read back a topology that did not have it, which is
/// the same class of fault as a stale cache and reads exactly like the apply having failed. So the
/// binding holds the HANDLE and asks it per call.
///
/// **Neutral in, JSON out.** Everything that crosses this seam is a neutral projection — names,
/// counts, flags and numbers — and never a core view struct or a config type. The rendering is this
/// file's, beside the ledger views' rendering, for the same reason: the composition root is the one
/// place entitled to write the bytes an operation answers with.
pub trait NodeFacts: Send + Sync {
    /// Every upstream provider this node has a lane for, with how many lanes route through it,
    /// ordered by provider name.
    ///
    /// The order is part of the answer rather than a detail: the operation it renders has always
    /// answered sorted, and a client diffing two reads of a stable node must see no change.
    fn providers(&self) -> Vec<(String, usize)>;

    /// Every model lane this node routes over, as `(model, provider)`, ordered by model name.
    ///
    /// One entry per LANE and not per model: two lanes may configure the same model name against
    /// different providers, and the operation this renders has always answered both.
    fn models(&self) -> Vec<(String, String)>;

    /// The ADMIN-plane guard chain this node runs, in order, AND the config generation it was read
    /// off.
    ///
    /// ONE METHOD FOR ONE READ, which is the rule every fact on this trait follows and the reason
    /// the version rides with the chain instead of being a method of its own. The answer this
    /// renders carries an `ETag` naming that generation, and a mutating caller chains `If-Match` off
    /// it; two calls would read two generations, and an `ETag` naming a generation the body beside
    /// it did not come from lets a caller chain a change onto a state that never existed.
    ///
    /// The empty chain is a real answer and not a missing one — it is the open dev posture — so the
    /// `configured` flag the read renders is derived from emptiness here rather than carried as a
    /// second fact that could disagree with the list beside it.
    fn admin_guard(&self) -> (Vec<String>, u64);

    /// This node's INGRESS front door: the auth-chain module names in order, the upstream-credential
    /// mode as the word it is reported by, and whether the door is open.
    ///
    /// The mode arrives as its WORD rather than as a value to translate here, because the surface
    /// underneath renders the same three facts into the effective-config read and a mapping written
    /// twice is a mapping that can be written differently twice.
    fn ingress_door(&self) -> (Vec<String>, String, bool);

    /// Everything the node says about ITSELF: its release, the proof of what was compiled into it,
    /// its boot epoch, the size of its tables, and the config generation it is running.
    ///
    /// One method for one read, off ONE generation, which matters more here than anywhere else on
    /// this trait: this answer names the config version AND the counts that version produced, and a
    /// reader that sampled them separately could publish a version that never had those tables.
    fn node_info(&self) -> NodeInfo;
}

/// What a node reports about itself, as the crossed `GET /info` renders it.
///
/// A struct rather than a tuple, and root-owned rather than substrate-owned. Ten facts positionally
/// is a shape nobody can read a call site of, and the alternative — a type in the substrate — would
/// put an ADMIN-shaped view in a crate whose whole job is to name no surface. So the carrier lives
/// here, beside the renderer that is the only thing entitled to write these bytes, and every FIELD
/// of it is a neutral scalar or list the node already answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// The release this node is running, as the crate that owns the surface reports it.
    pub version: String,
    /// The auth modules compiled into this binary, in the order the proof lists them.
    pub auth_modules: Vec<String>,
    /// The removable hook plugins compiled into this binary.
    pub hook_plugins: Vec<String>,
    /// The always-present weighted SWRR floor. Carried rather than written by the renderer because
    /// it is a claim about the BUILD, and a literal at a renderer is a literal a second renderer
    /// writes for itself.
    pub weighted_floor: bool,
    /// Seconds since this process started, or `None` when the start was never stamped.
    pub uptime_seconds: Option<u64>,
    /// The unix second this process started at — the BOOT EPOCH a consumer reads a counter reset
    /// against, so a reset is "new epoch" and never "reverted".
    pub started_at: Option<u64>,
    /// How many pools this node routes over.
    pub pools: usize,
    /// How many directly-addressable models this node routes over.
    pub models: usize,
    /// How many DISTINCT upstream providers those lanes reach.
    pub providers: usize,
    /// Whether an API-applied config change is durable across a restart.
    pub config_persistence: bool,
    /// The config generation this node is running.
    pub config_version: u64,
}

/// The facts of a node this composition never handed its handle to.
///
/// Not "no providers this node happens to have" — the honest answer for a binding with nothing
/// behind it, which is the same decision [`UnopenedLedger`] makes for the figures. An admin-only
/// composition really does route nothing, and the empty list is what it should say.
#[derive(Debug, Default)]
pub struct UnboundFacts;

impl NodeFacts for UnboundFacts {
    fn providers(&self) -> Vec<(String, usize)> {
        Vec::new()
    }

    fn models(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn admin_guard(&self) -> (Vec<String>, u64) {
        // The OPEN posture at the boot generation: nothing guards a surface that is not there, and a
        // binding with no node behind it has applied no config. The same honesty the two lists above
        // answer with.
        (Vec::new(), 0)
    }

    fn ingress_door(&self) -> (Vec<String>, String, bool) {
        // An OPEN door signing with its own credentials, which is what a node with no ingress really
        // is: no chain to run, and nothing to forward a caller's credential to.
        (Vec::new(), "own".to_string(), true)
    }

    fn node_info(&self) -> NodeInfo {
        // A node this composition never handed its handle to, described honestly: no release it can
        // name, nothing it can prove was compiled in, no boot it observed, and empty tables. Every
        // field is the same "nothing behind this binding" the lists above answer with, and none of
        // them is a plausible-looking figure invented to fill a shape.
        NodeInfo {
            version: String::new(),
            auth_modules: Vec::new(),
            hook_plugins: Vec::new(),
            weighted_floor: false,
            uptime_seconds: None,
            started_at: None,
            pools: 0,
            models: 0,
            providers: 0,
            config_persistence: false,
            config_version: 0,
        }
    }
}

/// The facts of a running node, read off whichever generation is current.
///
/// Holds the HANDLE and not a generation, which is the whole content of the type — see the seam's
/// own note above for what a captured generation would cost.
pub struct HandleFacts {
    handle: Arc<busbar_core::state::AppHandle>,
}

impl std::fmt::Debug for HandleFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleFacts").finish_non_exhaustive()
    }
}

impl HandleFacts {
    /// Bind the crossed reads to a node's live handle.
    #[must_use]
    pub fn new(handle: Arc<busbar_core::state::AppHandle>) -> Self {
        HandleFacts { handle }
    }
}

impl NodeFacts for HandleFacts {
    fn providers(&self) -> Vec<(String, usize)> {
        // ONE load, held for the length of the walk over the tables. Loading per lane would let a
        // config apply land between two indices and produce a count over two different topologies.
        let generation = self.handle.load();
        // THE PROJECTION IS THE SUBSTRATE'S, so this reading and the effective-config read's are the
        // same fact rather than two loops that agree today. See its own note for why.
        generation.engine_tables_view().providers_by_lane_count()
    }

    fn models(&self) -> Vec<(String, String)> {
        let generation = self.handle.load();
        generation.engine_tables_view().models_by_lane()
    }

    fn admin_guard(&self) -> (Vec<String>, u64) {
        // WHICHEVER GENERATION IS CURRENT, which is the whole of what makes the read coherent with
        // the `PUT` that still lives on the surface underneath: that write builds the next
        // generation and swaps it onto this handle, so the very next read through here sees it.
        // ONE load for both, so the chain and the version this answer's `ETag` names are the same
        // generation's.
        let generation = self.handle.load();
        (
            generation.admin_guard_chain().to_vec(),
            generation.config_version,
        )
    }

    fn ingress_door(&self) -> (Vec<String>, String, bool) {
        // THE FOLD IS THE NODE'S, so this reading and the effective-config read's are the same three
        // facts rather than two readings that agree today. See its own note for why.
        let (chain, upstream_credentials, open) = self.handle.load().ingress_door_facts();
        (
            chain.into_iter().map(ToString::to_string).collect(),
            upstream_credentials.to_string(),
            open,
        )
    }

    fn node_info(&self) -> NodeInfo {
        // ONE load for the whole answer. The counts below and the config version beside them are
        // facts of the SAME generation, and reading them off two loads could publish a version that
        // never had those tables — the same class of fault the seam's own note describes, one step
        // finer.
        let generation = self.handle.load();
        let tables = generation.engine_tables_view();
        let (auth_modules, hook_plugins, weighted_floor) = generation.compiled_in_proof();
        let (uptime_seconds, started_at) = generation.process_epoch();
        NodeInfo {
            version: generation.release_version().to_string(),
            auth_modules: auth_modules.into_iter().map(ToString::to_string).collect(),
            hook_plugins: hook_plugins.into_iter().map(ToString::to_string).collect(),
            weighted_floor,
            uptime_seconds,
            started_at,
            pools: tables.pools().len(),
            models: tables.model_indices().len(),
            // THE SAME PROJECTION `GET /providers` COUNTS, so the number this read publishes and the
            // list that read serves can never describe different nodes.
            providers: tables.providers_by_lane_count().len(),
            config_persistence: generation.config_persistence(),
            config_version: generation.config_version,
        }
    }
}

/// The operations of the sixty-six whose answer the LOOP now produces, from the node's own facts.
///
/// A closed set, and it is written as a set rather than as a condition inside the match below for
/// the reason every closed set in this file is: `answered_by` and the renderer have to agree about
/// which verbs have crossed, and two matches that each decide it separately are two answers to one
/// question. The ownership pin measures the consequence — a crossed verb must have no route on the
/// surface underneath, and an uncrossed one must have one.
pub(crate) const CROSSED_VERBS: &[KernelVerb] = &[
    KernelVerb::GetAdminAuth,
    KernelVerb::GetAuth,
    KernelVerb::GetInfo,
    KernelVerb::GetModels,
    KernelVerb::GetProviders,
];

/// The answer a crossed read produces: a 200 carrying JSON, and no other header.
///
/// The same two facts the surface underneath answered with, because they ARE the answer a client
/// pinned: `ok_json` sets one header, `content-type: application/json`, and the transport adds the
/// framing. A header this file added would be a byte the operation did not used to carry.
fn crossed_answer(body: Vec<u8>) -> AdminAnswer {
    AdminAnswer {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
}

/// Stamp the config-plane `ETag` a config-plane READ carries, in the shape an `If-Match` writer
/// sends back: the generation counter, quoted, as a strong validator.
///
/// It goes AFTER the content type because that is the order the retired handler emitted the two in —
/// its `respond` set the type and its wrapper inserted the tag — and this crate hands the transport
/// an ordered list rather than a map.
fn with_config_etag(mut answer: AdminAnswer, version: u64) -> AdminAnswer {
    answer
        .headers
        .push(("etag".to_string(), format!("\"{version}\"")));
    answer
}

/// The whole answer one crossed read produces, or `None` for a verb that has not crossed.
///
/// `None` is the uncrossed answer and it is load-bearing: it is what sends every other one of the
/// sixty-six on to the dispatch, so a verb is answered here only by being named above.
///
/// The ANSWER and not just its body, because a crossed read's headers are as pinned as its bytes:
/// `GET /admin-auth` has always carried the config-plane `ETag` its `PUT` chains `If-Match` off, and
/// a renderer that returned only bytes would leave that fact to be re-decided somewhere else.
pub(crate) fn render_crossed_view(verb: KernelVerb, facts: &dyn NodeFacts) -> Option<AdminAnswer> {
    if !CROSSED_VERBS.contains(&verb) {
        return None;
    }
    Some(match verb {
        KernelVerb::GetModels => crossed_answer(render_models(&facts.models()).into_bytes()),
        KernelVerb::GetProviders => {
            crossed_answer(render_providers(&facts.providers()).into_bytes())
        }
        KernelVerb::GetAdminAuth => {
            let (modules, version) = facts.admin_guard();
            with_config_etag(
                crossed_answer(render_admin_auth(&modules).into_bytes()),
                version,
            )
        }
        KernelVerb::GetAuth => {
            let (chain, upstream_credentials, open) = facts.ingress_door();
            crossed_answer(render_auth(&chain, &upstream_credentials, open).into_bytes())
        }
        KernelVerb::GetInfo => crossed_answer(render_info(&facts.node_info()).into_bytes()),
        // Unreachable while the set above and this match name the same verbs, which is the
        // invariant the set exists to make checkable rather than a case to invent a body for.
        _ => return None,
    })
}

/// `GET /api/v1/admin/admin-auth` — the guard chain the ADMINISTRATIVE plane itself runs behind.
///
/// The retired handler's shape, field for field and in its order. `configured` is DERIVED from the
/// chain rather than carried beside it: an empty chain is the open dev posture, and a node whose
/// guard is open while a flag beside it said "configured" would be the one disagreement this read
/// exists to make impossible. See [`render_providers`] for why it is written by hand.
fn render_admin_auth(modules: &[String]) -> String {
    let mut out = String::from("{\"configured\":");
    out.push_str(json_bool(!modules.is_empty()));
    out.push_str(",\"modules\":[");
    for (i, module) in modules.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(module, &mut out);
    }
    out.push_str("]}");
    out
}

/// `GET /api/v1/admin/auth` — the node's INGRESS front door: its auth chain, its upstream-credential
/// mode, and whether the door is open.
///
/// The retired handler's shape, field for field and in its order. Never a secret — module names, one
/// word and one flag, which is the whole of what this read has ever carried. See [`render_providers`]
/// for why it is written by hand.
fn render_auth(chain: &[String], upstream_credentials: &str, open: bool) -> String {
    let mut out = String::from("{\"chain\":[");
    for (i, module) in chain.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(module, &mut out);
    }
    out.push_str("],\"upstream_credentials\":");
    json_string(upstream_credentials, &mut out);
    out.push_str(",\"open\":");
    out.push_str(json_bool(open));
    out.push('}');
    out
}

/// `GET /api/v1/admin/info` — what the node says about itself.
///
/// The retired handler's shape, field for field and in its order, nested objects included: `build`
/// carries the compiled-in proof and `topology` the three counts, exactly where a client that
/// upgraded into this release expects to find them. See [`render_providers`] for why it is written
/// by hand.
///
/// The two `Option<u64>` fields render as `null` when absent, which is what the retired handler's
/// serializer did with them and is a different statement from `0`: a process whose start was never
/// stamped has no uptime, and reporting zero would claim it had just booted.
fn render_info(info: &NodeInfo) -> String {
    let mut out = String::from("{\"version\":");
    json_string(&info.version, &mut out);
    out.push_str(",\"build\":{\"auth_modules\":");
    json_string_array(&info.auth_modules, &mut out);
    out.push_str(",\"hook_plugins\":");
    json_string_array(&info.hook_plugins, &mut out);
    out.push_str(",\"weighted_floor\":");
    out.push_str(json_bool(info.weighted_floor));
    out.push_str("},\"uptime_seconds\":");
    json_optional_number(info.uptime_seconds, &mut out);
    out.push_str(",\"started_at\":");
    json_optional_number(info.started_at, &mut out);
    out.push_str(",\"topology\":{\"pools\":");
    out.push_str(&info.pools.to_string());
    out.push_str(",\"models\":");
    out.push_str(&info.models.to_string());
    out.push_str(",\"providers\":");
    out.push_str(&info.providers.to_string());
    out.push_str("},\"config_persistence\":");
    out.push_str(json_bool(info.config_persistence));
    out.push_str(",\"config_version\":");
    out.push_str(&info.config_version.to_string());
    out.push('}');
    out
}

/// One JSON array of strings, quoted and escaped.
fn json_string_array(values: &[String], out: &mut String) {
    out.push('[');
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(value, out);
    }
    out.push(']');
}

/// One JSON boolean.
///
/// Named rather than spelled inline at each of the four sites that need it, because `if b {"true"}
/// else {"false"}` written four times is four chances to write it once the other way round.
fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// One JSON number, or `null` for a reading that was never taken.
///
/// `null` and not `0`, and the distinction is the whole reason this is a function: a process whose
/// start instant was never stamped has NO uptime, and a zero would claim it had just booted.
fn json_optional_number(value: Option<u64>, out: &mut String) {
    match value {
        Some(number) => out.push_str(&number.to_string()),
        None => out.push_str("null"),
    }
}

/// `GET /api/v1/admin/providers` — the distinct upstream providers and how many lanes reach each.
///
/// The shape is the retiring handler's, field for field and in its order: a page envelope whose
/// `items` are `{provider, model_count}` and whose `next_cursor` is null, because the list reads
/// have always been one page. It is rendered by hand for the same reason the ledger views are — this
/// crate carries no serializer on the request path — and the pin beside it compares these bytes
/// against the ones the surface underneath used to produce.
fn render_providers(providers: &[(String, usize)]) -> String {
    let mut out = String::from("{\"items\":[");
    for (i, (provider, lanes)) in providers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"provider\":");
        json_string(provider, &mut out);
        out.push_str(",\"model_count\":");
        out.push_str(&lanes.to_string());
        out.push('}');
    }
    out.push_str("],\"next_cursor\":null}");
    out
}

/// `GET /api/v1/admin/models` — every configured model lane and the provider it reaches.
///
/// The retiring handler's shape, field for field and in its order, inside the same page envelope
/// every list read answers in. See [`render_providers`] for why it is written by hand.
fn render_models(models: &[(String, String)]) -> String {
    let mut out = String::from("{\"items\":[");
    for (i, (model, provider)) in models.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"model\":");
        json_string(model, &mut out);
        out.push_str(",\"provider\":");
        json_string(provider, &mut out);
        out.push('}');
    }
    out.push_str("],\"next_cursor\":null}");
    out
}
