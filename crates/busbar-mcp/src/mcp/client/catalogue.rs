// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOOL-LIST CACHE: a versioned snapshot with atomic swap, per-tool schema/description
//! hash-pinning, and the drift detection that is the RUG-PULL defence.
//!
//! ## What a rug-pull is, and what actually stops it
//!
//! An operator inspects an upstream's `read_file` tool, sees a schema taking one path, and approves
//! it. A week later the upstream re-serves `read_file` under the same name with a schema that also
//! takes a `webhook_url`, or a description that instructs the model to exfiltrate. Nothing about the
//! NAME changed, so a cache keyed on names re-adopts the poisoned definition silently. That is
//! CVE-2025-54136's shape.
//!
//! The defence is a per-tool DIGEST over exactly the parts an upstream controls — name, description
//! and input schema — approved once by the operator and re-compared on every refresh. A digest that
//! moved is DRIFT, drift DEMOTES the server, and a demoted server serves nothing until an operator
//! works the change. Crucially the demotion is not a flag anybody has to remember to set: it is
//! `busbar_core::trust::Approval::state` disagreeing with the last observation, which is the shared trust
//! lifecycle this module reuses rather than reimplements.
//!
//! ## Why the digest is over a CANONICAL rendering
//!
//! `serde_json` may or may not preserve object key order depending on features, and an upstream can
//! reorder its schema's keys freely without changing its meaning. A digest over the received bytes
//! would therefore raise drift on a no-op and — far worse — teach an operator that drift alerts are
//! noise to click through. So [`tool_digest`] renders the value with object keys sorted recursively
//! and hashes that. Reordering is not drift; changing one character of a description is.
//!
//! ## The refresh trigger is OURS, never the upstream's
//!
//! A refresh MUST NOT be driven solely by the server's own `notifications/tools/list_changed`,
//! because that is an attacker-controlled trigger: an upstream that wants its poisoned list adopted
//! can simply ask, repeatedly. [`RefreshGate`] rate-limits the notification to a floor interval and
//! the notification's CONTENTS are never read — it can only bring forward a re-pull of the
//! authoritative `tools/list`, which is then re-hashed exactly as a scheduled refresh would be.
//!
//! ## The pin GENERATION, and why dispatch re-reads it
//!
//! Revision `2026-07-28` has no sessions, so the designed session-tombstoning collapses into one
//! per-request check: selection resolves a candidate under generation *N*, and dispatch re-reads
//! the LIVE generation and refuses if it moved. That is what stops an in-flight call outliving the
//! quarantine that was meant to stop it. The generation is monotonic across the whole cache rather
//! than per server, deliberately: a coarser generation can only cause a spurious refusal and a retry,
//! where a per-server one gives every future caller a chance to pick the wrong counter.

// ── THIS MODULE IS NOW ON THE DISPATCH PATH ─────────────────────────────────────────────────────
//
// `crate::mcp::connect` fetches a live `tools/list`, re-hashes it here through
// [`ServerCatalogue::observe`], and publishes it into the [`CatalogueCache`] that rides the `App`.
// `crate::mcp::catalogue::Catalogue::resolve` then asks [`LiveSightings::digest_for`] for the digest
// the upstream is CURRENTLY serving and hands THAT to the trust lifecycle's own comparison — so a
// schema an upstream changed under a live cache is refused rather than dispatched. Previously the
// gate compared the approved digest against the schema hash the operator wrote in config, which
// proved the served tool matched what was approved and could not by construction notice the
// upstream moving underneath it.
//
// A small number of items here are still uncalled and they are named individually rather than
// blanket-allowed, so anything else losing its caller still breaks the build.

use super::identity::{BoundIdentity, ServerId, ToolKey};
use busbar_core::trust::{Approval, Observation, PinnedArtifact, Sighting, TrustState};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// One tool exactly as an upstream described it. Every field here is UPSTREAM-CONTROLLED, which is
/// why the type carries no routing method: the only thing the engine derives from it is a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolDef {
    /// The upstream's own (un-namespaced) tool name.
    pub(crate) name: String,
    /// Free text. Shown to an operator at approval time and fed to a model as context after
    /// markup-normalisation. NEVER an input to a routing decision, which reads the bound identity
    /// and nothing else — see `super::dispatch`, whose refusal to read this field is
    /// machine-checked.
    pub(crate) description: String,
    /// The JSON Schema for the tool's arguments.
    pub(crate) input_schema: serde_json::Value,
}

/// The per-tool schema/description hash the rug-pull defence pins on, as `sha256:<hex>`.
///
/// Covers name, description AND schema together, in one digest rather than three. Three digests
/// would let a caller approve a name change without a schema change or vice versa, and there is no
/// operator question those separate answers serve — the operator's question is "is this the same
/// tool I approved", which is one question.
pub(crate) fn tool_digest(def: &ToolDef) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    // Length-prefixed, so a description ending in what the next field starts with cannot forge the
    // same byte stream as a different split. Concatenating three attacker-influenced strings with a
    // separator the attacker may also type is the classic digest-collision-by-framing bug.
    for part in [
        def.name.as_str(),
        def.description.as_str(),
        &canonical_json(&def.input_schema),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Render `value` with every object's keys sorted, recursively. See the module header: this is what
/// makes key ORDER not-drift while any change of key, value or shape IS drift.
fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // The key goes through serde's own string encoder so an embedded quote or brace
                // cannot terminate the framing early.
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        // Scalars: serde's rendering is already canonical for our purpose (it is what an equality
        // comparison on the parsed value would agree with).
        other => out.push_str(&other.to_string()),
    }
}

/// The MCP plane's pinned artifact: one opaque transport-layer value. That arity is the reason the
/// shared lifecycle takes the artifact as a type parameter — a signed A2A card pins two halves, an
/// issuer key AND a card fingerprint, and a single string would have made MCP's arity universal.
///
/// The `mechanism` is carried rather than hard-coded so `cert_spki`, `mtls` and a future
/// `pinned_pubkey` are the same type with different operator-facing labels; the machine never reads
/// it (`busbar_core::trust` explicitly does not interpret `mechanism()`), so a per-mechanism special case
/// cannot be acquired by accident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportPin {
    mechanism: &'static str,
    value: String,
}

impl TransportPin {
    /// A pin on the endpoint's TLS certificate SPKI — where the operator-pinned trust root degrades
    /// to when an upstream offers no signature of its own, which for MCP is the common case: there
    /// is no MCP-native manifest signature to verify. Still a real network-layer authenticity root,
    /// and still not trust-on-first-use, because the operator supplies the value out of band.
    // STILL UNWIRED, and narrowly so: the shared HTTP client does not surface the peer's
    // certificate to this layer, so no code path observes an SPKI to construct one from. See
    // `crate::mcp::connect`'s stated gap. `declared` — the operator's out-of-band value — IS wired
    // and is what the registration builds.
    #[allow(dead_code)]
    pub(crate) fn cert_spki(value: &str) -> Self {
        Self {
            mechanism: "cert_spki",
            value: value.to_string(),
        }
    }

    /// A pin on a client-certificate-authenticated (mTLS) binding.
    // Unwired for the same reason as `cert_spki`: nothing observes a peer identity yet.
    #[allow(dead_code)]
    pub(crate) fn mtls(value: &str) -> Self {
        Self {
            mechanism: "mtls",
            value: value.to_string(),
        }
    }

    /// The pin an operator DECLARED in a registration, under the mechanism they named there.
    ///
    /// It is the same type as the observed pin above, deliberately: the SERVER direction's
    /// registration and the CLIENT direction's transport observation are two sources of one plane's
    /// authenticity root, and giving them two types is how the plane would end up with two
    /// lifecycles. The mechanism is carried as the operator's word for it and, as everywhere else,
    /// is never interpreted by the machine.
    pub(crate) fn declared(mechanism: &'static str, value: &str) -> Self {
        Self {
            mechanism,
            value: value.to_string(),
        }
    }
}

impl PinnedArtifact for TransportPin {
    fn mechanism(&self) -> &'static str {
        self.mechanism
    }

    fn digest(&self) -> String {
        self.value.clone()
    }
}

/// READING AN OPERATOR'S `tools.<server>.pin:` INTO THIS PLANE'S ARTIFACT — the whole of what MCP
/// writes for it. The sequence, and the refusal of a present-but-blank key, are
/// [`busbar_core::trust::declared`]'s.
///
/// Construction, not authorization. It answers only "is there a root to lock", and the answer feeds
/// the lifecycle rather than a dispatch decision: with no artifact there is nothing to hand
/// [`Approval::declared`], so the registration can only be [`Approval::registered`] — pending, and
/// serving nothing. That is a fact about what is CONSTRUCTIBLE, which is why `unpinned` cannot be
/// talked into serving by a later edit here.
impl busbar_core::trust::declared::Declares for TransportPin {
    type Mechanism = crate::mcp::config::McpPinMechanism;

    fn is_a_root(mechanism: Self::Mechanism) -> bool {
        mechanism.is_a_root()
    }

    fn artifact(
        reading: busbar_core::trust::declared::Reading<'_, Self::Mechanism>,
    ) -> Option<Self> {
        use busbar_core::trust::declared::Reading;
        match reading {
            // NO ARTIFACT AT ALL for an unrooted registration, which is this plane's ruling and not
            // core's: `Approval::declared` takes the pin BY VALUE, so "unpinned can never be
            // approved" stays a fact about what is constructible here rather than a runtime check
            // somebody could later relax.
            Reading::NoRoot { .. } => None,
            // The FINGERPRINT is ignored, and deliberately: an MCP server offers one opaque
            // transport-layer value and there is no MCP-native manifest fingerprint for an operator
            // to have approved out of band. The plane passes `None` for it and never reads it back.
            Reading::Rooted { mechanism, key, .. } => {
                Some(TransportPin::declared(mechanism.token(), key))
            }
        }
    }
}

/// One registered upstream's catalogue entry inside a snapshot: the operator's standing approval,
/// the last observation, and the tools derived from the two.
#[derive(Clone, Debug)]
pub(crate) struct ServerCatalogue {
    pub(crate) id: ServerId,
    /// Operator INTENT: the locked pin and the approved per-tool digests. Config-overlay state in a
    /// wired deployment.
    pub(crate) approval: Approval<TransportPin>,
    /// What the upstream was last observed to offer. Store state in a wired deployment.
    pub(crate) sighting: Sighting<TransportPin>,
    /// The observed tool definitions, by un-namespaced name. Kept beside the sighting because the
    /// sighting carries only digests: an operator approval screen needs the definition, and the
    /// markup-normalisation needs the description text.
    pub(crate) observed: BTreeMap<String, ToolDef>,
    /// THE REFRESH LEDGER: when this server was last contacted, when drift was last seen, and how
    /// often. Store state in a wired deployment, exactly as the sighting is, and it lives here for
    /// the same reason — this cache is what survives a config apply
    /// (`main.rs` carries `mcp_sightings` across), so a reload cannot reset a server's freshness
    /// clock and buy an upstream a fresh window.
    ///
    /// Read by verify-on-call ([`crate::mcp::connect::ledger_of`]) as this plane's `fetched_at`
    /// source, and stamped by [`crate::mcp::connect::stamp`] when it looks.
    pub(crate) ledger: busbar_core::trust::reverify::Ledger,
}

impl ServerCatalogue {
    /// A freshly registered server: nothing pinned, nothing approved, nothing observed, serves
    /// nothing. The fail-closed floor.
    pub(crate) fn registered(id: ServerId) -> Self {
        Self {
            id,
            approval: Approval::registered(),
            sighting: Sighting::Never,
            observed: BTreeMap::new(),
            ledger: busbar_core::trust::reverify::Ledger::default(),
        }
    }

    /// A cache entry seeded with the operator's STANDING approval, so the operator-facing views
    /// computed off this entry (its derived state, its changes queue) are computed against the same
    /// intent the dispatch gate is.
    ///
    /// It is a CONTAINER constructor and not a transition: the approval is handed in already built
    /// by whoever owns the intent, and nothing here approves, rejects or pins anything. The dispatch
    /// gate deliberately does NOT read this copy — it reads the LIVE config approval beside the
    /// sighting, so an approval edited after the last refresh bites without a re-fetch.
    pub(crate) fn seeded(id: ServerId, approval: Approval<TransportPin>) -> Self {
        Self {
            id,
            approval,
            sighting: Sighting::Never,
            observed: BTreeMap::new(),
            ledger: busbar_core::trust::reverify::Ledger::default(),
        }
    }

    /// Record a `tools/list` result: the presented identity and the tools it offered, hashed.
    ///
    /// This is the ONLY way an observation enters the cache, and it always re-hashes from the
    /// definitions rather than adopting a digest an upstream supplied. An upstream-supplied digest
    /// would be the rug-pull with an extra step.
    pub(crate) fn observe(&mut self, pin: Option<TransportPin>, tools: Vec<ToolDef>) {
        let mut capabilities = BTreeMap::new();
        let mut observed = BTreeMap::new();
        for def in tools {
            capabilities.insert(def.name.clone(), tool_digest(&def));
            observed.insert(def.name.clone(), def);
        }
        self.observed = observed;
        self.sighting = Sighting::Seen(Observation { pin, capabilities });
    }

    /// Record a failed contact. `Error` outranks `Approved` in the derived state, so a server we
    /// could not reach never presents as trusted.
    pub(crate) fn observe_failure(&mut self, reason: &str) {
        self.sighting = Sighting::Failed(reason.to_string());
    }

    /// The DERIVED trust state: a pure function of the approval and the sighting. Never stored, so
    /// a drift cannot leave a stale `Approved` behind — there is no stored `Approved` to leave.
    pub(crate) fn state(&self) -> TrustState {
        self.approval.state(&self.sighting)
    }

    /// The changes queue for the last observation: what an operator has to work before this server
    /// serves again.
    // The operator-facing changes queue is derived from the LIVE config approval beside this
    // entry's sighting (see `crate::mcp::connect::changes`), not from the cached copy of the intent
    // — so this convenience reader has no production caller and deliberately keeps none.
    #[allow(dead_code)]
    pub(crate) fn drift(&self) -> busbar_core::trust::Drift {
        self.approval.drift(&self.sighting)
    }

    /// The bound identity for one tool, or `None` when the tool is not currently observed.
    ///
    /// Returns the OBSERVED digest, not the approved one, deliberately: the dispatch gate's job is
    /// to compare them, and handing it the approved digest on both sides is how a gate is written
    /// that can never fail.
    pub(crate) fn bound_identity(&self, tool: &str) -> Option<BoundIdentity> {
        let def = self.observed.get(tool)?;
        Some(BoundIdentity {
            key: ToolKey::new(self.id.clone(), tool).ok()?,
            digest: tool_digest(def),
        })
    }

    /// Every tool this server currently SERVES: observed, and approved at the digest it is observed
    /// at. A quarantined server serves none, because `Approval::serves` refuses on drift.
    pub(crate) fn served_tools(&self) -> Vec<BoundIdentity> {
        if self.state() != TrustState::Approved {
            return Vec::new();
        }
        self.observed
            .keys()
            .filter_map(|name| self.bound_identity(name))
            .filter(|bi| self.approval.serves(bi.key.tool(), &bi.digest))
            .collect()
    }
}

/// AN IMMUTABLE CATALOGUE SNAPSHOT, stamped with the generation it was published under.
///
/// Readers hold an `Arc` of one of these for as long as they need it and never observe a torn
/// state; a writer builds an entirely new one and swaps it in. That is the same hot-swap discipline
/// `AppHandle` already uses for config.
#[derive(Clone, Debug)]
pub(crate) struct CatalogueSnapshot {
    generation: u64,
    servers: BTreeMap<String, ServerCatalogue>,
}

impl CatalogueSnapshot {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn server(&self, id: &ServerId) -> Option<&ServerCatalogue> {
        self.servers.get(id.as_str())
    }

    // No caller: every production read is keyed by server id, because the surfaces that show more
    // than one server iterate the REGISTRY (operator intent) and join, rather than iterating the
    // sightings (accumulated evidence) and hoping every registration has one.
    #[allow(dead_code)]
    pub(crate) fn servers(&self) -> impl Iterator<Item = &ServerCatalogue> {
        self.servers.values()
    }

    /// Every tool served across every approved server, namespaced. THE catalogue a caller sees,
    /// before its own grant narrows it further.
    pub(crate) fn served_tools(&self) -> Vec<BoundIdentity> {
        self.servers
            .values()
            .flat_map(|s| s.served_tools())
            .collect()
    }
}

/// THE CACHE: one live snapshot behind an atomic swap, plus the monotonic pin generation.
///
/// The generation is an `AtomicU64` OUTSIDE the lock and is bumped BEFORE the swap. Ordering
/// matters and it is deliberate: a dispatch that reads a generation newer than the snapshot it
/// selected under refuses and retries, which is a spurious refusal; the reverse order would let a
/// dispatch read a stale generation alongside a fresh snapshot and conclude nothing had changed,
/// which is the failure this check exists to prevent.
#[derive(Debug)]
pub(crate) struct CatalogueCache {
    live: RwLock<Arc<CatalogueSnapshot>>,
    generation: AtomicU64,
}

impl Default for CatalogueCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogueCache {
    pub(crate) fn new() -> Self {
        Self {
            live: RwLock::new(Arc::new(CatalogueSnapshot {
                generation: 0,
                servers: BTreeMap::new(),
            })),
            generation: AtomicU64::new(0),
        }
    }

    /// The live snapshot. Cheap: one lock acquisition and an `Arc` clone, no catalogue copy.
    pub(crate) fn load(&self) -> Arc<CatalogueSnapshot> {
        // A poisoned lock means a writer panicked mid-swap. The snapshot is immutable and was
        // published whole, so the value is still coherent; refusing to read it would take the whole
        // MCP plane down for a panic that cannot have corrupted it.
        match self.live.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// THE LIVE GENERATION, read without touching the snapshot. This is what dispatch re-reads on
    /// every request, so a call selected under an older generation cannot go out against a snapshot
    /// the operator has already revoked.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Apply `edit` to a COPY of the live catalogue and publish the result as a new generation.
    ///
    /// Read-copy-update rather than mutate-in-place: an in-flight reader keeps the snapshot it
    /// already has, and the new one becomes visible in one step. The generation bump happens for
    /// every apply, including one that changes nothing — a no-op refresh costing a spurious
    /// dispatch retry is strictly better than a real revocation that forgot to bump.
    pub(crate) fn apply(&self, edit: impl FnOnce(&mut BTreeMap<String, ServerCatalogue>)) {
        // THE WRITE LOCK IS HELD ACROSS THE WHOLE READ-COPY-UPDATE, not just the final swap. Two
        // applies targeting DIFFERENT server keys — a verify-on-call fetch settling one server while
        // another settles a second — each clone the pre-edit map, edit their own key, and publish.
        // If the clone-edit ran outside the lock (cloning from a cheap `load()` and only taking the
        // lock to swap), both would clone the SAME pre-edit map and the later swap would drop the
        // earlier server's edit: a just-detected drift or refresh silently lost. Holding the lock
        // from clone through publish makes the sequence atomic, so concurrent applies serialise and
        // every edit survives. Readers still pay only `load()`'s cheap read lock + `Arc` clone; the
        // edit closures do only in-memory map mutation and never re-enter the cache, so the critical
        // section is short and cannot deadlock.
        let mut live = match self.live.write() {
            Ok(g) => g,
            // A poisoned lock means a prior writer panicked mid-swap. The published snapshot is
            // immutable and whole, so it is still a coherent base to copy from; refusing it would
            // take the MCP plane down for a panic that cannot have corrupted it.
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut servers = live.servers.clone();
        edit(&mut servers);
        // Bump BEFORE publishing the swap, still under the write lock. A dispatch that reads a
        // generation newer than the snapshot it selected refuses and retries (spurious); the reverse
        // order would let it pair a stale generation with a fresh snapshot and conclude nothing
        // changed. The bump fires for every apply, no-op included.
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *live = Arc::new(CatalogueSnapshot {
            generation,
            servers,
        });
    }
}

/// THE DIGEST THE UPSTREAM IS CURRENTLY SERVING, as the dispatch gate sees it.
///
/// Three answers and not two, because "we have never looked" and "we looked and it moved" are
/// different facts with different correct outcomes, and collapsing them is how a drift gate ends up
/// either refusing every declaratively-approved deployment or admitting every drifted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveDigest {
    /// No successful `tools/list` has ever been taken for this server. The operator's declarative
    /// approval stands on its own and the config-written hash is what dispatch compares — which is
    /// the pre-existing behaviour, preserved deliberately: a deployment that never runs `connect`
    /// must keep serving exactly as it did.
    Unsighted,
    /// The last observation DISAGREES with the standing approval on some axis — a changed schema,
    /// a capability that vanished, an identity that moved, a failed contact, a suspension. Dispatch
    /// is refused until an operator works the change. The word is for the operator.
    Quarantined(&'static str),
    /// The upstream is currently serving this capability at this digest. Handed to the trust
    /// lifecycle's own comparison, which decides whether it is the approved one.
    At(String),
}

/// THE OPERATOR'S WORD FOR A STATE THAT DOES NOT SERVE, or `None` for the one that does.
///
/// One definition, two readers: the ADVERTISEMENT path asks it through [`LiveDigest`], and the
/// DISPATCH path asks it when the ordered validator refuses at the registration. Two spellings of
/// "this server is suspended" is busbar hiding a tool for one stated reason and refusing it for
/// another.
fn quarantine_word(state: TrustState) -> Option<&'static str> {
    match state {
        TrustState::Approved => None,
        TrustState::Quarantined => Some("the last refresh disagrees with what was approved"),
        TrustState::Error => Some("the last refresh could not reach this server"),
        TrustState::Suspended => Some("this server is suspended"),
        TrustState::Pending => Some("this server has no locked identity pin"),
    }
}

/// THE SAME QUESTION ASKED OF THE SIGHTING AS WELL AS THE STATE, which is what the two paths
/// actually need.
///
/// A demotion replayed from the durable record at boot derives `Quarantined` like any other drift,
/// but the operator reading it has a different question — the drift itself is not in hand, and the
/// sweep that re-derives it is due immediately. That fact lives on the SIGHTING and no `TrustState`
/// can carry it, so it is answered here rather than by inventing a state for the mapping to put it
/// in.
///
/// Both the advertisement path and the dispatch path call this, so a tool hidden for one stated
/// reason cannot be refused for another.
pub(crate) fn quarantine_word_for(
    sighting: &Sighting<TransportPin>,
    state: TrustState,
) -> Option<&'static str> {
    if matches!(sighting, Sighting::Demoted(_)) {
        return Some(
            "this server was demoted before the last restart and the demotion has not been worked",
        );
    }
    quarantine_word(state)
}

/// THE LIVE TOOL-LIST OBSERVATIONS, as a read-only view the dispatch gate can be handed.
///
/// A borrowed wrapper rather than a raw `Option<&CatalogueSnapshot>` so the SERVER direction's
/// catalogue never has to know the cache's internals, and so a call site that has no cache at all
/// has to say so out loud ([`LiveSightings::unsighted`]) rather than by passing a value that happens
/// to be empty.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LiveSightings<'a>(Option<&'a CatalogueSnapshot>);

impl<'a> LiveSightings<'a> {
    /// No live cache is consulted: every lookup answers [`LiveDigest::Unsighted`].
    // Production always has a cache to consult (it rides the `App`), so this is the shape used by
    // callers that legitimately have none — the catalogue's own unit batteries, which pin the
    // no-sighting fallback that a declarative deployment depends on.
    #[cfg_attr(any(not(test), feature = "extracted"), allow(dead_code))]
    pub(crate) fn unsighted() -> Self {
        Self(None)
    }

    /// Consult this snapshot.
    pub(crate) fn of(snapshot: &'a CatalogueSnapshot) -> Self {
        Self(Some(snapshot))
    }

    /// THE LAST SIGHTING for one registration, or `Sighting::Never` where this view has none.
    ///
    /// Handed to the ordered validator so the registration-level half of the artifact question is
    /// derived by the lifecycle itself rather than restated here. `Never` is not a failure: a record
    /// approved from a declarative config pin has legitimately never been reached, and it is what
    /// keeps a deployment that has never run a refresh serving exactly as it did.
    pub(crate) fn sighting_for(&self, server: &str) -> Sighting<TransportPin> {
        self.0
            .and_then(|s| s.servers.get(server))
            .map_or(Sighting::Never, |e| e.sighting.clone())
    }

    /// What `server`'s `tool` is CURRENTLY observed at, judged against the operator's LIVE standing
    /// approval.
    ///
    /// `approval` is passed in rather than read off the cached entry deliberately. The cached copy
    /// is whatever the intent was at the last refresh; the operator may have approved a new digest
    /// since, and a gate that consulted the stale copy would keep refusing a change the operator has
    /// already worked. The state and the drift are the lifecycle's own derivations, so there is no
    /// second opinion about what "quarantined" means.
    pub(crate) fn digest_for(
        &self,
        server: &str,
        tool: &str,
        approval: &Approval<TransportPin>,
    ) -> LiveDigest {
        let Some(entry) = self.0.and_then(|s| s.servers.get(server)) else {
            return LiveDigest::Unsighted;
        };
        let sighting = &entry.sighting;
        if matches!(sighting, Sighting::Never) {
            return LiveDigest::Unsighted;
        }
        // A DEMOTION THIS PROCESS DID NOT WITNESS, replayed from the durable record at boot, and
        // every other non-serving state — asked as ONE question so the advertisement path and the
        // dispatch path cannot answer it differently.
        if let Some(why) = quarantine_word_for(sighting, approval.state(sighting)) {
            return LiveDigest::Quarantined(why);
        }
        match sighting {
            Sighting::Seen(observation) => match observation.capabilities.get(tool) {
                Some(digest) => LiveDigest::At(digest.clone()),
                // Approved-and-no-longer-offered is `removed` drift and is already caught above, so
                // reaching here means a tool that was never approved either. Refusing rather than
                // falling back to the config hash is the fail-closed answer: the fallback is for a
                // server nobody has looked at, not for a tool nobody saw.
                None => LiveDigest::Quarantined("this tool is not in the last observed tool list"),
            },
            // `Never` returned above; `Failed` is `TrustState::Error` and returned above.
            _ => LiveDigest::Quarantined("there is no successful observation to dispatch against"),
        }
    }
}

/// THE REFRESH TRIGGER GATE: an upstream may ASK for a re-pull and may not have one on demand.
///
/// `notifications/tools/list_changed` is attacker-controlled in both timing and content. This gate
/// answers only the timing half — content is handled by never reading the notification's body at
/// all, which is a property of the caller and is asserted in the tests.
///
/// Deliberately NOT a token bucket. A bucket lets a burst through, and the thing being rationed is
/// "how recently did we re-pull", where a burst has no value: two re-pulls a millisecond apart
/// return the same list. A hard floor between accepted triggers is the honest shape.
// WIRED. `super::peer` classifies a peer's `…/list_changed` and `super::pool::RefreshTriggers`
// holds one of these per server; an accepted trigger puts the server's NAME — and nothing from the
// notification's body — into a pending set that verify-on-call consumes on the NEXT `tools/call`
// (`super::pool::RefreshTriggers::take_if_pending`), marking that server's snapshot stale so the call
// re-verifies. It moves TIMING, never content: what follows is the authoritative `tools/list`,
// re-hashed. The gate rate-limits so an upstream cannot turn one edit into a fetch storm.
#[derive(Debug)]
pub(crate) struct RefreshGate {
    min_interval_ms: u64,
    last_accepted_ms: AtomicU64,
    /// Rejections since construction, so an operator can see an upstream hammering the trigger
    /// rather than only seeing that nothing happened.
    rejected: AtomicU64,
}

#[allow(dead_code)]
impl RefreshGate {
    pub(crate) fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            // `u64::MAX` would make the first trigger wait; 0 with a saturating comparison makes the
            // first trigger always accepted, which is right: there has been no recent re-pull.
            last_accepted_ms: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Whether a notification arriving at `now_ms` may bring a re-pull forward.
    ///
    /// Takes the clock as an argument rather than reading it, so the rate limit is testable without
    /// sleeping — a rate limiter tested by sleeping is a rate limiter tested at one timing.
    pub(crate) fn allow(&self, now_ms: u64) -> bool {
        let last = self.last_accepted_ms.load(Ordering::SeqCst);
        // First-ever trigger: `last == 0` and any real clock is past the interval.
        if last != 0 && now_ms.saturating_sub(last) < self.min_interval_ms {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        self.last_accepted_ms.store(now_ms.max(1), Ordering::SeqCst);
        true
    }

    pub(crate) fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::SeqCst)
    }
}

#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/rugpull_tests.rs"]
mod rugpull_tests;

#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/catalogue_concurrency_tests.rs"]
mod catalogue_concurrency_tests;
