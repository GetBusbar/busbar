// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE AS A RUNNING THING: what the operator's `agents:` section lowers to, and the one
//! object whose EXISTENCE is the answer to "is this deployment an A2A plane?".
//!
//! ## Absent config means absent plane, not a disabled one
//!
//! [`A2aPlane::from_config`] returns `None` when no agent is configured. That is the whole gate:
//! a deployment with no `agents:` section holds no registry, spawns no job and mounts no route, so
//! "is the A2A plane running here?" is answered by the mounted surface rather than by a boolean an
//! operator has to trust. The alternative — always build the plane and check a flag on every path —
//! puts the answer in as many places as there are paths.
//!
//! ## INTENT is lowered once; ACCUMULATION lives here and only here
//!
//! [`super::config::AgentDefCfg`] is what the operator wrote and may edit. An
//! [`super::registry::AgentRegistration`] is that intent PLUS everything that has since been
//! observed: the last sighting, the cached card, the re-verification ledger, the breaker's window.
//! The split is the same one `AgentDefCfg`'s own doc draws, and this type is where the second half
//! actually lives — behind one `RwLock`, because verify-on-call mutates the registration it
//! re-verifies and a config apply rebuilds the whole registry, and a reader that saw a half-applied
//! mutation would be reading a registry that never existed.
//!
//! ## Nothing here comes into existence trusted
//!
//! Every registration is built by `AgentRegistration::registered`, which is the fail-closed floor:
//! `Pending`, no pin approved, no card cached, nothing delegable. A pin an operator DECLARED in
//! config is deliberately NOT lifted into an approval here — [`busbar_substrate::trust::declared`] can read
//! one off [`super::config::AgentPinCfg::declaration`], but an approval is a statement about a
//! document that was actually SEEN, and turning a
//! config value into one at boot would approve a card nobody has fetched. The `connect` verb
//! captures the fingerprint and a human approves it; that ordering is the trust root, not a
//! formality.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use super::config::{AgentPinCfg, AgentsCfg, DEFAULT_RECOVERY_BACKOFF_MS};
use super::fetch::FetchPolicy;
use super::registry::AgentRegistration;
use busbar_substrate::diag_warn;
use busbar_substrate::diagnostics::A2A_REVERIFY_CADENCE_UNPARSED;

/// THE PLANE. Built once per config generation; `None` when this deployment fronts no agents.
pub(crate) struct A2aPlane {
    /// busbar's public base origin, carried so the card-serving path has ONE reading of it. `None`
    /// is a serving-time refusal ([`super::serve::ServeError::BadPublicUrl`]) rather than a boot
    /// failure: an operator may configure `agents:` for the DELEGATING direction alone, and
    /// refusing to boot would make the receiving side's requirement the whole plane's.
    public_url: Option<String>,
    /// The card-fetch policy every pass on this plane uses. One reading, so verify-on-call and an
    /// operator-driven `connect` cannot guard differently.
    fetch_policy: FetchPolicy,
    /// The operator's trust roots, by agent id. Held apart from the registrations because a pin is
    /// INTENT: it is re-read from config on every apply, and a registration's accumulated half is
    /// not.
    pins: BTreeMap<String, AgentPinCfg>,
    /// THE REGISTRY. One lock over the whole vector rather than one per entry: verify-on-call takes
    /// the WRITE lock to re-verify one agent and a config apply rebuilds the whole vector, and a
    /// reader that saw a half-applied mutation would be reading a registry state that never existed at
    /// any instant.
    registrations: RwLock<Vec<AgentRegistration>>,
    /// THE GENERATION THIS REGISTRY IS AT, taken from the process-wide monotonic source in
    /// [`busbar_substrate::trust::validate`] and re-taken on every mutation.
    ///
    /// It is what makes an in-flight request unable to outlive the approval it was admitted under.
    /// Admission records this value; the gate immediately before the socket re-reads it; a move is a
    /// refusal. Without it a verify-on-call re-verification, a breaker trip or an operator's `suspend`
    /// that lands between admission and the socket takes effect on the NEXT request rather than on the
    /// one in flight — the exact window the sibling plane closed and this one had left open.
    ///
    /// Bumped for ANY mutation rather than only for trust-relevant ones. Deciding whether a
    /// particular change mattered means re-deriving the whole admission, and "did this specific
    /// change affect me" is the reasoning that lets a revocation slip through. Movement is refusal;
    /// the caller retries and is re-admitted under the new registry.
    generation: AtomicU64,
    /// THE RELAY SEAM: the resolver, the POST transport and the fetch policy the hot path submits a
    /// task through, held as ONE object so a caller cannot pair a real transport with a fixture
    /// resolver — the same reason [`super::transport::LiveCardFetch`] exists.
    ///
    /// Held on the plane rather than constructed per request so that the object a request relays
    /// through is the object this deployment was built with, and so a test can drive the real
    /// ingress against a recording seam without the ingress growing a test-shaped argument.
    relay: RwLock<Arc<dyn super::relay::RelaySeam>>,
    /// BUSBAR'S PUBLIC AGENT-CARD ISSUER KEY (`kid` + SPKI), stashed by the plane's `start` hook from
    /// the host-computed [`busbar_core::plane::registry::BootCtx::card_issuer`]. PUBLIC material only — the
    /// signing seed stays host-side and is reached through [`busbar_core::plane_host::card_sign_over`]. Held
    /// here so [`super::sign::card_signer`] reads the issuer off the plane's OWN slot rather than off
    /// `app.governance`, which is what lets the extracted plane name no `GovState`. `None` until the
    /// start hook runs, or when the deployment holds no card-signing key (the governance-off path).
    card_issuer: OnceLock<busbar_substrate::plane::registry::CardIssuer>,
    /// THE A2A VERIFY-ON-CALL GATE — the per-agent single-flight coalescer that re-verifies a fronted
    /// agent's signed card on the DELEGATION path when its recorded observation is older than
    /// `verify_ttl` (see [`busbar_core::trust::verify`]). Held HERE on the plane's own runtime object, like
    /// its MCP sibling holds `verify` on `McpRuntime`, rather than on the shared `App`: verify-on-call
    /// reads it off the plane slot, not off `busbar_core::state::App`.
    ///
    /// Arc-shared ACROSS config applies (carried by [`Self::from_config_carrying`] from the prior
    /// generation's plane), like its MCP sibling and for the same reason: the coalescing epochs are
    /// accumulated coordination state, not intent. When the `agents:` block is REMOVED there is no
    /// plane this generation, so the gate is dropped whole — the unobservable analogue of the old
    /// `retain(&empty)`, since a deployment fronting no agents runs no delegation to read it.
    verify: Arc<busbar_substrate::trust::VerifyGate>,
    /// THE A2A CARD-FETCH TRANSPORTS, resolved ONCE at boot (per-agent client identities, the same
    /// object the delegation hop relays through). Verify-on-call reads it on the request path to
    /// re-fetch and re-verify a stale card. Empty until the A2A `start` hook publishes it through
    /// [`Self::set_cards`] — and a delegation-only-or-absent deployment leaves it empty.
    ///
    /// A boot-resolved `OnceLock`, carried across applies by the SAME `Arc` (via
    /// [`Self::from_config_carrying`]) so the value set at boot persists: the client certificates are
    /// resolved from secrets at boot (a resolution failure is a boot refusal), and an agent added by a
    /// later apply is verified on the boot-time transport. Concrete type (no erasure) because this
    /// object lives inside the a2a module, which is compiled only under `plane-a2a`.
    cards: Arc<OnceLock<Arc<super::transport::LiveCardFetch>>>,
    /// THE RESOLVED `agents:` REGISTRY this generation was lowered from — the raw operator INTENT,
    /// carried on the plane's own runtime object so the admin read/config surface reads it off the
    /// neutral plane slot rather than off the type-erased `App::agent_defs` handle. The exact
    /// byte-analog of `McpRuntime::servers` (`Arc<config::ToolsCfg>`): the plane already keeps only
    /// the DERIVED state (registrations/pins/fetch_policy), so the raw `AgentsCfg` is genuinely new
    /// here. A cheap `Arc` clone of the same resolved config the composition root erased; `list`/
    /// `get`/`contains`/`reresolve_gates` read [`Self::agent_defs`] off it, so they name no `App`.
    defs: Arc<AgentsCfg>,
}

/// THE LIVE TRUST DECISION, read off THE PLANE'S OWN REGISTRY at the moment it is asked.
///
/// This is what makes a mid-flight demotion take effect on the request that is already in flight.
/// It holds an `Arc` to the plane rather than a copy of a registration, because a copy is a decision
/// that was true when it was copied — which is precisely the staleness the gate exists to close.
pub(crate) struct LiveGate(pub(crate) Arc<A2aPlane>);

impl super::relay::DelegationGate for LiveGate {
    /// `admitted` is the generation the request was ADMITTED under. It is carried down the hop
    /// rather than re-read here, because a value re-read here would be the live one compared against
    /// itself — a check that cannot fail.
    ///
    /// THE PRINCIPAL IS DELIBERATELY ABSENT. [`super::relay::RelayCall`] has no field a caller's
    /// credential could arrive through and that absence is a security property of the hop, so the
    /// identity step of the validator ran at admission and what stands in for it here is the
    /// generation: a key change that reaches the registry moves it, and a key change that does not
    /// is bounded by the life of one hop.
    fn still_delegable(
        &self,
        agent_id: &str,
        admitted: u64,
    ) -> Result<(), super::relay::NotDelegable> {
        let live = self.0.generation();
        self.0.with_registrations(|regs| {
            let Some(reg) = regs.iter().find(|r| r.agent_id == agent_id) else {
                // The registration was REMOVED by a config apply between admission and the socket.
                // Not a state the trust machine has a name for, so it is reported as the fail-closed
                // floor a fresh registration starts at rather than invented as something else.
                return Err(super::relay::NotDelegable {
                    agent_id: agent_id.to_string(),
                    state: busbar_substrate::trust::TrustState::Pending,
                    reason: Some("the registration no longer exists on this plane".to_string()),
                });
            };
            // THE ONE ORDERED GATE, reached from the third of this plane's paths. It can only ever
            // be more closed than admission was, never differently closed, because it is the same
            // function admission called.
            busbar_substrate::trust::validate::validate_request(
                &busbar_substrate::trust::validate::Ask {
                    principal: None,
                    now: 0,
                    grants: &[],
                    approval: &reg.approval,
                    sighting: &reg.sighting,
                    capability: None,
                    generation: busbar_substrate::trust::validate::Generations::since(
                        admitted, live,
                    ),
                },
            )
            .map_err(|refusal| super::relay::NotDelegable {
                agent_id: agent_id.to_string(),
                state: reg.trust_state(),
                reason: match &refusal {
                    busbar_substrate::trust::validate::Refusal::NotServing { reason, .. } => {
                        reason.clone()
                    }
                    other => Some(other.to_string()),
                },
            })
        })
    }
}

impl A2aPlane {
    /// LOWER `agents:` INTO A RUNNING REGISTRY, or answer that there is no plane here.
    ///
    /// Returns `None` when the section defines no agent. An `agents:` section carrying only the
    /// reserved section-level keys (`hooks:`, `upstream_credentials:`) is likewise no plane: those
    /// keys are defaults FOR agents, and defaults for an empty set are not a deployment that fronts
    /// anything.
    ///
    /// A per-agent cadence that does not parse is not reachable here: `validate_agent` already
    /// refused it at boot and at the admin write path, so [`super::config::policy_for`]'s error is
    /// a state config validation has already excluded. It is still handled rather than unwrapped —
    /// the registration keeps the constructor's default cadence and says so — because a panic in a
    /// config lowering is a panic on the operator's next apply.
    // Production builds the plane through `from_config_carrying` (it CARRIES the verify gate and card
    // transports across an apply); the fresh-gate `from_config` shorthand has callers only under
    // `test`/`test-support` (every A2A test, and the `TestApp` fixture), so it reads dead without them.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    pub(crate) fn from_config(cfg: &AgentsCfg, public_url: Option<&str>) -> Option<Arc<Self>> {
        // In the dual-compile / test-support build there is no composition root to install the neutral
        // `TaskCodec` seam (the `busbar` binary's `main` does that in production), so a plane test would
        // otherwise drive the TASKS engine with an uninstalled codec — its transitions/floor/restore
        // fragments are A2A domain logic reached only through this seam. Install it here, idempotently
        // (`OnceLock`), from the test/fixture entry point every A2A test builds a plane through —
        // mirroring how the MCP plane installs the hostless-egress seam in its own test path.
        #[cfg(any(all(test, feature = "test-support"), feature = "test-support"))]
        busbar_substrate::plane_host::install_task_codec(&super::task::A2aTaskCodec);
        // Same reason: the test/fixture build has no composition root, so bind core's `TaskReader`
        // backing here too, idempotently, so the plane's `HostCtx`-free task reads resolve.
        #[cfg(any(all(test, feature = "test-support"), feature = "test-support"))]
        busbar_substrate::plane_host::install_task_reader(&busbar_core::plane::CoreTaskReader);
        // And the parse-time section-list provider, so a plane built here validates its `hooks:`
        // cross-plane references against the real fold rather than the empty pre-bind list.
        #[cfg(any(all(test, feature = "test-support"), feature = "test-support"))]
        busbar_substrate::plane::config::install_plane_sections(
            busbar_core::plane::config::config_sections,
        );
        // And the self-enveloping verb backing, so `approve` renders its `Prebuilt` envelope + audit
        // through the real core helpers in a plane test with no composition root.
        #[cfg(any(all(test, feature = "test-support"), feature = "test-support"))]
        busbar_substrate::admin_verbs::install_plane_admin_envelope(
            &busbar_core::admin::planeverbs::CorePlaneAdminEnvelope,
        );
        Self::from_config_carrying(
            cfg,
            public_url,
            Arc::new(busbar_substrate::trust::VerifyGate::new()),
            Arc::new(OnceLock::new()),
        )
    }

    /// LOWER `agents:` INTO A RUNNING REGISTRY, CARRYING the verify-on-call gate and the boot-resolved
    /// card transports across from the prior generation's plane — the composition-root entry point
    /// ([`super::PLANE_DECL`]'s `build`) uses this so the coalescing epochs and the boot-set transports
    /// survive every config apply (fresh defaults on the first build). [`Self::from_config`] is the
    /// fresh-gate shorthand every test uses.
    pub(crate) fn from_config_carrying(
        cfg: &AgentsCfg,
        public_url: Option<&str>,
        verify: Arc<busbar_substrate::trust::VerifyGate>,
        cards: Arc<OnceLock<Arc<super::transport::LiveCardFetch>>>,
    ) -> Option<Arc<Self>> {
        if cfg.agents.is_empty() {
            return None;
        }
        let mut pins = BTreeMap::new();
        let mut registrations = Vec::with_capacity(cfg.agents.len());
        for (name, def) in &cfg.agents {
            // THE FAIL-CLOSED FLOOR, and the only constructor. Everything below adds INTENT to it;
            // nothing below makes it trusted.
            let mut reg = AgentRegistration::registered(name, &def.url);
            if let Some(v) = def.protocol_version.as_deref() {
                reg.protocol_version = v.to_string();
            }
            match super::config::policy_for(def, DEFAULT_RECOVERY_BACKOFF_MS) {
                Ok(policy) => reg.reverify = policy,
                Err(e) => diag_warn!(
                    A2A_REVERIFY_CADENCE_UNPARSED,
                    agent = %name,
                    error = %e,
                    "the re-verification cadence did not parse; this registration keeps the release \
                     default. Config validation should have refused this before boot."
                ),
            }
            reg.egress_scopes = def.egress_scopes.clone();
            reg.outbound_cred = def.upstream_credential.clone();
            reg.allow_private = def.allow_private;
            pins.insert(name.clone(), def.pin.clone());
            registrations.push(reg);
        }
        let fetch_policy = FetchPolicy::default();
        Some(Arc::new(Self {
            relay: RwLock::new(Arc::new(super::transport::LiveCardFetch::new(
                fetch_policy.clone(),
            ))),
            public_url: public_url.map(str::to_string),
            fetch_policy,
            pins,
            registrations: RwLock::new(registrations),
            generation: AtomicU64::new(busbar_substrate::trust::validate::next_generation()),
            card_issuer: OnceLock::new(),
            verify,
            cards,
            defs: Arc::new(cfg.clone()),
        }))
    }

    /// THE VERIFY-ON-CALL GATE this plane re-verifies fronted agents through, as the delegation path
    /// and the `retain_verify_gates` prune read it. Held on the plane, not on `App`, mirroring MCP's
    /// `McpRuntime::verify`.
    pub(crate) fn verify(&self) -> &Arc<busbar_substrate::trust::VerifyGate> {
        &self.verify
    }

    /// The OWNED-`Arc` twin of [`Self::verify`], for the carry across a config apply
    /// ([`Self::from_config_carrying`]) — a refcount bump of the same gate, so the coalescing epochs
    /// persist.
    pub(crate) fn verify_arc(&self) -> Arc<busbar_substrate::trust::VerifyGate> {
        Arc::clone(&self.verify)
    }

    /// THE BOOT-RESOLVED CARD-FETCH TRANSPORTS, as verify-on-call reads them on the request path.
    /// Empty until [`Self::set_cards`] publishes them from the `start` hook.
    pub(crate) fn cards(&self) -> &OnceLock<Arc<super::transport::LiveCardFetch>> {
        &self.cards
    }

    /// The OWNED-`Arc` twin of [`Self::cards`], carried across a config apply so the boot-set
    /// transports survive every generation.
    pub(crate) fn cards_arc(&self) -> Arc<OnceLock<Arc<super::transport::LiveCardFetch>>> {
        Arc::clone(&self.cards)
    }

    /// PUBLISH THE BOOT-RESOLVED CARD TRANSPORTS, once, from the plane's `start` hook. Idempotent
    /// (`OnceLock` semantics): a later config apply carries the same `Arc` forward, so the boot value
    /// stands.
    pub(crate) fn set_cards(&self, live: Arc<super::transport::LiveCardFetch>) {
        let _ = self.cards.set(live);
    }

    /// STASH BUSBAR'S PUBLIC CARD-ISSUER KEY, once, from the plane's `start` hook. Idempotent: a second
    /// call (a config re-apply reaching the same plane object) is a no-op, matching the `OnceLock`
    /// contract. Public material only.
    pub(crate) fn set_card_issuer(&self, issuer: busbar_substrate::plane::registry::CardIssuer) {
        let _ = self.card_issuer.set(issuer);
    }

    /// BUSBAR'S PUBLIC CARD-ISSUER KEY for this deployment, as the card-signing path reads it. `None`
    /// before the start hook has run or when no card-signing key is configured.
    pub(crate) fn card_issuer(&self) -> Option<&busbar_substrate::plane::registry::CardIssuer> {
        self.card_issuer.get()
    }

    /// THE RELAY SEAM this deployment submits relayed tasks through. The LIVE one, always, in a
    /// production build: the only other setter is `#[cfg(all(test, feature = "test-support"))]`.
    pub(crate) fn relay_seam(&self) -> Arc<dyn super::relay::RelaySeam> {
        Arc::clone(&self.relay.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Swap the relay seam. TEST ONLY, and compiled out of every release binary — a production
    /// build has exactly one way to obtain a seam, which is the constructor above.
    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn set_relay_seam(&self, seam: Arc<dyn super::relay::RelaySeam>) {
        *self.relay.write().unwrap_or_else(|e| e.into_inner()) = seam;
    }

    /// busbar's public base origin, as the card-serving path reads it.
    pub(crate) fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    /// The one card-fetch policy this plane guards with.
    pub(crate) fn fetch_policy(&self) -> &FetchPolicy {
        &self.fetch_policy
    }

    /// THE RESOLVED `agents:` REGISTRY this generation was lowered from — the admin read/config
    /// surface reads the operator's definitions HERE, off the plane's own runtime object, rather
    /// than off the type-erased `App::agent_defs` handle. The byte-analog of reading
    /// `McpRuntime::servers` (an `Arc<config::ToolsCfg>`) on the MCP plane.
    pub(crate) fn agent_defs(&self) -> &AgentsCfg {
        &self.defs
    }

    /// THE PLANE'S POLICY, NARROWED TO ONE REGISTRATION by that registration's `allow_private:`.
    ///
    /// Derived rather than stored, on every ask, so there is exactly one reading of the operator's
    /// line: verify-on-call, an operator-driven `connect` and an `approve` all obtain the policy here and
    /// therefore cannot guard differently — which is the property `fetch_policy` was added to hold
    /// for the plane-wide half and which a per-agent knob would have broken if each caller assembled
    /// its own.
    ///
    /// An id this plane does not front gets the plane default, which is the fail-closed one. There
    /// is deliberately no arm that reads "unknown agent ⇒ permissive".
    pub(crate) fn fetch_policy_for(&self, agent_id: &str) -> FetchPolicy {
        let allow_private = self.with_registrations(|regs| {
            regs.iter()
                .find(|r| r.agent_id == agent_id)
                .is_some_and(|r| r.allow_private)
        });
        FetchPolicy {
            allow_private,
            ..self.fetch_policy.clone()
        }
    }

    /// The operator's trust root for one agent. `None` for an id this plane does not front, which
    /// is the only honest answer: there is no default pin, and inventing one would be inventing a
    /// trust root.
    pub(crate) fn pin_for(&self, agent_id: &str) -> Option<&AgentPinCfg> {
        self.pins.get(agent_id)
    }

    /// READ the registry. The closure form rather than a returned guard so the lock's scope is
    /// visible at every call site and a caller cannot hold it across an await point.
    pub(crate) fn with_registrations<R>(&self, f: impl FnOnce(&[AgentRegistration]) -> R) -> R {
        let guard = self.registrations.read().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }

    /// MUTATE the registry. Same closure discipline as the read side, for the same reason.
    ///
    /// Poisoning is recovered from rather than propagated: a panic in one re-verification must not turn the
    /// registry into a permanently unreadable object, because a registry nobody can read is a plane
    /// that has silently stopped re-verifying anything.
    pub(crate) fn with_registrations_mut<R>(
        &self,
        f: impl FnOnce(&mut Vec<AgentRegistration>) -> R,
    ) -> R {
        let mut guard = self
            .registrations
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let out = f(&mut guard);
        // TAKEN WHILE THE WRITE LOCK IS STILL HELD, so no reader can observe the new registrations
        // under the old generation. A bump after the release would leave exactly the window this
        // number exists to close.
        self.generation.store(
            busbar_substrate::trust::validate::next_generation(),
            Ordering::Relaxed,
        );
        out
    }

    /// THE GENERATION THIS REGISTRY IS AT RIGHT NOW. Recorded at admission, re-read at the gate.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// RE-VERIFY ONE FRONTED AGENT'S CARD ON THE DELEGATION PATH — this plane's FETCH for verify-on-call.
    ///
    /// The single-flight, the freshness bound and the fail-closed ordering are
    /// [`busbar_substrate::trust::verify`]'s, once, for every plane; what is here is this plane's fetch: the same
    /// signed-card read, verification against the operator's out-of-band root, and settle that
    /// [`super::verify::reverify_once`] performs — over the per-agent transport that carries THIS
    /// registration's client certificate (`cards`), under the registry write lock. Blocking (a card
    /// fetch is a blocking socket read behind the SSRF guard), so the caller runs it on a blocking
    /// thread. `None` when the agent has no live registration or pin — a removed agent is not
    /// re-verified against a root nobody currently declares.
    ///
    /// It updates the registration's sighting and stamps its ledger, so the freshness clock records
    /// when verify-on-call looked and a failed contact derives `Error` (which the delegation gate then
    /// refuses fail-closed). Because [`Self::with_registrations_mut`] bumps the generation, the caller
    /// re-reads [`Self::generation`] AFTER this for the hop's admitted generation.
    pub(crate) fn reverify_agent(
        &self,
        agent_id: &str,
        resolver: &dyn super::fetch::Resolver,
        transports: &dyn super::verify::CardTransports,
        now_ms: u64,
    ) -> Option<super::verify::Pass> {
        let pin_cfg = self.pin_for(agent_id)?.clone();
        let fetch_policy = self.fetch_policy_for(agent_id);
        // SNAPSHOT under a SHORT read lock, then RELEASE it before the blocking fetch. The card read is
        // a blocking socket round-trip behind the SSRF guard; holding the registry WRITE lock across it
        // — as this once did — serialized every other agent's admission and verify against one agent's
        // full network round-trip, so a slow or hostile card host stalled the whole plane. Availability
        // is a named asset: the fetch below runs with NO registry lock held. `None` here keeps the
        // "no live registration" contract — a removed agent is not re-verified.
        let original =
            self.with_registrations(|regs| regs.iter().find(|r| r.agent_id == agent_id).cloned())?;
        let transport = transports.for_agent(agent_id);
        // FETCH + VERIFY + SETTLE on a CLONE, entirely UNLOCKED. While this blocks, no reader is blocked
        // on us. Single-flight (`busbar_substrate::trust::verify`) already guarantees at most one of these per agent
        // at a time, so nothing else is mutating this registration's accumulation concurrently.
        let mut working = original.clone();
        let pass = super::verify::reverify_once(
            &mut working,
            &pin_cfg,
            resolver,
            transport,
            &fetch_policy,
            now_ms,
            false,
        );
        // APPLY under a BRIEF write lock. TOCTOU: if the registration VANISHED, or its record CHANGED
        // (a config reapply replaces the whole registry with fresh records and bumps the generation
        // itself) during the unlocked fetch, DROP the sighting we just derived rather than write an
        // observation computed against a pin/approval that is no longer the operator's intent. Dropping
        // is fail-closed: the reapplied registration starts un-approved and its own generation bump
        // refuses the in-flight hop; the next call re-verifies. Writing `working` back through
        // `with_registrations_mut` bumps the generation exactly as before, so the caller's post-fetch
        // `generation()` read still names the hop's admitted generation.
        self.with_registrations_mut(|regs| {
            let reg = regs.iter_mut().find(|r| r.agent_id == agent_id)?;
            if *reg != original {
                return None;
            }
            *reg = working;
            Some(pass)
        })
    }

    /// THIS AGENT'S VERIFICATION LEDGER and its re-verification policy — the two the verify-on-call
    /// gate reads to decide staleness (`fetched_at` and `verify_ttl`). `None` for an agent with no live
    /// registration. Read WITHOUT mutating, so a freshness check never bumps the generation.
    pub(crate) fn verify_state_of(
        &self,
        agent_id: &str,
    ) -> Option<(
        busbar_substrate::trust::reverify::Ledger,
        busbar_substrate::trust::reverify::Policy,
    )> {
        self.with_registrations(|regs| {
            regs.iter()
                .find(|r| r.agent_id == agent_id)
                .map(|r| (r.ledger.clone(), r.reverify.clone()))
        })
    }

    /// How many agents this deployment fronts.
    pub(crate) fn len(&self) -> usize {
        self.with_registrations(<[AgentRegistration]>::len)
    }

    /// THIS PLANE'S ADMISSION FACTS, or `None` when it has no RECEIVING side to admit anyone to.
    ///
    /// `None` for exactly one reason: no usable `public_url`. That is the same asymmetry the field's
    /// own doc records — an operator may configure `agents:` for the DELEGATING direction alone, and
    /// a deployment that only delegates fronts nothing, so it has no resource for a token to be
    /// bound to and no metadata document to point a refused caller at. Answering `None` here is what
    /// makes `main` mount no receiving route in that case, rather than mounting one that could only
    /// ever refuse.
    ///
    /// Both strings come from [`super::serve`], which is also what builds the endpoint the served
    /// card advertises. A caller reads the audience to ask for off the card busbar served it, so the
    /// two must be one derivation — an independently configured audience is a confused-deputy gap
    /// that opens the first time somebody edits one of the two.
    pub(crate) fn admission(&self) -> Option<busbar_substrate::plane::PlaneAdmission> {
        let public = self.public_url.as_deref()?;
        Some(busbar_substrate::plane::PlaneAdmission {
            audience: super::serve::canonical_uri(public).ok()?,
            resource_metadata: super::serve::metadata_url(public).ok()?,
        })
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/plane_tests.rs"]
mod plane_tests;
