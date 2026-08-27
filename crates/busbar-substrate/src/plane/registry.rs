// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL PLANE-REGISTRY SURFACE — the plane VOCABULARY/SEAM declaration a plane crate names
//! WITHOUT reaching into `busbar-core`.
//!
//! ## Why this lives here
//!
//! `PlaneDecl` is the DATA a plane hands the composition root so a plane that is not in core joins by
//! being handed to the same constructor (`busbar_core::plane::registry::install_planes`). An EXTRACTED
//! plane crate (`busbar-mcp`, `busbar-a2a`) constructs its own `PlaneDecl` and every seam type its
//! fields name; for it to do so without a path back to core, those types live in the neutral substrate.
//! Core RE-EXPORTS each from `busbar_core::plane::registry` so the in-core call sites — the fold, the
//! dispatch build, the boot hooks and the built-in `PLANE_DECL`s — are unchanged.
//!
//! What STAYS in core is the population glue (`BUILTIN_PLANE_DECLS`, `plane_decls`, `install_planes`,
//! `merged_boot_plane_decls`, `build_dispatch`) — it names `busbar_core::plane::Plane` /
//! `PlaneDispatch` and the built-in plane statics, all core-live — and `BootCtx`, whose store surface
//! is `PlaneStore` but whose phase fields borrow the core-live `App` / `AppHandle`. A plane boot hook
//! reads that context through the NEUTRAL [`PlaneBootCtx`] trait (which `BootCtx` implements core-side),
//! so an extracted plane names no `App`.
//!
//! [`PlaneDecl`] carries the plane VOCABULARY — the facts core reads to name, section, scope and label
//! a plane — plus the app-state SLOT seam ([`PlaneDecl::build`], threaded a [`BuildCtx`]), the SURFACE
//! seam ([`PlaneDecl::routes`] / [`PlaneDecl::admin_routes`] / [`PlaneDecl::openapi`]), and the BOOT
//! seam ([`PlaneDecl::hydrate`] / [`PlaneDecl::start`], a [`BootHook`] over a [`PlaneBootCtx`]).

/// EVERYTHING A PLANE'S [`PlaneDecl::build`] NEEDS to construct its runtime object for one config
/// generation — threaded from `appbuild::build_app_from_config` so a plane builds its object from
/// the SAME resolved config the composition root read, never a second parse of it.
///
/// Individual `&`-fields rather than `&RootCfg` as a whole: by the point in `build_app_from_config`
/// where planes are built, several `RootCfg` fields unrelated to a plane (`models`, among others)
/// have already been partially moved out of `cfg` for lowering elsewhere, so a single `&RootCfg`
/// borrow would not compile at that call site. Holds only what today's two planes with a slot (MCP,
/// A2A) actually read; a future plane needing another section adds a field here rather than gaining
/// its own parameter list, so `build`'s signature never has to change per plane.
pub struct BuildCtx<'a> {
    /// The MCP plane's runtime object for THIS generation, ALREADY built and TYPE-ERASED at config
    /// resolution (`McpResource::from_cfg` ran at `RootCfg` construction) and handed across this seam
    /// as an OPAQUE slot — so the seam names no `crate::mcp` type. The MCP plane's `build` clones this
    /// `Arc` into `plane_slots` unchanged rather than constructing a second one; `None` exactly when
    /// `mcp:` is absent, matching `App::mcp`'s own absence. Erasing at the composition root instead of
    /// in the plane's `build` is what removes the one concrete-type name this struct used to carry
    /// into the eventual MCP extraction — the neutral analogue of how the LLM dialects left core.
    pub mcp_slot: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    // The A2A registry the A2A plane's `build` lowers, TYPE-ERASED so this seam names no `crate::a2a`
    // config type — reached through `RootCfg::agent_defs`'s neutral `PlaneCfg::as_any` (`AgentsCfg`
    // with the plane compiled in, the raw capture without it). The A2A `build` closure downcasts it
    // back inside its own module; no other plane reads it, and it is built and consumed synchronously
    // here, so the erased `&dyn Any` needs no `Send + Sync` bound.
    pub agent_defs: &'a dyn std::any::Any,
    pub public_url: Option<&'a str>,
    /// THE PRIOR GENERATION'S SLOT MAP, or `None` on a fresh boot — the same neutral
    /// [`crate::plane_host::PlaneSlots`] seam `build_runtime` receives, so a plane's `build` can CARRY
    /// accumulated coordination state (verify-on-call coalescing epochs, a boot-resolved transport
    /// `OnceLock`) off its own prior runtime object across a config apply without the composition root
    /// naming the plane's runtime type. Reached by key through [`crate::plane_host::PlaneSlots::plane_slot`]
    /// and downcast inside the plane's own `build`, exactly as the runtime accessors downcast the live
    /// slot. The A2A plane reads it to carry its `VerifyGate` and card-fetch `OnceLock`; a plane with no
    /// carry-over ignores it.
    pub prior: Option<&'a dyn crate::plane_host::PlaneSlots>,
}

/// A PLANE BOOT HOOK — [`PlaneDecl::hydrate`] or [`PlaneDecl::start`]. Handed the [`PlaneBootCtx`] for
/// its phase; an `Err` REFUSES BOOT (the fold propagates it with `?`).
///
/// The context is the NEUTRAL [`PlaneBootCtx`] trait object rather than the core-live `BootCtx` struct
/// so an extracted plane crate's boot hook names no `busbar_core` type: the MCP hook reads only the
/// neutral methods, while an in-core plane (A2A) recovers the concrete `BootCtx` through
/// [`PlaneBootCtx::as_any`].
pub type BootHook = fn(&dyn PlaneBootCtx) -> Result<(), String>;

/// A NEUTRAL, PLAIN-DATA SUMMARY of what a boot rehydrate of a plane's durable per-call log found —
/// the value [`PlaneBootCtx::restore_call_log`] returns so a plane's hydrate hook can log the outcome
/// WITHOUT naming the core-live `busbar_core::calllog::Restored` type (which carries the rich
/// `audit::ChainBreak`). Every field is the same value the old `Restored` comparison and logging
/// relied on: the three counts verbatim, and each chain break as its already-Display-formatted
/// string (the exact text the hook logged via `%brk`), so an all-default summary means an all-default
/// restore and the per-break diagnostic reads byte-identically.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoredSummary {
    /// Principals whose chain position was resumed.
    pub principals: usize,
    /// Records read back across every principal — the durability signal.
    pub records: usize,
    /// Principals the store enumerated but returned no records for.
    pub empty_chains: usize,
    /// Chains that FAILED to verify, each rendered as the exact break-detail text the hook logs.
    pub chain_breaks: Vec<String>,
}

/// A NEUTRAL, PLAIN-DATA SUMMARY of what a boot rehydrate of the A2A plane's durable in-flight task
/// working set found — the value [`PlaneBootCtx::restore_task_log`] returns so the A2A hydrate hook can
/// log the outcome WITHOUT naming the core-live `taskstore::Rehydrated` type (which carries the rich
/// `audit::ChainBreak`). Every field is the same value the old `Rehydrated` comparison and logging
/// relied on: the three counts verbatim, [`Self::empty`] the `r == Rehydrated::default()` guard the
/// hook opens its logging with, and each chain break its already-Display-formatted diagnostic text
/// PAIRED with the `scope` (task id) the hook logs as a distinct structured field — so the per-break
/// event reads byte-identically.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoredTasks {
    /// Active or interrupted tasks brought back and resumable.
    pub active: usize,
    /// Terminal tasks seen and deliberately not loaded into the working set.
    pub terminal: usize,
    /// Rows that would not parse — an in-flight task that ceased to exist across a deploy, counted
    /// rather than silently dropped.
    pub unreadable: usize,
    /// The `restore found NOTHING` guard: `true` exactly when the underlying `Rehydrated` equalled its
    /// `Default` (no active/terminal/unreadable rows and no chain breaks), the condition under which the
    /// hook logs nothing at all — byte-identical to the old `Ok(r) if r == Rehydrated::default()` arm.
    pub empty: bool,
    /// Tasks whose persisted provenance chain FAILED to verify — tamper evidence, each carried as the
    /// exact per-task diagnostic the hook logs.
    pub chain_breaks: Vec<TaskChainBreak>,
}

/// ONE A2A per-task provenance CHAIN BREAK, reduced to the two already-formatted strings the hook logs
/// — the `scope` (task id) it stamps as the `task_id` structured field and the `Display` text it stamps
/// as `break_detail` — so the neutral summary carries both values the old `%brk.scope` / `%brk` logging
/// used without naming the core-live `audit::ChainBreak`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskChainBreak {
    /// The task id the break was found on (the chain's `scope`) — logged as `task_id`.
    pub task_id: String,
    /// The chain break's full Display text — logged as `break_detail`.
    pub detail: String,
}

/// BUSBAR'S PUBLISHED CARD-ISSUER KEY, computed core-side and handed to the A2A [`PlaneDecl::start`]
/// hook as PUBLIC values ONLY — the `kid` and the base64 Ed25519 SPKI an operator hands a counterparty
/// out of band to pin busbar by. Deliberately NOT the signer and NOT its seed: a boot hook publishes
/// the public half, it never signs, so no signing material crosses this seam (invariant (a)). Lives in
/// the neutral substrate so the A2A boot hook reads it off [`PlaneBootCtx::card_issuer`] without naming
/// a `busbar_core` type; core re-exports it at `busbar_core::plane::registry::CardIssuer` so every
/// in-core caller (`governance::state`, the A2A plane's own card slot) resolves unchanged.
#[derive(Clone)]
pub struct CardIssuer {
    pub kid: String,
    pub issuer_spki_base64: String,
}

/// THE NEUTRAL BOOT-CONTEXT SEAM a plane's [`PlaneDecl::hydrate`] / [`PlaneDecl::start`] hook reads,
/// implemented core-side by `busbar_core::plane::registry::BootCtx` — so an extracted plane crate
/// (MCP) drives its boot restore through typed, neutral methods without the hook signature naming
/// `busbar_core::state::App`.
///
/// The MCP-facing methods each forward to the core-owned engine the concrete `BootCtx` wraps, keeping
/// every `App` / `PlaneStore` / `Store` reach on the CORE side of this seam (invariant (a)): the boot
/// hook can restore the plane's own durable state but never touches the append-only audit chain.
/// [`Self::as_any`] is the recovery hatch an IN-CORE plane twin (A2A, still in core) uses to downcast
/// back to the concrete `BootCtx` for the phase fields (`app`, `handle`, `card_issuer`) that name
/// core-live types; an extracted plane never calls it.
pub trait PlaneBootCtx {
    /// Whether governance configured a durable store for this deployment — the `ctx.store.is_none()`
    /// gate a hydrate hook opens with, so it skips its restore when the plane's durable state is
    /// ephemeral by design (`store: memory`). `true` iff a plane-narrowed store is present.
    fn has_store(&self) -> bool;

    /// REGISTER THE MCP PLANE'S DURABLE `call` STREAM with the host, in the hydrate phase — the first
    /// boot step of the per-call log, before the rehydrate. A no-op unless the freshly-built app
    /// (hydrate phase) is present.
    fn register_call_stream(&self);

    /// REHYDRATE THE MCP PLANE'S DURABLE `call` CHAIN from the plane-narrowed store, in the hydrate
    /// phase — the boot rehydrate, run AFTER [`Self::register_call_stream`]. Returns the NEUTRAL
    /// [`RestoredSummary`] rather than the core-live `calllog::Restored`, so the hook logs the outcome
    /// without naming a core-live type. The `Err` is the store error's Display string.
    fn restore_call_log(&self) -> Result<RestoredSummary, String>;

    /// ATTACH THE MCP PLANE'S DURABLE WRITE-THROUGH SINKS — the spent-approval ledger and the
    /// upstream-demotion record — to the plane-narrowed store, in the hydrate phase. A no-op unless
    /// BOTH the freshly-built app and a configured store are present.
    fn attach_mcp_durable_sinks(&self);

    /// REGISTER THE A2A PLANE'S DURABLE `task_event` STREAM with the host, in the hydrate phase — the
    /// first boot step of the durable task set, run BEFORE the row-upsert sink and the rehydrate so the
    /// host attaches its own chain sink at register time. A no-op unless the freshly-built app (hydrate
    /// phase) is present. The A2A twin of [`Self::register_call_stream`].
    fn register_task_event_stream(&self);

    /// ATTACH THE A2A PLANE'S TASK-ROW UPSERT SINK to the plane-narrowed store, in the hydrate phase —
    /// run AFTER [`Self::register_task_event_stream`] and BEFORE [`Self::restore_task_log`], so the
    /// row upserts and the host-side chain reach one backend. A no-op unless a configured store is
    /// present. The A2A twin of [`Self::attach_mcp_durable_sinks`].
    fn attach_a2a_durable_sinks(&self);

    /// REHYDRATE THE A2A PLANE'S IN-FLIGHT TASK WORKING SET from the plane-narrowed store, in the
    /// hydrate phase — the boot rehydrate, run AFTER [`Self::register_task_event_stream`] and
    /// [`Self::attach_a2a_durable_sinks`], opening a dispatch scope internally so the seed reaches the
    /// host over a live `HostCtx`. Returns the NEUTRAL [`RestoredTasks`] rather than the core-live
    /// `taskstore::Rehydrated`, so the hook logs the outcome without naming a core-live type. The `Err`
    /// is the store error's Display string. The A2A twin of [`Self::restore_call_log`].
    fn restore_task_log(&self) -> Result<RestoredTasks, String>;

    /// THE DEPLOYMENT'S PUBLIC CARD-ISSUER KEY, in the start phase — the `kid` and base64 SPKI the A2A
    /// start hook stashes on the plane's own card slot and publishes for an operator to pin busbar by.
    /// `Some` only when this deployment mints one and only in the start phase; `None` otherwise. PUBLIC
    /// material only — the signing seed never crosses this seam (invariant (a)).
    fn card_issuer(&self) -> Option<CardIssuer>;

    /// MINT THE NEUTRAL ENGINE HOST over the freshly-built app, in the hydrate phase — the
    /// snapshot-only mint a hydrate hook drives its durable boot-replay off (no live handle yet at
    /// hydration). The returned `Arc<dyn EngineHost>` is the neutral substrate seam and the app it
    /// wraps is the core-owned hydrate-phase `App`.
    fn engine_host(&self) -> std::sync::Arc<dyn crate::plane_host::EngineHost>;

    /// Recover the concrete core `BootCtx` as `&dyn Any` — the hatch an in-core plane twin (A2A)
    /// downcasts through to reach the phase fields (`app`, `handle`, `card_issuer`) that name core-live
    /// types. An extracted plane never names a concrete type through this, so it never calls it.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// EVERYTHING CORE KNOWS ABOUT A PLANE'S VOCABULARY, declared once by the plane itself.
///
/// Every field replaces one arm of one `match self` on `busbar_core::plane::Plane`. The doc on each
/// says which strings it feeds, because these are the strings that must not agree by coincidence: two
/// planes sharing a scope kind is how one plane's grant admits another plane's traffic, and two planes
/// sharing an audit kind is how one plane's records start answering another plane's question.
///
/// The TYPE is `pub` — the composition root names it in `install_planes`' signature, and a private
/// type cannot appear in a public one. The vocabulary/seam FIELDS are `pub` too: a plane crate built
/// outside core constructs its own `PlaneDecl` and hands it to `install_planes`, so each field it
/// populates is reachable. The seam types those fields name ([`BuildCtx`], [`BootHook`], the
/// router/view/admission types) are public for the same reason.
pub struct PlaneDecl {
    /// The registry key, the metrics label, the log label and the audit resource prefix.
    /// **OPERATOR-VISIBLE.** Replaces `Plane::key`'s match.
    pub key: &'static str,

    /// The top-level `config.yaml` section whose mere EXISTENCE declares this plane. Replaces
    /// `Plane::config_section`'s match, and it is this field that `config::config_sections_from`
    /// folds — so a plane registered from outside core gets its section into the hook-reference grammar
    /// with nothing written for it in core.
    pub config_section: &'static str,

    /// The `ScopeRef` kinds that grant access ON this plane. A slice because a plane may grant at
    /// more than one granularity (MCP grants a whole server or a single tool). Replaces
    /// `Plane::scope_kinds`' match.
    pub scope_kinds: &'static [&'static str],

    /// What ONE registration on this plane is called, in the words an operator reads back in a
    /// `404`. Replaces `Plane::subject_noun`'s match.
    pub subject_noun: &'static str,

    /// The audit RESOURCE KIND for a registration on this plane, and the prefix of every audit
    /// action word the plane's verbs record. Replaces `Plane::audit_kind`'s match.
    pub audit_kind: &'static str,

    /// The distinct WIRE FORMATS this plane translates between, named. A FUNCTION rather than a
    /// slice for exactly one reason, and it is the reason the field is worth its indirection: the
    /// LLM plane's answer is `busbar_core::proto::known_protocols` — read off the live protocol
    /// registry, so a seventh dialect does not depend on anybody remembering to bump a literal here.
    /// A plane whose list is constant returns a `&'static` slice and pays nothing.
    ///
    /// `Plane::wire_formats` and `Plane::has_superset_ir` stay DERIVED from this list's length, so
    /// the superset-IR rule remains a rule rather than a fact about today's planes.
    pub wire_format_names: fn() -> &'static [&'static str],

    /// THE PATHS THIS PLANE ANSWERS ON, and the wire format each is spoken in, computed from the
    /// plane's own RUNTIME OBJECT (its app slot, type-erased as `&dyn Any`). Every `(path, wire)`
    /// this returns is mounted into `PlaneDispatch` and — since `PlaneDispatch::admission_for`
    /// resolves the RFC 8707 audience THROUGH the mount table — becomes a path where a token's `aud`
    /// is checked. A plane that answers on a path it does NOT return here has left a confused-deputy
    /// hole: the door where any resource's token is admitted. So the invariant this list upholds is:
    /// every path a plane answers on is a path it claims here. The A2A
    /// plane returns TWO claims — `/a2a` and the gRPC service `/lf.a2a.v1.A2AService`, whose path a
    /// gRPC client derives from the `.proto` and cannot be pointed elsewhere.
    ///
    /// Returns the empty vec when the plane mounts nothing (a delegation-only A2A deployment, or a
    /// plane the operator did not configure — its slot is then absent and this is not called).
    pub claims: fn(&dyn std::any::Any) -> Vec<(String, &'static str)>,

    /// THE ADMISSION FACTS this plane binds — the audience a token presented at its door must carry,
    /// and where a refused caller is sent to get one — computed from the same runtime object. `None`
    /// when the plane has no RECEIVING side to admit anyone to (A2A without a `public_url`); a plane
    /// that [`Self::claims`] a path but returns `None` here is refused at boot by `build_dispatch`
    /// rather than left serving an unauthenticated resource (ratchet R2).
    pub admission: fn(&dyn std::any::Any) -> Option<super::PlaneAdmission>,

    /// BUILD THE PLANE'S RUNTIME OBJECT for one config generation, type-erased as
    /// `Arc<dyn Any + Send + Sync>` — the app-state SLOT that [`Self::claims`] and [`Self::admission`]
    /// above are computed from. Returns `None` when the plane is not configured for this generation
    /// (no `tools:` / no `agents:` block, or an `agents:` block with no receiving side), matching the
    /// `mcp: None` / absent-`a2a` behaviour those blocks' mere absence has always meant.
    ///
    /// A plane with no single runtime object to erase (today, `llm`: its state is the many `App`
    /// fields the LLM data plane already reads directly, not one object) returns `None`
    /// unconditionally — it contributes no slot, exactly as [`Self::claims`] already returns nothing
    /// for it.
    pub build: fn(&BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    /// THE PLANE'S DATA ROUTES, described NEUTRALLY (S4a Option A) — the one seam a plane contributes
    /// its data-plane routes through, naming no core router type. From the plane's own runtime slot
    /// (type-erased `&dyn Any`), the plane returns a flat list of
    /// [`crate::plane_routes::PlaneRouteSpec`] — each a `(path, method, auth, handler)`
    /// where the handler is a neutral async fn over a
    /// [`crate::plane_routes::PlaneReqCtx`], never an `axum` extractor or `Arc<AppHandle>`.
    /// The CORE adapter (`busbar_core::router::mount_plane_routes`) iterates the specs and, per spec,
    /// calls the EXISTING `CoreRouter::route` with the same `(path, method, auth)`, so the
    /// `CoreRouteTable` rows are byte-identical to the ones a core-typed handler would record — only
    /// the handler's shape sits behind the neutral seam.
    ///
    /// `None` for a plane that answers on no data path (the LLM plane, whose endpoints are the
    /// protocol catch-all, mounted in `base_data_router` directly rather than through this seam).
    #[allow(clippy::type_complexity)]
    pub routes: Option<fn(&dyn std::any::Any) -> Vec<crate::plane_routes::PlaneRouteSpec>>,

    /// CONTRIBUTE THE PLANE'S ADMIN VERBS to the Admin API v1 router — the operator surface a plane
    /// adds ON TOP of the generic named-definition CRUD (MCP's `connect`/`changes`/`health`, A2A's
    /// `connect`/`approve`). `None` for a plane with no admin verbs. Unconditional (not slot-gated):
    /// the verbs are part of the surface whether or not the plane is configured this generation, so
    /// this takes only the router. Merged in declaration order so the route order is stable and
    /// operator-visible.
    ///
    /// As with [`Self::routes`], the signature grants a plane's admin contribution ONLY the router —
    /// never a `Store`, a `GovCtx`, or an `audit::Chain`.
    /// Described NEUTRALLY (ADMIN-3), mirroring [`Self::routes`]: from the plane's own runtime slot
    /// (type-erased `&dyn Any`) the plane returns a flat list of
    /// [`crate::admin_verbs::AdminRouteSpec`] — each a `(method, path, scope, kind, handler)`
    /// where the handler is a neutral async fn over an
    /// [`crate::admin_verbs::AdminReqCtx`], never an `axum` extractor or `Arc<AppHandle>`. The
    /// CORE adapter (`busbar_core::admin::v1::json::mount_plane_admin_routes`) registers each spec at
    /// its VERBATIM `(method, path)`, so the auth middleware's `required_scope(method, path)` is
    /// byte-identical — the security invariant this seam preserves.
    #[allow(clippy::type_complexity)]
    pub admin_routes: Option<fn(&dyn std::any::Any) -> Vec<crate::admin_verbs::AdminRouteSpec>>,

    /// CONTRIBUTE THE PLANE'S OpenAPI PATH FRAGMENT — a JSON object whose keys are the ABSOLUTE admin
    /// paths this plane's verbs answer on and whose values are the OpenAPI path items. Merged into the
    /// admin document in declaration order. `None` for a plane that contributes no admin path. A plane
    /// that contributes admin verbs ([`Self::admin_routes`] is `Some`) MUST return a non-empty object
    /// here, so the document can never silently omit a mounted verb.
    // Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test; a
    // default `--no-default-features` build has neither, so the field is genuinely unread there.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    pub openapi: Option<fn() -> serde_json::Value>,

    /// RESTORE THIS PLANE'S DURABLE STATE, in order, BEFORE a listener is bound — the plane half of
    /// `busbar_core::boot::hydrate_all`. Handed a [`PlaneBootCtx`] whose store surface is `PlaneStore`
    /// and nothing that carries the audit chain, so a hydrate hook can attach the plane's write-through
    /// sinks and read them back but can never touch the append-only chain (invariant (a)). `None` for
    /// a plane with no durable state to restore (the LLM plane). A hook returning `Err` REFUSES BOOT:
    /// `busbar_core::boot::hydrate_all` propagates it with `?`, so a plane cannot half-restore and serve.
    pub hydrate: Option<BootHook>,

    /// START THIS PLANE'S BOOT-TIME WORK, AFTER the listeners are built — the plane half of
    /// `busbar_core::boot::start_planes`. Handed the same [`PlaneBootCtx`], now carrying the live app
    /// handle, the shutdown broadcast a spawned loop exits on and the deployment's PUBLIC card-issuer
    /// key (never its seed). Since verify-on-call replaced the background sweep, the built-in start
    /// hooks no longer spawn a reverify loop — the MCP plane has no start hook at all, and the A2A one
    /// only resolves and publishes its per-agent card transports. `None` for a plane that starts
    /// nothing. A hook returning `Err` REFUSES BOOT — an outbound identity that does not resolve is a
    /// startup failure, never a warning — so `busbar_core::boot::start_planes` propagates it with `?`.
    pub start: Option<BootHook>,

    /// VALIDATE ONE RAW NAMED-DEFINITION DOCUMENT for this plane's config section — the write-path
    /// grammar the admin API enforces so a definition the API accepts is exactly one `config.yaml`
    /// would accept. Handed the entry `name` and its raw definition document, it parses that document
    /// into the plane's own typed config and applies the plane's VALUE-level rules (an MCP server's
    /// pin matching its material, an agent's durations parsing, no cross-plane hook reference),
    /// returning `Ok(())` or the SAME error string boot produces — because the plane's own
    /// `Deserialize`/boot path reaches the identical function. It is the seam that lets
    /// `config::named_map::NamedMapSection::parse_def` validate a `tools:`/`agents:` write
    /// without core naming a `crate::mcp`/`crate::a2a` validate function.
    ///
    /// `None` for a plane whose section is not a 1.5.3 named-definition map (the LLM plane — `pools:`
    /// predates the generic path and keeps its own richer validation — and the residual `proto`
    /// plane, which owns no config section of its own).
    // Read only through the named-definition write path, which exists only when at least one plane
    // section (`plane-mcp`/`plane-a2a`) is compiled in; a build with neither never resolves a decl
    // to call it, so the field is genuinely unread there rather than dead.
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    #[allow(clippy::type_complexity)]
    pub config_validate: Option<fn(name: &str, def: &serde_json::Value) -> Result<(), String>>,

    /// THE DOMAIN this plane derives its agent-card signing subkey under — a versioned `&'static str`
    /// constant, NOT a fn over a signer. It is the ONLY thing the host needs to reproduce the plane's
    /// card key: `GovState::card_sign` reads it off this decl, derives the subkey from the core token
    /// signer (`TokenSigner::sign_with_card_subkey`) and signs HOST-side, so no signing material ever
    /// reaches the plane (invariant (a)). `None` for every plane that does not sign cards, so
    /// `GovState::a2a_card_issuer`/`card_sign` return `None` with the A2A plane compiled out and
    /// `governance/state.rs` names no `crate::a2a` type.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    pub card_signing_domain: Option<&'static str>,

    /// THE `kid` PREFIX this plane stamps on its card signatures, prepended to the token signer's own
    /// `kid` so a caller can SEE that the card key is not the token key. A `&'static str` constant for
    /// the same reason [`Self::card_signing_domain`] is: the host builds the published issuer `kid`
    /// (`GovState::a2a_card_issuer`) from this and the token `kid` without naming the plane. `None` for
    /// a plane that signs no cards.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    pub card_kid_prefix: Option<&'static str>,

    /// PROJECT THIS PLANE'S NAMED-DEFINITION REGISTRATIONS onto the shared read view — the plane half
    /// of the generic `GET /api/v1/admin/<section>` list, so `admin::v1::service` reads a plane's
    /// registrations without naming the plane's config or view types. Returns the empty vec for a
    /// plane with no live registry this generation. `None` for a plane whose section is not a
    /// named-definition map (the LLM plane; `proto`).
    ///
    /// Handed the neutral [`crate::plane_host::PlaneSlots`] seam (NOT `&App`), so a plane crate reads
    /// its own per-generation runtime object off the snapshot without the callback naming a core type;
    /// an in-core plane (A2A) recovers its snapshot through the seam's `as_any` hatch.
    // Read only through the admin named-def surface, which the two plane sections drive; with neither
    // plane compiled in nothing resolves a decl to call it, so the field is genuinely unread there.
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    #[allow(clippy::type_complexity)]
    pub named_def_list:
        Option<fn(&dyn crate::plane_host::PlaneSlots) -> Vec<crate::api::NamedDefView>>,

    /// PROJECT ONE NAMED-DEFINITION REGISTRATION by name onto the shared read view — the single-entry
    /// twin of [`Self::named_def_list`], the plane half of `GET /api/v1/admin/<section>/{name}`.
    /// `None` (the fn returns `None`) when the plane has no entry by that name; the FIELD is `None` for
    /// a plane with no named-definition map. Handed the same neutral [`crate::plane_host::PlaneSlots`]
    /// seam as [`Self::named_def_list`].
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    #[allow(clippy::type_complexity)]
    pub named_def_get:
        Option<fn(&dyn crate::plane_host::PlaneSlots, &str) -> Option<crate::api::NamedDefView>>,

    /// IS `name` A LIVE REGISTRATION on this plane's effective snapshot — the read-side membership
    /// check the admin write path consults so it names no plane registry type. `None` for a plane with
    /// no named-definition map.
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    #[allow(clippy::type_complexity)]
    pub registry_contains: Option<fn(&dyn crate::plane_host::PlaneSlots, &str) -> bool>,

    /// RE-RESOLVE THIS PLANE'S PER-REGISTRATION HOOK GATES against the next snapshot — the plane half
    /// of the config-swap gate rebuild. Reads the plane's own registry off the `&mut App` and writes
    /// its own gate field back, so `admin::v1::service::reresolve_plane_gates` names no plane registry
    /// type. `None` for a plane with no per-registration hook gates (the LLM plane).
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    pub reresolve_gates: Option<fn(&mut dyn crate::plane_host::ContainerGateSink)>,

    /// ATTACH THIS PLANE'S ADMIN TRUST-VERB SCHEMAS to the OpenAPI document — the plane half of the
    /// schema pass in `busbar_core::admin::v1::json::handlers::openapi_doc`. Handed the SHARED response
    /// and request [`schemars::SchemaGenerator`]s and the `paths` map, it registers its own view/body
    /// types into `#/components/schemas` and attaches their `$ref`s onto the paths its [`Self::openapi`]
    /// fragment inserted — so `handlers` names no `crate::mcp`/`crate::a2a` view type and the document
    /// stays byte-identical. `None` for a plane with no admin verbs (the LLM plane).
    ///
    /// Gated with `openapi-schema` because it is the only place `schemars` is named; a build without
    /// that feature generates no document, so the field is genuinely absent rather than unused.
    #[cfg(feature = "openapi-schema")]
    #[allow(clippy::type_complexity)]
    pub openapi_schemas: Option<
        fn(
            &mut schemars::SchemaGenerator,
            &mut schemars::SchemaGenerator,
            &mut serde_json::Map<String, serde_json::Value>,
        ),
    >,

    /// CARRY THIS PLANE'S ENGINE-OWNED STATE ACROSS A CONFIG SWAP — the plane half of
    /// `busbar_core::state::AppHandle::swap`. Run once per swap, AFTER the next snapshot is fully built
    /// and BEFORE it is published, with the PRIOR and NEXT snapshots each type-erased as `&dyn Any`.
    /// A plane whose runtime state is rebuilt from config on every apply carries nothing and sets this
    /// `None`; a plane that holds live state which deliberately OUTLIVES an apply (a connection pool,
    /// an accumulated-sightings cache) uses this to reconcile that state to the next generation —
    /// today, retiring the pooled children of a registration the next generation no longer declares,
    /// so a deleted registration's process does not run on unreferenced and unreachable.
    ///
    /// The erased pair is the plane's own runtime state to read and reconcile — never a `Store`, a
    /// `GovCtx`, or an `audit::Chain`. A plane whose swap-time work needs one of those is not cleanly
    /// separable through this seam.
    pub on_swap: Option<
        fn(prior: &dyn crate::plane_host::PlaneSlots, next: &dyn crate::plane_host::PlaneSlots),
    >,

    /// PARSE THIS PLANE'S TOP-LEVEL REGISTRY SECTION from a positionless `serde_yaml::Value` into its
    /// own typed config, boxed as the neutral [`crate::plane::config::PlaneCfg`] — the seam
    /// `DeployCfg`'s `tools:`/`agents:` field deserializes through, so core names no plane config type.
    /// `None` for a plane with no registry section (the LLM / `proto` planes).
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    #[allow(clippy::type_complexity)]
    pub parse_section:
        Option<fn(&serde_yaml::Value) -> Result<Box<dyn crate::plane::config::PlaneCfg>, String>>,

    /// PARSE THIS PLANE'S TOP-LEVEL ENDPOINT block (the MCP plane's `mcp:` door) from a positionless
    /// `serde_yaml::Value`, boxed as the neutral [`crate::plane::config::PlaneEndpointCfg`] — the seam
    /// `DeployCfg`'s `mcp:` field deserializes through. `None` for a plane with no endpoint block
    /// (every plane but MCP).
    #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    pub parse_endpoint: Option<
        fn(&serde_yaml::Value) -> Result<Box<dyn crate::plane::config::PlaneEndpointCfg>, String>,
    >,

    /// LOWER THIS PLANE'S ENDPOINT block into its validated runtime resource, type-erased as
    /// `Arc<dyn Any>` — the seam `config::resolve` derives `RootCfg::mcp` through, so core derives the
    /// validated resource without naming the plane's resource type. An `Err` is collected into the
    /// resolve error list verbatim. `None` for a plane with no endpoint block.
    #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    pub lower_endpoint: Option<
        fn(
            &dyn crate::plane::config::PlaneEndpointCfg,
        ) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String>,
    >,

    /// BUILD THIS PLANE'S PER-GENERATION RUNTIME OBJECT from its type-erased registry section — the
    /// seam `appbuild` composes the MCP runtime slot (`plane_slots[MCP_RUNTIME_SLOT]`) through,
    /// so core names no plane runtime type. The first argument is the plane's own section, erased as
    /// `&dyn Any` (its `PlaneCfg::as_any`); `prior` is the previous generation's snapshot for
    /// carry-over, read through the neutral [`crate::plane_host::PlaneSlots`] seam (NOT `&App`).
    /// `None` for a plane whose runtime is not carried through this seam (A2A's lives in `plane_slots`
    /// under its decl key; the LLM plane's is the many `App` fields it already reads).
    #[allow(clippy::type_complexity)]
    pub build_runtime: Option<
        fn(
            &dyn std::any::Any,
            prior: Option<&dyn crate::plane_host::PlaneSlots>,
        ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,

    /// PRUNE THIS PLANE'S VERIFY-ON-CALL COALESCING STATE to the subjects the freshly-built generation
    /// still fronts — the seam `appbuild` runs after building the `App`, so the carried per-subject
    /// flights/latches do not leak one dead entry per removed registration. `None` for a plane with no
    /// verify-on-call gate (the LLM / `proto` planes).
    pub retain_verify_gates: Option<fn(&dyn crate::plane_host::PlaneSlots)>,

    /// THIS PLANE'S EMPTY REGISTRY SECTION, boxed as the neutral [`crate::plane::config::PlaneCfg`] —
    /// the value `DeployCfg`'s `#[serde(default)]` `tools:`/`agents:` field takes when the section is
    /// ABSENT, so the default is the plane's own `Default` (byte-identical to the pre-seam
    /// `ToolsCfg::default()`) rather than a re-parse of an empty document. `None` for a plane with no
    /// registry section (the LLM / `proto` planes).
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    pub default_section: Option<fn() -> Box<dyn crate::plane::config::PlaneCfg>>,
}
