// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DRIVER'S ROW FOR ONE OPENED PLANE DOOR: [`PlaneDecl`], the handle the kernel holds to a door
//! the composition root bound (spec Part 3 section 12: one driver, the loop and the registry; Part 2
//! #2: one loading path, the kernel holding no plugin crate's Rust types).
//!
//! A row is the door's contract declaration ([`PlaneDeclaration`], every word the door's Statement
//! states) joined to the driver's own hooks over that door ([`PlaneHooks`]: `fn` pointers into the
//! driver, monomorphised per door index by [`crate::plane_driver::door::fold`]). The kernel reads a
//! row; it builds the set of rows nowhere. The composition root folds every door it binds, linked or
//! dropped in, into the set and installs it once ([`crate::plane_driver::doors`]).
//!
//! Beside the row: the [`BuildCtx`] a row's `build` reads, and the boot surface its `hydrate` and
//! `start` read ([`PlaneBootCtx`], which [`BootCtx`] implements), whose store surface is
//! [`PlaneStore`](crate::store::plane_view::PlaneStore) and never the audit-carrying `Store`
//! (invariant (a)).

/// EVERYTHING A PLANE'S BOOT HOOKS ([`PlaneDecl::hydrate`], [`PlaneDecl::start`]) MAY READ, and
/// DELIBERATELY nothing that carries the audit chain, the governance context or the signing seed
/// (invariant (a)). Its surface names [`PlaneStore`](crate::store::plane_view::PlaneStore) — never
/// `Store`, `audit::Chain` or `GovCtx` — so a hook can restore a plane's own durable state but cannot
/// reach the append-only chain or the token mint through it.
///
/// The two boot phases run at different points with different context available (hydration precedes
/// the listener; start follows it), so the phase-specific fields are `Option`: hydration supplies the
/// store and the freshly-built app; start supplies the live handle, the shutdown broadcast and the
/// public card-issuer key. A hook reads the field for its own phase.
///
/// A plane's boot hook is handed this as the NEUTRAL [`PlaneBootCtx`] trait object (this struct
/// IMPLEMENTS it), so an extracted plane crate's hook names none of the core-live types below. The
/// `app`/`handle` phase fields hold their `Arc` OWNED (a boot-time refcount bump, byte-identical to
/// the borrow they replaced) so this struct is `'static` and an in-core plane twin can recover
/// it through [`PlaneBootCtx::as_any`] to reach those fields.
pub struct BootCtx {
    /// The PLANE-NARROWED durable store — task / call / demotion / spent methods only, never the
    /// audit-carrying `Store`. `Some` in the hydrate phase whenever governance configured a store;
    /// `None` in the start phase (a start hook restores nothing).
    pub store: Option<std::sync::Arc<dyn crate::store::plane_view::PlaneStore>>,

    /// HYDRATE phase — the freshly-built `App`, off which a hydrate hook attaches its own
    /// write-through sink (`demotion_record`) and restores them. `None` in the start
    /// phase, where the app has been moved into the router builder and only the handle remains.
    pub app: Option<std::sync::Arc<crate::state::App>>,

    /// START phase — the live app handle a start hook reads THIS config generation off. `None` in the
    /// hydrate phase (no listener yet). There is no `shutdown` broadcast on this seam any more: the
    /// built-in start hooks spawn no background loop now that verify-on-call replaced the sweep, so a
    /// hook has nothing to exit on a shutdown of.
    pub handle: Option<std::sync::Arc<crate::state::AppHandle>>,

    /// The deployment's PUBLIC card-issuer key (see [`CardIssuer`]). `Some` in the start phase when
    /// this deployment mints one; `None` in the hydrate phase and when no card is signed.
    pub card_issuer: Option<CardIssuer>,
}

impl BootCtx {
    /// THE HYDRATE-PHASE CONTEXT: the plane-narrowed store and the freshly-built app. No listener
    /// exists yet, so there is no handle, no shutdown broadcast and no card-issuer key to publish.
    pub fn for_hydrate(
        store: Option<std::sync::Arc<dyn crate::store::plane_view::PlaneStore>>,
        app: &std::sync::Arc<crate::state::App>,
    ) -> Self {
        BootCtx {
            store,
            app: Some(app.clone()),
            handle: None,
            card_issuer: None,
        }
    }

    /// THE START-PHASE CONTEXT: the live handle and the PUBLIC card-issuer key (computed core-side;
    /// the seed never crosses). A start hook restores nothing, so no store.
    pub fn for_start(
        handle: &std::sync::Arc<crate::state::AppHandle>,
        card_issuer: Option<CardIssuer>,
    ) -> Self {
        BootCtx {
            store: None,
            app: None,
            handle: Some(handle.clone()),
            card_issuer,
        }
    }
}

impl PlaneBootCtx for BootCtx {
    fn has_store(&self) -> bool {
        self.store.is_some()
    }

    /// ATTACH A PLANE'S DURABLE WRITE-THROUGH SINK — the upstream-demotion record — to the
    /// plane-narrowed store, in the hydrate phase. Named HERE, core
    /// side, so the plane's own hydrate hook attaches them without its own code naming an `App` field:
    /// the sink field (`demotion_record`) is core-owned and the store is the
    /// core `PlaneStore`, so neither crosses the plane seam. A no-op unless BOTH the freshly-built app
    /// (hydrate phase) and a configured store are present — byte-identical to the old inline
    /// `app.demotion_record.set_sink(store)`.
    fn attach_durable_sinks(&self) {
        if let (Some(app), Some(store)) = (self.app.as_ref(), &self.store) {
            app.demotion_record.set_sink(store.clone());
        }
    }

    /// MINT THE NEUTRAL ENGINE HOST over the freshly-built app, in the hydrate phase — the
    /// snapshot-only mint a hydrate hook drives its durable boot-replay off (no live handle yet at
    /// hydration, which is correct: hydration reads exactly the generation it is restoring into). Named
    /// HERE so a plane's own hydrate hook mints its host without naming `crate::plane_host::engine_host`
    /// or an `App`: the returned `Arc<dyn EngineHost>` is the neutral substrate seam and the app it
    /// wraps is the core-owned hydrate-phase `App`.
    fn engine_host(&self) -> std::sync::Arc<dyn busbar_kernel::plane_host::EngineHost> {
        // PHASE-AWARE: the hydrate phase supplies the freshly-built `app` and mints a SNAPSHOT-ONLY
        // host over it (no live handle yet, which is correct — hydration reads exactly the
        // generation it restores into); the start phase supplies the live `handle` and mints a host
        // over its current load (`from_handle`), byte-identical to the old start hook's
        // `handle.load()`-driven reads. Exactly one of the two is present per phase.
        if let Some(handle) = self.handle.as_ref() {
            crate::plane_host::engine_host_from_handle(handle)
        } else {
            let app = self.app.as_ref().expect(
                "engine_host runs in the HYDRATE phase (app) or the START phase (handle); one is present",
            );
            crate::plane_host::engine_host(app)
        }
    }

    fn card_issuer(&self) -> Option<CardIssuer> {
        self.card_issuer.clone()
    }

    /// THE PLANE-NARROWED DURABLE STORE, or `None` under `store: memory` — the generic handle a
    /// plane drives its own task-set boot (sink attach + rehydrate) off, so no plane-specific boot
    /// logic lives in this core seam. Just clones the phase-carried `Option<Arc<dyn PlaneStore>>`.
    fn plane_store(
        &self,
    ) -> Option<std::sync::Arc<dyn busbar_kernel::store::plane_view::PlaneStore>> {
        self.store.clone()
    }

    /// THE RECOVERY HATCH for an in-core plane twin. `BootCtx` is `'static` (its `app`/`handle`
    /// `Arc`s are owned), so a hook handed the neutral `&dyn PlaneBootCtx` downcasts back to the
    /// concrete `BootCtx` here to reach the phase fields (`app`, `handle`, `card_issuer`) that name
    /// core-live types. An extracted plane never calls this.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(any(test, feature = "test-support"))]
impl BootCtx {
    /// A ctx carrying no phase context, for the boot-hook FOLD tests (R2-boot): a hook that only
    /// returns `Err` — or a `None`-hook plane — reads nothing off it.
    pub fn stub() -> BootCtx {
        BootCtx {
            store: None,
            app: None,
            handle: None,
            card_issuer: None,
        }
    }
}

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
    /// THIS plane's own SECTION-KEYED resource for THIS generation (`RootCfg::endpoint_resource` at
    /// the plane's `config_section`), ALREADY built and TYPE-ERASED at config resolution and handed
    /// across this seam as an OPAQUE slot — so the seam names no plane type. For the endpoint-door
    /// plane it is its lowered endpoint resource, which its `build` clones into `plane_slots`
    /// unchanged rather than constructing a second one (`None` exactly when its door block is
    /// absent); for a plane whose section the kernel carries RAW it is `(section, value)`, the bytes
    /// that plane's `build` hands its plugin over the ABI. `None` for a plane whose section carries
    /// no resource.
    pub endpoint_slot: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    /// EVERY DECLARED SECTION this generation writes, by config section, behind the neutral
    /// [`crate::config::plane_sections::PlaneCfg`] seam (`RootCfg::plane_defs`): a plane's `build`
    /// reads its own section off it and names no other plane's.
    pub plane_defs: &'a std::collections::BTreeMap<
        &'static str,
        Box<dyn crate::config::plane_sections::PlaneCfg>,
    >,
    pub public_url: Option<&'a str>,
    /// THE PRIOR GENERATION'S SLOT MAP, or `None` on a fresh boot — the same neutral
    /// [`crate::plane_driver::slots::PlaneSlots`] seam `build_runtime` receives, so a plane's `build` can CARRY
    /// accumulated coordination state (verify-on-call coalescing epochs, a boot-resolved transport
    /// `OnceLock`) off its own prior runtime object across a config apply without the composition root
    /// naming the plane's runtime type. Reached by key through [`crate::plane_driver::slots::PlaneSlots::plane_slot`]
    /// and downcast inside the plane's own `build`, exactly as the runtime accessors downcast the live
    /// slot. A plane with no carry-over ignores it.
    pub prior: Option<&'a dyn crate::plane_driver::slots::PlaneSlots>,
    /// THIS GENERATION'S RESOLVED `providers:` (catalog-merged), from which a door plane's probe is
    /// handed the dialect facts of the providers its section references, as its served instance
    /// is; `None` = none (a test build that states none).
    pub providers:
        Option<&'a std::collections::HashMap<String, crate::config::providers::ResolvedProvider>>,
}

/// A PLANE BOOT HOOK — [`PlaneDecl::hydrate`] or [`PlaneDecl::start`]. Handed the [`PlaneBootCtx`] for
/// its phase; an `Err` REFUSES BOOT (the fold propagates it with `?`).
///
/// The context is the NEUTRAL [`PlaneBootCtx`] trait object rather than the core-live `BootCtx` struct
/// so an extracted plane crate's boot hook names no `busbar_kernel` type: the MCP hook reads only the
/// neutral methods, while an in-core plane (A2A) recovers the concrete `BootCtx` through
/// [`PlaneBootCtx::as_any`].
pub type BootHook = fn(&dyn PlaneBootCtx) -> Result<(), String>;

/// BUSBAR'S PUBLISHED CARD-ISSUER KEY, computed core-side and handed to the A2A [`PlaneDecl::start`]
/// hook as PUBLIC values ONLY — the `kid` and the base64 Ed25519 SPKI an operator hands a counterparty
/// out of band to pin busbar by. Deliberately NOT the signer and NOT its seed: a boot hook publishes
/// the public half, it never signs, so no signing material crosses this seam (invariant (a)). Lives in
/// the neutral substrate so the A2A boot hook reads it off [`PlaneBootCtx::card_issuer`] without naming
/// a `busbar_kernel` type; core names it at `busbar_kernel::plane_driver::row::CardIssuer` so every
/// in-core caller (`governance::state`, the A2A plane's own card slot) resolves unchanged.
#[derive(Clone)]
pub struct CardIssuer {
    pub kid: String,
    pub issuer_spki_base64: String,
}

/// THE NEUTRAL BOOT-CONTEXT SEAM a plane's [`PlaneDecl::hydrate`] / [`PlaneDecl::start`] hook reads,
/// implemented core-side by [`BootCtx`] — so an extracted plane crate
/// (MCP) drives its boot restore through typed, neutral methods without the hook signature naming
/// `busbar_kernel::state::App`.
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

    /// ATTACH THE CALLING PLANE'S DURABLE WRITE-THROUGH SINKS (today only the MCP plane has durable task state to attach) — the spent-approval ledger and the
    /// upstream-demotion record — to the plane-narrowed store, in the hydrate phase. A no-op unless
    /// BOTH the freshly-built app and a configured store are present.
    fn attach_durable_sinks(&self);

    /// THE PLANE-NARROWED DURABLE STORE for this deployment, or `None` under `store: memory`. A plane
    /// that OWNS its durable subsystem (the A2A task set) drives its own `PlaneRecord` reads/writes off
    /// this handle at boot — attaching it as its registry's sink and running its own rehydrate — rather
    /// than reaching a core-owned engine through a named boot method. Neutral: the handle is the generic
    /// [`crate::store::plane_view::PlaneStore`], naming no plane type.
    fn plane_store(&self) -> Option<std::sync::Arc<dyn crate::store::plane_view::PlaneStore>>;

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

/// One billable class, the token family and the two fee units now live in the CONTRACT beside
/// [`PlaneDeclaration`], because a plane states them as data; re-exported here at their old paths.
pub use busbar_contract::plane::{check_owned_config_claims, BillableClass, PlaneDeclaration};
pub use busbar_contract::plane::{PER_REQUEST, PER_SESSION, TOKEN_FAMILY};

/// DECLARES THE PLANE BEHAVIOUR TABLE ONCE and derives both of its shapes from the one field list:
/// [`PlaneHooks`], what a plane hands over BESIDE its contract [`PlaneDeclaration`], and
/// [`PlaneDecl`], the row the registry holds — the declaration plus every hook, flat, so a reader
/// names `decl.claims` and `decl.key` alike (the data through `Deref`). [`PlaneDecl::assemble`] is
/// the one join, and it is the kernel's: a plane crate never builds a `PlaneDecl`.
macro_rules! plane_behaviour {
    ($($(#[$m:meta])* $f:ident: $t:ty,)*) => {
        /// A PLANE'S BEHAVIOUR — every hook the kernel runs for it, and nothing it states about
        /// itself (that is its contract [`PlaneDeclaration`]). Typed by kernel seams, so it stays
        /// kernel-side; [`PlaneDecl::assemble`] folds it with the declaration into the registry row.
        pub struct PlaneHooks { $($(#[$m])* pub $f: $t,)* }

        /// THE REGISTRY ROW: a plane's contract [`PlaneDeclaration`] (read through `Deref`, so
        /// `decl.key` is the declaration's key) and its [`PlaneHooks`], flat. Built only by
        /// [`PlaneDecl::assemble`] or, in a test, by a literal naming both halves.
        ///
        /// A hook that reads its plane's own row is handed it (`&PlaneDecl`): a plane served through
        /// its door carries the door it was folded from ([`Self::door`]) in the row itself, so the
        /// row the composition root owns is everything its hooks read.
        pub struct PlaneDecl {
            /// The facts the plane states about itself — contract data.
            pub declaration: PlaneDeclaration, $($(#[$m])* pub $f: $t,)*
            /// THE DOOR THIS ROW WAS FOLDED FROM ([`crate::plane_driver::door::fold`]), or `None`
            /// for a plane whose hooks are its own code.
            pub door: Option<&'static crate::plane_driver::door::DoorRow>,
        }

        impl PlaneDecl {
            /// JOIN a plane's contract declaration and its behaviour into the registry row.
            pub const fn assemble(declaration: PlaneDeclaration, hooks: PlaneHooks) -> PlaneDecl {
                PlaneDecl { declaration, $($f: hooks.$f,)* door: None }
            }
        }
    };
}

/// The shape of [`PlaneDecl::openapi_schemas`]: the `components.schemas` a plane states, as data
/// (schema name to schema body). The admin document's generator inserts them into its response
/// generator's definitions as written; the hook names no generator type, so its shape is the same in
/// every build and a build that generates no document simply never calls it.
pub type OpenapiSchemasHook = fn(&PlaneDecl) -> Option<serde_json::Map<String, serde_json::Value>>;

impl std::ops::Deref for PlaneDecl {
    type Target = PlaneDeclaration;
    fn deref(&self) -> &PlaneDeclaration {
        &self.declaration
    }
}

plane_behaviour! {
    /// The distinct WIRE FORMATS this plane translates between, named. A FUNCTION rather than a
    /// slice for exactly one reason, and it is the reason the field is worth its indirection: a door
    /// plane's answer is the dialects its own Statement tail states, read off the folded door, so a
    /// seventh dialect does not depend on anybody remembering to bump a literal here.
    /// A plane whose list is constant returns a `&'static` slice and pays nothing.
    ///
    /// `Plane::wire_formats` and `Plane::has_superset_ir` stay DERIVED from this list's length, so
    /// the superset-IR rule remains a rule rather than a fact about today's planes.
    wire_format_names: fn(&PlaneDecl) -> &'static [&'static str],

    /// THE DIALECTS A PROVIDER'S `protocol` MAY NAME, of those this plane speaks, in its order
    /// (ARCHITECT ruling 2026-10-16, item 3; BUSBAR-1.6.0.md #49: declared data). A door plane's
    /// are the dialects its tail's `dialect_auth` lines flag `DIALECT_PROVIDER`. The boot accepts a
    /// provider whose `protocol` some registered plane lists here, and its refusal lists them all.
    provider_dialects: fn(&PlaneDecl) -> &'static [&'static str],

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
    claims: fn(&dyn std::any::Any) -> Vec<(String, &'static str)>,

    /// THE ADMISSION FACTS this plane binds — the audience a token presented at its door must carry,
    /// and where a refused caller is sent to get one — computed from the same runtime object. `None`
    /// when the plane has no RECEIVING side to admit anyone to (A2A without a `public_url`); a plane
    /// that [`Self::claims`] a path but returns `None` here is refused at boot by `build_dispatch`
    /// rather than left serving an unauthenticated resource (ratchet R2).
    admission: fn(&dyn std::any::Any) -> Option<crate::plane_driver::claims::PlaneAdmission>,

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
    build: fn(&PlaneDecl, &BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    /// THE PLANE'S DATA ROUTES, described NEUTRALLY (S4a Option A) — the one seam a plane contributes
    /// its data-plane routes through, naming no core router type. From the plane's own runtime slot
    /// (type-erased `&dyn Any`), the plane returns a flat list of
    /// [`crate::plane_routes::PlaneRouteSpec`] — each a `(path, method, auth, handler)`
    /// where the handler is a neutral async fn over a
    /// [`crate::plane_routes::PlaneReqCtx`], never an `axum` extractor or `Arc<AppHandle>`.
    /// The CORE adapter (`busbar_kernel::router::mount_plane_routes`) iterates the specs and, per spec,
    /// calls the EXISTING `CoreRouter::route` with the same `(path, method, auth)`, so the
    /// `CoreRouteTable` rows are byte-identical to the ones a core-typed handler would record — only
    /// the handler's shape sits behind the neutral seam.
    ///
    /// `None` for a plane that answers on no data path (the LLM plane, whose endpoints are the
    /// protocol catch-all, mounted in `base_data_router` directly rather than through this seam).
    #[allow(clippy::type_complexity)]
    routes: Option<fn(&dyn std::any::Any) -> Vec<crate::plane_routes::PlaneRouteSpec>>,

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
    /// CORE adapter (`busbar_core_admin::v1::json::mount_plane_admin_routes`) registers each spec at
    /// its VERBATIM `(method, path)`, so the auth middleware's `required_scope(method, path)` is
    /// byte-identical — the security invariant this seam preserves.
    #[allow(clippy::type_complexity)]
    admin_routes:
        Option<fn(&PlaneDecl, &dyn std::any::Any) -> Vec<crate::admin_verbs::AdminRouteSpec>>,

    /// CONTRIBUTE THE PLANE'S OpenAPI PATH FRAGMENT — a JSON object whose keys are the ABSOLUTE admin
    /// paths this plane's verbs answer on and whose values are the OpenAPI path items. Merged into the
    /// admin document in declaration order. `None` for a plane that contributes no admin path. A plane
    /// that contributes admin verbs ([`Self::admin_routes`] is `Some`) MUST return a non-empty object
    /// here, so the document can never silently omit a mounted verb.
    // Read by the OpenAPI generator and the non-vacuity floor test.
    openapi: Option<fn(&PlaneDecl) -> serde_json::Value>,

    /// RESTORE THIS PLANE'S DURABLE STATE, in order, BEFORE a listener is bound — the plane half of
    /// `busbar_kernel::boot::hydrate_all`. Handed a [`PlaneBootCtx`] whose store surface is `PlaneStore`
    /// and nothing that carries the audit chain, so a hydrate hook can attach the plane's write-through
    /// sinks and read them back but can never touch the append-only chain (invariant (a)). `None` for
    /// a plane with no durable state to restore (the LLM plane). A hook returning `Err` REFUSES BOOT:
    /// `busbar_kernel::boot::hydrate_all` propagates it with `?`, so a plane cannot half-restore and serve.
    hydrate: Option<BootHook>,

    /// START THIS PLANE'S BOOT-TIME WORK, AFTER the listeners are built — the plane half of
    /// `busbar_kernel::boot::start_planes`. Handed the same [`PlaneBootCtx`], now carrying the live app
    /// handle, the shutdown broadcast a spawned loop exits on and the deployment's PUBLIC card-issuer
    /// key (never its seed). Since verify-on-call replaced the background sweep, the built-in start
    /// hooks no longer spawn a reverify loop — the MCP plane has no start hook at all, and the A2A one
    /// only resolves and publishes its per-agent card transports. `None` for a plane that starts
    /// nothing. A hook returning `Err` REFUSES BOOT — an outbound identity that does not resolve is a
    /// startup failure, never a warning — so `busbar_kernel::boot::start_planes` propagates it with `?`.
    start: Option<BootHook>,

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
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    config_validate:
        Option<fn(&PlaneDecl, name: &str, def: &serde_json::Value) -> Result<(), String>>,

    /// PROJECT THIS PLANE'S NAMED-DEFINITION REGISTRATIONS onto the shared read view — the plane half
    /// of the generic `GET /api/v1/admin/<section>` list, so `admin::v1::service` reads a plane's
    /// registrations without naming the plane's config or view types. Returns the empty vec for a
    /// plane with no live registry this generation. `None` for a plane whose section is not a
    /// named-definition map (the LLM plane; `proto`).
    ///
    /// Handed the neutral [`crate::plane_driver::slots::PlaneSlots`] seam (NOT `&App`), so a plane crate reads
    /// its own per-generation runtime object off the snapshot without the callback naming a core type;
    /// an in-core plane (A2A) recovers its snapshot through the seam's `as_any` hatch.
    // Read only through the admin named-def surface, which the two plane sections drive; with neither
    // plane compiled in nothing resolves a decl to call it, so the field is genuinely unread there.
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    named_def_list:
        Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots) -> Vec<crate::api::NamedDefView>>,

    /// PROJECT ONE NAMED-DEFINITION REGISTRATION by name onto the shared read view — the single-entry
    /// twin of [`Self::named_def_list`], the plane half of `GET /api/v1/admin/<section>/{name}`.
    /// `None` (the fn returns `None`) when the plane has no entry by that name; the FIELD is `None` for
    /// a plane with no named-definition map. Handed the same neutral [`crate::plane_driver::slots::PlaneSlots`]
    /// seam as [`Self::named_def_list`].
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    named_def_get:
        Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots, &str) -> Option<crate::api::NamedDefView>>,

    /// IS `name` A LIVE REGISTRATION on this plane's effective snapshot — the read-side membership
    /// check the admin write path consults so it names no plane registry type. `None` for a plane with
    /// no named-definition map.
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    registry_contains: Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots, &str) -> bool>,

    /// RE-RESOLVE THIS PLANE'S PER-REGISTRATION HOOK GATES against the next snapshot — the plane half
    /// of the config-swap gate rebuild. Reads the plane's own registry off the `&mut App` and writes
    /// its own gate field back, so `admin::v1::service::reresolve_plane_gates` names no plane registry
    /// type. `None` for a plane with no per-registration hook gates (the LLM plane).
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    reresolve_gates: Option<fn(&PlaneDecl, &mut dyn crate::plane_driver::slots::ContainerGateSink)>,

    /// STATE THIS PLANE'S ADMIN COMPONENT SCHEMAS for the OpenAPI document — the plane half of the
    /// schema pass in `busbar_core_admin::v1::json::handlers::openapi_doc`, which inserts the returned
    /// schemas into `#/components/schemas` as written; the `$ref`s naming them are already on the
    /// paths its [`Self::openapi`] fragment inserted. So `handlers` names no `crate::mcp`/`crate::a2a`
    /// view type and the document stays byte-identical. `None` for a plane with no admin verbs (the
    /// LLM plane).
    ///
    /// The hook's shape ([`OpenapiSchemasHook`]) is plain data in every build: the kernel names no
    /// schema generator for it.
    openapi_schemas: Option<OpenapiSchemasHook>,

    /// CARRY THIS PLANE'S ENGINE-OWNED STATE ACROSS A CONFIG SWAP — the plane half of
    /// `busbar_kernel::state::AppHandle::swap`. Run once per swap, AFTER the next snapshot is fully built
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
    on_swap: Option<
        fn(prior: &dyn crate::plane_driver::slots::PlaneSlots, next: &dyn crate::plane_driver::slots::PlaneSlots),
    >,

    /// PARSE THIS PLANE'S TOP-LEVEL REGISTRY SECTION from a positionless `serde_yaml::Value` into its
    /// own typed config, boxed as the neutral [`crate::config::plane_sections::PlaneCfg`] — the seam
    /// `DeployCfg`'s `tools:`/`agents:` field deserializes through, so core names no plane config type.
    /// `None` for a plane with no registry section (the LLM / `proto` planes).
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    parse_section:
        Option<fn(&PlaneDecl, &serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneCfg>, String>>,

    /// PARSE THIS PLANE'S TOP-LEVEL ENDPOINT block (the MCP plane's `mcp:` door) from a positionless
    /// `serde_yaml::Value`, boxed as the neutral [`crate::config::plane_sections::PlaneEndpointCfg`] — the seam
    /// `DeployCfg`'s `mcp:` field deserializes through. `None` for a plane with no endpoint block
    /// (every plane but MCP).
    #[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    parse_endpoint: Option<
        fn(&PlaneDecl, &serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String>,
    >,

    /// LOWER THIS PLANE'S ENDPOINT block into its validated runtime resource, type-erased as
    /// `Arc<dyn Any>` — the seam `config::resolve` derives `RootCfg::mcp` through, so core derives the
    /// validated resource without naming the plane's resource type. An `Err` is collected into the
    /// resolve error list verbatim. `None` for a plane with no endpoint block.
    #[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
    #[allow(clippy::type_complexity)]
    lower_endpoint: Option<
        fn(
            &PlaneDecl,
            &dyn crate::config::plane_sections::PlaneEndpointCfg,
        ) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String>,
    >,

    /// BUILD THIS PLANE'S PER-GENERATION RUNTIME OBJECT from its type-erased registry section — the
    /// seam `appbuild` composes the MCP runtime slot (`plane_slots[runtime_slot_key(<mcp decl key>)]`) through,
    /// so core names no plane runtime type. The first argument is the plane's own section, erased as
    /// `&dyn Any` (its `PlaneCfg::as_any`); `prior` is the previous generation's snapshot for
    /// carry-over, read through the neutral [`crate::plane_driver::slots::PlaneSlots`] seam (NOT `&App`).
    /// `None` for a plane whose runtime is not carried through this seam (A2A's lives in `plane_slots`
    /// under its decl key; the LLM plane's is the many `App` fields it already reads).
    #[allow(clippy::type_complexity)]
    build_runtime: Option<
        fn(
            &dyn std::any::Any,
            prior: Option<&dyn crate::plane_driver::slots::PlaneSlots>,
        ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,

    /// PROJECT THIS PLANE'S PER-GENERATION RUNTIME SLOT into the NEUTRAL [`crate::plane_driver::route_tables::EngineTablesView`]
    /// read seam — the cold/scrape-path viewer the core-resident `/metrics`, `/v1/models` and telemetry
    /// label readers reach a data-plane's routing tables through WITHOUT naming the plane's concrete
    /// `Lane`/`WeightedLane`/runtime type. The argument is the plane's own runtime object (the value
    /// `build_runtime` inserted into `plane_slots[runtime_slot_key(<decl key>)]`), erased as `&dyn Any`;
    /// the plane downcasts it to its own runtime type inside the plane crate and returns a borrow as the
    /// substrate trait object. Core's [`crate::plane_driver::slots::PlaneSlots`]-driven `engine_tables_view` calls
    /// this at most once per scrape/discovery read and falls back to the substrate-resident
    /// [`crate::plane_driver::route_tables::EMPTY_VIEW`] when the plane contributed no runtime slot (the zero-plane binary).
    /// `None` for a plane whose runtime exposes no routing tables (MCP/A2A: they contribute no
    /// `EngineTablesView`); the LLM plane sets it once its `NativeRuntime` lives in the retired engine crate.
    #[allow(clippy::type_complexity)]
    viewer:
        Option<fn(&(dyn std::any::Any + Send + Sync)) -> &dyn crate::plane_driver::route_tables::EngineTablesView>,

    /// PRUNE THIS PLANE'S VERIFY-ON-CALL COALESCING STATE to the subjects the freshly-built generation
    /// still fronts — the seam `appbuild` runs after building the `App`, so the carried per-subject
    /// flights/latches do not leak one dead entry per removed registration. `None` for a plane with no
    /// verify-on-call gate (the LLM / `proto` planes).
    retain_verify_gates: Option<fn(&dyn crate::plane_driver::slots::PlaneSlots)>,

    /// THIS PLANE'S EMPTY REGISTRY SECTION, boxed as the neutral [`crate::config::plane_sections::PlaneCfg`] —
    /// the value `DeployCfg`'s `#[serde(default)]` `tools:`/`agents:` field takes when the section is
    /// ABSENT, so the default is the plane's own `Default` (byte-identical to the pre-seam
    /// `ToolsCfg::default()`) rather than a re-parse of an empty document. `None` for a plane with no
    /// registry section (the LLM / `proto` planes).
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    default_section: Option<fn(&PlaneDecl) -> Box<dyn crate::config::plane_sections::PlaneCfg>>,

    /// MERGE ONE PROVIDER'S CATALOG DEFINITION (`providers.yaml`, [`crate::config::providers::ProviderDef`])
    /// WITH ITS OPERATOR DEPLOYMENT (`config.yaml`'s `providers:` entry,
    /// [`crate::config::providers::ProviderDeploy`]) INTO THE RESOLVED
    /// [`crate::config::providers::ResolvedProvider`] a lane is built from — the providers/models/pools
    /// LOGIC seam (1.6.0 pools stage-B). `busbar_kernel::config::resolve` calls this at the EXACT point
    /// the per-deployment merge always ran (right after the catalog lookup, itself unconditional core
    /// orchestration — "provider referenced but not found in providers.yaml" stays a core error), so
    /// the merged fields and their precedence (deployment override wins, catalog default otherwise)
    /// are byte-identical to the pre-seam inline merge. Pure — no I/O, no `errors` side channel, so it
    /// cannot itself reorder or add a validation error.
    ///
    /// `providers`/`pools` are `CORE_OWNED_CONCRETE_SECTIONS` and are NEVER evicted from
    /// `DeployCfg`/`RootCfg` (see that constant's doc) — unlike `tools:`/`agents:`/`mcp:`, a
    /// `providers:` entry is parsed and merged UNCONDITIONALLY, whether or not any plane is
    /// installed. So `None` (no plane implements the hook — an llm-plane-absent build) is not an
    /// "absent config section" refusal the way it is for a container plane's endpoint block: `resolve`
    /// falls back to its OWN byte-identical copy of this same merge, so a build compiled without the
    /// LLM plane keeps merging providers exactly as every prior release has, rather than silently
    /// dropping configured providers out of `RootCfg::providers`.
    #[allow(clippy::type_complexity)]
    resolve_provider: Option<
        fn(
            &crate::config::providers::ProviderDef,
            &crate::config::providers::ProviderDeploy,
        ) -> crate::config::providers::ResolvedProvider,
    >,
}
