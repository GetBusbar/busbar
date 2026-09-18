// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE REGISTRY — the `proto::registry` seam, for the plane axis.
//!
//! ## Why this exists
//!
//! `proto/registry.rs` made a protocol a DECLARATION: `BUILTIN_DECLS` is DATA, the registry
//! constructor takes an ITERATOR, and `install_protocols` is the composition root's one write, so a
//! protocol that is not in core joins by being handed to the same constructor. Its own header states
//! the correction that makes it worth anything:
//!
//! > **A REGISTRY WHOSE POPULATION IS A `match` IN CORE HAS NOT REMOVED THE MATCH, IT HAS MOVED IT.**
//!
//! The plane axis had not had that done to it. `Plane` USED TO BE a CLOSED ENUM with six
//! `match self` tables hanging off it (`key`, `config_section`, `scope_kinds`, `subject_noun`,
//! `audit_kind`, `wire_format_names`), and an enum is the same object as a match: a plane that was
//! not one of the three variants could not exist, no matter who linked what. `git grep PlaneDecl`
//! returned nothing before this file. That is the whole reason a plane extraction could not
//! proceed the way an earlier protocol extraction did — a plane had no `ProtocolDecl` and appeared in
//! no `BUILTIN_DECLS`, because a plane is not a protocol, it is a PLANE.
//!
//! ## The invariants, and they are deliberately the control's
//!
//! * **CANONICAL LAYERING ORDER, INSTALL-SOURCE-INDEPENDENT.** The plane list is operator-visible in
//!   the same way the protocol list is — it is the order [`super::config::config_sections`] reports,
//!   which is the order a cross-plane refusal names sections in. The fold normalises to the
//!   canonical layering order DERIVED FROM THE REGISTRATION DATA (see [`canonical_key_order`])
//!   regardless of whether a plane arrived as a built-in or as an installed crate, so an extracted
//!   plane keeps the position it has always held rather than shifting to the head or tail on the day
//!   it becomes a crate. See [`merged_boot_plane_decls`].
//! * **SAME KEY REGISTERED TWICE IS SKIPPED, AUDIBLY.** Same reason as the protocol registry: under
//!   `cargo test`'s feature unification a `test-support` build compiles an extracted plane back in
//!   as a built-in while the composition root still installs the crate's own copy. Refusing the
//!   boot would fail builds whose behaviour is identical; admitting both would give two decls one
//!   key. The later copy is skipped with a `tracing::info!`.
//! * **INSTALL BEFORE FIRST READ.** A decl installed after another layer resolved against the
//!   smaller set means two layers of one process disagree about which planes exist. Asserted.
//! * **ONE SOURCE PER FACT.** The plane accessors (`key`, `config_section`, `scope_kinds`,
//!   `subject_noun`, `audit_kind`, `wire_format_names`) now READ their decl rather than matching a
//!   closed enum. The three built-in planes are named by their stable registry KEY — the same
//!   `&'static str` every other plane surface is keyed by — so a match in core is no longer the
//!   place the facts live.
//!
//! ## What this file does NOT yet carry, stated so its absence is not read as a claim
//!
//! [`PlaneDecl`] carries the plane VOCABULARY — the facts core reads to name, section, scope and
//! label a plane — plus, as of [`PlaneDecl::build`], the app-state SLOT seam (how a plane's runtime
//! object for one config generation is constructed and type-erased) and, as of [`PlaneDecl::routes`]
//! / [`PlaneDecl::admin_routes`] / [`PlaneDecl::openapi`], the SURFACE seam: how a plane contributes
//! its data-plane routes, its admin verbs, and its OpenAPI fragment; and, as of
//! [`PlaneDecl::hydrate`] / [`PlaneDecl::start`], the BOOT seam: how a plane restores its durable
//! state before a listener binds and starts its background work after. A plane's boot hooks read a
//! [`BootCtx`] whose store surface is [`PlaneStore`](crate::plane::store::PlaneStore) and never the
//! audit-carrying `Store` (invariant (a)). This file is the proof that the control's mechanism
//! transfers to the plane axis — the vocabulary half, joined by the slot half, the surface half and
//! the boot half — and the honest measure of how much of the plane problem is covered.

// S4b: the NEUTRAL PLANE-REGISTRY VOCABULARY/SEAM — `PlaneDecl`, the `BuildCtx` its `build` reads, the
// neutral `PlaneBootCtx` boot-context trait + its `RestoredSummary` return, and the `BootHook` alias —
// relocated into `busbar-substrate` so an extracted plane crate constructs its own `PlaneDecl` and names
// every seam type without a path back to core. `check_owned_config_claims` (the neutral dup-claim guard)
// rode down with them.
//
// S1 (1.6.0 deletion-wave keystone): the plane-registry RESOLUTION surface joined them — see the block
// further down. `install_planes`, the boot fold, the process list (`plane_decls`), the built-in
// accessor, the by-key/by-section resolvers and the ABI index codecs all name only `PlaneDecl` +
// `busbar_api`, so they live on the substrate now and are re-exported HERE (or, under `cfg(test)`, wear
// a thin seeding veneer) at their old paths so every in-core caller resolves unchanged.
//
// What STAYS in this file is the population glue that DOES name core-live types: `BootCtx` (its phase
// fields hold the core-live `App`/`AppHandle`) — which IMPLEMENTS the neutral `PlaneBootCtx` so a plane
// hook reads it without naming `App` — and `build_dispatch` (it names `PlaneDispatch`). Both now name the
// moved resolution symbols through the shims below.
pub use busbar_substrate::plane::registry::{
    check_owned_config_claims, BootHook, BuildCtx, CardIssuer, PlaneBootCtx, PlaneDecl,
    RestoredSummary,
};

/// EVERYTHING A PLANE'S BOOT HOOKS ([`PlaneDecl::hydrate`], [`PlaneDecl::start`]) MAY READ, and
/// DELIBERATELY nothing that carries the audit chain, the governance context or the signing seed
/// (invariant (a)). Its surface names [`PlaneStore`](crate::plane::store::PlaneStore) — never
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
    pub store: Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>>,

    /// HYDRATE phase — the freshly-built `App`, off which a hydrate hook attaches its own
    /// write-through sinks (`spent_token_ledger`, `demotion_record`) and restores them. `None` in the start
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
        store: Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>>,
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

    /// ATTACH A PLANE'S DURABLE WRITE-THROUGH SINKS — the spent-approval ledger and the
    /// upstream-demotion record — to the plane-narrowed store, in the hydrate phase. Named HERE, core
    /// side, so the plane's own hydrate hook attaches them without its own code naming an `App` field:
    /// the sink fields (`spent_token_ledger`, `demotion_record`) are core-owned and the store is the
    /// core `PlaneStore`, so neither crosses the plane seam. A no-op unless BOTH the freshly-built app
    /// (hydrate phase) and a configured store are present — byte-identical to the old inline
    /// `app.spent_token_ledger.set_sink(store.clone()); app.demotion_record.set_sink(store)`.
    fn attach_durable_sinks(&self) {
        if let (Some(app), Some(store)) = (self.app.as_ref(), &self.store) {
            app.spent_token_ledger.set_sink(store.clone());
            app.demotion_record.set_sink(store.clone());
        }
    }

    /// REGISTER A PLANE'S DURABLE `call` STREAM with the host, in the hydrate phase — the first
    /// boot step of the per-call log, before the rehydrate. Named HERE, core side, so
    /// the plane's own hydrate hook registers the stream without its own code naming
    /// `crate::calllog` or an `App` field: the `with_dispatch_scope`/`HostCtx` mint the register
    /// does stays wholly inside `calllog::register_call_stream` (minted synchronously, never across an
    /// `.await`), and the app it reads is the core-owned hydrate-phase `App`. A no-op unless the
    /// freshly-built app (hydrate phase) is present — byte-identical to the old inline
    /// `busbar_core::calllog::register_call_stream(app)`.
    fn register_call_stream(&self) {
        if let Some(app) = self.app.as_ref() {
            crate::calllog::register_call_stream(app);
        }
    }

    /// REHYDRATE A PLANE'S DURABLE `call` CHAIN from the plane-narrowed store, in the hydrate
    /// phase — the boot rehydrate, run AFTER [`Self::register_call_stream`]. Returns the NEUTRAL
    /// [`RestoredSummary`] rather than the core-live `calllog::Restored` (which carries
    /// `audit::ChainBreak`), so the hook logs the outcome without naming a core-live type. The
    /// `with_dispatch_scope`/`HostCtx` mint stays wholly inside `calllog::restore_from_store_over`
    /// (minted synchronously, never across an `.await`). The `Err` is mapped to the store error's
    /// Display string so the hook's unread-call-log warning reads byte-identically. A no-op-shaped
    /// panic guards the impossible None-app/None-store hydrate call (the hook reaches here only past its
    /// store guard, in the phase that supplies the app) — byte-identical to the old inline
    /// `busbar_core::calllog::restore_from_store_over(app, store)`.
    fn restore_call_log(&self) -> Result<RestoredSummary, String> {
        let app = self.app.as_ref().expect(
            "restore_call_log runs in the HYDRATE phase, which supplies the freshly-built app",
        );
        let store = self.store.as_ref().expect(
            "restore_call_log runs past the hydrate hook's store guard, so a store is present",
        );
        crate::calllog::restore_from_store_over(app, store.as_ref())
            .map(|r| RestoredSummary {
                principals: r.principals,
                records: r.records,
                empty_chains: r.empty_chains,
                unreadable: r.unreadable,
                chain_breaks: r.chain_breaks.iter().map(|b| b.to_string()).collect(),
            })
            .map_err(|e| e.to_string())
    }

    /// MINT THE NEUTRAL ENGINE HOST over the freshly-built app, in the hydrate phase — the
    /// snapshot-only mint a hydrate hook drives its durable boot-replay off (no live handle yet at
    /// hydration, which is correct: hydration reads exactly the generation it is restoring into). Named
    /// HERE so a plane's own hydrate hook mints its host without naming `crate::plane_host::engine_host`
    /// or an `App`: the returned `Arc<dyn EngineHost>` is the neutral substrate seam and the app it
    /// wraps is the core-owned hydrate-phase `App`.
    fn engine_host(&self) -> std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost> {
        // PHASE-AWARE: the hydrate phase supplies the freshly-built `app` and mints a SNAPSHOT-ONLY host
        // over it (no live handle yet, which is correct — hydration reads exactly the generation it
        // restores into); the start phase supplies the live `handle` and mints a LIVE host from it
        // (`from_handle`, so `plane_slot_live` sees the current generation), byte-identical to the old
        // start hook's `handle.load()`-driven reads. Exactly one of the two is present per phase.
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
    ) -> Option<std::sync::Arc<dyn busbar_substrate::plane::store::PlaneStore>> {
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

#[cfg(test)]
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

// ── THE PLANE-REGISTRY RESOLUTION SURFACE — RELOCATED to `busbar_substrate::plane::registry` (S1) ────
// The Class-A RESOLUTION surface — `install_planes`, the boot fold
// (`merged_boot_plane_decls`/`canonical_key_order`), the process list (`plane_decls`), the built-in
// accessor (`builtin_plane_decls`), the by-key/by-section resolvers and the ABI index codecs — names
// only `PlaneDecl`, `busbar_api` and `busbar-contract`, never a core-live type, so it moved DOWN to the
// neutral substrate beside `PlaneDecl`. Re-exported HERE at the historical
// `busbar_core::plane::registry::…` paths so all ~50 in-core / composition-root / plugin callers compile
// unchanged. The population glue that DOES name core-live types — `BootCtx` (its phase fields borrow
// `App`/`AppHandle`) and `build_dispatch` (names `PlaneDispatch`) — stays in this file, and now names
// the moved symbols through these same shims.
//
// `install_planes`, `merged_boot_plane_decls` and `CORE_OWNED_CONCRETE_SECTIONS` read no process list
// (install is a write; the fold takes explicit args; the const is data), so they are DIRECT re-exports
// in every build. The READ accessors get a `cfg(test)` seeding VENEER (below), which is why they are
// re-exported only under `cfg(not(test))`.
#[cfg(not(test))]
pub use busbar_substrate::plane::registry::{
    builtin_plane_decls, plane_decl_for, plane_decl_for_config_section, plane_decls, plane_key_at,
    plane_key_index, scope_kind_at, scope_kind_index,
};
pub use busbar_substrate::plane::registry::{
    install_planes, merged_boot_plane_decls, CORE_OWNED_CONCRETE_SECTIONS,
};

// ── CORE'S OWN-TEST-BINARY BUILT-IN SEEDING (cfg(test) veneers) ─────────────────────────────────────
// Under core's OWN `#[cfg(test)]` binary the shipped `[llm, mcp, a2a]` plane set is named in the
// `registry_tests` module (a `tests/` file the neutral-purity lint excludes) and handed to the neutral
// substrate registry through its `set_test_builtins` hook as the stable TAIL of the boot fold — exactly
// as the pre-relocation core registry folded `builtin_plane_decls()` under `#[cfg(test)]`. The neutral
// substrate spells no plane crate; it only holds the fn pointer core hands it. Every READ accessor
// SEEDS the hook before it reads, idempotently — self-healing regardless of call order because the
// substrate memoises on a key that includes the built-in tail's length. Under `test-support` WITHOUT
// `cfg(test)` (a plane suite / core's integration target) the veneers are inactive and the hook stays
// unset — those consumers register their planes through `register_test_plane`, needing no core tail.
#[cfg(test)]
fn core_test_builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    registry_tests::TEST_BUILTIN_PLANE_DECLS
}

/// The built-in declarations for core's OWN test binary — the shipped plane set, seeded into the
/// neutral substrate's core-test hook then read back through it, so this file names no plane crate.
#[cfg(test)]
pub fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::builtin_plane_decls()
}

#[cfg(test)]
pub fn plane_decls() -> &'static [&'static PlaneDecl] {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::plane_decls()
}

#[cfg(test)]
pub fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::plane_decl_for(key)
}

#[cfg(test)]
pub fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::plane_decl_for_config_section(section)
}

#[cfg(test)]
pub fn plane_key_index(key: &str) -> u8 {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::plane_key_index(key)
}

#[cfg(test)]
pub fn plane_key_at(idx: u8) -> Option<&'static str> {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::plane_key_at(idx)
}

#[cfg(test)]
pub fn scope_kind_at(idx: u32) -> Option<&'static str> {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::scope_kind_at(idx)
}

#[cfg(test)]
pub fn scope_kind_index(kind: &str) -> Option<u32> {
    busbar_substrate::plane::registry::set_test_builtins(core_test_builtin_plane_decls);
    busbar_substrate::plane::registry::scope_kind_index(kind)
}

/// ONE PLANE'S DEFAULT per-generation runtime, type-erased — the object core's `cfg(test)` fixture
/// seeds under that plane's runtime-slot companion for every `TestApp` (the plane is a built-in of
/// core's own test process). Delegates to the `tests/registry_tests.rs` helper, the one `tests/`-file
/// the neutral-purity lint excludes, so the plane crate's name that builds it stays OFF this neutral
/// source.
#[cfg(test)]
pub fn default_mcp_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    registry_tests::default_mcp_test_runtime()
}

/// TEST-SUPPORT SEAM — register an extracted plane's declaration into the process registry. Re-exported
/// from the neutral substrate ([`busbar_substrate::plane::registry::register_test_plane`], which owns
/// the storage AND the whole resolution surface now) so core's own test-support callers keep one stable
/// path; the plane crates call the substrate function directly.
#[cfg(any(test, feature = "test-support"))]
pub use busbar_substrate::plane::registry::register_test_plane;

/// FOLD THE DISPATCH TABLE from the registered plane declarations and the per-plane runtime objects
/// (`slots`, each type-erased as `&dyn Any` and keyed by plane key). For every decl with a slot this
/// reads the plane's declared claims and admission from its OWN object — the seam that lets a plane
/// crate contribute its door without core naming its type — mounts each claim, and binds the
/// admission.
///
/// Split from `appbuild` and taking its inputs by argument so the admission ratchets are drivable
/// without booting an `App`, exactly as [`merged_boot_plane_decls`] is split from [`plane_decls`].
///
/// # The two security ratchets it enforces
/// - **R1 (every claimed path is audience-checked):** each `(path, wire)` a plane declares is
///   mounted, so [`super::PlaneDispatch::admission_for`] resolves an audience on it. A path a plane
///   answers on but omits here is unreachable through this table's audience check — which is why the
///   claim set, not the router, is the thing a test pins.
/// - **R2 (mounted ⇒ admitted, or boot refuses):** a plane that claims a path but returns no
///   admission would serve an audience-less — hence unauthenticated — resource. That is refused here
///   with a named error rather than mounted, so a future plane cannot lower its own bar to nothing by
///   omitting an admission.
pub fn build_dispatch(
    decls: &[&'static PlaneDecl],
    slots: &std::collections::BTreeMap<&'static str, &dyn std::any::Any>,
) -> Result<super::PlaneDispatch, String> {
    let mut dispatch = super::PlaneDispatch::default();
    for decl in decls {
        // A plane the operator did not configure has no runtime object, mounts nothing, and binds
        // no audience — skipped, exactly as the old `if let Some(..)` guards skipped it.
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        let admission = (decl.admission)(slot);
        // R2: a claimed path with no admission is a door with no lock. Refuse the boot.
        if !claims.is_empty() && admission.is_none() {
            return Err(format!(
                "plane `{}` mounts {} path(s) but bound no admission; a mounted plane must bind an \
                 RFC 8707 audience (see PlaneDispatch::admission_for) or claim no path — serving a \
                 claimed path with no audience admits a token minted for any other resource",
                decl.key,
                claims.len()
            ));
        }
        for (path, wire) in claims {
            dispatch = dispatch.mount_key(decl.key, &path, wire);
        }
        if let Some(admission) = admission {
            dispatch = dispatch.admit_key(decl.key, admission);
        }
    }
    Ok(dispatch)
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;
