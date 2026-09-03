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
//! The plane axis had not had that done to it. [`super::Plane`] is a CLOSED ENUM with six
//! `match self` tables hanging off it (`key`, `config_section`, `scope_kinds`, `subject_noun`,
//! `audit_kind`, `wire_format_names`), and an enum is the same object as a match: a plane that is
//! not one of the three variants cannot exist, no matter who links what. `git grep PlaneDecl`
//! returned nothing before this file. That is the whole reason the A2A extraction could not
//! proceed the way the anthropic control did — A2A has no `ProtocolDecl` and appears in no
//! `BUILTIN_DECLS`, because A2A is not a protocol, it is a PLANE.
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
//! * **ONE SOURCE PER FACT.** [`super::Plane`]'s accessors now READ their decl rather than matching.
//!   The enum survives as the in-core NAME for the three built-in planes (it is a `Copy` key in
//!   dispatch tables); what it no longer is, is the place the facts live.
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

// S4b: the NEUTRAL PLANE-REGISTRY SURFACE — `PlaneDecl` (the plane vocabulary/seam declaration), the
// `BuildCtx` its `build` reads, the neutral `PlaneBootCtx` boot-context trait + its `RestoredSummary`
// return, and the `BootHook` alias — relocated into `busbar-substrate` so an extracted plane crate
// constructs its own `PlaneDecl` and names every seam type without a path back to core. Re-exported
// HERE at their old paths so the population glue below, the built-in `PLANE_DECL`s and every in-core
// caller (`busbar_core::plane::registry::{PlaneDecl, BuildCtx, RestoredSummary}`) resolve unchanged.
// What did NOT move: the glue (it names `super::Plane`/`PlaneDispatch`/the built-in statics, all
// core-live) and `BootCtx` (its phase fields hold the core-live `App`/`AppHandle`) — `BootCtx` stays
// here and IMPLEMENTS the neutral `PlaneBootCtx` so a plane hook reads it without naming `App`.
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
/// the borrow they replaced) so this struct is `'static` and an in-core plane twin (A2A) can recover
/// it through [`PlaneBootCtx::as_any`] to reach those fields.
pub struct BootCtx {
    /// The PLANE-NARROWED durable store — task / mcp-call / demotion / spent methods only, never the
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
    pub(crate) fn for_hydrate(
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
    pub(crate) fn for_start(
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

    /// ATTACH THE MCP PLANE'S DURABLE WRITE-THROUGH SINKS — the spent-approval ledger and the
    /// upstream-demotion record — to the plane-narrowed store, in the hydrate phase. Named HERE, core
    /// side, so `crate::mcp::mcp_hydrate` attaches them without its own code naming an `App` field:
    /// the sink fields (`spent_token_ledger`, `demotion_record`) are core-owned and the store is the
    /// core `PlaneStore`, so neither crosses the plane seam. A no-op unless BOTH the freshly-built app
    /// (hydrate phase) and a configured store are present — byte-identical to the old inline
    /// `app.spent_token_ledger.set_sink(store.clone()); app.demotion_record.set_sink(store)`.
    fn attach_mcp_durable_sinks(&self) {
        if let (Some(app), Some(store)) = (self.app.as_ref(), &self.store) {
            app.spent_token_ledger.set_sink(store.clone());
            app.demotion_record.set_sink(store.clone());
        }
    }

    /// REGISTER THE MCP PLANE'S DURABLE `call` STREAM with the host, in the hydrate phase — the first
    /// boot step of the per-call log, before the rehydrate. Named HERE, core side, so
    /// `crate::mcp::mcp_hydrate` registers the stream without its own code naming
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

    /// REHYDRATE THE MCP PLANE'S DURABLE `call` CHAIN from the plane-narrowed store, in the hydrate
    /// phase — the boot rehydrate, run AFTER [`Self::register_call_stream`]. Returns the NEUTRAL
    /// [`RestoredSummary`] rather than the core-live `calllog::Restored` (which carries
    /// `audit::ChainBreak`), so the hook logs the outcome without naming a core-live type. The
    /// `with_dispatch_scope`/`HostCtx` mint stays wholly inside `calllog::restore_from_store_over`
    /// (minted synchronously, never across an `.await`). The `Err` is mapped to the store error's
    /// Display string so the hook's `MCP_CALLLOG_UNREAD` warning reads byte-identically. A no-op-shaped
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
    /// HERE so `crate::mcp::mcp_hydrate` mints its host without naming `crate::plane_host::engine_host`
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

    /// THE PLANE-NARROWED DURABLE STORE, or `None` under `store: memory` — the generic handle the A2A
    /// plane drives its own task-set boot (sink attach + rehydrate) off, so no A2A boot logic lives in
    /// this core seam. Just clones the phase-carried `Option<Arc<dyn PlaneStore>>`.
    fn plane_store(
        &self,
    ) -> Option<std::sync::Arc<dyn busbar_substrate::plane::store::PlaneStore>> {
        self.store.clone()
    }

    /// THE RECOVERY HATCH for an in-core plane twin (A2A). `BootCtx` is `'static` (its `app`/`handle`
    /// `Arc`s are owned), so a hook handed the neutral `&dyn PlaneBootCtx` downcasts back to the
    /// concrete `BootCtx` here to reach the phase fields (`app`, `handle`, `card_issuer`) that name
    /// core-live types. An extracted plane (MCP) never calls this.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
impl BootCtx {
    /// A ctx carrying no phase context, for the boot-hook FOLD tests (R2-boot): a hook that only
    /// returns `Err` — or a `None`-hook plane — reads nothing off it.
    pub(crate) fn stub() -> BootCtx {
        BootCtx {
            store: None,
            app: None,
            handle: None,
            card_issuer: None,
        }
    }
}

/// THE BUILT-INS — one line per plane, and every line is DATA.
///
/// This is the whole of core's knowledge of which planes exist. Each row is a reference to a
/// declaration that lives in the plane's OWN module beside the code it describes, which is what
/// makes the row — rather than a table of strings — the thing that leaves with the plane.
///
/// Order is the operator-visible LAYERING order, unchanged from `Plane::ALL`.
/// Production carries NO built-in plane rows: every plane is a plugin the composition root installs
/// through [`install_planes`]. Naming a plane crate's `PLANE_DECL` here would be a plane-crate symbol
/// reference in neutral source — a side channel around the ABI — so this stays empty.
///
/// Core's OWN test binary still needs the shipped `[llm, mcp, a2a]` process list (the plane crates are
/// dev-dependencies there), but that list names `busbar_{llm,mcp,a2a}::PLANE_DECL`, which belongs OFF
/// the neutral source. It is therefore defined in the test module (`registry_tests`, a `tests/` file
/// the neutral-purity lint excludes) and reached ONLY through [`builtin_plane_decls`]. An EXTERNAL
/// `test-support` consumer (the plane suites, core's integration target) has `cfg(test)` false and
/// registers through [`register_test_plane`] from each plane's `testkit`.
#[cfg(not(test))]
static BUILTIN_PLANE_DECLS: &[&PlaneDecl] = &[];

/// The built-in declarations. Read by [`plane_decls`] to build the process list, and by the
/// registry's own tests to build a list with ONE MORE declaration in it — which is the whole of what
/// a loader will do differently. Empty in production and under `test-support`; under core's own
/// `#[cfg(test)]` binary it is the test-module list, so no plane crate is named in neutral source.
#[cfg(not(test))]
pub(crate) fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    BUILTIN_PLANE_DECLS
}

#[cfg(test)]
pub(crate) fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    registry_tests::TEST_BUILTIN_PLANE_DECLS
}

/// THE MCP PLANE'S DEFAULT per-generation runtime, type-erased — the object core's `cfg(test)` fixture
/// seeds under the MCP runtime-slot companion for every `TestApp` (the plane is a built-in of core's
/// own test process). Delegates to the `tests/registry_tests.rs` helper, the one `tests/`-file the
/// neutral-purity lint excludes, so the `busbar_mcp` name that builds it stays OFF this neutral source.
#[cfg(test)]
pub(crate) fn default_mcp_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    registry_tests::default_mcp_test_runtime()
}

/// The process plane list, folded on first read from the built-ins plus anything installed. Under the
/// test-support surface `plane_decls` folds a growable test registration set instead (see below), so
/// this memo is the production path only.
#[cfg(not(any(test, feature = "test-support")))]
static PLANES: std::sync::OnceLock<Vec<&'static PlaneDecl>> = std::sync::OnceLock::new();

/// Declarations the COMPOSITION ROOT installed before the plane list was first read.
static INSTALLED: std::sync::OnceLock<&'static [&'static PlaneDecl]> = std::sync::OnceLock::new();

/// INSTALL PLANE DECLARATIONS — the composition root's one write into the plane axis, and the seam
/// an extracted plane crate registers through. Exactly `crate::proto::registry::install_protocols`'
/// shape and contract, on the plane axis. `pub`, not `pub(crate)`: the `busbar` binary crate is the
/// composition root and calls this from `main` (`register_planes`), before any config load or
/// validation touches a plane.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the plane list was first read: see the module header's INSTALL BEFORE FIRST
///   READ invariant.
pub fn install_planes(decls: &'static [&'static PlaneDecl]) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_planes called twice: there is one composition root, and it registers once"
    );
    // The "install before first read" invariant is enforced by the production memo.
    #[cfg(not(any(test, feature = "test-support")))]
    assert!(
        PLANES.get().is_none(),
        "install_planes called after the plane list was first read; register in main before any \
         config load or validation touches a plane"
    );
    // Under the test-support surface `plane_decls` re-folds on every read (no frozen `PLANES` memo),
    // so the FIRST-READ witness is `TEST_MEMO` being populated instead: it is set the first time the
    // process plane list is folded, so a non-empty memo means a layer has already resolved against the
    // built-ins-only set — the same invariant the production `PLANES` memo enforces, spelled on the
    // structure that stands in for it here.
    #[cfg(any(test, feature = "test-support"))]
    assert!(
        TEST_MEMO.lock().unwrap().is_none(),
        "install_planes called after the plane list was first read; register in main before any \
         config load or validation touches a plane"
    );
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per KEY, later same-key
/// registrations skipped audibly. Split from [`plane_decls`]' `OnceLock` so its order and skip
/// semantics are a function a test can drive — the process singleton can only ever be initialised
/// once per test binary, which would leave these rules provable only by booting binaries.
pub(crate) fn merged_boot_plane_decls(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static PlaneDecl> {
    let mut decls: Vec<&'static PlaneDecl> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.key == d.key) {
            tracing::info!(
                plane = d.key,
                "skipping a later registration of an already-declared plane (composition-root copy \
                 and built-in copy of one plane)"
            );
            continue;
        }
        decls.push(d);
    }
    // NORMALISE TO CANONICAL LAYERING ORDER. The dedup above still runs installed-first, so the
    // composition-root copy still wins a same-key collision; this only reorders the SURVIVORS so an
    // extracted plane (installed) lands in the same slot its built-in copy held — a stable sort, so
    // any plane outside the canonical list keeps its relative fold position at the tail.
    //
    // The canonical order is DATA, not a hard-coded token list: it is the order each plane KEY first
    // appears across the built-in rows then the installed ones. In production the built-in rows
    // compile out and the composition root installs the planes in layering order, so that install
    // order IS the canonical order; under the test / test-support surface the built-in rows supply
    // it. Either way core names no plane token here — the order leaves with the decls.
    let canonical = canonical_key_order(installed, builtins);
    let rank = |key: &str| {
        canonical
            .iter()
            .position(|k| *k == key)
            .unwrap_or(canonical.len())
    };
    decls.sort_by_key(|d| rank(d.key));
    // REGISTER EACH PLANE'S SCOPE KINDS with the neutral `busbar_api` scope-kind wire registry, so a
    // `VirtualKey` grant of a plane's kind (`mcp_server`, …) serializes to its `allowed_{kind}s` wire
    // field instead of failing the write. The kind strings are DATA off each `PlaneDecl.scope_kinds`
    // — core names no plane vocabulary here. Idempotent, so re-folding under the test surface is safe.
    for d in &decls {
        for kind in d.scope_kinds {
            busbar_api::register_scope_kind(kind);
        }
    }
    // PLANE-OWNED-CONFIG DUP-CLAIM GUARD (1.6.0 config-seam, stage 1). Refuse the boot if two planes
    // claim the same top-level config section, or if a plane claims a section core STILL owns
    // concretely (`CORE_OWNED_CONCRETE_SECTIONS`) — the invariant that makes the later section moves
    // safe. In stage 1 every `owned_config_sections` is empty, so this is unconditionally `Ok(())` and
    // adds no behaviour; it exists so the FIRST move that mis-claims a section fails at boot, loudly,
    // rather than silently double-declaring the grammar. A panic (not a `Result`) because a mis-wired
    // composition root is a build bug, not an operator error to recover from — same disposition as the
    // `install_planes`-twice / read-before-install asserts above.
    if let Err(refusal) =
        crate::plane::registry::check_owned_config_claims(&decls, CORE_OWNED_CONCRETE_SECTIONS)
    {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    decls
}

/// THE TOP-LEVEL CONFIG SECTIONS CORE STILL OWNS CONCRETELY as fields of
/// [`crate::config::DeployCfg`] — the reserved set the plane-owned-config dup-claim guard
/// ([`crate::plane::registry::check_owned_config_claims`]) refuses a plane from claiming until the
/// section is actually evicted from core in the SAME change.
///
/// STAGE 1 lists all five: `providers`/`models`/`pools`/`rate_card`/`limits` are all concrete today.
/// As the LATER stages move a section into its owning plane crate, that stage DELETES the section's
/// key from this list in lockstep with adding it to the plane's `owned_config_sections` — the two
/// edits are one change, so at no instant is a section either owned by nobody or claimed by two. Per
/// the reconciled-audit scope, `pools` and `providers` stay neutral in core and are NEVER removed
/// here; only `rate_card`, `limits` and `models`-capabilities are evictable in later stages.
pub(crate) const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

/// THE OPERATOR-VISIBLE LAYERING ORDER of the planes, by key — the order `config_sections` reports
/// and a cross-plane refusal names sections in — DERIVED FROM REGISTRATION DATA rather than a
/// hard-coded token list. It is the order each plane key FIRST APPEARS across the built-in rows then
/// the installed ones, deduped. The built-in rows (a plane's own `&PLANE_DECL`, `#[cfg(test)]`) fix
/// the canonical positions under the test/test-support surface; in production the built-ins compile
/// out and the composition root installs the planes in layering order, so the install order IS the
/// canonical order. Core spells no `"llm"/"mcp"/"a2a"` here — the order leaves with the decls.
///
/// `merged_boot_plane_decls` sorts its survivors by each key's index in this list (tail for a key not
/// present — an unknown/registered-later plane sorts stably after the canonical set rather than
/// jumping the queue), so the position is a property of the plane, not of whether it shipped as a
/// built-in or an installed crate.
fn canonical_key_order(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    for d in builtins.iter().chain(installed) {
        if !order.contains(&d.key) {
            order.push(d.key);
        }
    }
    order
}

/// The process plane list, in fold order. One acquire-load once initialised.
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) fn plane_decls() -> &'static [&'static PlaneDecl] {
    PLANES.get_or_init(|| {
        let installed = INSTALLED.get().copied().unwrap_or(&[]);
        merged_boot_plane_decls(installed, builtin_plane_decls())
    })
}

// ── TEST-SUPPORT PLANE REGISTRATION ──────────────────────────────────────────────────────────────
// The extracted plane crates can't be hard-coded into `BUILTIN_PLANE_DECLS` (core cannot name them),
// so under the test-support surface each plane's `testkit` REGISTERS its `&'static PlaneDecl` through
// the NEUTRAL seam [`busbar_substrate::plane::registry::register_test_plane`] — the storage lives on
// the substrate so a plane crate names no `busbar_core::` implementation to register itself, exactly
// as production's composition root `install_planes`. `plane_decls()` folds the registered set ahead of
// the built-ins on every read, recomputing (and leaking once) only when the set GROWS — so a plane
// registered by any test before it reads the list is visible regardless of test order, and the
// `&'static` contract holds. Bounded: at most one leak per distinct plane (≤ the plane count).
// Keyed on the PAIR `(installed_len, registered_len)`, not their sum: a set that GREW `installed` by
// one while `register_test_plane`'s set SHRANK by one (the isolation guard's snapshot/restore) sums to
// the same total but folds to a different list, and a lone sum would alias the two and hand back a
// stale leak. The pair distinguishes them for the price of one extra `usize`.
/// The memo entry: the `(installed_len, registered_len)` key the fold was last computed for, and the
/// leaked slice it produced.
#[cfg(any(test, feature = "test-support"))]
type TestMemoEntry = ((usize, usize), &'static [&'static PlaneDecl]);
#[cfg(any(test, feature = "test-support"))]
static TEST_MEMO: std::sync::Mutex<Option<TestMemoEntry>> = std::sync::Mutex::new(None);

/// TEST-SUPPORT SEAM — register an extracted plane's declaration into the process registry. Re-exported
/// from the neutral substrate ([`busbar_substrate::plane::registry::register_test_plane`], which owns
/// the storage) so core's own test-support callers keep one stable path; the plane crates call the
/// substrate function directly.
#[cfg(any(test, feature = "test-support"))]
pub use busbar_substrate::plane::registry::register_test_plane;

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn plane_decls() -> &'static [&'static PlaneDecl] {
    let reg = busbar_substrate::plane::registry::test_registered_planes();
    let installed = INSTALLED.get().copied().unwrap_or(&[]);
    let want = (installed.len(), reg.len());
    let mut memo = TEST_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((n, slice)) = *memo {
        if n == want {
            return slice;
        }
    }
    // Fold explicit `install_planes` registrations (registry's own tests) AND `register_test_plane`
    // registrations ahead of the built-ins, then leak ONCE for this (grown) set.
    let mut all: Vec<&'static PlaneDecl> = installed.to_vec();
    all.extend(reg.iter().copied());
    let merged = merged_boot_plane_decls(&all, builtin_plane_decls());
    let leaked: &'static [&'static PlaneDecl] = Box::leak(merged.into_boxed_slice());
    *memo = Some((want, leaked));
    leaked
}

/// THE ABI PLANE-KEY (the registration INDEX) for a plane's stable decl `key`, or `u8::MAX` when no
/// registered plane owns it — the opaque numeric handle the FFI PODs carry across the C-ABI seam,
/// resolved back to the key string via [`plane_key_at`]. This is the "registration index → key"
/// assignment the plane ABI keys on, in place of a hard-coded `0`/`1` numbering: core spells no plane
/// token; the number is only a position in the process registry.
pub(crate) fn plane_key_index(key: &str) -> u8 {
    plane_decls()
        .iter()
        .position(|d| d.key == key)
        .map_or(u8::MAX, |i| i as u8)
}

/// THE SCOPE-KIND at ABI scope-kind index `idx`, DERIVED FROM REGISTRY DATA rather than a hard-coded
/// table. Index `0` is core's neutral admission-pool topology (`"pool"`, the kind every deployment
/// always has); indices `1..` are each installed plane's declared `PlaneDecl.scope_kinds` in
/// registration order — the same order a plane encodes when it stamps a `TargetRef.scope_kind`. So a
/// host entitlement slot resolves the opaque numeric kind to its string without core spelling any
/// plane's kind token. `None` (fail-closed) for an index past the registered kinds.
///
/// The index is a bijection over the DISTINCT kinds, base first: a plane that also declares the
/// neutral base kind (the LLM plane grants over `"pool"`, which `busbar_api` already treats as the
/// unconditional `BUILTIN_POOL_KIND`) must NOT re-count it. Without this dedup the base `"pool"` and
/// the LLM decl's `"pool"` would occupy indices 0 AND 1, shifting every later plane's kind up by one
/// so a `pool` grant would wrongly resolve an `mcp_server` target (entitlement escalation). Folding a
/// re-declared base onto its existing index 0 keeps each grant target mapped to the RIGHT plane's kind.
pub(crate) fn scope_kind_at(idx: u32) -> Option<&'static str> {
    // `"pool"` is the neutral base kind (not a plane token); the plane kinds follow it as data,
    // de-duplicated in first-seen order so a re-declared base does not create a phantom index.
    let mut seen: Vec<&'static str> = Vec::new();
    std::iter::once("pool")
        .chain(
            plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
        .filter(|k| {
            let fresh = !seen.contains(k);
            if fresh {
                seen.push(k);
            }
            fresh
        })
        .nth(idx as usize)
}

/// THE ABI SCOPE-KIND INDEX for a kind string — the exact INVERSE of [`scope_kind_at`], sharing its
/// first-seen dedup so the two can never skew. Any encoder that must stamp a `TargetRef.scope_kind`
/// routes through here rather than re-deriving the numbering, which is what keeps the pool↛mcp_server
/// entitlement escalation closed: if the encode side and the [`scope_kind_at`] decode side computed
/// the base-first dedup independently they could drift, and a `pool` grant could resolve an
/// `mcp_server` target. Fail-closed (`None`) for a kind no registered plane declares.
pub(crate) fn scope_kind_index(kind: &str) -> Option<u32> {
    // The identical sequence `scope_kind_at` indexes: the neutral base kind first, then each plane's
    // declared kinds, de-duplicated in first-seen order. `position` over it is the inverse of `nth`.
    let mut seen: Vec<&'static str> = Vec::new();
    std::iter::once("pool")
        .chain(
            plane_decls()
                .iter()
                .flat_map(|d| d.scope_kinds.iter().copied()),
        )
        .filter(|k| {
            let fresh = !seen.contains(k);
            if fresh {
                seen.push(k);
            }
            fresh
        })
        .position(|k| k == kind)
        .map(|i| i as u32)
}

/// The stable decl `key` of the plane at ABI registration index `idx`, or `None` when out of range —
/// the inverse of [`plane_key_index`], so a host vtable slot that received the opaque numeric handle
/// resolves it back to the key string it looks its gate set / `ingress_protocol` label up by, naming
/// no plane token.
pub(crate) fn plane_key_at(idx: u8) -> Option<&'static str> {
    plane_decls().get(idx as usize).map(|d| d.key)
}

/// RESOLVE A PLANE DECLARATION BY KEY. Allocates nothing.
///
/// NAMED FOR ITS AXIS, not `decl_for`. `structure-lint.sh`'s declaration census holds
/// `fn decl_for(` to EXACTLY ONE production occurrence — "there is exactly ONE by-name protocol
/// resolution in busbar, and a second one is a second answer to which protocols exist". That rule
/// is right and is not weakened to make room for this: plane resolution is a different axis and
/// says so in its name, so the census keeps meaning what it means.
pub(crate) fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.key == key)
}

/// RESOLVE A PLANE DECLARATION BY ITS CONFIG SECTION, against the PROCESS list — the neutral bridge
/// the named-definition write path and the config parse/lower path cross to reach a plane's hooks
/// without naming the plane. Resolves through [`plane_decls`] (installed + built-ins, canonically
/// ordered) rather than the built-ins alone, so an EXTRACTED plane the composition root installed
/// (the MCP plane after B2) is found on the same footing as a still-built-in one.
pub(crate) fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
    plane_decls()
        .iter()
        .copied()
        .find(|d| d.config_section == section)
}

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
pub(crate) fn build_dispatch(
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
