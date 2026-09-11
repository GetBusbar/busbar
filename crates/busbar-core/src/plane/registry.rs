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
//! ## Where the list went
//!
//! The declaration LIST — which planes exist, by key, section and scope kind, in canonical layering
//! order, with the same-key-skipped and install-before-first-read invariants — is contract DATA now:
//! `busbar_contract::plane::registry`, written once by the composition root
//! (`crates/busbar/src/root/plane_install.rs`) and read by every layer, this one included. What a
//! plane DOES for a key — the [`PlaneDecl`] row of fn-pointer seams — is the substrate's behaviour
//! table, looked up by that key. This file keeps what is core-live: [`BootCtx`] and
//! [`build_dispatch`].
//!

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

/// THE BUILT-IN ROWS of core's OWN test binary — the shipped process plane list, whose rows name
/// `busbar_{llm,mcp,a2a}::PLANE_DECL` and therefore live in `registry_tests`, a `tests/` file the
/// neutral-purity lint excludes. Production carries NO built-in rows. Reading the rows installs them
/// (idempotent): a reader that consulted them without handing them over would be reading a second
/// answer to which planes exist.
#[cfg(test)]
pub(crate) fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    registry_tests::seeded::seed();
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

// ── THE PLANE LIST AND THE BEHAVIOUR TABLE ──────────────────────────────────────────────────────
// Core OWNS neither. Which planes exist is contract DATA (`busbar_contract::plane::registry`); what
// a plane DOES is the substrate's behaviour table, keyed by the same key. The names are bound HERE
// once, for one reason: core's own `cfg(test)` binary carries built-in rows that must be installed
// before the first read and has no bootstrap to do it — so under `cfg(not(test))` these are `use`s
// (no core copy) and under `cfg(test)` the `registry_tests::seeded` shim that installs, then delegates.
#[cfg(not(test))]
pub(crate) use list::{
    plane_decl_for, plane_decl_for_config_section, plane_decls, plane_key_at, plane_key_index,
    scope_kind_at,
};
#[cfg(test)]
pub(crate) use registry_tests::seeded::{
    behaviour_for, behaviour_for_config_section, plane_behaviours, plane_decl_for,
    plane_decl_for_config_section, plane_decls, plane_key_at, plane_key_index, scope_kind_at,
};
#[cfg(not(test))]
pub(crate) use table::{behaviour_for, behaviour_for_config_section, plane_behaviours};

// ── THE CONTRACT LIST, AS CORE READS IT ──────────────────────────────────────────────────────────
/// THE PLANE LIST'S READERS, passed straight through to the contract — with ONE thing done first
/// under `test-support`, and it is a thing the frozen substrate would otherwise have to do.
///
/// A plane's test-kit registers its behaviour row with `busbar_substrate::plane::registry`'s growable
/// test set. That set is a SOURCE of declarations, and the contract list has a slot for exactly that
/// (`install_late_registration_source`) — but the substrate cannot bind it: binding means building a
/// `PlaneDeclaration` from a row, and the substrate is FROZEN this release. So core binds it, at the
/// one place every core read of the list goes through, idempotently (the contract keeps the first
/// source bound). Without this a `test-support` binary sees a plane in the BEHAVIOUR table and not in
/// the LIST, and `plane_behaviours()` — which iterates the list — hands back nothing.
///
/// Under a production build `bind_late` is empty and every function here is one call: a production
/// binary has no late registration source, by design.
#[cfg(not(test))]
pub(crate) mod list {
    pub(crate) use busbar_contract::plane::registry::PlaneDeclaration;

    /// Bind the substrate's test registration set as the contract list's late source. Idempotent.
    #[cfg(feature = "test-support")]
    fn bind_late() {
        busbar_contract::plane::registry::install_late_registration_source(|| {
            busbar_substrate::plane::registry::test_registered_planes()
                .into_iter()
                .map(super::table::declaration_of)
                .collect()
        });
    }
    /// Nothing to bind: a production binary has no late registration source, by design.
    #[cfg(not(feature = "test-support"))]
    #[inline(always)]
    fn bind_late() {}

    pub(crate) fn plane_decls() -> &'static [PlaneDeclaration] {
        bind_late();
        busbar_contract::plane::registry::plane_decls()
    }
    pub(crate) fn plane_decl_for(key: &str) -> Option<&'static PlaneDeclaration> {
        bind_late();
        busbar_contract::plane::registry::plane_decl_for(key)
    }
    pub(crate) fn plane_decl_for_config_section(
        section: &str,
    ) -> Option<&'static PlaneDeclaration> {
        bind_late();
        busbar_contract::plane::registry::plane_decl_for_config_section(section)
    }
    pub(crate) fn plane_key_index(key: &str) -> u8 {
        bind_late();
        busbar_contract::plane::registry::plane_key_index(key)
    }
    pub(crate) fn plane_key_at(idx: u8) -> Option<&'static str> {
        bind_late();
        busbar_contract::plane::registry::plane_key_at(idx)
    }
    pub(crate) fn scope_kind_at(idx: u32) -> Option<&'static str> {
        bind_late();
        busbar_contract::plane::registry::scope_kind_at(idx)
    }
}

// ── THE BEHAVIOUR TABLE ──────────────────────────────────────────────────────────────────────────
/// WHAT EACH PLANE DOES, looked up by the key the contract list names — the rows the composition
/// root installed and the rows a test binary compiled in as built-ins. WHICH keys exist, in what
/// order, is the contract list's answer; this table only says what each key does.
///
/// WHY IT IS HERE AND NOT IN `busbar-substrate`, where the `PlaneDecl` row type lives: the substrate
/// is FROZEN this release — a deletion or a spelling retarget only — and a lookup table is neither.
/// It is here, in the crate that is being deleted, because it is glue that dies with the crate:
/// `busbar-core`'s dissolution takes the table with it, at which point the root writes the rows
/// wherever their type then lives. Putting it in the substrate would have bought "core owns nothing"
/// for ~125 lines added to a frozen crate and a `legacy-reach` rise, which is a worse trade than
/// naming this as the residue it is.
///
/// Core OWNS no fact here. Every DATA field on a row (`config_section`, `scope_kinds`,
/// `subject_noun`, `admin_noun`, `audit_kind`, `card_signing_domain`, `card_kid_prefix`,
/// `owned_config_sections`, `fallback`) is read from the CONTRACT list; `key` is the join column and
/// is the one data field still read off a row. What this table hands back is the fn-pointer seams.
pub(crate) mod table {
    use super::PlaneDecl;

    /// ONE PLANE, BOTH HALVES — the facts it states and the behaviour a layer runs for it, paired by
    /// the composition root (the only crate that may name both of a plane's crates).
    pub type PlaneRow = (
        &'static busbar_contract::plane::PlaneDeclaration,
        &'static PlaneDecl,
    );

    /// The rows the composition root installed, AS PAIRS. First write wins, following the contract
    /// slot, which is the one that REFUSES a second install.
    ///
    /// Pairs rather than a projected row list for a reason a ratchet made visible: projecting would
    /// mean building a new `Vec` and leaking it to get `'static` back, and `hold-escapes` counts a
    /// deliberate leak in production source as what it is. Storing what the root already owns leaks
    /// nothing, so this file has no escape at all and its `known_sites` entry is struck.
    static INSTALLED: std::sync::OnceLock<&'static [PlaneRow]> = std::sync::OnceLock::new();

    /// THE BUILT-IN ROWS a test binary installs. A test-support seam: production carries no built-in
    /// rows and has no installer for this slot, by design — every plane is installed by the
    /// composition root through the contract slot and [`install_plane_behaviours`].
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) mod builtins {
        use super::PlaneDecl;

        static ROWS: std::sync::OnceLock<&'static [&'static PlaneDecl]> =
            std::sync::OnceLock::new();

        /// Record a test binary's built-in rows. Idempotent by first write, like the contract's.
        pub(crate) fn install_builtin_behaviours(decls: &'static [&'static PlaneDecl]) {
            let _ = ROWS.set(decls);
        }

        /// The rows, or the empty set before any install.
        pub(super) fn rows() -> &'static [&'static PlaneDecl] {
            ROWS.get().copied().unwrap_or(&[])
        }
    }

    /// RECORD THE COMPOSITION ROOT'S ROWS.
    pub fn install_plane_behaviours(rows: &'static [PlaneRow]) {
        let _ = INSTALLED.set(rows);
    }

    /// THE BEHAVIOUR ROW for a plane key: installed copy first, then a late test registration, then
    /// the built-in row — the contract fold's own precedence — or `None` for a key no source
    /// declares.
    pub(crate) fn behaviour_for(key: &str) -> Option<&'static PlaneDecl> {
        let installed = INSTALLED.get().copied().unwrap_or(&[]);
        let installed = installed.iter().map(|(_, row)| *row);
        #[cfg(any(test, feature = "test-support"))]
        let (late, built_in) = (
            busbar_substrate::plane::registry::test_registered_planes(),
            builtins::rows(),
        );
        #[cfg(not(any(test, feature = "test-support")))]
        let (late, built_in): (Vec<&'static PlaneDecl>, &[&'static PlaneDecl]) = (Vec::new(), &[]);
        installed
            .chain(late.iter().copied())
            .chain(built_in.iter().copied())
            .find(|d| d.key == key)
    }

    /// THE BEHAVIOUR ROW for the plane that owns a config section, resolved through the CONTRACT
    /// list (which decides which plane owns the section) and then this table (which says what it
    /// does).
    pub(crate) fn behaviour_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
        super::plane_decl_for_config_section(section).and_then(|d| behaviour_for(d.key))
    }

    /// EVERY BEHAVIOUR ROW, in the CONTRACT list's canonical order — the iteration a boot fold or a
    /// surface merge runs over. A key the contract lists but no row backs is skipped; the two are
    /// fed by the same installer, so that is a wiring bug and not a runtime state.
    pub(crate) fn plane_behaviours() -> Vec<&'static PlaneDecl> {
        super::plane_decls()
            .iter()
            .filter_map(|d| behaviour_for(d.key))
            .collect()
    }

    /// THE TEN DATA FACTS a behaviour row still carries, as the contract's declaration.
    ///
    /// TRANSITIONAL, and `cfg(test)` so production cannot reach it: the four shipped planes declare
    /// their own `PLANE_DECLARATION` in their pure `busbar-plane-*` half and the composition root
    /// installs THOSE, so in a production binary a `PlaneDecl`'s data fields are written and never
    /// read. This function exists only for core's OWN test built-ins, which are core-local fixtures
    /// with no pure half to declare from. It dies with the fields, in SUB-1.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn declaration_of(
        d: &PlaneDecl,
    ) -> busbar_contract::plane::registry::PlaneDeclaration {
        busbar_contract::plane::registry::PlaneDeclaration {
            key: d.key,
            fallback: d.fallback,
            config_section: d.config_section,
            scope_kinds: d.scope_kinds,
            subject_noun: d.subject_noun,
            admin_noun: d.admin_noun,
            audit_kind: d.audit_kind,
            card_signing_domain: d.card_signing_domain,
            card_kid_prefix: d.card_kid_prefix,
            owned_config_sections: d.owned_config_sections,
            operator_routes: &[],
        }
    }
}

/// RECORD THE COMPOSITION ROOT'S BEHAVIOUR ROWS — re-exported at the module root so the root's
/// installer names one path beside the contract's `install`.
pub use table::{install_plane_behaviours, PlaneRow};

/// TEST-SUPPORT SEAM — register an extracted plane's declaration; the substrate's, re-exported so
/// core's own test-support callers keep one stable path.
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
pub(crate) mod registry_tests;
