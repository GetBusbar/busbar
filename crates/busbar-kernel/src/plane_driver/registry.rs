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
//! [`BootCtx`] whose store surface is [`PlaneStore`](crate::store::plane_view::PlaneStore) and never the
//! audit-carrying `Store` (invariant (a)). This file is the proof that the control's mechanism
//! transfers to the plane axis — the vocabulary half, joined by the slot half, the surface half and
//! the boot half — and the honest measure of how much of the plane problem is covered.

// S4b: the NEUTRAL PLANE-REGISTRY SURFACE — `PlaneDecl` (the plane vocabulary/seam declaration), the
// `BuildCtx` its `build` reads, the neutral `PlaneBootCtx` boot-context trait and the
// `BootHook` alias — relocated into `busbar-substrate` so an extracted plane crate
// constructs its own `PlaneDecl` and names every seam type without a path back to core. Re-exported
// HERE at their old paths so the population glue below, the built-in `PLANE_DECL`s and every in-core
// caller (`busbar_kernel::plane_driver::registry::{PlaneDecl, BuildCtx}`) resolve unchanged.
// What did NOT move: the glue (it names `PlaneDispatch`/the built-in statics, all
// core-live) and `BootCtx` (its phase fields hold the core-live `App`/`AppHandle`) — `BootCtx` stays
// here and IMPLEMENTS the neutral `PlaneBootCtx` so a plane hook reads it without naming `App`.

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

    /// HYDRATE phase — the freshly-built `App` a hydrate hook restores its durable state into (the
    /// kernel's trust record is attached by `boot::hydrate_all` itself). `None` in the start
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

    /// MINT THE NEUTRAL ENGINE HOST over the freshly-built app, in the hydrate phase — the
    /// snapshot-only mint a hydrate hook drives its durable boot-replay off (no live handle yet at
    /// hydration, which is correct: hydration reads exactly the generation it is restoring into). Named
    /// HERE so a plane's own hydrate hook mints its host without naming `crate::plane_driver::engine_host`
    /// or an `App`: the returned `Arc<dyn EngineHost>` is the neutral substrate seam and the app it
    /// wraps is the core-owned hydrate-phase `App`.
    fn engine_host(&self) -> std::sync::Arc<dyn busbar_kernel::plane_driver::EngineHost> {
        // PHASE-AWARE: the hydrate phase supplies the freshly-built `app` and mints a SNAPSHOT-ONLY
        // host over it (no live handle yet, which is correct — hydration reads exactly the
        // generation it restores into); the start phase supplies the live `handle` and mints a host
        // over its current load (`from_handle`), byte-identical to the old start hook's
        // `handle.load()`-driven reads. Exactly one of the two is present per phase.
        if let Some(handle) = self.handle.as_ref() {
            crate::plane_driver::engine_host_from_handle(handle)
        } else {
            let app = self.app.as_ref().expect(
                "engine_host runs in the HYDRATE phase (app) or the START phase (handle); one is present",
            );
            crate::plane_driver::engine_host(app)
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

/// THE BUILT-INS — one line per plane, and every line is DATA.
///
/// This is the whole of core's knowledge of which planes exist. Each row is a reference to a
/// declaration that lives in the plane's OWN module beside the code it describes, which is what
/// makes the row — rather than a table of strings — the thing that leaves with the plane.
///
/// Order is the operator-visible LAYERING order, unchanged from `Plane::ALL`.
/// Production carries NO built-in plane rows: every plane is a plugin the composition root installs
/// through [`install_planes`]. Naming a plane crate's `PLANE_DECLARATION` here would be a plane-crate symbol
/// reference in neutral source — a side channel around the ABI — so this stays empty.
///
/// Core's OWN `#[cfg(test)]` unit-test binary carries NO built-in plane rows either — same as
/// production and `test-support` (the A6/HostCtx dev-dependency-cycle cleanup dropped the
/// `registry_tests`-backed `#[cfg(test)]` special case, which named the three plane crates' real
/// `PLANE_DECL`s directly and only type-checked by accepting a SECOND, distinct `busbar_kernel`
/// instance in the dependency graph). A test that needs the shipped `[llm, mcp, a2a]` roster
/// registers it explicitly (`register_test_plane` from each plane's `testkit`) — exactly the posture
/// an EXTERNAL `test-support` consumer (the plane suites, `tests/*.rs` here) already used, and now
/// the ONLY posture, so this neutral source names no plane crate under any build surface.
static BUILTIN_PLANE_DECLS: &[&PlaneDecl] = &[];

/// The built-in declarations. Read by [`plane_decls`]. Always empty — see [`BUILTIN_PLANE_DECLS`].
pub fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    BUILTIN_PLANE_DECLS
}

/// ONE PLANE'S DEFAULT per-generation runtime, type-erased — historically the object core's OWN
/// `#[cfg(test)]` fixture seeded under the MCP plane's runtime-slot companion for every `TestApp`,
/// back when the MCP plane was an automatic built-in there (see [`BUILTIN_PLANE_DECLS`]). With no
/// plane auto-registered under `cfg(test)` any more, [`plane_decl_for_config_section`] finds no
/// `tools:`-owning plane and this is never actually reached — kept only so the (now dead-at-runtime)
/// call chain in `test_support::TestApp::build` still compiles; a test that wants a plane's real
/// runtime seeded registers that plane itself and installs its runtime
/// (`TestApp::install_plane_runtime`), exactly as an external `test-support` consumer already did.
#[cfg(test)]
pub fn default_section_plane_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    std::sync::Arc::new(())
}

/// The process plane list: null until first read, then the fold of the built-ins plus anything
/// installed ([`plane_decls`]), or a list [`publish_planes`] set. Every pointer stored here comes from
/// `Box::leak` and is never freed or written through, so a reader holds it for `'static`.
static PLANES: std::sync::atomic::AtomicPtr<&'static [&'static PlaneDecl]> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// The list behind a non-null [`PLANES`] pointer.
#[allow(unsafe_code)]
fn planes_at(ptr: *mut &'static [&'static PlaneDecl]) -> &'static [&'static PlaneDecl] {
    // SAFETY: `ptr` is non-null and was stored in `PLANES` from `Box::leak`, which is never freed
    // or mutated; the Acquire load that read it pairs with the Release/AcqRel store that wrote it.
    unsafe { *ptr }
}

/// Declarations the COMPOSITION ROOT installed before the plane list was first read.
static INSTALLED: std::sync::OnceLock<&'static [&'static PlaneDecl]> = std::sync::OnceLock::new();

/// INSTALL PLANE DECLARATIONS — the composition root's one write into the plane axis, and the seam
/// an extracted plane crate registers through. Exactly `crate::proto::registry::install_protocols`'
/// shape and contract, on the plane axis. `pub`, not `pub`: the `busbar` binary crate is the
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
    assert!(
        PLANES.load(std::sync::atomic::Ordering::Acquire).is_null(),
        "install_planes called after the plane list was first read; register in main before any \
         config load or validation touches a plane"
    );
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per KEY, later same-key
/// registrations skipped audibly. Split from [`plane_decls`]' `OnceLock` so its order and skip
/// semantics are a function a test can drive — the process singleton can only ever be initialised
/// once per test binary, which would leave these rules provable only by booting binaries.
pub fn merged_boot_plane_decls(
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
    decls.sort_by_key(|d| {
        canonical
            .iter()
            .position(|k| *k == d.key)
            .unwrap_or(canonical.len())
    });
    // PLANE-OWNED-CONFIG DUP-CLAIM GUARD (1.6.0 config-seam, stage 1). Refuse the boot if two planes
    // claim the same top-level config section, or if a plane claims a section core STILL owns
    // concretely (`CORE_OWNED_CONCRETE_SECTIONS`) — the invariant that makes the later section moves
    // safe. In stage 1 every `owned_config_sections` is empty, so this is unconditionally `Ok(())` and
    // adds no behaviour; it exists so the FIRST move that mis-claims a section fails at boot, loudly,
    // rather than silently double-declaring the grammar. A panic (not a `Result`) because a mis-wired
    // composition root is a build bug, not an operator error to recover from — same disposition as the
    // `install_planes`-twice / read-before-install asserts above.
    let declared: Vec<&PlaneDeclaration> = decls.iter().map(|d| &d.declaration).collect();
    if let Err(refusal) = check_owned_config_claims(&declared, CORE_OWNED_CONCRETE_SECTIONS) {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    decls
}

/// THE TOP-LEVEL CONFIG SECTIONS CORE STILL OWNS CONCRETELY as fields of
/// [`crate::config::DeployCfg`] — the reserved set the plane-owned-config dup-claim guard
/// ([`crate::plane_driver::registry::check_owned_config_claims`]) refuses a plane from claiming until the
/// section is actually evicted from core in the SAME change.
///
/// STAGE 1 lists all five: `providers`/`models`/`pools`/`rate_card`/`limits` are all concrete today.
/// As the LATER stages move a section into its owning plane crate, that stage DELETES the section's
/// key from this list in lockstep with adding it to the plane's `owned_config_sections` — the two
/// edits are one change, so at no instant is a section either owned by nobody or claimed by two. Per
/// the reconciled-audit scope, `pools` and `providers` stay neutral in core and are NEVER removed
/// here; only `rate_card`, `limits` and `models`-capabilities are evictable in later stages.
pub const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

/// THE OPERATOR-VISIBLE LAYERING ORDER of the planes, by key — the order `config_sections` reports
/// and a cross-plane refusal names sections in — DERIVED FROM REGISTRATION DATA rather than a
/// hard-coded token list. It is the order each plane key FIRST APPEARS across the built-in rows then
/// the installed ones, deduped. The built-in rows (a plane's own registry row, `#[cfg(test)]`) fix
/// the canonical positions under the test/test-support surface; in production the built-ins compile
/// out and the composition root installs the planes in layering order, so the install order IS the
/// canonical order. Core spells no specific plane's key here — the order leaves with the decls.
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

/// The process plane list, in fold order. One acquire-load once set.
pub fn plane_decls() -> &'static [&'static PlaneDecl] {
    use std::sync::atomic::Ordering;
    let ptr = PLANES.load(Ordering::Acquire);
    if !ptr.is_null() {
        return planes_at(ptr);
    }
    let installed = INSTALLED.get().copied().unwrap_or(&[]);
    let folded: &'static [&'static PlaneDecl] =
        Box::leak(merged_boot_plane_decls(installed, builtin_plane_decls()).into_boxed_slice());
    let fresh: *mut &'static [&'static PlaneDecl] = Box::leak(Box::new(folded));
    match PLANES.compare_exchange(
        std::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => planes_at(fresh),
        // Another reader (or a publish) set the list first: that one stands.
        Err(set) => planes_at(set),
    }
}

/// Set the process plane list to the fold of the installed declarations plus `registered` (ahead of
/// the built-ins), replacing any list set before. The composition root never calls this: it installs
/// once through [`install_planes`]. A test binary that registers planes as it goes publishes each
/// registration set through it.
#[doc(hidden)]
pub fn publish_planes(registered: &[&'static PlaneDecl]) {
    let mut all: Vec<&'static PlaneDecl> = INSTALLED.get().copied().unwrap_or(&[]).to_vec();
    all.extend_from_slice(registered);
    let folded: &'static [&'static PlaneDecl] =
        Box::leak(merged_boot_plane_decls(&all, builtin_plane_decls()).into_boxed_slice());
    PLANES.store(
        Box::leak(Box::new(folded)),
        std::sync::atomic::Ordering::Release,
    );
}

/// THE SCOPE-KIND at ABI scope-kind index `idx`, DERIVED FROM REGISTRY DATA rather than a hard-coded
/// table. Index `0` is core's neutral admission-pool topology (`"pool"`, the kind every deployment
/// always has); indices `1..` are each installed plane's declared `PlaneDecl.scope_kinds` in
/// registration order — the same order a plane encodes when it stamps a `TargetRef.scope_kind`. So a
/// host entitlement slot resolves the opaque numeric kind to its string without core spelling any
/// plane's kind token. `None` (fail-closed) for an index past the registered kinds.
///
/// The index is a bijection over the DISTINCT kinds, base first: a plane that also declares the
/// neutral base kind (one plane grants over `"pool"`, which `busbar_contract` already treats as the
/// unconditional `BUILTIN_POOL_KIND`) must NOT re-count it. Without this dedup the base `"pool"` and
/// that plane's own `"pool"` declaration would occupy indices 0 AND 1, shifting every later plane's
/// kind up by one so a `pool` grant would wrongly resolve a different plane's scope kind (entitlement
/// escalation). Folding a re-declared base onto its existing index 0 keeps each grant target mapped to
/// the RIGHT plane's kind.
pub fn scope_kind_at(idx: u32) -> Option<&'static str> {
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
/// routes through here rather than re-deriving the numbering, which is what keeps the base-kind
/// entitlement escalation closed: if the encode side and the [`scope_kind_at`] decode side computed
/// the base-first dedup independently they could drift, and a `pool` grant could resolve a
/// different plane's scope-kind target. Fail-closed (`None`) for a kind no registered plane declares.
pub fn scope_kind_index(kind: &str) -> Option<u32> {
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

/// RESOLVE A PLANE DECLARATION BY KEY. Allocates nothing.
///
/// NAMED FOR ITS AXIS, not `decl_for`. the `structure-lint` gate's declaration census holds
/// `fn decl_for(` to EXACTLY ONE production occurrence — "there is exactly ONE by-name protocol
/// resolution in busbar, and a second one is a second answer to which protocols exist". That rule
/// is right and is not weakened to make room for this: plane resolution is a different axis and
/// says so in its name, so the census keeps meaning what it means.
pub fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.key == key)
}

/// RESOLVE A PLANE DECLARATION BY ITS CONFIG SECTION, against the PROCESS list — the neutral bridge
/// the named-definition write path and the config parse/lower path cross to reach a plane's hooks
/// without naming the plane. Resolves through [`plane_decls`] (installed + built-ins, canonically
/// ordered) rather than the built-ins alone, so an EXTRACTED plane the composition root installed
/// is found on the same footing as a still-built-in one.
pub fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
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
///   mounted, so [`super::dispatch::PlaneDispatch::admission_for`] resolves an audience on it. A path a plane
///   answers on but omits here is unreachable through this table's audience check — which is why the
///   claim set, not the router, is the thing a test pins.
/// - **R2 (mounted ⇒ admitted, or boot refuses):** a plane that claims a path but has no admission
///   path would serve an unauthenticated resource. That is refused here with a named error rather
///   than mounted, so a future plane cannot lower its own bar to nothing by omitting an admission.
///   A claim is ADMITTED by an audience the plane binds, or — for a plane served through its door
///   ([`crate::plane_driver::door::is_door`]) — by the kernel's key-verify chain (`key_chain`: the data chain
///   verifies the busbar key), which admits a door claim exactly as it admits any data-plane path.
///   A door claim with neither is refused, as any plane's is.
pub fn build_dispatch(
    decls: &[&'static PlaneDecl],
    slots: &std::collections::BTreeMap<&'static str, &dyn std::any::Any>,
    key_chain: bool,
) -> Result<super::dispatch::PlaneDispatch, String> {
    let mut dispatch = super::dispatch::PlaneDispatch::default();
    for decl in decls {
        // A plane the operator did not configure has no runtime object, mounts nothing, and binds
        // no audience — skipped, exactly as the old `if let Some(..)` guards skipped it.
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        let admission = (decl.admission)(slot);
        // R2: a claimed path with no admission path is a door with no lock. Refuse the boot.
        let key_admitted = key_chain && crate::plane_driver::door::is_door(decl);
        if !claims.is_empty() && admission.is_none() && !key_admitted {
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

// `registry_tests` MOVED to `crates/busbar/tests/registry_cross_plane.rs` (the A6/HostCtx dev-dependency-cycle
// cleanup): most of it drove the REAL the retired engine crate/`busbar_mcp` and agent-engine `PLANE_DECL`s and their
// real runtime objects, which only type-checks with ONE `busbar_kernel` in the graph — an
// integration-test target, never this `#[cfg(test)]` unit module. See that file's header. The two
// `#[cfg(test)]` seams it used to reach through (`builtin_plane_decls`, `default_section_plane_test_runtime`
// below) now behave identically under `cfg(test)` and under the external `test-support` surface: an
// EMPTY built-in set unless a test explicitly registers (`register_test_plane`) — the posture the
// module doc below already described for external consumers.

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
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
/// a `busbar_kernel` type; core re-exports it at `busbar_kernel::plane_driver::registry::CardIssuer` so every
/// in-core caller (`governance::state`, the A2A plane's own card slot) resolves unchanged.
#[derive(Clone)]
pub struct CardIssuer {
    pub kid: String,
    pub issuer_spki_base64: String,
}

/// THE NEUTRAL BOOT-CONTEXT SEAM a plane's [`PlaneDecl::hydrate`] / [`PlaneDecl::start`] hook reads,
/// implemented core-side by `busbar_kernel::plane_driver::registry::BootCtx` — so an extracted plane crate
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
    fn engine_host(&self) -> std::sync::Arc<dyn crate::plane_driver::EngineHost>;

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
        pub struct PlaneDecl {
            /// The facts the plane states about itself — contract data.
            pub declaration: PlaneDeclaration, $($(#[$m])* pub $f: $t,)*
        }

        impl PlaneDecl {
            /// JOIN a plane's contract declaration and its behaviour into the registry row.
            pub const fn assemble(declaration: PlaneDeclaration, hooks: PlaneHooks) -> PlaneDecl {
                PlaneDecl { declaration, $($f: hooks.$f,)* }
            }
        }
    };
}

/// The shape of [`PlaneDecl::openapi_schemas`]: the schema pass over the two SHARED generators and
/// the `paths` map. With `openapi-schema` off nothing generates a document and no plane can supply
/// one, so the type collapses to an uncallable fn and `schemars` is named nowhere.
#[cfg(feature = "openapi-schema")]
pub type OpenapiSchemasHook = fn(
    &mut schemars::SchemaGenerator,
    &mut schemars::SchemaGenerator,
    &mut serde_json::Map<String, serde_json::Value>,
);
/// See the `openapi-schema` twin: uncallable, because no document is generated in this build.
#[cfg(not(feature = "openapi-schema"))]
pub type OpenapiSchemasHook = fn(std::convert::Infallible);

/// THE SCHEMAS HOOK OF THE DOOR PLANE AT `I` (ARCHITECT Q2): the `components.schemas` its admin
/// OpenAPI blob states ([`crate::plane_driver::door::stated_schemas`]), inserted into the generator's
/// definitions as written. `None` in a build that generates no document.
#[cfg(feature = "openapi-schema")]
pub(crate) const fn stated_schemas_hook<const I: usize>() -> Option<OpenapiSchemasHook> {
    Some(stated_schemas::<I>)
}

/// See the `openapi-schema` twin: no document is generated in this build.
#[cfg(not(feature = "openapi-schema"))]
pub(crate) const fn stated_schemas_hook<const I: usize>() -> Option<OpenapiSchemasHook> {
    None
}

#[cfg(feature = "openapi-schema")]
fn stated_schemas<const I: usize>(
    schema_gen: &mut schemars::SchemaGenerator,
    _req_gen: &mut schemars::SchemaGenerator,
    _paths: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(schemas) = crate::plane_driver::door::stated_schemas::<I>() {
        schema_gen.definitions_mut().extend(schemas);
    }
}

impl std::ops::Deref for PlaneDecl {
    type Target = PlaneDeclaration;
    fn deref(&self) -> &PlaneDeclaration {
        &self.declaration
    }
}

plane_behaviour! {
    /// The distinct WIRE FORMATS this plane translates between, named. A FUNCTION rather than a
    /// slice for exactly one reason, and it is the reason the field is worth its indirection: the
    /// LLM plane's answer is `busbar_kernel::ingress::protocols::known_protocols` — read off the live protocol
    /// registry, so a seventh dialect does not depend on anybody remembering to bump a literal here.
    /// A plane whose list is constant returns a `&'static` slice and pays nothing.
    ///
    /// `Plane::wire_formats` stays DERIVED from this list.
    wire_format_names: fn() -> &'static [&'static str],

    /// THE DIALECTS A PROVIDER'S `protocol` MAY NAME, of those this plane speaks, in its order
    /// (ARCHITECT ruling 2026-10-16, item 3; BUSBAR-1.6.0.md #49: declared data). A door plane's
    /// are the dialects its tail's `dialect_auth` lines flag `DIALECT_PROVIDER`. The boot accepts a
    /// provider whose `protocol` some registered plane lists here, and its refusal lists them all.
    provider_dialects: fn() -> &'static [&'static str],

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
    admission: fn(&dyn std::any::Any) -> Option<super::dispatch::PlaneAdmission>,

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
    build: fn(&BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

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
    admin_routes: Option<fn(&dyn std::any::Any) -> Vec<crate::admin_verbs::AdminRouteSpec>>,

    /// CONTRIBUTE THE PLANE'S OpenAPI PATH FRAGMENT — a JSON object whose keys are the ABSOLUTE admin
    /// paths this plane's verbs answer on and whose values are the OpenAPI path items. Merged into the
    /// admin document in declaration order. `None` for a plane that contributes no admin path. A plane
    /// that contributes admin verbs ([`Self::admin_routes`] is `Some`) MUST return a non-empty object
    /// here, so the document can never silently omit a mounted verb.
    // Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test; a
    // default `--no-default-features` build has neither, so the field is genuinely unread there.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    openapi: Option<fn() -> serde_json::Value>,

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
    #[allow(clippy::type_complexity)]
    config_validate: Option<fn(name: &str, def: &serde_json::Value) -> Result<(), String>>,

    /// PROJECT THIS PLANE'S NAMED-DEFINITION REGISTRATIONS onto the shared read view — the plane half
    /// of the generic `GET /api/v1/admin/<section>` list, so `admin::v1::service` reads a plane's
    /// registrations without naming the plane's config or view types. Returns the empty vec for a
    /// plane with no live registry this generation. `None` for a plane whose section is not a
    /// named-definition map (the LLM plane; `proto`).
    ///
    /// Handed the neutral [`crate::plane_driver::slots::PlaneSlots`] seam (NOT `&App`), so a plane crate reads
    /// its own per-generation runtime object off the snapshot without the callback naming a core type;
    /// an in-core plane (A2A) recovers its snapshot through the seam's `as_any` hatch.
    #[allow(clippy::type_complexity)]
    named_def_list:
        Option<fn(&dyn crate::plane_driver::slots::PlaneSlots) -> Vec<crate::api::NamedDefView>>,

    /// PROJECT ONE NAMED-DEFINITION REGISTRATION by name onto the shared read view — the single-entry
    /// twin of [`Self::named_def_list`], the plane half of `GET /api/v1/admin/<section>/{name}`.
    /// `None` (the fn returns `None`) when the plane has no entry by that name; the FIELD is `None` for
    /// a plane with no named-definition map. Handed the same neutral [`crate::plane_driver::slots::PlaneSlots`]
    /// seam as [`Self::named_def_list`].
    #[allow(clippy::type_complexity)]
    named_def_get:
        Option<fn(&dyn crate::plane_driver::slots::PlaneSlots, &str) -> Option<crate::api::NamedDefView>>,

    /// IS `name` A LIVE REGISTRATION on this plane's effective snapshot — the read-side membership
    /// check the admin write path consults so it names no plane registry type. `None` for a plane with
    /// no named-definition map.
    #[allow(clippy::type_complexity)]
    registry_contains: Option<fn(&dyn crate::plane_driver::slots::PlaneSlots, &str) -> bool>,

    /// RE-RESOLVE THIS PLANE'S PER-REGISTRATION HOOK GATES against the next snapshot — the plane half
    /// of the config-swap gate rebuild. Reads the plane's own registry off the `&mut App` and writes
    /// its own gate field back, so `admin::v1::service::reresolve_plane_gates` names no plane registry
    /// type. `None` for a plane with no per-registration hook gates (the LLM plane).
    reresolve_gates: Option<fn(&mut dyn crate::plane_driver::slots::ContainerGateSink)>,

    /// ATTACH THIS PLANE'S ADMIN TRUST-VERB SCHEMAS to the OpenAPI document — the plane half of the
    /// schema pass in `busbar_core_admin::v1::json::handlers::openapi_doc`. Handed the SHARED response
    /// and request [`schemars::SchemaGenerator`]s and the `paths` map, it registers its own view/body
    /// types into `#/components/schemas` and attaches their `$ref`s onto the paths its [`Self::openapi`]
    /// fragment inserted — so `handlers` names no `crate::mcp`/`crate::a2a` view type and the document
    /// stays byte-identical. `None` for a plane with no admin verbs (the LLM plane).
    ///
    /// The FIELD is unconditional and only its type ([`OpenapiSchemasHook`]) follows the
    /// `openapi-schema` feature, so a plane that supplies `None` builds whichever crate turned the
    /// kernel's feature on.
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
    #[allow(clippy::type_complexity)]
    parse_section:
        Option<fn(&serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneCfg>, String>>,

    /// PARSE THIS PLANE'S TOP-LEVEL ENDPOINT block (the MCP plane's `mcp:` door) from a positionless
    /// `serde_yaml::Value`, boxed as the neutral [`crate::config::plane_sections::PlaneEndpointCfg`] — the seam
    /// `DeployCfg`'s `mcp:` field deserializes through. `None` for a plane with no endpoint block
    /// (every plane but MCP).
    #[allow(clippy::type_complexity)]
    parse_endpoint: Option<
        fn(&serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String>,
    >,

    /// LOWER THIS PLANE'S ENDPOINT block into its validated runtime resource, type-erased as
    /// `Arc<dyn Any>` — the seam `config::resolve` derives `RootCfg::mcp` through, so core derives the
    /// validated resource without naming the plane's resource type. An `Err` is collected into the
    /// resolve error list verbatim. `None` for a plane with no endpoint block.
    #[allow(clippy::type_complexity)]
    lower_endpoint: Option<
        fn(
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
    default_section: Option<fn() -> Box<dyn crate::config::plane_sections::PlaneCfg>>,

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

/// The test registration's former path, which the pinned plane repos' root tests still name; it
/// goes when they are re-pinned onto [`crate::test_support::planes`].
#[cfg(any(test, feature = "test-support"))]
pub use crate::test_support::planes::{register_test_plane, TestRegistryIsolation};

#[cfg(test)]
#[path = "tests/registry_memo_tests.rs"]
mod registry_memo_tests;
