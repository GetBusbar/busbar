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
//! * **INSTALLED FOLD AHEAD OF BUILT-INS.** The plane list is operator-visible in the same way the
//!   protocol list is — it is the order [`super::config::config_sections`] reports, which is the
//!   order a cross-plane refusal names sections in. Prepending keeps an extracted plane in the
//!   position it has always held rather than demoting it to the tail on the day it becomes a crate.
//!   See [`merged_boot_plane_decls`].
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
//! object for one config generation is constructed and type-erased) and, as of [`PlaneDecl::mount`]
//! / [`PlaneDecl::admin_routes`] / [`PlaneDecl::openapi`], the SURFACE seam: how a plane contributes
//! its data-plane routes, its admin verbs, and its OpenAPI fragment; and, as of
//! [`PlaneDecl::hydrate`] / [`PlaneDecl::start`], the BOOT seam: how a plane restores its durable
//! state before a listener binds and starts its background work after. A plane's boot hooks read a
//! [`BootCtx`] whose store surface is [`PlaneStore`](crate::plane::store::PlaneStore) and never the
//! audit-carrying `Store` (invariant (a)). This file is the proof that the control's mechanism
//! transfers to the plane axis — the vocabulary half, joined by the slot half, the surface half and
//! the boot half — and the honest measure of how much of the plane problem is covered.

use super::Plane;

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
pub(crate) struct BuildCtx<'a> {
    /// The MCP plane's runtime object for THIS generation, ALREADY built and TYPE-ERASED at config
    /// resolution (`McpResource::from_cfg` ran at `RootCfg` construction) and handed across this seam
    /// as an OPAQUE slot — so the seam names no `crate::mcp` type. The MCP plane's `build` clones this
    /// `Arc` into `plane_slots` unchanged rather than constructing a second one; `None` exactly when
    /// `mcp:` is absent, matching `App::mcp`'s own absence. Erasing at the composition root instead of
    /// in the plane's `build` is what removes the one concrete-type name this struct used to carry
    /// into the eventual MCP extraction — the neutral analogue of how the LLM dialects left core.
    pub(crate) mcp_slot: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    // The A2A registry the A2A plane's `build` lowers. Its type is `crate::a2a`'s and does not exist
    // when the plane is compiled out (`plane-a2a` off); in that build the field carries the neutral
    // raw capture instead — no A2A plane reads it, and no `agents:` section survived resolve.
    #[cfg(feature = "plane-a2a")]
    pub(crate) agent_defs: &'a crate::a2a::config::AgentsCfg,
    #[cfg(not(feature = "plane-a2a"))]
    pub(crate) agent_defs: &'a crate::plane::config::RawPlaneSection,
    pub(crate) public_url: Option<&'a str>,
}

/// A PLANE BOOT HOOK — [`PlaneDecl::hydrate`] or [`PlaneDecl::start`]. Handed the [`BootCtx`] for its
/// phase; an `Err` REFUSES BOOT (the fold propagates it with `?`).
pub(crate) type BootHook = fn(&BootCtx) -> Result<(), String>;

/// BUSBAR'S PUBLISHED CARD-ISSUER KEY, computed core-side and handed to the A2A [`PlaneDecl::start`]
/// hook as PUBLIC values ONLY — the `kid` and the base64 Ed25519 SPKI an operator hands a counterparty
/// out of band to pin busbar by. Deliberately NOT the signer and NOT its seed: a boot hook publishes
/// the public half, it never signs, so no signing material crosses this seam (invariant (a)). This is
/// the plan's "sign-only" preference taken to its limit — there is nothing to sign at boot, so the
/// seam carries strictly the public key rather than even a closure over the secret.
#[derive(Clone)]
pub(crate) struct CardIssuer {
    pub(crate) kid: String,
    pub(crate) issuer_spki_base64: String,
}

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
pub struct BootCtx<'a> {
    /// The PLANE-NARROWED durable store — task / mcp-call / demotion / spent methods only, never the
    /// audit-carrying `Store`. `Some` in the hydrate phase whenever governance configured a store;
    /// `None` in the start phase (a start hook restores nothing).
    pub(crate) store: Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>>,

    /// HYDRATE phase — the freshly-built `App`, off which a hydrate hook attaches its own
    /// write-through sinks (`plane_approvals`, `mcp_demotions`) and restores them. `None` in the start
    /// phase, where the app has been moved into the router builder and only the handle remains.
    pub(crate) app: Option<&'a std::sync::Arc<crate::state::App>>,

    /// START phase — the live app handle a start hook reads THIS config generation off. `None` in the
    /// hydrate phase (no listener yet). There is no `shutdown` broadcast on this seam any more: the
    /// built-in start hooks spawn no background loop now that verify-on-call replaced the sweep, so a
    /// hook has nothing to exit on a shutdown of.
    pub(crate) handle: Option<&'a std::sync::Arc<crate::state::AppHandle>>,

    /// The deployment's PUBLIC card-issuer key (see [`CardIssuer`]). `Some` in the start phase when
    /// this deployment mints one; `None` in the hydrate phase and when no card is signed.
    pub(crate) card_issuer: Option<CardIssuer>,
}

impl<'a> BootCtx<'a> {
    /// THE HYDRATE-PHASE CONTEXT: the plane-narrowed store and the freshly-built app. No listener
    /// exists yet, so there is no handle, no shutdown broadcast and no card-issuer key to publish.
    pub(crate) fn for_hydrate(
        store: Option<std::sync::Arc<dyn crate::plane::store::PlaneStore>>,
        app: &'a std::sync::Arc<crate::state::App>,
    ) -> Self {
        BootCtx {
            store,
            app: Some(app),
            handle: None,
            card_issuer: None,
        }
    }

    /// THE START-PHASE CONTEXT: the live handle and the PUBLIC card-issuer key (computed core-side;
    /// the seed never crosses). A start hook restores nothing, so no store.
    pub(crate) fn for_start(
        handle: &'a std::sync::Arc<crate::state::AppHandle>,
        card_issuer: Option<CardIssuer>,
    ) -> Self {
        BootCtx {
            store: None,
            app: None,
            handle: Some(handle),
            card_issuer,
        }
    }

    /// A ctx carrying no phase context, for the boot-hook FOLD tests (R2-boot): a hook that only
    /// returns `Err` — or a `None`-hook plane — reads nothing off it.
    #[cfg(test)]
    pub(crate) fn stub() -> BootCtx<'static> {
        BootCtx {
            store: None,
            app: None,
            handle: None,
            card_issuer: None,
        }
    }
}

/// EVERYTHING CORE KNOWS ABOUT A PLANE'S VOCABULARY, declared once by the plane itself.
///
/// Every field replaces one arm of one `match self` on [`super::Plane`]. The doc on each says which
/// strings it feeds, because these are the strings that must not agree by coincidence: two planes
/// sharing a scope kind is how one plane's grant admits another plane's traffic, and two planes
/// sharing an audit kind is how one plane's records start answering another plane's question.
///
/// The TYPE is `pub` — the composition root names it in [`install_planes`]' signature, and a private
/// type cannot appear in a public one. Every FIELD stays `pub(crate)`: nothing outside this crate
/// constructs or reads a `PlaneDecl` yet (the binary installs an empty extra slice), so no field is
/// widened until a loaded plane crate actually needs to build one.
pub struct PlaneDecl {
    /// The registry key, the metrics label, the log label and the audit resource prefix.
    /// **OPERATOR-VISIBLE.** Replaces `Plane::key`'s match.
    pub(crate) key: &'static str,

    /// The top-level `config.yaml` section whose mere EXISTENCE declares this plane. Replaces
    /// `Plane::config_section`'s match, and it is this field that
    /// [`super::config::config_sections_from`] folds — so a plane registered from outside core gets
    /// its section into the hook-reference grammar with nothing written for it in core.
    pub(crate) config_section: &'static str,

    /// The `ScopeRef` kinds that grant access ON this plane. A slice because a plane may grant at
    /// more than one granularity (MCP grants a whole server or a single tool). Replaces
    /// `Plane::scope_kinds`' match.
    pub(crate) scope_kinds: &'static [&'static str],

    /// What ONE registration on this plane is called, in the words an operator reads back in a
    /// `404`. Replaces `Plane::subject_noun`'s match.
    pub(crate) subject_noun: &'static str,

    /// The audit RESOURCE KIND for a registration on this plane, and the prefix of every audit
    /// action word the plane's verbs record. Replaces `Plane::audit_kind`'s match.
    pub(crate) audit_kind: &'static str,

    /// The distinct WIRE FORMATS this plane translates between, named. A FUNCTION rather than a
    /// slice for exactly one reason, and it is the reason the field is worth its indirection: the
    /// LLM plane's answer is [`crate::proto::known_protocols`] — read off the live protocol
    /// registry, so a seventh dialect does not depend on anybody remembering to bump a literal here.
    /// A plane whose list is constant returns a `&'static` slice and pays nothing.
    ///
    /// `Plane::wire_formats` and `Plane::has_superset_ir` stay DERIVED from this list's length, so
    /// the superset-IR rule remains a rule rather than a fact about today's planes.
    pub(crate) wire_format_names: fn() -> &'static [&'static str],

    /// THE PATHS THIS PLANE ANSWERS ON, and the wire format each is spoken in, computed from the
    /// plane's own RUNTIME OBJECT (its app slot, type-erased as `&dyn Any`). Every `(path, wire)`
    /// this returns is mounted into [`super::PlaneDispatch`] and — since [`super::PlaneDispatch::admission_for`]
    /// resolves the RFC 8707 audience THROUGH the mount table — becomes a path where a token's `aud`
    /// is checked. A plane that answers on a path it does NOT return here has left a confused-deputy
    /// hole: the door where any resource's token is admitted. So the invariant this list upholds is:
    /// every path a plane answers on is a path it claims here. The A2A
    /// plane returns TWO claims — `/a2a` and the gRPC service `/lf.a2a.v1.A2AService`, whose path a
    /// gRPC client derives from the `.proto` and cannot be pointed elsewhere.
    ///
    /// Returns the empty vec when the plane mounts nothing (a delegation-only A2A deployment, or a
    /// plane the operator did not configure — its slot is then absent and this is not called).
    pub(crate) claims: fn(&dyn std::any::Any) -> Vec<(String, &'static str)>,

    /// THE ADMISSION FACTS this plane binds — the audience a token presented at its door must carry,
    /// and where a refused caller is sent to get one — computed from the same runtime object. `None`
    /// when the plane has no RECEIVING side to admit anyone to (A2A without a `public_url`); a plane
    /// that [`Self::claims`] a path but returns `None` here is refused at boot by
    /// [`build_dispatch`] rather than left serving an unauthenticated resource (ratchet R2).
    pub(crate) admission: fn(&dyn std::any::Any) -> Option<super::PlaneAdmission>,

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
    pub(crate) build: fn(&BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    /// MOUNT THE PLANE'S DATA-PLANE ROUTES onto the shared data router, from the plane's own runtime
    /// object (its app slot, type-erased as `&dyn Any`). `None` for a plane that answers on no data
    /// path (the LLM plane, whose endpoints are the protocol catch-all). Called once per config
    /// generation, only when the plane has a slot to mount from — a plane the operator did not
    /// configure is skipped before this runs, exactly as the old typed-`Option` guards skipped it.
    ///
    /// The signature grants a plane's mount ONLY the router and its own `&dyn Any` slot — never a
    /// `Store`, a `GovCtx`, or an `audit::Chain`. A plane that needs one of those to decide its routes
    /// is not cleanly separable through this seam.
    #[allow(clippy::type_complexity)]
    pub(crate) mount: Option<
        fn(crate::core_routes::CoreRouter, &dyn std::any::Any) -> crate::core_routes::CoreRouter,
    >,

    /// CONTRIBUTE THE PLANE'S ADMIN VERBS to the Admin API v1 router — the operator surface a plane
    /// adds ON TOP of the generic named-definition CRUD (MCP's `connect`/`changes`/`health`, A2A's
    /// `connect`/`approve`). `None` for a plane with no admin verbs. Unconditional (not slot-gated):
    /// the verbs are part of the surface whether or not the plane is configured this generation, so
    /// this takes only the router. Merged in declaration order so the route order is stable and
    /// operator-visible.
    ///
    /// As with [`Self::mount`], the signature grants a plane's admin contribution ONLY the router —
    /// never a `Store`, a `GovCtx`, or an `audit::Chain`.
    #[allow(clippy::type_complexity)]
    pub(crate) admin_routes: Option<
        fn(
            axum::Router<std::sync::Arc<crate::state::AppHandle>>,
        ) -> axum::Router<std::sync::Arc<crate::state::AppHandle>>,
    >,

    /// CONTRIBUTE THE PLANE'S OpenAPI PATH FRAGMENT — a JSON object whose keys are the ABSOLUTE admin
    /// paths this plane's verbs answer on and whose values are the OpenAPI path items. Merged into the
    /// admin document in declaration order. `None` for a plane that contributes no admin path. A plane
    /// that contributes admin verbs ([`Self::admin_routes`] is `Some`) MUST return a non-empty object
    /// here, so the document can never silently omit a mounted verb.
    // Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test; a
    // default `--no-default-features` build has neither, so the field is genuinely unread there.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    pub(crate) openapi: Option<fn() -> serde_json::Value>,

    /// RESTORE THIS PLANE'S DURABLE STATE, in order, BEFORE a listener is bound — the plane half of
    /// [`crate::boot::hydrate_all`]. Handed a [`BootCtx`] whose store surface is [`PlaneStore`] and
    /// nothing that carries the audit chain, so a hydrate hook can attach the plane's write-through
    /// sinks and read them back but can never touch the append-only chain (invariant (a)). `None` for
    /// a plane with no durable state to restore (the LLM plane). A hook returning `Err` REFUSES BOOT:
    /// [`crate::boot::hydrate_all`] propagates it with `?`, so a plane cannot half-restore and serve.
    pub(crate) hydrate: Option<BootHook>,

    /// START THIS PLANE'S BOOT-TIME WORK, AFTER the listeners are built — the plane half of
    /// [`crate::boot::start_planes`]. Handed the same [`BootCtx`], now carrying the live app handle,
    /// the shutdown broadcast a spawned loop exits on and the deployment's PUBLIC card-issuer key
    /// (never its seed). Since verify-on-call replaced the background sweep, the built-in start hooks
    /// no longer spawn a reverify loop — the MCP plane has no start hook at all, and the A2A one only
    /// resolves and publishes its per-agent card transports. `None` for a plane that starts nothing. A
    /// hook returning `Err` REFUSES BOOT — an outbound identity that does not resolve is a startup
    /// failure, never a warning — so [`crate::boot::start_planes`] propagates it with `?`.
    pub(crate) start: Option<BootHook>,

    /// CARRY THIS PLANE'S ENGINE-OWNED STATE ACROSS A CONFIG SWAP — the plane half of
    /// [`crate::state::AppHandle::swap`]. Run once per swap, AFTER the next snapshot is fully built
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
    pub(crate) on_swap: Option<fn(prior: &dyn std::any::Any, next: &dyn std::any::Any)>,
}

/// THE BUILT-INS — one line per plane, and every line is DATA.
///
/// This is the whole of core's knowledge of which planes exist. Each row is a reference to a
/// declaration that lives in the plane's OWN module beside the code it describes, which is what
/// makes the row — rather than a table of strings — the thing that leaves with the plane.
///
/// Order is the operator-visible LAYERING order, unchanged from `Plane::ALL`.
static BUILTIN_PLANE_DECLS: &[&PlaneDecl] = &[
    &crate::proto::PLANE_DECL,
    #[cfg(feature = "plane-mcp")]
    &crate::mcp::PLANE_DECL,
    #[cfg(feature = "plane-a2a")]
    &crate::a2a::PLANE_DECL,
];

/// The built-in declarations. Read by [`plane_decls`] to build the process list, and by the
/// registry's own tests to build a list with ONE MORE declaration in it — which is the whole of what
/// a loader will do differently.
pub(crate) fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    BUILTIN_PLANE_DECLS
}

/// The process plane list, folded on first read from the built-ins plus anything installed.
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
    assert!(
        PLANES.get().is_none(),
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
    decls
}

/// The process plane list, in fold order. One acquire-load once initialised.
pub(crate) fn plane_decls() -> &'static [&'static PlaneDecl] {
    PLANES.get_or_init(|| {
        let installed = INSTALLED.get().copied().unwrap_or(&[]);
        merged_boot_plane_decls(installed, BUILTIN_PLANE_DECLS)
    })
}

/// RESOLVE A PLANE DECLARATION BY KEY. Allocates nothing.
///
/// NAMED FOR ITS AXIS, not `decl_for`. `structure-lint.sh`'s declaration census holds
/// `fn decl_for(` to EXACTLY ONE production occurrence — "there is exactly ONE by-name protocol
/// resolution in busbar, and a second one is a second answer to which protocols exist". That rule
/// is right and is not weakened to make room for this: plane resolution is a different axis and
/// says so in its name, so the census keeps meaning what it means.
#[allow(dead_code)] // the by-key resolver a registered plane's admin/router surface will read
pub(crate) fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.key == key)
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

impl Plane {
    /// THE ONE PLACE the enum meets its declaration. Every `Plane` accessor reads this, so the enum
    /// is a NAME for a built-in plane rather than a second statement of its facts.
    ///
    /// It resolves against [`builtin_plane_decls`] rather than [`plane_decls`] deliberately: the
    /// three enum variants ARE the built-ins, and resolving them through the process list would
    /// make a `Plane::A2a.key()` call depend on the composition root having run — which every unit
    /// test in this crate would then have to arrange. A registered fourth plane has no enum variant
    /// and is reached by decl, never by `Plane`.
    pub(crate) fn decl(self) -> &'static PlaneDecl {
        let key = match self {
            Plane::Llm => "llm",
            Plane::Mcp => "mcp",
            Plane::A2a => "a2a",
        };
        builtin_plane_decls()
            .iter()
            .copied()
            .find(|d| d.key == key)
            .expect("every Plane variant has a built-in declaration")
    }
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;
