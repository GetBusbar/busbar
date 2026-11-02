// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub struct BootCtx {
    pub store: Option<std::sync::Arc<dyn crate::store::plane_view::PlaneStore>>,

    pub app: Option<std::sync::Arc<crate::state::App>>,

    pub handle: Option<std::sync::Arc<crate::state::AppHandle>>,

    pub card_issuer: Option<CardIssuer>,
}

impl BootCtx {
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

    fn engine_host(&self) -> std::sync::Arc<dyn busbar_kernel::plane_driver::EngineHost> {
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

    fn plane_store(
        &self,
    ) -> Option<std::sync::Arc<dyn busbar_kernel::store::plane_view::PlaneStore>> {
        self.store.clone()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
impl BootCtx {
    pub fn stub() -> BootCtx {
        BootCtx {
            store: None,
            app: None,
            handle: None,
            card_issuer: None,
        }
    }
}

static BUILTIN_PLANE_DECLS: &[&PlaneDecl] = &[];

pub fn builtin_plane_decls() -> &'static [&'static PlaneDecl] {
    BUILTIN_PLANE_DECLS
}

#[cfg(test)]
pub fn default_section_plane_test_runtime() -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    std::sync::Arc::new(())
}

static PLANES: std::sync::atomic::AtomicPtr<&'static [&'static PlaneDecl]> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[allow(unsafe_code)]
fn planes_at(ptr: *mut &'static [&'static PlaneDecl]) -> &'static [&'static PlaneDecl] {
    // SAFETY: `ptr` is non-null and was stored in `PLANES` from `Box::leak`, which is never freed
    // or mutated; the Acquire load that read it pairs with the Release/AcqRel store that wrote it.
    unsafe { *ptr }
}

static INSTALLED: std::sync::OnceLock<&'static [&'static PlaneDecl]> = std::sync::OnceLock::new();

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

    let canonical = canonical_key_order(installed, builtins);
    decls.sort_by_key(|d| {
        canonical
            .iter()
            .position(|k| *k == d.key)
            .unwrap_or(canonical.len())
    });

    let declared: Vec<&PlaneDeclaration> = decls.iter().map(|d| &d.declaration).collect();
    if let Err(refusal) = check_owned_config_claims(&declared, CORE_OWNED_CONCRETE_SECTIONS) {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    decls
}

pub const CORE_OWNED_CONCRETE_SECTIONS: &[&str] =
    &["providers", "models", "pools", "rate_card", "limits"];

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

pub fn scope_kind_at(idx: u32) -> Option<&'static str> {
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

pub fn scope_kind_index(kind: &str) -> Option<u32> {
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

pub fn plane_decl_for(key: &str) -> Option<&'static PlaneDecl> {
    plane_decls().iter().copied().find(|d| d.key == key)
}

pub fn plane_decl_for_config_section(section: &str) -> Option<&'static PlaneDecl> {
    plane_decls()
        .iter()
        .copied()
        .find(|d| d.config_section == section)
}

pub fn build_dispatch(
    decls: &[&'static PlaneDecl],
    slots: &std::collections::BTreeMap<&'static str, &dyn std::any::Any>,
    key_chain: bool,
) -> Result<super::dispatch::PlaneDispatch, String> {
    let mut dispatch = super::dispatch::PlaneDispatch::default();
    for decl in decls {
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        let admission = (decl.admission)(slot);

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

pub struct BuildCtx<'a> {
    pub endpoint_slot: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    pub plane_defs: &'a std::collections::BTreeMap<
        &'static str,
        Box<dyn crate::config::plane_sections::PlaneCfg>,
    >,
    pub public_url: Option<&'a str>,

    pub prior: Option<&'a dyn crate::plane_driver::slots::PlaneSlots>,

    pub providers:
        Option<&'a std::collections::HashMap<String, crate::config::providers::ResolvedProvider>>,
}

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

pub trait PlaneBootCtx {
    fn has_store(&self) -> bool;

    fn plane_store(&self) -> Option<std::sync::Arc<dyn crate::store::plane_view::PlaneStore>>;

    fn card_issuer(&self) -> Option<CardIssuer>;

    fn engine_host(&self) -> std::sync::Arc<dyn crate::plane_driver::EngineHost>;

    fn as_any(&self) -> &dyn std::any::Any;
}

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
        /// row is everything its hooks read.
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

#[cfg(feature = "openapi-schema")]
pub type OpenapiSchemasHook = fn(
    &PlaneDecl,
    &mut schemars::SchemaGenerator,
    &mut schemars::SchemaGenerator,
    &mut serde_json::Map<String, serde_json::Value>,
);

#[cfg(not(feature = "openapi-schema"))]
pub type OpenapiSchemasHook = fn(&PlaneDecl, std::convert::Infallible);

#[cfg(feature = "openapi-schema")]
pub(crate) const fn stated_schemas_hook() -> Option<OpenapiSchemasHook> {
    Some(stated_schemas)
}

#[cfg(not(feature = "openapi-schema"))]
pub(crate) const fn stated_schemas_hook() -> Option<OpenapiSchemasHook> {
    None
}

#[cfg(feature = "openapi-schema")]
fn stated_schemas(
    decl: &PlaneDecl,
    schema_gen: &mut schemars::SchemaGenerator,
    _req_gen: &mut schemars::SchemaGenerator,
    _paths: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(schemas) = crate::plane_driver::door::stated_schemas(decl) {
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
    wire_format_names: fn(&PlaneDecl) -> &'static [&'static str],

    /// THE DIALECTS A PROVIDER'S `protocol` MAY NAME, of those this plane speaks, in its order
    /// A door plane's
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
    // Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test; a
    // default `--no-default-features` build has neither, so the field is genuinely unread there.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
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
    #[allow(clippy::type_complexity)]
    named_def_list:
        Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots) -> Vec<crate::api::NamedDefView>>,

    /// PROJECT ONE NAMED-DEFINITION REGISTRATION by name onto the shared read view — the single-entry
    /// twin of [`Self::named_def_list`], the plane half of `GET /api/v1/admin/<section>/{name}`.
    /// `None` (the fn returns `None`) when the plane has no entry by that name; the FIELD is `None` for
    /// a plane with no named-definition map. Handed the same neutral [`crate::plane_driver::slots::PlaneSlots`]
    /// seam as [`Self::named_def_list`].
    #[allow(clippy::type_complexity)]
    named_def_get:
        Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots, &str) -> Option<crate::api::NamedDefView>>,

    /// IS `name` A LIVE REGISTRATION on this plane's effective snapshot — the read-side membership
    /// check the admin write path consults so it names no plane registry type. `None` for a plane with
    /// no named-definition map.
    #[allow(clippy::type_complexity)]
    registry_contains: Option<fn(&PlaneDecl, &dyn crate::plane_driver::slots::PlaneSlots, &str) -> bool>,

    /// RE-RESOLVE THIS PLANE'S PER-REGISTRATION HOOK GATES against the next snapshot — the plane half
    /// of the config-swap gate rebuild. Reads the plane's own registry off the `&mut App` and writes
    /// its own gate field back, so `admin::v1::service::reresolve_plane_gates` names no plane registry
    /// type. `None` for a plane with no per-registration hook gates (the LLM plane).
    reresolve_gates: Option<fn(&PlaneDecl, &mut dyn crate::plane_driver::slots::ContainerGateSink)>,

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
        Option<fn(&PlaneDecl, &serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneCfg>, String>>,

    /// PARSE THIS PLANE'S TOP-LEVEL ENDPOINT block (the MCP plane's `mcp:` door) from a positionless
    /// `serde_yaml::Value`, boxed as the neutral [`crate::config::plane_sections::PlaneEndpointCfg`] — the seam
    /// `DeployCfg`'s `mcp:` field deserializes through. `None` for a plane with no endpoint block
    /// (every plane but MCP).
    #[allow(clippy::type_complexity)]
    parse_endpoint: Option<
        fn(&PlaneDecl, &serde_yaml::Value) -> Result<Box<dyn crate::config::plane_sections::PlaneEndpointCfg>, String>,
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

#[cfg(test)]
#[path = "tests/registry_memo_tests.rs"]
mod registry_memo_tests;
