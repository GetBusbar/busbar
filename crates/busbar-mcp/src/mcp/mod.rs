// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S FRONT DOOR: busbar as an OAuth 2.1 RESOURCE SERVER, and the HTTP-level MUSTs of
//! MCP revision `2026-07-28`.
//!
//! ## What busbar is here
//!
//! busbar is the MCP SERVER. An AI agent connects to it exactly as it connects to a model provider:
//! with no credential first, which earns a `401` carrying a `WWW-Authenticate` challenge that names
//! this resource's RFC 9728 metadata document; it follows that to the operator's authorization
//! server, does ordinary OAuth over plain HTTPS, and comes back with a token. busbar then checks
//! that the token's audience is ITSELF — and from there it is machinery that already exists:
//! identity, budget, policy, rate limits, audit.
//!
//! **THIS MODULE is not the authorization server**, and the split is deliberate: with `mcp:` alone
//! the tokens are minted by the operator's existing IdP (Okta, Entra, Auth0) and nothing here issues
//! one, so a resource server's whole job stays a resource server's job — verify, never mint.
//!
//! busbar the PRODUCT does have an authorization server, and it is not a plugin surface and not
//! deferred: core's `oauth_as` module is a first-class in-core plane, off unless the `oauth_as:` block is
//! configured, serving all three of the `2026-07-28` registration mechanisms and issuing RFC 9068
//! `at+jwt` access tokens whose `aud` is one of busbar's own protected resources
//! (core's `oauth_as::plane`, routes in its `oauth_as::routes`). It exists because an
//! enterprise identity team will not turn on RFC 7591 for Codex or Claude.ai, so "point at your IdP"
//! is not an answer for the clients people actually run. The two planes compose rather than
//! overlap: `oauth_as:` mints, `mcp:` verifies, and this module's audience check is the same check
//! either way — it does not care, and must not care, which authorization server minted the token.
//!
//! ## Why the audience check is the load-bearing one
//!
//! It is the CONFUSED-DEPUTY defence, and it is the difference between a gateway and an open relay.
//! Without it, a token an agent legitimately obtained for some OTHER resource — a token that IdP
//! happily issued, for a service that has nothing to do with busbar — is spendable here, against
//! busbar's pools, budget and upstream credentials. RFC 8707 exists precisely so a resource server
//! can say "this was not minted for me". busbar therefore compares the token's `aud` for EQUALITY
//! against one operator-configured canonical URI, and refuses anything else, including a token that
//! carries no audience at all.
//!
//! The check lives in the VERIFIER, reached through the plane's mount
//! (`busbar_substrate::plane::PlaneAdmission`), not in a handler — so a route added to this plane tomorrow
//! inherits it and cannot forget it.
//!
//! ## The revision this targets, and what that means
//!
//! MCP `2026-07-28`, the streamable-HTTP stateless RC (SEP-2243/SEP-2575). It is a breaking
//! redesign, not an increment, and the parts of it that are pure HTTP are enforced here:
//!
//! - There is no `initialize` handshake and there are no protocol sessions. Every request is
//!   self-describing, carrying its protocol version and the client's capabilities in `_meta`. So
//!   there is no `Mcp-Session-Id` to mint, honour, or invalidate. A stateful protocol would need
//!   to TOMBSTONE the sessions pinned to a server the operator has de-approved; with no handshake
//!   and no sessions there is nothing to tombstone, so that defence collapses into a per-request
//!   generation check, which is simpler and cannot go stale.
//! - The GET stream endpoint is gone, and with it resumability. GET and DELETE answer `405`.
//! - `Mcp-Method` mirrors the body's `method` on every request, and `Mcp-Name` mirrors the target
//!   name on `tools/call`, `resources/read` and `prompts/get`. Both are REQUIRED for compliance, and
//!   a header that disagrees with the body is `400` with JSON-RPC code `-32020` — because a proxy
//!   routing on the header while the server executes the body is a request-smuggling primitive.
//! - `MCP-Protocol-Version` must equal the body `_meta` protocol version, same `-32020` on mismatch.
//!   A `_meta` that is ABSENT or incomplete is a different failure and answers `-32602` with `400`:
//!   that is a defect in the request's own params, not two readings of one request disagreeing.
//! - An unknown method is `404` with JSON-RPC `-32601`, NOT a `200` carrying an error object.
//! - `Origin` validation is a MUST, `403` on an invalid one — the DNS-rebinding defence for a
//!   gateway that may be reachable from a browser context.
//!
//! ## The rooms behind the door
//!
//! The JSON-RPC method surface — the CATALOGUE (`tools/list`, `prompts/list`, `resources/list`,
//! `resources/templates/list`, `server/discover`) and DISPATCH (`tools/call`, `prompts/get`,
//! `resources/read`) — lives in [`method`], computed over the versioned snapshot in [`catalogue`],
//! scoped by the caller's key grants, sanitised by [`sanitize`] and bounded by [`inputreq`]. A
//! method absent from that table still takes the `404` / `-32601` arm, which was never a
//! placeholder: it is the correct answer for an unimplemented method and it stayed correct unchanged
//! when the table gained entries.
//!
//! The registry those answers are computed from is the `tools:` config block ([`config`]), which is
//! the MCP plane in the same sense `pools:` is the LLM plane.
//!
//! ## The other direction, which is also here
//!
//! busbar calling OUT is [`client`], and a `tools/call` is a real round trip to the registered
//! upstream: SSRF-checked, address-pinned, connection-pooled, and carrying a credential
//! [`upstream::authorise`] selected under the INBOUND caller's grant. That binding is the
//! confused-deputy defence for this direction, and it is what the whole plane's authorization model
//! rests on — which is why an `mcp:` block with an empty `auth.chain` is refused at boot rather than
//! served: with no inbound principal there is no grant to bind to, and none to narrow the catalogue
//! by either, so both properties go vacuous at once.
//!
//! ## What is deliberately NOT here
//!
//! An upstream's ASK — `elicitation/create`, `sampling/createMessage`, `roots/list` arriving as an
//! `input_required` result — TERMINATES at busbar. It is never proxied onward to the caller.
//! Proxying one would ask the caller to grant, on the upstream's behalf, authority busbar itself has
//! just declined to spend.
//!
//! ## The distinction that replaced "busbar never emits one"
//!
//! That sentence used to end "…so busbar never emits an `input_required` result of its own and every
//! result it returns is `complete`". The first half is the rule; the second half was a CONSEQUENCE
//! of not having built anything, and stating it as an invariant confused a property busbar must hold
//! with a feature busbar had not written.
//!
//! busbar now does emit `InputRequiredResult`s, and the rule is untouched, because the two are not
//! the same object and cannot be converted into one another:
//!
//! | | authored by | may reach busbar's caller |
//! |---|---|---|
//! | [`inputreq::Ask`] | an upstream | NEVER — [`inputreq::Outcome`] has no arm to carry it, and a terminal check in `method.rs` refuses one that somehow arrives anyway |
//! | [`callerask::CallerAsk`] | the OPERATOR, in `ask_caller:` config | yes — that is what it is for |
//!
//! There is no `From` between them, none constructible, and `callerask.rs` is scanned at test time
//! for so much as the NAME of the modules an upstream's values live in. An operator-authored ask
//! sealed with state busbar mints is the same rule that already makes busbar publish the operator's
//! tool description rather than the upstream's — applied to the field where it matters most.

/// THE MCP PLANE'S VOCABULARY DECLARATION, beside the code it describes. Folded into
/// `plane::registry::BUILTIN_PLANE_DECLS`; every field replaces one arm of a `Plane::Mcp` `match`.
///
/// `wire_format_names` is the single JSON-RPC 2.0 dialect, carried over any of three transports — a
/// transport is not a wire format, so this list has one entry and the plane earns no superset IR.
pub const PLANE_DECL: busbar_substrate::plane::registry::PlaneDecl =
    busbar_substrate::plane::registry::PlaneDecl {
        key: "mcp",
        // A MOUNTED plane, not the fallback catch-all.
        fallback: false,
        config_section: "tools",
        scope_kinds: &["mcp_server", "mcp_tool"],
        subject_noun: "MCP server",
        admin_noun: "mcp-server",
        audit_kind: "mcp_server",
        wire_format_names: || &[busbar_substrate::plane::WIRE_JSONRPC],
        // THE MCP DOOR, from the validated resource. One claim — the ingress mount — spoken in
        // JSON-RPC, and the audience is that resource's canonical URI. Whenever `mcp:` is configured
        // the plane both mounts and admits, so the ratchet's "mounted ⇒ admitted" holds by
        // construction here; the boot-refuse in `build_dispatch` guards the planes that might not.
        claims: |slot| {
            let r = slot
                .downcast_ref::<McpResource>()
                .expect("the mcp plane's dispatch slot is an McpResource");
            vec![(
                r.mount_path().to_string(),
                busbar_substrate::plane::WIRE_JSONRPC,
            )]
        },
        admission: |slot| {
            let r = slot
                .downcast_ref::<McpResource>()
                .expect("the mcp plane's dispatch slot is an McpResource");
            Some(r.admission())
        },
        // THE MCP SLOT: the validated resource is already built by config resolution
        // (`McpResource::from_cfg`, run once at `RootCfg` construction) AND already type-erased at the
        // composition root into the neutral `BuildCtx::mcp_slot`, so `build` here is a CLONE of that
        // ONE opaque `Arc` — not a second construction and not a re-erasure. `None` exactly when
        // `cfg.mcp` is `None`, matching `App::mcp`'s own absence.
        build: |ctx| ctx.mcp_slot.clone(),
        // S4a Option A: the MCP plane's data routes are contributed NEUTRALLY through `routes`, so
        // its handlers no longer extract `axum::State<Arc<AppHandle>>`.
        routes: Some(mcp_routes),
        admin_routes: Some(mcp_admin_routes),
        openapi: Some(mcp_openapi_fragment),
        config_validate: Some(mcp_config_validate),
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: Some(admin_view::list),
        named_def_get: Some(admin_view::get),
        registry_contains: Some(admin_view::contains),
        reresolve_gates: Some(admin_view::reresolve_gates),
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: Some(admin_view::openapi_schemas),
        hydrate: Some(mcp_hydrate),
        // NO START HOOK. Verify-on-call is LAZY — it re-verifies on the `tools/call` path against a
        // ≤`verify_ttl` single-flight snapshot (see `busbar_substrate::trust::verify`), so there is no background
        // sweep to spawn at boot. A server nobody calls is never fetched. The daemon this replaced is
        // gone; its removal is the whole of this plane's boot change.
        start: None,
        on_swap: Some(mcp_on_swap),
        parse_section: Some(mcp_parse_section),
        parse_endpoint: Some(mcp_parse_endpoint),
        lower_endpoint: Some(mcp_lower_endpoint),
        build_runtime: Some(mcp_build_runtime),
        viewer: None,
        retain_verify_gates: Some(mcp_retain_verify_gates),
        default_section: Some(mcp_default_section),
        // config-seam stage 1: the registry starts EMPTY — nothing has moved out of core yet.
        owned_config_sections: &[],
    };

/// VALIDATE ONE `tools:` NAMED-DEFINITION DOCUMENT — the MCP plane's half of
/// [`busbar_substrate::plane::registry::PlaneDecl::config_validate`]. Parses the raw document into
/// [`config::McpServerDefCfg`] (`deny_unknown_fields`, so a typo'd key is refused HERE exactly as the
/// file refuses it) and applies the same value rules boot applies through the identical
/// [`config::validate_server`]. Naming `crate::mcp` types HERE is correct: this is the MCP plane's
/// own module, and it is what lets `config::named_map` validate a `tools:` write without doing so.
fn mcp_config_validate(name: &str, def: &serde_json::Value) -> Result<(), String> {
    let cfg: config::McpServerDefCfg = serde_json::from_value(def.clone())
        .map_err(|e| format!("invalid `tools.{name}` definition: {e}"))?;
    config::validate_server(name, &cfg)
}

/// THE MCP RUNTIME OBJECT for this config generation, read through the TYPE-ERASED `plane_slots`
/// seam ([`busbar_substrate::plane_host::PlaneSlots::plane_slot`]) and downcast back to
/// [`McpResource`] HERE, inside the plane — so core OUTSIDE this module reaches the resource only as
/// an opaque `Arc<dyn Any>` slot and names no `crate::mcp` type. `None` exactly when `mcp:` is not
/// configured this generation (the plane contributed no slot — the same absence the deleted
/// `App::mcp: None` used to encode). The downcast never fails: the mcp slot is always an
/// `McpResource` (`PLANE_DECL::build`).
///
/// Takes `&impl PlaneSlots` — the neutral slot-holder seam core implements for its engine snapshot —
/// so this plane names no concrete snapshot type. A snapshot held behind an `Arc`, a load guard or a
/// plain borrow satisfies the bound too (the substrate forwards `PlaneSlots` through any pointer to a
/// slot holder), which is how a test's `&app` reaches here unchanged.
///
/// It, and its `runtime` sibling, live in the [`test_app_reads`] module: both are TEST-SUPPORT reads
/// off a whole snapshot (production uses the `resource_of` / `runtime_slots` twins, which read off the
/// bound host), so they are gated to the `test-support` surface and out of every shipped build.
#[cfg(feature = "test-support")]
pub use test_app_reads::resource;
// `runtime` is read only by the plane's own tests, so a `test-support` lib build (which links none)
// sees the re-export unused; the allowance keeps that build warning-clean, mirroring the read fns.
#[cfg_attr(not(test), allow(unused_imports))]
#[cfg(feature = "test-support")]
pub(crate) use test_app_reads::runtime;

/// TEST-SUPPORT typed reads off a whole snapshot (`&impl PlaneSlots`) — the snapshot-typed twins of
/// the host-based `resource_of` / `runtime_slots` seams, kept here for the plane's own test fixtures
/// and core's plane-integration tests. Gated on `test-support` because no shipped path reads a whole
/// snapshot; the fixtures do.
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(feature = "test-support")]
mod test_app_reads {
    use super::{McpResource, McpRuntime, PLANE_DECL};
    use busbar_substrate::plane_host::PlaneSlots;

    /// See the module-level note: the snapshot-typed read of the config-conditional dispatch slot.
    pub fn resource<S: PlaneSlots + ?Sized>(app: &S) -> Option<&McpResource> {
        app.plane_slot(PLANE_DECL.key).map(|slot| {
            slot.downcast_ref::<McpResource>()
                .expect("the mcp plane's dispatch slot is an McpResource")
        })
    }

    /// See the module-level note: the snapshot-typed read of the always-present runtime slot.
    pub fn runtime<S: PlaneSlots + ?Sized>(app: &S) -> &McpRuntime {
        app.plane_slot(busbar_substrate::plane_host::runtime_slot_key(
            PLANE_DECL.key,
        ))
        .expect("the mcp runtime slot is present on every generation the plane is compiled into")
        .downcast_ref::<McpRuntime>()
        .expect("the mcp runtime slot is an McpRuntime")
    }
}

/// THE HOST-BASED TWIN of [`resource`] — the plane's dispatch object off the BOUND snapshot, read
/// through the neutral [`busbar_substrate::plane_host::EngineHost::plane_slot`] seam and downcast HERE.
/// Returns an OWNED `Arc<McpResource>` (a refcount bump of the same `Arc` `plane_slots` holds) so it
/// outlives the call, since the borrow now comes from an owned host, not an `&App`. `None` exactly
/// when `mcp:` is not configured this generation; the downcast never fails ([`PLANE_DECL::build`]).
pub(crate) fn resource_of(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> Option<std::sync::Arc<McpResource>> {
    host.plane_slot(PLANE_DECL.key).map(|slot| {
        slot.downcast::<McpResource>()
            .expect("the mcp plane's dispatch slot is an McpResource")
    })
}

/// THE MCP PLANE'S PER-GENERATION CLIENT-DIRECTION RUNTIME — the objects the plane carries for one
/// config generation, bundled into ONE mcp-owned struct so core's `App` names no `crate::mcp` type for
/// any of them. It is carried in the engine snapshot's type-erased `plane_slots` map behind `Arc<dyn Any>` under
/// the always-present companion key [`runtime_slot_key`](busbar_substrate::plane_host::runtime_slot_key), and [`runtime`] downcasts
/// it back HERE, inside the plane.
///
/// It rides its OWN `plane_slots` key rather than the plane's decl key (`"mcp"`, where the server-side
/// dispatch object [`McpResource`] lives) because these objects are ALWAYS present — even a deployment
/// with no `tools:`/`mcp:` block carries an empty catalogue and a live pool — whereas the `"mcp"` slot
/// is config-conditional (absent when the plane is not configured) and is what `build_dispatch` reads
/// to decide the plane's door. Folding an always-present bundle onto the config-conditional slot would
/// change `plane_slot("mcp")`'s presence semantics; a separate companion key preserves byte-identical
/// behaviour.
///
/// Each field's cross-apply lifecycle is UNCHANGED — the carry-over rules (fresh
/// `catalogue`/`servers`/`pool` per apply, carried `sightings`/`roots_epochs`/`sampling_spend` and the
/// `verify` coalescer folded in here from the former flat `App::mcp_verify` field) live in
/// [`McpRuntime::build`].
pub(crate) struct McpRuntime {
    pub(crate) catalogue: std::sync::Arc<catalogue::Catalogue>,
    pub(crate) servers: std::sync::Arc<config::ToolsCfg>,
    pub(crate) pool: std::sync::Arc<client::pool::McpConnectionPool>,
    pub(crate) sightings: std::sync::Arc<client::catalogue::CatalogueCache>,
    pub(crate) roots_epochs: std::sync::Arc<roots::RootsEpochs>,
    pub(crate) sampling_spend: std::sync::Arc<sampling::SamplingSpend>,
    /// THE MCP VERIFY-ON-CALL GATE — the per-server single-flight coalescer that re-verifies an
    /// upstream's advertised tool surface on the `tools/call` path when its recorded observation is
    /// older than `verify_ttl` (see [`busbar_substrate::trust::verify`]). It is the plane's OWN coalescing
    /// state, so it lives ON the plane's runtime object (reached via `ctx.slot`) rather than as a flat
    /// `App` field. Arc-shared ACROSS config applies, like the `sightings` cache it freshens, and for
    /// the same reason: the coalescing epochs are ACCUMULATED coordination state, not intent, so
    /// [`McpRuntime::build`] carries it from `prior` rather than rebuilding it.
    pub(crate) verify: std::sync::Arc<busbar_substrate::trust::VerifyGate>,
}

impl McpRuntime {
    /// Build the generation's runtime from the resolved `tools:` registry, carrying the accumulated
    /// state forward from the prior generation exactly as the flat-field construction did:
    /// `catalogue`/`servers`/`pool` are fresh (a new pin generation, a fresh pool), while
    /// `sightings`/`roots_epochs`/`sampling_spend` are ACCUMULATED evidence and are carried from
    /// `prior` when there is one.
    pub(crate) fn build(tool_defs: &config::ToolsCfg, prior: Option<&McpRuntime>) -> McpRuntime {
        McpRuntime {
            catalogue: std::sync::Arc::new(catalogue::Catalogue::build(tool_defs)),
            servers: std::sync::Arc::new(tool_defs.clone()),
            pool: std::sync::Arc::new(client::pool::McpConnectionPool::new()),
            sightings: prior.map_or_else(
                || std::sync::Arc::new(client::catalogue::CatalogueCache::new()),
                |p| p.sightings.clone(),
            ),
            roots_epochs: prior.map_or_else(
                || std::sync::Arc::new(roots::RootsEpochs::new()),
                |p| p.roots_epochs.clone(),
            ),
            sampling_spend: prior.map_or_else(
                || std::sync::Arc::new(sampling::SamplingSpend::new()),
                |p| p.sampling_spend.clone(),
            ),
            // CARRIED ACROSS THE APPLY beside the sightings it freshens: the verify-on-call
            // coalescing epochs are accumulated coordination state, not intent, and rebuilding them
            // on every apply would let a burst of callers each fetch during the window an unrelated
            // edit reset. Pruned to the live server set by [`mcp_retain_verify_gates`] after the
            // build, exactly as it was when this was the flat `App::mcp_verify` field.
            verify: prior.map_or_else(
                std::sync::Arc::<busbar_substrate::trust::VerifyGate>::default,
                |p| p.verify.clone(),
            ),
        }
    }
}

/// THE NEUTRAL-SLOT twin of [`runtime`] — the plane's runtime object read through the
/// [`busbar_substrate::plane_host::PlaneSlots`] seam rather than off `&App`, so the core-owned
/// `PlaneDecl` callbacks the MCP plane fills (`on_swap`, `registry_contains`, `retain_verify_gates`)
/// name no concrete engine-snapshot type. Same borrowed `&McpRuntime` and never-failing `.expect`s as
/// [`runtime`]; the slot key is the always-present runtime companion in the neutral substrate.
pub(crate) fn runtime_slots(slots: &dyn busbar_substrate::plane_host::PlaneSlots) -> &McpRuntime {
    slots
        .plane_slot(busbar_substrate::plane_host::runtime_slot_key(
            crate::PLANE_DECL.key,
        ))
        .expect("the mcp runtime slot is present on every generation the plane is compiled into")
        .downcast_ref::<McpRuntime>()
        .expect("the mcp runtime slot is an McpRuntime")
}

/// THE BOUND-SNAPSHOT host twin of [`runtime`] — the plane's runtime object off the snapshot the host
/// was minted on, read through the neutral
/// [`busbar_substrate::plane_host::EngineHost::plane_slot`] seam under the always-present runtime slot
/// [`runtime_slot_key`](busbar_substrate::plane_host::runtime_slot_key) and downcast HERE. Returns an OWNED
/// `Arc<McpRuntime>` so the caller binds it to a local and reaches its fields through the owned `Arc`
/// (the borrow no longer comes from `&App`). Both the lookup and the downcast `.expect`: the slot is
/// present on every generation the plane is compiled into and is always an `McpRuntime`.
pub(crate) fn runtime_of(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> std::sync::Arc<McpRuntime> {
    host.plane_slot(busbar_substrate::plane_host::runtime_slot_key(
        crate::PLANE_DECL.key,
    ))
    .expect("the mcp runtime slot is present on every generation the plane is compiled into")
    .downcast::<McpRuntime>()
    .expect("the mcp runtime slot is an McpRuntime")
}

/// THE LIVE-SNAPSHOT twin of [`runtime_of`] — the plane's runtime object off the CURRENT snapshot,
/// re-loading the live handle through [`busbar_substrate::plane_host::EngineHost::plane_slot_live`] so
/// a config swap or revocation AFTER admission is seen. Used only where the re-read is semantically
/// required (dispatch-time re-validation, per-round grant/roots re-reads, background/poll
/// generation-watch loops); the bound [`runtime_of`] is used everywhere the request's own snapshot is
/// the intended one. Same owned-`Arc` return and never-failing `.expect`s as [`runtime_of`].
pub(crate) fn runtime_live(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> std::sync::Arc<McpRuntime> {
    host.plane_slot_live(busbar_substrate::plane_host::runtime_slot_key(
        crate::PLANE_DECL.key,
    ))
    .expect("the mcp runtime slot is present on every generation the plane is compiled into")
    .downcast::<McpRuntime>()
    .expect("the mcp runtime slot is an McpRuntime")
}

/// BUILD THE GENERATION'S MCP RUNTIME, TYPE-ERASED for the neutral `plane_slots` runtime slot
/// ([`runtime_slot_key`](busbar_substrate::plane_host::runtime_slot_key)) — the one entry point `appbuild` calls so the
/// composition of the `App` names no `crate::mcp` runtime type.
/// `prior` is the prior generation's snapshot, read through the neutral
/// [`busbar_substrate::plane_host::PlaneSlots`] seam (for the carry-over rules in
/// [`McpRuntime::build`]) so this function, not `appbuild`, owns the downcast and the signature names
/// no concrete engine-snapshot type.
pub(crate) fn build_runtime(
    tool_defs: &config::ToolsCfg,
    prior: Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    std::sync::Arc::new(McpRuntime::build(tool_defs, prior.map(runtime_slots)))
}

/// PARSE THE `tools:` SECTION through the MCP plane's own `Deserialize` — the
/// [`busbar_substrate::plane::registry::PlaneDecl::parse_section`] hook, so `DeployCfg` deserializes its `tools:`
/// field without naming [`config::ToolsCfg`]. The `serde_yaml::Value` intermediate carries no source
/// position, so the plane's own `split_section` refusals reach the operator by their SENTENCE (the
/// content core pins), the `at line`/`column` suffix aside.
fn mcp_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_substrate::plane::config::PlaneCfg>, String> {
    serde_yaml::from_value::<config::ToolsCfg>(v.clone())
        .map(|c| Box::new(c) as Box<dyn busbar_substrate::plane::config::PlaneCfg>)
        .map_err(|e| e.to_string())
}

/// [`busbar_substrate::plane::registry::PlaneDecl::default_section`] hook — the empty `tools:` registry, so an
/// ABSENT section defaults to `ToolsCfg::default()` byte-identically to the pre-seam typed field.
fn mcp_default_section() -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
    Box::<config::ToolsCfg>::default()
}

/// PARSE THE `mcp:` ENDPOINT block through the MCP plane's own `Deserialize` — the
/// [`busbar_substrate::plane::registry::PlaneDecl::parse_endpoint`] hook, so `DeployCfg` deserializes its `mcp:`
/// field without naming [`McpCfg`].
fn mcp_parse_endpoint(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_substrate::plane::config::PlaneEndpointCfg>, String> {
    serde_yaml::from_value::<McpCfg>(v.clone())
        .map(|c| Box::new(c) as Box<dyn busbar_substrate::plane::config::PlaneEndpointCfg>)
        .map_err(|e| e.to_string())
}

/// LOWER THE `mcp:` ENDPOINT into the validated [`McpResource`], type-erased — the
/// [`busbar_substrate::plane::registry::PlaneDecl::lower_endpoint`] hook, so `config::resolve` derives
/// `RootCfg::mcp` (`Option<Arc<dyn Any>>`) without naming [`McpResource`] or its constructor. The
/// error string is `McpCfgError`'s `Display`, verbatim, so the boot refusal is byte-identical.
fn mcp_lower_endpoint(
    endpoint: &dyn busbar_substrate::plane::config::PlaneEndpointCfg,
) -> Result<std::sync::Arc<dyn std::any::Any + Send + Sync>, String> {
    let cfg = endpoint
        .as_any()
        .downcast_ref::<McpCfg>()
        .expect("the mcp plane's endpoint is an McpCfg");
    McpResource::from_cfg(cfg)
        .map(|r| std::sync::Arc::new(r) as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        .map_err(|e| e.to_string())
}

/// BUILD THE MCP RUNTIME from the type-erased `tool_defs` slot — the
/// [`busbar_substrate::plane::registry::PlaneDecl::build_runtime`] hook, so `appbuild` composes the MCP
/// runtime slot (the plane's `runtime_slot_key` bundle) through the plane without naming
/// [`config::ToolsCfg`]. Downcasts back to `ToolsCfg` HERE (inside the plane) and delegates to
/// [`build_runtime`].
fn mcp_build_runtime(
    tool_defs: &dyn std::any::Any,
    prior: Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
    let tool_defs = tool_defs
        .downcast_ref::<config::ToolsCfg>()
        .expect("the mcp plane's build_runtime slot is a ToolsCfg");
    build_runtime(tool_defs, prior)
}

/// PRUNE THE MCP VERIFY-ON-CALL GATES to the servers THIS generation fronts — the
/// [`busbar_substrate::plane::registry::PlaneDecl::retain_verify_gates`] hook, so `appbuild` prunes the carried
/// coalescing state without naming the MCP runtime. Byte-identical to the old inline `appbuild` arm.
fn mcp_retain_verify_gates(slots: &dyn busbar_substrate::plane_host::PlaneSlots) {
    let rt = runtime_slots(slots);
    let live: std::collections::HashSet<String> =
        rt.catalogue.servers().map(|s| s.id.clone()).collect();
    rt.verify.retain(&live);
}

/// The `mcp:` ENDPOINT block, as the neutral [`busbar_substrate::plane::config::PlaneEndpointCfg`] seam — a
/// present `McpCfg` (a fully-deserialized block) is always present; the deletion-gate `is_present`
/// question is only ASKED of the raw carrier the compiled-out build captures.
impl busbar_substrate::plane::config::PlaneEndpointCfg for McpCfg {
    fn is_present(&self) -> bool {
        true
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// CARRY THE MCP CONNECTION POOL ACROSS A CONFIG SWAP — retire every stdio child whose registration
/// is gone from the NEXT generation. The pool deliberately outlives an apply (a socket negotiated
/// nothing this revision, so reusing it across a config edit is safe and desirable), and the
/// catalogue does not — so without this, deleting a `tools:` entry would leave its child process
/// running forever, unreferenced by any live registration and unreachable, which is a leak an
/// operator has no surface to see or stop. The keep-set is the NEXT catalogue's server ids, so a
/// registration the operator removed is exactly the child that is dropped; a registration that
/// survives keeps its live child and the connection reuse the pool exists for.
///
/// It reads the NEXT snapshot's own MCP runtime state (`mcp_pool`, `mcp_catalogue`) and nothing that
/// carries the audit chain or the governance context. The prior snapshot is unread here: the pool is
/// Arc-carried onto the next snapshot by `App::clone` (a live-config mutation) already, so the work
/// is a reconciliation of the carried pool to the next catalogue, not a copy from prior to next; the
/// argument is present for a plane whose swap must DIFF the two generations. When the MCP plane's
/// pool and catalogue move out of the flat `App` fields into the plane's own slot object, this
/// downcasts that slot instead of the `App`.
pub(crate) fn mcp_on_swap(
    _prior: &dyn busbar_substrate::plane_host::PlaneSlots,
    next: &dyn busbar_substrate::plane_host::PlaneSlots,
) {
    let rt = runtime_slots(next);
    rt.pool.children.retain(
        &rt.catalogue
            .servers()
            .map(|s| s.id.clone())
            .collect::<std::collections::BTreeSet<_>>(),
    );
}

/// RESTORE THE MCP PLANE'S DURABLE STATE, in order, BEFORE a listener binds — the per-call log, the
/// upstream-demotion record and the spent-approval ledger, each attached as a write-through sink to
/// the plane-narrowed store and read back. The narrowed store (task/mcp/demotion/spent methods only,
/// never `append_audit`) is the whole of what this hook touches of the durable home, so an MCP
/// hydrate can neither read nor forge the audit chain (invariant (a)). With `store: memory` (no
/// governance store) `ctx.store` is `None` and every block below is skipped — the call log, the
/// demotion record and the spent ledger are ephemeral BY DESIGN there, exactly as the audit ring is.
pub(crate) fn mcp_hydrate(
    ctx: &dyn busbar_substrate::plane::registry::PlaneBootCtx,
) -> Result<(), String> {
    if !ctx.has_store() {
        return Ok(());
    }

    // DURABLE MCP PER-CALL LOG. The tamper-evident record of who called which tool, under which
    // approved digest, and whether it went out — the Art 26(6) record-keeping pillar. Attached as a
    // write-through sink and READ BACK, because a write's `Ok(())` proves nothing about a trait whose
    // defaults accept and keep nothing.
    //
    // THE RESTORE IS NOT A FORMALITY. It is the only place in a running deployment where a persisted
    // chain is recomputed, so it is also the only place a tamper is detected — every break it finds is
    // logged at ERROR, naming the principal, while the records stay restored (refusing to restore them
    // would let anyone able to write to the store DELETE a caller's history by corrupting one byte).
    // REGISTER the durable `call` stream FIRST — the host attaches its sink from `app.governance` (the
    // same plane-narrowed store) at register time, bounded at the MCP call log's LRU cap — then rehydrate
    // through the seam, opening a dispatch scope so the caller-driven seed reaches the host over a live
    // `HostCtx`.
    ctx.register_call_stream();
    let restored = ctx.restore_call_log();
    match restored {
        Ok(r) if r == busbar_substrate::plane::registry::RestoredSummary::default() => {}
        Ok(r) => {
            tracing::info!(
                principals = r.principals,
                records = r.records,
                unreadable = r.unreadable,
                "MCP per-call log restored from the durable governance store"
            );
            // An UNDECODABLE row is an evidence record this build could not read back — counted and
            // SKIPPED per-record (each already logged LOUDLY at its skip site in core). Repeated here
            // at the boot summary and at WARN, and fired whenever `unreadable > 0` even if `records`
            // is zero (a scope whose rows were ALL undecodable), so the aggregate is never invisible.
            if r.unreadable > 0 {
                busbar_substrate::diag_warn!(
                    busbar_substrate::diagnostics::PLANE_CALLLOG_ROW_UNREADABLE,
                    rows = r.unreadable,
                    "persisted MCP per-call records could not be decoded on restore and were SKIPPED; \
                     they were most likely written by a different engine version or the store is corrupt"
                );
            }
            // An ENUMERATED-BUT-EMPTY chain is the one shape the verifier cannot judge alone, and it
            // is what one caller's evidence being deleted wholesale looks like. Surfaced separately
            // rather than summed into `principals`.
            if r.empty_chains > 0 {
                busbar_substrate::diag_warn!(
                    crate::diagnostics::MCP_CALLLOG_EMPTY_CHAINS,
                    principals = r.empty_chains,
                    "the durable MCP call log enumerates these principals but holds NO records \
                     for them; their chains reopen at seq 1"
                );
            }
            for brk in &r.chain_breaks {
                busbar_substrate::diag_error!(
                    crate::diagnostics::MCP_CALLLOG_CHAIN_VERIFY_FAILED,
                    break_detail = %brk,
                    "MCP per-call CHAIN VERIFICATION FAILED on restore — TAMPER EVIDENCE"
                );
            }
        }
        Err(e) => busbar_substrate::diag_warn!(
            crate::diagnostics::MCP_CALLLOG_UNREAD,
            error = %e,
            "could not read the durable MCP per-call log; chains start at their persisted \
             tail being unknown, which means a principal with rows in the store may reopen at \
             seq 1 and collide"
        ),
    }

    // THE DURABLE MCP DEMOTION RECORD, and the SPENT-APPROVAL LEDGER. Two security properties that
    // were process-local, attached to the same durable home and each closing a window a restart used
    // to re-open: a DEMOTED UPSTREAM stays demoted (replayed here, BEFORE a listener binds, so the
    // quarantine is in force for the first request), and a SPENT APPROVAL stays spent across a restart
    // AND across a fleet (two nodes share the signing key, so they share the seal, and without a shared
    // ledger one approval was redeemable once per node — on a money-moving tool that is the defect the
    // gate exists to stop). Both take the plane-narrowed store off the one wrapper.
    // Attach both write-through sinks through the core-side BootCtx convenience, so this hook names no
    // `App` sink field: the ledger/record and the store are all core-owned and stay core-side.
    ctx.attach_mcp_durable_sinks();
    // The demotion boot-replay reads the durable rows and the bound-snapshot runtime off a host minted
    // over the freshly-built app — a snapshot-only mint (no live handle at hydrate), which is correct:
    // hydration reads exactly the generation it is restoring into.
    let host = ctx.engine_host();
    match crate::mcp::demotion::hydrate(&host, ctx.plane_store().as_ref()) {
        0 => {}
        n => busbar_substrate::diag_warn!(
            crate::diagnostics::MCP_DEMOTIONS_RESTORED,
            servers = n,
            "MCP upstream demotions restored from the durable governance store: these servers \
             were quarantined before the last restart and are refused until an operator works \
             the change or a sweep observes them serving what was approved"
        ),
    }
    Ok(())
}

/// MOUNT THE MCP PLANE'S DATA ROUTES from the validated resource (its dispatch slot). The paths are
/// CONCRETE, derived from the operator's canonical URI at mount time — no prefix matching, so the
/// auth middleware's exact-match discipline survives. The RFC 9728 metadata document is the one open
/// route (a credential-less client reads it to learn which credential to present); the endpoint
/// itself takes the normal key chain, where the plane's admission facts make the verifier require
/// this deployment's canonical URI as the token audience. GET and DELETE answer 405 (no GET stream,
/// no sessions this revision) behind the same key bar.
pub(crate) fn mcp_routes(
    slot: &dyn std::any::Any,
) -> Vec<busbar_substrate::plane_routes::PlaneRouteSpec> {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};
    let resource = slot
        .downcast_ref::<McpResource>()
        .expect("the mcp plane's routes slot is an McpResource");
    // The two CONCRETE paths, derived from the operator's canonical URI at mount time exactly as
    // before — no prefix matching, so the auth middleware's exact-match discipline survives.
    let metadata_path = resource.metadata_path().to_string();
    let mount_path = resource.mount_path().to_string();
    // Each spec's `(path, method, auth)` is handed VERBATIM to `CoreRouter::route` by the core
    // adapter, so the `CoreRouteTable` rows are byte-identical to the ones `mcp_mount` recorded. The
    // handlers are the neutral async fns over `PlaneReqCtx` — no `axum::State<Arc<AppHandle>>`.
    vec![
        PlaneRouteSpec {
            path: metadata_path,
            method: RouteMethod::Get,
            auth: RouteAuth::None,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(crate::mcp::envelope::metadata_route(ctx))
            }),
        },
        PlaneRouteSpec {
            path: mount_path.clone(),
            method: RouteMethod::Post,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(crate::mcp::envelope::rpc(ctx))
            }),
        },
        PlaneRouteSpec {
            path: mount_path.clone(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(crate::mcp::envelope::legacy_verb(ctx))
            }),
        },
        PlaneRouteSpec {
            path: mount_path,
            method: RouteMethod::Delete,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx: PlaneReqCtx| -> PlaneRouteFuture {
                Box::pin(crate::mcp::envelope::legacy_verb(ctx))
            }),
        },
    ]
}

/// CONTRIBUTE THE MCP TRUST VERBS to the Admin API v1 router: the operator's standing decision about
/// the upstream behind a `tools` registration, additive on top of the generic `tools` CRUD.
/// `connect` is the shared plane verb; `changes` and `health` are the two derived reads that contact
/// nothing.
pub(crate) fn mcp_admin_routes(
    _slot: &dyn std::any::Any,
) -> Vec<busbar_substrate::admin_verbs::AdminRouteSpec> {
    use crate::mcp::admin_view::McpServers;
    use busbar_plugin::cold::http_endpoint::RouteMethod;
    use busbar_substrate::admin_verbs::{
        connect_reply, AdminReplyFuture, AdminReqCtx, AdminRouteSpec, AdminScope, AdminVerbKind,
    };
    vec![
        // `connect` is the SHARED audited verb: resolve, look, and the core adapter records the
        // applied/rejected row. `Full` scope (a POST that reaches the network and can quarantine).
        AdminRouteSpec {
            method: RouteMethod::Post,
            path: "/tools/{name}/connect".to_string(),
            scope: AdminScope::Full,
            kind: AdminVerbKind::Audited { verb: "connect" },
            handler: std::sync::Arc::new(|ctx: AdminReqCtx| -> AdminReplyFuture {
                Box::pin(connect_reply::<McpServers>(ctx))
            }),
        },
        // The two derived reads contact nothing and audit nothing: `ReadOnly` scope (a GET).
        AdminRouteSpec {
            method: RouteMethod::Get,
            path: "/tools/{name}/changes".to_string(),
            scope: AdminScope::ReadOnly,
            kind: AdminVerbKind::Read,
            handler: std::sync::Arc::new(|ctx: AdminReqCtx| -> AdminReplyFuture {
                Box::pin(crate::mcp::admin_view::changes(ctx))
            }),
        },
        AdminRouteSpec {
            method: RouteMethod::Get,
            path: "/tools/{name}/health".to_string(),
            scope: AdminScope::ReadOnly,
            kind: AdminVerbKind::Read,
            handler: std::sync::Arc::new(|ctx: AdminReqCtx| -> AdminReplyFuture {
                Box::pin(crate::mcp::admin_view::health(ctx))
            }),
        },
    ]
}

/// THE MCP TRUST VERBS' OpenAPI FRAGMENT — the three admin paths keyed absolute, merged into the
/// admin document. Kept beside the routes that answer them so the two cannot drift.
// Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test.
#[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
pub(crate) fn mcp_openapi_fragment() -> serde_json::Value {
    let ap = |rel: &str| format!("{}{rel}", busbar_substrate::api::ADMIN_PREFIX);
    serde_json::json!({
        ap("/tools/{name}/connect"): {
            "post": {
                "summary": "Fetch a registered MCP server's LIVE tool list, hash it, and record the observation. Approves nothing: adopting what was seen is a separate operator act",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (the derived trust state and changes queue; a refresh that landed a quarantine is still a 200 — the drift is in the body)"},
                }
            }
        },
        ap("/tools/{name}/changes"): {
            "get": {
                "summary": "The changes queue for one MCP server, derived from the LAST observation. Contacts nothing",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                }
            }
        },
        ap("/tools/{name}/health"): {
            "get": {
                "summary": "Whether one MCP server currently serves, and why not when it does not",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                }
            }
        }
    })
}

/// THE MCP PLANE'S ADMIN PROJECTION, and the plane's half of the shared trust verb surface —
/// where an MCP registration is resolved from, what looking at one means, and the two derived reads
/// (`changes`, `health`) that contact nothing. `connect` itself is
/// [`busbar_substrate::admin_verbs::connect_reply`], written once for every plane.
pub mod admin_view;
/// THE SEALED `requestState` busbar mints for its OWN asks: HMAC over a payload binding the
/// authenticated principal, the request, the catalogue generation, a round index and a TTL.
/// BUSBAR'S OWN ask of its caller, composed from operator configuration alone.
pub mod callerask;
/// THE DURABLE PER-CALL LOG — one hash-chained record per tool call, written through to the
/// configured store and read back at boot. Separate from the admin audit ring on purpose: see the
/// module header.
pub mod catalogue;
/// The CLIENT direction: busbar calling OUT to external MCP tool servers. The other half of
/// the same governance boundary this module's front door opens — same revision, same trust
/// lifecycle, same scope kinds, opposite initiator.
pub(crate) mod client;
/// THE DURABLE DEMOTION RECORD: what a sweep saw, written through to the configured store and
/// replayed into the sightings cache at boot, so a quarantine outlives the process that took it.
pub(crate) mod demotion;

/// The per-request progress channel: what the CALLER asked to be told, and what the upstream said.
///
/// BUSBAR MINTS ITS OWN TOKEN FOR THE UPSTREAM LEG and maps it back on the way out; it does not
/// forward the caller's. That is the discipline the rest of this plane already follows — busbar
/// publishes the OPERATOR's tool descriptions rather than the upstream's, mints its own
/// `requestState`, and never relays an upstream's ask — and it is the conservative direction here
/// for a concrete reason: a `progressToken` is a caller-CHOSEN opaque value, so forwarding it hands
/// an upstream a correlator for one caller across every call that caller makes.
#[derive(Debug, Default)]
pub(crate) struct ProgressChannel {
    /// The token the CALLER supplied, if any. `None` means the caller asked for no progress — and
    /// busbar then sends no token upstream, because a server MUST NOT emit progress without one.
    pub(crate) caller_token: Option<serde_json::Value>,
    /// Frames the upstream produced, in arrival order, still carrying BUSBAR's minted token.
    pub(crate) frames: Vec<serde_json::Value>,
}

impl ProgressChannel {
    /// The most progress frames busbar retains for one request. A progress stream is UNTRUSTED
    /// upstream input — both wires (`client::stdio`, `client::transport`) push whatever the peer
    /// emits, across every round of a multi-round `tools/call`, into this one request-wide channel —
    /// so it is bounded like the plane's other peer-input surfaces (`MAX_INTERLEAVED_MESSAGES`,
    /// `max_upstream_buffered_bytes`). Without it a peer that streams progress without end grows
    /// busbar's per-request memory without end. Mirrors `MAX_INTERLEAVED_MESSAGES` (256): more than
    /// enough for any real progress UI, few enough that an abusive stream cannot exhaust memory.
    pub(crate) const MAX_FRAMES: usize = 256;

    /// Append one upstream progress frame, DROPPING it past [`Self::MAX_FRAMES`]. The frames kept are
    /// the EARLIEST — a caller's progress UI reads them in order, so retaining the first N and
    /// dropping the tail keeps the run monotonic rather than showing a gap. Over-cap drops are noted
    /// once (latched) so the condition is visible without a per-frame log storm.
    pub(crate) fn push_frame(&mut self, frame: serde_json::Value) {
        if self.frames.len() >= Self::MAX_FRAMES {
            // Debug rather than a coded warn: the plane's warn/error records must carry a diagnostic
            // code and there is none in scope to add one here. Latched to one line per process.
            static OVER_CAP_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !OVER_CAP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::debug!(
                    cap = Self::MAX_FRAMES,
                    "mcp: an upstream produced more progress frames than busbar retains for one \
                     request; the excess is dropped"
                );
            }
            return;
        }
        self.frames.push(frame);
    }
}

tokio::task_local! {
    /// PER-REQUEST slot: `ingress` scopes it, the outbound builder reads the caller's token from it,
    /// the transport appends the upstream's frames to it, and `ingress` drains it when it frames the
    /// answer.
    ///
    /// A task-local rather than a return value, for the same reason `proxy::UPSTREAM_RTT_US` is one:
    /// the frames are produced four layers below the code that emits them (`client::transport` ->
    /// `upstream` -> `inputreq` -> `method` -> `ingress`), and every one of those layers models a
    /// SINGLE JSON-RPC answer. Threading an optional, usually-empty channel through all four would
    /// put a progress-shaped hole in four signatures that have nothing to do with progress.
    ///
    /// Absent outside `ingress`'s scope, where every access is a deliberate no-op.
    pub(crate) static UPSTREAM_PROGRESS: std::sync::Arc<std::sync::Mutex<ProgressChannel>>;
}
pub mod config;
/// THE CONNECT / REFRESH PATH: fetch an upstream's LIVE tool list, re-hash it, and feed the
/// trust lifecycle — the missing right-hand side of the rug-pull comparison. On-demand now, driven by
/// verify-on-call ([`busbar_substrate::trust::verify`]) rather than a boot-time sweep.
pub(crate) mod connect;

/// THIS REVISION'S ENVELOPE RULES. Not `ingress` any more, and the rename is the statement: the
/// ingress SEQUENCE is `busbar_substrate::ingress::protocol`, once, for every JSON-RPC plane. Every rule left
/// in here is a statement about the ENVELOPE — `params._meta`, the mirrored routing headers, the
/// protocol version — which is what its own header said it was all along.
pub mod envelope;
pub(crate) mod inputreq;
pub mod method;
/// The check that keeps the promise `outputSchema` makes. Publishing a schema makes conforming
/// structured results a MUST for the server that published it, and on this plane that server is
/// busbar — while the value itself comes from an upstream that can return whatever it likes.
pub(crate) mod outputschema;
pub(crate) mod reroute;
pub(crate) mod resource;
pub(crate) mod roots;
/// The `sampling/createMessage` SATISFIER and the per-upstream budget it spends — the other
/// operator-declared answer to an upstream's ask, beside `roots`.
pub(crate) mod sampling;
pub(crate) mod sanitize;
/// THE POST's SSE RESPONSE FRAMING and the `notifications/message` records that ride it. This
/// revision removed the GET stream, not Server-Sent Events — see the module header.
pub(crate) mod sse;
/// THE STDIO SERVE MODE: busbar as an MCP server on its own stdin/stdout — the same serve
/// sequence, the same dispatch, a second transport binding. See the module header for the
/// boot-time governance design. `pub`, not `pub(crate)`: the thin `busbar` binary's `main.rs`
/// is the `--mcp-stdio` entry point and lives in a different crate after the core split.
pub mod stdio_serve;
/// `subscriptions/listen` — THE SERVER-TO-CLIENT CHANNEL of this revision. The GET stream was
/// removed and the channel MOVED onto a method; see the module header for why that is not the same
/// thing as the channel being deleted.
pub(crate) mod subscribe;
/// SEP-2663 — the TASKS EXTENSION: `tools/call` answered with a task, then `tasks/get` /
/// `tasks/update` / `tasks/cancel`. See the module header for what is and is not claimed about
/// durability.
pub(crate) mod tasks;
pub(crate) mod upstream;

use serde::{Deserialize, Serialize};

/// The top-level `mcp:` config block. Its mere PRESENCE mounts the MCP plane; its absence means the
/// deployment carries no MCP surface at all — no ingress, no metadata document, nothing added to the
/// route table. A gateway that is not an MCP server should not answer as one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpCfg {
    /// The RFC 8707 resource indicator for this deployment: the canonical, absolute URI that names
    /// busbar's MCP endpoint, and therefore the exact `aud` value every inbound token must carry.
    ///
    /// It is OPERATOR-CONFIGURED rather than derived from the request's `Host`, and that is the
    /// whole point: deriving it from the request would let a caller choose its own audience by
    /// sending a `Host` header, which turns the confused-deputy defence into a formality. It is also
    /// what closes the multi-tenant gap — one deployment, one canonical audience, stated once.
    ///
    /// The MOUNT PATH is derived from this rather than configured separately, so the path a client
    /// posts to and the identifier its token is bound to cannot drift apart.
    pub canonical_uri: String,
    /// RFC 9728 `authorization_servers`: the issuer identifiers of the authorization servers that
    /// may mint tokens for this resource — in practice, the operator's IdP. At least one is
    /// REQUIRED, because this list is the entire content of the answer a credential-less client came
    /// for; an empty one advertises a resource nobody can obtain a token for.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// RFC 9728 `scopes_supported`: the scope values this resource understands. Advisory metadata —
    /// authorization is decided by the caller's grant, never by what this list says.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Browser origins accepted on the MCP ingress, for the `2026-07-28` `Origin` MUST.
    ///
    /// EMPTY IS THE DEFAULT AND IT MEANS "no browser origin is accepted", which is the safe posture
    /// for a server whose clients are agents rather than pages: a request carrying NO `Origin` (every
    /// non-browser client) is unaffected, and a request carrying one is refused unless the operator
    /// listed it. The threat is DNS rebinding — a page on an attacker's origin resolving a name to
    /// busbar's loopback address and driving the tool plane with the user's ambient credentials.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// The VALIDATED MCP resource: `McpCfg` after every derivation and refusal has already happened, so
/// nothing downstream re-parses a URI or re-decides a path.
///
/// Built once at boot. A config that cannot produce one does not boot — an MCP plane that is
/// half-configured is worse than one that is absent, because it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpResource {
    /// The canonical URI verbatim, as configured. THE audience.
    canonical_uri: String,
    /// The path component of `canonical_uri`, normalised to a leading and no trailing slash. The
    /// ingress mount.
    mount_path: String,
    /// The RFC 9728 §3.1 metadata path: `/.well-known/oauth-protected-resource` with the resource's
    /// path INSERTED AFTER it, not before. This is the one detail of RFC 9728 that is easy to get
    /// backwards, and getting it backwards means every compliant client's discovery 404s.
    metadata_path: String,
    /// The absolute form of `metadata_path`, which is what goes in the challenge — a client that has
    /// no credential also has no reason to trust its own reconstruction of our origin.
    metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    allowed_origins: Vec<String>,
}

/// Why an `mcp:` block was refused at boot. Every arm names the field and what a correct value looks
/// like: a boot refusal that does not say what to type is a boot refusal the operator works around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpCfgError {
    /// `canonical_uri` was empty or absent.
    MissingCanonicalUri,
    /// `canonical_uri` was not an absolute `http`/`https` URI.
    CanonicalUriNotAbsolute(String),
    /// `canonical_uri` carried a query or a fragment. RFC 8707 §2 forbids a fragment outright, and a
    /// query would make the identifier depend on parameter ordering — two spellings of one resource
    /// is one spelling too many when the value is compared for equality.
    CanonicalUriHasQueryOrFragment(String),
    /// `canonical_uri` had no path, or only `/`. The resource must be distinguishable from the
    /// deployment's root: mounting the MCP plane at `/` would put it in front of the LLM residual
    /// and claim every path in the process.
    CanonicalUriHasNoPath(String),
    /// `authorization_servers` was empty.
    NoAuthorizationServers,
    /// An `authorization_servers` entry was not an absolute `http`/`https` URI.
    AuthorizationServerNotAbsolute(String),
}

impl std::fmt::Display for McpCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpCfgError::MissingCanonicalUri => write!(
                f,
                "mcp.canonical_uri is required: it is the audience every inbound token must carry \
                 (RFC 8707) and the path the endpoint mounts at. Example: \
                 `canonical_uri: https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriNotAbsolute(v) => write!(
                f,
                "mcp.canonical_uri `{v}` is not an absolute http(s) URI. It is compared for exact \
                 equality against a token's `aud`, so it must be the same absolute string the \
                 authorization server was asked to mint for. Example: \
                 `https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriHasQueryOrFragment(v) => write!(
                f,
                "mcp.canonical_uri `{v}` carries a query or fragment. RFC 8707 resource indicators \
                 carry neither: drop everything from the first `?` or `#`."
            ),
            McpCfgError::CanonicalUriHasNoPath(v) => write!(
                f,
                "mcp.canonical_uri `{v}` has no path. The MCP endpoint needs its own path so it \
                 does not claim the whole deployment. Example: `https://gateway.example.com/mcp`"
            ),
            McpCfgError::NoAuthorizationServers => write!(
                f,
                "mcp.authorization_servers must list at least one issuer. It is the entire content \
                 of the answer a client with no credential comes here for; with none, the `401` it \
                 gets names nowhere to go. Example: \
                 `authorization_servers: [https://login.example.com]`"
            ),
            McpCfgError::AuthorizationServerNotAbsolute(v) => write!(
                f,
                "mcp.authorization_servers entry `{v}` is not an absolute http(s) URI. An issuer \
                 identifier is an absolute URL. Example: `https://login.example.com`"
            ),
        }
    }
}

/// The RFC 9728 §3.1 well-known prefix. The resource's own path is appended AFTER this, per the
/// "path insertion" rule the RFC defines for a resource that is not at an origin root.
const PROTECTED_RESOURCE_WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

impl McpResource {
    /// Validate and derive. Every refusal is fail-closed at BOOT rather than at first request: an
    /// operator finds out from a process that will not start, not from an agent that cannot connect.
    pub fn from_cfg(cfg: &McpCfg) -> Result<Self, McpCfgError> {
        let uri = cfg.canonical_uri.trim();
        if uri.is_empty() {
            return Err(McpCfgError::MissingCanonicalUri);
        }
        let (origin, path) = split_absolute(uri)
            .ok_or_else(|| McpCfgError::CanonicalUriNotAbsolute(uri.to_string()))?;
        if path.contains('?') || path.contains('#') || origin.contains('#') {
            return Err(McpCfgError::CanonicalUriHasQueryOrFragment(uri.to_string()));
        }
        let mount_path = normalise_path(path);
        if mount_path.is_empty() {
            return Err(McpCfgError::CanonicalUriHasNoPath(uri.to_string()));
        }
        if cfg.authorization_servers.is_empty() {
            return Err(McpCfgError::NoAuthorizationServers);
        }
        for issuer in &cfg.authorization_servers {
            if split_absolute(issuer.trim()).is_none() {
                return Err(McpCfgError::AuthorizationServerNotAbsolute(issuer.clone()));
            }
        }
        let metadata_path = format!("{PROTECTED_RESOURCE_WELL_KNOWN}{mount_path}");
        Ok(Self {
            metadata_url: format!("{origin}{metadata_path}"),
            canonical_uri: uri.to_string(),
            mount_path,
            metadata_path,
            authorization_servers: cfg
                .authorization_servers
                .iter()
                .map(|s| s.trim().to_string())
                .collect(),
            scopes_supported: cfg.scopes_supported.clone(),
            allowed_origins: cfg.allowed_origins.clone(),
        })
    }

    /// THE audience. Compared for equality by the verifier; never parsed again.
    pub(crate) fn canonical_uri(&self) -> &str {
        &self.canonical_uri
    }

    /// The ingress mount path (`/mcp` for `https://host/mcp`).
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// The RFC 9728 metadata path this deployment serves the document at.
    pub(crate) fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// The absolute metadata URL, for the `resource_metadata` challenge parameter.
    pub(crate) fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    pub(crate) fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    pub(crate) fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// THE OPERATOR'S BROWSER-ORIGIN ALLOWLIST, as data.
    ///
    /// This used to be `origin_allowed(&self, origin) -> bool` — the DECISION. The decision is now
    /// `busbar_substrate::ingress::protocol::origin_admitted`, made once for every JSON-RPC plane, because
    /// DNS-rebinding is not a fact about MCP: A2A had no `Origin` check at all for as long as this
    /// one was a method here. The plane keeps the DATA and core keeps the verdict, which is
    /// `busbar_substrate::net_guard`'s rule stated for a second concern — a caller keeps its refusal
    /// VOCABULARY, not its DECISION.
    ///
    /// The empty allowlist admits no browser origin, which is the documented default; loopback is
    /// admitted unconditionally by the shared rule, and the argument for that is on it.
    pub(crate) fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// The plane admission facts this resource contributes to the dispatch table: the audience a
    /// token must carry here, and where a refused caller is told to go.
    pub fn admission(&self) -> busbar_substrate::plane::PlaneAdmission {
        busbar_substrate::plane::PlaneAdmission {
            audience: self.canonical_uri().to_string(),
            resource_metadata: self.metadata_url().to_string(),
        }
    }
}

/// Split an absolute `http(s)` URI into `(origin, path)`, or `None` when it is not one.
///
/// Hand-written rather than pulled from a URL crate on purpose: what is needed is a STRICT
/// recogniser for one shape, and a permissive general-purpose parser is the wrong tool for a value
/// whose whole job is to be compared for exact equality. A lenient parse that accepts and normalises
/// `HTTPS://Host:443/mcp` would hand back a string that no longer equals the `aud` the IdP minted.
/// So: recognise, do not normalise.
fn split_absolute(uri: &str) -> Option<(&str, &str)> {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;
    // The authority must be non-empty, must not itself contain a scheme separator, and must not be
    // the whole string's remainder only because the string ended at the scheme.
    let authority_len = rest.find('/').unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let scheme_len = uri.len() - rest.len();
    let split = scheme_len + authority_len;
    Some((&uri[..split], &uri[split..]))
}

/// `/mcp/` -> `/mcp`, `` -> ``, `/` -> ``. The same normalisation
/// core's plane dispatch applies to its mount path, so the derived mount and the dispatch mount are
/// the same string by construction rather than by two functions agreeing.
fn normalise_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

// THE ENGINE BINDING for the plane's test binary: the one module that names the engine crate. Every
// App-needing test below reaches the engine through it (the neutral `testkit::engine_kit` seam).
// Gated on `test-support` alone (never bare `cfg(test)`, where no engine is in the closure): that is
// also the feature a dependent crate's test binary compiles the plane batteries in under
// (`admin_view::adminverbs_tests`), so those reach it too; in that feature-only build its helpers
// read as dead to rustc, which is the compilation mode, not rot.
#[cfg(feature = "test-support")]
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
#[path = "tests/engine.rs"]
pub(crate) mod test_engine;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/config_tests.rs"]
mod config_tests;

// WHAT SURVIVES THE MOMENT THE DEFENCE FIRES: a quarantine across a restart, the sweep that has to
// be STARTED for one to be taken at all, and the demoted upstream that must stop being ADVERTISED
// and not merely stop being dispatchable. Hung here rather than under `connect` or `method` because
// it spans both and the boot path besides.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/quarantine_boot_tests.rs"]
mod quarantine_boot_tests;

#[cfg(test)]
#[path = "tests/progress_cap_tests.rs"]
mod progress_cap_tests;

// THE TRANSPORT-OBSERVED IDENTITY AXIS, MADE REAL: `cert_spki`/`mtls` compared against a peer
// certificate a REAL TLS handshake actually presented, not against the operator's own declared
// value echoed back as its own proof. See the module header.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/transport_pin_tests.rs"]
mod transport_pin_tests;
