// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE: busbar-owned canonical types, and this plane's instantiation of the plane-neutral
//! trust lifecycle.
//!
//! ## The canonical type is ours, and that is a ruling rather than a taste
//!
//! A plane owns ONE canonical internal type: protocol in, canonical type, protocol out. For A2A that
//! type is busbar-owned structs MIRRORING the A2A specification, never a third party's generated
//! wire types. The protocol is versioned and moving, and a generated type would let a specification
//! revision ripple out of the reader and into the registry, the catalogue cache and the audit
//! records. Mirroring contains a revision to the edge.
//!
//! A2A has ONE wire format today, so it earns no superset intermediate representation. The rule is
//! that a plane earns one at its SECOND wire format and not before.
//!
//! ## What this plane does NOT rebuild
//!
//! The trust lifecycle. [`crate::trust`] is the plane-neutral machine, written with the pinned
//! artifact as a type parameter; this plane supplies an artifact ([`pin::CardPin`]) and nothing else.
//! `tests/reuse_tests.rs` drives one transition table over this plane's REAL artifact and a
//! single-value transport pin of the shape the sibling plane offers, so the claim that the machine
//! generalised is a test over production code rather than an assertion nobody can check.

// THE RECEIVING HOT PATH NOW HAS A ROUTER. What used to be a plane-wide `allow(dead_code)` with a
// list of nine unmounted modules in its prose is gone from this file, because the thing it was
// describing is gone: [`ingress`] mounts `GET`/`POST /a2a/agents/{agent_id}` and this plane's RFC
// 9728 metadata document, and a request arriving there is authenticated by the shared middleware
// against [`crate::plane::PlaneAdmission`], authorised by [`inbound::authorize`], filtered by
// [`registry::inbound_catalogue`], attributed by [`meter::Attribution`], recorded through
// [`task`]/[`taskstore`]/[`provenance`], and served through [`serve::rewrite_card`].
//
// AND THE ROUTER NOW RELAYS. [`relay`] is the hop `ingress::invoke` makes to the registered backend
// agent: it guards and pins the target through the SAME `fetch::guard_hop` — and therefore the
// same `crate::net_guard` resolve-then-pin — the card fetch
// uses, RE-ASKS the trust question against the live registry immediately before the socket so a
// mid-flight demotion is not something an in-flight request escapes, presents BUSBAR'S OWN leased
// credential or none, and turns every way the hop can fail into a busbar-attributed error rather
// than a Task envelope for work that never started. A single answer comes back under busbar's task
// identity; a streamed one comes back as SSE, event by event, under the same identity. An INTERRUPT
// comes back as itself and the task is persisted paused, which on an asynchronous plane is the
// NORMAL path rather than an edge case. Every outcome lands on the per-task provenance chain.
//
// AND THE TRUST VERBS ARE REACHABLE. `POST /agents/{name}/connect` is the shared
// [`busbar_substrate::admin_verbs::connect_reply`] mounted over this plane's [`verbs::A2aAgents`], and
// `POST /agents/{name}/approve` is [`verbs::approve`]; together they are what takes a registration
// out of the fail-closed `Pending` its only constructor puts it in. Before that, [`verbs::connect`]
// was written, unit-tested and callable from nothing: `A2aPlane::from_config` rightly refuses to
// lift a declared pin into an approval, so a busbar booted from YAML fronted agents it could never
// serve, and every A2A test in the tree passed while it did. The shape is not merely LIKE the MCP
// plane's — the sequence is literally the same code, which is the only version of "the same shape"
// that cannot drift.
//
// MODULES WITH RESIDUAL SURFACE THAT NO PRODUCTION PATH CALLS still carry their OWN narrowed
// attribute at the top of their own file, stating what is driven and what is not. The residue is
// coherent rather than scattered — it is the trust verbs `connect` did not bring with it (`sync`,
// `suspend`, `resume`), push-notification DELIVERY (registration is live; delivery is not), and the
// task-read verbs.
//
// Narrowing this way is the point. A plane-wide attribute made an unused item ANYWHERE here
// invisible, including in the modules a request now goes through; per-file, a new gap in a mounted
// module is a warning again, and the file that still has one has to say why.

/// THE A2A PLANE'S VOCABULARY DECLARATION, beside the code it describes. Folded into
/// `plane::registry::BUILTIN_PLANE_DECLS`; every field replaces one arm of a `Plane::A2a` `match`.
///
/// `wire_format_names` is THREE BINDINGS OF ONE AGENT, ordered so the first is the canonical one:
/// the JSON-RPC envelope (which a door refusal is shaped in), HTTP+JSON, and the gRPC service.
/// `serve::servable_bindings` reads this list to decide what a served card may advertise, and its
/// length (> 1) is what earns this plane a superset IR and denies it a `sole_wire_format`.
pub(crate) const PLANE_DECL: crate::plane::registry::PlaneDecl =
    crate::plane::registry::PlaneDecl {
        key: "a2a",
        config_section: "agents",
        scope_kinds: &["agent"],
        subject_noun: "fronted agent",
        audit_kind: "a2a_agent",
        wire_format_names: || {
            &[
                crate::plane::WIRE_JSONRPC,
                crate::plane::WIRE_HTTP_JSON,
                crate::plane::WIRE_GRPC,
            ]
        },
        // THE A2A DOOR — TWO claims, and only when the plane has a RECEIVING side. `/a2a` (canonical,
        // JSON-RPC, the dialect a door refusal is shaped in) and the gRPC service
        // `/lf.a2a.v1.A2AService`, whose path the vendored `.proto` dictates and a gRPC client cannot
        // be pointed off of — so it is claimed here or it is a path where no token's `aud` is
        // checked. Both claims are gated on `admission().is_some()`: a delegation-only deployment
        // (no `public_url`) fronts nothing, mounts nothing, and binds no audience.
        claims: |slot| {
            let p = slot
                .downcast_ref::<crate::a2a::plane::A2aPlane>()
                .expect("the a2a plane's dispatch slot is an A2aPlane");
            if p.admission().is_some() {
                vec![
                    (
                        crate::a2a::serve::MOUNT_PATH.to_string(),
                        crate::plane::WIRE_JSONRPC,
                    ),
                    (
                        crate::a2a::serve::GRPC_MOUNT_PATH.to_string(),
                        crate::plane::WIRE_GRPC,
                    ),
                ]
            } else {
                Vec::new()
            }
        },
        admission: |slot| {
            let p = slot
                .downcast_ref::<crate::a2a::plane::A2aPlane>()
                .expect("the a2a plane's dispatch slot is an A2aPlane");
            p.admission()
        },
        // THE A2A SLOT: lowered from `agent_defs:`/`public_url` through the SAME `from_config` the
        // dispatch table and the re-verification job's registry are lowered from, so the object this
        // seam erases and the object every other A2A consumer reads are one lowering, not two. `None`
        // when no agent is configured — the absence `crate::a2a::runtime` reports, and NOT the same
        // condition as `admission().is_none()` (a delegation-only plane has a slot but claims/admits
        // nothing).
        build: |ctx| {
            // The registry crosses `BuildCtx` type-erased; downcast it back HERE, inside the plane.
            let agent_defs = ctx
                .agent_defs
                .downcast_ref::<crate::a2a::config::AgentsCfg>()
                .expect(
                    "BuildCtx::agent_defs carries an AgentsCfg when the A2A plane is compiled in",
                );
            crate::a2a::plane::A2aPlane::from_config(agent_defs, ctx.public_url)
                .map(|p| p as std::sync::Arc<dyn std::any::Any + Send + Sync>)
        },
        // S7: A2A contributes its data routes through the NEUTRAL `routes` seam (like MCP). Its
        // handlers ({well_known_card, card, agent_rpc, plane_rpc, push_notification, grpc::serve,
        // metadata_route} + the REST family) are neutral async fns over `PlaneReqCtx`, no longer
        // extracting `axum::State<Arc<AppHandle>>`.
        routes: Some(crate::a2a::receive::a2a_routes),
        admin_routes: Some(admin_routes),
        openapi: Some(openapi_fragment),
        config_validate: Some(a2a_config_validate),
        card_signing_domain: Some(crate::a2a::sign::CARD_SIGNING_DOMAIN),
        card_kid_prefix: Some(crate::a2a::sign::CARD_KID_PREFIX),
        named_def_list: Some(crate::a2a::admin_view::list),
        named_def_get: Some(crate::a2a::admin_view::get),
        registry_contains: Some(crate::a2a::admin_view::contains),
        reresolve_gates: Some(crate::a2a::admin_view::reresolve_gates),
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: Some(crate::a2a::admin_view::openapi_schemas),
        hydrate: Some(a2a_hydrate),
        start: Some(a2a_start),
        parse_section: Some(a2a_parse_section),
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        retain_verify_gates: Some(a2a_retain_verify_gates),
        default_section: Some(a2a_default_section),
        // NOTHING TO CARRY ACROSS A SWAP. The A2A plane's runtime object (`A2aPlane`) is rebuilt from
        // `agents:`/`public_url` on every apply, and its durable task table is restored at boot
        // through `hydrate`, not reconciled here — so there is no engine-owned live object that
        // outlives an apply for this seam to carry.
        on_swap: None,
    };

/// VALIDATE ONE `agents:` NAMED-DEFINITION DOCUMENT — the A2A plane's half of
/// [`crate::plane::registry::PlaneDecl::config_validate`]. Parses the raw document into
/// [`crate::a2a::config::AgentDefCfg`] (`deny_unknown_fields`, refusing a typo'd key HERE exactly as
/// the file refuses it) and applies the same value rules boot applies through the identical
/// [`crate::a2a::config::validate_agent`]. Naming `crate::a2a` types HERE is correct: this is the A2A
/// plane's own module, and it is what lets `config::named_map` validate an `agents:` write without
/// doing so.
fn a2a_config_validate(name: &str, def: &serde_json::Value) -> Result<(), String> {
    let cfg: crate::a2a::config::AgentDefCfg = serde_json::from_value(def.clone())
        .map_err(|e| format!("invalid `agents.{name}` definition: {e}"))?;
    crate::a2a::config::validate_agent(name, &cfg)
}

/// PARSE THE `agents:` SECTION through the A2A plane's own `Deserialize` — the
/// [`crate::plane::registry::PlaneDecl::parse_section`] hook, so `DeployCfg` deserializes its
/// `agents:` field without naming [`crate::a2a::config::AgentsCfg`]. The `serde_yaml::Value`
/// intermediate carries no source position, so the plane's own `split_section` / passthrough refusals
/// reach the operator by their SENTENCE, the `at line`/`column` suffix aside.
fn a2a_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn crate::plane::config::PlaneCfg>, String> {
    serde_yaml::from_value::<crate::a2a::config::AgentsCfg>(v.clone())
        .map(|c| Box::new(c) as Box<dyn crate::plane::config::PlaneCfg>)
        .map_err(|e| e.to_string())
}

/// [`crate::plane::registry::PlaneDecl::default_section`] hook — the empty `agents:` registry, so an
/// ABSENT section defaults to `AgentsCfg::default()` byte-identically to the pre-seam typed field.
fn a2a_default_section() -> Box<dyn crate::plane::config::PlaneCfg> {
    Box::<crate::a2a::config::AgentsCfg>::default()
}

/// PRUNE THE A2A VERIFY-ON-CALL GATES to the agents THIS generation fronts — the
/// [`crate::plane::registry::PlaneDecl::retain_verify_gates`] hook. UNCONDITIONAL: when the operator
/// removes the `agents:` block the live set is EMPTY, so retain drops every carried flight/latch
/// instead of leaking one per removed agent. Byte-identical to the old inline `appbuild` arm.
fn a2a_retain_verify_gates(slots: &dyn busbar_substrate::plane_host::PlaneSlots) {
    // A2A is still IN CORE, so its twin recovers the concrete snapshot for `a2a_verify` (not a
    // `plane_slots` entry) through the neutral seam's `as_any` hatch — byte-identical to the old
    // `&App` arm once recovered.
    let app = slots
        .as_any()
        .downcast_ref::<crate::state::App>()
        .expect("the a2a retain_verify_gates hook is handed an App snapshot");
    let live: std::collections::HashSet<String> = crate::a2a::runtime(app)
        .map_or_else(std::collections::HashSet::new, |plane| {
            plane.with_registrations(|regs| regs.iter().map(|r| r.agent_id.clone()).collect())
        });
    app.a2a_verify.retain(&live);
}

/// THE RESOLVED `agents:` REGISTRY for this generation, downcast back HERE from the opaque
/// [`crate::state::App::agent_defs`] handle — so core outside this module names no
/// `crate::a2a::config` type and the A2A plane reads the SAME resolved `AgentsCfg` the composition
/// root erased (a clone, never a reparse). The downcast never fails under `plane-a2a`: `App::agent_defs`
/// always carries an `AgentsCfg` in that build (`appbuild` erases exactly `RootCfg::agent_defs`, which
/// is `AgentsCfg` with the plane compiled in).
pub(crate) fn agent_cfg(app: &crate::state::App) -> &crate::a2a::config::AgentsCfg {
    app.agent_defs
        .downcast_ref::<crate::a2a::config::AgentsCfg>()
        .expect("App::agent_defs carries an AgentsCfg when the A2A plane is compiled in")
}

/// THE A2A RUNTIME OBJECT for this config generation, read through the TYPE-ERASED `plane_slots`
/// seam ([`crate::state::App::plane_slot`]) and downcast back to [`crate::a2a::plane::A2aPlane`]
/// HERE, inside the plane — so core OUTSIDE this module reaches the plane only as an opaque
/// `Arc<dyn Any>` slot and names no `crate::a2a` type. `None` exactly when `agents:` is not
/// configured this generation (the plane contributed no slot — the same absence the deleted
/// `App::a2a: None` used to encode). The downcast never fails: the a2a slot is always an `A2aPlane`
/// (`PLANE_DECL::build`). The exact byte-analog of `crate::mcp::resource`; A2A carries ONE object,
/// so this single accessor is its whole runtime seam.
pub(crate) fn runtime(app: &crate::state::App) -> Option<&crate::a2a::plane::A2aPlane> {
    app.plane_slot(PLANE_DECL.key).map(|slot| {
        slot.downcast_ref::<crate::a2a::plane::A2aPlane>()
            .expect("the a2a plane's dispatch slot is an A2aPlane")
    })
}

/// The OWNED-`Arc` twin of [`runtime`], for the callers that need the plane to OUTLIVE the `App`
/// snapshot borrow it was read from (a moved snapshot guard, or a value carried past the borrow).
/// Clones the SAME `Arc` `plane_slots` holds (a refcount bump, not a second construction). `None`
/// and the never-fail downcast have the same meaning as [`runtime`]. The byte-analog of
/// `crate::mcp::resource_arc`.
pub(crate) fn runtime_arc(
    app: &crate::state::App,
) -> Option<std::sync::Arc<crate::a2a::plane::A2aPlane>> {
    app.plane_slot(PLANE_DECL.key).map(|slot| {
        slot.clone()
            .downcast::<crate::a2a::plane::A2aPlane>()
            .expect("the a2a plane's dispatch slot is an A2aPlane")
    })
}

/// THE HOST TWIN of [`runtime_arc`] — the A2A plane's runtime object off the host's BOUND snapshot,
/// read through the neutral [`busbar_substrate::plane_host::EngineHost::plane_slot`] seam so the
/// trust-verb `resolve` reaches it without `&Arc<App>`. Owned `Arc` (the host returns an owned clone);
/// `None` exactly when `agents:` is not configured this generation, the same absence `runtime_arc`
/// encodes off `&App`.
pub(crate) fn runtime_arc_of(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> Option<std::sync::Arc<crate::a2a::plane::A2aPlane>> {
    host.plane_slot(PLANE_DECL.key).map(|slot| {
        slot.downcast::<crate::a2a::plane::A2aPlane>()
            .expect("the a2a plane's dispatch slot is an A2aPlane")
    })
}

/// RESTORE THE A2A PLANE'S DURABLE TASK STATE, BEFORE a listener binds. A2A is ASYNC BY DESIGN: a
/// task spans turns, can be interrupted waiting on a human, and can outlive the process that started
/// it — an in-memory task table loses every in-flight task on restart, which is the difference between
/// a suspend/resume that is real and one that is nominal. The task store is a PLANE, so it is handed
/// the plane-narrowed `Arc<dyn PlaneStore>` (task/provenance methods only), never the `Store` that
/// also carries `append_audit`. With `store: memory` `ctx.store` is `None` and in-flight tasks are
/// ephemeral BY DESIGN, exactly as the audit ring is.
use crate::diagnostics::{
    diag_error, diag_warn, A2A_TASK_CHAIN_VERIFY_FAILED, A2A_TASK_ROWS_UNREADABLE,
    A2A_TASK_STATE_UNREAD,
};

pub(crate) fn a2a_hydrate(ctx: &crate::plane::registry::BootCtx) -> Result<(), String> {
    let Some(plane_store) = ctx.store.clone() else {
        return Ok(());
    };
    let app = ctx
        .app
        .expect("a2a hydrate runs in the HYDRATE phase, which supplies the freshly-built app");
    // REGISTER the durable `task_event` stream FIRST — the host attaches its own sink from
    // `app.governance` (the same plane-narrowed store) at register time, so the host-side chain and the
    // task-row upserts reach one backend. THEN attach the row-upsert sink and rehydrate through the
    // seam, opening a dispatch scope so the caller-driven `seed` reaches the host over a live `HostCtx`.
    crate::plane::taskstore::register_task_event_stream(app);
    crate::plane::taskstore::TASKS.set_sink(plane_store.clone());
    let restored = crate::plane_host::with_dispatch_scope(app, |host, _vt| {
        crate::plane::taskstore::TASKS.restore_from_store(host, plane_store.as_ref())
    });
    match restored {
        Ok(r) if r == crate::plane::taskstore::Rehydrated::default() => {}
        Ok(r) => {
            tracing::info!(
                active = r.active,
                terminal = r.terminal,
                unreadable = r.unreadable,
                "A2A in-flight tasks rehydrated from the durable governance store"
            );
            // An UNREADABLE row is an in-flight task that this binary cannot resume. Reported
            // separately and at WARN, because summing it into the restored count is how a task that
            // silently ceased to exist across a deploy stays invisible.
            if r.unreadable > 0 {
                diag_warn!(
                    A2A_TASK_ROWS_UNREADABLE,
                    rows = r.unreadable,
                    "persisted A2A task rows could not be read back and are NOT resumable; \
                     they were most likely written by a different engine version"
                );
            }
            // A chain break is TAMPER EVIDENCE and is a different event from a read hiccup, so it is
            // logged at ERROR and names the task rather than being folded into a count.
            for brk in &r.chain_breaks {
                diag_error!(
                    A2A_TASK_CHAIN_VERIFY_FAILED,
                    task_id = %brk.scope,
                    break_detail = %brk,
                    "A2A per-task provenance CHAIN VERIFICATION FAILED on restore"
                );
            }
        }
        Err(e) => diag_warn!(
            A2A_TASK_STATE_UNREAD,
            error = %e,
            "could not read durable A2A task state; in-flight tasks start empty"
        ),
    }
    Ok(())
}

/// ARM A2A VERIFY-ON-CALL, after the listeners are built. An approval is a statement about a document
/// at a moment and nothing keeps it true; the pin catches a change only when somebody looks, and under
/// verify-on-call the somebody is the DELEGATION itself, not a background job. This hook runs ONCE at
/// boot, only when `agents:` defines a plane: it resolves the outbound client identities ONCE — an
/// identity that does not resolve is a boot REFUSAL (the returned `Err`), never a warning — publishes
/// busbar's PUBLIC card-issuer key, builds the per-agent card transports once, and hands that one
/// transport to BOTH the delegation hop (the plane's relay seam) and verify-on-call (the app's
/// `a2a_cards`). There is no sweep loop to spawn: a fronted agent nobody delegates to is never
/// re-fetched, and one that is delegated to is re-verified on the call path within its `verify_ttl`.
pub(crate) fn a2a_start(ctx: &crate::plane::registry::BootCtx) -> Result<(), String> {
    let handle = ctx
        .handle
        .expect("a2a start runs in the START phase, which supplies the live app handle");
    let app = handle.load();
    if let Some(plane) = crate::a2a::runtime_arc(&app) {
        tracing::info!(
            agents = plane.len(),
            "a2a: verify-on-call is armed — fronted agents are re-verified on the delegation path \
             within their `verify_ttl`, single-flight and fail-closed, with no background sweep"
        );
        // PUBLISH BUSBAR'S AGENT-CARD ISSUER KEY, once, at the one moment an operator is watching.
        // busbar signs the cards it serves so external callers have something to pin it BY, and a pin
        // is only a root if the pinning party got the key OUT OF BAND — which means a human has to be
        // able to read it off this deployment. It is a PUBLIC key, so a log line is the right place;
        // the secret it is derived from never appears here (the seam handed only the public half — see
        // `BootCtx::card_issuer`). Logged beside the plane's start rather than at key resolution,
        // because this value only means anything where an A2A plane is actually serving cards.
        if let Some(issuer) = ctx.card_issuer.as_ref() {
            // STASH the public issuer key on the plane's OWN slot, so `sign::card_signer` reads it
            // here rather than off `app.governance` — the route-through that lets the extracted plane
            // name no `GovState`. Public material only; the signing seed stays host-side and is reached
            // through `plane_host::card_sign_over`.
            plane.set_card_issuer(issuer.clone());
            tracing::info!(
                kid = %issuer.kid,
                issuer_key = %issuer.issuer_spki_base64,
                "a2a: agent cards served by this deployment are signed with this key; give it to \
                 callers out of band so they can pin busbar"
            );
        }
        // THE OUTBOUND CLIENT CERTIFICATES, resolved ONCE, HERE, and fatal if they do not. Same
        // discipline as `tls::build_server_config` on the inbound side: a cert/key that does not load
        // is a startup failure naming its source, never a warning. A registration whose
        // `client_identity:` did not resolve could never complete a handshake with its endpoint, so
        // booting past it would produce a deployment that re-verifies nothing for that agent while
        // reading, in config and in the admin API, as though mutual TLS were configured.
        let a2a_identities = crate::a2a::transport::resolve_client_identities(
            crate::a2a::agent_cfg(&handle.load()),
            &handle.load().secret_resolver,
        )
        .map_err(|e| format!("a2a: outbound client identity: {e}"))?;
        // THE PER-AGENT TRANSPORTS, BUILT ONCE at boot. The identities were resolved just above (a
        // failure is a boot refusal), and a transport now carries a private key, so building the
        // bundle once and holding it is what keeps that key material out of a per-request rebuild.
        let live = std::sync::Arc::new(crate::a2a::transport::LiveCardFetch::presenting(
            plane.fetch_policy().clone(),
            &a2a_identities,
        ));
        // PUBLISHED FOR VERIFY-ON-CALL to re-fetch a stale card with. It carries the per-agent CLIENT
        // IDENTITIES the card verification (`pin.mechanism: mtls`) needs, which the plane's own relay
        // seam — built at `from_config` before secrets resolve — deliberately does not: the delegation
        // HOP authenticates with a leased bearer and needs no client certificate, so the two transports
        // are separate exactly as they were when the sweep held its own. Set into the app's
        // boot-resolved `OnceLock` (carried across every config apply), so the request path always has
        // a transport to re-verify with. There is no sweep to spawn: verify-on-call is lazy and runs on
        // the delegation path, so a fronted agent nobody delegates to is never re-fetched.
        let _ = app.a2a_cards.set(live);
    }
    Ok(())
}

/// CONTRIBUTE THE A2A TRUST VERBS to the Admin API v1 router, beside their MCP siblings so the two
/// planes' operator surfaces are read together. Without these the `agents:` surface is CRUD only,
/// every registration stays `Pending`, and no sequence of operator actions can make a fronted agent
/// serve. `connect` is the shared plane verb; `approve` locks a registration to a seen fingerprint.
pub(crate) fn admin_routes(
    _slot: &dyn std::any::Any,
) -> Vec<busbar_substrate::admin_verbs::AdminRouteSpec> {
    use busbar_plugin::cold::http_endpoint::RouteMethod;
    use busbar_substrate::admin_verbs::{
        connect_reply, AdminReplyFuture, AdminReqCtx, AdminRouteSpec, AdminScope, AdminVerbKind,
    };
    vec![
        // `connect` is the SHARED audited verb (resolve, look; the core adapter records the row).
        AdminRouteSpec {
            method: RouteMethod::Post,
            path: "/agents/{name}/connect".to_string(),
            scope: AdminScope::Full,
            kind: AdminVerbKind::Audited { verb: "connect" },
            handler: std::sync::Arc::new(|ctx: AdminReqCtx| -> AdminReplyFuture {
                Box::pin(connect_reply::<crate::a2a::verbs::A2aAgents>(ctx))
            }),
        },
        // `approve` is an AUDITED WRITE that carries a body and its own condition-tagged envelope: it
        // builds the response and records its own audit row, so it returns `AdminReply::Prebuilt` and
        // the core adapter passes it through verbatim. `Full` scope (a POST that moves a registration
        // into service).
        AdminRouteSpec {
            method: RouteMethod::Post,
            path: "/agents/{name}/approve".to_string(),
            scope: AdminScope::Full,
            kind: AdminVerbKind::Audited { verb: "approve" },
            handler: std::sync::Arc::new(|ctx: AdminReqCtx| -> AdminReplyFuture {
                Box::pin(crate::a2a::verbs::approve(ctx))
            }),
        },
    ]
}

/// THE A2A TRUST VERBS' OpenAPI FRAGMENT — the two admin paths keyed absolute, merged into the admin
/// document. Kept beside the routes that answer them so the two cannot drift.
// Read only by the OpenAPI generator (feature `openapi-schema`) and the non-vacuity floor test.
#[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
pub(crate) fn openapi_fragment() -> serde_json::Value {
    let ap = |rel: &str| format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
    serde_json::json!({
        ap("/agents/{name}/connect"): {
            "post": {
                "summary": "Fetch a registered agent's card, verify it against the operator's out-of-band root, and report the fingerprint. Approves nothing and writes nothing",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (the derived trust state and the fingerprint a human is being asked to approve; a card that could not be authenticated is still a 200 — the reason is in `failure` and the state is `error`)"},
                }
            }
        },
        ap("/agents/{name}/approve"): {
            "post": {
                "summary": "Lock a registered agent to the card fingerprint the operator has SEEN. The card is re-fetched and re-verified, and an approval naming any other fingerprint is refused",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (the registration's state AFTER the approval, read off the live registry)"},
                }
            }
        }
    })
}

pub(crate) mod admin_view;
pub(crate) mod anomaly;
pub(crate) mod canonical;
pub(crate) mod card;
pub(crate) mod config;
pub(crate) mod creds;
pub(crate) mod fetch;
pub(crate) mod grpc;
pub(crate) mod idmap;
pub(crate) mod inbound;
pub(crate) mod jws;
pub(crate) mod local;
pub(crate) mod meter;
/// THE HOPS BUSBAR ORIGINATES ITSELF, on verbs `local` also answers: the callback substitution and
/// the task-list poll. One relay, one egress gate, one framing lookup — see the module header.
pub(crate) mod originate;
pub(crate) mod pin;
pub(crate) mod plane;
/// BUSBAR'S OWN CALLBACK, the one it registers with a BACKEND so the backend never learns the
/// caller's. The substitution [`pushdeliver`] delivers the other half of.
pub(crate) mod pushback;
pub(crate) mod pushdeliver;
pub(crate) mod pushnotify;
/// THE RECEIVING HOT PATH. Not `ingress` any more, and the rename is the statement: the ingress
/// SEQUENCE is `crate::ingress::protocol`, once, for every JSON-RPC plane. What is in here is what
/// was left when it moved out — this plane's method vocabulary, its verb dispatch and its refusal
/// wording.
pub(crate) mod receive;
pub(crate) mod registry;
pub(crate) mod relay;
/// The plane's HTTP+JSON binding — the SECOND wire format, re-framed onto `ingress`'s one sequence.
pub(crate) mod rest;
pub(crate) mod route;
pub(crate) mod rpcerror;
/// THIS PLANE'S REFUSAL VOCABULARY: `A2aWords`, the total match that gives every refusal
/// `crate::ingress::protocol` decides a sentence in A2A's own error envelope, plus the three facts
/// of its RFC 9728 document.
pub(crate) mod words;
// THE CADENCE MOVED, and the plane keeps its spelling. `super::reverify::…` still resolves, so no
// call site in this plane changed — but there is now exactly ONE cadence in the tree and the MCP
// refresh timer drives the same `due` this one does. See the standing rule: unify the duplicate
// before a second copy can drift from the first.
pub(crate) use busbar_substrate::trust::reverify;
pub(crate) mod serve;
pub(crate) mod sign;
pub(crate) mod spki;
pub(crate) mod task;
pub(crate) mod transport;
pub(crate) mod verbs;
pub(crate) mod verify;
