// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-voice — the DUPLEX / LIVE-VOICE plane (Plane 4), as ONE plugin crate. SKELETON.
//!
//! WHAT THIS CRATE HOLDS TODAY. The plane's DECLARATIONS — [`PLANE_DECL`] (a
//! [`busbar_substrate::plane::registry::PlaneDecl`]) and [`DECLS`] (a
//! [`busbar_substrate::proto::ProtocolDecl`] with `codec: None`, one dialect `openai_realtime`) — plus
//! the plane's OWN four-layer duplex/session IR as TYPE STUBS ([`ir`]). There is no pump, no
//! reader/writer body, no session store yet: this is the skeleton the P2 build (see
//! `docs/design/plane4-duplex-session.md` §8) fills in.
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-mcp` / `busbar-a2a` state: nothing in `busbar-core`
//! names this crate. Everything the plane consumes from the engine comes through the neutral
//! `busbar-substrate` surface (+ `busbar-api`); the `busbar` BINARY — the composition root — is what
//! links it and hands [`PLANE_DECL`] / [`DECLS`] to the registry installers at boot. The neutral crates
//! do NOT change to accept it, and the crate is strong-form DELETABLE (`git rm -r crates/busbar-voice`
//! leaves the neutral crates compiling) — proven by `scripts/plane-delete-test.sh voice`.
//!
//! `codec: None` (§1.4): while OpenAI Realtime is the ONLY dialect the plane earns no cross-dialect
//! superset IR — its IR is its OWN, a busbar-owned mirror. The superset is earned at the SECOND dialect
//! (Gemini Live), exactly as A2A earns one at its second wire format and not before.

pub mod ir;

// THE T2 LIVE-SESSION RUNTIME + both topologies — behind the `runtime` cargo feature (OFF by default,
// HARD RULE 4). The default / prod build compiles the skeleton IR + declarations only; turning the
// feature on compiles the duplex session pump, the D2 metering lease, the durable `SessionScope`
// binding, and the browser-sideband / telephony topologies. Voice stays dev-only until DoD.
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "runtime")]
pub mod topology;

/// THE `PLANE_DECL.build_runtime` VALUE — wired to the real runtime constructor
/// ([`runtime::build_runtime`]) behind the `runtime` feature, `None` in the default skeleton build so
/// the prod `PLANE_DECL` is byte-unchanged (voice stays dev-only until DoD). Split by `cfg` because the
/// `runtime` module (and its constructor) only exist behind the feature.
// `type_complexity`: this fn-pointer is the mirror of the frozen `PlaneDecl::build_runtime` field type
// (`busbar_substrate::plane::registry`), which carries the SAME `#[allow(clippy::type_complexity)]` — the
// shape is the ABI, not a factorable local type.
#[cfg(feature = "runtime")]
#[allow(clippy::type_complexity)]
const VOICE_BUILD_RUNTIME: Option<
    fn(
        &dyn std::any::Any,
        Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
    ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
> = Some(runtime::build_runtime);
#[cfg(not(feature = "runtime"))]
#[allow(clippy::type_complexity)]
const VOICE_BUILD_RUNTIME: Option<
    fn(
        &dyn std::any::Any,
        Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
    ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
> = None;

/// THE DIALECT NAME this plane speaks first — OpenAI's bidirectional Realtime voice API. Named once
/// here; it is the [`DECLS`] registry key and the plane's sole [`PLANE_DECL`] wire format (one
/// dialect ⇒ no superset IR yet).
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// THE ONE WIRE FORMAT this plane translates today: just the one dialect. Its length (== 1) is what
/// denies this plane a superset IR (`Plane::has_superset_ir` is DERIVED from this list's length), the
/// A2A discipline — a plane earns a superset at its SECOND wire format and not before.
const VOICE_WIRE_FORMATS: &[&str] = &[OPENAI_REALTIME];

/// THE VOICE PLANE'S DECLARATION — a `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_voice::PLANE_DECL`). SKELETON: it declares the plane's
/// identity (key, config section, audit kind, wire format) and returns EMPTY/`None` from every runtime
/// hook — it mounts nothing, admits no one, and builds no runtime object yet. The neutral registry
/// unions this without naming it (the MCP/A2A precedent).
pub const PLANE_DECL: busbar_substrate::plane::registry::PlaneDecl =
    busbar_substrate::plane::registry::PlaneDecl {
        key: "voice",
        // A MOUNTED plane, not the fallback catch-all.
        fallback: false,
        config_section: "voice",
        // One session is granted at the whole-session granularity.
        scope_kinds: &["session"],
        subject_noun: "voice session",
        admin_noun: "voice-session",
        audit_kind: "voice_session",
        // ONE dialect ⇒ no superset IR (see VOICE_WIRE_FORMATS).
        wire_format_names: || VOICE_WIRE_FORMATS,
        // SKELETON: the plane mounts nothing, admits no one, and builds no runtime object yet — the
        // pump / session-open through `run_gauntlet_session` is the P2 build (§8).
        claims: |_slot| Vec::new(),
        admission: |_slot| None,
        build: |_ctx| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        // RUNTIME HOOK — wired to the real per-generation runtime constructor behind the `runtime`
        // feature (see [`VOICE_BUILD_RUNTIME`]); `None` in the default skeleton build so the prod build
        // is byte-unchanged. The remaining runtime hooks (`build` / `hydrate` / `start` /
        // `parse_section` / `default_section`) stay `None`: they need the plane's config-section grammar
        // and the host metering-lease seam, both outside this crate's scope (see the T2 report).
        build_runtime: VOICE_BUILD_RUNTIME,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
    };

/// THE VOICE PLANE'S PROTOCOL DECLARATION — a `ProtocolDecl` with `codec: None` and ONE dialect
/// (`openai_realtime`), re-exported at the crate root so the `busbar` binary names one stable path
/// (`busbar_voice::DECLS`). Like MCP, it declares NO codec: its IR is its own (the [`ir`] module),
/// there is no cross-dialect translation into or out of it while it speaks one dialect.
///
/// SKELETON: `handler: None` and `verbs: &[]` — the duplex handler / gauntlet-session entry is the P2
/// build. Every other field carries the neutral default a codec-less protocol declares (the MCP
/// `DECL` shape).
pub static DECLS: busbar_substrate::proto::ProtocolDecl = busbar_substrate::proto::ProtocolDecl {
    name: OPENAI_REALTIME,
    // ITS IR IS ITS OWN (§1.4): no cross-dialect codec while one dialect is spoken.
    codec: None,
    // SKELETON: no request handler yet — the duplex pump / session entry is P2.
    handler: None,
    // SKELETON: no verbs declared yet (the long-lived Subscribe/Control shapes arrive with the pump).
    verbs: &[],
    head_keys: &[],
    streaming_content_type: None,
    array_stream_shim_key: None,
    native_tool_id_prefix: None,
    ingress_auth: busbar_substrate::proto::IngressAuth::Bearer,
    egress_auth_headers: None,
    egress_auth_lane_constant: false,
    stream_usage_requires_opt_in: false,
    // Promoted writer facts: this plane declares no cross-dialect codec and has no writer, so every
    // promoted fact is the `ProtocolWriter` trait DEFAULT — the same values the codec-less MCP `DECL`
    // states. Inert for a `codec: None` protocol, but the declaration must state them.
    requires_max_tokens: false,
    stop_sequence_cap: None,
    cache_markers_model_gated: false,
    fills_thought_signature: false,
    frame_after_message_start: None,
    reshapes_body_at_path_base: false,
    max_cache_control_breakpoints: None,
    quota_exceeded_status: axum::http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: false,
    max_citations_per_delta: None,
    egress_user_agent: busbar_substrate::proxy::EGRESS_UA_DEFAULT,
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        axum::http::StatusCode::UNAUTHORIZED,
        busbar_substrate::proto::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: "authentication failed",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    egress_stream_accept: busbar_substrate::proxy::TEXT_EVENT_STREAM,
    models_list_envelope: None,
    // Identified by its EXPLICIT mount, never by a wire fingerprint — so it claims no router or
    // residual rung, contributes no vendor response metadata, and is not the residual default.
    claims: None,
    residual_claims: None,
    residual_default: false,
    vendor_response_metadata: None,
    list_models_fingerprint_headers: &[],
};
