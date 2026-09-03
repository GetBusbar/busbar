// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-voice — the DUPLEX / LIVE-VOICE plane (Plane 4), as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS. The plane's DECLARATIONS — [`PLANE_DECL`] (a
//! [`busbar_substrate::plane::registry::PlaneDecl`]) and [`DECLS`] (a
//! [`busbar_substrate::proto::ProtocolDecl`] with `codec: None`) — plus the plane's OWN four-layer
//! duplex/session IR ([`ir`]) and BOTH dialect codecs (OpenAI Realtime + Gemini Live). The live pump,
//! reader/writer bodies, and session store are implemented in [`runtime`] behind the `runtime` feature
//! (see `docs/design/plane4-duplex-session.md` §8). Boot-mounting that runtime into the composition
//! root (route / admission / handler wiring) is separate, tracked work — see [`PLANE_DECL`].
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-mcp` / `busbar-a2a` state: nothing in `busbar-core`
//! names this crate. Everything the plane consumes from the engine comes through the neutral
//! `busbar-substrate` surface (+ `busbar-api`); the `busbar` BINARY — the composition root — is what
//! links it and hands [`PLANE_DECL`] / [`DECLS`] to the registry installers at boot. The neutral crates
//! do NOT change to accept it, and the crate is strong-form DELETABLE (`git rm -r crates/busbar-voice`
//! leaves the neutral crates compiling) — proven by `scripts/plane-delete-test.sh voice`.
//!
//! THE SUPERSET IR, EARNED (`plane4-duplex-session.md` §1.4). With TWO dialects — OpenAI Realtime and
//! Gemini Live — the plane earns a cross-dialect superset IR: a neutral vocabulary both codecs read and
//! write, so `Plane::has_superset_ir("voice")` is true — DERIVED from the length-2 `VOICE_WIRE_FORMATS`
//! (the A2A rule: a plane earns a superset at its SECOND wire format and not before). The plane realizes
//! that superset as its OWN shared IR types ([`ir`]), not the LLM-style `DialectCodec` facade, so
//! [`DECLS`] stays `codec: None` exactly as MCP / A2A do.

pub mod ir;

/// THE `streams:` CONFIG SECTION — the voice plane's owned config grammar ([`config::StreamsCfg`]) and
/// its `parse_section` / `default_section` seam hooks. UNCONDITIONAL (outside the `runtime` gate):
/// the plane DECLARES and PARSES `streams:` even in the default feature-off build, so config validation
/// reaches the owned grammar whether or not the live session pump is compiled in.
pub mod config;

pub mod diagnostics;

/// THE VOICE PLANE'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the
/// composition root installs via `busbar_substrate::diagnostics::install_diagnostics`, re-exported at
/// the crate root so the `busbar` binary names one stable path (`busbar_voice::DIAGNOSTICS`), exactly
/// as `busbar_mcp::DIAGNOSTICS` / `busbar_a2a::DIAGNOSTICS`. Not yet booted by the binary — voice
/// joins `register_diagnostics` at M5; the export exists now so that is a one-line addition. See
/// [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;

// THE T2 LIVE-SESSION RUNTIME + both topologies — behind the `runtime` cargo feature (OFF by default,
// HARD RULE 4). The default / prod build compiles the IR + declarations only (no async runtime pulled
// in); turning the feature on compiles the duplex session pump, the D2 metering lease, the durable
// `SessionScope` binding, and the browser-sideband / telephony topologies — all feature-gated OFF by
// default (HARD RULE 4), not because the code is incomplete.
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "runtime")]
pub mod topology;

/// THE `PLANE_DECL.build_runtime` VALUE — wired to the real runtime constructor
/// ([`runtime::build_runtime`]) behind the `runtime` feature, `None` when the feature is off so the
/// default `PLANE_DECL` is byte-unchanged. Split by `cfg` because the
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
/// here; it is the [`DECLS`] registry key and the FIRST of the plane's [`PLANE_DECL`] wire formats.
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// THE SECOND DIALECT this plane speaks — Google's Gemini Live `BidiGenerateContent` API. Its codec is
/// [`ir::GeminiLiveCodec`]; adding it to `VOICE_WIRE_FORMATS` is what EARNS the plane its superset IR
/// (the A2A discipline — a plane earns a superset at its SECOND wire format and not before).
pub const GEMINI_LIVE: &str = "gemini_live";

/// THE TWO WIRE FORMATS this plane translates: OpenAI Realtime and Gemini Live. Its length (== 2) is
/// what EARNS this plane a superset IR (`Plane::has_superset_ir` is DERIVED from this list's length),
/// the A2A discipline — a plane earns a superset at its SECOND wire format and not before.
const VOICE_WIRE_FORMATS: &[&str] = &[OPENAI_REALTIME, GEMINI_LIVE];

/// THE VOICE PLANE'S DECLARATION — a `&'static PlaneDecl` the composition root installs at boot so the
/// `busbar` binary names one stable path (`busbar_voice::PLANE_DECL`). It declares the plane's identity
/// (key, config section, audit kind, wire formats) and — at M5 — is INSTALLED at boot behind the
/// `plane-voice` feature, with `build_runtime` wired to the real runtime constructor. The remaining
/// boot-mounting hooks (`claims` / `admission` / `build` / `routes` / handler) still return EMPTY/`None`:
/// route-mounting the feature-gated topology entry into the composition root is follow-on work. The
/// neutral registry unions this without naming it (the MCP/A2A precedent).
pub const PLANE_DECL: busbar_substrate::plane::registry::PlaneDecl =
    busbar_substrate::plane::registry::PlaneDecl {
        key: "voice",
        // A MOUNTED plane, not the fallback catch-all.
        fallback: false,
        // THE DUPLEX / LIVE-VOICE PLANE'S DECLARING SECTION is `streams:` (1.6.0 config-seam KEYSTONE
        // stage C) — the top-level noun whose mere existence declares this plane, the fourth plane
        // noun beside `pools:`/`tools:`/`agents:`. The registry `key` stays the crate identity
        // (`"voice"`), so key ≠ config_section here exactly as the MCP plane's key is `"mcp"` while its
        // declaring section is `"tools:"`. The plane parses `streams:` through the seam
        // (`parse_section`) once its config grammar lands; the plane declares the noun now so
        // core names no `streams`/`voice` parse target and voice can register `streams:` and boot.
        config_section: "streams",
        // One session is granted at the whole-session granularity.
        scope_kinds: &["session"],
        subject_noun: "voice session",
        admin_noun: "voice-session",
        audit_kind: "voice_session",
        // TWO dialects ⇒ superset IR, DERIVED from this list's length (see VOICE_WIRE_FORMATS).
        wire_format_names: || VOICE_WIRE_FORMATS,
        // NOT YET MOUNTED: the runtime engine exists (`crate::runtime`, behind the `runtime` feature),
        // but this decl still mounts nothing and admits no one at boot — route-mounting the pump /
        // session-open through `run_gauntlet_session` is follow-on work (`plane4-duplex-session.md` §8).
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
        // config-seam: voice PARSES its owned `streams:` section through its own typed `StreamsCfg`,
        // so `DeployCfg` names no `busbar_voice` type (the MCP `mcp_parse_section` / A2A
        // `a2a_parse_section` pattern). UNCONDITIONAL — the hook lives outside the `runtime` gate so
        // the default feature-off build validates `streams:` too.
        parse_section: Some(config::streams_parse_section),
        parse_endpoint: None,
        lower_endpoint: None,
        // RUNTIME HOOK — wired to the real per-generation runtime constructor behind the `runtime`
        // feature (see [`VOICE_BUILD_RUNTIME`]); `None` when the feature is off so the default build is
        // byte-unchanged. The remaining boot-mounting hooks (`build` / `hydrate` / `start`) stay `None`:
        // route-mounting the topology entry needs the host route/admission seam, follow-on work outside
        // this crate's scope (see the T2 report).
        build_runtime: VOICE_BUILD_RUNTIME,
        viewer: None,
        retain_verify_gates: None,
        // config-seam: the empty `streams:` default, so an ABSENT section decodes byte-identically to
        // `StreamsCfg::default()` (mirror of `a2a_default_section` / `mcp_default_section`). Without
        // it the neutral `StreamsSection::default()` newtype would fall back to a raw capture, not the
        // typed default.
        default_section: Some(config::streams_default_section),
        // config-seam: voice OWNS the `streams:` grammar. `"streams"` is NOT in core's
        // `CORE_OWNED_CONCRETE_SECTIONS` (providers/models/pools/rate_card/limits), so the dup-claim
        // guard admits this claim; a second claimant of `streams` is refused by construction.
        owned_config_sections: &["streams"],
    };

/// THE VOICE PLANE'S PROTOCOL DECLARATION — a `ProtocolDecl` with `codec: None`, re-exported at the
/// crate root so the `busbar` binary names one stable path (`busbar_voice::DECLS`). Like MCP / A2A, it
/// declares NO codec even though the plane now speaks TWO dialects: the plane realizes its cross-dialect
/// superset as its OWN shared IR types (the [`ir`] module's `DuplexReader` / `DuplexWriter` pair, one
/// per dialect), not the LLM-style `DialectCodec` facade the `codec` field carries.
///
/// NOT YET MOUNTED: `handler: None` and `verbs: &[]` — route-mounting the duplex handler /
/// gauntlet-session entry is follow-on work. Every other field carries the neutral default a codec-less
/// protocol declares (the MCP `DECL` shape).
pub static DECLS: busbar_substrate::proto::ProtocolDecl = busbar_substrate::proto::ProtocolDecl {
    name: OPENAI_REALTIME,
    // THE SUPERSET IS ITS OWN IR (`plane4-duplex-session.md` §1.4): the two dialects meet in the plane's
    // shared IR types, not a `DialectCodec` facade — so this field stays `None`, the MCP/A2A precedent.
    codec: None,
    // NOT YET MOUNTED: no request handler wired here yet — the duplex pump exists in `crate::runtime`;
    // route-mounting its entry point is follow-on work.
    handler: None,
    // NOT YET MOUNTED: no verbs declared yet (the long-lived Subscribe/Control shapes arrive with the
    // boot-mounting pass).
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
