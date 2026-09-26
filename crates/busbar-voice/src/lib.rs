// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-voice — the DUPLEX / LIVE-VOICE plane (Plane 4), as ONE plugin crate.
//!
//! WHAT THIS CRATE HOLDS. The plane's DECLARATIONS — [`PLANE_DECLARATION`] (a contract
//! [`busbar_contract::plane::PlaneDeclaration`], joined kernel-side to [`PLANE_HOOKS`]) and [`DECLS`] (a
//! [`busbar_kernel::proto::ProtocolDecl`] with `codec: None`) — plus the plane's OWN four-layer
//! duplex/session IR ([`ir`]) and BOTH dialect codecs (OpenAI Realtime + Gemini Live). The live pump,
//! reader/writer bodies, and session store are implemented in [`runtime`] behind the `runtime` feature
//! (see `docs/design/plane4-duplex-session.md` §8).
//!
//! BOOT-MOUNTING HAS LANDED — this paragraph used to say it was separate, tracked work, and that is
//! no longer true. `plane-voice` is IN the binary's `default` feature set, and the composition root
//! installs this crate at four sites: `register_planes` pushes [`PLANE_DECLARATION`] into the plane axis,
//! `register_diagnostics` extends with [`DIAGNOSTICS`], `register_ws_arrivals` installs
//! `mount::voice_ws_arrivals()`, and `mount_root_voice` calls `mount::install_governed_calls`. The
//! shipped binary therefore serves this plane; see [`PLANE_DECLARATION`].
//!
//! ONE PLUGIN PER PROTOCOL, the same rule `busbar-mcp` / `busbar-a2a` state: nothing in `busbar-core`
//! names this crate. Everything the plane consumes from the engine comes through the neutral
//! `busbar-substrate` surface (+ `busbar-api`); the `busbar` BINARY — the composition root — is what
//! links it and hands [`PLANE_DECLARATION`] / [`DECLS`] to the registry installers at boot. The neutral crates
//! do NOT change to accept it, and the crate is strong-form DELETABLE (`git rm -r crates/busbar-voice`
//! leaves the neutral crates compiling) — proven by `scripts/plane-delete-test.sh voice`.
//!
//! THE SUPERSET IR, EARNED (`plane4-duplex-session.md` §1.4). With TWO dialects — OpenAI Realtime and
//! Gemini Live — the plane earns a cross-dialect superset IR: a neutral vocabulary both codecs read and
//! write, so `Plane::has_superset_ir("voice")` is true — DERIVED from the length-2 `VOICE_WIRE_FORMATS`
//! (the A2A rule: a plane earns a superset at its SECOND wire format and not before). The plane realizes
//! that superset as its OWN shared IR types ([`ir`]), not the LLM-style `DialectCodec` facade, so
//! [`DECLS`] stays `codec: None` exactly as MCP / A2A do.

/// THE DUPLEX IR AND THE DIALECT CODECS, RE-EXPORTED FROM `busbar-voice-codec`.
///
/// The plane-4 session intermediate representation (media, control, events, tools, session config,
/// usage), the shared duplex reader/writer and the Gemini Live dialect live in `busbar-voice-codec`
/// now — the pure half of this plugin, split out so `busbar-plane-streaming` can name the IR without
/// linking this crate's axum mount, WebSocket accept, tokio session tasks and telephony dial. They
/// are re-exported HERE, under their old name, so every caller that spells `busbar_voice::ir::…`
/// resolves exactly what it always did. The split is a MOVE: no item changed shape crossing it.
pub use busbar_voice_codec::ir;

/// THE `streams:` CONFIG SECTION — the voice plane's owned config grammar ([`config::StreamsCfg`]) and
/// its `parse_section` / `default_section` seam hooks. UNCONDITIONAL (outside the `runtime` gate):
/// the plane DECLARES and PARSES `streams:` even in the default feature-off build, so config validation
/// reaches the owned grammar whether or not the live session pump is compiled in.
pub mod config;

pub mod diagnostics;

/// THE VOICE PLANE'S PLANE-CONTRIBUTED DIAGNOSTICS — the `&'static [&'static Diagnostic]` the
/// composition root installs via `busbar_kernel::diagnostics::install_diagnostics`, re-exported at
/// the crate root so the `busbar` binary names one stable path (`busbar_voice::DIAGNOSTICS`), exactly
/// as `busbar_mcp::DIAGNOSTICS` / `busbar_a2a::DIAGNOSTICS`. BOOTED BY THE BINARY: `main.rs`'s
/// `register_diagnostics` carries `installed.extend_from_slice(busbar_voice::DIAGNOSTICS)` under
/// `plane-voice`, which is in `default`. (This line used to read "not yet booted … at M5"; M5
/// landed.) See [`diagnostics`].
pub use diagnostics::DIAGNOSTICS;

/// THE ONE ENTRY THIS PLUGIN IS REGISTERED THROUGH — everything a composition root that linked it
/// wires, one item per registration axis, read off the crate rather than spelled at the root. The
/// root's manifest names this crate and the axes it registers on
/// (`[package.metadata.busbar.linked-axes]`: the plane — its protocol declaration is not installed
/// on the protocol axis — its owned diagnostics, its inbound WS-accept arrivals, and its realtime
/// provider composed off the deployment's catalog; the last two are wired behind `runtime`, exactly
/// as the mount hooks are); its build script turns that into one table per axis over these items,
/// and the root's source names no item of this crate.
pub mod linked {
    /// The WS-accept axis and the provider-composition axis.
    #[cfg(feature = "runtime")]
    pub use crate::mount::{compose_plane as compose, install_arrivals as install_ws_arrivals};
    /// The diagnostics axis.
    pub use crate::DIAGNOSTICS;
    /// The plane axis: the contract declaration, joined kernel-side to the behaviour table.
    pub use crate::{PLANE_DECLARATION, PLANE_HOOKS};
    /// The claims axis: the pure plane the composition root's boot seal registers, and the claims it
    /// declares.
    pub const PLANE: busbar_plane_streaming::StreamingPlane =
        busbar_plane_streaming::StreamingPlane::EMPTY;
    /// The bytes that plane claims.
    pub const CLAIMS: &[busbar_contract::grammar::Claim] =
        <busbar_plane_streaming::StreamingPlane as busbar_contract::plane::PlaneMeta>::CLAIMS;
}

// THE T2 LIVE-SESSION RUNTIME + both topologies — behind the `runtime` cargo feature (OFF by default,
// HARD RULE 4). The default / prod build compiles the IR + declarations only (no async runtime pulled
// in); turning the feature on compiles the duplex session pump, the D2 metering lease, the durable
// `SessionScope` binding, and the browser-sideband / telephony topologies — all feature-gated OFF by
// default (HARD RULE 4), not because the code is incomplete.
#[cfg(feature = "runtime")]
pub mod runtime;

/// THE NODE'S OPEN-CALL TABLE — the client-served tool calls this node's sessions are waiting on,
/// and the port the session runtime reaches it through; composed by this plane's own `compose` step.
#[cfg(feature = "runtime")]
pub mod governed;
#[cfg(feature = "runtime")]
pub mod topology;

/// THE DATA-ROUTE MOUNT — the voice plane's `PLANE_HOOKS` `routes` / `claims` / `admission` / `build`
/// hooks and the neutral handlers behind them (see [`mount`]). Behind the `runtime` feature because the
/// route handlers open governed sessions through the T2 topologies (`crate::topology`, itself
/// runtime-gated); the default feature-off build mounts nothing and keeps the byte-unchanged
/// `PLANE_HOOKS` (the hooks stay empty/`None`, wired through the [`VOICE_CLAIMS`] / [`VOICE_ADMISSION`] /
/// [`VOICE_BUILD`] / [`VOICE_ROUTES`] cfg-split consts, exactly as [`VOICE_BUILD_RUNTIME`] is).
#[cfg(feature = "runtime")]
pub mod mount;

/// THIS PLANE'S OWN TEST-KIT — the in-memory engine-host double, the loopback HTTP provider and the
/// metrics capture this crate's batteries drive. A plane tests ITSELF (1.6.0 Locked Decision #33:
/// "the kernel never tests a plugin"), so these doubles live HERE rather than in the deleted
/// `busbar_kernel::testkit`. Behind `runtime` for the same reason `mount`/`topology` are — every cell
/// that drives them is runtime-gated, and the doubles name the async/metrics deps that feature pulls.
#[cfg(all(feature = "runtime", any(test, feature = "test-support")))]
pub mod testkit;

/// THE `PLANE_HOOKS.build_runtime` VALUE — wired to the real runtime constructor
/// ([`runtime::build_runtime`]) behind the `runtime` feature, `None` when the feature is off so the
/// default `PLANE_HOOKS` is byte-unchanged. Split by `cfg` because the
/// `runtime` module (and its constructor) only exist behind the feature.
// `type_complexity`: this fn-pointer is the mirror of the frozen `PlaneDecl::build_runtime` field type
// (`busbar_kernel::plane::registry`), which carries the SAME `#[allow(clippy::type_complexity)]` — the
// shape is the ABI, not a factorable local type.
#[cfg(feature = "runtime")]
#[allow(clippy::type_complexity)]
const VOICE_BUILD_RUNTIME: Option<
    fn(
        &dyn std::any::Any,
        Option<&dyn busbar_kernel::plane_host::PlaneSlots>,
    ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
> = Some(runtime::build_runtime);
#[cfg(not(feature = "runtime"))]
#[allow(clippy::type_complexity)]
const VOICE_BUILD_RUNTIME: Option<
    fn(
        &dyn std::any::Any,
        Option<&dyn busbar_kernel::plane_host::PlaneSlots>,
    ) -> std::sync::Arc<dyn std::any::Any + Send + Sync>,
> = None;

// ── THE DATA-ROUTE MOUNT HOOKS — cfg-split exactly as `VOICE_BUILD_RUNTIME`, so the default
// (feature-off) `PLANE_HOOKS` is BYTE-UNCHANGED (claims empty, admits no one, builds no slot, mounts no
// route) and the `runtime` build wires the real neutral hooks in `crate::mount`. Route-mounting the
// pump needs the T2 topologies (runtime-gated) to open governed sessions, so these arm in lock-step
// with the runtime — a plane installed at boot (only under `plane-voice`, which turns on
// `busbar-voice/runtime`) both mounts and admits, keeping the ratchet's "mounted ⇒ admitted" true.

/// `PLANE_HOOKS.build` — construct the per-generation dispatch slot from `public_url` (the audience),
/// `crate::mount::voice_build` with the feature on; `|_| None` (no slot) with it off.
#[cfg(feature = "runtime")]
const VOICE_BUILD: fn(
    &busbar_kernel::plane::registry::BuildCtx,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> = mount::voice_build;
#[cfg(not(feature = "runtime"))]
const VOICE_BUILD: fn(
    &busbar_kernel::plane::registry::BuildCtx,
) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> = |_ctx| None;

/// `PLANE_HOOKS.claims` — the one audience-checked base the plane answers on, or nothing off-feature.
#[cfg(feature = "runtime")]
const VOICE_CLAIMS: fn(&dyn std::any::Any) -> Vec<(String, &'static str)> = mount::voice_claims;
#[cfg(not(feature = "runtime"))]
const VOICE_CLAIMS: fn(&dyn std::any::Any) -> Vec<(String, &'static str)> = |_slot| Vec::new();

/// `PLANE_HOOKS.admission` — the RFC 8707 audience bound from `public_url`, or `None` off-feature.
#[cfg(feature = "runtime")]
const VOICE_ADMISSION: fn(&dyn std::any::Any) -> Option<busbar_kernel::plane::PlaneAdmission> =
    mount::voice_admission;
#[cfg(not(feature = "runtime"))]
const VOICE_ADMISSION: fn(&dyn std::any::Any) -> Option<busbar_kernel::plane::PlaneAdmission> =
    |_slot| None;

/// `PLANE_HOOKS.routes` — the four neutral ingress routes, or `None` (no data path) off-feature.
#[cfg(feature = "runtime")]
#[allow(clippy::type_complexity)]
const VOICE_ROUTES: Option<
    fn(&dyn std::any::Any) -> Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
> = Some(mount::voice_routes);
#[cfg(not(feature = "runtime"))]
#[allow(clippy::type_complexity)]
const VOICE_ROUTES: Option<
    fn(&dyn std::any::Any) -> Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
> = None;

/// `PLANE_HOOKS.hydrate` — boot-rehydrate the durable voice-session working-set before any listener
/// binds ([`mount::voice_hydrate`]); `None` off-feature so the default decl is byte-unchanged.
#[cfg(feature = "runtime")]
const VOICE_HYDRATE: Option<busbar_kernel::plane::registry::BootHook> = Some(mount::voice_hydrate);
#[cfg(not(feature = "runtime"))]
const VOICE_HYDRATE: Option<busbar_kernel::plane::registry::BootHook> = None;

/// `PLANE_HOOKS.start` — the post-listener boot step ([`mount::voice_start`]); `None` off-feature so the
/// default decl is byte-unchanged.
#[cfg(feature = "runtime")]
const VOICE_START: Option<busbar_kernel::plane::registry::BootHook> = Some(mount::voice_start);
#[cfg(not(feature = "runtime"))]
const VOICE_START: Option<busbar_kernel::plane::registry::BootHook> = None;

/// THE VOICE (STREAMING) PLANE'S CAPABILITY KEY (`"voice"`) — the string the composition root flips
/// onto the unified kernel loop's SESSION admit and the same string the voice session gauntlet reports
/// from its `GauntletPlane::capability_key`. Re-exported at the crate root so the `busbar` binary names
/// ONE stable path (`busbar_voice::PLANE_KEY`) and the plane and the flip cannot drift onto two.
pub use busbar_voice_codec::PLANE_KEY;

/// THE DIALECT NAME this plane speaks first — OpenAI's bidirectional Realtime voice API. Named once
/// here; it is the [`DECLS`] registry key and the FIRST of the plane's [`PLANE_HOOKS`] wire formats.
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// THE SECOND DIALECT this plane speaks — Google's Gemini Live `BidiGenerateContent` API. Its codec is
/// [`ir::GeminiLiveCodec`]; adding it to `VOICE_WIRE_FORMATS` is what EARNS the plane its superset IR
/// (the A2A discipline — a plane earns a superset at its SECOND wire format and not before).
pub const GEMINI_LIVE: &str = "gemini_live";

/// THE TWO WIRE FORMATS this plane translates: OpenAI Realtime and Gemini Live. Its length (== 2) is
/// what EARNS this plane a superset IR (`Plane::has_superset_ir` is DERIVED from this list's length),
/// the A2A discipline — a plane earns a superset at its SECOND wire format and not before.
const VOICE_WIRE_FORMATS: &[&str] = &[OPENAI_REALTIME, GEMINI_LIVE];

/// THE VOICE PLANE'S PROVIDER-FACING BEARER — the ONE construction that plans the provider-facing
/// `Authorization: Bearer <credential>` from the RESOLVED provider-credential string, and NEVER a
/// caller/governance token passed through. Both [`voice_egress_auth_headers`] (the
/// `egress_auth_headers` decl) and the LIVE one-shot serving passes ([`mount::serve_sdp`]) authenticate
/// the provider hop through THIS function, so the lane-constant builder the `egress_tests` battery
/// proves is the SAME code the live SDP broker runs — the tested builder IS the live credential path.
/// It authenticates busbar's OWN authority to the provider (the real provider key on the broker hop),
/// never the caller's inbound bearer (which the Auth plugin already consumed at the door).
///
/// NOTE — the SDP broker authenticates with the PROVIDER key (busbar brokers the call server-side).
/// An `ek_`-RELAY model (forward the browser's ephemeral secret as the upstream credential) is a
/// distinct protocol shape: it needs a resolved `ek_` source — the inbound `RouteAuth::Key`
/// `Authorization` slot carries the caller's GOVERNANCE key (forwarding it upstream would leak
/// busbar's own authority), so an `ek_` relay would have to arrive on a non-`Authorization` inbound
/// slot or be minted+persisted server-side. That is a flagged protocol follow-on, not this hop.
pub(crate) fn voice_provider_bearer(
    key: &str,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    busbar_kernel::proto::bearer_auth_headers(OPENAI_REALTIME, key)
}

/// `ProtocolDecl::egress_auth_headers` — the plain-Bearer arm of `busbar-llm`'s OpenAI dialect (the
/// Bedrock module hands in its SigV4 signer the same way). A pure function of the resolved credential
/// string (it reads nothing off the [`SigningContext`]), so [`DECLS`] declares it LANE-CONSTANT.
fn voice_egress_auth_headers(
    key: &str,
    _ctx: &busbar_kernel::proto::SigningContext,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    voice_provider_bearer(key)
}

use busbar_contract::plane::{BillableClass, PER_SESSION, TOKEN_FAMILY};
use busbar_kernel::plane::registry::PlaneHooks;

/// THE VOICE PLANE'S DECLARATION — contract data the composition root registers at boot, joined
/// kernel-side to [`PLANE_HOOKS`], so the `busbar` binary names one stable path
/// (`busbar_voice::PLANE_DECLARATION`). Together the two declare the plane's identity
/// (key, config section, audit kind, wire formats), is INSTALLED at boot behind the `plane-voice`
/// feature with `build_runtime` wired to the real runtime constructor, and — behind the `runtime`
/// feature (which `plane-voice` turns on) — MOUNTS its data plane: `build` erases the dispatch slot from
/// `public_url`, `claims`/`admission` bind the plane's RFC 8707 audience, and `routes` mounts the five
/// ingress doors across both dialects (see [`mount`]), and the BOOT hooks `hydrate` / `start` rehydrate the durable session
/// working-set before the listener and confirm readiness after. What stays `None` is the `ProtocolDecl`
/// `handler`: a long-lived duplex SESSION is not a one-shot `RequestHandler` (whose `OperationHandler`
/// cells are request→response codecs), so the session driver lives in the plane's own runtime
/// (`crate::topology`) over the neutral pump, not on that field. The neutral registry unions this
/// without naming it (the MCP/A2A precedent).
pub const PLANE_DECLARATION: busbar_contract::plane::PlaneDeclaration =
    busbar_contract::plane::PlaneDeclaration {
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
        card_signing_domain: None,
        card_kid_prefix: None,
        // config-seam: voice OWNS the `streams:` grammar. `"streams"` is NOT in core's
        // `CORE_OWNED_CONCRETE_SECTIONS` (providers/models/pools/rate_card/limits), so the dup-claim
        // guard admits this claim; a second claimant of `streams` is refused by construction.
        owned_config_sections: &["streams"],
        // The classes the plane crate declares (`busbar_plane_streaming::meta`), by its own symbols.
        //
        // `cached_tokens` is deliberately NOT here (architect ruling #71, money-model integrity): the
        // dialects' own `cached_tokens` figure is a SUBSET of the input token classes above (OpenAI
        // Realtime reports it INSIDE `input_token_details`; Gemini Live the same, inside
        // `promptTokensDetails`), so a rate card that priced it too would bill the same cached input
        // twice. A billable class must be disjoint from every other one the plane declares; a subset
        // measure is attribution, not a class. The figure is still carried, unbilled, as the
        // `cached_tokens` content fact (`busbar_plane_streaming::meta::FACT_CACHED_TOKENS`).
        billable_classes: &[
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_AUDIO_TOKENS_IN.as_str(),
                family: TOKEN_FAMILY,
            },
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_AUDIO_TOKENS_OUT.as_str(),
                family: TOKEN_FAMILY,
            },
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_TEXT_TOKENS_IN.as_str(),
                family: TOKEN_FAMILY,
            },
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_TEXT_TOKENS_OUT.as_str(),
                family: TOKEN_FAMILY,
            },
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_AUDIO_SECONDS_IN.as_str(),
                family: "duration",
            },
            BillableClass {
                class: busbar_plane_streaming::meta::CLASS_TOOL_CALLS.as_str(),
                family: "count",
            },
        ],
        // The fee unit this plane counts: one per opened session (`SessionAccount::open`). A turn never
        // passes per-request admission, so `streams.fees.per_request` would charge nothing — refused.
        fee_units: &[PER_SESSION],
        metric_families: &[],
        record_kinds: &[],
        served_op_classes: &[],
    };

/// THE PLANE'S BEHAVIOUR — every hook the kernel runs for it, handed over BESIDE
/// [`PLANE_DECLARATION`] and joined to it kernel-side (`PlaneDecl::assemble`). The registration item
/// is the declaration, which names no kernel type; this table is typed by kernel seams and stays on
/// the kernel side of every fold.
pub const PLANE_HOOKS: PlaneHooks = PlaneHooks {
    // TWO dialects ⇒ superset IR, DERIVED from this list's length (see VOICE_WIRE_FORMATS).
    wire_format_names: || VOICE_WIRE_FORMATS,
    // MOUNTED (behind `runtime`): the plane builds its dispatch slot from `public_url`, claims TWO
    // audience-checked bases — `/v1/realtime` (OpenAI) and `/v1/realtime/gemini` (Gemini Live) —
    // under the SAME bound audience, and mounts the five ingress routes across both dialects, whose
    // handlers open governed sessions through `run_gauntlet_session` (see `crate::mount`).
    // Off-feature these stay empty/`None` (the byte-unchanged default decl). A plane installed at
    // boot is installed under `plane-voice` (⇒ `busbar-voice/runtime`), so it always both mounts and
    // admits — the ratchet's "mounted ⇒ admitted" holds by construction.
    claims: VOICE_CLAIMS,
    admission: VOICE_ADMISSION,
    build: VOICE_BUILD,
    routes: VOICE_ROUTES,
    admin_routes: None,
    openapi: None,
    // BOOT hooks — rehydrate the durable session working-set before the listener, then the
    // post-listener readiness step. Wired behind `runtime` (see [`VOICE_HYDRATE`] / [`VOICE_START`]);
    // `None` off-feature so the default decl is byte-unchanged.
    hydrate: VOICE_HYDRATE,
    start: VOICE_START,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
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
    // byte-unchanged. The DATA-plane hooks (`build` / `claims` / `admission` / `routes`) and the
    // BOOT hooks (`hydrate` / `start`) are wired too (see [`mount`]) — all behind `runtime`.
    build_runtime: VOICE_BUILD_RUNTIME,
    viewer: None,
    retain_verify_gates: None,
    // config-seam: the empty `streams:` default — the plane's own statement that an ABSENT section
    // is byte-identically `StreamsCfg::default()` (mirror of `a2a_default_section` /
    // `mcp_default_section`). The kernel's declared-section carrier holds no entry for an absent
    // section; this hook is what that absence means to the plane.
    default_section: Some(config::streams_default_section),
    resolve_provider: None,
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
pub static DECLS: busbar_kernel::proto::ProtocolDecl = busbar_kernel::proto::ProtocolDecl {
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
    ingress_auth: busbar_kernel::proto::IngressAuth::Bearer,
    // THE ONE EGRESS CREDENTIAL MECHANISM: the provider bearer / WebRTC `ek_` / telephony carrier
    // credential is planned onto the dial's headers HERE, never a caller token passed through (see
    // [`voice_egress_auth_headers`]). LANE-CONSTANT: the builder is a pure function of the resolved
    // credential string and reads nothing off the `SigningContext`, so the boot path may prebuild the
    // header set once per lane (the plain-Bearer discipline the LLM plane's OpenAI dialect declares).
    egress_auth_headers: Some(voice_egress_auth_headers),
    egress_auth_lane_constant: true,
    egress_scheme: None,
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
    egress_user_agent: busbar_kernel::proxy::EGRESS_UA_DEFAULT,
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        axum::http::StatusCode::UNAUTHORIZED,
        busbar_kernel::proto::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: "authentication failed",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    egress_stream_accept: busbar_kernel::proxy::TEXT_EVENT_STREAM,
    models_list_envelope: None,
    // Identified by its EXPLICIT mount, never by a wire fingerprint — so it claims no router or
    // residual rung, contributes no vendor response metadata, and is not the residual default.
    claims: None,
    residual_claims: None,
    residual_default: false,
    vendor_response_metadata: None,
    list_models_fingerprint_headers: &[],
    static_headers: &[],
};
