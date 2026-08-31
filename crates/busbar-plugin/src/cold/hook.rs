// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **hook** payload schema (kind = [`crate::cold::kind::HOOK`]) that rides the kind-neutral `call`.
//!
//! ## One transport, every hook op
//!
//! A `kind: hook` plugin is a routing policy behind the frozen six-symbol C ABI. Every hook operation
//! that used to ride the out-of-process socket/webhook wire (`decide`/`transform`/`notify`/
//! `configure`/`describe`/`status`) now rides the ONE `busbar_call` as an op-discriminated JSON
//! envelope — [`HookRequest`]. The variant IS the op-code, so the C symbol set never grows.
//!
//! ## The contract is preserved bit-for-bit
//!
//! The PAYLOAD each op carries — and the reply shape it expects — is EXACTLY the engine's existing
//! `hooks::wire` contract (the request projection with its opt-in `prompt`/`user` keys; the reply
//! verbs `order`/`abstain`/`reject`/`restrict`/`rewrite`; the fail-closed parsing; the reject-status
//! clamp; the metric validation). Only the TRANSPORT changed: `busbar_call` instead of
//! NDJSON-over-socket / POST-over-HTTP. To keep the two seams provably identical, the projection is
//! carried as an opaque [`serde_json::Value`] built by the engine's `hooks::wire::build` and the reply
//! is parsed back through the SAME `hooks::wire` fail-closed normalizers — this ABI adds the envelope,
//! never a second copy of the semantics.
//!
//! ## Grants are CORE-enforced, never plugin-driven
//!
//! The opt-in `prompt`/`user` projection keys ride INSIDE the `payload` value ONLY when the engine's
//! operator grant (AND the signed-manifest declared intent) allow it — the plugin has no say and
//! cannot cause content to be sent. This ABI just carries whatever the core chose to project.

use crate::cold::http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route};
use serde::{Deserialize, Serialize};

/// The hook-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: hook`).
/// v1 (1.5.0): the op-discriminated `decide`/`transform`/`notify`/`configure`/`describe`/`status`
/// envelope lifted verbatim from the retired socket/webhook wire. This is the per-kind PAYLOAD axis,
/// NOT the transport axis — a hook plugin exports the SAME six neutral symbols ([`crate::cold::symbol`]) as
/// every other kind, at `busbar_abi() == TRANSPORT_VERSION`.
pub const HOOK_ABI_VERSION: u32 = 1;

/// A hook operation, serialized as the `call` request payload. One self-describing enum keeps the C
/// ABI to a single `call` symbol; the variant is the op-code. Mirrors the retired socket/webhook wire
/// op set one-to-one.
///
/// The per-request ops (`Decide`/`Transform`/`Notify`) carry `payload` — the engine's
/// `hooks::wire::build` projection as an opaque JSON object (the request projection + candidates +
/// context + any opt-in `prompt`/`user` the CORE granted). The management ops (`Configure`/`Describe`/
/// `Status`) carry only their own small bodies. Serialized with the op as a JSON tag so a plugin
/// matches on it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HookRequest {
    /// `decide` — the gate's blocking ranking/verdict. `payload` is the full request projection
    /// (candidates + context). Reply: a [`HookReply`] (`order`/`abstain`/`reject`/`restrict`).
    Decide { payload: serde_json::Value },
    /// `transform` — the `prompt: rw` gate's rewrite pass. `payload` is the request projection (no
    /// candidates). Reply: a [`HookReply`] (`reject`/`rewrite`/`abstain`).
    Transform { payload: serde_json::Value },
    /// `notify` — a tap's fire-and-forget observation. `payload` is the (stage) projection. The
    /// engine never reads the reply.
    Notify { payload: serde_json::Value },
    /// `configure` — push the hook's desired-state settings; the reply MUST ack the exact version.
    Configure(ConfigureBody),
    /// `describe` — ask the hook for its self-description envelope (`{schema, dashboard?}`).
    Describe,
    /// `status` — ask the hook for its observed settings + metrics (the control-plane scrape read).
    Status,
    /// `routes` — asked ONCE at load: which HTTP [`Route`]s does this hook serve (a routing hook's
    /// inbound `/feedback`, confined to `/hooks/<name>/*`)? Reply: [`HookReply::Routes`]. ADDITIVE —
    /// an older hook that cannot decode this op declares no routes.
    Routes,
    /// `http_endpoint` — dispatch one inbound HTTP request matched to a registered route of THIS hook.
    /// Fires only for a matched plugin route, off the data-plane hot path. Reply: [`HookReply::Http`].
    HttpEndpoint {
        /// The host-built inbound request (bounded headers, no raw `Authorization`).
        request: HttpEndpointRequest,
    },
}

/// The `configure` body: the hook's own name (echo), its opaque settings, the monotonic version the
/// ack must echo, and the engine version. Mirrors the retired `ConfigureBody` (now owned — this ABI
/// serializes it into the `call` payload, it does not borrow the live registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureBody {
    /// The hook's registry name (context echo).
    pub hook: String,
    /// The opaque settings map from the hook's registry entry (operator/API-owned).
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// Monotonic settings version (the config_version that committed them) — the ack echoes it.
    pub settings_version: u64,
    /// The engine's version string.
    pub busbar_version: String,
}

/// The success payload for a hook `call`. Module-level FAILURES (a hook that genuinely errored) ride
/// `STATUS_ERR` with a UTF-8 message, NOT here. Each variant matches the request op:
///
/// - `Decide`/`Transform`/`Notify` → [`HookReply::Reply`] carrying the raw reply object, which the
///   engine parses through its EXISTING `hooks::wire` fail-closed normalizers (so the socket/webhook
///   and dlopen seams can never diverge on reject-precedence, status-clamp, or restrict/rewrite
///   parsing). `Notify` returns [`HookReply::None`] (nothing to read).
/// - `Configure` → [`HookReply::ConfigureAck`] (the version the hook acked).
/// - `Describe`/`Status` → [`HookReply::Reply`] carrying the hook's self-description / observed-state
///   object, parsed liberally by the engine.
///
/// Carrying `Reply` as an opaque [`serde_json::Value`] is deliberate: the fail-closed reply CONTRACT
/// (reject wins, malformed detail degrades to a rejection not a silent route, metrics bounded) lives
/// in ONE place — the engine's `hooks::wire` — and this ABI must not fork it.
///
/// UNLIKE [`HookRequest`] (`op`-tagged, snake_case, documented and test-pinned), this type carries NO
/// `#[serde(...)]` attribute, so it serializes with serde's default externally-tagged representation,
/// verbatim by Rust variant name. Any non-Rust hook author (Go, Zig, …) must match these THREE literal
/// JSON forms exactly, and nothing on the fire-and-forget `notify` path errors on a mismatch:
/// - `None` → the bare JSON string `"None"`.
/// - `ConfigureAck { settings_version }` → `{"ConfigureAck":{"settings_version":N}}`.
/// - `Reply(v)` → `{"Reply": v}`.
///
/// Pinned by `hook_reply_json_encoding_is_pinned` in this module's tests. Adding a `#[serde(...)]`
/// attribute here to "fix" the asymmetry with `HookRequest` would change all three encodings: this
/// is JSON over the frozen C-ABI transport (`plugin-loader`'s
/// `transport_call::<HookRequest, HookReply>`), so a tagging change is a wire-breaking change, not
/// a cosmetic one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookReply {
    /// A per-request or management reply object, parsed by the engine's `hooks::wire` normalizers.
    Reply(serde_json::Value),
    /// A `configure` ack: the settings version the hook acknowledged (the engine requires it to
    /// equal the pushed version, exactly as the socket preamble/PATCH push did).
    ConfigureAck { settings_version: u64 },
    /// A `notify` (tap) reply: nothing to read (fire-and-forget).
    None,
    /// A `routes` reply: the HTTP routes this hook serves (collected once at load). ADDITIVE — a new
    /// externally-tagged variant that does not disturb the `None`/`ConfigureAck`/`Reply` encodings
    /// pinned by `hook_reply_json_encoding_is_pinned`.
    Routes(Vec<Route>),
    /// An `http_endpoint` reply: the hook's response to a dispatched inbound request. ADDITIVE.
    Http(HttpEndpointResponse),
    /// The hook could not answer: its own dependency failed, timed out, or returned something it
    /// refuses to act on. ADDITIVE, same reasoning as `Routes`/`Http`.
    ///
    /// This exists because there was previously NO WAY for a hook to say so. `HookHandler::decide`
    /// returns a bare value, and the only thing a plugin could return when its remote brain was
    /// down was `{}` — which the engine reads as a successful ABSTAIN, meaning "no opinion". The
    /// two are not the same and the engine already treats them differently: an abstain contributes
    /// nothing and the request proceeds, while a failure resolves the operator's `on_error` chain,
    /// whose terminal can be `reject`. So a gate an operator deliberately configured to fail CLOSED
    /// failed OPEN instead, silently, and looked exactly like a hook that had no opinion.
    ///
    /// `message` is for the operator's log. It must not carry request content.
    Failed { message: String },
}

#[cfg(test)]
#[path = "tests/hook_tests.rs"]
mod tests;
