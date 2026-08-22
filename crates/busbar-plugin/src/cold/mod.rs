// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar **plugin C ABI** — the frozen, KIND-NEUTRAL wire between the engine and a backend
//! (`store` | `secret` | `auth`) that lives in a dynamic library (`.so`/`.dll`/`.dylib`) it loads at
//! runtime, OR is compiled straight in.
//!
//! ## The frozen transport contract (ONE set, all kinds)
//!
//! A plugin exports SIX kind-neutral `extern "C"` symbols (see [`symbol`]). The names carry NO kind —
//! ONE library shape serves every kind, and the KIND is bound at LOAD, never in a per-call envelope.
//! The engine resolves the symbols via `libloading` and calls across the boundary passing
//! **JSON-serialized bytes** (a `ptr + len`), never C structs. JSON — not a `repr(C)` struct —
//! because:
//!
//! - it is **version-tolerant**: fields can be added to the contract records without breaking the
//!   ABI (a new field an old plugin doesn't know is simply ignored / defaulted);
//! - it is **language-agnostic**: a plugin can be written in C/Go/Zig as long as it speaks the
//!   symbols and the JSON;
//! - the cost is **irrelevant**: these backends are off the request hot path (the store is
//!   write-behind, auth is cached), so a serialize per call never touches request latency.
//!
//! The six symbols are `busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`,
//! `busbar_free`, `busbar_close`. Every operation for a kind rides the single `call`, self-described
//! by that kind's request enum, so the C symbol set never grows as a trait does.
//!
//! ## Two version axes (the crux)
//!
//! 1. **Transport version** = the `busbar_abi` symbol, frozen at [`TRANSPORT_VERSION`] (=1), ONE number for all
//!    kinds. It is the low-level linker contract (the six signatures, ptr+len byte buffers, the
//!    plugin-allocates/plugin-frees rule, the status codes). Bumping it is a real, no-turning-back
//!    linker event; it changes ~never.
//! 2. **Per-kind payload schema version** = the SIGNED manifest's `abi_version` field. It bumps
//!    routinely, per kind, ADDITIVELY. The engine negotiates it against `supported_abi` (a contiguous
//!    RANGE per kind, in the loader/registry): in range → load; below the floor / above the max →
//!    refuse LOUD. This is the axis the store schema churned 1→2→3→4 on — all PAYLOAD, zero transport.
//!
//! ## Kind bound AT LOAD — the security spine
//!
//! Kind is NEVER in the per-call envelope. At load the engine reads the signed manifest `kind`,
//! cross-checks it EQUALS the exported `busbar_plugin_kind` (mismatch = hard fail-closed load
//! error), then dispatches to the TYPED seam (`Box<dyn Store>` / `Box<dyn SecretModule>` /
//! `Box<dyn AuthModule>`). From there kind is a Rust TYPE, not a wire tag.

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneSelector,
    UsageDelta, UsageLedger, VirtualKey,
};
use serde::{Deserialize, Serialize};
use std::os::raw::c_void;

pub mod auth;
pub mod export;
pub mod hook;
pub mod http_endpoint;

/// The "decision observability" signal catalog — re-exported wholesale from
/// `busbar-api` (where it actually lives; see that crate's `signal` module doc comment for why) so
/// a hook plugin author can write `busbar_plugin::cold::Signal::CandidateBreakerState` without a
/// direct `busbar-api` dependency, mirroring every other type this crate re-exports for the same
/// reason (`AuditRecord`, `VirtualKey`, …, imported above). `busbar-plugin-sdk` re-exports it again
/// from here (or directly from `busbar-api`) so the common plugin-author path is
/// `busbar_plugin_sdk::Signal`.
pub use busbar_api::{Signal, SignalBag, SignalValue};

/// The kind-neutral **TRANSPORT** ABI version, returned by a plugin's `busbar_abi()`. Frozen at 1:
/// this is the low-level linker contract (the six C signatures, ptr+len byte buffers, the
/// plugin-allocates/plugin-frees rule, the status codes). DISTINCT from the per-kind PAYLOAD schema
/// version (the signed manifest's `abi_version`), which bumps additively per kind. Bumping THIS is a
/// real, no-turning-back linker event — side-by-side migration, never a routine change.
pub const TRANSPORT_VERSION: u32 = 1;

/// The kind strings a plugin may declare via `busbar_plugin_kind()` and its signed manifest `kind`.
///
/// EACH kind comes in TWO forms and they are NOT interchangeable:
///
/// * the plain `&str` (`STORE`, `SECRET`, …) — for comparisons, manifests, logs, anything Rust-side;
/// * the `*_NUL` `&[u8]` sibling (`STORE_NUL`, `SECRET_NUL`, …) — the ONLY form that may back a
///   [`PluginKindFn`] return value.
///
/// The reason is the ABI itself: `busbar_plugin_kind()` returns a bare `*const u8` with NO length,
/// and the engine reads it with `CStr::from_ptr`. A plain `&str` is NOT NUL-terminated, so the
/// obvious hand-written `busbar_plugin_kind() { kind::EXPORT.as_ptr() }` compiles cleanly and is an
/// UNBOUNDED out-of-bounds read in the engine (undefined behavior). Return `kind::EXPORT_NUL.as_ptr()`
/// instead — same discipline the [`symbol`] constants have always used (`b"busbar_abi\0"`). Plugins
/// built on `busbar-plugin-sdk` never touch either form: the SDK's export macro emits the safe one.
pub mod kind {
    /// A durable governance store (`Box<dyn busbar_api::Store>`).
    pub const STORE: &str = "store";
    /// A secret-resolution module (`Box<dyn busbar_api::SecretModule>`).
    pub const SECRET: &str = "secret";
    /// An external identity provider / auth module (`Box<dyn busbar_api::AuthModule>`).
    pub const AUTH: &str = "auth";
    /// An in-process routing hook / policy (`Arc<dyn busbar_api::RoutingPolicy>`). The 1.5.0
    /// replacement for the retired out-of-process socket/webhook hook transport.
    pub const HOOK: &str = "hook";
    /// A telemetry export sink that carries the engine's observability streams
    /// (metrics/logs/audit/traces) OUT to an external backend. Its payload schema lives in
    /// [`crate::cold::export`].
    pub const EXPORT: &str = "export";

    /// [`STORE`], NUL-terminated — return `STORE_NUL.as_ptr()` from `busbar_plugin_kind()`.
    pub const STORE_NUL: &[u8] = b"store\0";
    /// [`SECRET`], NUL-terminated — return `SECRET_NUL.as_ptr()` from `busbar_plugin_kind()`.
    pub const SECRET_NUL: &[u8] = b"secret\0";
    /// [`AUTH`], NUL-terminated — return `AUTH_NUL.as_ptr()` from `busbar_plugin_kind()`.
    pub const AUTH_NUL: &[u8] = b"auth\0";
    /// [`HOOK`], NUL-terminated — return `HOOK_NUL.as_ptr()` from `busbar_plugin_kind()`.
    pub const HOOK_NUL: &[u8] = b"hook\0";
    /// [`EXPORT`], NUL-terminated — return `EXPORT_NUL.as_ptr()` from `busbar_plugin_kind()`.
    pub const EXPORT_NUL: &[u8] = b"export\0";
}

/// The store-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: store`).
/// Bumped only on a breaking change to the wire — the request/response shape or the C signatures;
/// additive changes (e.g. a new serde-default field) keep the version. The engine refuses a plugin
/// whose manifest `abi_version` falls outside the supported range at load, never mis-calling a
/// mismatched plugin.
///
/// v1 -> v2 (1.5.0, credentials generalization): the AWS-specific `PutAwsCredential`/
/// `PutKeyWithAwsCredential`/`ListAwsCredentials` request variants and the `AwsCreds` response
/// variant are REMOVED (not additive — `AwsCredential` itself no longer exists in `busbar-api`) in
/// favor of the kind-polymorphic `PutCredential`/`PutKeyWithCredential`/`ListCredentials`/
/// `LookupCredentialSecret`/`RevokeCredential`/`ListCredentialsSince`/`ListKeysSince` variants
/// carrying `CredentialMeta`/`CredentialSecret`. A v1-built plugin cannot speak v2 at all — this is
/// a real breaking bump, correctly gated by the engine's `supported_abi` range check at load,
/// unlike every other change on this axis so far.
///
/// v2 -> v3 (1.6.0, durable-plane genericization): the fourteen protocol-named durable request
/// variants (`PutTask`/`GetTask`/…/`RedeemAskState`) and their seven named response variants
/// (`Task`/`Tasks`/`TaskEvents`/`McpCalls`/`McpCallPrincipals`/`McpDemotions`/`Redeemed`) are
/// REMOVED in favor of the eight kind-tagged neutral variants (`UpsertPlaneRecord`/…/
/// `RedeemPlaneToken`, with `PlaneRecord`/`PlaneRecords`/`PlaneRecordParents`/`Redeemed` responses).
/// This is a REAL breaking bump, not the additive churn the earlier 1.6.0 work rode: a v2 plugin
/// that speaks only the named variants can no longer be called, so the engine's `supported_abi`
/// FLOOR is raised to 3 and an old named-only artifact is REFUSED at load (fail-closed) rather than
/// answered from a default — a stale plugin fails loud, it never silently drops a durable write.
pub const ABI_VERSION: u32 = 3;

/// The exported-symbol names the engine resolves after `dlopen`/`LoadLibrary`. A plugin of ANY kind
/// MUST export all SIX with these exact (kind-NEUTRAL) names and the signatures in the `*Fn` type
/// aliases below. NUL-terminated so they pass straight to `libloading`'s C-string symbol lookup. The
/// KIND a library speaks is read from [`symbol::PLUGIN_KIND`], not encoded in the symbol names.
pub mod symbol {
    /// `busbar_abi() -> u32` — the frozen TRANSPORT version handshake ([`super::TRANSPORT_VERSION`]).
    pub const ABI: &[u8] = b"busbar_abi\0";
    /// `busbar_plugin_kind() -> *const u8` — a NUL-terminated string, the ONE kind this lib speaks.
    pub const PLUGIN_KIND: &[u8] = b"busbar_plugin_kind\0";
    /// `busbar_open(cfg, cfg_len, out_handle, out_err, out_err_len) -> i32`.
    pub const OPEN: &[u8] = b"busbar_open\0";
    /// `busbar_call(handle, req, req_len, out, out_len) -> i32`.
    pub const CALL: &[u8] = b"busbar_call\0";
    /// `busbar_free(ptr, len)` — free a buffer the plugin allocated for the engine.
    pub const FREE: &[u8] = b"busbar_free\0";
    /// `busbar_close(handle)` — drop the instance.
    pub const CLOSE: &[u8] = b"busbar_close\0";
    /// `busbar_set_log_sink(sink, ctx)` — OPTIONAL, the only symbol here that is. See
    /// [`super::SetLogSinkFn`] for why its absence is not an error and not a transport bump.
    pub const SET_LOG_SINK: &[u8] = b"busbar_set_log_sink\0";
}

/// Severity for a record crossing [`LogSinkFn`]. Deliberately a plain `u32` rather than a Rust enum:
/// this crosses a C boundary between two independently-compiled objects, so it has to be a value
/// with a fixed representation. An unrecognized level is clamped by the host, never rejected — a
/// newer plugin inventing a level must not lose the message.
pub mod log_level {
    pub const ERROR: u32 = 1;
    pub const WARN: u32 = 2;
    pub const INFO: u32 = 3;
    pub const DEBUG: u32 = 4;
    /// Distinct from [`DEBUG`] on purpose. Folding the two together destroys the level in transit,
    /// so a host running at DEBUG could not filter plugin TRACE back out.
    pub const TRACE: u32 = 5;
    /// "Emit nothing." What the host passes when its own subscriber is disabled entirely, so the
    /// plugin can skip building a record no one will read.
    pub const OFF: u32 = 0;
}

/// The host-side callback a plugin invokes to emit one log record.
///
/// `ctx` is the opaque pointer the host supplied alongside this fn — a plain fn pointer carries no
/// captured state, so the host needs it to know WHICH plugin is talking. The plugin passes it back
/// verbatim and must never interpret or free it.
///
/// `extern "C"`, NOT `"C-unwind"`: this is the host's code called FROM the plugin, and a panic
/// unwinding out of it into a differently-compiled object is undefined behaviour. The host catches
/// its own panics inside.
///
/// `msg` is UTF-8, `msg_len` bytes, borrowed for the duration of the call only. The host copies
/// anything it keeps.
pub type LogSinkFn =
    unsafe extern "C" fn(ctx: *mut c_void, level: u32, msg: *const u8, msg_len: usize);

/// `busbar_set_log_sink` — the host hands the plugin somewhere to send its diagnostics.
///
/// WHY THIS EXISTS. A plugin is a cdylib that statically links its OWN copy of `tracing-core`, so it
/// gets its own dispatcher, and nothing bridges that to the host's. Every `tracing::warn!` inside a
/// loaded plugin was therefore discarded — including auth-oidc's on a FAILED TOKEN SIGNATURE
/// VERIFICATION, which is precisely the line an operator needs. Plugins worked around it with
/// `eprintln!`, which does reach the shared stderr, but bypasses the host's subscriber entirely: no
/// level filtering, no structured fields, no OTLP export, and nothing tying the line to which plugin
/// emitted it.
///
/// WHY IT IS NOT A TRANSPORT BUMP. [`TRANSPORT_VERSION`] covers the SIX required signatures and the
/// ptr+len rule; this is a SEVENTH, OPTIONAL symbol and none of the six change. The loader looks it
/// up and simply does not call it when absent, so an existing signed artifact keeps loading and
/// behaving exactly as before. Same reasoning already applied to adding `STATUS_UNSUPPORTED` /
/// `STATUS_PANIC`.
///
/// CALLED ONCE, immediately after a successful `busbar_open`, before any `busbar_call`. The sink must
/// remain valid for the life of the plugin and may be invoked from ANY thread, so a plugin storing it
/// needs a `Sync` cell.
/// `max_level` is the HOST's own maximum enabled level (a [`log_level`] constant), so the plugin can
/// filter on ITS side of the boundary. That direction matters: a plugin's dispatcher would otherwise
/// claim interest in everything, and every `trace!`/`debug!` in the plugin's whole dependency tree
/// (its SQL driver, its HTTP stack) would render a string and cross this call on the REQUEST PATH
/// only for the host to drop it. Sampled once at load; a host whose level changes later keeps
/// working, it just filters a little coarsely until the next load.
pub type SetLogSinkFn =
    unsafe extern "C-unwind" fn(sink: LogSinkFn, ctx: *mut c_void, max_level: u32);

/// The hard cap on a single response/error buffer a plugin returns, checked BEFORE allocation on both
/// sides. Defense against a buggy/hostile plugin handing back a huge length to OOM the engine. 256 MiB
/// is orders of magnitude past any real governance/auth payload, so a legitimate reply never trips it.
pub const MAX_PLUGIN_RESPONSE_LEN: usize = 256 * 1024 * 1024;

/// Status returned by `open`/`call`. The four positive/neutral codes below are DISTINCT signals the
/// loader keys different behavior on; they are never overloaded. See each const.
///
/// TRANSPORT is FROZEN at [`TRANSPORT_VERSION`] = 1: adding [`STATUS_UNSUPPORTED`]/[`STATUS_PANIC`] is
/// NOT a transport bump — the six signatures, the ptr+len rule, and the meanings of `OK`/`ERR` are
/// unchanged; `PROTOCOL` merely stops being overloaded and two positive codes are added. A v1-era SDK
/// plugin that predates these still returns `STATUS_PROTOCOL` WITH a `"malformed request JSON: …"`
/// body for an undecodable variant; the loader keys its legacy-shape acceptance on exactly that body
/// (see `plugin-loader`'s `LEGACY_V1_UNDECODABLE_PREFIX`), never on the status alone.
///
/// `OK`: the out buffer holds the success payload.
pub const STATUS_OK: i32 = 0;
/// A DEFINED backend failure — the out buffer holds a UTF-8 error message. The op RAN and returned an
/// error (a [`busbar_api::StoreError`]/`SecretError`/… rendered). Propagated by the loader.
pub const STATUS_ERR: i32 = 1;
/// A caller-PROTOCOL violation the plugin detected BEFORE running user code: a null handle, a null
/// request buffer with `len > 0`, a garbled ABI frame. No user code ran, so the out buffer stays
/// EMPTY. Propagated, never a fallback signal.
///
/// Value is negative for backward wire compatibility with the v1-era SDK, which overloaded this code.
/// The two v1 uses are told apart by the OUT BUFFER, and the direction matters: a v1 undecodable
/// request variant wrote `"malformed request JSON: …"` into the buffer (→ the loader's legacy
/// unsupported signal, see [`STATUS_UNSUPPORTED`]), whereas a v1 CAUGHT PANIC returned this status
/// bare, with NO buffer — exactly like a null handle. So an EMPTY buffer is never the unsupported
/// signal; reading it as one re-opens the revocation fail-open [`STATUS_PANIC`] exists to close.
pub const STATUS_PROTOCOL: i32 = -1;
/// The plugin could not DECODE this request variant — an older SDK build that predates the op. A
/// forward-compat signal the loader MAY treat as "op unsupported by this build" and fall back to a
/// safe default WHERE a fallback is defined (denylist/audit-tail/append-audit). NEVER emitted for a
/// panic or a backend failure — that distinction is what closes the revocation fail-open. Out buffer =
/// UTF-8 message.
pub const STATUS_UNSUPPORTED: i32 = 2;
/// User code PANICKED and was caught at the export boundary. A REAL failure that MUST propagate — it is
/// explicitly NOT the unsupported signal, so a plugin panic can never open the safe-default fallback
/// (the revocation-denylist fail-open is closed by this distinction). Out buffer = UTF-8 message.
pub const STATUS_PANIC: i32 = 3;

/// A `Store` operation and its arguments, serialized as the `call` request payload. One
/// self-describing enum keeps the C ABI to a single `call` symbol regardless of how many methods
/// the `Store` trait grows — the variant IS the op-code. Mirrors [`busbar_api::Store`] one-to-one.
#[derive(Debug, Serialize, Deserialize)]
pub enum StoreRequest {
    PutKey(VirtualKey),
    GetKey(String),
    ListKeys,
    /// TOMBSTONE `id` — see [`busbar_api::Store::delete_key`]'s doc. The row survives; the plugin
    /// implements the cascade (destroy credentials, `enabled=false`, `deleted_at=now()`).
    DeleteKey(String),
    /// PII-erasure-only on an already-tombstoned key. See
    /// [`busbar_api::Store::scrub_key`].
    ScrubKey(String),
    /// Incremental hydration delta for keys — see [`busbar_api::Store::list_keys_since`].
    ListKeysSince(u64),
    /// `get_usage` - the (bucket, window) token ledger. `bucket_id` is a key id or a budget-group
    /// bucket id; no dollar field crosses this wire (spend derives from ledger x rate card).
    GetUsage {
        bucket_id: String,
        window_start: u64,
    },
    /// `put_usage` - ABSOLUTE set of a (bucket, window) ledger (single-writer write-behind).
    PutUsage {
        bucket_id: String,
        window_start: u64,
        ledger: UsageLedger,
    },
    /// `add_usage` - ADDITIVE accumulate of a (bucket, window) ledger: a signed requests delta plus
    /// per-(model, tier) signed token deltas (the fleet-honest flush; counters floor at 0).
    AddUsage {
        bucket_id: String,
        window_start: u64,
        delta: UsageDelta,
    },
    AddMetering(MeteringDelta),
    ListMetering(u64),
    /// Retention purge for the rate-limit window ledger. See
    /// [`busbar_api::Store::purge_windows_before`].
    PurgeWindowsBefore(u64),
    /// Retention purge for the durable billing ledger. Admin-triggered only, never automatic — see
    /// [`busbar_api::Store::purge_metering_before`].
    PurgeMeteringBefore(String),
    /// `put_credential` — see [`busbar_api::Store::put_credential`]. Kind-polymorphic (today only
    /// `kind: "sigv4"`), the generalized replacement for the old AWS-specific
    /// `PutAwsCredential`/`AwsCredential` shape.
    PutCredential(CredentialSecret),
    PutKeyWithCredential {
        key: VirtualKey,
        secret: CredentialSecret,
    },
    ListCredentials(String),
    LookupCredentialSecret {
        kind: String,
        public_id: String,
    },
    RevokeCredential {
        id: String,
        reason: String,
    },
    /// Incremental hydration delta for credentials — see
    /// [`busbar_api::Store::list_credentials_since`].
    ListCredentialsSince(u64),
    /// `append_audit` — persist one admin audit record durably. ADDITIVE (ABI stays v1): a plugin
    /// built against the older SDK never sees this variant; the engine's loader maps its
    /// "unexpected/unsupported response" into the trait's default no-op, so old plugins are safe.
    AppendAudit(AuditRecord),
    /// `list_audit` — every persisted audit record (oldest-first), the boot restore source. ADDITIVE.
    ListAudit,
    /// `list_audit_tail` - the most-recent `limit` audit records, oldest-first (the BOUNDED boot
    /// restore source). ADDITIVE (ABI stays v1): a plugin built against the older SDK never sees this
    /// variant, so the engine's loader FALLS BACK to `ListAudit` + tail-truncation. Bounds the restore
    /// read so a large durable history cannot exceed the ABI response cap or OOM the ring.
    ListAuditTail(u64),
    /// `add_denylist` - revoke a signed-token key by subject id (1.5.0). ADDITIVE.
    AddDenylist {
        sub: String,
        reason: String,
    },
    /// `list_denylist` - every denied subject id (boot hydrate). ADDITIVE.
    ListDenylist,

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD SURFACE (1.6.0) ──────────────────────────────────
    //
    // Eight KIND-TAGGED variants that SUBSUME the fourteen protocol-named durable ops
    // (put_task/…/redeem_ask_state) the wire once carried — the wire half of the 14→8 collapse in
    // the 1.6.0 design, now the ONLY durable-plane surface (the named variants are deleted and
    // `ABI_VERSION` bumped to 3, so an old named-only artifact is refused at load, never mis-called).
    // Every one maps to a DEFAULTED accept-and-keep-nothing trait method, so a backend that keeps no
    // durable rows behaves exactly as the shipped RAM default does.
    //
    // The typed sidecar columns of the neutral record (`parent`/`seq`/`ts`/`disposition`) live on
    // the trait's [`busbar_api::PlaneRecord`] envelope; this commit's WIRE carries only the subset
    // each verb needs to route (`kind`/`id`/`body`, plus append's `parent`/`seq`). Relocating the
    // full sidecar onto the wire is the later schema commit — see the 1.6.0 design's retention note.
    /// UPSERT one plane record by `(kind, id)` — the neutral `PutTask`/`PutMcpDemotion`.
    UpsertPlaneRecord {
        kind: String,
        id: String,
        body: Vec<u8>,
    },
    /// GET the opaque body for `(kind, id)`, or `None` — the neutral `GetTask`.
    GetPlaneRecord {
        kind: String,
        id: String,
    },
    /// APPEND one child record within `parent`, ordered by `seq` — the neutral
    /// `AppendTaskEvent`/`AppendMcpCall`.
    AppendPlaneRecord {
        kind: String,
        parent: String,
        seq: u64,
        body: Vec<u8>,
    },
    /// LIST a kind's records, narrowed by `selector` — the neutral `ListTasks`/`ListMcpDemotions`
    /// ([`PlaneSelector::All`]) and `ListTaskEvents`/`ListMcpCalls` ([`PlaneSelector::Parent`]).
    ListPlaneRecords {
        kind: String,
        selector: PlaneSelector,
    },
    /// LIST every parent with a record of `kind` — the neutral `ListMcpCallPrincipals`.
    ListPlaneRecordParents {
        kind: String,
    },
    /// RETENTION purge for `kind`, honoring that kind's terminal-only-vs-all contract — the neutral
    /// `PurgeTasksBefore`/`PurgeMcpCallsBefore`.
    PurgePlaneRecordsBefore {
        kind: String,
        before: u64,
    },
    /// DELETE the record `(kind, id)`; absent is a no-op — the neutral `ClearMcpDemotion`.
    DeletePlaneRecord {
        kind: String,
        id: String,
    },
    /// TEST-AND-SET one single-use token of `kind` — the neutral `RedeemAskState`.
    RedeemPlaneToken {
        kind: String,
        token: String,
        expires_at: u64,
        now: u64,
    },
}

/// The success payload for a `call`, matched to the request variant. Store-level errors do NOT ride
/// here — they return `STATUS_ERR` with the message in the out buffer — so a caller that sees `OK`
/// deserializes exactly the response shape its request implies.
#[derive(Debug, Serialize, Deserialize)]
pub enum StoreResponse {
    /// A write that returns nothing (`put_key`, `delete_key`, `put_usage`, `add_metering`, …).
    Unit,
    /// `get_key` — the key, or `None` if absent.
    Key(Option<VirtualKey>),
    /// `list_keys` / `list_keys_since` — every key (unfiltered — see
    /// [`busbar_api::Store::list_keys`]'s doc; tombstones included).
    Keys(Vec<VirtualKey>),
    /// `get_usage` - the (bucket, window) token ledger.
    Usage(UsageLedger),
    /// `list_metering` — the bucket's rows.
    Metering(Vec<MeteringRow>),
    /// A retention-purge count (`purge_windows_before`/`purge_metering_before`).
    Purged(u64),
    /// `list_credentials` — a key's credential metadata rows (never the secret).
    Credentials(Vec<CredentialMeta>),
    /// `lookup_credential_secret` — the resolved credential, or `None` if unknown.
    CredentialSecret(Option<CredentialSecret>),
    /// `list_credentials_since` — the hydration delta, secrets included (see that method's doc for
    /// why the verify-path hydration cache needs the plaintext in-process).
    CredentialSecrets(Vec<CredentialSecret>),
    /// `list_audit` — every persisted audit record, oldest-first. ADDITIVE (ABI stays v1).
    Audit(Vec<AuditRecord>),
    /// `list_denylist` - every denied subject id (1.5.0 signed-token revocation). ADDITIVE.
    Denylist(Vec<String>),

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD SURFACE (1.6.0) ──────────────────────────────────
    //
    // Four response variants for the eight kind-tagged requests, now the ONLY durable-plane
    // responses (the named `Task`/`Tasks`/`TaskEvents`/`McpCalls`/`McpCallPrincipals`/`McpDemotions`
    // variants are deleted and `ABI_VERSION` bumped to 3). `GetPlaneRecord`/`ListPlaneRecords`/
    // `ListPlaneRecordParents` carry OPAQUE bodies (the store never decodes the protocol row); the
    // write/purge verbs reuse `Unit`/`Purged`, and `RedeemPlaneToken` returns `Redeemed`. Each is its
    // OWN variant rather than folded into a same-shaped sibling (e.g. `PlaneRecordParents` and
    // `Denylist` are both `Vec<String>`) so `unexpected()` still catches a plugin answering the wrong
    // shape — that guard only works if the shapes differ.
    /// `get_plane_record` — the opaque record body, or `None` when absent.
    PlaneRecord(Option<Vec<u8>>),
    /// `list_plane_records` — the selected records' opaque bodies, oldest-first for a parent selector.
    PlaneRecords(Vec<Vec<u8>>),
    /// `list_plane_record_parents` — every parent with a record of the kind.
    PlaneRecordParents(Vec<String>),
    /// `redeem_plane_token` — whether THIS redemption was the first. Its own variant rather than a
    /// shared boolean so `unexpected()` can catch a plugin answering the wrong shape (that guard only
    /// works if the shapes differ).
    Redeemed(bool),
}

// ── SECRET-plugin wire (`kind: secret`) ─────────────────────────────────────────────────────────
// A secret plugin rides the SAME six-symbol C shape as a store plugin (busbar_abi/
// busbar_plugin_kind/busbar_open/busbar_call/busbar_free/busbar_close; JSON payloads over ptr+len),
// under the SAME kind-neutral symbol names ([`symbol`]) — NOT its own — distinguished only by its
// signed manifest's `kind` and its own tiny request enum. A plugin is a plugin: the
// tarball/manifest/signature/trust pipeline is IDENTICAL - only the manifest `kind` (and therefore
// which engine seam consumes it) differs.

/// The secret-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: secret`).
/// v1 (1.5.0): the initial `Resolve` wire. This is the per-kind payload axis, NOT the transport axis
/// — a secret plugin exports the SAME six neutral symbols ([`symbol`]) as every other kind.
pub const SECRET_ABI_VERSION: u32 = 1;

/// The auth-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: auth`).
/// v1 (1.5.0): the initial wire. Named the same way `SECRET_ABI_VERSION` and `hook::HOOK_ABI_VERSION`
/// are — auth was the one kind still floor-checked against a bare `&[1, 1]` literal duplicated in
/// `plugin-loader::registry` AND `plugin-sdk`, with no compiler link between the two halves of the
/// handshake; the other two kinds already share a named const, so a bump there is caught at compile
/// time. This closes that gap without changing the value.
///
/// v2 (1.5.2 token-exchange): ADDITIVELY adds the browser-login primitives —
/// [`auth::AuthRequest::BeginLogin`]/[`auth::AuthRequest::CompleteLogin`] and
/// [`auth::AuthResponse::AuthorizeUrl`]/[`auth::AuthResponse::TokenExchange`]. `AuthRequest`/
/// `AuthResponse` are externally-tagged with NO `deny_unknown_fields`, so the new variants are
/// wire-additive: a v1 plugin that only ever emits `Authenticate`/`Identity` is unaffected, and the
/// loader floor stays `[1, 2]` (v1 plugins still load). Bumping the const value is the v2
/// declaration; the identity-only `Identity` invariant (its own `deny_unknown_fields`) is untouched.
pub const AUTH_ABI_VERSION: u32 = 2;

/// A [`busbar_api::SecretModule`] operation, serialized as the secret `call` request payload.
#[derive(Debug, Serialize, Deserialize)]
pub enum SecretRequest {
    /// `resolve` - one secret reference's opaque settings map in, the secret bytes out.
    Resolve {
        settings: serde_json::Map<String, serde_json::Value>,
        /// Optional caller-side deadline in milliseconds. `#[serde(default)]` so an OLD
        /// plugin decoding a request from a NEW engine (which doesn't know this field) still
        /// parses fine, and a NEW plugin decoding a request from an OLD engine (which never sends
        /// it) sees `None` — additive both directions. Advisory only: the transport itself does
        /// not enforce it; a module that can bound its own call SHOULD honor it.
        #[serde(default)]
        deadline_ms: Option<u64>,
    },
}

/// The success payload for a secret `call`. A TRANSPORT-level failure (the plugin panicked, or
/// explicitly signals a status the loader treats as an error) still returns `STATUS_ERR` with a
/// UTF-8 message in the out buffer (which must never carry secret material) — that path is
/// unchanged and every plugin built before this variant existed keeps working exactly as before.
/// `Error` is the ADDITIVE alternative: a plugin that wants to report a TYPED module-level
/// failure (as opposed to a transport failure) returns it here, via `STATUS_OK`, instead of the
/// untyped `STATUS_ERR` string channel — this is what lets a host distinguish "no such secret"
/// from "the backend is unreachable" and react correctly to each.
#[derive(Debug, Serialize, Deserialize)]
pub enum SecretResponse {
    /// `resolve` - the secret bytes.
    Bytes(Vec<u8>),
    /// `resolve` failed at the module level (not the transport level) with a known taxonomy.
    Error {
        kind: busbar_api::SecretErrorKind,
        message: String,
    },
}

// ── C fn-pointer signatures the engine resolves ──────────────────────────────────────────────────
// Provided as type aliases so the engine's loader and the plugin's SDK agree on the exact ABI. All
// are `unsafe extern "C-unwind"`. Buffers the plugin allocates (the `out*` params) are owned by the
// engine until it calls `busbar_free` on them.
//
// WHY `"C-unwind"` (not plain `"C"`): under the workspace default `panic = "unwind"`, a Rust panic
// that tries to unwind OUT OF a plain `extern "C"` function is turned by the compiler into an
// immediate ABORT at the callee (plugin) frame — it never reaches the caller, so the engine's
// `catch_unwind` at the call site can NEVER intercept it and a panicking plugin aborts the whole
// gateway. `extern "C-unwind"` makes unwinding across this boundary DEFINED: a panic propagates as a
// forced unwind that the engine's `catch_unwind` DOES catch, turning a panicking plugin into a clean
// fail-closed error instead of a process abort. This is the load-bearing half of the panic-safety
// seam; the engine wraps every call site (open/call/close/free/handshake) in `catch_unwind` (see the
// loader), and non-`"C-unwind"` C/Go/Zig plugins still abort on unwind exactly as before (their
// runtimes don't unwind), which is the pre-existing, documented behavior for non-Rust plugins.

/// `busbar_abi` — returns the [`TRANSPORT_VERSION`] the plugin was built against.
pub type AbiFn = unsafe extern "C-unwind" fn() -> u32;

/// `busbar_plugin_kind` — returns a pointer to a NUL-terminated static string naming the ONE kind
/// this library speaks: `"store"` | `"secret"` | `"auth"` | `"hook"` | `"export"` (the full set is
/// [`kind`]).
///
/// The return carries NO LENGTH: the engine reads it with `CStr::from_ptr` and walks to the first
/// NUL byte. A pointer into a non-NUL-terminated buffer is therefore an unbounded out-of-bounds read
/// in the ENGINE's address space — undefined behavior, not a load error. So the pointer MUST come
/// from one of the NUL-terminated [`kind`] siblings (`kind::STORE_NUL.as_ptr()`, …), never from the
/// plain `kind::STORE.as_ptr()` (a `&str`, which has no terminator). Plugins built on
/// `busbar-plugin-sdk` get the safe form from the export macro and never write this by hand.
pub type PluginKindFn = unsafe extern "C-unwind" fn() -> *const u8;

/// `busbar_open` — construct an instance from a JSON config blob. On `STATUS_OK`, `*out_handle` is
/// the opaque instance pointer (passed back to `call`/`close`). On `STATUS_ERR`, `*out_err` /
/// `*out_err_len` hold a UTF-8 message the engine must `free`.
pub type OpenFn = unsafe extern "C-unwind" fn(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
) -> i32;

/// `busbar_call` — run one request (JSON in `req`). On `STATUS_OK`, `*out`/`*out_len` hold the JSON
/// response; on `STATUS_ERR`, a UTF-8 error message. Either way the engine owns and must `free` the
/// out buffer.
pub type CallFn = unsafe extern "C-unwind" fn(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// `busbar_free` — release a buffer the plugin allocated (`open`'s error, `call`'s payload). The
/// plugin frees with the SAME allocator it allocated with — the engine never frees plugin memory.
pub type FreeFn = unsafe extern "C-unwind" fn(ptr: *mut u8, len: usize);

/// `busbar_close` — drop the instance behind `handle`. Called once, at shutdown/unload.
pub type CloseFn = unsafe extern "C-unwind" fn(handle: *mut c_void);

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
