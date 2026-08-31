// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral capped-read primitive shared by every upstream body read.
//!
//! `read_capped` streams an upstream response body under a byte cap rather than buffering it whole,
//! and [`ReadEnd`] records WHY the read stopped so a caller that must parse the whole body can tell
//! a body that arrived in full from one that was cut short. It lives in the neutral substrate
//! because both core's proxy engine and the egress/auth paths read upstream bodies this way, and a
//! plane crate names it without reaching into `busbar-core`. Core's `proxy::wire` re-exports it
//! unchanged.

pub mod sse;

use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Historical default cap on a buffered upstream ERROR / verbatim-relay body (bytes) — 256 KiB, the
/// value read before any operator config is installed (unit tests, pre-boot). Owned HERE, in the
/// neutral substrate, and re-exported by core's `config` as `DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES`
/// so the number has ONE definition: core's `limits` installs the resolved value into the process
/// global below, and a plane crate reads it back through [`max_upstream_buffered_bytes`] without
/// reaching into `busbar-core` (whose `LimitsResolved`/`config` types are not neutral).
pub const UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT: usize = 256 * 1024;

/// Process-global cap on a buffered upstream ERROR body (bytes). Seeded to the historical default so
/// an UNINSTALLED read (unit tests, pre-boot) is byte-identical to core's `limits` fallback; core's
/// `limits::install`/`InstallGuard` overwrite it with the operator-resolved value on every apply and
/// restore it on a rejected apply, so the value here always tracks core's installed
/// `LimitsResolved::upstream_error_body_max_bytes`. Read PER upstream-error-body buffer (not per
/// byte), so a `Relaxed` atomic is ample — no accessor orders anything against this load.
static UPSTREAM_ERROR_BODY_MAX_BYTES: AtomicUsize =
    AtomicUsize::new(UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT);

/// Read the installed cap on a buffered upstream ERROR / verbatim-relay body (bytes). The neutral
/// twin of core's `proxy::max_upstream_buffered_bytes()`: same process-global value, named from a
/// plane crate without reaching into `busbar-core`. Falls back to
/// [`UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT`] until core installs the resolved limits.
pub fn max_upstream_buffered_bytes() -> usize {
    UPSTREAM_ERROR_BODY_MAX_BYTES.load(Ordering::Relaxed)
}

/// Install the resolved upstream-error-body cap process-wide. Called ONLY by core's `limits`
/// install/reload/rollback path with the value it also installs into its own `LimitsResolved` slot,
/// so the two never diverge; there is no other writer.
pub fn set_max_upstream_buffered_bytes(bytes: usize) {
    UPSTREAM_ERROR_BODY_MAX_BYTES.store(bytes, Ordering::Relaxed);
}

/// Historical default egress translate-body cap (bytes) — 32 MiB, the value read before any operator
/// config is installed (unit tests, pre-boot). MUST equal core's `config::DEFAULT_REQUEST_BODY_MAX_BYTES`
/// (the one knob that drives both the inbound `DefaultBodyLimit` and this egress translate cap); the two
/// are pinned equal by construction and by core's `limits` tests. Owned HERE, in the neutral substrate,
/// so a plane crate reads the cap without reaching into `busbar-core`.
pub const TRANSLATE_BODY_MAX_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

/// Process-global egress translate-body cap (bytes). Seeded to the historical default so an
/// UNINSTALLED read (unit tests, pre-boot) is byte-identical to core's
/// `limits::translate_body_max_bytes()` fallback; core's `limits::install`/`InstallGuard` overwrite it
/// with the operator-resolved `LimitsResolved::request_body_max_bytes` on every apply and restore it on
/// a rejected apply, so the value here always tracks core's installed knob. Read PER translated body
/// (not per byte), so a `Relaxed` atomic is ample.
static TRANSLATE_BODY_MAX_BYTES: AtomicUsize = AtomicUsize::new(TRANSLATE_BODY_MAX_BYTES_DEFAULT);

/// Read the installed egress translate-body cap (bytes). The neutral twin of core's
/// `limits::translate_body_max_bytes()`: same process-global value, named from a plane crate without
/// reaching into `busbar-core`. Falls back to [`TRANSLATE_BODY_MAX_BYTES_DEFAULT`] until core installs
/// the resolved limits.
pub fn max_translate_body_bytes() -> usize {
    TRANSLATE_BODY_MAX_BYTES.load(Ordering::Relaxed)
}

/// Install the resolved egress translate-body cap process-wide. Called ONLY by core's `limits`
/// install/reload/rollback path with the value it also installs into its own `LimitsResolved` slot,
/// so the two never diverge; there is no other writer.
pub fn set_max_translate_body_bytes(bytes: usize) {
    TRANSLATE_BODY_MAX_BYTES.store(bytes, Ordering::Relaxed);
}

/// Why a [`read_capped`] read stopped — distinguishes a body that arrived in full from one that
/// was cut short, so the buffered cross-protocol translate path can avoid mis-accounting a
/// half-received completion as a clean success (recording breaker success + charging tokens on a
/// body that is in fact a truncated/corrupt fragment of a failed transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadEnd {
    /// The upstream signalled end-of-body (`Ok(None)`): the buffer holds the complete response.
    Complete,
    /// The body overran `cap` before EOF: the buffer holds a prefix, more bytes existed.
    Truncated,
    /// The transport failed mid-body (`Err(_)` from `chunk()`): the buffer holds an incomplete,
    /// possibly-corrupt fragment of a transfer that never finished. NOT a clean completion.
    TransportError,
}

/// Read an upstream response body, buffering at most `cap` bytes. Streams chunks with a running byte
/// counter rather than `r.bytes()` (which would buffer the entire — possibly multi-gigabyte — body
/// before any cap could apply). Returns the buffered prefix and whether the body was TRUNCATED (more
/// bytes remained at the cap), so a caller that must parse the whole body (cross-protocol 2xx
/// translation) can distinguish "too large to translate" from "genuinely unparseable" instead of
/// silently mis-reporting a truncated success as an untranslatable error.
///
/// GENERIC over the chunk source: the LLM hot path reads a hyper `Incoming`, the
/// substrate/preflight callers read a reqwest response — one capped loop serves both, so the cap
/// semantics (bounded reserve, truncate-on-overrun, transport-error flag) cannot drift between
/// clients. `futures::Stream<Item = Result<Bytes, E>>` is the meeting point both convert to for
/// free (`bytes_stream()` / `BodyStream` + data frames).
pub async fn read_capped<E>(
    mut chunks: impl futures::Stream<Item = Result<Bytes, E>> + Unpin,
    cap: usize,
) -> (Bytes, ReadEnd) {
    // Pre-reserve a BOUNDED initial capacity so the per-chunk `extend_from_slice` below does not
    // reallocate-and-copy the buffer through a geometric growth series as it climbs toward `cap`.
    // Bounded two ways so this never becomes an allocation-amplification lever: (a) capped at `cap`
    // itself (the 256 KiB upstream-buffer cap, or 32 MiB translate cap — never larger), and (b)
    // ceilinged at `READ_CAPPED_RESERVE_CEILING` so a 32 MiB-cap read does not eagerly commit 32 MiB
    // for a response that is, in practice, a few KiB. The cap ENFORCEMENT is unchanged — `cap` still
    // bounds every write below and an over-cap body is still rejected/Truncated; this only changes the
    // starting allocation, never how many bytes are admitted.
    const READ_CAPPED_RESERVE_CEILING: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(READ_CAPPED_RESERVE_CEILING));
    use futures::StreamExt;
    let mut end = ReadEnd::Complete;
    loop {
        match chunks.next().await {
            Some(Ok(chunk)) => {
                let remaining = cap.saturating_sub(buf.len());
                if remaining == 0 {
                    // Cap already full but more bytes arrived — the body overran the cap. Stop
                    // reading; the connection is dropped when `r` falls out of scope.
                    end = ReadEnd::Truncated;
                    break;
                }
                let take = remaining.min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    end = ReadEnd::Truncated; // this chunk filled the cap with bytes left over
                    break;
                }
            }
            None => break, // clean end of body — buffer is complete
            Some(Err(_)) => {
                // Transport error mid-body. Keep what we have for any best-effort error relay, but
                // flag it so the buffered translate path does NOT treat a half-received body as a
                // clean 2xx completion (which would record breaker success and charge tokens on a
                // corrupt fragment). (Was previously indistinguishable from clean EOF.)
                end = ReadEnd::TransportError;
                break;
            }
        }
    }
    (Bytes::from(buf), end)
}

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. Hoisted to one const so the literal isn't repeated across egress/health/observability.
/// Lives here (not `pub(crate)` in core) so a plane crate and the relocated `OperationHandler`
/// codec surface name it without reaching into `busbar-core`; core's `proxy` re-exports it for its
/// own `crate::proxy::APPLICATION_JSON` call sites.
pub const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client. Neutral protocol-boundary content-type named by
/// core's proxy engine and by the plane crates; lives here so a plane names it without reaching
/// into `busbar-core`.
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Metric-label values for the `disposition` dimension on `UPSTREAM_FAILURES_TOTAL` and the
/// `reason` dimension on `FAILOVERS_TOTAL`.
pub const DISPOSITION_TRANSIENT: &str = "transient_upstream";

/// Bounded `pool` metric-label sentinel used for every pre-routing failure (malformed body,
/// unresolved model, governance rejection) so the label space stays finite (metrics.rs).
pub const POOL_LABEL_UNRESOLVED: &str = "unresolved";

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
/// Returned by `client_fault_kind` for `StatusClass::ContextLength` and drives the per-protocol
/// writer to emit the native context-length error category.
pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

/// Unknown/foreign egress protocol default `User-Agent`: a generic-but-present UA still beats
/// sending none. Lives here (not `pub(crate)` in core) so a codec-less protocol declaration in a
/// plane crate (`busbar-mcp`) can state it as its `ProtocolDecl::egress_user_agent` default — an MCP
/// registration has no writer, so its promoted UA fact is this trait default, and the plane must be
/// able to name it without reaching into `busbar-core`. Core's `proxy::egress` re-exports it for its
/// own resolver fallback and the per-protocol writers.
pub const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

// ── Canonical error-KIND tokens the forward layer produces (`cross_protocol_error_kind`) and passes
//    to `ingress_error` as the `kind` argument — the protocol-agnostic discriminant each per-protocol
//    writer maps to its native error category. Relocated DOWN from `busbar-core`'s `proxy` so the
//    `busbar-llm` dialect writers name them without reaching into `busbar-core`; core's `proxy`
//    re-exports each at its historical `crate::proxy::KIND_*` path. The values shared with the
//    OpenAI-family vocabulary alias their canonical home in [`crate::proto`]; the two forward-specific
//    tokens (`overloaded`, `timeout`) are defined here.
/// Anthropic-vocabulary/agnostic forward kind for a generic upstream/API failure.
pub const KIND_API_ERROR: &str = crate::proto::ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from `proto::ERR_TYPE_OVERLOADED` ("overloaded_error",
/// the Anthropic wire spelling): this is busbar's own agnostic kind for a relayed upstream 503.
pub const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from the Anthropic wire's `timeout_error` spelling.
pub const KIND_TIMEOUT: &str = "timeout";
/// Transient upstream-failure forward kind (aliases the OpenAI `server_error` type).
pub const KIND_SERVER_ERROR: &str = crate::proto::ERR_TYPE_SERVER_ERROR;
