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

/// Read an upstream response body, buffering at most `cap` bytes. Streams chunks with a running byte
/// counter rather than `r.bytes()` (which would buffer the entire — possibly multi-gigabyte — body
/// before any cap could apply). Returns the buffered prefix and whether the body was TRUNCATED (more
/// bytes remained at the cap), so a caller that must parse the whole body (cross-protocol 2xx
/// translation) can distinguish "too large to translate" from "genuinely unparseable" instead of
/// silently mis-reporting a truncated success as an untranslatable error.
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

pub async fn read_capped(r: reqwest::Response, cap: usize) -> (Bytes, ReadEnd) {
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
    let mut r = r;
    let mut end = ReadEnd::Complete;
    loop {
        match r.chunk().await {
            Ok(Some(chunk)) => {
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
            Ok(None) => break, // clean end of body — buffer is complete
            Err(_) => {
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
