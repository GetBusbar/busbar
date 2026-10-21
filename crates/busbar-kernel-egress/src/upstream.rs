// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the egress unit does to an upstream exchange's bytes and headers (#83a O1): the capped
//! upstream-body read ([`read_capped`], and [`ReadEnd`], WHY it stopped), the two operator body caps
//! it reads under, the network-failure labels a transient failure is recorded with, and the
//! per-connection mechanics dropped from the head a plane hands the kernel ([`strip_re_derived`]).
//! Moved verbatim from the retired shared value crate; the kernel's `proxy` re-exports every item
//! at its historical `busbar_kernel::proxy::…` path.

use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Historical default cap on a buffered upstream ERROR / verbatim-relay body (bytes) — 256 KiB, the
/// value read before any operator config is installed (unit tests, pre-boot). Owned HERE and
/// re-exported by the kernel's `config` as `DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES` so the number has
/// ONE definition: the kernel's `limits` installs the resolved value into the process global below,
/// and [`max_upstream_buffered_bytes`] reads it back.
pub const UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT: usize = 256 * 1024;

/// Process-global cap on a buffered upstream ERROR body (bytes). Seeded to the historical default so
/// an UNINSTALLED read (unit tests, pre-boot) is byte-identical to core's `limits` fallback; core's
/// `limits::install`/`InstallGuard` overwrite it with the operator-resolved value on every apply and
/// restore it on a rejected apply, so the value here always tracks core's installed
/// `LimitsResolved::upstream_error_body_max_bytes`. Read PER upstream-error-body buffer (not per
/// byte), so a `Relaxed` atomic is ample — no accessor orders anything against this load.
static UPSTREAM_ERROR_BODY_MAX_BYTES: AtomicUsize =
    AtomicUsize::new(UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT);

/// Read the installed cap on a buffered upstream ERROR / verbatim-relay body (bytes). Falls back to
/// [`UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT`] until the kernel installs the resolved limits.
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
/// are pinned equal by construction and by core's `limits` tests. Owned HERE, beside the cap it seeds.
pub const TRANSLATE_BODY_MAX_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

/// Process-global egress translate-body cap (bytes). Seeded to the historical default so an
/// UNINSTALLED read (unit tests, pre-boot) is byte-identical to core's
/// `limits::translate_body_max_bytes()` fallback; core's `limits::install`/`InstallGuard` overwrite it
/// with the operator-resolved `LimitsResolved::request_body_max_bytes` on every apply and restore it on
/// a rejected apply, so the value here always tracks core's installed knob. Read PER translated body
/// (not per byte), so a `Relaxed` atomic is ample.
static TRANSLATE_BODY_MAX_BYTES: AtomicUsize = AtomicUsize::new(TRANSLATE_BODY_MAX_BYTES_DEFAULT);

/// Read the installed egress translate-body cap (bytes): the same process-global value as core's
/// `limits::translate_body_max_bytes()`. Falls back to [`TRANSLATE_BODY_MAX_BYTES_DEFAULT`] until
/// the kernel installs the resolved limits.
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
/// GENERIC over the chunk source: a caller hands its body as a `futures::Stream` of byte chunks,
/// and one capped loop serves every caller, so the cap semantics (bounded reserve,
/// truncate-on-overrun, transport-error flag) cannot drift between them.
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
                    // reading; the connection goes when `chunks` is dropped.
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

// ── The network-failure classes a pre-response failure is counted under (the kernel's
//    `busbar_failovers_total` `reason` values beside the dispositions). Distinct from the protocol's
//    error-KIND tokens: they label the *category* of network failure, not the protocol-level error
//    kind surfaced to the caller.
/// The class counted when the upstream connection could not be opened.
pub const ERR_NET_CONNECT: &str = "connect";
/// The class counted when the upstream did not answer within the attempt's deadline.
pub const ERR_NET_TIMEOUT: &str = "timeout";

// ── THE HEAD'S PER-CONNECTION MECHANICS (OWNER HARD RULE 2026-10-02, "BUSBAR IS INVISIBLE TO
//    UPSTREAMS") ───────────────────────────────────────────────────────────────────────────────────
//
// What a client sends goes out; the plane decides which of its fields a request carries. The
// fields that never pass are mechanics, not choices, and they are stated here ONCE, naming no
// dialect header: the fields HTTP defines per connection (the contract's `hop_by_hop`, plus every
// name a `connection` field nominates), `host`/`content-length`, which the connection carrying the
// upstream request derives for itself (`RE_DERIVED`), and busbar's own `x-busbar-` namespace
// (`CONTROL_PREFIX`). The far end strips them from every head a plane hands it
// (`strip_re_derived`).

/// The fields the upstream connection derives for itself, beyond HTTP's hop-by-hop set.
///
/// `accept-encoding` is here because busbar reads the answer to meter it and decodes no content
/// coding: a client's `gzip` would make the far end compress what busbar must read (escalated
/// 2026-10-02, PROTO-FIXES; the owner's ruling decides whether it stays).
const RE_DERIVED: &[&str] = &["host", "content-length", "accept-encoding"];

/// busbar's own header namespace: a client field under it is addressed to busbar, never upstream.
const CONTROL_PREFIX: &str = "x-busbar-";

/// Whether the client field `name` is a per-connection mechanic the upstream request re-derives: a
/// hop-by-hop field, a field a `connection` field `nominated`, or one of [`RE_DERIVED`].
fn re_derived<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    // A request's own header names are lower-case already; only a plane-spelled one pays the copy.
    let lower: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        name.to_ascii_lowercase().into()
    } else {
        name.into()
    };
    RE_DERIVED.contains(&&*lower)
        || busbar_contract::abi::transport::fields::hop_by_hop(&lower, nominated)
}

/// Drop from the head a plane hands the kernel the per-connection mechanics (HTTP's hop-by-hop
/// fields, every name a `connection` field nominates, `host`, `content-length` and
/// `accept-encoding`) and busbar's own `x-busbar-` namespace. The connection re-derives the
/// mechanics; the rest is addressed to busbar, never upstream.
pub fn strip_re_derived(fields: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let nominated: Vec<Vec<u8>> = fields
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
        .map(|(_, v)| v.clone())
        .collect();
    fields.retain(|(n, _)| {
        !std::str::from_utf8(n).is_ok_and(|n| {
            re_derived(n, nominated.iter().map(Vec::as_slice))
                || n.to_ascii_lowercase().starts_with(CONTROL_PREFIX)
        })
    });
}
