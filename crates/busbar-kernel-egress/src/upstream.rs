// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the egress unit does to an upstream exchange's bytes and headers (#83a O1): the capped
//! upstream-body read ([`read_capped`], and [`ReadEnd`], WHY it stopped), the two operator body caps
//! it reads under, the network-failure labels a transient failure is recorded with, and the
//! client-header transparency that carries caller-sent headers onto the egress request. Moved
//! verbatim from the retired shared value crate; the kernel's `proxy` re-exports every item at its
//! historical `busbar_kernel::proxy::…` path.

use busbar_contract::http;
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

// ── Network-transient `err_type` values passed to `record_transient_in`. Distinct from the
//    protocol's error-KIND tokens: they label the *category* of network failure recorded in the
//    breaker store, not the protocol-level error kind surfaced to the caller.
/// `err_type` recorded when the upstream connection could not be opened.
pub const ERR_NET_CONNECT: &str = "connect";
/// `err_type` recorded when the upstream did not answer within the attempt's deadline.
pub const ERR_NET_TIMEOUT: &str = "timeout";
/// `err_type` recorded when the transport failed after the connection opened.
pub const ERR_NET_TRANSPORT: &str = "transport";
/// `err_type` recorded when a HalfOpen probe's degraded forward returns a non-2xx (bumps cooldown).
pub const ERR_DEGRADED_NON2XX: &str = "degraded-non2xx";

// ── CLIENT-HEADER FORWARDING — THE NEUTRAL MECHANISM (dialect-agnostic) ────────────────────────────
//
// busbar rebuilds the egress header map FRESH from lane creds + CT/UA/Accept and historically DROPPED
// every client-supplied request header. Forwarding a caller's opt-in selector headers back onto the
// upstream request is a two-phase mechanism, provided HERE as neutral primitives that hard-code NO
// header name and know NOTHING about any dialect: the SET of names to forward is supplied entirely by
// the caller (a plane), as DATA. The plane owns the policy (which names, and which are meaningful for
// which egress destination); this crate owns only the "capture these names / fold these names in"
// mechanics. A neutral build with no plane resident calls neither and forwards nothing.
//
//   * [`collect_client_headers`] — capture, at INGRESS, exactly the client headers whose name is in
//     the caller-supplied `names`, preserving bytes and multiplicity (opt-in: a name the caller did
//     not send contributes nothing). Nothing is synthesized.
//   * [`apply_client_headers`] — fold the previously-collected headers into a freshly built EGRESS
//     header map, forwarding ONLY those whose name is in the caller-supplied `allowed` set (the
//     per-destination allowlist the plane narrows to at the egress assembly site).

/// Capture from an inbound client header map exactly the headers whose (case-insensitive) name appears
/// in `names` and that the caller ACTUALLY SENT — preserving the exact bytes and the MULTIPLICITY (a
/// header sent more than once is captured once per value). OPT-IN and non-synthesizing: a name absent
/// from `headers` contributes nothing, so a request carrying none of `names` yields an EMPTY vec.
///
/// The `names` set is supplied by the caller; this function hard-codes none — it is the neutral "grab
/// this set of header names off the request" mechanic, with the set itself owned entirely by the
/// caller (a plane).
pub fn collect_client_headers(
    headers: &http::HeaderMap,
    names: &[&str],
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    let mut out = Vec::new();
    // Iterate the request's OWN headers (their `HeaderName` is already the canonical lowercase form)
    // and keep the ones the caller asked for — so the returned name is the real inbound one, never a
    // token this function fabricated.
    for (name, value) in headers.iter() {
        if names.iter().any(|n| name.as_str().eq_ignore_ascii_case(n)) {
            out.push((name.clone(), value.clone()));
        }
    }
    out
}

/// Fold previously-[`collect_client_headers`]ed headers into a freshly built egress header map,
/// forwarding ONLY those whose (case-insensitive) name appears in the caller-supplied `allowed` set —
/// the per-destination allowlist. Anything whose name is not in `allowed` is dropped. The FIRST
/// forwarded value for a given name REPLACES any existing value for it (`insert` clears priors — so a
/// caller's explicit value wins over a busbar default); subsequent same-name values are APPENDED,
/// preserving multiplicity. A no-op on an empty `collected` or empty `allowed`, so the non-forwarding
/// path stays byte-identical.
///
/// `allowed` is supplied by the caller; this function hard-codes no header name — it forwards exactly
/// the set it is given and nothing else.
pub fn apply_client_headers(
    egress_headers: &mut http::HeaderMap,
    collected: &[(http::HeaderName, http::HeaderValue)],
    allowed: &[&str],
) {
    let mut replaced: Vec<&http::HeaderName> = Vec::new();
    for (name, value) in collected {
        if !allowed
            .iter()
            .any(|a| name.as_str().eq_ignore_ascii_case(a))
        {
            continue;
        }
        if replaced.contains(&name) {
            egress_headers.append(name.clone(), value.clone());
        } else {
            egress_headers.insert(name.clone(), value.clone());
            replaced.push(name);
        }
    }
}
