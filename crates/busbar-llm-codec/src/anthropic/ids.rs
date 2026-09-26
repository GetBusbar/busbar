// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Synthesized native-format Anthropic ids (`msg_…`, `req_…`) drawn from the OS CSPRNG.

use super::*;

/// Mint a protocol-correct Anthropic message id for the cross-protocol path, where the backend
/// supplied none. A native id is `msg_01` + a fixed-length mixed-case base62 token; an official
/// Anthropic SDK only requires the `msg_` prefix and a non-empty unique suffix (it does not parse
/// the body), but matching the native alphabet/version-prefix/length AND drawing the token from the
/// OS CSPRNG removes the structural/entropy tell a client could use to spot a synthesized id.
pub(super) fn synth_message_id() -> String {
    synth_id_with_prefix("msg_")
}

/// Mint a protocol-correct Anthropic request id (`req_01<token>`) for the top level of an error
/// envelope, where busbar synthesizes the error itself and has no upstream request id to forward.
/// Current Anthropic API error responses carry a top-level `request_id`; emitting one whose shape
/// (version prefix, mixed-case base62 alphabet, fixed length) AND entropy match the native form
/// keeps the envelope indistinguishable. Same CSPRNG construction as `synth_message_id`.
pub(super) fn synth_request_id() -> String {
    synth_id_with_prefix("req_")
}

/// The same `req_01<24 base62>` id, built from entropy the CALLER supplies.
///
/// The shape and the width are the native ones — this is the same id, in the same alphabet, at the
/// same length; only the source of the bytes moves. That matters because the envelope is the one
/// place a refusal carries a minted value, and a plane may read no random source: it is handed one.
/// The same bytes always produce the same id, so a caller that supplies a fixed input gets a fixed
/// envelope, and a caller that supplies real entropy gets an envelope indistinguishable from the
/// native form.
///
/// `entropy` is consumed with the SAME rejection sampling the drawn form uses (bytes at or above the
/// largest multiple of 62 are discarded, so the character distribution stays uniform), and it is
/// cycled if it is shorter than the draw needs — so a caller can pass as little as one byte and
/// still get a well-formed id, at the entropy it actually supplied.
#[must_use]
pub fn request_id_from_entropy(entropy: &[u8]) -> String {
    const BASE62_REJECT_FLOOR: u8 = crate::dialect::BASE62_REJECT_THRESHOLD;
    let alphabet = ANTHROPIC_NATIVE_ALPHABET;
    let mut token = [b'0'; SYNTH_ID_TOKEN_LEN];
    if !entropy.is_empty() {
        let mut filled = 0usize;
        // Bounded by construction: every pass over `entropy` either fills at least one character or
        // the input has no in-range byte at all, and the second case is caught by the round counter.
        let mut rounds = 0usize;
        while filled < SYNTH_ID_TOKEN_LEN && rounds < SYNTH_ID_TOKEN_LEN + 1 {
            let mut progressed = false;
            for &byte in entropy {
                if byte >= BASE62_REJECT_FLOOR {
                    continue; // biased residue — discard, exactly as the drawn form does
                }
                token[filled] = alphabet[(byte % 62) as usize];
                filled += 1;
                progressed = true;
                if filled == SYNTH_ID_TOKEN_LEN {
                    break;
                }
            }
            if !progressed {
                break; // every supplied byte was out of range; the '0' fill stands
            }
            rounds += 1;
        }
    }
    // `token` is ASCII base62 by construction, hence always valid UTF-8.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("req_01{token}")
}

/// Shared id construction for both `msg_` and `req_`. The suffix is the native `01` version marker
/// followed by a fixed-width 24-char mixed-case base62 token drawn ENTIRELY from the OS CSPRNG
/// (mirroring the sibling `synth_anthropic_request_id` and `openai_chat::synth_completion_id`). The
/// earlier `(unix_second, counter)` encoding was a deterministic clock+counter fingerprint, and even
/// a counter overlaid into a fixed region of an otherwise-random token leaves those characters
/// predictable/low-entropy (the counter stays small, so its high base62 digits are constant '0') —
/// a structural tell at WHATEVER position (leading or trailing) it occupies. We therefore overlay NO
/// counter at all: a 24-char base62 token is ~142 bits of entropy with a ~2^71 birthday bound, so
/// pure CSPRNG output is collision-free in practice and every position stays fully random, exactly
/// like a native Anthropic id. Never panics on the request path.
/// Fill `out` with uniformly-distributed base62 characters drawn from `alphabet`, via REJECTION
/// SAMPLING. A bare `byte % 62` is biased: 256 = 4*62 + 8, so the residues 0..7 are drawn from 5
/// source bytes and 8..61 from only 4 — over-representing the low characters by ~25%, a
/// statistical fingerprint that distinguishes a synthesized id from a native (uniform) one. We
/// therefore reject any byte >= 248 (the largest multiple of 62 that fits in a u8) and consume
/// only the in-range bytes — the ONE bias-elimination scheme this module uses, shared by both
/// `synth_id_with_prefix` and `synth_anthropic_request_id` (mirrors
/// `openai_chat::synth_completion_id`, the other rejection-sampling base62 synth). Returns `false`
/// on an entropy failure — callers decide what to do with the partially-filled buffer; `out` is
/// left with whatever prefix was already written plus its initial contents for the rest.
pub(super) fn fill_base62(out: &mut [u8], alphabet: &[u8; 62]) -> bool {
    const BASE62_REJECT_FLOOR: u8 = crate::dialect::BASE62_REJECT_THRESHOLD;
    // Fixed stack buffer, no heap allocation on this hot path — both callers' tokens (24 chars)
    // fit comfortably; a batch this size draws `len` fresh bytes per retry round, same as before.
    debug_assert!(
        out.len() <= 32,
        "fill_base62 batch buffer is sized for <=32 chars"
    );
    let len = out.len();
    let mut filled = 0usize;
    'outer: while filled < len {
        let mut batch = [0u8; 32];
        let batch = &mut batch[..len];
        // Draw from the thread-local OS-entropy pool (same OS-CSPRNG bytes, syscall amortised across
        // ~130 ids per `getentropy` instead of one syscall per id — the whole `rb_finish` cost on the
        // anthropic-ingress hot path). Same false-on-CSPRNG-failure contract as the host entropy source.
        // `super::super::synth_rng` (not `crate::`) so this resolves in BOTH the native busbar-llm
        // build (`crate::synth_rng`) and the `#[path]` dual-compile into busbar-core
        // (`crate::proto::synth_rng`), matching the `super::super::usage_tail` convention the readers
        // use (this file sits one module below the dialect root).
        if !super::super::synth_rng::fill_entropy(batch) {
            return false;
        }
        for &byte in batch.iter() {
            if byte >= BASE62_REJECT_FLOOR {
                continue; // biased residue — discard to keep the distribution uniform
            }
            out[filled] = alphabet[(byte % 62) as usize];
            filled += 1;
            if filled == len {
                break 'outer;
            }
        }
    }
    true
}

pub(super) fn synth_id_with_prefix(prefix: &str) -> String {
    // On an entropy failure we leave the remaining '0' fill rather than panic; no counter. Same
    // ordering-independent reduction cutoff as every other base62 synth (4 * 62 = 248); only this
    // module's ALPHABET *ordering* (uppercase-first) is intentionally local.
    let mut token = [b'0'; SYNTH_ID_TOKEN_LEN];
    fill_base62(&mut token, ANTHROPIC_NATIVE_ALPHABET);

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards
    // against an impossible non-ASCII byte and keeps the path panic-free.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    format!("{prefix}01{token}")
}

/// Mint a protocol-correct Anthropic request id (`req_01<token>`) for the `request-id` RESPONSE HEADER
/// a native Anthropic response always carries. The official SDK reads this header into
/// `APIError.request_id` / `Message._request_id` (NOT the body), so a busbar anthropic response that
/// omitted it left `request_id == None` — impossible against the real API and a deterministic proxy
/// tell. Used by `proxy engine` on anthropic-ingress success/relay 2xx responses that have NO upstream
/// `request-id` to forward (the error path mirrors the writer's own body `request_id` into the header
/// instead; the same-protocol passthrough forwards the UPSTREAM `request-id` verbatim and never calls
/// this). The shape mirrors a native id EXACTLY: the `req_` prefix, the `01` version marker, then a
/// fixed-width 24-char mixed-case base62 token from the OS CSPRNG — `req_01` + 24 = 30 chars
/// total, matching `synth_id_with_prefix("req_")` (used for the body `request_id`) so the
/// response-header length is not a fingerprint tell (a 22-char value would be 8 chars short of
/// native). Returns `None` (caller OMITS the header) only if entropy is unavailable — on the request
/// path, must never panic. Uses the SHARED `crate::dialect::BASE62_ALPHABET` (lowercase-first ordering)
/// deliberately — NOT this module's local uppercase-first `ANTHROPIC_NATIVE_ALPHABET`. The alphabet
/// ORDERING differs from the sibling synth, but a uniform draw over a permuted alphabet is uniform
/// over the same character set, so that difference is irrelevant to the distribution.
pub fn synth_anthropic_request_id() -> Option<String> {
    // 24 base62 chars via the SAME rejection-sampling fill `synth_id_with_prefix` uses — the
    // `Option` contract (omit the header on entropy failure) differs from that sibling's
    // '0'-fill-on-failure contract, so this stays a separate call rather than delegating to it.
    let mut token = [0u8; 24];
    if !fill_base62(&mut token, crate::dialect::BASE62_ALPHABET) {
        return None;
    }
    // token is ASCII base62, always valid UTF-8.
    let token = std::str::from_utf8(&token).unwrap_or("000000000000000000000000");
    Some(format!("req_01{token}"))
}
