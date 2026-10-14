//! ENTROPY for synthesized wire ids, drawn from the HOST's entropy source on every draw.
//!
//! Every protocol writer that must invent a shape-correct id when the upstream omitted one
//! (`anthropic` `req_…`, `bedrock`/`gemini` request ids, `cohere` v4 uuids, `responses` `resp_…`)
//! asks here for a fistful of random bytes. THE BYTES ARE THE HOST'S (#83a O10; the entropy arrives
//! through the host, never drawn by the plane itself): each draw goes straight to the
//! [`CodecHost`](busbar_contract::codec::CodecHost) the caller handed down the codec call graph (the
//! kernel's OS CSPRNG for the linked engine, the door's `random.fill` service for a door). A host
//! with no source serves nothing: the draw reports failure and each caller takes its own
//! entropy-unavailable branch.
//!
//! NO STATE OF ITS OWN. This module used to amortise the host call through a 4 KiB per-thread
//! buffer. A plugin holds no process-global state — what it keeps is per-instance, and the one
//! owner-approved per-thread slot is the door's log-capture slot (BUSBAR-1.6.0.md THE DESIGN §2) —
//! so that buffer is gone: every draw is one host call, and nothing outlives it or is shared
//! between instances on a thread (a dropped-in image carries no copy either).

/// Fill `out` with host-CSPRNG bytes: returns `true` on success, `false` iff the host's entropy
/// source is unavailable (in which case `out`'s contents are unspecified and callers must honour
/// their entropy-failure branch).
#[inline]
pub fn fill_entropy(host: &dyn busbar_contract::codec::CodecHost, out: &mut [u8]) -> bool {
    host.fill_entropy(out)
}

#[cfg(test)]
#[path = "tests/synth_rng_tests.rs"]
mod tests;
