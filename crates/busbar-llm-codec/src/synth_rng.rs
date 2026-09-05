//! Thread-local OS-entropy POOL for synthesized wire ids.
//!
//! Every protocol writer that must invent a shape-correct id when the upstream omitted one
//! (`anthropic` `req_…`, `bedrock`/`gemini` request ids, `cohere` v4 uuids, `responses` `resp_…`)
//! needs a fistful of random bytes on the HOT response path. Calling [`getrandom::fill`] once PER
//! id issues a `getentropy(2)` syscall per response — ~1–2 µs on macOS, and on the
//! anthropic-ingress benchmark that single syscall was the ENTIRE `rb_finish` cost (~2.5 µs p50 of a
//! ~6.6 µs `busbar;dur`). The synthesized ids are non-secret response-correlation strings returned
//! only to the client that made the request; on a single-operator proxy they never cross a trust
//! boundary. So there is no reason to pay a syscall each.
//!
//! This pool draws a [`POOL_BYTES`]-byte block from the OS CSPRNG ONCE and hands out slices of it,
//! refilling from `getrandom` only when drained. Every byte served is still a fresh OS-CSPRNG byte —
//! this is NOT a userspace PRNG substituting for the OS generator, it is the exact same entropy
//! source with the syscall AMORTISED (~one `getentropy` per `POOL_BYTES` bytes instead of per id).
//! The randomness quality, distribution, and unpredictability are byte-for-byte identical to the
//! per-call `getrandom::fill` it replaces; only the syscall frequency changes.
//!
//! Thread-local so there is no lock and no cross-thread contention on the hot path. A worker thread
//! amortises its first-request syscall across the next few hundred requests it serves.
//!
//! FORK SAFETY. A userspace entropy buffer is not fork-safe: a child that inherits this thread's
//! buffer at the same read position would serve the SAME "random" bytes as the parent until its next
//! refill, so both could emit duplicate ids. This is SOUND for busbar as it exists: busbar runs a
//! tokio multi-thread runtime and never `fork()`s a worker that then synthesizes ids (subprocess
//! egress immediately `exec`s a different binary, which does not run this code). The values are
//! non-secret response-correlation strings, so even a post-fork collision is low-harm. If busbar ever
//! adds a fork-based worker model that synthesizes ids in the child, reset this pool in a
//! `pthread_atfork` child handler (or gate `fill` on a cached pid) BEFORE relying on it there.

use std::cell::RefCell;

/// Size of the per-thread entropy block. 4 KiB serves ~130 anthropic ids (30 bytes each, before
/// rejection-sampling waste) per `getentropy` syscall — a ~100× syscall reduction — while staying a
/// trivially-bounded stack/TLS cost. Large enough to matter, small enough to never notice.
const POOL_BYTES: usize = 4096;

struct EntropyPool {
    buf: [u8; POOL_BYTES],
    /// Next unread byte. `pos == POOL_BYTES` means drained → refill on next draw.
    pos: usize,
    /// Set if the LAST refill's `getrandom` failed; callers translate this into their own
    /// entropy-unavailable contract (anthropic OMITS the header, cohere zero-fills, etc.).
    healthy: bool,
}

impl EntropyPool {
    fn new() -> Self {
        // Start drained so the first draw triggers the initial fill (and surfaces a broken CSPRNG
        // immediately, rather than serving a zeroed buffer).
        EntropyPool {
            buf: [0u8; POOL_BYTES],
            pos: POOL_BYTES,
            healthy: true,
        }
    }

    /// Refill the whole block from the OS CSPRNG. On failure the pool is marked unhealthy and left
    /// drained so no stale/zeroed bytes are served.
    fn refill(&mut self) {
        match getrandom::fill(&mut self.buf) {
            Ok(()) => {
                self.pos = 0;
                self.healthy = true;
            }
            Err(_) => {
                self.pos = POOL_BYTES;
                self.healthy = false;
            }
        }
    }

    /// Fill `out` with fresh OS-CSPRNG bytes from the pool, refilling as needed. Returns `false`
    /// (filling nothing meaningful) iff the OS CSPRNG is unavailable — same contract as a failed
    /// `getrandom::fill(out)`. A single `out` larger than the pool is filled across multiple refills.
    fn fill(&mut self, out: &mut [u8]) -> bool {
        let mut written = 0usize;
        while written < out.len() {
            if self.pos == POOL_BYTES {
                self.refill();
                if !self.healthy {
                    return false;
                }
            }
            let take = (out.len() - written).min(POOL_BYTES - self.pos);
            out[written..written + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
        true
    }
}

thread_local! {
    static POOL: RefCell<EntropyPool> = RefCell::new(EntropyPool::new());
}

/// Fill `out` with OS-CSPRNG bytes from the thread-local pool. Drop-in replacement for
/// `getrandom::fill(out).is_ok()`: returns `true` on success, `false` iff the OS CSPRNG is
/// unavailable (in which case `out`'s contents are unspecified and callers must honour their
/// entropy-failure branch). Amortises the `getentropy` syscall across [`POOL_BYTES`] bytes.
#[inline]
pub fn fill_entropy(out: &mut [u8]) -> bool {
    POOL.with(|p| p.borrow_mut().fill(out))
}

#[cfg(test)]
#[path = "tests/synth_rng_tests.rs"]
mod tests;
