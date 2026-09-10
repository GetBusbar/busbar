//! Thread-local entropy POOL for synthesized wire ids, fed by an INSTALLED SOURCE.
//!
//! Every protocol writer that must invent a shape-correct id when the upstream omitted one
//! (`anthropic` `req_…`, `bedrock`/`gemini` request ids, `cohere` v4 uuids, `responses` `resp_…`)
//! needs a fistful of random bytes on the HOT response path. Drawing from the OS once PER id costs a
//! `getentropy(2)` syscall per response — ~1–2 µs on macOS, and on the anthropic-ingress benchmark
//! that single syscall was the ENTIRE `rb_finish` cost (~2.5 µs p50 of a ~6.6 µs `busbar;dur`). The
//! synthesized ids are non-secret response-correlation strings returned only to the client that
//! made the request; on a single-operator proxy they never cross a trust boundary. So there is no
//! reason to pay a syscall each.
//!
//! This pool draws a [`POOL_BYTES`]-byte block from the installed source ONCE and hands out slices
//! of it, refilling only when drained. Every byte served is still a fresh byte from that source —
//! this is NOT a userspace PRNG substituting for it, it is the exact same entropy with the call
//! AMORTISED (~one source call per `POOL_BYTES` bytes instead of per id). The randomness quality,
//! distribution, and unpredictability are byte-for-byte those of the source; only the call
//! frequency changes.
//!
//! THE SEAM. This crate is the pure half of its protocol: it translates bytes and reaches no OS
//! primitive, and its transitive closure is what the plane and the dialect crates carry. An
//! entropy source is an OS primitive (a syscall wrapper over `libc`), so the codec does NOT own one.
//! Instead the composition root — the `busbar` binary, through the engine half — [`install`]s one
//! at boot, exactly as it installs the protocol declarations; a test binary installs one through
//! the same seam (the engine half's test kit, `install_test_seams`). With NO source installed every draw
//! reports entropy-unavailable (`false`), which is the contract every caller already honours: the
//! anthropic writer omits the header, cohere zero-fills, the openai-chat suffix stays absent. A
//! plane-built refusal never depends on this pool at all — its one minted identifier is built from
//! entropy the plane hands in (`write_error_envelope`'s `entropy` argument).
//!
//! Thread-local so there is no lock and no cross-thread contention on the hot path. A worker thread
//! amortises its first-request source call across the next few hundred requests it serves.
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
use std::sync::OnceLock;

/// An entropy source: fill the whole slice with fresh unpredictable bytes and return `true`, or
/// return `false` leaving the slice's contents unspecified. The same contract as
/// `getrandom::fill(out).is_ok()`, which is what the composition root installs.
pub type EntropySource = fn(&mut [u8]) -> bool;

/// Size of the per-thread entropy block. 4 KiB serves ~130 anthropic ids (30 bytes each, before
/// rejection-sampling waste) per source call — a ~100× reduction — while staying a
/// trivially-bounded stack/TLS cost. Large enough to matter, small enough to never notice.
const POOL_BYTES: usize = 4096;

/// THE ONE INSTALLED SOURCE, process-wide. Set once by the composition root; every thread's pool
/// refills through it. `OnceLock` so the install is a single atomic load on the hot path after the
/// first call, and so a second install can never swap the source out from under a live pool.
static SOURCE: OnceLock<EntropySource> = OnceLock::new();

/// INSTALL THE PROCESS'S ENTROPY SOURCE — the composition root's one write into this seam.
///
/// Returns `true` if `source` is now the installed source (first install, or a repeat install of the
/// same function, which is what makes an idempotent test-kit safe to call from many tests) and
/// `false` if a DIFFERENT source was already installed — the first writer wins and the pool is
/// never re-pointed, because a pool that changed source mid-run would be serving bytes nobody
/// reviewed. Never panics: a refused second install is a caller's boot-order fact, not a fault.
pub fn install(source: EntropySource) -> bool {
    match SOURCE.set(source) {
        Ok(()) => true,
        // `fn` pointers compare by address; two names for the same function are one source.
        Err(_) => SOURCE
            .get()
            .is_some_and(|s| std::ptr::fn_addr_eq(*s, source)),
    }
}

/// The installed source, if the composition root has installed one.
///
/// In this crate's OWN test binary — and only there — the OS is the source when none was installed,
/// through the `getrandom` DEV-dependency: the codec's suites exercise every synthesized-id path and
/// none of them is a composition root. A shipped target never sees this arm; `cfg(test)` is false
/// in every build a dependent makes, so the crate's normal dependency graph carries no entropy
/// source at all, which is the property the plane's denylist closure measures.
fn installed_source() -> Option<EntropySource> {
    #[cfg(test)]
    let fallback: Option<EntropySource> = Some(tests::os_entropy_for_tests);
    #[cfg(not(test))]
    let fallback: Option<EntropySource> = None;
    SOURCE.get().copied().or(fallback)
}

struct EntropyPool {
    buf: [u8; POOL_BYTES],
    /// Next unread byte. `pos == POOL_BYTES` means drained → refill on next draw.
    pos: usize,
    /// Set if the LAST refill failed (no source installed, or the source reported failure);
    /// callers translate this into their own entropy-unavailable contract (anthropic OMITS the
    /// header, cohere zero-fills, etc.).
    healthy: bool,
}

impl EntropyPool {
    fn new() -> Self {
        // Start drained so the first draw triggers the initial fill (and surfaces a broken or
        // missing source immediately, rather than serving a zeroed buffer).
        EntropyPool {
            buf: [0u8; POOL_BYTES],
            pos: POOL_BYTES,
            healthy: true,
        }
    }

    /// Refill the whole block from `source`. On failure the pool is marked unhealthy and left
    /// drained so no stale/zeroed bytes are served.
    fn refill(&mut self, source: Option<EntropySource>) {
        match source {
            Some(fill) if fill(&mut self.buf) => {
                self.pos = 0;
                self.healthy = true;
            }
            _ => {
                self.pos = POOL_BYTES;
                self.healthy = false;
            }
        }
    }

    /// Fill `out` with fresh bytes from the pool, refilling from `source` as needed. Returns
    /// `false` (filling nothing meaningful) iff entropy is unavailable — no source, or the source
    /// failed — same contract as a failed `getrandom::fill(out)`. A single `out` larger than the
    /// pool is filled across multiple refills.
    fn fill(&mut self, source: Option<EntropySource>, out: &mut [u8]) -> bool {
        let mut written = 0usize;
        while written < out.len() {
            if self.pos == POOL_BYTES {
                self.refill(source);
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

/// Fill `out` with bytes from the thread-local pool of the installed entropy source. Drop-in
/// replacement for `getrandom::fill(out).is_ok()`: returns `true` on success, `false` iff entropy is
/// unavailable — no source [`install`]ed, or the source failed — in which case `out`'s contents are
/// unspecified and callers must honour their entropy-failure branch. Amortises the source call
/// across [`POOL_BYTES`] bytes.
#[inline]
pub fn fill_entropy(out: &mut [u8]) -> bool {
    let source = installed_source();
    POOL.with(|p| p.borrow_mut().fill(source, out))
}

#[cfg(test)]
#[path = "tests/synth_rng_tests.rs"]
mod tests;
