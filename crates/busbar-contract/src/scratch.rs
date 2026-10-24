//! The per-call scratch memory contract (DECISIONS #41).
//!
//! Scratch is the one resource handle a plugin is given: a small, per-call bump of memory every
//! byte a plugin produces comes out of. DECISIONS #41 pins its semantics and kills the old
//! fixed-cap model:
//!
//! > Scratch memory GROWS on demand — never a fixed cap, never a crash. Per-request scratch grows
//! > on demand by adding chunks; it never crashes and never issues a size-based refusal. A measured
//! > small size is only a STARTING size (a perf hint); a big request pays one heap grow instead of
//! > crashing. It shrinks back to the starting size after a big request so no worker permanently
//! > hoards. The only refusal is an abuse-only backstop — a ceiling set absurdly high that only a
//! > runaway or attack could hit — and on trip it cleanly refuses THAT ONE request, never panics.
//!
//! This is the trait; the kernel owns the one implementation ([`ScratchPad`] in
//! `busbar-kernel::scratch`), backed by an audited chunk-chaining bump allocator. Planes are
//! size-blind: they allocate, and the allocation succeeds unless the caller is an attacker. The
//! deliberately-dead `PlaneAlloc` trait beside this one is the fixed-4-KiB-cap-that-refuses design #41
//! replaces; it is kept only while the shipped per-call seam is cut over.
//!
//! [`ScratchPad`]: https://docs.rs/busbar-kernel

use core::fmt;

use crate::bounded::{ScratchBytes, Span};

/// Per-call scratch memory that grows on demand and never refuses a request for being too large.
///
/// The three allocation methods mirror the shape a plane already reaches for on the per-call
/// context: copy bytes in, copy a string in, copy a resolved span table in — each returning a
/// handle that borrows the pad for the call's lifetime. Unlike the dead fixed-cap arena, none of
/// them fails because the pad is "full": the pad grows a chunk to fit. The only error any of them
/// returns is [`ScratchRefused`], the abuse-only backstop, which a legitimate call never reaches.
///
/// The trait is intentionally NOT `Send + Sync`: the runtime is `!Send`, thread-per-core, one pad
/// per worker on its own `LocalSet`, so the bump allocator behind it never crosses a thread and
/// need not synchronise. That is the one bound difference from the retired `PlaneAlloc` trait.
pub trait Scratch {
    /// Copy bytes into the pad and hand back a borrowed view of where they landed.
    ///
    /// Grows the pad by a chunk if what is left does not fit. Never refuses for size; only the
    /// abuse backstop can say no.
    ///
    /// # Errors
    /// [`ScratchRefused`] when honouring the request would carry the pad past its abuse ceiling —
    /// a size only a runaway or an attack reaches.
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, ScratchRefused>;

    /// Copy a string into the pad and hand back a borrowed view of it.
    ///
    /// # Errors
    /// [`ScratchRefused`] on the abuse ceiling, as [`alloc_bytes`](Scratch::alloc_bytes).
    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ScratchRefused>;

    /// Copy a resolved span table into the pad.
    ///
    /// The pointers are already `'a` — the plane's own declared pointers — so only the pairs
    /// themselves are copied. This is the allocation that lets a plane's own scan be the one the
    /// loop reads instead of re-scanning bytes the plane already scanned.
    ///
    /// # Errors
    /// [`ScratchRefused`] on the abuse ceiling.
    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ScratchRefused>;

    /// How many more bytes the pad will hand out before the abuse backstop trips.
    ///
    /// This is headroom to the ceiling, NOT headroom in the current chunk: a pad with a nearly-full
    /// chunk still reports the whole distance to the ceiling, because the next allocation simply
    /// grows a new chunk. A plane never needs to read this — it exists so a test can prove the
    /// backstop is where it is, and so an operator can see how far a runaway got.
    fn remaining(&self) -> usize;
}

/// The scratch pad refused ONE request because honouring it would cross the abuse-only ceiling.
///
/// This is not the dead `PlaneAllocBudget` size refusal: the pad grows for any legitimate request. It
/// is the runaway/attack backstop, set absurdly high, and a trip refuses only the single request
/// that asked — the pad is untouched and the worker serves the next call normally. It is carried,
/// never panicked, so the loop ends that one unit at the step that asked and posts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchRefused {
    /// How many bytes the refused request asked for.
    pub wanted: usize,
    /// The abuse ceiling the request would have crossed.
    pub ceiling: usize,
}

impl fmt::Display for ScratchRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scratch abuse ceiling reached: wanted {} bytes, ceiling is {}",
            self.wanted, self.ceiling
        )
    }
}

impl std::error::Error for ScratchRefused {}
