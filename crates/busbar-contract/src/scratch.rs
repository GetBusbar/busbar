//! The per-call scratch memory contract (DECISIONS #41).

use core::fmt;

use crate::bounded::{ScratchBytes, Span};

/// Per-call scratch memory that grows on demand and never refuses a request for being too large.
pub trait Scratch {
    /// Copy bytes into the pad and hand back a borrowed view of where they landed.
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, ScratchRefused>;

    /// Copy a string into the pad and hand back a borrowed view of it.
    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ScratchRefused>;

    /// Copy a resolved span table into the pad.
    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ScratchRefused>;

    /// How many more bytes the pad will hand out before the abuse backstop trips.
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
