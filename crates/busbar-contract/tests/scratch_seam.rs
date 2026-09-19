//! Red-before-green guards for the one `Scratch` resource trait (arena seam, DECISIONS #38/#42).
//!
//! Two invariants the fresh cut must hold:
//!  1. `Scratch` is a single trait with fallible allocation: past capacity it returns
//!     [`ArenaBudget`] carrying the true `wanted`/`remaining`, it never grows and never panics.
//!  2. The `!Send`/`!Sync` shape (the `tokio::spawn`-must-not-compile topology guard) is proven by
//!     the `compile_fail` doctest on `busbar_contract::bounded::Scratch` itself.

use std::cell::Cell;

use busbar_contract::bounded::{ArenaBudget, ArenaBytes, Scratch, Span};

/// A capacity-bounded scratch double: it leaks under budget (a test-lifetime leak — this crate
/// forbids unsafe) and REFUSES past it with the exact budget, the fallible discipline the real
/// bumpalo-backed `ScratchArena` must honour.
struct CappedScratch {
    remaining: Cell<usize>,
}

impl CappedScratch {
    fn with(bytes: usize) -> Self {
        Self {
            remaining: Cell::new(bytes),
        }
    }

    fn charge(&self, wanted: usize) -> Result<(), ArenaBudget> {
        let left = self.remaining.get();
        if wanted > left {
            return Err(ArenaBudget {
                wanted,
                remaining: left,
            });
        }
        self.remaining.set(left - wanted);
        Ok(())
    }
}

impl Scratch for CappedScratch {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        self.charge(src.len())?;
        Ok(ArenaBytes::new(Box::leak(src.to_vec().into_boxed_slice())))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        self.charge(src.len())?;
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        self.charge(std::mem::size_of_val(src))?;
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        self.remaining.get()
    }
}

#[test]
fn scratch_allocates_under_budget_and_reports_true_remaining() {
    let s = CappedScratch::with(8);
    let got = s.alloc_bytes(b"abcd").expect("4 fits in 8");
    assert_eq!(got.as_slice(), b"abcd");
    assert_eq!(
        s.remaining(),
        4,
        "the allocator charged exactly what it handed out"
    );
}

#[test]
fn scratch_refuses_past_capacity_with_the_true_budget_and_never_grows() {
    let s = CappedScratch::with(4);
    let err = s
        .alloc_bytes(b"abcdefgh")
        .expect_err("8 does not fit in 4 — the arena says no");
    assert_eq!(
        err,
        ArenaBudget {
            wanted: 8,
            remaining: 4
        }
    );
    // The refusal did not consume the arena: it is unchanged, not grown.
    assert_eq!(
        s.remaining(),
        4,
        "a refused allocation leaves the arena untouched"
    );
    // A str past capacity is refused the same way.
    assert!(s.alloc_str("way too long").is_err());
    assert_eq!(s.remaining(), 4);
}

#[test]
fn scratch_is_object_safe_and_used_by_shared_reference() {
    // `&dyn Scratch` (shared `&self`, no `&mut`) is the one resource handle a unit is given.
    let s = CappedScratch::with(16);
    let dynref: &dyn Scratch = &s;
    assert_eq!(dynref.remaining(), 16);
    let _ = dynref.alloc_str("ok").expect("2 fits in 16");
    assert_eq!(dynref.remaining(), 14);
}
