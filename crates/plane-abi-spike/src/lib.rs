// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! P0 SPIKE — the load-bearing performance proof for the plugin-ABI extraction.
//!
//! The locked design says a hot host-call (e.g. `govern_admit`) passes a `#[repr(C)]` PLAIN-OLD-DATA
//! struct BY POINTER, returns POD by value, allocates nothing and serializes nothing on the call.
//! Compiled-in through a fn-pointer vtable it should cost ~2-5ns; through a `.so` PLT ~+1-3ns.
//!
//! The DANGER this deletes is the shipped `crates/busbar-core/src/plane/host.rs` `PlaneHost`, whose
//! every capability returns `Result<Vec<u8>, _>` — a heap alloc + serialize on the hot path.
//!
//! This crate is a self-contained proof of that delta. It is NOT wired into the engine.
//!
//! Three call shapes are compared (see the criterion bench in `benches/abi_bench.rs`):
//!   (a) [`govern_admit_direct`]  — monomorphized in-core call (baseline).
//!   (b) [`PlaneHostVtable`]      — the SAME work through an `extern "C-unwind"` fn-pointer in a
//!                                  struct, as a compiled-in plugin would be reached.
//!   (c) [`govern_admit_vec`]     — the shipped anti-pattern: parse `&[u8]`, alloc a `Vec<u8>` out.
//!
//! A counting global allocator ([`ALLOC`]) proves (a) and (b) allocate ZERO on the call path, while
//! (c) allocates per call.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The sized/versioned POD ABI — the WorkItem/struct discipline the design prescribes.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The plugin-ABI schema version this spike's `Facts`/`Decision` layout speaks.
pub const ABI_VERSION: u16 = 1;

/// A `#[repr(C)]` PLAIN-OLD-DATA fact bundle passed to a host-call BY POINTER.
///
/// Fixed-layout: a sized/versioned preamble (`size`,`version`) as the struct discipline requires,
/// then a few `u64`/`u32` scalars, then a BORROWED `(ptr,len)` for a variable field (the pool name).
/// No owned heap field lives in the struct — the variable field is a borrow the caller keeps alive,
/// so passing `&Facts` across the seam moves no ownership and allocates nothing.
///
/// # Safety / discipline
/// `pool_name_ptr`/`pool_name_len` MUST describe a valid, initialized, `'a`-live UTF-8 (or opaque)
/// byte range for the duration of any call that receives `&Facts`. Construct via [`Facts::new`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    /// `size_of::<Facts>()` at construction — the receiver rejects a mismatch (forward-compat guard).
    pub size: u32,
    /// ABI schema version (see [`ABI_VERSION`]).
    pub version: u16,
    /// Explicit tail padding of the preamble, kept in the layout so the struct is fully defined.
    pub _reserved: u16,
    /// Tokens this work item wants to admit.
    pub tokens: u64,
    /// Budget remaining for the tenant, in the same unit as `tokens`.
    pub budget_remaining: u64,
    /// Opaque tenant identifier.
    pub tenant_id: u64,
    /// Request priority (higher = more important).
    pub priority: u32,
    /// Bitflags (bit 0 = "trusted caller", etc.).
    pub flags: u32,
    /// Borrowed pointer to the variable pool-name bytes (NOT owned by `Facts`).
    pub pool_name_ptr: *const u8,
    /// Length of the borrowed pool-name range.
    pub pool_name_len: usize,
}

impl Facts {
    /// Build a `Facts` borrowing `pool_name` for `'a`. No allocation, no copy of the name.
    /// Returns a [`FactsGuard`] (not `Self`) so the borrow can't outlive the name — hence the allow.
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'a>(
        tokens: u64,
        budget_remaining: u64,
        tenant_id: u64,
        priority: u32,
        flags: u32,
        pool_name: &'a [u8],
    ) -> FactsGuard<'a> {
        FactsGuard {
            facts: Facts {
                size: core::mem::size_of::<Facts>() as u32,
                version: ABI_VERSION,
                _reserved: 0,
                tokens,
                budget_remaining,
                tenant_id,
                priority,
                flags,
                pool_name_ptr: pool_name.as_ptr(),
                pool_name_len: pool_name.len(),
            },
            _borrow: core::marker::PhantomData,
        }
    }

    /// SAFETY: caller guarantees the `(ptr,len)` range is live and initialized for this call.
    #[inline]
    unsafe fn pool_name(&self) -> &[u8] {
        if self.pool_name_ptr.is_null() || self.pool_name_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.pool_name_ptr, self.pool_name_len)
        }
    }
}

/// A `Facts` tied to the lifetime of its borrowed pool-name, so the borrow can't dangle.
pub struct FactsGuard<'a> {
    facts: Facts,
    _borrow: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> core::ops::Deref for FactsGuard<'a> {
    type Target = Facts;
    #[inline]
    fn deref(&self) -> &Facts {
        &self.facts
    }
}

/// The `#[repr(u8)]` POD decision returned BY VALUE from a host-call.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Refuse the work item.
    Deny = 0,
    /// Admit the work item.
    Admit = 1,
    /// Admit but throttle (soft-limit).
    Throttle = 2,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The governance kernel — identical work behind every call shape, so the bench measures ONLY the
// call mechanism, not different amounts of computation.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The one true admit computation. Reads scalars and the borrowed pool-name slice; branches on
/// budget, priority, flags and a cheap per-byte fold of the name (so the name read is not dead).
#[inline]
fn govern_admit_kernel(f: &Facts) -> Decision {
    // Forward-compat / discipline guard: a receiver rejects a struct whose preamble it doesn't know.
    if f.size < core::mem::size_of::<Facts>() as u32 || f.version != ABI_VERSION {
        return Decision::Deny;
    }
    if f.tokens > f.budget_remaining {
        return Decision::Deny;
    }
    // SAFETY: callers of every public shape construct Facts via `Facts::new`, keeping the borrow live.
    let name = unsafe { f.pool_name() };
    let mut fold: u32 = f.priority ^ (f.tenant_id as u32);
    for &b in name {
        fold = fold.rotate_left(5) ^ (b as u32);
    }
    let trusted = f.flags & 1 != 0;
    let headroom = f.budget_remaining - f.tokens;
    if trusted || headroom >= f.tokens {
        Decision::Admit
    } else if fold & 1 == 0 {
        Decision::Throttle
    } else {
        Decision::Deny
    }
}

// ── shape (a): direct monomorphized in-core call — the baseline ────────────────────────────────

/// (a) The baseline: what a govern_admit costs compiled directly into core today.
#[inline]
pub fn govern_admit_direct(f: &Facts) -> Decision {
    govern_admit_kernel(f)
}

// ── shape (b): fn-pointer vtable — a compiled-in plugin reached through the ABI ─────────────────

/// The `extern "C-unwind"` host-call signature — a POD pointer in, a POD `Decision` out.
///
/// `C-unwind` (not plain `C`) is deliberate: it matches the ABI direction where a panic must be able
/// to unwind across the seam rather than abort, exactly as the workspace release profile keeps
/// `panic = "unwind"` for per-request isolation.
pub type HostGovernAdmit = extern "C-unwind" fn(*const Facts) -> Decision;

/// A `#[repr(C)]` vtable of host-call fn-pointers — the design's `PlaneHostVtable`, minimal.
/// Reached as a compiled-in (or `dlopen`ed) plugin would reach it: `(host.govern_admit)(&facts)`.
#[repr(C)]
pub struct PlaneHostVtable {
    /// The govern_admit slot (an absent capability would be a NULL/`Option` slot in the full design).
    pub govern_admit: HostGovernAdmit,
}

/// The concrete `extern "C-unwind"` implementation stored behind the vtable slot.
///
/// # Safety
/// `f` must be a valid pointer to a live `Facts` whose borrowed pool-name range is live.
// The seam is a plain `extern "C-unwind" fn(*const Facts)` by ABI contract, so it can populate a
// non-`unsafe` fn-pointer vtable slot; the pointer-deref safety contract is documented above.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C-unwind" fn govern_admit_ffi(f: *const Facts) -> Decision {
    // SAFETY: the caller (the bench / a plane) upholds the contract above.
    let facts = unsafe { &*f };
    govern_admit_kernel(facts)
}

impl PlaneHostVtable {
    /// The in-core vtable: the same work, reachable through a fn-pointer indirection.
    pub const IN_CORE: PlaneHostVtable = PlaneHostVtable {
        govern_admit: govern_admit_ffi,
    };
}

// ── shape (c): the shipped anti-pattern — parse &[u8], alloc a Vec<u8> out ──────────────────────

/// Encode a `Facts` to the fixed 48-byte wire the anti-pattern parses (name is NOT included; the
/// anti-pattern in the shipped seam passes opaque bytes, and here we mirror the scalar preamble a
/// plane would serialize). This alloc happens on the CALLER side and is part of the anti-pattern's
/// cost, but the bench measures only the call itself against a pre-encoded buffer to be charitable.
pub fn encode_facts(f: &Facts) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(&f.size.to_le_bytes());
    v.extend_from_slice(&f.version.to_le_bytes());
    v.extend_from_slice(&f._reserved.to_le_bytes());
    v.extend_from_slice(&f.tokens.to_le_bytes());
    v.extend_from_slice(&f.budget_remaining.to_le_bytes());
    v.extend_from_slice(&f.tenant_id.to_le_bytes());
    v.extend_from_slice(&f.priority.to_le_bytes());
    v.extend_from_slice(&f.flags.to_le_bytes());
    // The variable field appended as length-prefixed bytes, as a plane would serialize it.
    // SAFETY: mirror of the borrowed range; used only for encoding here.
    let name = unsafe { f.pool_name() };
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(name);
    v
}

/// (c) The shipped anti-pattern shape: `fn(&[u8]) -> Result<Vec<u8>, ()>`. It parses the opaque
/// request and returns the decision in a freshly-allocated `Vec<u8>` — a heap alloc per call, the
/// exact cost `crates/busbar-core/src/plane/host.rs`'s `Result<Vec<u8>>` incurs today.
// `Result<_, ()>` mirrors the anti-pattern's shape closely enough for the spike; a real error type
// is beside the point being measured (the per-call heap alloc).
#[allow(clippy::result_unit_err)]
pub fn govern_admit_vec(req: &[u8]) -> Result<Vec<u8>, ()> {
    if req.len() < 40 {
        return Err(());
    }
    let g = |o: usize| -> [u8; 8] { req[o..o + 8].try_into().unwrap() };
    let g4 = |o: usize| -> [u8; 4] { req[o..o + 4].try_into().unwrap() };
    let size = u32::from_le_bytes(g4(0));
    let version = u16::from_le_bytes(req[4..6].try_into().unwrap());
    let tokens = u64::from_le_bytes(g(8));
    let budget_remaining = u64::from_le_bytes(g(16));
    let tenant_id = u64::from_le_bytes(g(24));
    let priority = u32::from_le_bytes(g4(32));
    let flags = u32::from_le_bytes(g4(36));
    let name_len = u32::from_le_bytes(g4(40)) as usize;
    let name = req.get(44..44 + name_len).ok_or(())?;

    if size < core::mem::size_of::<Facts>() as u32 || version != ABI_VERSION {
        // The alloc still happens even on the deny path (a Vec return type has no zero-alloc branch).
        return Ok(vec![Decision::Deny as u8]);
    }
    if tokens > budget_remaining {
        return Ok(vec![Decision::Deny as u8]);
    }
    let mut fold: u32 = priority ^ (tenant_id as u32);
    for &b in name {
        fold = fold.rotate_left(5) ^ (b as u32);
    }
    let trusted = flags & 1 != 0;
    let headroom = budget_remaining - tokens;
    let d = if trusted || headroom >= tokens {
        Decision::Admit
    } else if fold & 1 == 0 {
        Decision::Throttle
    } else {
        Decision::Deny
    };
    // THE ANTI-PATTERN: return the answer in a heap allocation.
    Ok(vec![d as u8])
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Counting global allocator — the ALLOC-GATE proof instrument.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A `System` wrapper that counts every allocation. Set as the crate's `#[global_allocator]`, so any
/// binary/bench/test linking this crate counts allocs on the hot path.
pub struct CountingAlloc;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

impl CountingAlloc {
    /// Total allocations observed since process start (or last [`reset`](Self::reset)).
    pub fn count() -> u64 {
        ALLOC_COUNT.load(Ordering::Relaxed)
    }
    /// Reset the counter to zero and return the previous value.
    pub fn reset() -> u64 {
        ALLOC_COUNT.swap(0, Ordering::Relaxed)
    }
}

unsafe impl GlobalAlloc for CountingAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

/// The active global allocator — public so the bench can call [`CountingAlloc::count`]/`reset`.
#[global_allocator]
pub static ALLOC: CountingAlloc = CountingAlloc;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Tests: correctness (all shapes agree) + the alloc-gate proof.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
