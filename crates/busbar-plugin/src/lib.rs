// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE busbar plugin interface, TWO lanes** — over a single shared root.
//!
//! busbar has exactly one plugin boundary, but two disciplines ride it, because two classes of
//! plugin have opposite performance shapes. Rather than cram both into one call convention, this
//! crate exposes them as two lane modules over a shared contract:
//!
//! * [`cold`] — the COLD lane (was `busbar-plugin-abi`). A frozen, versioned wire: JSON over a tiny
//!   six-symbol `extern "C"` surface, for backends OFF the request hot path (`store` | `secret` |
//!   `auth` | `hook` | `export`), where a serialize per call never touches request latency. Its
//!   `extern "C"` symbols, JSON shapes, and [`cold::TRANSPORT_VERSION`] are a SIGNED wire contract
//!   that MUST NOT change; an external plugin's compiled artifact keeps working across this move —
//!   only the SOURCE import path changes (`busbar_plugin_abi::X` → `busbar_plugin::cold::X`).
//! * [`hot`] — the HOT lane (was `busbar-plane-abi`). A `#[repr(C)]` fn-pointer vtable, POD args by
//!   pointer, small results by value, large results into a caller `&mut MaybeUninit<Out>`, zero
//!   alloc / zero serde on the call. ADDITIVE and not yet wired into the engine.
//!
//! # The shared root (this module)
//!
//! Both lanes obey the SAME cross-boundary discipline, hoisted here so there is one definition:
//!
//! 1. **The airlock preamble** ([`AbiPreamble`], [`check_preamble`]) — a `#[repr(C)]` header FROZEN
//!    FOR ALL TIME. Its three fields (`magic`, `abi_major`, `abi_minor`) may NEVER be reordered,
//!    resized, or removed. A major mismatch or a magic mismatch is fail-closed (the seam refuses),
//!    so an incompatible peer can never be reached across the boundary.
//! 2. **Sized-struct / append-only discipline** — every cross-boundary POD struct LEADS with a
//!    `size`/`version` and a receiver reads a field only when `size` proves the sender wrote it (see
//!    [`field_present`] / [`read_sized_field`]). New fields may ONLY be appended; a peer that
//!    predates a field simply never reads it. Reorder/resize/insert = a MAJOR airlock bump.
//! 3. **The out-param write discipline** ([`write_out`]) — the init-only-on-Ok rule a callee uses to
//!    publish a large POD result into a caller slot without a `Vec` return.
//!
//! The airlock and these helpers are what the two lanes SHARE. Their call conventions (JSON bytes
//! over six C symbols vs. a repr(C) fn-pointer vtable) stay deliberately opposite, in [`cold`] and
//! [`hot`] respectively.
//!
//! # Neutrality
//!
//! The HOT lane's capability surface was DERIVED from a primitive taxonomy, not ENUMERATED from any
//! one protocol plane: no type, function, variant, or carrier name under [`hot`] may contain a
//! protocol/role noun. A CI witness (`scripts/plane-abi-neutrality.sh`) greps the [`hot`] tree for
//! the banned set and asserts zero. The COLD lane's existing names (its `store`/`auth`/`hook`
//! vocabulary) predate that rule and are exempt — the witness covers `::hot` only.

#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::MaybeUninit;

pub mod cold;
pub mod hot;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 1. The airlock preamble — FROZEN FOR ALL TIME. Shared by both lanes.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The magic value every plugin-ABI peer stamps into [`AbiPreamble::magic`]. A wrong magic means the
/// bytes are not a busbar-plugin-ABI preamble at all (a mislinked / corrupt / hostile peer) and the
/// seam refuses. Chosen to be non-zero and unlikely to occur by accident: ASCII `"BUSPLANE"`
/// little-end.
pub const ABI_MAGIC: u64 = u64::from_le_bytes(*b"BUSPLANE");

/// The MAJOR airlock version. Bumping this is a no-turning-back linker event: a reorder/resize/
/// removal of any frozen field, a preamble change, or any non-append-only alteration. Peers with
/// different majors are INCOMPATIBLE and [`check_preamble`] refuses them.
pub const ABI_MAJOR: u32 = 1;

/// The MINOR airlock version. Bumped for every APPEND-ONLY addition (a new trailing struct field, a
/// new reserved `#[repr(u8)]` variant, a new trailing vtable slot). A newer minor is compatible with
/// an older one BY the sized-struct discipline: the older peer never reads the newer trailing bytes.
///
/// 19→20 (1.6.0 M1): the append-only `hot::Usage` keyed-unit tail (`units_ptr`/`units_len`), paired
/// with `POD_VERSION` 2→3. `check_preamble` still accepts an older minor (append-only compatibility).
///
/// 20→21 (1.6.0): `hot::JournalStreamDesc._reserved` becomes `max_scopes: u32` — the LRU bound on a
/// registered stream's RAM position cache, `0` = the host default. Weaker than an append: every
/// offset and the struct size are UNCHANGED, and a minor-20 peer wrote `0` there, which decodes to
/// the host default it already received. `POD_VERSION` is unmoved for the same reason.
pub const ABI_MINOR: u32 = 21;

/// The FROZEN-FOR-ALL-TIME ABI header. This exact layout — `magic` at offset 0, `abi_major` at 8,
/// `abi_minor` at 12 — is a permanent contract: it may NEVER be reordered, resized, extended, or
/// removed, because it is the one struct read BEFORE version negotiation, so it cannot itself be
/// versioned. Every subsequent struct carries its own `size`/`version`; this one cannot, so it is
/// frozen. The layout golden pins these three offsets and a change here is a deliberate MAJOR event.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiPreamble {
    /// Must equal [`ABI_MAGIC`]. A mismatch is fail-closed (not a plugin-ABI peer).
    pub magic: u64,
    /// The peer's [`ABI_MAJOR`]. A mismatch is fail-closed (incompatible airlock).
    pub abi_major: u32,
    /// The peer's [`ABI_MINOR`]. Never a refusal reason on its own (append-only compatibility).
    pub abi_minor: u32,
}

impl AbiPreamble {
    /// This build's preamble — what a local peer stamps for the other side to check.
    pub const CURRENT: AbiPreamble = AbiPreamble {
        magic: ABI_MAGIC,
        abi_major: ABI_MAJOR,
        abi_minor: ABI_MINOR,
    };
}

impl Default for AbiPreamble {
    fn default() -> Self {
        AbiPreamble::CURRENT
    }
}

/// Why a peer's [`AbiPreamble`] was refused. Fail-closed: any non-`Ok` outcome means the seam is
/// NOT reachable — the caller must abort the crossing, never degrade to a partial read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreambleError {
    /// The peer's `magic` is not [`ABI_MAGIC`]: these are not plugin-ABI bytes.
    BadMagic {
        /// The magic the peer presented.
        found: u64,
    },
    /// The peer's `abi_major` differs from this build's [`ABI_MAJOR`]: incompatible airlock.
    MajorMismatch {
        /// The major this build speaks.
        ours: u32,
        /// The major the peer presented.
        theirs: u32,
    },
}

/// Check a peer's preamble, FAIL-CLOSED. Refuses on a magic mismatch or a MAJOR mismatch; a differing
/// MINOR is accepted (append-only compatibility — whichever side is older simply never reads the
/// newer trailing bytes). This is the FIRST thing any crossing does, before a single sized struct is
/// interpreted.
pub fn check_preamble(peer: &AbiPreamble) -> Result<(), PreambleError> {
    if peer.magic != ABI_MAGIC {
        return Err(PreambleError::BadMagic { found: peer.magic });
    }
    if peer.abi_major != ABI_MAJOR {
        return Err(PreambleError::MajorMismatch {
            ours: ABI_MAJOR,
            theirs: peer.abi_major,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 2. Sized-struct discipline — the append-only field-read guard. Shared by both lanes.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// True iff a sender who advertised `advertised_size` bytes definitely WROTE the field that ends at
/// `field_end` (= its offset + its size). The append-only rule makes this a total forward-compat
/// guard: an older sender advertises a smaller `size`, so a newer field reads as "absent" instead of
/// as uninitialized garbage. Use via [`read_sized_field`] rather than by hand.
///
/// This is the LOWER half of the guard only — it bounds the shorter sender. The advertised size is
/// SELF-ATTESTED by the peer, so the upper half ([`honoured_size`]) belongs with it: pass
/// `honoured_size(advertised, size_of::<T>())` rather than the raw claim. [`read_sized_field`] does
/// that clamp for you.
#[inline]
#[must_use]
pub const fn field_present(advertised_size: u32, field_end: usize) -> bool {
    advertised_size as usize >= field_end
}

/// The UPPER half of the sized-struct guard: the largest peer-attested `size` this build will honour
/// for a `struct_size`-byte struct, i.e. `min(advertised_size, struct_size)`.
///
/// `size` is written by the PEER and this side has no way to measure how many bytes it actually
/// mapped, so an over-large claim is an unverifiable assertion, not a fact. Clamping it to this
/// build's own `size_of::<T>()` means an over-claim can never widen the read window past the struct
/// this build compiled — a genuinely NEWER peer's trailing bytes are simply never named here (which
/// is exactly the append-only rule, from the other side), and a peer that stamps a wild `size` over a
/// short buffer gains nothing beyond the fields this build already knows.
///
/// It does NOT rescue a peer that stamps an over-large `size` over a struct SHORTER than this
/// build's — no clamp can, because nothing on this side can measure the peer's real extent. That
/// residual is why the analogous claim on the host vtable is REFUSED outright rather than clamped
/// (see `hot::host::PlaneHostVtable::check`): a wrong POD field is bad data, a wrong vtable slot is a
/// fn-pointer this side then CALLS.
#[inline]
#[must_use]
pub const fn honoured_size(advertised_size: u32, struct_size: usize) -> u32 {
    let struct_size = if struct_size > u32::MAX as usize {
        u32::MAX
    } else {
        struct_size as u32
    };
    if advertised_size < struct_size {
        advertised_size
    } else {
        struct_size
    }
}

/// The byte size of whatever `p` points at — the type-level companion to [`field_present`], used to
/// compute a field's END offset from a raw field pointer without ever dereferencing one.
#[inline]
#[must_use]
pub const fn pointee_size<T>(_p: *const T) -> usize {
    core::mem::size_of::<T>()
}

/// Read a `Copy` field from a sized POD struct ONLY if its advertised `size` proves the sender wrote
/// it, yielding `Option<FieldTy>`. This is the mechanical form of the append-only rule: a field
/// appended in a later minor is `None` when read from an older sender's struct, never undefined.
///
/// Takes a RAW POINTER and the advertised size, never a reference. The whole point of the guard is
/// that the peer's buffer may be SHORTER than the struct it describes — an older sender's `Usage` is
/// genuinely fewer bytes than this build's — and forming a `&Usage` over such a buffer asserts the
/// full struct is there and dereferenceable the instant the reference exists, which is precisely the
/// claim the guard was written to avoid making. The field is reached with `addr_of!` and copied with
/// `read_unaligned` only AFTER [`field_present`] says the advertised size covers it, so nothing past
/// the sender's own bytes is ever touched and no alignment the peer did not promise is assumed.
///
/// # Safety
/// The macro expands inline, so its obligation is documented rather than compiler-enforced: `ptr`
/// must address at least `size` live, initialized bytes laid out as the leading prefix of `$struct`.
/// It need not be aligned, and it need NOT be a whole `$struct` — that latitude is the entire reason
/// the guard takes a pointer.
///
/// ```
/// use busbar_plugin::{read_sized_field, hot::Facts};
/// let g = Facts::new(10, 100, 1, 0, 0, b"pool");
/// // `tokens` lives within every non-truncated `Facts`, so it reads as `Some`.
/// assert_eq!(read_sized_field!(&*g, g.size, Facts, tokens), Some(10));
/// ```
#[macro_export]
macro_rules! read_sized_field {
    ($ptr:expr, $size:expr, $struct:ty, $field:ident) => {{
        let p: *const $struct = $ptr;
        // The peer's claim, CLAMPED to this build's own struct (the upper half of the guard): a
        // self-attested `size` larger than `$struct` can never widen the window past what this build
        // compiled. See `honoured_size`.
        let advertised: u32 =
            $crate::honoured_size($size, ::core::mem::size_of::<$struct>());
        // The field's END offset, derived WITHOUT touching `p`: a full-size `MaybeUninit` probe is a
        // real, correctly-sized, correctly-aligned allocation, and `addr_of!` only computes an
        // address — it never reads the uninitialized bytes. Const-folds to a literal.
        let probe = ::core::mem::MaybeUninit::<$struct>::uninit();
        let end = ::core::mem::offset_of!($struct, $field)
            + $crate::pointee_size(
                // SAFETY: `probe` is a whole, aligned `$struct`; `addr_of!` performs no read.
                unsafe { ::core::ptr::addr_of!((*probe.as_ptr()).$field) },
            );
        if $crate::field_present(advertised, end) {
            // SAFETY: `field_present` just proved the sender's advertised size reaches THROUGH this
            // field, so the projection lands inside the caller-guaranteed live prefix, and
            // `read_unaligned` copies it out without forming a reference or assuming alignment.
            ::core::option::Option::Some(unsafe {
                ::core::ptr::read_unaligned(::core::ptr::addr_of!((*p).$field))
            })
        } else {
            ::core::option::Option::None
        }
    }};
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 3. The out-param write discipline — init-only-on-Ok. Shared by both lanes.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Write `value` into a caller-provided `&mut MaybeUninit<T>` out-slot, the ONLY way a hot host-call
/// returns a large POD without a `Vec`. Mirrors `plugin-sdk/boundary.rs`: the callee fully writes the
/// slot INSIDE its `catch_unwind` and marks it initialized ONLY on the Ok path — so a caller that
/// sees a non-`Ok` status must treat the slot as still uninitialized and never read it. A null `out`
/// is tolerated (the value is dropped), matching the boundary's null-out-guard.
///
/// # Safety
/// `out`, when non-null, must point to a writable, properly-aligned `MaybeUninit<T>` for the duration
/// of the call. On any non-`Ok` status the caller MUST NOT assume the slot was written.
#[inline]
pub unsafe fn write_out<T>(out: *mut MaybeUninit<T>, value: T) {
    if out.is_null() {
        // No slot to publish into: drop the value, never write through a null pointer.
        drop(value);
        return;
    }
    // SAFETY: the caller guarantees `out` is a writable, aligned `MaybeUninit<T>` per the contract.
    unsafe { (*out).write(value) };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Test-only instrument: a per-thread counting allocator, THE ALLOC-GATE PROOF.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A `System` wrapper that counts every allocation THIS THREAD makes, for THIS CRATE'S OWN TESTS
/// only. Ported from the deleted `plane-abi-spike` (`git show 527bdbf96^:crates/plane-abi-spike/src/lib.rs`)
/// verbatim in idiom (see also `busbar-llm`'s `CountingJemalloc` /
/// `engine/tests/alloc_gate_tests.rs`, the same "counting allocator, exact count asserted" pattern
/// applied to jemalloc instead of `System`): a `#[global_allocator]` in a LIBRARY is inherited by
/// every binary that links it, so this is declared `#[cfg(test)]` ONLY — a dependent never gets it
/// handed to it uninvited.
///
/// PER-THREAD, not process-global: `cargo test` runs this crate's tests concurrently, so a single
/// shared atomic would let another test thread's allocations inflate the measured thread's count and
/// flap an exact-equality gate under load. A `const`-initialized thread-local isolates each thread's
/// count — no lazy init, no destructor, no heap — so `.with()` is a plain TLS read/write, safe to call
/// from inside `GlobalAlloc` (`System.*` never re-enters this allocator).
#[cfg(test)]
pub(crate) struct CountingAlloc;

#[cfg(test)]
thread_local! {
    static ALLOC_COUNT: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
impl CountingAlloc {
    /// Allocations observed on THIS thread since process start (or last [`reset`](Self::reset)).
    pub(crate) fn count() -> u64 {
        ALLOC_COUNT.with(|c| c.get())
    }
    /// Reset this thread's counter to zero and return the previous value.
    pub(crate) fn reset() -> u64 {
        ALLOC_COUNT.with(|c| c.replace(0))
    }
}

#[cfg(test)]
// SAFETY: every method forwards straight to `System`, only adding a per-thread counter increment
// before the call — it changes no allocation behaviour, only observes it.
unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { std::alloc::System.alloc(layout) }
    }
    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout` are unchanged.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
    #[inline]
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }
    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        // SAFETY: forwarded verbatim; the caller's obligations on `ptr`/`layout`/`new_size` are
        // unchanged.
        unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(test)]
#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
