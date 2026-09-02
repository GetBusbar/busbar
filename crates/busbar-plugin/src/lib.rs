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
pub const ABI_MINOR: u32 = 19;

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
#[inline]
#[must_use]
pub const fn field_present(advertised_size: u32, field_end: usize) -> bool {
    advertised_size as usize >= field_end
}

/// Read a `Copy` field from a sized POD struct ONLY if its `size` proves the sender wrote it,
/// yielding `Option<FieldTy>`. This is the mechanical form of the append-only rule: a field appended
/// in a later minor is `None` when read from an older sender's struct, never undefined.
///
/// ```
/// use busbar_plugin::{read_sized_field, hot::Facts};
/// let g = Facts::new(10, 100, 1, 0, 0, b"pool");
/// // `tokens` lives within every non-truncated `Facts`, so it reads as `Some`.
/// assert_eq!(read_sized_field!(&*g, Facts, tokens), Some(10));
/// ```
#[macro_export]
macro_rules! read_sized_field {
    ($val:expr, $struct:ty, $field:ident) => {{
        let v = $val;
        let end = ::core::mem::offset_of!($struct, $field) + ::core::mem::size_of_val(&v.$field);
        if $crate::field_present(v.size, end) {
            ::core::option::Option::Some(v.$field)
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

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
