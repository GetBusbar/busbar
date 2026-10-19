// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT LANE'S SIZED-STRUCT DISCIPLINE: the append-only field-read guard its POD structs
//! (`Facts`, `Usage`, `Signal`, `EgressDesc`) are read through. It belongs to this lane alone and
//! goes with it; the memory ABI has no such guard, because its every struct has exactly one size
//! (owner ruling 21).

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
/// use busbar_contract::abi::{read_sized_field, hot::Facts};
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
            $crate::abi::hot::sized::honoured_size($size, ::core::mem::size_of::<$struct>());
        // The field's END offset, derived WITHOUT touching `p`: a full-size `MaybeUninit` probe is a
        // real, correctly-sized, correctly-aligned allocation, and `addr_of!` only computes an
        // address — it never reads the uninitialized bytes. Const-folds to a literal.
        let probe = ::core::mem::MaybeUninit::<$struct>::uninit();
        let end = ::core::mem::offset_of!($struct, $field)
            + $crate::abi::hot::sized::pointee_size(
                // SAFETY: `probe` is a whole, aligned `$struct`; `addr_of!` performs no read.
                unsafe { ::core::ptr::addr_of!((*probe.as_ptr()).$field) },
            );
        if $crate::abi::hot::sized::field_present(advertised, end) {
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
