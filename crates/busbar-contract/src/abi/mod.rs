// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE busbar plugin interface** — the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, the plugin ABI:
//! plugins speak the memory ABI only) over the shared mechanism, one folder per kind.
//!
//! * [`mechanism`] and `abi/<kind>/` — the ONE memory ABI: one door, one call shape, one
//!   lifecycle, and each kind's own operations, shapes and version.
//! * The HOT lane (`abi::hot`, a `#[repr(C)]` fn-pointer vtable) and the COLD/JSON lane, which THE
//!   DESIGN's plugin ABI abolished, are deleted, with the handshake (`busbar_abi`,
//!   `busbar_plugin_kind`) they shared. A 1.5.5 JSON-contract plugin is refused at boot naming the
//!   rebuild against the 1.6.0 SDK (the plugin ABI's "no legacy loading").
//!
//! # The shared root (this module)
//!
//! The cross-boundary discipline, hoisted here so there is one definition:
//!
//! 1. **The airlock preamble** ([`AbiPreamble`]) — a `#[repr(C)]` header FROZEN
//!    FOR ALL TIME. Its three fields (`magic`, `abi_major`, `abi_minor`) may NEVER be reordered,
//!    resized, or removed. A major mismatch or a magic mismatch is fail-closed (the seam refuses),
//!    so an incompatible peer can never be reached across the boundary.
//! 2. **Sized-struct / append-only discipline** — a cross-boundary POD struct that LEADS with a
//!    `size` is read field by field only where `size` proves the sender wrote it (see
//!    [`field_present`] / [`read_sized_field`]). New fields may ONLY be appended; a peer that
//!    predates a field simply never reads it. Reorder/resize/insert = a MAJOR airlock bump.

#![deny(unsafe_op_in_unsafe_fn)]

/// ONE DECLARATIVE LIST PER TABLE: each slot's fn-pointer type and the `#[repr(C)]` table holding
/// one `Option` of each — the table's size header first, then the slots in the order listed, each
/// named for the trait method it lowers, each answering the outcome byte the list states (`->
/// Outcome`). The coverage witness (`tests/conn_slot_coverage.rs`) reads the list and holds it to
/// the trait.
///
/// Every slot is `unsafe extern "C"`: its raw ranges need a caller's ownership proof. The C ABI
/// (THE DESIGN, the signed kind-ABI design's finding M3: unwinding across
/// a foreign cdylib is undefined behaviour, so a slot catches its own panic and answers its fault
/// byte, and a panic that escapes it aborts).
macro_rules! slot_table {
    (
        extern "C";
        $(#[$doc:meta])*
        pub struct $table:ident lowers $trait:ident -> $ret:ty {
            $(
                $(#[$sdoc:meta])*
                $slot:ident: $alias:ident = fn($($arg:ident: $ty:ty),* $(,)?);
            )*
        }
    ) => {
        $(
            $(#[$sdoc])*
            ///
            /// # Safety
            /// The context is this table's live host-minted context. Numeric handles are checked
            /// by the host as the slot specifies; they do not authorize pointer dereferences. Input
            /// pointers name initialized, live, immutable ranges of their stated lengths;
            /// output pointers name live, exclusive writable ranges of their stated capacities.
            /// Nested ranges and returned borrows obey this slot's documented lifetime. The
            /// caller keeps these owners alive and upholds the method's concurrency contract.
            pub type $alias = unsafe extern "C" fn($($arg: $ty),*) -> $ret;
        )*
        slot_table!(@table $(#[$doc])* $table { $($slot: $alias),* });
    };
    (@table $(#[$doc:meta])* $table:ident { $($slot:ident: $alias:ident),* }) => {
        $(#[$doc])*
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct $table {
            #[doc = concat!("`size_of::<", stringify!($table), ">()` at construction.")]
            pub size: u32,
            /// Alignment padding.
            pub _reserved: u32,
            $(
                #[doc = concat!("`", stringify!($slot), "`.")]
                pub $slot: Option<$alias>,
            )*
        }
    };
}

/// THE LIST FIELDS OF ONE ABI STRUCT, written and read through methods: a list
/// is a pointer and a length, which these set together,
/// to items that live for the program. The fields remain
/// public. Per list `name, name_len: T => name_ptr, with_name,
/// with_raw_name;` it states, in the struct's `impl`:
///
/// * `with_name(&'static [T])` — the safe setter, `const`: the pointer and the length together;
/// * `with_raw_name(ptr, len)` — `unsafe`: a list stated unchecked, as a host's own test states
///   what a foreign plugin could, for the host's checks to judge;
/// * `name()` — the items, `unsafe` while the fields are pub (safe code could state any pointer by
///   hand);
/// * `name_ptr()` / `name_len()` — the raw pointer and length, which a host reads a foreign
///   struct by, under its own checks.
macro_rules! abi_lists {
    ($($list:ident, $len:ident: $t:ty => $ptr:ident, $with:ident, $raw:ident;)+) => {$(
        #[doc = concat!(
            "Set `", stringify!($list), "` to `items`, which live for the program: its pointer ",
            "and its length together (status row 194)."
        )]
        #[must_use]
        pub const fn $with(mut self, items: &'static [$t]) -> Self {
            self.$list = items.as_ptr();
            self.$len = items.len();
            self
        }

        #[doc = concat!(
            "Set `", stringify!($list), "` to `len` items at `ptr`, unchecked: a host's own test ",
            "stating a list as a foreign plugin could, for the host's checks to judge."
        )]
        ///
        /// # Safety
        ///
        #[doc = concat!(
            "Every read of the list as items finds `len` initialised items at `ptr`, alive and ",
            "unwritten for as long as that read. A list nothing reads that way (one only a host's ",
            "checks read, through [`Self::", stringify!($ptr), "`]) may be anything."
        )]
        #[must_use]
        pub const unsafe fn $raw(mut self, ptr: *const $t, len: usize) -> Self {
            self.$list = ptr;
            self.$len = len;
            self
        }

        #[doc = concat!(
            "The `", stringify!($list), "` items: a list set by [`Self::", stringify!($with),
            "`] lives for the program."
        )]
        ///
        /// # Safety
        ///
        #[doc = concat!(
            "The list's pointer and length name `len` initialised items, alive and unwritten for ",
            "the borrow of `self`: true of a list set by [`Self::", stringify!($with), "`] (items ",
            "that live for the program) and not since written through the pub pointer and length ",
            "fields, which this tree's code honours. #1471 makes those fields private and this ",
            "reader safe; a plugin calls it as `unsafe { x.", stringify!($list), "() }` under ",
            "`#[allow(unused_unsafe)]`, and the same line compiles before and after."
        )]
        #[must_use]
        pub unsafe fn $list(&self) -> &[$t] {
            // SAFETY: the caller's contract.
            unsafe { crate::abi::abi_slice(self.$list, self.$len) }
        }

        #[doc = concat!("The raw pointer of `", stringify!($list), "` (NULL = none).")]
        #[must_use]
        pub const fn $ptr(&self) -> *const $t {
            self.$list
        }

        #[doc = concat!("How many items `", stringify!($list), "` states.")]
        #[must_use]
        pub const fn $len(&self) -> usize {
            self.$len
        }
    )+};
}

/// `len` items at `p`, or none for a NULL `p` or a zero `len`: the one place the lists and strings
/// of the ABI are read as slices by their `unsafe` readers.
///
/// # Safety
///
/// A non-NULL `p` with a non-zero `len` names `len` initialised, aligned `T`s, alive and unwritten
/// for `'a`.
pub(crate) unsafe fn abi_slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }
}

pub mod host;
pub mod sdk;

pub mod auth;
pub mod export;
pub mod hook;
pub mod mechanism;
pub mod plane;
pub mod secret;
/// The shapes the memory ABI's connection table carries that the retired HOT lane named first.
pub mod shared;
pub mod store;
pub mod transport;

pub use crate::read_sized_field;

extern "Rust" {
    fn __busbar_kernel_root(seal: crate::caps::KernelSeal) -> Box<dyn std::any::Any + Send + Sync>;
}

/// Hand `seal` to the kernel's root symbol; [`crate::caps::KernelSeal::deliver`] is the only

#[inline]
pub(crate) fn kernel_root(seal: crate::caps::KernelSeal) -> Box<dyn std::any::Any + Send + Sync> {
    // SAFETY: `__busbar_kernel_root` is defined exactly once, by `busbar-kernel`
    // (`crates/busbar-kernel/src/seal.rs`), with this exact signature, and both crates are built
    // together by one compiler in one workspace, so the Rust ABI of the declaration and the
    // definition agree. The definition takes the seal by value and returns an owned box; it
    // touches no other state.
    unsafe { __busbar_kernel_root(seal) }
}

/// The magic value every plugin-ABI peer stamps into [`AbiPreamble::magic`]. A wrong magic means the

pub const ABI_MAGIC: u64 = u64::from_le_bytes(*b"BUSPLANE");

/// The MAJOR airlock version. Bumping this is a no-turning-back linker event: a reorder/resize/

pub const ABI_MAJOR: u32 = 2;

/// The MINOR airlock version. Bumped for every APPEND-ONLY addition (a new trailing struct field, a

pub const ABI_MINOR: u32 = 34;

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

/// True iff a sender who advertised `advertised_size` bytes definitely WROTE the field that ends at

#[inline]
#[must_use]
pub const fn field_present(advertised_size: u32, field_end: usize) -> bool {
    advertised_size as usize >= field_end
}

/// The UPPER half of the sized-struct guard: the largest peer-attested `size` this build will honour

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

#[inline]
#[must_use]
pub const fn pointee_size<T>(_p: *const T) -> usize {
    core::mem::size_of::<T>()
}

/// The raw copy used by [`read_sized_field!`].
///
/// # Safety
///
/// `p` must be readable for a valid, initialized `T`, without concurrent writes. Any references
/// in the copied value must remain valid for their stated lifetimes. Alignment is not required.
#[doc(hidden)]
pub unsafe fn read_sized_copy<T: Copy>(p: *const T) -> T {
    // SAFETY: the caller guarantees a valid, initialized `T` at `p`.
    unsafe { core::ptr::read_unaligned(p) }
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
/// The invocation requires an `unsafe` block. `ptr` must address the live prefix of `$struct`
/// covered by `min(size, size_of::<$struct>())`. A field within that prefix must be a valid,
/// initialized `Copy` value, with no concurrent writes; any references it contains must remain
/// valid for their stated lifetimes. The pointer need not be aligned or name a whole `$struct`.
///
/// ```
/// use busbar_contract::abi::read_sized_field;
/// #[repr(C)]
/// struct Shape {
///     size: u32,
///     tokens: u64,
/// }
/// let whole = Shape { size: core::mem::size_of::<Shape>() as u32, tokens: 10 };
/// // `tokens` lies within a whole `Shape`, so it reads as `Some`.
/// assert_eq!(unsafe { read_sized_field!(&whole, whole.size, Shape, tokens) }, Some(10));
/// // A sender whose `size` stops before `tokens` never wrote it: `None`.
/// let short = Shape { size: 4, tokens: 10 };
/// assert_eq!(unsafe { read_sized_field!(&short, short.size, Shape, tokens) }, None);
/// ```
///
/// A caller cannot read an arbitrary raw pointer from safe Rust:
///
/// ```compile_fail,E0133
/// use busbar_contract::abi::read_sized_field;
/// #[repr(C)]
/// struct Shape { size: u32, tokens: u64 }
/// let p = core::ptr::dangling::<Shape>();
/// let _ = read_sized_field!(p, core::mem::size_of::<Shape>() as u32, Shape, tokens);
/// ```
///
/// Even in an unsafe block, the macro cannot duplicate ownership of a non-`Copy` field:
///
/// ```compile_fail,E0277
/// use busbar_contract::abi::read_sized_field;
/// #[repr(C)]
/// struct Shape { size: u32, owned: String }
/// let whole = Shape { size: core::mem::size_of::<Shape>() as u32, owned: String::new() };
/// let _ = unsafe { read_sized_field!(&whole, whole.size, Shape, owned) };
/// ```
#[macro_export]
macro_rules! read_sized_field {
    ($ptr:expr, $size:expr, $struct:ty, $field:ident) => {{
        let p: *const $struct = $ptr;
        // The peer's claim, CLAMPED to this build's own struct (the upper half of the guard): a
        // self-attested `size` larger than `$struct` can never widen the window past what this build
        // compiled. See `honoured_size`.
        let advertised: u32 =
            $crate::abi::honoured_size($size, ::core::mem::size_of::<$struct>());
        // The field's END offset, derived WITHOUT touching `p`: a full-size `MaybeUninit` probe is a
        // real, correctly-sized, correctly-aligned allocation, and `addr_of!` only computes an
        // address — it never reads the uninitialized bytes. Const-folds to a literal.
        let probe = ::core::mem::MaybeUninit::<$struct>::uninit();
        // The address projection needs its own unsafe context in the macro definition, even
        // when the caller's required unsafe context also surrounds this expansion.
        #[allow(unused_unsafe)]
        let end = ::core::mem::offset_of!($struct, $field)
            + $crate::abi::pointee_size(
                // SAFETY: `probe` is a whole, aligned `$struct`; `addr_of!` performs no read.
                unsafe { ::core::ptr::addr_of!((*probe.as_ptr()).$field) },
            );
        if $crate::abi::field_present(advertised, end) {
            // Deliberately no unsafe block here: the caller must establish the raw prefix's
            // validity. The helper also enforces `Copy`, so owned fields cannot be duplicated.
            ::core::option::Option::Some($crate::abi::read_sized_copy(
                ::core::ptr::addr_of!((*p).$field),
            ))
        } else {
            ::core::option::Option::None
        }
    }};
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
