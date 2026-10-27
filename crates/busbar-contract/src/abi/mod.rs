// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE busbar plugin interface** — the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, the plugin ABI:
//! plugins speak the memory ABI only) over the shared mechanism, one folder per kind.
//!
//! * [`mechanism`] and `abi/<kind>/` — the ONE memory ABI: one door, one call shape, one
//!   lifecycle, and each kind's own operations, shapes and version.
//! * The HOT lane (`abi::hot`, a `#[repr(C)]` fn-pointer vtable) and the COLD/JSON lane, which THE
//!   DESIGN's plugin ABI abolished, are deleted (status row 84), with the handshake (`busbar_abi`,
//!   `busbar_plugin_kind`) they shared. A 1.5.5 JSON-contract plugin is refused at boot naming the
//!   rebuild against the 1.6.0 SDK (the plugin ABI's "no legacy loading").
//!
//! # The shared root (this module)
//!
//! The cross-boundary discipline, hoisted here so there is one definition:
//!
//! 1. **The airlock preamble** ([`AbiPreamble`], [`check_preamble`]) — a `#[repr(C)]` header FROZEN
//!    FOR ALL TIME. Its three fields (`magic`, `abi_major`, `abi_minor`) may NEVER be reordered,
//!    resized, or removed. A major mismatch or a magic mismatch is fail-closed (the seam refuses),
//!    so an incompatible peer can never be reached across the boundary.
//! 2. **Sized-struct / append-only discipline** — a cross-boundary POD struct that LEADS with a
//!    `size` is read field by field only where `size` proves the sender wrote it (see
//!    [`field_present`] / [`read_sized_field`]). New fields may ONLY be appended; a peer that
//!    predates a field simply never reads it. Reorder/resize/insert = a MAJOR airlock bump.
//! 3. **The out-param write discipline** ([`write_out`]) — the init-only-on-Ok rule a callee uses to
//!    publish a large POD result into a caller slot without a `Vec` return.

#![deny(unsafe_op_in_unsafe_fn)]

/// ONE DECLARATIVE LIST PER TABLE: each slot's fn-pointer type and the `#[repr(C)]` table holding
/// one `Option` of each — the table's size header first, then the slots in the order listed, each
/// named for the trait method it lowers, each answering the outcome byte the list states (`->
/// Outcome`). The coverage witness (`tests/conn_slot_coverage.rs`) reads the list and holds it to
/// the trait.
///
/// Every slot is `extern "C"` (THE DESIGN, the signed kind-ABI design's finding M3: unwinding across
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
            pub type $alias = extern "C" fn($($arg: $ty),*) -> $ret;
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

/// THE LIST FIELDS OF ONE ABI STRUCT, written and read through methods (status row 194): a list
/// is a pointer and a length, which these set together, to items that live for the program. The
/// fields themselves stay pub until row 194 makes them private (#1471); these methods are the
/// surface a plugin moves to first. Per list `name, name_len: T => name_ptr, with_name,
/// with_raw_name;` it states, in the struct's `impl`:
///
/// * `with_name(&'static [T])` — the safe setter, `const`: the pointer and the length together;
/// * `with_raw_name(ptr, len)` — `unsafe`: a list stated unchecked, as a host's own test states
///   what a foreign plugin could, for the host's checks to judge;
/// * `name()` — the items, `unsafe` while the fields are pub (safe code could state any pointer by
///   hand); #1471 makes the fields private and this reader safe;
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
/// of the ABI are read as slices by their `unsafe` readers (status row 194).
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

// THE ONE MEMORY ABI (the design's locked plugin ABI: one place for every shape): the shared
// mechanism and one folder per kind.
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

// The `#[macro_export]` sized-read macro, named at this module's path too, so a caller writes
// `busbar_contract::abi::read_sized_field!` exactly where it wrote `busbar_plugin::read_sized_field!`.
pub use crate::read_sized_field;

// THE KERNEL SEAL'S ONE CROSSING (#65, ARCHITECT ruling 2026-10-14): declared here, DEFINED only
// by `busbar-kernel` (`crates/busbar-kernel/src/seal.rs`). It lives in `abi` because calling it is
// `unsafe`, and the contract's unsafe lives in this module alone (the unsafe policy in `lib.rs`;
// `caps` stays `forbid(unsafe_code)`). See [`crate::caps::KernelSeal::deliver`].
extern "Rust" {
    fn __busbar_kernel_root(seal: crate::caps::KernelSeal) -> Box<dyn std::any::Any + Send + Sync>;
}

/// Hand `seal` to the kernel's root symbol; [`crate::caps::KernelSeal::deliver`] is the only
/// caller. `#[inline]` for the reason `deliver` is: only an image that calls it references the
/// symbol.
#[inline]
pub(crate) fn kernel_root(seal: crate::caps::KernelSeal) -> Box<dyn std::any::Any + Send + Sync> {
    // SAFETY: `__busbar_kernel_root` is defined exactly once, by `busbar-kernel`
    // (`crates/busbar-kernel/src/seal.rs`), with this exact signature, and both crates are built
    // together by one compiler in one workspace, so the Rust ABI of the declaration and the
    // definition agree. The definition takes the seal by value and returns an owned box; it
    // touches no other state.
    unsafe { __busbar_kernel_root(seal) }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 1. The airlock preamble — FROZEN FOR ALL TIME.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The magic value every plugin-ABI peer stamps into [`AbiPreamble::magic`]. A wrong magic means the
/// bytes are not a busbar-plugin-ABI preamble at all (a mislinked / corrupt / hostile peer) and the
/// seam refuses. Chosen to be non-zero and unlikely to occur by accident: ASCII `"BUSPLANE"`
/// little-end.
pub const ABI_MAGIC: u64 = u64::from_le_bytes(*b"BUSPLANE");

/// The MAJOR airlock version. Bumping this is a no-turning-back linker event: a reorder/resize/
/// removal of any frozen field, a preamble change, or any non-append-only alteration. Peers with
/// different majors are INCOMPATIBLE and [`check_preamble`] refuses them.
///
/// 1→2 (1.6.0, item 410): minor 21 RESIZED an interior field — `hot::BuildCtx.host_ctx`, 8 → 16
/// bytes, shifting `config_ptr`/`config_len`/`resolved_refs_*` by 8 — under the old major, so
/// `check_preamble` admitted a peer built at any earlier minor and that peer read those fields from
/// the wrong offsets. A resize is not append-only (rule 2 above), so it is this bump. The minor is not
/// reset: it keeps counting append-only additions, and the plane manifest's payload axis reads it.
pub const ABI_MAJOR: u32 = 2;

/// The MINOR airlock version. Bumped for every APPEND-ONLY addition (a new trailing struct field, a
/// new reserved `#[repr(u8)]` variant, a new trailing vtable slot). A newer minor is compatible with
/// an older one BY the sized-struct discipline: the older peer never reads the newer trailing bytes.
///
/// 19→20 (1.6.0 M1): the append-only `hot::Usage` keyed-unit tail (`units_ptr`/`units_len`), paired
/// with `POD_VERSION` 2→3. `check_preamble` still accepts an older minor (append-only compatibility).
///
/// 20→21 (1.6.0, ABI review A6): the HOT-lane `hot::host::HostCtx` gains a `generation` stamp + `kind`
/// tag (it becomes a `#[repr(C)]` opaque handle instead of a bare `*mut c_void`), so the host rejects a
/// stale host handle at slot entry instead of dereferencing it (a use-after-free guard). Append-only on
/// the NEW-in-1.6.0 hot plane/transport ABI (no 1.5.5 byte-identity constraint, nothing on the money
/// JSON path); the version-locked planes rebuild in lockstep. That change RESIZED `BuildCtx.host_ctx`
/// and shifted the fields after it — a MAJOR event, not an append — so it is carried under
/// [`ABI_MAJOR`] 2, which refuses every major-1 peer (item 410).
///
/// 21→22 (1.6.0, item 63): `hot::PlaneDecl` gains the append-only DECLARATION tail (`fallback`, the
/// nouns, `audit_kind`, the signing domain and `kid` prefix, and borrowed lists of scope kinds, owned
/// config sections, billable classes and fee units), so a dropped-in plane states every fact a linked
/// plane's declaration holds. The loader refuses a decl that does not reach the end of that tail: a
/// plane that cannot state its declaration is not installed with one invented for it.
///
/// 22→23 (1.6.0, item 63 / TRACKER H6 part 1): a dropped-in plane SERVES. `hot::PlaneDecl` gains
/// the `claims` and `admission` slots (what a built plane answers on and the audience it binds),
/// `hot::BuildCtx` gains the deployment's public URL, and `hot::WorkItem` gains the dispatch's own
/// host vtable + `HostCtx` and a reply buffer — so the host mounts, admits and drives a plane over
/// the ABI exactly as it does a linked one. All append-only.
///
/// 23→24 (1.6.0, K8; #3 OWNER-LOCKED, #30, #40): a TRANSPORT is droppable. `hot::TransportDecl` is
/// new — the linked transport row (its key, the layers it composes over, `build(lower, settings)`)
/// as declared data plus `listen`/`accept`/`dial`/`read`/`write`/`close` slots over opaque handles,
/// with configuration crossing only as the opaque `hot::WireConfig`. A new struct, so append-only:
/// no existing offset moves, and every earlier-minor plane keeps loading.
///
/// 24→25 (1.6.0, MET-1; ARCHITECT RULING S2-c; #2 rule (2), #30, #65): the METRIC-FAMILY seam.
/// `hot::PlaneDecl` gains the append-only `metric_families` tail (each `hot::decl::DeclMetricFamily`
/// a name, a kind and label keys), and `hot::host::PlaneHostVtable` the trailing `counter_add` slot —
/// a plane adds to a counter family it DECLARED, and the host renders exactly the declared name and
/// keys. A decl ending before the tail declares none. All append-only.
///
/// 25→26 (1.6.0, K8 / K3c intake): `hot::TransportDecl` appends `session` (the linked row's
/// `SESSION`), so a dropped-in transport declares whether it carries sessions exactly as a linked one
/// does. Append-only at the decl's tail; the loader admits a transport decl only from minor 26.
///
/// 26→27 (1.6.0, XPLANE; ARCHITECT RULING (S); #2 rule (2), #47/#49): `hot::PlaneDecl` appends the
/// `served_op_classes` tail (each `hot::decl::DeclServedOpClass` an operation class and the plane's
/// display name), so a dropped-in plane serves a nested destination — which names a class, never a
/// plane — exactly as a linked one does. A decl ending before the tail serves none. Append-only.
///
/// 27→28 (1.6.0, K8c; ARCHITECT "K8b residue", #30, #40(c)): the transport decl's POLL shape. The
/// blocking byte slots cost a thread handoff per crossing (bridge p50 4.25 µs / p99 19 µs, over the
/// HOT-lane budget), so `hot::TransportDecl` appends `init` (build, handed the host's `#[repr(C)]`
/// `hot::transport::WireWaker` handle), `connect` (a dial that answers at once) and the five POLL slots
/// `poll_accept` / `poll_read` / `poll_write` / `poll_flush` / `poll_close`, each answering
/// Ready(n) | Pending | Error (`hot::transport::WireOutcome::Pending` is the appended outcome `13`).
/// The host drives them inline from its reactor. The blocking `build` / `accept` / `dial` / `read` /
/// `write` / `close` are RETIRED in this minor — no shipped wire needs them: their fields keep their
/// offsets, a minor-28 decl leaves them `None`, and the loader refuses a transport built before minor
/// 28 (manifest and decl alike) and a decl that fills a retired slot. Append-only everywhere else.
///
/// 28→29 (1.6.0, UC-VERBS; owner answer Q71(2), ARCHITECT RULING (b)): `hot::PlaneDecl` appends the
/// `record_kinds` tail (a borrowed list of `hot::decl::DeclStr`), so a dropped-in plane declares the
/// plane-record kinds it keeps exactly as a linked one does, and the administrative
/// `plane_record_write` verb writes only a kind the named plane declares. A decl ending before the
/// tail keeps none. Append-only.
///
/// 29→30 (1.6.0, HOTDOOR-B; ARCHITECT DEC-SERVE G2 + SD-3 queue (6); spec Part 3, #28): the CARRIER a
/// plane in its own repository needs. `hot::WorkItem` appends the request-head handle and its
/// accessor slot (`head`, `head_read`: method, path, query, headers), the answer's head slot
/// (`emit_head`: status `u16` + headers) and the response-stream emit handle and slot (`stream`,
/// `emit_body`) a body over the reply buffer is written through — the kind tags still reserve
/// absent/duplex. `hot::host::PlaneHostVtable` appends the four host-service slots (`entropy_fill`,
/// `wall_clock`, `tap_fault_latch`, `translate_cap`), and a plane image may export the optional
/// `busbar_plane_arm` door symbol the host calls to arm its contract ports over them. Append-only.
///
/// 30→31 (1.6.0, TRANSPORT-STACK; OWNER-APPROVED 2026-09-27, spec #3): the TRANSPORT decl is
/// replaced whole — its own generation 2 (`hot::transport::TRANSPORT_DECL_MAJOR`, stated in the
/// decl's `version`), not an append. The byte-stream decl (a key, a composes-over list, a session
/// flag and the poll slots, minors 24–30) is retired, not kept beside the new one: a transport is a
/// carrier or a framer (`crate::transport::stack`), and `hot::TransportDecl` is those two traits
/// lowered one slot per method (`hot::transport::CarrierSlots`, `hot::transport::FramerSlots`), with
/// every constant the transport declares as its row. The loader admits a transport decl only from
/// this minor and only at generation 2. No plane struct moves.
///
/// 31→32 (1.6.0, HOTDOOR-B queue 2; ARCHITECT 2026-09-27, #30 HOT lane): `hot::PlaneDecl` appends
/// `dispatch_flags` (+ padding). A plane's dispatch runs INLINE on the request's worker — no thread
/// hop on the hot lane — unless it sets `hot::decl::DISPATCH_BLOCKS`, when the host runs it on a
/// blocking thread. A decl ending before the tail is run as blocking. Append-only.
///
/// 32→33 (1.6.0, TRANSPORT-STACK claims; ARCHITECT 2026-09-27 ruling (A)): a transport ENTRY answers
/// for one or more schemes. `hot::TransportDecl` appends the claims list (`claims_ptr`,
/// `claims_len`; each `hot::transport::DeclClaim` a scheme and its per-scheme row — sessions, first
/// unit, status leg, facts and selector forms), and `hot::transport::WireConnFacts` appends the
/// claim the host resolved a connection to, which a framer opens its state for. A decl ending before
/// the tail makes the one claim its row describes; facts ending before theirs name the first claim.
/// Append-only.
///
/// 33→34 (1.6.0, CONFIG-REQ; ARCHITECT 2026-09-27, Law 7, Q69(1)): `hot::PlaneDecl` appends the
/// `required_sections` tail (a borrowed list of `hot::decl::DeclStr`), so a dropped-in plane
/// declares the config sections it requires exactly as a linked one does, and a section no
/// registered plane requires may be omitted. A decl ending before the tail requires none.
/// Append-only.
///
/// APPENDED WITHOUT A MINOR (OWNER RULING 2026-09-27: every ABI version constant ships as its v1.5.5
/// value + 1, so pre-release changes do not bump it; the layout golden and the append-compat tests
/// keep appends safe): the framer clock seam — `hot::transport::WireFramerOut` appends the host's time
/// at the call and `wake_at`, `hot::transport::FramerSlots` appends `tick`, and a slot table ending
/// before `tick` keeps no deadline — and the connection table, `host::conn::ConnSlots`, the one table
/// every plugin of every kind reaches the network through. And the mechanism's optional `ready`
/// (ARCHITECT 2026-10-02, discovery at boot): `mechanism::door::Door` appends `ready` after `ops`,
/// with its `in` `mechanism::lifecycle::ReadyIn` — a door ending before it states none and loads
/// exactly as before; no table slot and no kind op moves.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 2. Sized-struct discipline — the append-only field-read guard.
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
/// residual is why the analogous claim on a slot table is REFUSED outright rather than clamped: a
/// wrong POD field is bad data, a wrong slot is a fn-pointer this side then CALLS.
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
/// use busbar_contract::abi::read_sized_field;
/// #[repr(C)]
/// struct Shape {
///     size: u32,
///     tokens: u64,
/// }
/// let whole = Shape { size: core::mem::size_of::<Shape>() as u32, tokens: 10 };
/// // `tokens` lies within a whole `Shape`, so it reads as `Some`.
/// assert_eq!(read_sized_field!(&whole, whole.size, Shape, tokens), Some(10));
/// // A sender whose `size` stops before `tokens` never wrote it: `None`.
/// let short = Shape { size: 4, tokens: 10 };
/// assert_eq!(read_sized_field!(&short, short.size, Shape, tokens), None);
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
        let end = ::core::mem::offset_of!($struct, $field)
            + $crate::abi::pointee_size(
                // SAFETY: `probe` is a whole, aligned `$struct`; `addr_of!` performs no read.
                unsafe { ::core::ptr::addr_of!((*probe.as_ptr()).$field) },
            );
        if $crate::abi::field_present(advertised, end) {
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
// 3. The out-param write discipline — init-only-on-Ok.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
