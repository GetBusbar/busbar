// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE busbar plugin interface** — the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, the plugin ABI:
//! plugins speak the memory ABI only) over the shared mechanism, one folder per kind, and the HOT
//! lane's shapes, which the legacy planes' host still names until it is deleted.
//!
//! * [`mechanism`] and `abi/<kind>/` — the ONE memory ABI: one door, one call shape, one
//!   lifecycle, and each kind's own operations, shapes and version.
//! * [`hot`] — the HOT lane (was `busbar-plane-abi`). A `#[repr(C)]` fn-pointer vtable no plugin
//!   image loads through any more: every plane and transport loads through its door (row 84). Its
//!   shapes stay while the legacy planes' host names them, and go with it.
//! * The COLD/JSON lane, which THE DESIGN's plugin ABI abolished, is deleted, with the handshake
//!   (`busbar_abi`, `busbar_plugin_kind`) the HOT lane shared with it. A 1.5.5 JSON-contract plugin
//!   is refused at boot naming the rebuild against the 1.6.0 SDK (the plugin ABI's "no legacy
//!   loading").
//!
//! # The shared root (this module)
//!
//! The HOT lane obeys this cross-boundary discipline, hoisted here so there is one definition:
//!
//! 1. **The airlock preamble** ([`AbiPreamble`], [`check_preamble`]) — a `#[repr(C)]` header FROZEN
//!    FOR ALL TIME. Its three fields (`magic`, `abi_major`, `abi_minor`) may NEVER be reordered,
//!    resized, or removed. A major mismatch or a magic mismatch is fail-closed (the seam refuses),
//!    so an incompatible peer can never be reached across the boundary.
//! 2. **The HOT lane's sized-struct discipline** lives with that lane ([`hot::sized`]); the memory
//!    ABI has none: its every struct has exactly one size (owner ruling 21).
//! 3. **The out-param write discipline** ([`write_out`]) — the init-only-on-Ok rule a callee uses to
//!    publish a large POD result into a caller slot without a `Vec` return.
//!
//! # Neutrality
//!
//! The HOT lane's capability surface was DERIVED from a primitive taxonomy, not ENUMERATED from any
//! one protocol plane: no type, function, variant, or carrier name under [`hot`] may contain a
//! protocol/role noun. A CI witness (`scripts/plane-abi-neutrality.sh`) greps the [`hot`] tree for
//! the banned set and asserts zero.

#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::MaybeUninit;

pub mod host;
pub mod hot;
pub mod sdk;

// THE ONE MEMORY ABI (the design's locked plugin ABI: one place for every shape): the shared
// mechanism and one folder per kind.
pub mod auth;
pub mod export;
pub mod hook;
pub mod mechanism;
pub mod plane;
pub mod secret;
/// The shapes the memory ABI's connection table carries that the condemned HOT lane named first.
pub mod shared;
pub mod store;
pub mod transport;

// The two `#[macro_export]` sized-read macros, named at this module's path too, so a caller writes
// `busbar_contract::abi::read_sized_field!` exactly where it wrote `busbar_plugin::read_sized_field!`.
pub use crate::{host_slot, read_sized_field};

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
/// before `tick` keeps no deadline. (The memory ABI is outside this counter: its every struct has
/// one size, owner ruling 21.)
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
