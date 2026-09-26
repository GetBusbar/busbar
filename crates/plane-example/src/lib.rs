// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: plane` plugin** — a `cdylib` exporting a real
//! [`busbar_plugin::hot::PlaneDecl`] over the HOT-tier ABI. It is the in-tree both-ways coverage for
//! the `kind: plane` seam (the ABI-fixture analogue of the other in-tree example plugin fixtures), and
//! the copy-me template a plane author exports through [`busbar_plugin_sdk::export_plane!`].
//!
//! ## STANDALONE ON PURPOSE
//!
//! Like the other in-tree example plugin fixtures, this crate names NO other plane: its whole
//! behaviour is in this file. It is a REAL, loadable plane — every slot is wired (no
//! `unimplemented!()`), every FFI body runs inside a `catch_unwind`, and every out-param is written
//! only on the `Ok` path.
//!
//! ## IT RIDES THE HOST VTABLE — THAT IS THE WHOLE POINT
//!
//! This plane is deliberately trivial in what it *computes* and deliberately NOT trivial in what it
//! *crosses*: every dispatch makes SIX real inbound calls back through the
//! [`PlaneHostVtable`](busbar_plugin::hot::PlaneHostVtable) — the one its work item carries (minted
//! for that dispatch), or, from an older host, the one it was handed at `build` — and a seventh at
//! `start`. It is the tree's proof that the plane ABI is crossed in both directions by a real
//! dropped-in artifact rather than exercised host-to-itself.
//!
//! **Every one of those calls is REQUIRED, not opportunistic.** An absent slot, a fail-closed return
//! or a denied decision makes [`dispatch`] answer [`StatusClass::Refused`] — so a host that does not
//! actually grant the capability cannot get an `Ok` out of this plane. That is what makes a test over
//! this fixture able to FAIL when the seam is not really crossed: handing it
//! [`PlaneHostVtable::EMPTY`](busbar_plugin::hot::PlaneHostVtable::EMPTY) refuses, and nulling ONE
//! slot of an otherwise-real host refuses naming that slot. A plane that merely *mentioned* the
//! vtable would pass either way, which is the failure mode this fixture exists to make impossible.
//!
//! The six crossings, in the order the lifecycle makes them:
//!
//! | hop | slot | why this plane needs it |
//! | --- | --- | --- |
//! | `build` | (the AIRLOCK, not a slot) | `PlaneHostVtable::check` — the preamble/size handshake |
//! | `start` | `clock_now` | the plane takes NO ambient clock; its start instant is the host's |
//! | `dispatch` | `clock_now` | the work item's arrival instant, likewise the host's |
//! | `dispatch` | `govern_admit` | admission is the HOST's decision; a `Deny` refuses the item |
//! | `dispatch` | `meter_charge` | the one-shot raw-count fact (see the money note below) |
//! | `dispatch` | `cost_reserve` | open the metering LEASE for the item |
//! | `dispatch` | `cost_settle` | settle the lease and read back exhaustion |
//! | `dispatch` | `journal_append` | one audit row per dispatch, framed and chained by the host |
//!
//! ## IT SERVES — THE SAME WAY LINKED OR DROPPED IN
//!
//! Built with the deployment's public URL, the plane states one door through its `claims` slot
//! (`POST /example`, `http+json`) and the audience it binds through `admission` (the public URL joined
//! to that path). Every dispatch that carries a reply channel answers one JSON object: the raw count
//! it metered and the config section it was built with, quoted verbatim — the proof the operator's
//! `example:` section reached `build` over the ABI.
//!
//! ## MONEY: THIS PLANE IS PRICING-BLIND, AND EVERY NANODOLLAR IT HANDS OVER IS LITERALLY ZERO
//!
//! DECISIONS #43/#71: a plane COUNTS, it never VALUES. #77(3): a price is NEVER stored. So:
//!
//! * The only money fact this plane produces is a RAW COUNT — the number of inbound bytes the work
//!   item carried — emitted through `meter_charge` as [`UsageComponent::Bytes`] with
//!   `unit_cost_micros` set to **0**. It reads no rate card, holds no rate, and performs no
//!   multiplication whose result is money.
//! * `cost_reserve`/`cost_settle` take ALREADY-PRICED nanodollars. A pricing-blind plane has no
//!   priced figure to put in them, so it passes **0** for the reserve, the flat fee and every
//!   settlement, and declares the lease UNCAPPED (`cap_present = false`). The lease is opened and
//!   settled because the LIFECYCLE is the plane's obligation; the AMOUNT is not the plane's to know.
//! * There is no `f32`/`f64` anywhere in this file, on a money path or off one (#77(8)/#81). Every
//!   count is a `u64` and every crossing is an integer.
//!
//! ## Both-ways by construction
//!
//! [`PLANE_DECL`] is a `pub static`, so the SAME decl is usable STATICALLY (a build depends on this
//! crate as a normal `lib` and hands `&PLANE_DECL` to a registry) OR DROPPED-IN (the `cdylib` the
//! [`export_plane!`](busbar_plugin_sdk::export_plane) symbols deliver, loaded by
//! `busbar_plugin_loader::load_plane`). The drop-in conformance test loads it BOTH ways and asserts
//! the two decls are byte-identical at the vocabulary/carrier/preamble surface — the plane's both-ways
//! proof over the ABI.

use busbar_plugin::hot::decl::{
    BuildCtx, DeclBillableClass, DeclMetricFamily, DeclServedOpClass, DeclStr, IngressCarrier,
    OpaqueHandle,
};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::pod::{
    AdmissionId, CostLeaseId, CostSettleOut, Decision, Facts, Framing, FramingDesc, MeterOutcome,
    OpaqueState, RawFraming, RawStatus, StatusClass, Usage, UsageComponent, POD_VERSION,
};
use busbar_plugin::hot::{PlaneDecl, WorkItem};
use busbar_plugin::{host_slot, write_out, AbiPreamble};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

// ── The plane's own vocabulary (borrowed by the decl; `'static` for the life of the image) ──────────
const NAME: &[u8] = b"example";
const SECTION_KEY: &[u8] = b"example";
const SCOPE: &[u8] = b"example";
const LABEL: &[u8] = b"Example Plane";

// ── The rest of the plane's declaration (the decl's declaration tail) ────────────────────────────
// Every value differs from the plane's key on purpose: a host that fell back to the key (or to any
// default) for a fact the plane states would install a different row, and the both-doors proof
// (`crates/busbar/src/root/tests/linked.rs`) compares the row against what is stated here.
/// The grant kinds that admit traffic on this plane; `SCOPE` leads them.
static SCOPE_KINDS: [DeclStr; 2] = [DeclStr::new("example"), DeclStr::new("example_route")];
/// The top-level config sections this plane owns the grammar of.
static OWNED_SECTIONS: [DeclStr; 1] = [DeclStr::new("example_routes")];
/// The one billable class this plane ledgers: the inbound-byte RAW COUNT its `dispatch` meters.
static BILLABLE_CLASSES: [DeclBillableClass; 1] = [DeclBillableClass {
    class: DeclStr::new("inbound_bytes"),
    family: DeclStr::new("byte"),
}];
/// The fee unit this plane counts: once per billable request.
static FEE_UNITS: [DeclStr; 1] = [DeclStr::new("per_request")];
/// The label keys of [`METRIC_FAMILIES`]' first-party family, in the order the host renders them.
static CARRIED_KEYS: [DeclStr; 2] = [DeclStr::new("protocol"), DeclStr::new("reason")];
/// The label key of [`METRIC_FAMILIES`]' own family.
static OWN_KEYS: [DeclStr; 1] = [DeclStr::new("carrier")];
/// The counter families this plane adds to through the host's `counter_add`: one of its own, and
/// one first-party series the host lists as carriable — the seam's byte-identity witness.
static METRIC_FAMILIES: [DeclMetricFamily; 2] = [
    DeclMetricFamily {
        name: DeclStr::new("example_dispatches_total"),
        kind: DeclStr::new("counter"),
        label_keys_ptr: OWN_KEYS.as_ptr(),
        label_keys_len: OWN_KEYS.len(),
    },
    DeclMetricFamily {
        name: DeclStr::new("busbar_billing_tap_decode_fail_total"),
        kind: DeclStr::new("counter"),
        label_keys_ptr: CARRIED_KEYS.as_ptr(),
        label_keys_len: CARRIED_KEYS.len(),
    },
];

/// The operation class this plane serves one level down, and the display name a refusal naming it
/// reads — so a dropped-in plane answers a nested destination (which names a class, never a plane)
/// exactly as a linked one does, and the both-doors proof compares a non-empty row.
static SERVED_OP_CLASSES: [DeclServedOpClass; 1] = [DeclServedOpClass {
    op: DeclStr::new("example_echo"),
    name: DeclStr::new("Example Plane"),
}];

/// The plane-record kind this plane keeps, so the both-doors proof compares a non-empty row.
static RECORD_KINDS: [DeclStr; 1] = [DeclStr::new("example_record")];

/// THE PATH THIS PLANE ANSWERS ON, the method it takes and the wire format it speaks — what its
/// `claims` slot states once it is built with a public URL to be admitted under.
const CLAIM_METHOD: &str = "POST";
/// See [`CLAIM_METHOD`].
const CLAIM_PATH: &str = "/example";
/// See [`CLAIM_METHOD`].
const CLAIM_WIRE: &str = "http+json";

/// The journal scope this plane writes one audit row per dispatch into, through the host's
/// `journal_append` — the host frames, chains and digests it; the plane supplies the content only.
const AUDIT_SCOPE: u32 = 0x0045_5850;

/// The neutral pool name this plane admits against. A pool is the HOST's routing/limit bucket; the
/// plane names its own section key so an operator's limits land where they expect. Borrowed by the
/// [`Facts`] handed to `govern_admit`, so it must outlive the call — a `'static` does.
const ADMIT_POOL: &[u8] = b"example";

/// The parsed-config handle `config_validate` produces. Trivial (the example accepts any config), but
/// a REAL heap allocation so the `free` round-trip is exercised, not skipped.
struct ParsedConfig;

/// The built plane's live state.
///
/// It holds the INBOUND CAPABILITY SEAM the host handed over at `build` — the
/// [`PlaneHostVtable`] pointer, the honoured size
/// [`PlaneHostVtable::check`](busbar_plugin::hot::PlaneHostVtable::check) attested for it, and the
/// opaque [`HostCtx`] every host call threads back — plus the counters that prove the crossings
/// happened. Stashing the seam at `build` and calling it at `start`/`dispatch` is exactly what a real
/// plane does; it is also what makes "did the vtable actually get crossed?" a question this fixture's
/// return status can answer.
struct PlaneState {
    /// The host's capability vtable. Valid for the life of the built plane (the `build` contract).
    host: *const PlaneHostVtable,
    /// The honoured size `PlaneHostVtable::check` returned. EVERY slot is read through it via
    /// [`host_slot!`], so a host built against an OLDER airlock minor (a shorter table) reads a
    /// trailing slot it never wrote as ABSENT rather than as a fn-pointer from past its allocation.
    host_size: u32,
    /// The opaque host context threaded as the first argument of every host call. Never dereferenced
    /// by the plane; handed back so the host recovers its own state.
    host_ctx: HostCtx,
    /// How many work items this plane has dispatched (each one having made its full host round trip).
    dispatched: AtomicU64,
    /// The host clock reading `start` took, in Unix nanoseconds. The plane takes no ambient clock.
    started_at_nanos: AtomicU64,
    /// The running RAW COUNT this plane has reported through `meter_charge`: inbound bytes. A COUNT,
    /// never a value — see the module's money note.
    metered_units: AtomicU64,
    /// The raw config section bytes the host built this plane with — the operator's `example:`
    /// section as the host lifted it, copied out of the build context (whose range is live only for
    /// the `build` call). Every reply quotes it, which is how a caller sees the section arrived.
    section: Vec<u8>,
    /// The deployment's public URL, when the host stated one. Without it the plane has no audience
    /// to be admitted under, so it claims no path (a mounted door with no lock is refused at boot).
    public_url: Option<String>,
}

/// NEVER-PANICS free for a [`ParsedConfig`] handle (the catch-guarded shape a real plane's `free`
/// uses). # Safety: `ptr`, when non-null, is exactly a handle `config_validate` produced.
extern "C-unwind" fn free_parsed(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<ParsedConfig>` in `config_validate`.
        drop(unsafe { Box::from_raw(ptr as *mut ParsedConfig) });
    }));
}

/// NEVER-PANICS free for a [`PlaneState`] handle. # Safety: `ptr`, when non-null, is exactly a handle
/// `build` produced and not yet freed.
extern "C-unwind" fn free_state(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<PlaneState>` in `build`.
        drop(unsafe { Box::from_raw(ptr as *mut PlaneState) });
    }));
}

/// `config_validate` — accept any raw config, producing an opaque parsed handle on `Ok`.
extern "C-unwind" fn config_validate(
    _raw_ptr: *const u8,
    _raw_len: usize,
    out_parsed: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        let handle = OpaqueState {
            ptr: Box::into_raw(Box::new(ParsedConfig)) as *mut c_void,
            free: Some(free_parsed),
        };
        // SAFETY: `out_parsed` is a caller MaybeUninit slot (or null, which `write_out` tolerates);
        // written only on the Ok path (init-only-on-Ok).
        unsafe { write_out(out_parsed, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `build` — construct the plane from a [`BuildCtx`] (secrets pre-resolved), producing the opaque
/// plane handle core keeps and never downcasts.
///
/// THIS IS THE PLANE'S HALF OF THE AIRLOCK. The loader checked the plane's `PlaneDecl` preamble
/// before it called anything here; this is the symmetric check in the other direction — the plane
/// [`check`](busbar_plugin::hot::PlaneHostVtable::check)s the HOST's table before it will hold a
/// pointer it later CALLS THROUGH. A null host, a host whose magic/MAJOR does not match this build,
/// or a host whose attested size is under the frozen header or over this build's struct is
/// [`StatusClass::Refused`] — the plane does not build at all. Fail-closed both ways is the contract:
/// a wrong POD field is bad data, a wrong vtable slot is a fn-pointer this side then calls.
extern "C-unwind" fn build(
    ctx: *const BuildCtx,
    out_handle: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if ctx.is_null() {
            return StatusClass::Refused;
        }
        // Read the ctx's own attested size WITHOUT forming a `&BuildCtx` over a possibly-shorter
        // peer allocation, exactly as the loader reads a decl's.
        // SAFETY: a non-null `ctx` addresses at least the leading prefix of a `BuildCtx` (the ABI
        // build contract); `addr_of!` computes an address only and `read_unaligned` assumes no
        // alignment the peer did not promise.
        let advertised: u32 =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ctx).size)) };
        // SAFETY (both reads): `field_present` inside the macro proves the attested size reaches
        // through each field before it is projected; see `read_sized_field!`'s own contract.
        let host = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, host);
        let host_ctx = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, host_ctx);
        let (Some(host), Some(host_ctx)) = (host, host_ctx) else {
            // A ctx too short to carry the capability seam cannot build a plane that rides it.
            return StatusClass::Refused;
        };
        // The borrowed ranges are live for this call only, so each is COPIED out. The section is the
        // config range; the public URL is the minor-23 tail, absent from an older host's ctx.
        let config_ptr = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, config_ptr);
        let config_len = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, config_len);
        let url_ptr = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, public_url_ptr);
        let url_len = busbar_plugin::read_sized_field!(ctx, advertised, BuildCtx, public_url_len);
        let section = borrowed(
            config_ptr.unwrap_or(core::ptr::null()),
            config_len.unwrap_or(0),
        );
        let public_url = url_ptr
            .filter(|p| !p.is_null())
            .and_then(|p| String::from_utf8(borrowed(p, url_len.unwrap_or(0))).ok());
        if host.is_null() {
            return StatusClass::Refused;
        }
        // THE AIRLOCK, plane side. `check` reads the frozen preamble + attested size by address and
        // never forms a `&PlaneHostVtable`, so a host allocation shorter than this build's struct is
        // refused rather than read past.
        // SAFETY: `host` is non-null and, per the `build` contract, addresses at least the leading
        // prefix of a live `PlaneHostVtable` that outlives the built plane.
        let Ok(host_size) = (unsafe { PlaneHostVtable::check(host) }) else {
            return StatusClass::Refused;
        };
        let handle = OpaqueState {
            ptr: Box::into_raw(Box::new(PlaneState {
                host,
                host_size,
                host_ctx,
                dispatched: AtomicU64::new(0),
                started_at_nanos: AtomicU64::new(0),
                metered_units: AtomicU64::new(0),
                section,
                public_url,
            })) as *mut c_void,
            free: Some(free_state),
        };
        // SAFETY: as `config_validate`.
        unsafe { write_out(out_handle, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `hydrate` — no persisted state to restore (idempotent Ok).
extern "C-unwind" fn hydrate(state: *mut c_void) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            StatusClass::Refused
        } else {
            StatusClass::Ok
        }
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `start` — begin accepting work, stamping the start instant FROM THE HOST CLOCK.
///
/// The first real crossing of the lifecycle: a plane takes no ambient clock (that is what the
/// `clock_now` slot is for), so an absent slot or the slot's fail-closed `0` reading REFUSES the
/// start rather than inventing a time. Idempotent — a second `start` simply re-stamps.
extern "C-unwind" fn start(state: *mut c_void) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is the live `PlaneState` `build` produced (ABI lifecycle discipline); it is
        // mutated only through its atomics.
        let st = unsafe { &*(state as *const PlaneState) };
        // SAFETY: `st.host`/`st.host_size` are exactly what `PlaneHostVtable::check` validated at
        // build, over a table the host guarantees outlives the built plane.
        let Some(clock_now) = host_slot!(st.host, st.host_size, clock_now) else {
            return StatusClass::Refused;
        };
        let now_nanos = clock_now(st.host_ctx);
        if now_nanos == 0 {
            // `0` is the slot's documented fail-closed reading, never a wild value — and never a
            // real Unix nanosecond. Treat it as "the host did not answer".
            return StatusClass::Refused;
        }
        st.started_at_nanos.store(now_nanos, Ordering::Relaxed);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `dispatch` — THE ingress entry point, and THE cross-ABI round trip.
///
/// Recovers the built [`PlaneState`], then makes SIX REQUIRED calls back through the host vtable:
/// `clock_now` → `govern_admit` → `meter_charge` → `cost_reserve` → `cost_settle` →
/// `journal_append`. Any absent slot, any fail-closed reading, any `Deny`/`Rejected`/non-`Ok`, any
/// exhausted lease and any unwritten audit row answers [`StatusClass::Refused`]; only a full round
/// trip answers `Ok` (and writes the reply, when the work item carries a channel). See the module
/// docs for the money posture — every nanodollar this fn hands the host is a literal `0`.
extern "C-unwind" fn dispatch(state: *mut c_void, work: *const WorkItem) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() || work.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is a live `PlaneState` `build` produced; `work` is a live `WorkItem` for the
        // call (ABI dispatch discipline). Neither is mutated through a shared ref except the atomics.
        let st = unsafe { &*(state as *const PlaneState) };
        let w = unsafe { &*work };
        // THE DISPATCH'S OWN HOST, when the work item carries one (minor 23): a serving host mints a
        // fresh `HostCtx` per dispatch, live only for this call, so the plane calls back through it
        // and `check`s that table as it checked the build-time one. An older host's work item carries
        // none, and the plane rides the seam it was handed at build.
        let advertised = w.size;
        let (host, host_size, ctx) = match (
            busbar_plugin::read_sized_field!(work, advertised, WorkItem, host),
            busbar_plugin::read_sized_field!(work, advertised, WorkItem, host_ctx),
        ) {
            (Some(host), Some(ctx)) if !host.is_null() => {
                // SAFETY: a non-null work-item host addresses a live `PlaneHostVtable` for the call.
                let Ok(size) = (unsafe { PlaneHostVtable::check(host) }) else {
                    return StatusClass::Refused;
                };
                (host, size, ctx)
            }
            _ => (st.host, st.host_size, st.host_ctx),
        };

        // THE RAW COUNT this item consumed: the inbound byte length. Touching `inbound.len` also
        // proves the borrowed `(ptr,len)` crossed the seam intact rather than being silently dropped.
        // A COUNT, in the unit the plane declares — never a value, never multiplied by a rate.
        let units: u64 = w.inbound.len as u64;

        // ── 1. CLOCK — the item's arrival instant, from the host. ────────────────────────────────
        // SAFETY (this and every `host_slot!` below): `host`/`host_size` are exactly what
        // `PlaneHostVtable::check` validated at build, over a table that outlives the built plane;
        // `host_slot!` reads each slot only when the attested size proves the host WROTE it.
        let Some(clock_now) = host_slot!(host, host_size, clock_now) else {
            return StatusClass::Refused;
        };
        if clock_now(ctx) == 0 {
            return StatusClass::Refused; // the slot's fail-closed reading
        }

        // ── 2. ADMIT — admission is the HOST's decision, never the plane's. ───────────────────────
        let Some(govern_admit) = host_slot!(host, host_size, govern_admit) else {
            return StatusClass::Refused;
        };
        // `tokens = budget_remaining = 0` makes the POD's own pre-chain gate a no-op, so the host's
        // real limit chain is the sole decider — the same Facts shape core's own admit wrapper builds.
        let facts = Facts::new(0, 0, 0, 0, 0, ADMIT_POOL);
        let facts_ptr: *const Facts = &*facts;
        if govern_admit(ctx, facts_ptr) == Decision::Deny {
            return StatusClass::Refused;
        }

        // ── 3. METER — the one-shot RAW-COUNT fact. `unit_cost_micros` is 0 BECAUSE THIS PLANE DOES
        //    NOT PRICE (#43/#71): it reports how much was consumed, the host decides what that is
        //    worth, and the worth is a read-time view the plane never sees and never stores (#77(3)).
        //    `AdmissionId::NONE` = no resolved attribution; the host synthesizes one. ───────────────
        let Some(meter_charge) = host_slot!(host, host_size, meter_charge) else {
            return StatusClass::Refused;
        };
        let usage = Usage::charge(UsageComponent::Bytes, units, 0, AdmissionId::NONE);
        let usage_ptr: *const Usage = &*usage;
        if meter_charge(ctx, usage_ptr) != MeterOutcome::Charged {
            return StatusClass::Refused;
        }

        // ── 4. RESERVE — open the item's metering lease. A pricing-blind plane has no priced figure
        //    to reserve, so the reserve, the flat fee and the cap are all `0` and the lease is
        //    declared UNCAPPED (`cap_present = false`, which is never exhausted). Opening the lease is
        //    the plane's LIFECYCLE obligation; sizing it is the host's money obligation. ────────────
        let Some(cost_reserve) = host_slot!(host, host_size, cost_reserve) else {
            return StatusClass::Refused;
        };
        let mut lease_slot = MaybeUninit::<CostLeaseId>::uninit();
        let lease_out: *mut MaybeUninit<CostLeaseId> = &mut lease_slot;
        if cost_reserve(ctx, 0, 0, 0, false, lease_out) != StatusClass::Ok {
            return StatusClass::Refused; // init-only-on-Ok: `lease_slot` stays unread
        }
        // SAFETY: init-only-on-Ok — the host wrote `lease_slot` before returning `Ok`.
        let lease = unsafe { lease_slot.assume_init() };
        if lease.is_none() {
            return StatusClass::Refused; // the reserved NONE sentinel is not a lease
        }

        // ── 5. SETTLE — settle the lease and read back exhaustion. `settle_nanos` is `0` for the
        //    same reason the reserve was: the plane has no priced increment. `breakdown` is absent
        //    (null/0) — there is no itemization of a figure the plane never computed. ──────────────
        let Some(cost_settle) = host_slot!(host, host_size, cost_settle) else {
            return StatusClass::Refused;
        };
        let mut settle_slot = MaybeUninit::<CostSettleOut>::uninit();
        let settle_out: *mut MaybeUninit<CostSettleOut> = &mut settle_slot;
        if cost_settle(ctx, lease, 0, core::ptr::null(), 0, settle_out) != StatusClass::Ok {
            return StatusClass::Refused; // init-only-on-Ok: `settle_slot` stays unread
        }
        // SAFETY: init-only-on-Ok — the host wrote `settle_slot` before returning `Ok`.
        let settled = unsafe { settle_slot.assume_init() };
        if settled.exhausted != 0 {
            // A dry lease means the carrier must hard-close — the one thing post-hoc metering
            // structurally cannot do, and the reason this plane settles before it answers.
            return StatusClass::Refused;
        }

        // ── 6. AUDIT — one row saying what this dispatch was, appended to the host's hash-chained
        //    journal. The host frames the prelude, mints the sequence and digests; the plane states
        //    only the content. A `Seq::NONE` (no row written) refuses the item: a dispatch that left
        //    no record is not one this plane answers. ────────────────────────────────────────────────
        let Some(journal_append) = host_slot!(host, host_size, journal_append) else {
            return StatusClass::Refused;
        };
        let framing = FramingDesc {
            size: core::mem::size_of::<FramingDesc>() as u32,
            version: POD_VERSION,
            framing: RawFraming::of(Framing::PipeSeparated),
            digests_scope: 1,
        };
        let row = format!("example|dispatch|bytes={units}");
        if journal_append(ctx, AUDIT_SCOPE, row.as_ptr(), row.len(), &framing).is_none() {
            return StatusClass::Refused;
        }

        st.dispatched.fetch_add(1, Ordering::Relaxed);
        st.metered_units.fetch_add(units, Ordering::Relaxed);

        // ── 7. REPLY — when the work item carries a reply channel (minor 23): the section this plane
        //    was built with and the raw count it metered, as one JSON object. ────────────────────────
        let reply_ptr = busbar_plugin::read_sized_field!(work, advertised, WorkItem, reply_ptr);
        let reply_cap = busbar_plugin::read_sized_field!(work, advertised, WorkItem, reply_cap);
        let written = busbar_plugin::read_sized_field!(work, advertised, WorkItem, reply_written);
        if let (Some(buf), Some(cap), Some(written)) = (reply_ptr, reply_cap, written) {
            if !buf.is_null() && !written.is_null() {
                let section = if st.section.is_empty() {
                    &b"null"[..]
                } else {
                    &st.section[..]
                };
                let mut body =
                    format!("{{\"plane\":\"example\",\"bytes\":{units},\"section\":").into_bytes();
                body.extend_from_slice(section);
                body.push(b'}');
                if body.len() > cap {
                    return StatusClass::Refused;
                }
                // SAFETY: `buf` is the host's live reply channel of `cap` bytes and `written` its
                // live count slot, both for this call (the reply discipline); `body` fits.
                unsafe {
                    core::ptr::copy_nonoverlapping(body.as_ptr(), buf, body.len());
                    *written = body.len();
                }
            }
        }
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// Copy a borrowed `(ptr, len)` range out (empty for NULL). Safe only on a range the caller's ABI
/// contract makes live for the call, which is every range this plane reads.
fn borrowed(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: a non-null borrowed ABI range is live and initialized for the call.
    unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
}

/// Write `text` into a caller buffer and its length into `out_written`; `Refused` when it does not
/// fit or the caller handed no buffer.
fn answer(text: &str, buf: *mut u8, buf_cap: usize, out_written: *mut usize) -> StatusClass {
    if out_written.is_null() || (buf.is_null() && !text.is_empty()) || text.len() > buf_cap {
        return StatusClass::Refused;
    }
    // SAFETY: `buf` is a live caller range of `buf_cap` bytes and `out_written` a live slot (the
    // buffer discipline); `text` fits.
    unsafe {
        if !text.is_empty() {
            core::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len());
        }
        *out_written = text.len();
    }
    StatusClass::Ok
}

/// `claims` — the one path this plane answers on, once it has an audience to be admitted under.
extern "C-unwind" fn claims(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is the live `PlaneState` `build` produced.
        let st = unsafe { &*(state as *const PlaneState) };
        let text = match st.public_url {
            Some(_) => format!("{CLAIM_METHOD} {CLAIM_PATH} {CLAIM_WIRE}"),
            None => String::new(),
        };
        answer(&text, buf, buf_cap, out_written)
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `admission` — the audience a token presented at this plane's door must carry (the public URL
/// joined to its path) and where a refused caller finds the authorization server.
extern "C-unwind" fn admission(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is the live `PlaneState` `build` produced.
        let st = unsafe { &*(state as *const PlaneState) };
        let text = match st.public_url.as_deref() {
            Some(url) => {
                let url = url.trim_end_matches('/');
                format!("{url}{CLAIM_PATH}\n{url}/.well-known/oauth-protected-resource{CLAIM_PATH}")
            }
            None => String::new(),
        };
        answer(&text, buf, buf_cap, out_written)
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// THE decl: the example plane's `#[repr(C)]` HOT-tier vtable. A `pub static` so it is BOTH the
/// compiled-in reference (linked as an `rlib`) AND, via [`export_plane!`](busbar_plugin_sdk::export_plane)
/// below, the dropped-in `cdylib` entrypoint's payload. Provides the request/response carrier; leaves
/// `admin_routes`/`openapi` `None` (the example contributes no admin/OpenAPI surface).
pub static PLANE_DECL: PlaneDecl = PlaneDecl {
    abi: AbiPreamble::CURRENT,
    size: core::mem::size_of::<PlaneDecl>() as u32,
    version: busbar_plugin::ABI_MINOR,
    name_ptr: NAME.as_ptr(),
    name_len: NAME.len(),
    section_key_ptr: SECTION_KEY.as_ptr(),
    section_key_len: SECTION_KEY.len(),
    scope_ptr: SCOPE.as_ptr(),
    scope_len: SCOPE.len(),
    label_ptr: LABEL.as_ptr(),
    label_len: LABEL.len(),
    provided_carriers: IngressCarrier::RequestResponse.bit(),
    _reserved: 0,
    config_validate: Some(config_validate),
    build: Some(build),
    hydrate: Some(hydrate),
    start: Some(start),
    admin_routes: None,
    openapi: None,
    dispatch: Some(dispatch),
    fallback: 0,
    _reserved2: 0,
    subject_noun: DeclStr::new("example route"),
    admin_noun: DeclStr::new("example-route"),
    audit_kind: DeclStr::new("example_route"),
    signing_domain: DeclStr::new("busbar-example-signing-v1"),
    signing_kid_prefix: DeclStr::new("example-"),
    scope_kinds_ptr: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    owned_sections_ptr: OWNED_SECTIONS.as_ptr(),
    owned_sections_len: OWNED_SECTIONS.len(),
    billable_classes_ptr: BILLABLE_CLASSES.as_ptr(),
    billable_classes_len: BILLABLE_CLASSES.len(),
    fee_units_ptr: FEE_UNITS.as_ptr(),
    fee_units_len: FEE_UNITS.len(),
    claims: Some(claims),
    admission: Some(admission),
    metric_families_ptr: METRIC_FAMILIES.as_ptr(),
    metric_families_len: METRIC_FAMILIES.len(),
    served_op_classes_ptr: SERVED_OP_CLASSES.as_ptr(),
    served_op_classes_len: SERVED_OP_CLASSES.len(),
    record_kinds_ptr: RECORD_KINDS.as_ptr(),
    record_kinds_len: RECORD_KINDS.len(),
};

// Emit the `cdylib` boundary symbols (`busbar_abi`, `busbar_plugin_kind() == "plane"`,
// `busbar_plane_decl()`), delivering `PLANE_DECL` as the dropped-in entrypoint's payload.
busbar_plugin_sdk::export_plane!(PLANE_DECL);
