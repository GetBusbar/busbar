// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAKE HOST: the host tables a plugin's test opens its door over, each service a test double
//! written as safe Rust. A double implements [`FakeService`] over one service `in` and is installed
//! in its slot by [`FakeHost::serve`]; the contract's trampoline reads the `in` the plugin passed,
//! checks its head, hands the double a [`ServiceCall`] and writes the `ServiceOut` back. A double
//! never touches a raw pointer: it reads the strings, blobs and lists the plugin lent through the
//! call, and writes the buffers and slots the plugin lent through it, each checked first.
//!
//! ```ignore
//! use busbar_contract::abi::host::service::ClockNowIn;
//! use busbar_contract::abi::mechanism::call::Outcome;
//! use busbar_test_kit::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
//!
//! struct Clock;
//! impl FakeService for Clock {
//!     type In = ClockNowIn;
//!     fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
//!         call.put(|i| &i.reading, reading_at(7));
//!         Outcome::Ready
//!     }
//! }
//! let host = FakeHost::new().serve(fake::host::CLOCK_NOW, Clock);
//! let lent = host.lend_to(open_in); // borrows the host: it cannot outlive it
//! // SAFETY: these raw frames and this open slot have matching types and live borrowed inputs.
//! let opened = unsafe { reply::call_hosted(open, std::ptr::null_mut(), &lent, open_out) };
//! ```
//!
//! TRUST: a `ServiceFn` is called with the `in` of the slot it is installed in and a writable
//! `ServiceOut` (the service ABI, `abi::host::service`); the strings, lists and buffers that `in`
//! names are live for the call. The trampoline relies on exactly that, and checks what can be
//! checked (NULL, alignment, the head's op and size, a region's count against the capacity lent)
//! before every read or write. A double that panics answers FAULT (the panic is reported, and never
//! crosses the C boundary).

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem::{offset_of, size_of};
use core::ptr;

use super::zeroed;
use busbar_contract::abi::host::conn::connector::{self, ConnectorSlots};
use busbar_contract::abi::host::io::{self as hio, IoSlots};
use busbar_contract::abi::host::service::{
    self as svc, check_head, HostSlots, ItemSpan, ServiceBufs, ServiceHead, ServiceOut,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, WakeFn};

mod sealed {
    use busbar_contract::abi::host::service::ServiceFn;

    pub trait Table: Sized {
        fn install(&mut self, op: u32, f: ServiceFn);

        fn of(host: &mut super::FakeHost) -> &mut Self;
    }

    /// One pointer field of a service `in` and what it lends: where it sits, how many `T` it names,
    /// which way, and (for an `in` two slots share) on which op.
    #[derive(Debug, Clone, Copy)]
    pub struct Region {
        /// The pointer field's offset in the `in`.
        pub at: usize,
        /// The offset of the `usize` field counting it; `None` = it names exactly one.
        pub count_at: Option<usize>,
        /// `size_of` the pointee.
        pub size: usize,
        /// `true` = the host writes it; `false` = the host reads it.
        pub write: bool,
        /// The one op it lends on; `None` = every op.
        pub op: Option<u32>,
    }

    pub trait In {
        const REGIONS: &'static [Region];
    }

    /// Only [`super::FakeHost::lend_to`] makes one.
    #[derive(Debug)]
    pub struct HostToken(pub(super) ());

    pub trait Host {
        fn host_field(
            &mut self,
            token: HostToken,
        ) -> &mut *const busbar_contract::abi::mechanism::ticket::HostTables;
    }

    pub trait Ptr<T> {
        fn get(&self) -> *const T;
    }
}

use sealed::Region;

pub trait ServiceIn: sealed::In + Copy + 'static {}

pub trait ServiceTable: sealed::Table + Copy + 'static {}

pub trait RawPtr<T>: sealed::Ptr<T> {}
impl<T> sealed::Ptr<T> for *const T {
    fn get(&self) -> *const T {
        *self
    }
}
impl<T> RawPtr<T> for *const T {}
impl<T> sealed::Ptr<T> for *mut T {
    fn get(&self) -> *const T {
        self.cast_const()
    }
}
impl<T> RawPtr<T> for *mut T {}

pub trait TakesHost: sealed::Host {}
impl sealed::Host for busbar_contract::abi::mechanism::lifecycle::OpenIn {
    fn host_field(&mut self, _: sealed::HostToken) -> &mut *const HostTables {
        &mut self.host
    }
}
impl TakesHost for busbar_contract::abi::mechanism::lifecycle::OpenIn {}
impl sealed::Host for busbar_contract::abi::plane::PlaneOpenIn {
    fn host_field(&mut self, _: sealed::HostToken) -> &mut *const HostTables {
        &mut self.open.host
    }
}
impl TakesHost for busbar_contract::abi::plane::PlaneOpenIn {}

/// An `open` `in` whose `host` names a [`FakeHost`]'s tables, borrowed from that host: it cannot
/// outlive it, and safe code reads no copy of it (only [`super::reply::call_hosted`] does).
#[derive(Debug)]
pub struct LentIn<'h, I> {
    pub(crate) input: I,
    /// The lists a [`TestIn`](super::test_in::TestIn) lent with it made ([`FakeHost::lend_in`]),
    /// kept for as long as the `in` names them.
    _held: Vec<Box<dyn core::any::Any>>,
    host: PhantomData<&'h FakeHost>,
}

pub trait FakeService: 'static {
    type In: ServiceIn;

    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome;
}

/// One slot of one host table, served over `I` at op `OP`. The constants in [`host`], [`io`] and
/// [`conn`] are the only values: a double is installed only where its `in` is the slot's.
#[derive(Debug)]
pub struct ServiceSlot<T, I, const OP: u32>(PhantomData<fn() -> (T, I)>);

impl<T, I, const OP: u32> Clone for ServiceSlot<T, I, OP> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, I, const OP: u32> Copy for ServiceSlot<T, I, OP> {}

/// `slots!(Table in host_field; NAME => field: In, ...)`, invoked where `ops` names the table's op
/// numbers: one [`ServiceSlot`] constant per slot, and the table's install.
macro_rules! slots {
    ($table:ident in $home:ident; $($name:ident => $field:ident: $in:ty),+ $(,)?) => {
        $(
            #[doc = concat!("The `", stringify!($field), "` slot, over `", stringify!($in), "`.")]
            pub const $name: super::ServiceSlot<$table, $in, { ops::$name }> =
                super::ServiceSlot(core::marker::PhantomData);
        )+

        impl super::sealed::Table for $table {
            fn install(&mut self, op: u32, f: busbar_contract::abi::host::service::ServiceFn) {
                match op {
                    $(ops::$name => self.$field = Some(f),)+
                    _ => panic!("{}: no slot {op}", stringify!($table)),
                }
            }
            fn of(host: &mut super::FakeHost) -> &mut Self {
                &mut host.$home
            }
        }
        impl super::ServiceTable for $table {}
    };
}

pub mod host {
    use busbar_contract::abi::host::service::op as ops;
    use busbar_contract::abi::host::service::{self as svc, HostSlots};

    slots!(HostSlots in services;
        CLOCK_NOW => clock_now: svc::ClockNowIn,
        RECORDS_GET => records_get: svc::RecordsGetIn,
        RECORDS_LIST => records_list: svc::RecordsListIn,
        RECORDS_CLAIM => records_claim: svc::RecordsClaimIn,
        DEST_JUDGE => dest_judge: svc::DestJudgeIn,
        SIGN => sign: svc::SignIn,
        UNIT_NEST => unit_nest: svc::UnitNestIn,
        WORK_OPEN => work_open: svc::WorkOpenIn,
        WORK_FIND => work_find: svc::WorkFindIn,
        WORK_SETTLE => work_settle: svc::WorkSettleIn,
        WORK_RESUME => work_resume: svc::WorkResumeIn,
        TRUST_SIGHT => trust_sight: svc::TrustSightIn,
        TRUST_DUE => trust_due: svc::TrustDueIn,
        VERIFY_LOOKUP => verify_lookup: svc::VerifyLookupIn,
        VERIFY_STORE => verify_store: svc::VerifyStoreIn,
        ENTITLEMENT_CHECK => entitlement_check: svc::EntitlementCheckIn,
        CONTENT_SCAN => content_scan: svc::ContentScanIn,
        HOOK_CALL => hook_call: svc::HookCallIn,
        RANDOM_FILL => random_fill: svc::RandomFillIn,
        NEED_ADMIT => need_admit: svc::NeedAdmitIn,
        TRUST_VERIFY => trust_verify: svc::TrustVerifyIn,
        RECORDS_SECRET => records_secret: svc::RecordsSecretIn,
        DISK_APPEND => disk_append: svc::DiskAppendIn,
        SNAPSHOT_READ => snapshot_read: svc::SnapshotReadIn,
        TRUST_SIGHT_ITEM => trust_sight_item: svc::TrustSightItemIn,
        TRUST_SERVES => trust_serves: svc::TrustServesIn,
        TRUST_DECIDE => trust_decide: svc::TrustDecideIn,
        TRUST_STATE => trust_state: svc::TrustStateIn,
        SESSION_EMIT => session_emit: svc::SessionEmitIn,
    );
}

pub mod io {
    use busbar_contract::abi::host::io::op as ops;
    use busbar_contract::abi::host::io::{self as hio, IoSlots};

    slots!(IoSlots in io;
        OPEN => open: hio::OpenIn,
        LISTEN => listen: hio::ListenIn,
        ACCEPT => accept: hio::AddrIn,
        READ => read: hio::ReadIn,
        WRITE => write: hio::WriteIn,
        READY => ready: hio::ReadyIn,
        SHUT => shut: hio::ShutIn,
        CLOSE => close: hio::HandleIn,
        SPAWN => spawn: hio::SpawnIn,
        ENDS => ends: hio::AddrIn,
    );
}

pub mod conn {
    use busbar_contract::abi::host::conn::connector::service as ops;
    use busbar_contract::abi::host::conn::connector::{self as c, ConnectorSlots};

    slots!(ConnectorSlots in conns;
        ESTABLISH => establish: c::EstablishIn,
        REJECT_ENDPOINT => reject_endpoint: c::StreamIn,
        SIDE_STREAM => side_stream: c::StreamIn,
        READ => read: c::IoIn,
        WRITE => write: c::IoIn,
        UPGRADE_SECURE => upgrade_secure: c::UpgradeIn,
        FACTS => facts: c::FactsIn,
        CHECKOUT => checkout: c::CheckoutIn,
        CHECKIN => checkin: c::CheckinIn,
        CLOSE => close: c::StreamIn,
        IDENTITY => identity: c::IdentityIn,
        READ_REPLY => read_reply: c::ReplyIn,
        WRITE_REQUEST => write_request: c::RequestIn,
    );
}

const fn one(at: usize, size: usize, write: bool) -> Region {
    Region {
        at,
        count_at: None,
        size,
        write,
        op: None,
    }
}

const fn counted(at: usize, count_at: usize, size: usize, write: bool, op: Option<u32>) -> Region {
    Region {
        at,
        count_at: Some(count_at),
        size,
        write,
        op,
    }
}

const W: bool = true;
const R: bool = false;

/// `service_in!(In => [regions]; ...)`.
macro_rules! service_in {
    ($($t:ty => [$($r:expr),* $(,)?]);+ $(;)?) => {$(
        impl sealed::In for $t {
            const REGIONS: &'static [Region] = &[$($r),*];
        }
        impl ServiceIn for $t {}
    )+};
}

service_in!(
    svc::ClockNowIn => [one(
        offset_of!(svc::ClockNowIn, reading),
        size_of::<svc::ClockReading>(),
        W,
    )];
    svc::RecordsGetIn => [];
    svc::RecordsListIn => [];
    svc::RecordsClaimIn => [];
    svc::RecordsSecretIn => [];
    svc::DestJudgeIn => [];
    svc::SignIn => [];
    svc::UnitNestIn => [];
    svc::WorkOpenIn => [];
    svc::WorkFindIn => [];
    svc::WorkSettleIn => [];
    svc::WorkResumeIn => [];
    svc::TrustSightIn => [];
    svc::TrustDueIn => [];
    svc::VerifyLookupIn => [];
    svc::VerifyStoreIn => [];
    svc::EntitlementCheckIn => [];
    svc::ContentScanIn => [];
    svc::HookCallIn => [one(
        offset_of!(svc::HookCallIn, prompt),
        size_of::<busbar_contract::abi::hook::PromptView>(),
        R,
    )];
    svc::RandomFillIn => [];
    svc::NeedAdmitIn => [];
    svc::TrustVerifyIn => [];
    svc::DiskAppendIn => [one(
        offset_of!(svc::DiskAppendIn, result),
        size_of::<svc::DiskWritten>(),
        W,
    )];
    svc::SnapshotReadIn => [];
    svc::TrustSightItemIn => [];
    svc::TrustServesIn => [];
    svc::TrustDecideIn => [];
    svc::TrustStateIn => [];
    svc::SessionEmitIn => [];
    hio::OpenIn => [];
    hio::ListenIn => [counted(
        offset_of!(hio::ListenIn, addr_buf),
        offset_of!(hio::ListenIn, addr_cap),
        1,
        W,
        None,
    )];
    hio::AddrIn => [counted(
        offset_of!(hio::AddrIn, addr_buf),
        offset_of!(hio::AddrIn, addr_cap),
        1,
        W,
        None,
    )];
    hio::ReadIn => [counted(offset_of!(hio::ReadIn, buf), offset_of!(hio::ReadIn, cap), 1, W, None)];
    hio::WriteIn => [counted(
        offset_of!(hio::WriteIn, bytes),
        offset_of!(hio::WriteIn, len),
        1,
        R,
        None,
    )];
    hio::ReadyIn => [];
    hio::ShutIn => [];
    hio::HandleIn => [];
    hio::SpawnIn => [
        counted(
            offset_of!(hio::SpawnIn, args),
            offset_of!(hio::SpawnIn, args_len),
            size_of::<AbiStr>(),
            R,
            None,
        ),
        counted(
            offset_of!(hio::SpawnIn, env),
            offset_of!(hio::SpawnIn, env_len),
            size_of::<Field>(),
            R,
            None,
        ),
    ];
    connector::EstablishIn => [];
    connector::StreamIn => [];
    connector::IoIn => [
        counted(
            offset_of!(connector::IoIn, buf),
            offset_of!(connector::IoIn, len),
            1,
            W,
            Some(connector::service::READ),
        ),
        counted(
            offset_of!(connector::IoIn, buf),
            offset_of!(connector::IoIn, len),
            1,
            R,
            Some(connector::service::WRITE),
        ),
    ];
    connector::UpgradeIn => [];
    connector::FactsIn => [one(
        offset_of!(connector::FactsIn, facts),
        size_of::<connector::StreamFacts>(),
        W,
    )];
    connector::CheckoutIn => [];
    connector::CheckinIn => [];
    connector::IdentityIn => [one(
        offset_of!(connector::IdentityIn, identity),
        size_of::<connector::ProcessIdentity>(),
        W,
    )];
    connector::ReplyIn => [
        counted(
            offset_of!(connector::ReplyIn, buf),
            offset_of!(connector::ReplyIn, len),
            1,
            W,
            None,
        ),
        one(
            offset_of!(connector::ReplyIn, piece),
            size_of::<connector::ReplyPiece>(),
            W,
        ),
    ];
    connector::RequestIn => [
        counted(
            offset_of!(connector::RequestIn, buf),
            offset_of!(connector::RequestIn, len),
            1,
            R,
            None,
        ),
        one(
            offset_of!(connector::RequestIn, piece),
            size_of::<connector::RequestPiece>(),
            R,
        ),
    ];
);

/// One call of a fake service: the `in` the plugin passed (a copy), and the reply being built.
#[derive(Debug)]
pub struct ServiceCall<I> {
    ctx: HostCtx,
    op: u32,
    input: I,
    reply: ServiceOut,
}

impl<I: ServiceIn> ServiceCall<I> {
    #[must_use]
    pub fn ctx(&self) -> HostCtx {
        self.ctx
    }

    #[must_use]
    pub fn input(&self) -> &I {
        &self.input
    }

    pub fn bytes(&self, field: impl FnOnce(&I) -> &AbiStr) -> &[u8] {
        let s = field(&self.input);
        self.offset(s, "an AbiStr");
        lent(s.ptr, s.len, "AbiStr")
    }

    pub fn text(&self, field: impl FnOnce(&I) -> &AbiStr) -> &str {
        let b = self.bytes(field);
        core::str::from_utf8(b).unwrap_or_else(|_| panic!("AbiStr: not UTF-8: {b:?}"))
    }

    pub fn blob(&self, field: impl FnOnce(&I) -> &Blob) -> &[u8] {
        let b = field(&self.input);
        self.offset(b, "a Blob");
        lent(b.ptr, b.len, "Blob")
    }

    pub fn lent<T: 'static, P: RawPtr<T>>(&self, field: impl FnOnce(&I) -> &P) -> &[T] {
        let p = field(&self.input);
        let at = self.offset(p, "a pointer");
        let (n, _) = self.region(at, R, size_of::<T>());
        lent(p.get(), n, "the read region")
    }

    pub fn lent_fields(&self, field: impl FnOnce(&I) -> &*const Field) -> Vec<(&[u8], &[u8])> {
        let list: &[Field] = self.lent(field);
        list.iter()
            .map(|f| {
                (
                    lent(f.name.ptr, f.name.len, "a listed field's name"),
                    lent(f.value.ptr, f.value.len, "a listed field's value"),
                )
            })
            .collect()
    }

    pub fn fill(
        &mut self,
        field: impl FnOnce(&I) -> &ServiceBufs,
        bytes: &[u8],
        spans: &[ItemSpan],
    ) -> bool {
        let into = field(&self.input);
        self.offset(into, "a ServiceBufs");
        let into = *into;
        if bytes.len() > into.cap || spans.len() > into.spans_cap {
            self.reply.needed_bytes = bytes.len() as u64;
            self.reply.needed_items = spans.len() as u64;
            return false;
        }
        if !bytes.is_empty() {
            assert!(!into.buf.is_null(), "into.buf: NULL with a capacity");
            // SAFETY: the plugin lent `cap >= bytes.len()` writable bytes at `buf` for the call.
            unsafe { ptr::copy(bytes.as_ptr(), into.buf, bytes.len()) };
        }
        if !spans.is_empty() {
            assert!(!into.spans.is_null(), "into.spans: NULL with a capacity");
            assert!(into.spans.is_aligned(), "into.spans: misaligned");
            // SAFETY: the plugin lent `spans_cap >= spans.len()` writable spans for the call.
            unsafe { ptr::copy(spans.as_ptr(), into.spans, spans.len()) };
        }
        self.reply.len = bytes.len() as u64;
        self.reply.items = spans.len() as u64;
        true
    }

    pub fn fill_lent(&mut self, field: impl FnOnce(&I) -> &*mut u8, bytes: &[u8]) -> bool {
        let p = field(&self.input);
        let at = self.offset(p, "a pointer");
        let buf = *p;
        let (cap, _) = self.region(at, W, 1);
        if bytes.len() > cap {
            self.reply.needed_bytes = bytes.len() as u64;
            return false;
        }
        if !bytes.is_empty() {
            assert!(!buf.is_null(), "the write region: NULL with a capacity");
            // SAFETY: the plugin lent `cap >= bytes.len()` writable bytes at `buf` for the call.
            unsafe { ptr::copy(bytes.as_ptr(), buf, bytes.len()) };
        }
        self.reply.len = bytes.len() as u64;
        true
    }

    pub fn put<T: Copy>(&mut self, field: impl FnOnce(&I) -> &*mut T, value: T) {
        let p = field(&self.input);
        let at = self.offset(p, "a pointer");
        let slot = *p;
        let (_, one) = self.region(at, W, size_of::<T>());
        assert!(
            one,
            "the write region names a list: write it with fill_lent"
        );
        assert!(!slot.is_null(), "the write region: NULL");
        assert!(slot.is_aligned(), "the write region: misaligned");
        // SAFETY: the plugin lent one writable `T` at `slot` for the call (the region, reviewed).
        unsafe { slot.write(value) };
    }

    pub fn set_value(&mut self, value: u64) -> &mut Self {
        self.reply.value = value;
        self
    }

    pub fn set_len(&mut self, len: u64) -> &mut Self {
        self.reply.len = len;
        self
    }

    pub fn set_error(&mut self, reason: &'static str) -> &mut Self {
        self.reply.error = AbiStr {
            ptr: reason.as_ptr(),
            len: reason.len(),
        };
        self
    }

    fn offset<F>(&self, field: &F, what: &str) -> usize {
        let base = ptr::addr_of!(self.input).addr();
        let at = ptr::from_ref(field).addr();
        assert!(
            at >= base && at - base + size_of::<F>() <= size_of::<I>(),
            "{what}: the selector names no field of this call's in"
        );
        at - base
    }

    fn region(&self, at: usize, write: bool, size: usize) -> (usize, bool) {
        let op = self.op;
        let r = I::REGIONS
            .iter()
            .find(|r| r.at == at && r.write == write && r.op.is_none_or(|o| o == op))
            .unwrap_or_else(|| {
                panic!(
                    "the field at offset {at} lends no {} region on op {op}",
                    if write { "write" } else { "read" }
                )
            });
        assert_eq!(r.size, size, "the region's entries are not this type");
        match r.count_at {
            None => (1, true),
            Some(c) => {
                // SAFETY: `c` is the offset of a `usize` field of `I` (the reviewed region), and
                // `self.input` is a whole `I`.
                let n = unsafe {
                    ptr::addr_of!(self.input)
                        .cast::<u8>()
                        .add(c)
                        .cast::<usize>()
                        .read_unaligned()
                };
                (n, false)
            }
        }
    }
}

fn lent<'a, T>(ptr: *const T, len: usize, field: &str) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    assert!(!ptr.is_null(), "{field}: NULL with a count of {len}");
    assert!(ptr.is_aligned(), "{field}: misaligned");
    assert!(
        len <= isize::MAX as usize / size_of::<T>().max(1),
        "{field}: a count of {len} overflows the address space"
    );
    // SAFETY: non-NULL, aligned and within the address space; `len` live entries for the call by
    // the service ABI.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

extern "C" fn trampoline<S: FakeService, const OP: u32>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    let ran = busbar_contract::abi::sdk::boundary::caught(|| {
        assert!(!input.is_null(), "service {OP}: the in is NULL");
        // SAFETY: a non-NULL `in` a plugin passed a host service leads with its `ServiceHead`.
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if let Err(f) = check_head(&head, OP, size_of::<S::In>()) {
            panic!("service {OP}: {f:?}");
        }
        // SAFETY: the head states this slot's op and at least `size_of::<S::In>()` bytes.
        let input = unsafe { input.cast::<S::In>().read_unaligned() };
        let mut reply: ServiceOut = zeroed();
        reply.size = size_of::<ServiceOut>() as u32;
        let mut call = ServiceCall {
            ctx,
            op: OP,
            input,
            reply,
        };
        let outcome = S::serve(&mut call);
        call.reply.outcome = RawOutcome::of(outcome);
        call.reply
    });
    let reply = ran.unwrap_or_else(|| {
        let mut fault: ServiceOut = zeroed();
        fault.size = size_of::<ServiceOut>() as u32;
        fault.outcome = RawOutcome::of(Outcome::Fault);
        fault
    });
    if !out.is_null() && out.is_aligned() {
        // SAFETY: the plugin's `out`, writable for the call.
        unsafe { out.write(reply) };
    }
    reply.outcome
}

/// A fake host: its three tables, every slot absent until a double is served in it, and the
/// `HostTables` an `OpenIn::host` names. It owns every table it lends; keep it alive while the
/// instance opened over it lives. The tables reach the door through [`FakeHost::lend_to`] alone:
/// safe code holds no table and no `ServiceFn` of it. The pairs proving both, and that what it
/// lends cannot outlive it, sit on the always-compiled `abi::sdk::door::MacroDoor`.
#[derive(Debug)]
pub struct FakeHost {
    tables: Box<HostTables>,
    services: Box<HostSlots>,
    io: Box<IoSlots>,
    conns: Box<ConnectorSlots>,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeHost {
    #[must_use]
    pub fn new() -> Self {
        let mut services: HostSlots = zeroed();
        services.size = size_of::<HostSlots>() as u32;
        services.slots = svc::SERVICES;
        let mut io: IoSlots = zeroed();
        io.size = size_of::<IoSlots>() as u32;
        io.slots = hio::SLOTS;
        let mut conns: ConnectorSlots = zeroed();
        conns.size = size_of::<ConnectorSlots>() as u32;
        conns.slots = connector::SERVICES;
        let mut host = Self {
            tables: Box::new(HostTables {
                size: size_of::<HostTables>() as u32,
                _reserved: 0,
                ctx: HostCtx::NONE,
                wake: None,
                conns: ptr::null(),
                services: ptr::null(),
                io: ptr::null(),
            }),
            services: Box::new(services),
            io: Box::new(io),
            conns: Box::new(conns),
        };
        host.link();
        host
    }

    #[must_use]
    pub fn serve<S, T, const OP: u32>(
        mut self,
        _slot: ServiceSlot<T, S::In, OP>,
        _double: S,
    ) -> Self
    where
        S: FakeService,
        T: ServiceTable,
    {
        T::of(&mut self).install(OP, trampoline::<S, OP>);
        self.link();
        self
    }

    #[must_use]
    pub fn far(mut self) -> Self {
        self.conns.establish = Some(super::far::establish);
        self.conns.write_request = Some(super::far::write_request);
        self.conns.read_reply = Some(super::far::read_reply);
        self.conns.close = Some(super::far::close);
        self.link();
        self
    }

    #[must_use]
    pub fn ctx(mut self, ctx: HostCtx) -> Self {
        self.tables.ctx = ctx;
        self
    }

    #[must_use]
    pub fn wake(mut self, wake: WakeFn) -> Self {
        self.tables.wake = Some(wake);
        self
    }

    pub fn lend_to<I: TakesHost>(&self, mut input: I) -> LentIn<'_, I> {
        *input.host_field(sealed::HostToken(())) = ptr::from_ref(&*self.tables);
        LentIn {
            input,
            _held: Vec::new(),
            host: PhantomData,
        }
    }

    pub fn lend_in<'h, I: TakesHost + super::AllZero>(
        &'h self,
        input: super::test_in::TestIn<'h, I>,
    ) -> LentIn<'h, I> {
        input.check();
        let super::test_in::TestIn {
            mut input, held, ..
        } = input;
        *input.host_field(sealed::HostToken(())) = ptr::from_ref(&*self.tables);
        LentIn {
            input,
            _held: held,
            host: PhantomData,
        }
    }

    pub fn lent(&self) -> busbar_contract::abi::sdk::Lent<'_, HostTables> {
        // SAFETY: the tables are this host's own, every pointer in them one of its own boxed
        // tables, all alive and unmoved while `self` is borrowed (`link` points them only when
        // `self` is owned mutably).
        unsafe { busbar_contract::abi::sdk::test_support::lend(&*self.tables) }
    }

    /// The tables, for this crate's own tests of the trampoline (a malformed `in` no SDK path
    /// sends, and the SDK's `Services` over the fake).
    #[cfg(test)]
    #[doc(hidden)]
    pub fn tables_for_tests(&self) -> &HostTables {
        &self.tables
    }

    /// The three tables as served, for this crate's own tests that hand the trampoline a malformed
    /// `in` (no SDK path sends one).
    #[cfg(test)]
    #[doc(hidden)]
    pub fn slots_for_tests(&self) -> (&HostSlots, &IoSlots, &ConnectorSlots) {
        (&self.services, &self.io, &self.conns)
    }

    fn link(&mut self) {
        self.tables.services = ptr::from_ref(&*self.services);
        self.tables.io = ptr::from_ref(&*self.io);
        self.tables.conns = ptr::from_ref(&*self.conns);
    }
}
