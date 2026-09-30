// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The generic lifecycle through the real trampoline: one door built with `lifecycle: life(L)`,
//! every slot answering what [`Life`] states, leases held until `release` and an unknown lease
//! REFUSED, the refresh metric riding the envelope, and a failure's text living until the thread's
//! next failure.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET,
    FLAG_RESUME,
};
use crate::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};
use crate::abi::secret::{ResolveIn, ResolveOut};

use super::*;

/// The disposition this test kind states for `cancel`.
const DISPOSITION: u32 = 3;
/// Generations retired, summed.
static RETIRED: AtomicU64 = AtomicU64::new(0);

/// The test kind's state: the bytes `resolve` answers.
struct Echo(Vec<u8>);

impl Life for Echo {
    const CANCEL: u32 = DISPOSITION;
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_object(settings).map(|_| ())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        if settings == b"refuse" {
            return Err(Refusal::refused("the echo refuses"));
        }
        Ok(Echo(secrets.first().map_or(settings, |s| *s).to_vec()))
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        match settings {
            b"count" => Ok(Refreshed {
                counted: Some(Counted {
                    family: 2,
                    value: 9.0,
                }),
            }),
            b"fail" => Err(Refusal::failed(format!("refresh failed: {}", 7))),
            _ => Ok(Refreshed::default()),
        }
    }

    fn retire(&self, generation: u64) {
        RETIRED.fetch_add(generation, Ordering::SeqCst);
    }

    fn tick(&self, now_ns: u64) -> u64 {
        now_ns + self.0.len() as u64
    }
}

/// `resolve`: the state's bytes, under a secret lease.
struct Resolve;
impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Echo>;
    fn call(
        i: Instance<'_, Held<Echo>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(h) = i.get() else {
            return Outcome::Fault;
        };
        if h.life().0 == b"park" {
            // The parking probe, answering in `error_kind`. With no ticket: how many tickets hold
            // parked state. In a RESUME: whether its op's `u64` came back (another type never
            // does: FAULT if it did). Fresh on a ticket, by `deadline_class`: park and pend (0),
            // park and FAIL (1), or pend having parked nothing (2).
            if input.head.ticket.is_none() {
                out.set(|o| &o.error_kind, i.parked_count() as u32);
                return Outcome::Ready;
            }
            if input.head.flags & FLAG_RESUME != 0 {
                if i.resume::<String>().is_some() {
                    return Outcome::Fault;
                }
                let found = i.resume::<u64>().map_or(0, |b| *b);
                out.set(|o| &o.error_kind, u32::try_from(found).unwrap_or(0));
                return Outcome::Ready;
            }
            return match input.head.deadline_class {
                0 => {
                    i.park(7_u64);
                    Outcome::Pending
                }
                1 => {
                    i.park(7_u64);
                    Outcome::Failed
                }
                _ => Outcome::Pending,
            };
        }
        out.lease_secret(|o| &o.secret, h.leases(), h.life().0.clone(), BLOB_OCTETS);
        Outcome::Ready
    }
}

mod plugin {
    use super::*;
    crate::plugin_door! {
        ops: crate::abi::secret::Ops,
        statement: crate::abi::sdk::door::statement("life-echo", "0", 4),
        lifecycle: life(Echo),
        kind_ops: { resolve: crate::abi::sdk::Safe<Resolve> },
    }
}

fn table() -> &'static crate::abi::secret::Ops {
    // SAFETY: the macro's `'static` door and table.
    unsafe { &*(*plugin::door()).ops.cast::<crate::abi::secret::Ops>() }
}

fn in_head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: blob(b""),
    }
}

fn blob(b: &[u8]) -> Blob {
    Blob {
        ptr: if b.is_empty() {
            ptr::null()
        } else {
            b.as_ptr()
        },
        len: b.len(),
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

fn zeroed<T>() -> T {
    // SAFETY: every `in`/`out` here is plain data; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn out_head<T>() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = size_of::<T>() as u32;
    h.outcome = RawOutcome::of(Outcome::Fault);
    h
}

fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    op.expect("every slot is filled")(
        instance,
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

fn text(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the plugin's error text, live until this thread's next failure.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn open(settings: &[u8], secrets: &[Blob]) -> (Outcome, *mut c_void, String) {
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.settings = blob(settings);
    input.secrets = if secrets.is_empty() {
        ptr::null()
    } else {
        secrets.as_ptr()
    };
    input.secrets_len = secrets.len();
    input.generation = 1;
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    let o = call(table().head.open, ptr::null_mut(), &input, &mut out);
    (o, out.instance, text(out.head.error))
}

fn resolve(inst: *mut c_void) -> (Outcome, Vec<u8>, u64, u32) {
    let mut input: ResolveIn = zeroed();
    input.head = in_head::<ResolveIn>(crate::abi::secret::slot::RESOLVE);
    let mut out: ResolveOut = zeroed();
    out.head = out_head::<ResolveOut>();
    let o = call(table().resolve, inst, &input, &mut out);
    // SAFETY: the plugin's leased bytes, held until `release`.
    let bytes = unsafe { std::slice::from_raw_parts(out.secret.ptr, out.secret.len) }.to_vec();
    (o, bytes, out.head.lease, out.secret.flags)
}

fn release(inst: *mut c_void, lease: u64) -> Outcome {
    let mut input: ReleaseIn = zeroed();
    input.head = in_head::<ReleaseIn>(slot::RELEASE);
    input.lease = lease;
    let mut out = out_head::<OutHead>();
    call(table().head.release, inst, &input, &mut out)
}

fn refresh(inst: *mut c_void, settings: &[u8]) -> (Outcome, OutHead) {
    let mut input: RefreshIn = zeroed();
    input.head = in_head::<RefreshIn>(slot::REFRESH);
    input.settings = blob(settings);
    input.generation = 2;
    let mut out = out_head::<OutHead>();
    let o = call(table().head.refresh, inst, &input, &mut out);
    (o, out)
}

fn close(inst: *mut c_void) -> Outcome {
    let input = in_head::<InHead>(slot::CLOSE);
    let mut out = out_head::<OutHead>();
    call(table().head.close, inst, &input, &mut out)
}

#[test]
fn validate_answers_what_the_kind_states_with_its_text() {
    let mut input: ValidateIn = zeroed();
    input.head = in_head::<ValidateIn>(slot::VALIDATE);
    input.settings = blob(b"[1]");
    let mut out = out_head::<OutHead>();
    assert_eq!(
        call(table().head.validate, ptr::null_mut(), &input, &mut out),
        Outcome::Failed
    );
    assert_eq!(text(out.error), "settings: must be a JSON object");
    input.settings = blob(b"");
    let mut out = out_head::<OutHead>();
    assert_eq!(
        call(table().head.validate, ptr::null_mut(), &input, &mut out),
        Outcome::Ready,
        "empty settings are {{}}"
    );
}

#[test]
fn open_holds_the_kinds_state_and_a_refused_open_answers_its_text() {
    let (o, inst, _) = open(b"abc", &[]);
    assert_eq!(o, Outcome::Ready);
    assert!(!inst.is_null());
    assert_eq!(close(inst), Outcome::Ready);
    let (o, inst, why) = open(b"refuse", &[]);
    assert_eq!(o, Outcome::Refused);
    assert!(inst.is_null());
    assert_eq!(why, "the echo refuses");
}

#[test]
fn every_lifecycle_slot_answers_the_kinds_value() {
    let (_, inst, _) = open(b"abcd", &[]);
    // tick
    let mut ti: TickIn = zeroed();
    ti.head = in_head::<TickIn>(slot::TICK);
    ti.now_ns = 100;
    let mut to: TickOut = zeroed();
    to.head = out_head::<TickOut>();
    assert_eq!(call(table().head.tick, inst, &ti, &mut to), Outcome::Ready);
    assert_eq!(to.next_tick_ns, 104);
    // retire
    let mut gi: GenIn = zeroed();
    gi.head = in_head::<GenIn>(slot::RETIRE);
    gi.generation = 5;
    let before = RETIRED.load(Ordering::SeqCst);
    let mut go = out_head::<OutHead>();
    assert_eq!(
        call(table().head.retire, inst, &gi, &mut go),
        Outcome::Ready
    );
    assert_eq!(RETIRED.load(Ordering::SeqCst) - before, 5);
    // drive: the kind's value
    let mut di: DriveIn = zeroed();
    di.head = in_head::<DriveIn>(slot::DRIVE);
    let mut dout = out_head::<OutHead>();
    assert_eq!(
        call(table().head.drive, inst, &di, &mut dout),
        Outcome::Refused
    );
    // cancel: the kind's disposition
    let mut ci: CancelIn = zeroed();
    ci.head = in_head::<CancelIn>(slot::CANCEL);
    let mut co: CancelOut = zeroed();
    co.head = out_head::<CancelOut>();
    assert_eq!(
        call(table().head.cancel, inst, &ci, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.disposition, DISPOSITION);
    assert_eq!(close(inst), Outcome::Ready);
}

#[test]
fn a_leased_answer_is_held_until_release_and_an_unknown_lease_is_refused() {
    let secret = blob(b"s3cret");
    let (_, inst, _) = open(b"{}", &[secret]);
    let (o, bytes, lease, flags) = resolve(inst);
    assert_eq!(o, Outcome::Ready);
    assert_eq!(bytes, b"s3cret");
    assert_ne!(lease, 0);
    assert_eq!(flags, BLOB_SECRET);
    let (_, _, second, _) = resolve(inst);
    assert_ne!(second, lease, "each answer its own lease");
    assert_eq!(release(inst, lease), Outcome::Ready);
    assert_eq!(release(inst, lease), Outcome::Refused, "released twice");
    assert_eq!(release(inst, 999), Outcome::Refused, "never leased");
    assert_eq!(release(inst, second), Outcome::Ready);
    assert_eq!(close(inst), Outcome::Ready);
}

#[test]
fn a_refresh_reports_its_count_in_the_envelope_or_fails_with_its_text() {
    let (_, inst, _) = open(b"{}", &[]);
    let (o, out) = refresh(inst, b"count");
    assert_eq!(o, Outcome::Ready);
    assert_eq!(out.envelope.metrics_len, 1);
    // SAFETY: the instance holds the entry until its next lifecycle op.
    let m = unsafe { &*out.envelope.metrics };
    assert_eq!((m.family_idx, m.value), (2, 9.0));
    let (o, out) = refresh(inst, b"uncounted");
    assert_eq!(o, Outcome::Ready);
    assert_eq!(out.envelope.metrics_len, 0);
    let (o, out) = refresh(inst, b"fail");
    assert_eq!(o, Outcome::Failed);
    assert_eq!(text(out.error), "refresh failed: 7");
    assert_eq!(close(inst), Outcome::Ready);
}

#[test]
fn a_failure_text_lives_until_the_threads_next_failure() {
    let mut first = out_head::<OutHead>();
    assert_eq!(
        fail(&mut first, Refusal::failed(String::from("one"))),
        Outcome::Failed
    );
    assert_eq!(text(first.error), "one");
    let mut stat = out_head::<OutHead>();
    assert_eq!(
        fail(&mut stat, Refusal::refused("static")),
        Outcome::Refused
    );
    assert_eq!(text(stat.error), "static");
    assert_eq!(
        text(first.error),
        "one",
        "a static text leaves the slot alone"
    );
    let mut bare = out_head::<OutHead>();
    assert_eq!(fail(&mut bare, Refusal::bare()), Outcome::Refused);
    assert!(bare.error.ptr.is_null());
}

#[test]
fn leases_are_instance_state() {
    fn state<T: Send + Sync + 'static>() {}
    state::<Held<Echo>>();
    let l = Leases::default();
    let mut h = out_head::<OutHead>();
    assert_eq!(l.blob(&mut h, Vec::new(), BLOB_OCTETS).fmt, BLOB_ABSENT);
    assert_eq!(h.lease, 0, "nothing leased for nothing");
    assert_eq!(l.held(), 0);
}

#[test]
fn a_kept_answer_is_dropped_at_its_release_and_only_then() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    struct Storage(Arc<AtomicUsize>, #[allow(dead_code)] Vec<Box<[u8]>>);
    impl Drop for Storage {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let leases = Leases::default();
    let mut head = out_head::<OutHead>();
    let lease = leases.keep(
        &mut head,
        Storage(drops.clone(), vec![b"a".to_vec().into()]),
    );
    assert_eq!(head.lease, lease);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "held until release");
    assert_eq!(leases.release(lease), Outcome::Ready);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "dropped at release");
    assert_eq!(leases.release(lease), Outcome::Refused);
}

/// A kind that states no `validate` of its own: the SDK's object check, in the SDK's words.
struct Defaulted;
impl Life for Defaulted {
    const CANCEL: u32 = 0;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Defaulted)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// A kind whose plugin answers its own refusal text (a 1.5.5 plugin's words).
struct Worded;
impl Life for Worded {
    const CANCEL: u32 = 0;
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_object(settings)
            .map(|_| ())
            .map_err(|_| Refusal::failed("worded-hook: invalid plugin config: expected an object"))
    }
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Worded)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

#[test]
fn validate_defaults_to_the_object_check_and_a_kind_may_answer_its_own_words() {
    assert_eq!(<Defaulted as Life>::validate(b"{}"), Ok(()));
    assert_eq!(<Defaulted as Life>::validate(b""), Ok(()));
    let refused = <Defaulted as Life>::validate(b"[1]").expect_err("not an object");
    assert_eq!(refused.text(), Some("settings: must be a JSON object"));
    let worded = <Worded as Life>::validate(b"7").expect_err("not an object");
    assert_eq!(
        worded.text(),
        Some("worded-hook: invalid plugin config: expected an object")
    );
    assert_eq!(worded.outcome(), Outcome::Failed);
}

fn resolve_on(inst: *mut c_void, ticket: Ticket) -> (Outcome, u32) {
    resolve_as(inst, ticket, 0, 0)
}

/// `resolve` on `ticket` with `flags` and the probe's mode in `deadline_class`.
fn resolve_as(inst: *mut c_void, ticket: Ticket, flags: u32, mode: u8) -> (Outcome, u32) {
    let mut input: ResolveIn = zeroed();
    input.head = in_head::<ResolveIn>(crate::abi::secret::slot::RESOLVE);
    input.head.ticket = ticket;
    input.head.flags = flags;
    input.head.deadline_class = mode;
    let mut out: ResolveOut = zeroed();
    out.head = out_head::<ResolveOut>();
    let o = call(table().resolve, inst, &input, &mut out);
    (o, out.error_kind)
}

#[test]
fn state_parked_on_a_ticket_is_dropped_by_its_cancel() {
    let parked = Ticket {
        slot: 9,
        generation: 1,
    };
    let (_, inst, _) = open(b"park", &[]);
    assert_eq!(resolve_on(inst, parked).0, Outcome::Pending);
    assert_eq!(resolve_on(inst, Ticket::NONE), (Outcome::Ready, 1));
    let mut ci: CancelIn = zeroed();
    ci.head = in_head::<CancelIn>(slot::CANCEL);
    ci.ticket = parked;
    let mut co: CancelOut = zeroed();
    co.head = out_head::<CancelOut>();
    assert_eq!(
        call(table().head.cancel, inst, &ci, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.disposition, DISPOSITION);
    assert_eq!(
        resolve_on(inst, Ticket::NONE),
        (Outcome::Ready, 0),
        "the cancel dropped it"
    );
    assert_eq!(close(inst), Outcome::Ready);
}

#[test]
fn a_pending_op_resumes_what_it_parked_and_only_its_own_type() {
    let t = Ticket {
        slot: 4,
        generation: 1,
    };
    let (_, inst, _) = open(b"park", &[]);
    assert_eq!(resolve_as(inst, t, 0, 0).0, Outcome::Pending);
    assert_eq!(
        resolve_as(inst, t, FLAG_RESUME, 0),
        (Outcome::Ready, 7),
        "the RESUME takes back its own u64 (a String ask is None and leaves it)"
    );
    assert_eq!(resolve_on(inst, Ticket::NONE), (Outcome::Ready, 0));
    assert_eq!(close(inst), Outcome::Ready);
}

/// REVIEWER's MEDIUM: what an op parked must never reach the next op on its ticket once the op is
/// over. Each arm goes RED with its clear removed from `Safe::enter`.
#[test]
fn a_recycled_ticket_never_resumes_a_finished_ops_parked_state() {
    let t = Ticket {
        slot: 5,
        generation: 3,
    };
    let (_, inst, _) = open(b"park", &[]);
    // Parked, then a FAILED answer: the op is over, so the SDK drops it with the answer.
    assert_eq!(resolve_as(inst, t, 0, 1).0, Outcome::Failed);
    assert_eq!(
        resolve_on(inst, Ticket::NONE),
        (Outcome::Ready, 0),
        "a terminal answer drops what its op parked"
    );
    assert_eq!(
        resolve_as(inst, t, FLAG_RESUME, 0),
        (Outcome::Ready, 0),
        "the next op's RESUME on the ticket must not see the failed op's state"
    );
    // Parked and pending, then a fresh (non-RESUME) op on the same ticket, the recycled ticket's
    // next request: it drops the old state on entry, so its own RESUME finds nothing.
    assert_eq!(resolve_as(inst, t, 0, 0).0, Outcome::Pending);
    assert_eq!(resolve_on(inst, Ticket::NONE), (Outcome::Ready, 1));
    assert_eq!(resolve_as(inst, t, 0, 2).0, Outcome::Pending);
    assert_eq!(
        resolve_on(inst, Ticket::NONE),
        (Outcome::Ready, 0),
        "a fresh entry drops what an earlier op parked on its ticket"
    );
    assert_eq!(
        resolve_as(inst, t, FLAG_RESUME, 0),
        (Outcome::Ready, 0),
        "the new op's RESUME must not see the earlier op's state"
    );
    assert_eq!(close(inst), Outcome::Ready);
}
