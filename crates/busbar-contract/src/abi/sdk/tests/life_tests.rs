// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The generic lifecycle through the real trampoline: one door built with `lifecycle: life(L)`,
//! every slot answering what [`Life`] states, leases held until `release` and an unknown lease
//! REFUSED, the refresh metric riding the envelope, a failure's owned text and a body's envelope
//! kept by THE INSTANCE THAT ANSWERED (never by the thread: two instances interleaved on one thread
//! each read their own), and an instance-less failure's text written into the host's lent reason
//! buffer.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET,
    FLAG_RESUME, METRIC_ADD,
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
        if let Some(why) = settings.strip_prefix(b"worded:") {
            // An owned text, as a 1.5.5 plugin's words often are.
            return Err(Refusal::failed(format!(
                "echo: invalid settings: {}",
                String::from_utf8_lossy(why)
            )));
        }
        settings_object(settings).map(|_| ())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        if settings == b"refuse" {
            return Err(Refusal::refused("the echo refuses"));
        }
        if let Some(why) = settings.strip_prefix(b"boom:") {
            return Err(Refusal::failed(format!(
                "echo open failed:{}",
                String::from_utf8_lossy(why)
            )));
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
        if h.life().0.starts_with(b"probe:") {
            // The per-instance probe: a metric counting this instance's name, then a failure
            // saying it, both in memory the SDK allocated for this answer.
            let name = String::from_utf8_lossy(&h.life().0).into_owned();
            let n = u32::try_from(name.len()).unwrap_or(u32::MAX);
            assert!(out.metric(n, METRIC_ADD, f64::from(n)));
            return out.fail(Refusal::failed(format!(
                "{name} failed, in words its own instance keeps"
            )));
        }
        if h.life().0 == b"str" {
            // The leased-string probe: the answer's text, held under `head.lease`.
            out.lease_str(|o| &o.head.error, h.leases(), "a leased answer".to_string());
            return Outcome::Ready;
        }
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
    // SAFETY: the plugin's error text: its instance's, or the lent buffer the test still holds.
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

/// RED: a leased string outlives the call and a refresh generation, and lives until its release;
/// a second release of it is REFUSED (its storage is gone).
#[test]
fn a_leased_string_is_read_back_across_a_refresh_generation_until_its_release() {
    let (_, inst, _) = open(b"str", &[]);
    let mut input: ResolveIn = zeroed();
    input.head = in_head::<ResolveIn>(crate::abi::secret::slot::RESOLVE);
    let mut out: ResolveOut = zeroed();
    out.head = out_head::<ResolveOut>();
    assert_eq!(
        call(table().resolve, inst, &input, &mut out),
        Outcome::Ready
    );
    let (lease, said) = (out.head.lease, out.head.error);
    assert_ne!(lease, 0, "the string is leased");
    assert_eq!(refresh(inst, b"{}").0, Outcome::Ready);
    let _churn: Vec<Vec<u8>> = (0..64).map(|i| vec![0xAA; 15 + i]).collect();
    assert_eq!(
        text(said),
        "a leased answer",
        "held across the refresh generation"
    );
    assert_eq!(release(inst, lease), Outcome::Ready);
    assert_eq!(
        release(inst, lease),
        Outcome::Refused,
        "released: nothing is held there"
    );
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

/// `resolve` on the probe instance `inst`: its outcome and its `out`.
fn probe(inst: *mut c_void) -> (Outcome, ResolveOut) {
    let mut input: ResolveIn = zeroed();
    input.head = in_head::<ResolveIn>(crate::abi::secret::slot::RESOLVE);
    let mut out: ResolveOut = zeroed();
    out.head = out_head::<ResolveOut>();
    let o = call(table().resolve, inst, &input, &mut out);
    (o, out)
}

/// The metrics an answer's envelope names.
fn metrics(out: &ResolveOut) -> Vec<(u32, f64)> {
    let env = out.head.envelope;
    if env.metrics.is_null() {
        return Vec::new();
    }
    // SAFETY: the envelope the answering instance keeps (until KEPT_RING newer ones).
    unsafe { std::slice::from_raw_parts(env.metrics, env.metrics_len) }
        .iter()
        .map(|m| (m.family_idx, m.value))
        .collect()
}

/// RED on a per-thread slot: TWO INSTANCES OF ONE PLUGIN, INTERLEAVED ON ONE THREAD, each read
/// their own answer after the other has answered. A per-thread envelope is emptied and refilled
/// by the second call, so the first answer's metrics would name the second instance's; a
/// per-thread error slot would free the first text when the second failure replaced it.
#[test]
fn red_two_instances_interleaved_on_one_thread_never_see_each_others_answers() {
    let (_, alpha, _) = open(b"probe:alpha", &[]);
    let (_, bravo, _) = open(b"probe:bravo-bravo", &[]);
    let (oa, a) = probe(alpha);
    let (ob, b) = probe(bravo);
    let (oa2, a2) = probe(alpha);
    assert_eq!(
        (oa, ob, oa2),
        (Outcome::Failed, Outcome::Failed, Outcome::Failed)
    );
    // The envelopes first: reading them is sound whatever holds them.
    assert_eq!(
        metrics(&a),
        vec![(11, 11.0)],
        "alpha's envelope names alpha's metric"
    );
    assert_eq!(
        metrics(&b),
        vec![(17, 17.0)],
        "bravo's envelope names bravo's metric"
    );
    assert_eq!(metrics(&a2), vec![(11, 11.0)]);
    assert_ne!(
        a.head.envelope.metrics, b.head.envelope.metrics,
        "one envelope each"
    );
    // Then the texts: each held by its own instance.
    assert_eq!(
        text(a.head.error),
        "probe:alpha failed, in words its own instance keeps"
    );
    assert_eq!(
        text(b.head.error),
        "probe:bravo-bravo failed, in words its own instance keeps"
    );
    assert_eq!(text(a2.head.error), text(a.head.error));
    assert_ne!(
        a.head.error.ptr, a2.head.error.ptr,
        "each answer keeps its own text"
    );
    // Closing one instance leaves the other's answers readable.
    assert_eq!(close(alpha), Outcome::Ready);
    assert_eq!(metrics(&b), vec![(17, 17.0)]);
    assert_eq!(
        text(b.head.error),
        "probe:bravo-bravo failed, in words its own instance keeps"
    );
    assert_eq!(close(bravo), Outcome::Ready);
}

/// `validate` through the door with the host's reason buffer `buf` lent (`None`: none lent).
fn validate_lent(settings: &[u8], buf: Option<&mut [u8]>) -> (Outcome, OutHead) {
    let mut input: ValidateIn = zeroed();
    input.head = in_head::<ValidateIn>(slot::VALIDATE);
    input.settings = blob(settings);
    if let Some(b) = buf {
        input.err_buf = b.as_mut_ptr();
        input.err_cap = b.len();
    }
    let mut out = out_head::<OutHead>();
    let o = call(table().head.validate, ptr::null_mut(), &input, &mut out);
    (o, out)
}

/// `open` through the door with the host's reason buffer `buf` lent (`None`: none lent).
fn open_lent(settings: &[u8], buf: Option<&mut [u8]>) -> (Outcome, OpenOut) {
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.settings = blob(settings);
    input.generation = 1;
    if let Some(b) = buf {
        input.err_buf = b.as_mut_ptr();
        input.err_cap = b.len();
    }
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    let o = call(table().head.open, ptr::null_mut(), &input, &mut out);
    (o, out)
}

/// An instance-less failure (`validate`, a failed `open`) has no instance to keep an owned text:
/// it goes into the reason buffer the host lent the call, cut on a char boundary to its capacity
/// (`open` states the length in `err_len`), byte for byte the plugin's words. Only when the host
/// lent no buffer is the fixed text answered.
#[test]
fn an_instance_less_owned_text_rides_the_hosts_lent_buffer_and_only_else_a_fixed_text() {
    let mut vbuf = [0_u8; 64];
    let (o, out) = validate_lent(b"worded:no port", Some(&mut vbuf[..]));
    assert_eq!(o, Outcome::Failed);
    assert_eq!(text(out.error), "echo: invalid settings: no port");
    assert_eq!(
        out.error.ptr,
        vbuf.as_ptr(),
        "named inside the host's buffer"
    );
    assert_eq!(&vbuf[..out.error.len], b"echo: invalid settings: no port");

    let mut obuf = [0_u8; 64];
    let (o, out) = open_lent(b"boom: x", Some(&mut obuf[..]));
    assert_eq!(o, Outcome::Failed);
    assert!(out.instance.is_null());
    assert_eq!(&obuf[..out.err_len], b"echo open failed: x");
    assert_eq!(text(out.head.error), "echo open failed: x");

    // Cut to the capacity on a char boundary: `é` is two bytes and the cut falls inside one.
    let mut small = [0_u8; 19];
    let (_, out) = open_lent("boom: é".as_bytes(), Some(&mut small[..]));
    assert_eq!(out.err_len, 18);
    assert_eq!(&small[..18], b"echo open failed: ");
    assert_eq!(small[18], 0, "nothing past the cut is written");

    // No buffer lent: the fixed text, for both.
    let (o, out) = validate_lent(b"worded:x", None);
    assert_eq!(o, Outcome::Failed);
    assert_eq!(text(out.error), crate::abi::sdk::out::NO_REASON_BUFFER);
    let (o, out) = open_lent(b"boom: x", None);
    assert_eq!(o, Outcome::Failed);
    assert_eq!(out.err_len, 0);
    assert_eq!(text(out.head.error), crate::abi::sdk::out::NO_REASON_BUFFER);

    // A 'static text is named where it lives, buffer or not.
    let (o, out) = validate_lent(b"[1]", Some(&mut vbuf[..]));
    assert_eq!(o, Outcome::Failed);
    assert_eq!(text(out.error), "settings: must be a JSON object");
    assert_ne!(out.error.ptr, vbuf.as_ptr());
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
