// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host services (`BUSBAR-1.6.0.md` THE DESIGN, §11.12) through the table an instance is
//! handed, over a kind-neutral test double: a route that records its wakes and a provider with a
//! fixed clock and a `dest.judge` that answers a scripted verdict at once, or pends until the test
//! answers it by hand. The judgement itself is the kernel's and is tested there.

use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::host::service::{
    check_clock_now, check_dest_judge, EntitlementCheckIn, ItemSpan, DEST_INTERNAL, DEST_METADATA,
    DEST_RESOLVE,
};
use busbar_contract::abi::mechanism::check::Filled;

use super::*;

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 9,
};

/// The provider half of the double: `dest.judge` answers [`DEST_METADATA`] at once for a
/// destination starting `now:`, and otherwise pends, holding its [`Later`] for the test.
#[derive(Default)]
struct Provider {
    judged: AtomicUsize,
    held: Mutex<Vec<Later>>,
    /// Every caller-scoped call, as `(instance, service, first argument)`.
    scoped: Mutex<Vec<(String, &'static str, Vec<u8>)>>,
}

impl Provider {
    fn saw(&self, c: &Caller, what: &'static str, arg: &[u8]) {
        self.scoped
            .lock()
            .unwrap()
            .push((c.instance.to_string(), what, arg.to_vec()));
    }
}

impl HostServices for Provider {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 1_700_000_000_000_000_000,
            mono_ns: 42,
        }
    }

    fn dest_judge(&self, dest: &str, _class: u32, _resolve: bool, later: Option<Later>) -> Ran {
        self.judged.fetch_add(1, Ordering::SeqCst);
        if dest.starts_with("now:") {
            return Ran::Now(Stored::ready(DEST_METADATA));
        }
        match later {
            Some(l) => {
                self.held.lock().unwrap().push(l);
                Ran::Later
            }
            None => Ran::Now(Stored::refused("no ticket")),
        }
    }

    fn records_get(&self, c: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        self.saw(c, "records.get", kind.as_bytes());
        let mut stored = Stored::ready(svc::FOUND);
        stored.bytes = [key, b"=v"].concat();
        stored.spans = vec![ItemSpan {
            key_off: 0,
            key_len: key.len() as u32,
            value_off: key.len() as u32,
            value_len: 2,
        }];
        later(stored);
        Ran::Later
    }

    fn records_claim(&self, c: &Caller, kind: &str, _key: &[u8], ttl: u64, _l: Later) -> Ran {
        self.saw(c, "records.claim", kind.as_bytes());
        Ran::Now(Stored::ready(if ttl == 1 {
            svc::CLAIM_WON
        } else {
            svc::CLAIM_TAKEN
        }))
    }

    fn sign(&self, c: &Caller, data: &[u8]) -> Stored {
        self.saw(c, "sign", data);
        Stored::ready(0)
    }

    fn trust_due(&self, c: &Caller) -> Stored {
        self.saw(c, "trust.due", b"");
        Stored::ready(0)
    }
}

/// The route half: records every wake.
struct Route {
    store: Arc<ServiceStore>,
    provider: Arc<Provider>,
    wakes: Mutex<Vec<Ticket>>,
}

impl WakeRoute for Route {
    fn wake(&self, t: Ticket) {
        self.wakes.lock().unwrap().push(t);
    }

    fn services(&self) -> Option<Served> {
        Some(Served {
            store: Arc::clone(&self.store),
            provider: self.provider.clone(),
        })
    }
}

struct Double {
    route: Arc<Route>,
    ctx: HostCtx,
}

fn double() -> Double {
    let route = Arc::new(Route {
        store: Arc::default(),
        provider: Arc::default(),
        wakes: Mutex::default(),
    });
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let dyn_route: Arc<dyn WakeRoute> = route.clone();
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    assert!(wake
        .caller
        .set(Caller {
            instance: Arc::from("double"),
            plugin: Arc::from("double-plugin"),
            kind: busbar_contract::abi::mechanism::KindCode::Plane,
        })
        .is_ok());
    Double {
        route,
        ctx: HostCtx {
            ptr: std::ptr::from_ref(wake).cast_mut().cast(),
        },
    }
}

fn head(service: u32, ticket: Ticket, seq: u32, size: usize) -> ServiceHead {
    ServiceHead {
        size: size as u32,
        op: service,
        handle: CompletionHandle {
            ticket,
            seq,
            _reserved: 0,
        },
    }
}

fn blank() -> ServiceOut {
    // SAFETY: every field of `ServiceOut` is valid zeroed.
    unsafe { std::mem::zeroed() }
}

fn judge_in(dest: &'static str, ticket: Ticket, seq: u32, flags: u32) -> DestJudgeIn {
    DestJudgeIn {
        head: head(op::DEST_JUDGE, ticket, seq, size_of::<DestJudgeIn>()),
        dest: AbiStr {
            ptr: dest.as_ptr(),
            len: dest.len(),
        },
        egress_class: 0,
        flags,
    }
}

fn call_judge(d: &Double, i: &DestJudgeIn) -> (RawOutcome, ServiceOut) {
    let mut o = blank();
    let f = HOST_SLOTS.dest_judge.unwrap();
    let ret = f(d.ctx, std::ptr::from_ref(i).cast(), &mut o);
    (ret, o)
}

fn error(o: &ServiceOut) -> &'static str {
    // SAFETY: the host's error texts are `'static`.
    let bytes = unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) };
    Box::leak(String::from_utf8(bytes.to_vec()).unwrap().into_boxed_str())
}

#[test]
fn clock_now_reads_the_one_clock_without_a_ticket() {
    let d = double();
    let mut reading = ClockReading {
        size: 0,
        _reserved: 0,
        wall_ns: 0,
        mono_ns: 0,
    };
    let i = ClockNowIn {
        head: head(op::CLOCK_NOW, Ticket::NONE, 0, size_of::<ClockNowIn>()),
        reading: &mut reading,
    };
    let mut o = blank();
    let ret = HOST_SLOTS.clock_now.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(check_clock_now(&i, ret, &o), Ok(Filled::Written));
    assert_eq!(
        (reading.wall_ns, reading.mono_ns),
        (1_700_000_000_000_000_000, 42)
    );
}

/// A service that may pend, called with no ticket (a pure op's call), is REFUSED and never
/// runs, for every may-pend service in the table.
#[test]
fn a_may_pend_service_from_a_ticketless_op_is_refused() {
    let d = double();
    let (ret, o) = call_judge(
        &d,
        &judge_in("https://api.example.com/", Ticket::NONE, 0, DEST_RESOLVE),
    );
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), UNTICKETED);
    assert_eq!(d.route.provider.judged.load(Ordering::SeqCst), 0);
    assert!(check_dest_judge(&judge_in("", Ticket::NONE, 0, 0), ret, &o).is_ok());

    let slots = [
        HOST_SLOTS.clock_now,
        HOST_SLOTS.records_get,
        HOST_SLOTS.records_list,
        HOST_SLOTS.records_claim,
        HOST_SLOTS.dest_judge,
        HOST_SLOTS.sign,
        HOST_SLOTS.unit_nest,
        HOST_SLOTS.work_open,
        HOST_SLOTS.work_find,
        HOST_SLOTS.work_settle,
        HOST_SLOTS.work_resume,
        HOST_SLOTS.trust_sight,
        HOST_SLOTS.trust_due,
        HOST_SLOTS.verify_lookup,
        HOST_SLOTS.verify_store,
        HOST_SLOTS.entitlement_check,
        HOST_SLOTS.content_scan,
        HOST_SLOTS.hook_call,
    ];
    assert_eq!(slots.len(), SERVICES as usize);
    for (service, f) in (0..SERVICES).zip(slots) {
        // The largest `in` in the table, all zero past its head: every `in` fits it.
        let mut raw = [0u64; 32];
        let h = head(service, Ticket::NONE, 0, size_of_val(&raw));
        // SAFETY: the head fits the buffer's start.
        unsafe { raw.as_mut_ptr().cast::<ServiceHead>().write_unaligned(h) };
        let mut o = blank();
        let ret = f.unwrap()(d.ctx, raw.as_ptr().cast(), &mut o);
        if may_pend(service) {
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), UNTICKETED, "service {service}");
        } else if !matches!(service, op::CLOCK_NOW | op::SIGN | op::TRUST_DUE) {
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), UNIMPLEMENTED, "service {service}");
        }
    }
}

#[test]
fn every_other_slot_answers_unimplemented_on_a_ticket() {
    let d = double();
    let i = EntitlementCheckIn {
        head: head(
            op::ENTITLEMENT_CHECK,
            TICKET,
            0,
            size_of::<EntitlementCheckIn>(),
        ),
        target: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
    };
    let mut o = blank();
    let ret = HOST_SLOTS.entitlement_check.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), UNIMPLEMENTED);
}

#[test]
fn an_in_for_another_service_or_of_a_short_size_is_fault() {
    let d = double();
    let mut i = judge_in("https://a.example/", TICKET, 0, 0);
    i.head.op = op::CLOCK_NOW;
    assert_eq!(call_judge(&d, &i).0.outcome(), Outcome::Fault);
    let mut i = judge_in("https://a.example/", TICKET, 0, 0);
    i.head.size -= 1;
    assert_eq!(call_judge(&d, &i).0.outcome(), Outcome::Fault);
    let i = judge_in("https://a.example/", TICKET, 0, 2);
    assert_eq!(
        call_judge(&d, &i).0.outcome(),
        Outcome::Fault,
        "an unknown flag"
    );
}

/// A verdict the kernel answers at once is READY on the first call, and never pends.
#[test]
fn dest_judge_answers_at_once_what_the_kernel_decides_at_once() {
    let d = double();
    let i = judge_in("now:https://169.254.169.254/", TICKET, 0, DEST_RESOLVE);
    let (ret, o) = call_judge(&d, &i);
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, DEST_METADATA));
    assert!(check_dest_judge(&i, ret, &o).is_ok());
    assert!(d.route.wakes.lock().unwrap().is_empty());
}

/// A pended judgement: PENDING on the ticket; its answer wakes the ticket; the re-issued handle
/// reads the stored verdict, and the kernel was asked once.
#[test]
fn dest_judge_pends_on_the_ticket_and_the_recall_reads_the_verdict() {
    let d = double();
    let i = judge_in("https://api.example.com/v1", TICKET, 5, DEST_RESOLVE);
    let (ret, o) = call_judge(&d, &i);
    assert_eq!(ret.outcome(), Outcome::Pending);
    assert!(check_dest_judge(&i, ret, &o).is_ok());
    assert_eq!(
        call_judge(&d, &i).0.outcome(),
        Outcome::Pending,
        "still running"
    );
    let later = d.route.provider.held.lock().unwrap().pop().unwrap();
    later(Stored::ready(DEST_INTERNAL));
    assert_eq!(*d.route.wakes.lock().unwrap(), vec![TICKET]);
    let (ret, o) = call_judge(&d, &i);
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, DEST_INTERNAL));
    assert_eq!(d.route.provider.judged.load(Ordering::SeqCst), 1);
}

// ── the mechanism, kind-neutral ──────────────────────────────────────────────────────────────

/// A service body that answers eight bytes in one span and counts its runs.
fn eight(runs: &AtomicUsize) -> impl FnOnce(Option<Completer>) -> Ran + '_ {
    move |_| {
        runs.fetch_add(1, Ordering::SeqCst);
        Ran::Now(Stored {
            bytes: b"01234567".to_vec(),
            spans: vec![ItemSpan {
                key_off: check::SPAN_ABSENT,
                key_len: 0,
                value_off: 0,
                value_len: 8,
            }],
            ..Stored::ready(1)
        })
    }
}

fn bufs(buf: &mut [u8], spans: &mut [ItemSpan]) -> ServiceBufs {
    ServiceBufs {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
    }
}

fn nowhere() -> Weak<dyn WakeRoute> {
    let r: Arc<dyn WakeRoute> = Arc::new(Route {
        store: Arc::default(),
        provider: Arc::default(),
        wakes: Mutex::default(),
    });
    Arc::downgrade(&r)
}

const SPAN: ItemSpan = ItemSpan {
    key_off: 0,
    key_len: 0,
    value_off: 0,
    value_len: 0,
};

/// The first short answer earns ONE re-call on the same handle; a second short answer on it
/// is FAULT, and the service never ran twice.
#[test]
fn a_second_short_call_on_one_handle_is_fault() {
    let store = Arc::new(ServiceStore::default());
    let runs = AtomicUsize::new(0);
    let h = head(op::RECORDS_GET, TICKET, 0, 0);
    let (mut b, mut s) = ([0u8; 4], [SPAN; 1]);
    let into = bufs(&mut b, &mut s);
    // SAFETY: the test's own buffers.
    let first = unsafe { serve(&store, &nowhere(), &h, Some(&into), eight(&runs)) };
    assert_eq!(first.outcome, Outcome::Failed);
    assert_eq!((first.needed_bytes, first.needed_items), (8, 1));
    assert_eq!((first.len, first.items), (0, 0), "nothing written");
    assert_eq!(b, [0; 4]);
    // SAFETY: as above.
    let second = unsafe { serve(&store, &nowhere(), &h, Some(&into), eight(&runs)) };
    assert_eq!(second.outcome, Outcome::Fault);
    assert_eq!(second.error, SECOND_SHORT);
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

/// The re-call a short answer earns reads the STORED result: the service does not run again, and a
/// re-issued handle after it reads the same result.
#[test]
fn a_recall_reads_the_stored_result_without_running_again() {
    let store = Arc::new(ServiceStore::default());
    let runs = AtomicUsize::new(0);
    let h = head(op::RECORDS_GET, TICKET, 1, 0);
    let (mut small, mut s1) = ([0u8; 4], [SPAN; 1]);
    let into = bufs(&mut small, &mut s1);
    // SAFETY: the test's own buffers.
    let short = unsafe { serve(&store, &nowhere(), &h, Some(&into), eight(&runs)) };
    assert_eq!(short.outcome, Outcome::Failed);
    let (mut big, mut s2) = ([0u8; 8], [SPAN; 1]);
    let into = bufs(&mut big, &mut s2);
    // SAFETY: as above.
    let recall = unsafe { serve(&store, &nowhere(), &h, Some(&into), eight(&runs)) };
    assert_eq!(
        (recall.outcome, recall.value, recall.len, recall.items),
        (Outcome::Ready, 1, 8, 1)
    );
    assert_eq!(&big, b"01234567");
    assert_eq!(s2[0].value_len, 8);
    // SAFETY: as above.
    let again = unsafe { serve(&store, &nowhere(), &h, Some(&into), eight(&runs)) };
    assert_eq!(again, recall);
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    store.forget(TICKET);
    assert_eq!(store.held(), 0, "a recycled ticket's results are forgotten");
}

fn text(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn claim_in(ttl_ms: u64) -> RecordsClaimIn {
    RecordsClaimIn {
        head: head(op::RECORDS_CLAIM, TICKET, 0, size_of::<RecordsClaimIn>()),
        kind: text("approval"),
        key: text("k1"),
        ttl_ms,
    }
}

fn call_claim(d: &Double, i: &RecordsClaimIn) -> (RawOutcome, ServiceOut) {
    let mut o = blank();
    let ret = HOST_SLOTS.records_claim.unwrap()(d.ctx, std::ptr::from_ref(i).cast(), &mut o);
    (ret, o)
}

/// A caller-scoped service called from an instance bind stated no caller for is REFUSED and never
/// reaches the kernel.
#[test]
fn a_caller_scoped_service_with_no_caller_is_refused() {
    let d = double();
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let dyn_route: Arc<dyn WakeRoute> = d.route.clone();
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    let anon = HostCtx {
        ptr: std::ptr::from_ref(wake).cast_mut().cast(),
    };
    let i = claim_in(1);
    let mut o = blank();
    let ret = HOST_SLOTS.records_claim.unwrap()(anon, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), NO_CALLER);
    assert!(d.route.provider.scoped.lock().unwrap().is_empty());
}

/// A claim with no time to live is refused before it reaches the kernel; there is no default.
#[test]
fn a_claim_with_no_time_to_live_is_refused_and_never_runs() {
    let d = double();
    let (ret, o) = call_claim(&d, &claim_in(0));
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), NO_TTL);
    assert!(d.route.provider.scoped.lock().unwrap().is_empty());
    let (ret, o) = call_claim(&d, &claim_in(1));
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.value, svc::CLAIM_WON);
    assert!(svc::check_records_claim(&claim_in(1), ret, &o).is_ok());
}

/// `records.get` hands the kernel the caller bind stated, the kind and the key, and delivers what
/// it answered into the caller's buffers.
#[test]
fn records_get_reaches_the_kernel_as_its_caller_and_delivers_the_record() {
    let d = double();
    let mut buf = [0u8; 16];
    let mut spans = [ItemSpan {
        key_off: 0,
        key_len: 0,
        value_off: 0,
        value_len: 0,
    }; 1];
    let i = RecordsGetIn {
        head: head(op::RECORDS_GET, TICKET, 0, size_of::<RecordsGetIn>()),
        kind: text("approval"),
        key: text("k1"),
        into: bufs(&mut buf, &mut spans),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.records_get.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.value, svc::FOUND);
    assert_eq!(&buf[..4], b"k1=v");
    assert!(svc::check_records_get(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().as_slice(),
        &[("double".to_string(), "records.get", b"approval".to_vec())]
    );
}

/// The services that never pend reach the kernel from a ticketless op, as their caller.
#[test]
fn sign_and_trust_due_reach_the_kernel_without_a_ticket() {
    let d = double();
    let data = b"payload";
    let i = SignIn {
        head: head(op::SIGN, Ticket::NONE, 0, size_of::<SignIn>()),
        data: busbar_contract::abi::mechanism::call::Blob {
            ptr: data.as_ptr(),
            len: data.len(),
            fmt: 0,
            flags: 0,
        },
        into: bufs(&mut [], &mut []),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.sign.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    let due = TrustDueIn {
        head: head(op::TRUST_DUE, Ticket::NONE, 0, size_of::<TrustDueIn>()),
        into: bufs(&mut [], &mut []),
    };
    let ret = HOST_SLOTS.trust_due.unwrap()(d.ctx, std::ptr::from_ref(&due).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    let seen = d.route.provider.scoped.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            ("double".to_string(), "sign", data.to_vec()),
            ("double".to_string(), "trust.due", Vec::new()),
        ]
    );
}
