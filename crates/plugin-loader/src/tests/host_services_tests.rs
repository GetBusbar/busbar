// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host services (`BUSBAR-1.6.0.md` THE DESIGN, §11.12) through the table an instance is
//! handed, over a kind-neutral test double: a route that records its wakes and a provider with a
//! fixed clock and a `dest.judge` that answers a scripted verdict at once, or pends until the test
//! answers it by hand. The judgement itself is the kernel's and is tested there.

use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::host::service::{
    check_clock_now, check_dest_judge, check_random_fill, ContentScanIn, EntitlementCheckIn,
    ItemSpan, RandomFillIn, DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_RESOLVE,
};
use busbar_contract::abi::mechanism::call::Span;
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
    /// How many `random.fill`s reached the provider.
    filled: AtomicUsize,
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
            key: Span {
                offset: 0,
                len: key.len() as u32,
            },
            value: Span {
                offset: key.len() as u32,
                len: 2,
            },
        }];
        later(stored);
        Ran::Later
    }

    /// Not served by the double: refused, as the loader refuses a slot with no service.
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNIMPLEMENTED))
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

    /// Not served by the double: refused, as the loader refuses a slot with no service.
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNIMPLEMENTED))
    }

    fn trust_due(&self, c: &Caller) -> Stored {
        self.saw(c, "trust.due", b"");
        Stored::ready(0)
    }

    /// Answers the payload's length as the verdict, and the counterparty as the bytes.
    fn trust_verify(&self, c: &Caller, cp: &str, payload: &[u8], sigs: &[u8]) -> Stored {
        self.saw(c, "trust.verify", &[payload, b"|", sigs].concat());
        Stored {
            bytes: cp.as_bytes().to_vec(),
            ..Stored::ready(payload.len() as u64)
        }
    }

    fn entitlement_check(&self, c: &Caller, unit: Option<u64>, target: &str) -> Stored {
        let arg = format!("{unit:?} {target}");
        self.saw(c, "entitlement.check", arg.as_bytes());
        Stored::ready(svc::ENTITLED)
    }

    /// Every fill's bytes differ from the last one's: all `n`, the fill's ordinal.
    fn random_fill(&self, len: u64) -> Stored {
        let n = self.filled.fetch_add(1, Ordering::SeqCst) + 1;
        Stored {
            bytes: vec![n as u8; len as usize],
            ..Stored::ready(0)
        }
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
        into: ServiceBufs {
            buf: std::ptr::null_mut(),
            cap: 0,
            spans: std::ptr::null_mut(),
            spans_cap: 0,
        },
    }
}

const NO_SPAN: ItemSpan = ItemSpan {
    key: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
};

/// The kernel's admitted answer naming `addrs`, one span's key each.
fn admitted(addrs: &[&str]) -> Stored {
    let mut s = Stored::ready(DEST_ALLOWED);
    for a in addrs {
        let at = s.bytes.len() as u32;
        s.bytes.extend_from_slice(a.as_bytes());
        s.spans.push(ItemSpan {
            key: Span {
                offset: at,
                len: a.len() as u32,
            },
            value: Span {
                offset: check::SPAN_ABSENT,
                len: 0,
            },
        });
    }
    s
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
        HOST_SLOTS.random_fill,
        HOST_SLOTS.need_admit,
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
        } else if !matches!(
            service,
            op::CLOCK_NOW | op::SIGN | op::TRUST_DUE | op::ENTITLEMENT_CHECK | op::RANDOM_FILL
        ) {
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), UNIMPLEMENTED, "service {service}");
        }
    }
}

#[test]
fn every_other_slot_answers_unimplemented_on_a_ticket() {
    let d = double();
    let i = ContentScanIn {
        head: head(op::CONTENT_SCAN, TICKET, 0, size_of::<ContentScanIn>()),
        content: busbar_contract::abi::mechanism::call::Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        },
        into: bufs(&mut [], &mut []),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.content_scan.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
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

/// THE JUDGED ADDRESSES go into the caller's buffers under the short-buffer rule: no room is a
/// FAILED short answer naming the full size, and the re-call with room reads the stored addresses
/// (the kernel judged once).
#[test]
fn dest_judge_writes_the_judged_addresses_under_the_short_buffer_rule() {
    let d = double();
    let mut i = judge_in("https://api.example.com/v1", TICKET, 6, DEST_RESOLVE);
    assert_eq!(call_judge(&d, &i).0.outcome(), Outcome::Pending);
    let later = d.route.provider.held.lock().unwrap().pop().unwrap();
    later(admitted(&["198.51.100.7", "2001:db8::7"]));
    let (ret, o) = call_judge(&d, &i);
    assert_eq!(
        (ret.outcome(), o.needed_bytes, o.needed_items),
        (Outcome::Failed, 23, 2)
    );
    assert!(check_dest_judge(&i, ret, &o).is_ok());
    let (mut buf, mut spans) = ([0u8; 23], [NO_SPAN; 2]);
    i.into = bufs(&mut buf, &mut spans);
    let (ret, o) = call_judge(&d, &i);
    assert_eq!(
        (ret.outcome(), o.value, o.len, o.items),
        (Outcome::Ready, DEST_ALLOWED, 23, 2)
    );
    assert!(check_dest_judge(&i, ret, &o).is_ok());
    assert_eq!(&buf[..12], b"198.51.100.7");
    assert_eq!(d.route.provider.judged.load(Ordering::SeqCst), 1);
}

/// THE SDK'S WRAPPER over this table: `dest.judge` pends on the op's ticket, the answer wakes it,
/// and the op's re-entry re-issues the same handle and reads the stored verdict (the kernel judged
/// once).
#[test]
fn the_sdk_dest_judge_pends_and_its_reissue_reads_the_stored_verdict() {
    use busbar_contract::abi::mechanism::ticket::HostTables;
    use busbar_contract::abi::sdk::Services;
    let d = double();
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: d.ctx,
        wake: None,
        conns: std::ptr::null(),
        services: &HOST_SLOTS,
    };
    let s = Services::of(&tables).expect("the table is handed");
    let handle = CompletionHandle {
        ticket: TICKET,
        seq: 2,
        _reserved: 0,
    };
    let url = "https://api.example.com/v1";
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 2]);
    assert!(s
        .dest_judge(handle, url, 0, Some((&mut buf[..], &mut spans[..])))
        .is_pending());
    let later = d.route.provider.held.lock().unwrap().pop().unwrap();
    later(admitted(&["198.51.100.7"]));
    assert_eq!(*d.route.wakes.lock().unwrap(), vec![TICKET]);
    let std::task::Poll::Ready(Ok(j)) =
        s.dest_judge(handle, url, 0, Some((&mut buf[..], &mut spans[..])))
    else {
        panic!("the stored answer");
    };
    assert_eq!(
        (j.verdict, j.within()),
        (DEST_ALLOWED, "198.51.100.7".to_owned())
    );
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
                key: Span {
                    offset: check::SPAN_ABSENT,
                    len: 0,
                },
                value: Span { offset: 0, len: 8 },
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
    key: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
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
    assert_eq!(s2[0].value.len, 8);
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
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
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

fn blob(b: &[u8]) -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: 0,
        flags: 0,
    }
}

/// `trust.verify` reaches the kernel from a ticketless op as its caller, with the counterparty,
/// payload and signatures it named; the kernel's bytes land in the caller's buffer.
#[test]
fn trust_verify_reaches_the_kernel_without_a_ticket_and_answers_into_the_callers_buffer() {
    let d = double();
    let mut buf = [0u8; 8];
    let i = TrustVerifyIn {
        head: head(op::TRUST_VERIFY, Ticket::NONE, 0, size_of::<TrustVerifyIn>()),
        counterparty: text("peer"),
        payload: blob(b"doc"),
        signatures: blob(b"[]"),
        into: bufs(&mut buf, &mut []),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.trust_verify.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!((o.value, o.len), (3, 4));
    assert_eq!(&buf[..4], b"peer");
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().as_slice(),
        &[("double".to_string(), "trust.verify", b"doc|[]".to_vec())]
    );
}

/// RED: a signatures blob that names a length with no bytes is FAULT, and never reaches the kernel.
#[test]
fn trust_verify_with_a_null_blob_of_a_length_is_fault() {
    let d = double();
    let mut i = TrustVerifyIn {
        head: head(op::TRUST_VERIFY, Ticket::NONE, 0, size_of::<TrustVerifyIn>()),
        counterparty: text("peer"),
        payload: blob(b"doc"),
        signatures: blob(b""),
        into: bufs(&mut [], &mut []),
    };
    i.signatures.ptr = std::ptr::null();
    i.signatures.len = 2;
    let mut o = blank();
    let ret = HOST_SLOTS.trust_verify.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Fault);
    assert!(d.route.provider.scoped.lock().unwrap().is_empty());
}

fn entitlement_in(target: &'static str) -> EntitlementCheckIn {
    EntitlementCheckIn {
        head: head(
            op::ENTITLEMENT_CHECK,
            Ticket::NONE,
            0,
            size_of::<EntitlementCheckIn>(),
        ),
        target: text(target),
    }
}

#[test]
fn entitlement_check_reaches_the_kernel_with_the_unit_its_crossing_serves() {
    let d = double();
    let ask = |target| {
        let i = entitlement_in(target);
        let mut o = blank();
        let ret =
            HOST_SLOTS.entitlement_check.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        (ret.outcome(), o.value)
    };
    // Outside any crossing: no unit.
    assert_eq!(ask("item:one"), (Outcome::Ready, svc::ENTITLED));
    {
        let _outer = serving(Some(7));
        assert_eq!(ask("item:two").0, Outcome::Ready);
        {
            // A nested crossing states its own unit, and its end restores the outer one.
            let _inner = serving(Some(8));
            ask("item:three");
        }
        ask("item:four");
    }
    ask("item:five");
    let seen: Vec<String> = d
        .route
        .provider
        .scoped
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, what, _)| *what == "entitlement.check")
        .map(|(_, _, arg)| String::from_utf8(arg.clone()).unwrap())
        .collect();
    assert_eq!(
        seen,
        vec![
            "None item:one",
            "Some(7) item:two",
            "Some(8) item:three",
            "Some(7) item:four",
            "None item:five",
        ]
    );
}

fn fill_in(len: u64, buf: &mut [u8]) -> RandomFillIn {
    RandomFillIn {
        head: head(op::RANDOM_FILL, Ticket::NONE, 0, size_of::<RandomFillIn>()),
        len,
        into: bufs(buf, &mut []),
    }
}

#[test]
fn random_fill_writes_the_kernels_bytes_and_refuses_outside_its_cap_before_the_kernel() {
    let d = double();
    let fill = |len: u64, buf: &mut [u8]| {
        let i = fill_in(len, buf);
        let mut o = blank();
        let ret = HOST_SLOTS.random_fill.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        (check_random_fill(&i, ret, &o), ret.outcome(), o)
    };
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    let (checked, outcome, o) = fill(16, &mut a[..]);
    assert_eq!(
        (checked, outcome, o.len),
        (Ok(Filled::Written), Outcome::Ready, 16)
    );
    let (checked, _, _) = fill(16, &mut b[..]);
    assert_eq!(checked, Ok(Filled::Written));
    // Each fill lands in its own buffer.
    assert_eq!((a, b), ([1; 16], [2; 16]));
    assert_ne!(a, b, "two fills are never equal");
    for len in [0, svc::MAX_RANDOM_FILL + 1, u64::MAX] {
        let mut big = vec![0u8; 2048];
        let (_, outcome, o) = fill(len, &mut big[..]);
        assert_eq!(outcome, Outcome::Refused, "len {len}");
        assert_eq!(error(&o), FILL_OUT_OF_RANGE, "len {len}");
        assert!(big.iter().all(|x| *x == 0), "nothing written");
    }
    assert_eq!(
        d.route.provider.filled.load(Ordering::SeqCst),
        2,
        "a refused fill never reaches the kernel"
    );
}

/// A RECYCLE drops the stored service results of every `(ticket, n)` of its ticket, through the
/// dispatcher's own recycle path: nothing an earlier request's services answered survives into the
/// ticket's next life, and a replay of an old handle runs its service afresh rather than reading
/// the stored result.
#[test]
fn a_recycled_ticket_drops_its_stored_service_results() {
    let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let t = d.mint(0).expect("a ticket");
    let store = d.service_store();
    let runs = AtomicUsize::new(0);
    let heads = [
        head(op::RECORDS_GET, t, 0, 0),
        head(op::RECORDS_GET, t, 1, 0),
    ];
    for h in &heads {
        let (mut b, mut s) = ([0u8; 8], [SPAN; 1]);
        let into = bufs(&mut b, &mut s);
        // SAFETY: the test's own buffers.
        let a = unsafe { serve(&store, &nowhere(), h, Some(&into), eight(&runs)) };
        assert_eq!((a.outcome, a.value), (Outcome::Ready, 1));
    }
    assert_eq!(d.services().held(), 2, "one stored result per (ticket, n)");
    let (mut b, mut s) = ([0u8; 8], [SPAN; 1]);
    let into = bufs(&mut b, &mut s);
    // SAFETY: as above.
    let replay = unsafe { serve(&store, &nowhere(), &heads[0], Some(&into), eight(&runs)) };
    assert_eq!(replay.outcome, Outcome::Ready);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "a replay before the recycle reads, not runs"
    );

    d.recycle(t);
    let start = std::time::Instant::now();
    while d.services().held() != 0 {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "the recycle must drop the ticket's stored results"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    // SAFETY: as above.
    let after = unsafe { serve(&store, &nowhere(), &heads[0], Some(&into), eight(&runs)) };
    assert_eq!(after.outcome, Outcome::Ready);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        3,
        "the recycled ticket's old handle runs afresh: no earlier result is read back"
    );
}
