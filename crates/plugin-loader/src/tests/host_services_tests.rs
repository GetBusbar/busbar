// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host services (`BUSBAR-1.6.0.md` THE DESIGN, §11.12) through the table an instance is
//! handed, over a kind-neutral test double: a route that records its wakes and a provider with a
//! fixed clock and a `dest.judge` that answers a scripted verdict at once, or pends until the test
//! answers it by hand. The judgement itself is the kernel's and is tested there.

use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::host::service::{
    check_clock_now, check_content_scan, check_dest_judge, check_hook_call, check_random_fill,
    check_ticket_mint, check_ticket_take, check_verify_lookup, check_verify_store, ContentScanIn,
    EntitlementCheckIn, HookCallIn, ItemSpan, RandomFillIn, VerifyLookupIn, VerifyStoreIn,
    DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_RESOLVE,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::Filled;
use busbar_contract::services::DiskDest;

use super::*;
use crate::dispatch::ticket::{InstanceWake, WakeRoute};

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
    /// Every `records.secret` read that reached the provider, as `kind:id`.
    secrets: Mutex<Vec<String>>,
    /// Every `disk.append` that reached the provider: the destination and the bytes.
    appended: Mutex<Vec<(DiskDest, Vec<u8>)>>,
    /// Whether `snapshot.read` answers NOT READY (the recorder is not installed).
    snapshot_not_ready: std::sync::atomic::AtomicBool,
}

impl Provider {
    fn saw(&self, c: &Caller, what: &'static str, arg: &[u8]) {
        self.scoped
            .lock()
            .unwrap()
            .push((c.instance.to_string(), what, arg.to_vec()));
    }
}

/// Every service but `trust.sight`, which the contract's shared double refuses as unserved
/// ([`UNIMPLEMENTED`]), as the loader refuses a slot with no service.
impl busbar_contract::services::double::ServicesDouble for Provider {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 1_700_000_000_000_000_000,
            mono_ns: 42,
        }
    }

    fn dest_judge(&self, dest: &str, _class: u32, _flags: u32, later: Option<Later>) -> Ran {
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

    /// [`LISTED`] after `after`, key then value per record, one span each, at once.
    fn records_list(&self, c: &Caller, list: RecordsList, _: Later) -> Ran {
        self.saw(c, "records.list", list.kind.as_bytes());
        let mut stored = Stored::ready(0);
        for (k, v) in LISTED
            .iter()
            .filter(|(k, _)| list.after.as_deref().is_none_or(|a| *k > a))
        {
            let at = stored.bytes.len() as u32;
            stored.bytes.extend_from_slice(k);
            stored.bytes.extend_from_slice(v);
            stored.spans.push(ItemSpan {
                key: Span {
                    offset: at,
                    len: k.len() as u32,
                },
                value: Span {
                    offset: at + k.len() as u32,
                    len: v.len() as u32,
                },
            });
        }
        Ran::Now(stored)
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

    /// Records `<counterparty>/<item> <digest>`; answers a new sighting.
    fn trust_sight_item(&self, c: &Caller, counterparty: &str, item: &str, digest: &str) -> Stored {
        let arg = format!("{counterparty}/{item} {digest}");
        self.saw(c, "trust.sight_item", arg.as_bytes());
        Stored::ready(svc::TRUST_NEW)
    }

    /// Records `<counterparty>/<item>@<digest>`; answers that it serves.
    fn trust_serves(
        &self,
        c: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        let arg = format!(
            "{counterparty}/{}@{}",
            item.unwrap_or("-"),
            digest.unwrap_or("-")
        );
        self.saw(c, "trust.serves", arg.as_bytes());
        Stored::ready(svc::DISTRUST_NONE)
    }

    /// Records `<counterparty>/<item>@<expected> <approve>`; answers serving.
    fn trust_decide(
        &self,
        c: &Caller,
        key: busbar_contract::services::TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored {
        let arg = format!(
            "{}/{}@{} {approve}",
            key.counterparty,
            key.item.unwrap_or("-"),
            expected.unwrap_or("-")
        );
        self.saw(c, "trust.decide", arg.as_bytes());
        Stored::ready(svc::TRUST_DECIDED_SERVING)
    }

    /// One item `t` approved at `d1`, sighted at `d2`: drifted; the counterparty the same.
    fn trust_state(&self, c: &Caller, counterparty: &str) -> Stored {
        self.saw(c, "trust.state", counterparty.as_bytes());
        let value = b"drifted\0d1\0d2";
        let mut stored = Stored::ready(svc::KEY_SAME);
        stored.bytes = [&b"t"[..], value].concat();
        stored.spans = vec![ItemSpan {
            key: Span { offset: 0, len: 1 },
            value: Span {
                offset: 1,
                len: value.len() as u32,
            },
        }];
        stored
    }

    /// The last verdict, never a sighting: `TRUST_SAME`.
    fn trust_unreached(&self, c: &Caller, counterparty: &str) -> Stored {
        self.saw(c, "trust.unreached", counterparty.as_bytes());
        Stored::ready(svc::TRUST_SAME)
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

    /// The ticket double: a ticket naming the unit, expiring `1_700_000_000 + ttl`.
    fn ticket_mint(&self, c: &Caller, unit: Option<u64>, ttl_secs: u64, record: &[u8]) -> Stored {
        let arg = format!("{unit:?} {ttl_secs} {}", String::from_utf8_lossy(record));
        self.saw(c, "ticket.mint", arg.as_bytes());
        Stored {
            bytes: format!("tk_{}", unit.unwrap_or(0)).into_bytes(),
            ..Stored::ready(1_700_000_000 + ttl_secs)
        }
    }

    /// The take double: unit 7 was admitted by a ticket whose record is `rec`; any other by a key.
    fn ticket_take(&self, c: &Caller, unit: Option<u64>) -> Stored {
        self.saw(c, "ticket.take", format!("{unit:?}").as_bytes());
        if unit == Some(7) {
            Stored {
                bytes: b"rec".to_vec(),
                ..Stored::ready(svc::TICKET_TAKEN)
            }
        } else {
            Stored::ready(svc::TICKET_NONE)
        }
    }

    /// Every fill's bytes differ from the last one's: all `n`, the fill's ordinal.
    fn random_fill(&self, len: u64) -> Stored {
        let n = self.filled.fetch_add(1, Ordering::SeqCst) + 1;
        Stored {
            bytes: vec![n as u8; len as usize],
            ..Stored::ready(0)
        }
    }

    /// The credential double: `<kind>:<id>` live, its secret `s3cr3t`, answered at once.
    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        self.secrets.lock().unwrap().push(format!("{kind}:{id}"));
        let mut stored = Stored::ready(svc::SECRET_LIVE);
        stored.bytes = b"s3cr3t".to_vec();
        stored.spans = vec![ItemSpan {
            key: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 6 },
        }];
        later(stored);
        Ran::Later
    }

    /// Records `<unit> <verb> <target> <body>`; answers status 201, the body `child`, no field.
    fn unit_nest(&self, c: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        let arg = [
            format!("{unit:?} {} {} ", ask.verb, ask.target).as_bytes(),
            &ask.body,
        ]
        .concat();
        self.saw(c, "unit.nest", &arg);
        let mut stored = Stored::ready(201);
        stored.bytes = b"child".to_vec();
        stored.spans = vec![ItemSpan {
            key: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
            value: Span { offset: 0, len: 5 },
        }];
        later(stored);
        Ran::Later
    }

    /// Records `<unit> <kind> <record>`; answers handle 5 and the reference `ref` in span 0.
    fn work_open(
        &self,
        c: &Caller,
        unit: Option<u64>,
        kind: &str,
        rec: &[u8],
        later: Later,
    ) -> Ran {
        let arg = [format!("{unit:?} {kind} ").as_bytes(), rec].concat();
        self.saw(c, "work.open", &arg);
        let mut stored = Stored::ready(5);
        stored.bytes = b"ref".to_vec();
        stored.spans = vec![ItemSpan {
            key: Span { offset: 0, len: 3 },
            value: Span {
                offset: busbar_contract::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
        }];
        later(stored);
        Ran::Later
    }

    /// Records `<unit> <reference>`; answers absent.
    fn work_find(&self, c: &Caller, unit: Option<u64>, reference: &[u8], _: Later) -> Ran {
        let arg = [format!("{unit:?} ").as_bytes(), reference].concat();
        self.saw(c, "work.find", &arg);
        Ran::Now(Stored::ready(svc::ABSENT))
    }

    /// Records `<unit> <handle> <record>`.
    fn work_settle(&self, c: &Caller, unit: Option<u64>, handle: u64, rec: &[u8], _: Later) -> Ran {
        let arg = [format!("{unit:?} {handle} ").as_bytes(), rec].concat();
        self.saw(c, "work.settle", &arg);
        Ran::Now(Stored::ready(0))
    }

    /// Records `<unit> <handle>`.
    fn work_resume(&self, c: &Caller, unit: Option<u64>, handle: u64, _: Later) -> Ran {
        self.saw(c, "work.resume", format!("{unit:?} {handle}").as_bytes());
        Ran::Now(Stored::ready(0))
    }

    /// Records the key; answers a hit whose entry is `entry`, in span 0, through `later`.
    fn verify_lookup(&self, c: &Caller, key: &[u8], later: Later) -> Ran {
        self.saw(c, "verify.lookup", key);
        let mut stored = Stored::ready(svc::VERIFY_HIT);
        stored.bytes = b"entry".to_vec();
        stored.spans = vec![ItemSpan {
            key: Span {
                offset: check::SPAN_ABSENT,
                len: 0,
            },
            value: Span { offset: 0, len: 5 },
        }];
        later(stored);
        Ran::Later
    }

    /// Records `<key> <entry> <ttl>`.
    fn verify_store(&self, c: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        let arg = [key, b" ", entry, format!(" {ttl_ms}").as_bytes()].concat();
        self.saw(c, "verify.store", &arg);
        Stored::ready(0)
    }

    /// Records `<unit> <content>`; blocks it.
    fn content_scan(&self, c: &Caller, unit: Option<u64>, content: &[u8], _: Later) -> Ran {
        let arg = [format!("{unit:?} ").as_bytes(), content].concat();
        self.saw(c, "content.scan", &arg);
        Ran::Now(Stored::ready(svc::CONTENT_BLOCK))
    }

    /// Records `<unit> <stage> <from> <system> <role>=<text>...`; answers `1 + from`, the bytes
    /// `rw`.
    fn hook_call(&self, c: &Caller, unit: Option<u64>, ask: HookAsk, _: Later) -> Ran {
        let mut arg = format!("{unit:?} {} {} {:?}", ask.stage, ask.from, ask.system);
        for (role, text) in &ask.messages {
            arg.push_str(&format!(" {role}={text}"));
        }
        self.saw(c, "hook.call", arg.as_bytes());
        Ran::Now(Stored {
            bytes: b"rw".to_vec(),
            ..Stored::ready(1 + u64::from(ask.from))
        })
    }

    /// The disk-lane double: records the append and answers through `later` — READY with the
    /// file rotated first, or, for a path ending `.fail`, FAILED at the open step.
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        self.appended.lock().unwrap().push((dest.clone(), bytes));
        let failing = dest.path.ends_with(".fail");
        later(
            DiskReport {
                step: if failing { svc::DISK_OPEN_FAILED } else { 0 },
                rotated: true,
                faults: 0,
                error: if failing {
                    "No such file or directory"
                } else {
                    ""
                },
            }
            .stored(),
        );
        Ran::Later
    }

    fn snapshot_read(&self, c: &Caller, scope: u32) -> busbar_contract::services::Snapshot {
        self.saw(c, "snapshot.read", scope.to_string().as_bytes());
        if self.snapshot_not_ready.load(Ordering::Relaxed) {
            return busbar_contract::services::Snapshot::NotReady;
        }
        busbar_contract::services::Snapshot::Families(snapshot_families())
    }
}

/// The records the double's `records.list` holds, in key order.
const LISTED: [(&[u8], &[u8]); 2] = [(b"p/1", b"a"), (b"p/2", b"b")];

/// The route half: records every wake.
struct Route {
    store: Arc<ServiceStore>,
    provider: Arc<Provider>,
    wakes: Mutex<Vec<Ticket>>,
    /// The kernel's side of the auth handle, when a test installs one.
    auth: std::sync::OnceLock<Arc<dyn crate::dispatch::auth_handle::AuthHandleHost>>,
}

impl WakeRoute for Route {
    fn wake(&self, t: Ticket, _supplier: Option<&'static InstanceWake>) {
        self.wakes.lock().unwrap().push(t);
    }

    fn services(&self) -> Option<Served> {
        Some(Served {
            store: Arc::clone(&self.store),
            provider: self.provider.clone(),
        })
    }

    fn auth_handle(&self) -> Option<Arc<dyn crate::dispatch::auth_handle::AuthHandleHost>> {
        self.auth.get().cloned()
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
        auth: std::sync::OnceLock::new(),
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
        ctx: crate::dispatch::handle::mint(wake).expect("the host mints a handle"),
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
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    out
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
        HOST_SLOTS.trust_verify,
        HOST_SLOTS.records_secret,
        HOST_SLOTS.disk_append,
        HOST_SLOTS.snapshot_read,
        HOST_SLOTS.trust_sight_item,
        HOST_SLOTS.trust_serves,
        HOST_SLOTS.trust_decide,
        HOST_SLOTS.trust_state,
        HOST_SLOTS.session_emit,
        HOST_SLOTS.auth_call,
        HOST_SLOTS.unit_hand_in,
        HOST_SLOTS.unit_refuse,
        HOST_SLOTS.ticket_mint,
        HOST_SLOTS.ticket_take,
    ];
    assert_eq!(slots.len(), SERVICES as usize);
    // The room a READ service is handed, so its well-formed call can be answered whole.
    let (mut read_buf, mut read_spans) = ([0u8; 64], [NO_SPAN; 4]);
    for (service, f) in (0..SERVICES).zip(slots) {
        // The largest `in` in the table, all zero past its head: every `in` fits it.
        let mut raw = [0u64; 32];
        let h = head(service, Ticket::NONE, 0, size_of_val(&raw));
        // SAFETY: the head fits the buffer's start.
        unsafe { raw.as_mut_ptr().cast::<ServiceHead>().write_unaligned(h) };
        // A read that answers into the caller's buffers is handed a WELL-FORMED `in` (a named
        // counterparty, room for its items): the slot is served as any other is. Its all-zero
        // `in` is a short answer of its own (`an_all_zero_trust_state_in_is_a_short_answer`).
        if service == op::TRUST_STATE {
            let well_formed = svc::TrustStateIn {
                head: h,
                counterparty: text("peer"),
                into: bufs(&mut read_buf, &mut read_spans),
            };
            // SAFETY: a `TrustStateIn` fits the buffer's start.
            unsafe {
                raw.as_mut_ptr()
                    .cast::<svc::TrustStateIn>()
                    .write_unaligned(well_formed)
            };
        }
        let mut o = blank();
        let ret = f.unwrap()(d.ctx, raw.as_ptr().cast(), &mut o);
        if may_pend(service) {
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), UNTICKETED, "service {service}");
        } else if service == op::NEED_ADMIT {
            // The connection table's verdict: an instance handed no table declared nothing.
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(
                error(&o),
                busbar_contract::conn::ConnError::UndeclaredNeed.text(),
                "service {service}"
            );
        } else if service == op::TRUST_STATE {
            // Its well-formed call, answered whole into the room it named.
            assert_eq!(ret.outcome(), Outcome::Ready, "service {service}");
        } else if service == op::SESSION_EMIT {
            // An emit naming no session and nothing to write is refused before the provider.
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), EMIT_NOTHING, "service {service}");
        } else if matches!(service, op::UNIT_HAND_IN | op::UNIT_REFUSE) {
            // The auth handle's `in` has one exact size; this one states the buffer's.
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), NOT_EXACT, "service {service}");
        } else if service == op::TICKET_MINT {
            // A mint asking no lifetime is refused before the provider.
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), MINT_OUT_OF_RANGE, "service {service}");
        } else if service == op::VERIFY_STORE {
            // Served: the zeroed `in` names no key, which is refused before the cache is read.
            assert_eq!(ret.outcome(), Outcome::Refused, "service {service}");
            assert_eq!(error(&o), NO_VERIFY_KEY, "service {service}");
        } else if matches!(
            service,
            op::TRUST_SIGHT_ITEM | op::TRUST_SERVES | op::TRUST_DECIDE
        ) {
            // Served, with no ticket: the zeroed `in` names empty texts, which reach the kernel.
            assert_eq!(ret.outcome(), Outcome::Ready, "service {service}");
        } else {
            assert!(
                matches!(
                    service,
                    op::CLOCK_NOW
                        | op::SIGN
                        | op::TRUST_DUE
                        | op::ENTITLEMENT_CHECK
                        | op::RANDOM_FILL
                        | op::TRUST_VERIFY
                        | op::SNAPSHOT_READ
                        | op::TICKET_TAKE
                ),
                "service {service}"
            );
        }
        // No slot of the table is left unserved.
        if !o.error.ptr.is_null() {
            assert_ne!(
                error(&o),
                busbar_contract::services::UNSERVED,
                "service {service}"
            );
        }
    }
}

fn no_bufs() -> ServiceBufs {
    ServiceBufs {
        buf: std::ptr::null_mut(),
        cap: 0,
        spans: std::ptr::null_mut(),
        spans_cap: 0,
    }
}

fn over(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob_over(b: &[u8]) -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: 0,
        flags: 0,
    }
}

/// `verify.lookup` reaches the kernel with the caller and the key, and the entry it answers is
/// written into the caller's buffers; a lookup that names no key is REFUSED before the cache is
/// read (RED arm).
#[test]
fn verify_lookup_answers_the_callers_cache_and_refuses_an_empty_key() {
    let d = double();
    let (mut buf, mut spans) = ([0u8; 8], [NO_SPAN; 1]);
    let mut i = VerifyLookupIn {
        head: head(op::VERIFY_LOOKUP, TICKET, 0, size_of::<VerifyLookupIn>()),
        key: over(b"card:a"),
        into: bufs(&mut buf, &mut spans),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.verify_lookup.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.value, svc::VERIFY_HIT);
    assert_eq!(&buf[..o.len as usize], b"entry");
    assert!(check_verify_lookup(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().last().cloned(),
        Some(("double".to_string(), "verify.lookup", b"card:a".to_vec()))
    );

    i.key = over(b"");
    i.head = head(op::VERIFY_LOOKUP, TICKET, 1, size_of::<VerifyLookupIn>());
    let before = d.route.provider.scoped.lock().unwrap().len();
    let mut o = blank();
    let ret = HOST_SLOTS.verify_lookup.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), NO_VERIFY_KEY);
    assert_eq!(d.route.provider.scoped.lock().unwrap().len(), before);
}

/// `verify.store` never pends: it is served with no ticket, with the caller, key, entry and ttl;
/// an empty key is REFUSED before the cache is written (RED arm).
#[test]
fn verify_store_is_served_without_a_ticket_and_refuses_an_empty_key() {
    let d = double();
    let mut i = VerifyStoreIn {
        head: head(
            op::VERIFY_STORE,
            Ticket::NONE,
            0,
            size_of::<VerifyStoreIn>(),
        ),
        key: over(b"k"),
        entry: blob_over(b"e"),
        ttl_ms: 9,
    };
    let mut o = blank();
    let ret = HOST_SLOTS.verify_store.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert!(check_verify_store(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().last().cloned(),
        Some(("double".to_string(), "verify.store", b"k e 9".to_vec()))
    );
    i.key = over(b"");
    let mut o = blank();
    let ret = HOST_SLOTS.verify_store.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), NO_VERIFY_KEY);
}

/// `content.scan` reaches the kernel with the unit the crossing serves and the content; called
/// with no ticket it is REFUSED (it may pend) and never runs (RED arm).
#[test]
fn content_scan_scans_for_the_unit_the_crossing_serves() {
    let d = double();
    let content = b"tool result";
    let mut i = ContentScanIn {
        head: head(op::CONTENT_SCAN, TICKET, 0, size_of::<ContentScanIn>()),
        content: blob_over(content),
        into: no_bufs(),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(7));
        HOST_SLOTS.content_scan.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o)
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.value, svc::CONTENT_BLOCK);
    assert!(check_content_scan(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().last().cloned(),
        Some((
            "double".to_string(),
            "content.scan",
            b"Some(7) tool result".to_vec()
        ))
    );
    i.head = head(
        op::CONTENT_SCAN,
        Ticket::NONE,
        0,
        size_of::<ContentScanIn>(),
    );
    let before = d.route.provider.scoped.lock().unwrap().len();
    let mut o = blank();
    let ret = HOST_SLOTS.content_scan.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), UNTICKETED);
    assert_eq!(d.route.provider.scoped.lock().unwrap().len(), before);
}

fn hook_in(
    stage: u32,
    from: u32,
    prompt: *const busbar_contract::abi::hook::PromptView,
    seq: u32,
    into: ServiceBufs,
) -> HookCallIn {
    HookCallIn {
        head: head(op::HOOK_CALL, TICKET, seq, size_of::<HookCallIn>()),
        stage,
        from,
        prompt,
        into,
    }
}

/// `hook.call` copies the caller's prompt view and runs the stage for the unit the crossing
/// serves; the rewrite it answers is written into the caller's buffers.
#[test]
fn hook_call_runs_the_stage_over_the_copied_prompt() {
    use busbar_contract::abi::hook::{MessageView, PromptView};
    let d = double();
    let messages = [MessageView {
        role: over(b"user"),
        text: over(b"hi"),
    }];
    let view = PromptView {
        system: over(b"sys"),
        message_count: 1,
        body: busbar_contract::abi::mechanism::call::Blob::ABSENT,
        messages: messages.as_ptr(),
        messages_len: 1,
    };
    let (mut buf, mut spans) = ([0u8; 4], [NO_SPAN; 1]);
    let i = hook_in(svc::HOOK_REWRITE, 2, &view, 0, bufs(&mut buf, &mut spans));
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(4));
        HOST_SLOTS.hook_call.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o)
    };
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!((o.value, &buf[..o.len as usize]), (3, &b"rw"[..]));
    assert!(check_hook_call(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().last().cloned(),
        Some((
            "double".to_string(),
            "hook.call",
            b"Some(4) 1 2 Some(\"sys\") user=hi".to_vec()
        ))
    );
}

/// RED, one arm each: an unknown stage, a chain resumed past the cap, a resumed gate and a missing
/// prompt are each REFUSED in their own words before any hook runs; a prompt view that breaks its
/// own rules is FAULT.
#[test]
fn hook_call_refuses_each_malformed_in_before_any_hook_runs() {
    use busbar_contract::abi::hook::PromptView;
    let d = double();
    let view = PromptView {
        system: over(b""),
        message_count: 0,
        body: busbar_contract::abi::mechanism::call::Blob::ABSENT,
        messages: std::ptr::null(),
        messages_len: 0,
    };
    let broken = PromptView {
        message_count: 2,
        messages_len: 2,
        ..view
    };
    let cases: [(HookCallIn, Outcome, &str); 5] = [
        (
            hook_in(7, 0, &view, 0, no_bufs()),
            Outcome::Refused,
            HOOK_UNKNOWN_STAGE,
        ),
        (
            hook_in(
                svc::HOOK_REWRITE,
                svc::HOOK_FROM_MAX + 1,
                &view,
                1,
                no_bufs(),
            ),
            Outcome::Refused,
            HOOK_FROM_PAST_CAP,
        ),
        (
            hook_in(svc::HOOK_GATE, 1, &view, 2, no_bufs()),
            Outcome::Refused,
            HOOK_GATE_RESUMED,
        ),
        (
            hook_in(svc::HOOK_GATE, 0, std::ptr::null(), 3, no_bufs()),
            Outcome::Refused,
            HOOK_NO_PROMPT,
        ),
        (
            hook_in(svc::HOOK_GATE, 0, &broken, 4, no_bufs()),
            Outcome::Fault,
            "",
        ),
    ];
    for (i, outcome, why) in cases {
        let mut o = blank();
        let ret = HOST_SLOTS.hook_call.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        assert_eq!(ret.outcome(), outcome, "{why}");
        if outcome == Outcome::Refused {
            assert_eq!(error(&o), why);
        }
    }
    assert!(d.route.provider.scoped.lock().unwrap().is_empty());
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
    let i = judge_in("https://a.example/", TICKET, 0, 8);
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
    let d = double();
    let s = sdk(&d);
    let handle = ticketed(2);
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

/// The SDK's services over this table, as `open` hands them to the double's instance.
fn sdk(d: &Double) -> busbar_contract::abi::sdk::Services {
    use busbar_contract::abi::mechanism::ticket::HostTables;
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: d.ctx,
        wake: None,
        conns: std::ptr::null(),
        services: &HOST_SLOTS,
        io: std::ptr::null(),
    };
    busbar_contract::abi::sdk::Services::of(&tables).expect("the table is handed")
}

/// The handle of a ticketed op's `seq`th service call.
const fn ticketed(seq: u32) -> CompletionHandle {
    CompletionHandle {
        ticket: TICKET,
        seq,
        _reserved: 0,
    }
}

/// THE SDK'S RECORDS WRAPPERS over this table (K-RECORDS): `records.get` reads the value the
/// kernel answered for the caller; `records.list` its rows, and the next page after a key it
/// answered (an `after` the plugin left absent reaches the kernel as none); `records.claim` the
/// kernel's won or taken, and a claim with no time to live never leaves the plugin.
#[test]
fn the_sdk_records_wrappers_reach_the_kernel_as_their_caller() {
    use std::task::Poll;
    let d = double();
    let s = sdk(&d);
    let mut buf = [0u8; 16];
    assert_eq!(
        s.records_get(ticketed(0), "approval", b"k1", &mut buf),
        Poll::Ready(Ok(Some(&b"=v"[..])))
    );
    let (mut buf, mut spans) = ([0u8; 16], [NO_SPAN; 4]);
    let Poll::Ready(Ok(all)) = s.records_list(
        ticketed(1),
        "task",
        b"",
        None,
        0,
        (&mut buf[..], &mut spans[..]),
    ) else {
        panic!("every record");
    };
    assert!(all.records().eq(LISTED));
    let after = all.records().next().expect("a record").0.to_vec();
    let (mut buf, mut spans) = ([0u8; 16], [NO_SPAN; 4]);
    let Poll::Ready(Ok(rest)) = s.records_list(
        ticketed(2),
        "task",
        b"",
        Some(after.as_slice()),
        0,
        (&mut buf[..], &mut spans[..]),
    ) else {
        panic!("the records after the first");
    };
    assert!(rest.records().eq(LISTED[1..].iter().copied()));
    assert_eq!(
        s.records_claim(ticketed(3), "approval", b"k1", 0),
        Poll::Ready(Err(busbar_contract::abi::sdk::ServiceError::Declined(
            Outcome::Refused
        )))
    );
    assert_eq!(
        s.records_claim(ticketed(4), "approval", b"k1", 1),
        Poll::Ready(Ok(true))
    );
    assert_eq!(
        s.records_claim(ticketed(5), "approval", b"k1", 2),
        Poll::Ready(Ok(false))
    );
    let seen: Vec<_> = d
        .route
        .provider
        .scoped
        .lock()
        .unwrap()
        .iter()
        .map(|(who, what, _)| (who.clone(), *what))
        .collect();
    let me = || "double".to_string();
    assert_eq!(
        seen,
        [
            (me(), "records.get"),
            (me(), "records.list"),
            (me(), "records.list"),
            (me(), "records.claim"),
            (me(), "records.claim"),
        ]
    );
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

fn nowhere() -> Waking {
    let r: Arc<dyn WakeRoute> = Arc::new(Route {
        store: Arc::default(),
        provider: Arc::default(),
        wakes: Mutex::default(),
        auth: std::sync::OnceLock::new(),
    });
    Waking {
        route: Arc::downgrade(&r),
        supplier: None,
    }
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
    let first = unsafe { serve(&store, &nowhere(), &h, 0, Some(&into), eight(&runs)) };
    assert_eq!(first.outcome, Outcome::Failed);
    assert_eq!((first.needed_bytes, first.needed_items), (8, 1));
    assert_eq!((first.len, first.items), (0, 0), "nothing written");
    assert_eq!(b, [0; 4]);
    // SAFETY: as above.
    let second = unsafe { serve(&store, &nowhere(), &h, 0, Some(&into), eight(&runs)) };
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
    let short = unsafe { serve(&store, &nowhere(), &h, 0, Some(&into), eight(&runs)) };
    assert_eq!(short.outcome, Outcome::Failed);
    let (mut big, mut s2) = ([0u8; 8], [SPAN; 1]);
    let into = bufs(&mut big, &mut s2);
    // SAFETY: as above.
    let recall = unsafe { serve(&store, &nowhere(), &h, 0, Some(&into), eight(&runs)) };
    assert_eq!(
        (recall.outcome, recall.value, recall.len, recall.items),
        (Outcome::Ready, 1, 8, 1)
    );
    assert_eq!(&big, b"01234567");
    assert_eq!(s2[0].value.len, 8);
    // SAFETY: as above.
    let again = unsafe { serve(&store, &nowhere(), &h, 0, Some(&into), eight(&runs)) };
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
    let anon = crate::dispatch::handle::mint(wake).expect("the host mints a handle");
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
        head: head(
            op::TRUST_VERIFY,
            Ticket::NONE,
            0,
            size_of::<TrustVerifyIn>(),
        ),
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
        head: head(
            op::TRUST_VERIFY,
            Ticket::NONE,
            0,
            size_of::<TrustVerifyIn>(),
        ),
        counterparty: text("peer"),
        payload: blob(b"doc"),
        signatures: no_blob(),
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

fn mint_in(ttl_secs: u64, record: &[u8], buf: &mut [u8]) -> TicketMintIn {
    TicketMintIn {
        head: head(op::TICKET_MINT, Ticket::NONE, 0, size_of::<TicketMintIn>()),
        ttl_secs,
        record: Blob {
            ptr: record.as_ptr(),
            len: record.len(),
            fmt: 0,
            flags: 0,
        },
        into: bufs(buf, &mut []),
    }
}

fn take_in(buf: &mut [u8]) -> TicketTakeIn {
    TicketTakeIn {
        head: head(op::TICKET_TAKE, Ticket::NONE, 0, size_of::<TicketTakeIn>()),
        into: bufs(buf, &mut []),
    }
}

#[test]
fn tickets_reach_the_kernel_with_the_unit_their_crossing_serves() {
    let d = double();
    let mint = |ttl: u64, record: &[u8], buf: &mut [u8]| {
        let i = mint_in(ttl, record, buf);
        let mut o = blank();
        let ret = HOST_SLOTS.ticket_mint.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        (check_ticket_mint(&i, ret, &o), ret.outcome(), o)
    };
    let take = |buf: &mut [u8]| {
        let i = take_in(buf);
        let mut o = blank();
        let ret = HOST_SLOTS.ticket_take.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        (check_ticket_take(&i, ret, &o), ret.outcome(), o)
    };
    let mut buf = [0u8; 16];
    {
        let _unit = serving(Some(7));
        let (checked, outcome, o) = mint(600, b"{\"m\":1}", &mut buf[..]);
        assert_eq!((checked, outcome), (Ok(Filled::Written), Outcome::Ready));
        assert_eq!(
            (&buf[..o.len as usize], o.value),
            (&b"tk_7"[..], 1_700_000_600)
        );
        let (checked, outcome, o) = take(&mut buf[..]);
        assert_eq!((checked, outcome), (Ok(Filled::Written), Outcome::Ready));
        assert_eq!(
            (o.value, &buf[..o.len as usize]),
            (svc::TICKET_TAKEN, &b"rec"[..])
        );
    }
    {
        // A unit a key admitted: NONE, nothing written.
        let _unit = serving(Some(8));
        let (checked, outcome, o) = take(&mut buf[..]);
        assert_eq!((checked.is_ok(), outcome), (true, Outcome::Ready));
        assert_eq!((o.value, o.len), (svc::TICKET_NONE, 0));
    }
    // Out of range: refused before the kernel, nothing written.
    let over = vec![b'x'; svc::MAX_TICKET_RECORD as usize + 1];
    for (ttl, record) in [(0, &b"{}"[..]), (600, &over[..])] {
        let mut out = [0u8; 16];
        let (_, outcome, o) = mint(ttl, record, &mut out[..]);
        assert_eq!(outcome, Outcome::Refused, "ttl {ttl}");
        assert_eq!(error(&o), MINT_OUT_OF_RANGE, "ttl {ttl}");
        assert!(out.iter().all(|x| *x == 0), "nothing written");
    }
    let seen: Vec<(&'static str, String)> = d
        .route
        .provider
        .scoped
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, what, _)| what.starts_with("ticket."))
        .map(|(_, what, arg)| (*what, String::from_utf8(arg.clone()).unwrap()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("ticket.mint", "Some(7) 600 {\"m\":1}".to_string()),
            ("ticket.take", "Some(7)".to_string()),
            ("ticket.take", "Some(8)".to_string()),
        ]
    );
}

/// RED (loader-PL1 #5): a late completion from an op that is over never lands on the next op's
/// handle on the same ticket (THE DESIGN §11.11 H2, §11.12). The first op's service pends and the
/// op ends unredeemed (a deadline `cancel`, or it answered without redeeming); a new op starts on
/// the ticket (the worker forgets the ticket's results at every new op's start) and its handle 0
/// pends too. The first op's completer then answers: it wakes nothing and the new op does not read
/// it; the new op's own completion lands and wakes it.
#[test]
fn a_late_completion_from_an_ended_op_never_lands_on_the_next_ops_handle() {
    let d = double();
    let store = Arc::clone(&d.route.store);
    let dyn_route: Arc<dyn WakeRoute> = d.route.clone();
    let route = Waking {
        route: Arc::downgrade(&dyn_route),
        supplier: None,
    };
    let held: Mutex<Option<Completer>> = Mutex::new(None);
    let pend = || {
        |c: Option<Completer>| {
            *held.lock().unwrap() = c;
            Ran::Later
        }
    };
    let h = head(op::RECORDS_GET, TICKET, 0, 0);
    let (mut b, mut s) = ([0u8; 8], [SPAN; 1]);
    let into = bufs(&mut b, &mut s);
    // SAFETY: the test's own buffers.
    let first = unsafe { serve(&store, &route, &h, 0, Some(&into), pend()) };
    assert_eq!(first.outcome, Outcome::Pending);
    let late = held
        .lock()
        .unwrap()
        .take()
        .expect("the first op's completer");

    // The first op is over; a new op starts on the ticket, and its handle 0 pends.
    store.forget(TICKET);
    // SAFETY: as above.
    let second = unsafe { serve(&store, &route, &h, 0, Some(&into), pend()) };
    assert_eq!(second.outcome, Outcome::Pending);
    let own = held.lock().unwrap().take().expect("the new op's completer");

    late.complete(Stored::ready(7));
    assert!(
        d.route.wakes.lock().unwrap().is_empty(),
        "a completion of an op that is over wakes nothing"
    );
    // SAFETY: as above.
    let resumed = unsafe { serve(&store, &route, &h, 0, Some(&into), |_| panic!("ran twice")) };
    assert_eq!(
        resumed.outcome,
        Outcome::Pending,
        "the new op never reads the ended op's result"
    );

    own.complete(Stored::ready(9));
    assert_eq!(*d.route.wakes.lock().unwrap(), vec![TICKET]);
    // SAFETY: as above.
    let landed = unsafe { serve(&store, &route, &h, 0, Some(&into), |_| panic!("ran twice")) };
    assert_eq!(
        (landed.outcome, landed.value),
        (Outcome::Ready, 9),
        "the new op's own completion lands"
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
        let a = unsafe { serve(&store, &nowhere(), h, 0, Some(&into), eight(&runs)) };
        assert_eq!((a.outcome, a.value), (Outcome::Ready, 1));
    }
    assert_eq!(d.services().held(), 2, "one stored result per (ticket, n)");
    let (mut b, mut s) = ([0u8; 8], [SPAN; 1]);
    let into = bufs(&mut b, &mut s);
    // SAFETY: as above.
    let replay = unsafe { serve(&store, &nowhere(), &heads[0], 0, Some(&into), eight(&runs)) };
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
    let after = unsafe { serve(&store, &nowhere(), &heads[0], 0, Some(&into), eight(&runs)) };
    assert_eq!(after.outcome, Outcome::Ready);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        3,
        "the recycled ticket's old handle runs afresh: no earlier result is read back"
    );
}

fn secret_in(
    kind: &'static str,
    id: &'static str,
    buf: &mut [u8],
    spans: &mut [ItemSpan],
) -> RecordsSecretIn {
    RecordsSecretIn {
        head: head(op::RECORDS_SECRET, TICKET, 0, size_of::<RecordsSecretIn>()),
        kind: text(kind),
        id: text(id),
        into: bufs(buf, spans),
    }
}

fn call_secret(ctx: HostCtx, i: &RecordsSecretIn) -> (RawOutcome, ServiceOut) {
    let mut o = blank();
    let ret = HOST_SLOTS.records_secret.unwrap()(ctx, std::ptr::from_ref(i).cast(), &mut o);
    (ret, o)
}

/// THE DECLARED NEED (ARCHITECT ruling B): `records.secret` serves an instance only the credential
/// kinds its Statement declares. An undeclared kind, and a caller that declares none (any non-auth
/// instance), are REFUSED before the kernel reads anything; a declared kind reaches the kernel and
/// its secret lands in the caller's buffers; ticketless it is refused as any may-pend service is.
/// RED: before the slot, `records.secret` was no slot at all.
#[test]
fn records_secret_serves_only_a_declared_kind() {
    let d = double();
    let (mut buf, mut spans) = (
        [0u8; 16],
        [ItemSpan {
            key: Span { offset: 0, len: 0 },
            value: Span { offset: 0, len: 0 },
        }; 1],
    );
    // A caller that declares no credential kind.
    let i = secret_in("signed", "AKID", &mut buf, &mut spans);
    let (ret, o) = call_secret(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), UNDECLARED_KIND);
    assert!(d.route.provider.secrets.lock().unwrap().is_empty());

    // A caller that declares `signed`.
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let dyn_route: Arc<dyn WakeRoute> = d.route.clone();
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    assert!(wake
        .credential_kinds
        .set(vec!["signed".to_string()])
        .is_ok());
    let reader = crate::dispatch::handle::mint(wake).expect("the host mints a handle");
    let other = secret_in("bearer", "AKID", &mut buf, &mut spans);
    let (ret, o) = call_secret(reader, &other);
    assert_eq!(ret.outcome(), Outcome::Refused, "an undeclared kind");
    assert_eq!(error(&o), UNDECLARED_KIND);
    assert!(d.route.provider.secrets.lock().unwrap().is_empty());

    let mut ticketless = secret_in("signed", "AKID", &mut buf, &mut spans);
    ticketless.head.handle.ticket = Ticket::NONE;
    let (ret, o) = call_secret(reader, &ticketless);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), UNTICKETED);
    assert!(d.route.provider.secrets.lock().unwrap().is_empty());

    let i = secret_in("signed", "AKID", &mut buf, &mut spans);
    let (ret, o) = call_secret(reader, &i);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert_eq!(o.value, svc::SECRET_LIVE);
    assert!(svc::check_records_secret(&i, ret, &o).is_ok());
    assert_eq!(&buf[..6], b"s3cr3t");
    assert_eq!(
        d.route.provider.secrets.lock().unwrap().as_slice(),
        &["signed:AKID".to_string()]
    );
}

/// The work family reaches the kernel as its caller, with the unit its crossing serves, and a
/// record past its cap is refused before the kernel sees it.
#[test]
fn the_work_family_reaches_the_kernel_with_the_unit_its_crossing_serves() {
    let d = double();
    let mut buf = [0u8; 32];
    let mut spans = [ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    }; 1];
    let record = b"rec";
    let open = svc::WorkOpenIn {
        head: head(op::WORK_OPEN, TICKET, 0, size_of::<svc::WorkOpenIn>()),
        kind: text("job"),
        record: blob(record),
        into: bufs(&mut buf, &mut spans),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(7));
        HOST_SLOTS.work_open.unwrap()(d.ctx, std::ptr::from_ref(&open).cast(), &mut o)
    };
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, 5));
    assert_eq!(&buf[..3], b"ref");
    assert!(svc::check_work_open(&open, ret, &o).is_ok());

    let long = vec![0u8; svc::MAX_WORK_RECORD + 1];
    let too_long = svc::WorkOpenIn {
        head: head(op::WORK_OPEN, TICKET, 1, size_of::<svc::WorkOpenIn>()),
        record: blob(&long),
        ..open
    };
    let mut o = blank();
    let ret = HOST_SLOTS.work_open.unwrap()(d.ctx, std::ptr::from_ref(&too_long).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), WORK_RECORD_TOO_LONG);

    let find = svc::WorkFindIn {
        head: head(op::WORK_FIND, TICKET, 2, size_of::<svc::WorkFindIn>()),
        reference: text("ref"),
        into: bufs(&mut [], &mut []),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(8));
        HOST_SLOTS.work_find.unwrap()(d.ctx, std::ptr::from_ref(&find).cast(), &mut o)
    };
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, svc::ABSENT));
    assert!(svc::check_work_find(&find, ret, &o).is_ok());

    let settle = svc::WorkSettleIn {
        head: head(op::WORK_SETTLE, TICKET, 3, size_of::<svc::WorkSettleIn>()),
        handle: 5,
        record: blob(b"done"),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(6));
        HOST_SLOTS.work_settle.unwrap()(d.ctx, std::ptr::from_ref(&settle).cast(), &mut o)
    };
    assert_eq!(ret.outcome(), Outcome::Ready);

    let resume = svc::WorkResumeIn {
        head: head(op::WORK_RESUME, TICKET, 4, size_of::<svc::WorkResumeIn>()),
        handle: 5,
        into: bufs(&mut [], &mut []),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(9));
        HOST_SLOTS.work_resume.unwrap()(d.ctx, std::ptr::from_ref(&resume).cast(), &mut o)
    };
    assert_eq!(ret.outcome(), Outcome::Ready);

    let seen: Vec<(&str, String)> = d
        .route
        .provider
        .scoped
        .lock()
        .unwrap()
        .iter()
        .map(|(who, what, arg)| {
            assert_eq!(who, "double");
            (*what, String::from_utf8(arg.clone()).unwrap())
        })
        .collect();
    assert_eq!(
        seen,
        vec![
            ("work.open", "Some(7) job rec".to_string()),
            ("work.find", "Some(8) ref".to_string()),
            ("work.settle", "Some(6) 5 done".to_string()),
            ("work.resume", "Some(9) 5".to_string()),
        ]
    );
}

/// `unit.nest` reaches the kernel as its caller with the unit its crossing serves, and delivers the
/// child's whole reply into the caller's buffers.
#[test]
fn unit_nest_reaches_the_kernel_with_the_unit_its_crossing_serves() {
    let d = double();
    let mut buf = [0u8; 8];
    let mut spans = [ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    }; 2];
    let body = b"ask";
    let i = svc::UnitNestIn {
        head: head(op::UNIT_NEST, TICKET, 0, size_of::<svc::UnitNestIn>()),
        verb: text("POST"),
        target: text("/child"),
        body: blob(body),
        into: bufs(&mut buf, &mut spans),
    };
    let mut o = blank();
    let ret = {
        let _unit = serving(Some(11));
        HOST_SLOTS.unit_nest.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o)
    };
    assert_eq!((ret.outcome(), o.value, o.items), (Outcome::Ready, 201, 1));
    assert_eq!(&buf[..5], b"child");
    assert!(svc::check_unit_nest(&i, ret, &o).is_ok());
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().as_slice(),
        &[(
            "double".to_string(),
            "unit.nest",
            b"Some(11) POST /child ask".to_vec()
        )]
    );
}

/// A `disk.append` `in` naming `key`, appending `bytes`, its result into `result`.
fn disk_in(
    key: &'static str,
    bytes: &'static [u8],
    seq: u32,
    result: &mut svc::DiskWritten,
) -> svc::DiskAppendIn {
    svc::DiskAppendIn {
        head: head(op::DISK_APPEND, TICKET, seq, size_of::<svc::DiskAppendIn>()),
        dest_key: AbiStr {
            ptr: key.as_ptr(),
            len: key.len(),
        },
        bytes: Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
            flags: 0,
        },
        result: std::ptr::from_mut(result),
    }
}

fn call_disk(ctx: HostCtx, i: &svc::DiskAppendIn) -> (RawOutcome, ServiceOut) {
    let mut o = blank();
    let ret = HOST_SLOTS.disk_append.unwrap()(ctx, std::ptr::from_ref(i).cast(), &mut o);
    (ret, o)
}

fn blank_written() -> svc::DiskWritten {
    svc::DiskWritten {
        size: 0,
        rotated: 0,
        faults: 0,
        _reserved: [0; 2],
        written: 0,
    }
}

/// THE DESTINATION RULE (THE DESIGN §11.12 `disk.append`): an instance appends only to the
/// destinations its manifest declares (granted by the opener), at the path its settings bound; a key
/// it was not granted, or one its settings leave unset, is never opened: FAILED at the
/// `DISK_OPEN_FAILED` step in the host's words before the kernel sees anything, the step a sink
/// reports as a file it could not open (1.5.5's BUSBAR-7074).
/// A granted, bound key reaches the kernel's disk lane with the bound path and the bytes unchanged,
/// and the lane's report lands in the caller's result slot (READY: the whole of the bytes; FAILED:
/// the step in `value`, nothing written). RED: before the slot, `disk.append` was no slot at all.
#[test]
fn disk_append_writes_only_to_a_granted_bound_destination() {
    let d = double();
    let mut w = blank_written();
    // The double's instance was granted no destination.
    let i = disk_in("path", b"line\n", 0, &mut w);
    let (ret, o) = call_disk(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Failed);
    assert_eq!(o.value, svc::DISK_OPEN_FAILED);
    assert_eq!(error(&o), NO_DESTINATION);
    assert!(
        svc::check_disk_append(&i, ret, &o).is_ok(),
        "the open-step failure is a well-formed FAILED answer"
    );
    assert!(d.route.provider.appended.lock().unwrap().is_empty());

    // An instance granted `path`, its settings binding it.
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let dyn_route: Arc<dyn WakeRoute> = d.route.clone();
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    assert!(wake.destinations.set(vec!["path".to_string()]).is_ok());
    let ctx = crate::dispatch::handle::mint(wake).expect("the host mints a handle");
    // Granted, not yet bound (its settings set no path): refused.
    let (ret, o) = call_disk(ctx, &disk_in("path", b"line\n", 0, &mut w));
    assert_eq!(ret.outcome(), Outcome::Failed);
    assert_eq!(o.value, svc::DISK_OPEN_FAILED);
    assert_eq!(error(&o), NO_DESTINATION);
    let bound = DiskDest {
        key: "path".into(),
        path: "/var/log/busbar/requests.jsonl".into(),
        rotate_at: Some(1024 * 1024),
        rotate: busbar_contract::services::DiskRotate::Truncate,
    };
    wake.bound.write().unwrap().push(bound.clone());
    // A key the instance was not granted, even with a path under it.
    let (ret, o) = call_disk(ctx, &disk_in("other", b"line\n", 0, &mut w));
    assert_eq!(ret.outcome(), Outcome::Failed);
    assert_eq!(o.value, svc::DISK_OPEN_FAILED);
    assert_eq!(error(&o), NO_DESTINATION);
    assert!(d.route.provider.appended.lock().unwrap().is_empty());

    let i = disk_in("path", b"line\n", 0, &mut w);
    let (ret, o) = call_disk(ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready);
    assert!(svc::check_disk_append(&i, ret, &o).is_ok());
    assert_eq!((w.rotated, w.faults, w.written), (svc::DISK_ROTATED, 0, 5));
    assert_eq!(
        d.route.provider.appended.lock().unwrap().as_slice(),
        &[(bound, b"line\n".to_vec())]
    );

    // The lane's FAILED report: the step in `value`, nothing appended, the rotation reported.
    wake.bound.write().unwrap()[0].path = "/nowhere/requests.fail".into();
    let mut w = blank_written();
    let i = disk_in("path", b"line\n", 1, &mut w);
    let (ret, o) = call_disk(ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Failed);
    assert_eq!(o.value, svc::DISK_OPEN_FAILED);
    assert_eq!(error(&o), "No such file or directory");
    assert!(svc::check_disk_append(&i, ret, &o).is_ok());
    assert_eq!((w.rotated, w.written), (svc::DISK_ROTATED, 0));
}

/// `trust.sight` WITH `TRUST_UNREACHABLE` (ARCHITECT 2026-10-06): the plane could not reach the
/// counterparty; the kernel answers its last verdict and nothing is sighted (the hash is unread,
/// and may be empty). RED: an outcome the vocabulary does not hold is FAULT, and reaches nothing.
#[test]
fn an_unreachable_sighting_reaches_the_last_verdict_and_an_unknown_outcome_is_fault() {
    let d = double();
    let sight = |outcome: u32| svc::TrustSightIn {
        head: head(op::TRUST_SIGHT, TICKET, 0, size_of::<svc::TrustSightIn>()),
        counterparty: text("peer"),
        catalogue_hash: text(""),
        outcome,
        _outcome_reserved: 0,
    };
    let call = |i: &svc::TrustSightIn| {
        let mut o = blank();
        let ret = HOST_SLOTS.trust_sight.unwrap()(d.ctx, std::ptr::from_ref(i).cast(), &mut o);
        (ret, o)
    };
    let unreached = sight(svc::TRUST_UNREACHABLE);
    let (ret, o) = call(&unreached);
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, svc::TRUST_SAME));
    assert!(svc::check_trust_sight(&unreached, ret, &o).is_ok());
    let (ret, _) = call(&sight(svc::TRUST_UNREACHABLE + 1));
    assert_eq!(ret.outcome(), Outcome::Fault);
    let seen = d.route.provider.scoped.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![("double".to_string(), "trust.unreached", b"peer".to_vec())]
    );
}

/// The handle of an unticketed op's `seq`th service call.
const fn unticketed(seq: u32) -> CompletionHandle {
    CompletionHandle {
        ticket: Ticket::NONE,
        seq,
        _reserved: 0,
    }
}

/// `trust.decide` OVER THE SDK (ARCHITECT 2026-10-06): the key, the expected fingerprint and the
/// decision reach the kernel as the caller's, with no ticket; RED: a decision the vocabulary does
/// not hold is FAULT and reaches nothing.
#[test]
fn trust_decide_reaches_the_kernel_and_an_unknown_decision_is_fault() {
    let d = double();
    let s = sdk(&d);
    assert_eq!(
        s.trust_decide(unticketed(0), "peer", Some("t"), Some("d1"), true),
        Ok(svc::TRUST_DECIDED_SERVING)
    );
    assert_eq!(
        s.trust_decide(unticketed(1), "peer", None, None, false),
        Ok(svc::TRUST_DECIDED_SERVING)
    );
    let bad = svc::TrustDecideIn {
        head: head(
            op::TRUST_DECIDE,
            Ticket::NONE,
            0,
            size_of::<svc::TrustDecideIn>(),
        ),
        counterparty: text("peer"),
        item: text(""),
        expected: text(""),
        decision: svc::TRUST_DECIDE_REVOKE + 1,
        _reserved: 0,
    };
    let mut o = blank();
    let ret = HOST_SLOTS.trust_decide.unwrap()(d.ctx, std::ptr::from_ref(&bad).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Fault);
    let seen = d.route.provider.scoped.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            (
                "double".to_string(),
                "trust.decide",
                b"peer/t@d1 true".to_vec()
            ),
            (
                "double".to_string(),
                "trust.decide",
                b"peer/-@- false".to_vec()
            ),
        ]
    );
}

/// `trust.state` OVER THE SDK: the counterparty's state and its items, read through the
/// caller's buffers under the short-buffer rule (a short buffer is `Short`, the re-call on the same
/// handle reads the stored answer), and the kernel was asked once.
#[test]
fn the_sdk_trust_state_reads_the_kernels_items_under_the_short_buffer_rule() {
    use busbar_contract::abi::sdk::{ServiceError, TrustItem};
    let d = double();
    let s = sdk(&d);
    let (mut buf, mut spans) = ([0u8; 4], [NO_SPAN; 4]);
    assert!(matches!(
        s.trust_state(ticketed(0), "peer", &mut buf, &mut spans),
        Err(ServiceError::Short { .. })
    ));
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 4]);
    let state = s
        .trust_state(ticketed(0), "peer", &mut buf, &mut spans)
        .expect("the stored answer");
    assert_eq!(state.state, svc::KEY_SAME);
    assert_eq!(
        state.items().collect::<Vec<_>>(),
        vec![TrustItem {
            item: "t",
            state: "drifted",
            approved: Some("d1"),
            seen: Some("d2"),
        }]
    );
    let seen = d.route.provider.scoped.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![("double".to_string(), "trust.state", b"peer".to_vec())]
    );
}

/// `trust.state` WITH AN ALL-ZERO `in`: it names no room, so the item the kernel answers is a
/// SHORT answer, FAILED with the full size named (the short-buffer rule), never READY.
#[test]
fn an_all_zero_trust_state_in_is_a_short_answer() {
    let d = double();
    let mut raw = [0u64; 32];
    let h = head(op::TRUST_STATE, Ticket::NONE, 0, size_of_val(&raw));
    // SAFETY: the head fits the buffer's start.
    unsafe { raw.as_mut_ptr().cast::<ServiceHead>().write_unaligned(h) };
    let mut o = blank();
    let ret = HOST_SLOTS.trust_state.unwrap()(d.ctx, raw.as_ptr().cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Failed);
    assert!(
        o.needed_bytes > 0 && o.needed_items == 1,
        "the full size is named"
    );
}

/// The families the double's `snapshot.read` answers: every shape the scrape layout carries (a
/// labelled histogram's legs, a family with help and unit, one with neither, one with no samples).
fn snapshot_families() -> Vec<busbar_contract::export_calls::Family> {
    use busbar_contract::abi::export::{
        SCRAPE_KIND_COUNTER, SCRAPE_KIND_GAUGE, SCRAPE_KIND_HISTOGRAM,
    };
    use busbar_contract::export_calls::{Family, Sample};
    let sample = |name: &str, labels: &[(&str, &str)], value: &str| Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        value: value.into(),
    };
    vec![
        Family {
            name: "x_requests_total".into(),
            help: None,
            unit: None,
            kind: SCRAPE_KIND_COUNTER,
            samples: vec![sample(
                "x_requests_total",
                &[("hook", "a\\\"b"), ("ok", "1")],
                "3",
            )],
        },
        Family {
            name: "x_depth".into(),
            help: Some("queue depth".into()),
            unit: Some("items".into()),
            kind: SCRAPE_KIND_GAUGE,
            samples: Vec::new(),
        },
        Family {
            name: "x_seconds".into(),
            help: Some(String::new()),
            unit: None,
            kind: SCRAPE_KIND_HISTOGRAM,
            samples: vec![
                sample("x_seconds_bucket", &[("le", "0.5")], "1"),
                sample("x_seconds_bucket", &[("le", "+Inf")], "2"),
                sample("x_seconds_sum", &[], "0.75"),
                sample("x_seconds_count", &[], "2"),
            ],
        },
    ]
}

/// THE HOST SNAPSHOT SERVICE through the SDK, ticketless as an export `serve` calls it: a short
/// buffer earns the bytes the layout needs; the re-call reads every family back exactly as the
/// kernel answered it, the scope reaching the kernel as the caller's; NOT READY is `None`, never an
/// empty snapshot.
#[test]
fn snapshot_read_lays_the_families_out_in_the_callers_buffer() {
    use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
    use busbar_contract::abi::sdk::ServiceError;
    let d = double();
    let none = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };
    let services = sdk(&d);
    let mut small = [0u64; 4];
    let needed = match services.snapshot_read(none, SNAPSHOT_SCOPE_HOOKS, &mut small) {
        Err(ServiceError::Short { bytes, items: 0 }) => bytes,
        other => panic!("a short buffer earns its size: {other:?}"),
    };
    let mut buf = vec![0u64; usize::try_from(needed).unwrap().div_ceil(8)];
    let read = services
        .snapshot_read(none, SNAPSHOT_SCOPE_HOOKS, &mut buf)
        .expect("the re-call reads");
    assert_eq!(read, Some(snapshot_families()), "read back exactly");
    d.route
        .provider
        .snapshot_not_ready
        .store(true, Ordering::Relaxed);
    assert_eq!(
        services.snapshot_read(none, SNAPSHOT_SCOPE_WHOLE, &mut buf),
        Ok(None),
        "not ready is NONE, never an empty success"
    );
    let seen: Vec<_> = d
        .route
        .provider
        .scoped
        .lock()
        .unwrap()
        .iter()
        .map(|(i, w, a)| (i.clone(), *w, String::from_utf8_lossy(a).into_owned()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("double".to_string(), "snapshot.read", "1".to_string()),
            ("double".to_string(), "snapshot.read", "1".to_string()),
            ("double".to_string(), "snapshot.read", "0".to_string()),
        ]
    );
}

/// RED: an unknown scope, or a buffer without the layout's alignment, is FAULT before the kernel
/// is asked.
#[test]
fn snapshot_read_refuses_an_unknown_scope_or_a_misaligned_buffer() {
    use busbar_contract::abi::host::service::{SnapshotReadIn, SNAPSHOT_SCOPES};
    let d = double();
    let mut words = [0u64; 512];
    let at = words.as_mut_ptr().cast::<u8>();
    let call = |scope: u32, buf: *mut u8, cap: usize| {
        let i = SnapshotReadIn {
            head: head(
                op::SNAPSHOT_READ,
                Ticket::NONE,
                0,
                size_of::<SnapshotReadIn>(),
            ),
            scope,
            _reserved: 0,
            into: ServiceBufs {
                buf,
                cap,
                spans: std::ptr::null_mut(),
                spans_cap: 0,
            },
        };
        let mut o = blank();
        HOST_SLOTS.snapshot_read.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o).outcome()
    };
    assert_eq!(call(SNAPSHOT_SCOPES, at, 4096), Outcome::Fault);
    assert_eq!(call(0, at.wrapping_add(1), 4095), Outcome::Fault);
    assert_eq!(call(0, at, 4096), Outcome::Ready);
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().len(),
        1,
        "only the well-formed call reached the kernel"
    );
}

/// #74, THE UNTRUSTED-ABI HALF: a context the host did not mint is refused before it names an
/// instance. The service answers as it answers no context and the wake wakes nothing; the minted
/// context does both (the control). It used to be an address the host read through, whatever the
/// plugin handed back. (The counting is `handle_tests`', on a latch of its own.)
#[test]
fn a_forged_context_is_refused_before_it_names_an_instance() {
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
    let woken = Ticket {
        slot: 3,
        generation: 1,
    };
    let tag_bit = 1u64 << crate::dispatch::handle::HANDLE_ID_BITS;
    for forged in [
        HostCtx {
            handle: d.ctx.handle ^ tag_bit,
        },
        HostCtx {
            handle: d.ctx.handle ^ 1,
        },
        // The raw address of the very entry the handle names: the old shape of a context.
        HostCtx {
            handle: std::ptr::from_ref(crate::dispatch::handle::resolve(d.ctx).unwrap()) as usize
                as u64,
        },
    ] {
        let mut o = blank();
        let ret = HOST_SLOTS.clock_now.unwrap()(forged, std::ptr::from_ref(&i).cast(), &mut o);
        assert_eq!(ret.outcome(), Outcome::Refused, "{forged:?}");
        crate::dispatch::ticket::host_wake(forged, woken);
        assert!(
            d.route.wakes.lock().unwrap().is_empty(),
            "a forged context woke a ticket: {forged:?}"
        );
    }
    let mut o = blank();
    let ret = HOST_SLOTS.clock_now.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready);
    crate::dispatch::ticket::host_wake(d.ctx, woken);
    assert_eq!(*d.route.wakes.lock().unwrap(), vec![woken]);
}

/// RED (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
/// validated before it is formed"; audit PL1 #1): a service's `in` string or blob stated over the
/// hard byte maximum (`u32::MAX`) is refused before any slice is formed or copied, as NULL with a
/// length is. Run in a child: a copy past the caller's eight bytes kills the process.
#[test]
fn red_a_service_length_over_the_byte_cap_is_refused_before_any_copy() {
    crate::dispatch_tests::assert_child_passes(
        "red_a_service_length_over_the_byte_cap_is_refused_before_any_copy",
        "a service length over the byte cap was copied",
        oversize_service_lengths_child,
    );
}

/// The child half of the test above, in a process of its own.
fn oversize_service_lengths_child() {
    let b = [7_u8; 8];
    let past = u32::MAX as usize + 1;
    let s = AbiStr {
        ptr: b.as_ptr(),
        len: past,
    };
    assert!(bytes_of(s, "test.bytes").is_none(), "a string over the cap");
    assert!(text_of(s, "test.text").is_none(), "a text over the cap");
    let blob = Blob {
        len: past,
        ..blob_over(&b)
    };
    assert!(blob_of(blob, "test.blob").is_none(), "a blob over the cap");
    assert_eq!(bytes_of(over(&b), "test.bytes"), Some(b.to_vec()));
}

/// A caller's `out` lent in 96 bytes, stating `size`: every byte past the size field is `0xAA`, so
/// a write past what the caller stated shows.
#[repr(C, align(8))]
struct LentOut([u8; 96]);

impl LentOut {
    fn stating(size: u32) -> Self {
        let mut b = [0xAA_u8; 96];
        b[..4].copy_from_slice(&size.to_ne_bytes());
        Self(b)
    }

    fn out(&mut self) -> *mut busbar_contract::abi::host::service::ServiceOut {
        self.0.as_mut_ptr().cast()
    }

    /// Whether every byte from `from` on is still the caller's.
    fn untouched_from(&self, from: usize) -> bool {
        self.0[from..].iter().all(|b| *b == 0xAA)
    }
}

/// RED (Q128 kernel-scope MEDIUM, the host service frame): the host writes a caller's `out` only as far
/// as the caller STATED it (`min(out.size, its own)`), and refuses an `out` stated below the first
/// `ServiceOut` before the service runs, writing none of it, so a `ServiceOut` may grow by appending
/// and an older caller's smaller one is never overrun. RED before: the frame wrote a whole
/// `ServiceOut` over whatever the caller lent.
#[test]
fn red_the_host_service_frame_writes_no_further_than_the_out_the_caller_stated() {
    use busbar_contract::abi::host::service::SERVICE_OUT_V1;
    use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
    let mut lent = LentOut::stating(32);
    let raw: RawOutcome = framed(std::ptr::null(), lent.out(), 0, 0, |_| {
        unreachable!("a NULL `in` never reaches the body")
    });
    assert_eq!(raw.outcome(), Outcome::Refused, "a short `out` was served");
    assert!(lent.untouched_from(4), "a short `out` was written");
    let mut lent = LentOut::stating(SERVICE_OUT_V1 as u32);
    let raw: RawOutcome = framed(std::ptr::null(), lent.out(), 0, 0, |_| {
        unreachable!("a NULL `in` never reaches the body")
    });
    assert_eq!(raw.outcome(), Outcome::Fault, "a NULL `in` is FAULT");
    assert!(
        lent.untouched_from(SERVICE_OUT_V1),
        "the host wrote past the `out` stated"
    );
    assert_eq!(lent.0[5], 0, "`exited` is written zero by every frame");
}

// ── the host auth handle ──────────────────────────────────────────────────────────────────────

use busbar_contract::abi::auth::{FieldSpan, POINT_HEAD};
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthCallIn, AuthRef, HeadView, RefusalAnswer, UnitHandInIn, UnitRef, UnitRefuseIn,
    LINE_NONE, REFUSE_NO_ROUTE,
};

use crate::dispatch::auth_handle::{
    generation, mint_auth_ref, mint_unit_ref, verify_auth_ref, verify_unit_ref, RefRefused,
    REF_NOT_MINTED,
};

/// The owner a double's refs are minted for: its instance identity.
fn owner(d: &Double) -> u64 {
    crate::dispatch::handle::instance_id(d.ctx).0
}

fn get_view() -> HeadView {
    HeadView {
        method: text("GET"),
        target: text("/v1"),
        authority: text("a.example"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        fields: std::ptr::null(),
        fields_len: 0,
        scheme: busbar_contract::abi::host::service::SCHEME_SECURE,
        _scheme_reserved: [0; 7],
    }
}

fn no_blob() -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: 0,
        flags: 0,
    }
}

fn answer_slot() -> AuthAnswer {
    AuthAnswer {
        size: 0,
        flow: 0,
        unit: UnitRef::NONE,
    }
}

fn auth_call_in(auth: AuthRef, answer: &mut AuthAnswer) -> AuthCallIn {
    AuthCallIn {
        head: head(op::AUTH_CALL, TICKET, 0, size_of::<AuthCallIn>()),
        auth,
        unit: UnitRef::NONE,
        point: POINT_HEAD,
        _reserved: 0,
        conn: 1,
        stream: 1,
        request: get_view(),
        body: no_blob(),
        buf: std::ptr::null_mut(),
        cap: 0,
        spans: std::ptr::null_mut::<FieldSpan>(),
        spans_cap: 0,
        answer,
    }
}

fn call_auth(ctx: HostCtx, i: &AuthCallIn) -> (RawOutcome, ServiceOut) {
    let mut o = blank();
    let ret = HOST_SLOTS.auth_call.unwrap()(ctx, std::ptr::from_ref(i).cast(), &mut o);
    (ret, o)
}

/// RED (#65, #74): a ref minted for owner A, presented by owner B, is refused before anything
/// else; the same ref presented by A passes the ref check (and reaches "not yet served").
#[test]
fn an_auth_ref_minted_for_another_owner_is_refused() {
    let (a, b) = (double(), double());
    assert_ne!(owner(&a), owner(&b));
    let r = mint_auth_ref(owner(&a), generation(), 5).expect("minted");
    let mut slot = answer_slot();
    let i = auth_call_in(r, &mut slot);
    let (ret, o) = call_auth(b.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), REF_NOT_MINTED);
    let (ret, o) = call_auth(a.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(
        error(&o),
        AUTH_HANDLE_NOT_SERVED,
        "the owner's own ref passes"
    );
    assert_eq!(
        verify_auth_ref(owner(&b), generation(), &r),
        Err(RefRefused::NotMinted)
    );
}

/// RED (#74): a ref of an older generation is refused against the current one.
#[test]
fn an_auth_ref_of_an_older_generation_is_refused() {
    let d = double();
    let stale = mint_auth_ref(owner(&d), generation().wrapping_sub(1), 5).expect("minted");
    let mut slot = answer_slot();
    let (ret, o) = call_auth(d.ctx, &auth_call_in(stale, &mut slot));
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), REF_NOT_MINTED);
    let r = mint_auth_ref(owner(&d), 4, 5).expect("minted");
    assert_eq!(verify_auth_ref(owner(&d), 4, &r), Ok(5));
    assert_eq!(
        verify_auth_ref(owner(&d), 5, &r),
        Err(RefRefused::NotMinted)
    );
}

/// RED (#74): a ref with any one bit of its mac flipped is refused; the ref as minted passes.
#[test]
fn an_auth_ref_with_one_mac_bit_flipped_is_refused() {
    let d = double();
    let r = mint_auth_ref(owner(&d), generation(), 5).expect("minted");
    assert_eq!(verify_auth_ref(owner(&d), generation(), &r), Ok(5));
    for bit in 0..64 {
        let forged = AuthRef {
            mac: r.mac ^ (1 << bit),
            ..r
        };
        assert_eq!(
            verify_auth_ref(owner(&d), generation(), &forged),
            Err(RefRefused::NotMinted),
            "bit {bit}"
        );
    }
    let forged = AuthRef {
        mac: r.mac ^ 1,
        ..r
    };
    let mut slot = answer_slot();
    let (ret, o) = call_auth(d.ctx, &auth_call_in(forged, &mut slot));
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), REF_NOT_MINTED);
    // Another id under the same mac is no better.
    let moved = AuthRef { id: 6, ..r };
    assert_eq!(
        verify_auth_ref(owner(&d), generation(), &moved),
        Err(RefRefused::NotMinted)
    );
    assert_eq!(
        verify_auth_ref(owner(&d), generation(), &AuthRef::NONE),
        Err(RefRefused::Absent)
    );
}

/// RED (exact sizes): each auth-handle `in` presented one field short (or longer) is refused
/// before any field of it is read; a ticketless `auth.call` is refused as a may-pend service.
#[test]
fn an_auth_handle_in_one_field_short_is_refused() {
    let d = double();
    let r = mint_auth_ref(owner(&d), generation(), 5).expect("minted");
    let mut slot = answer_slot();
    let exact = size_of::<AuthCallIn>() as u32;
    for size in [exact - 8, exact + 8] {
        let mut i = auth_call_in(r, &mut slot);
        i.head.size = size;
        let (ret, o) = call_auth(d.ctx, &i);
        assert_eq!(ret.outcome(), Outcome::Refused, "{size}");
        assert_eq!(error(&o), NOT_EXACT, "{size}");
    }
    let mut i = auth_call_in(r, &mut slot);
    i.head.handle.ticket = Ticket::NONE;
    assert_eq!(error(&call_auth(d.ctx, &i).1), UNTICKETED);

    let mut hand = UnitHandInIn {
        head: head(
            op::UNIT_HAND_IN,
            Ticket::NONE,
            0,
            size_of::<UnitHandInIn>() - 8,
        ),
        auth: r,
        unit: UnitRef::NONE,
        line: 1,
        _reserved: 0,
        conn: 1,
        stream: 1,
        request: get_view(),
        answer: &mut slot,
    };
    let mut o = blank();
    let f = HOST_SLOTS.unit_hand_in.unwrap();
    assert_eq!(
        f(d.ctx, std::ptr::from_ref(&hand).cast(), &mut o).outcome(),
        Outcome::Refused
    );
    assert_eq!(error(&o), NOT_EXACT);
    hand.head.size = size_of::<UnitHandInIn>() as u32;
    let mut o = blank();
    f(d.ctx, std::ptr::from_ref(&hand).cast(), &mut o);
    assert_eq!(error(&o), AUTH_HANDLE_NOT_SERVED, "the exact size passes");

    let mut refusal = RefusalAnswer {
        size: 0,
        status: 0,
        _reserved: 0,
        fields: std::ptr::null(),
        fields_len: 0,
        body: no_blob(),
    };
    let mut refuse = UnitRefuseIn {
        head: head(
            op::UNIT_REFUSE,
            Ticket::NONE,
            0,
            size_of::<UnitRefuseIn>() - 8,
        ),
        unit: UnitRef::NONE,
        cause: REFUSE_NO_ROUTE,
        line: LINE_NONE,
        conn: 1,
        stream: 1,
        answer: &mut refusal,
        request: get_view(),
    };
    let f = HOST_SLOTS.unit_refuse.unwrap();
    let mut o = blank();
    f(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
    assert_eq!(error(&o), NOT_EXACT);
    refuse.head.size = size_of::<UnitRefuseIn>() as u32;
    let mut o = blank();
    f(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
    assert_eq!(error(&o), AUTH_HANDLE_NOT_SERVED, "the exact size passes");
    // A unit the host cannot verify is refused, fail closed.
    refuse.cause = svc::REFUSE_STOPPED;
    refuse.line = 1;
    refuse.unit = UnitRef { id: 3, mac: 9 };
    let mut o = blank();
    f(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
    assert_eq!(error(&o), UNIT_UNVERIFIED);
    // A malformed `in` of the exact size is refused after its refs.
    refuse.unit = UnitRef::NONE;
    refuse.cause = 0;
    let mut o = blank();
    f(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
    assert_eq!(error(&o), AUTH_IN_MALFORMED);
}

/// RED (#74): a unit verifies only for its own request's secret, generation, owner and line, with
/// the mac as minted; a replayed (another request's secret) or cross-line unit is refused.
#[test]
fn a_unit_ref_verifies_only_for_its_own_request() {
    let (secret, other) = ([1, 2], [1, 3]);
    let u = mint_unit_ref(secret, 7, 40, 2, 99).expect("minted");
    assert_eq!(verify_unit_ref(secret, 7, 40, 2, &u), Ok(99));
    assert_eq!(
        verify_unit_ref(other, 7, 40, 2, &u),
        Err(RefRefused::NotMinted),
        "another request's"
    );
    assert_eq!(
        verify_unit_ref(secret, 8, 40, 2, &u),
        Err(RefRefused::NotMinted)
    );
    assert_eq!(
        verify_unit_ref(secret, 7, 41, 2, &u),
        Err(RefRefused::NotMinted)
    );
    assert_eq!(
        verify_unit_ref(secret, 7, 40, 3, &u),
        Err(RefRefused::NotMinted)
    );
    let flipped = UnitRef {
        mac: u.mac ^ (1 << 63),
        ..u
    };
    assert_eq!(
        verify_unit_ref(secret, 7, 40, 2, &flipped),
        Err(RefRefused::NotMinted)
    );
    assert_eq!(
        verify_unit_ref(secret, 7, 40, 2, &UnitRef::NONE),
        Err(RefRefused::Absent)
    );
    assert!(mint_unit_ref(secret, 7, 40, 2, 0).is_none());
    assert!(mint_auth_ref(40, 7, 0).is_none());
}

/// RED (the upstream's scheme, rule 1: a zero never grants): an `auth.call` whose request view
/// declares no scheme (a zeroed view's code) is REFUSED with its declared refusal, before the
/// auth would run, and never read as plain; the same call with the scheme declared passes.
#[test]
fn an_auth_call_whose_view_declares_no_scheme_is_refused_by_name() {
    use busbar_contract::abi::host::service::{
        SCHEME_PLAIN, SCHEME_UNDECLARED, SCHEME_UNDECLARED_REFUSED,
    };
    let d = double();
    let r = mint_auth_ref(owner(&d), generation(), 5).expect("minted");
    let mut slot = answer_slot();
    let mut i = auth_call_in(r, &mut slot);
    i.request.scheme = SCHEME_UNDECLARED;
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&o), SCHEME_UNDECLARED_REFUSED);
    i.request.scheme = SCHEME_PLAIN;
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(
        error(&o),
        AUTH_HANDLE_NOT_SERVED,
        "a declared scheme passes"
    );
}

/// Whether `d`'s instance is still served: a ticketless `clock.now` through its context. A
/// quarantined instance's context names nothing, so the host answers it REFUSED.
fn still_served(d: &Double) -> bool {
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
    HOST_SLOTS.clock_now.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o).outcome()
        == Outcome::Ready
}

/// RED (status row 189, THE DESIGN §11.2: a host answer belongs to exactly one request): a handle
/// on a ticket is bound to the service it was first used for. A fleet plugin reused handle 0 of
/// one ticket for its record load and then for `entitlement.check`, and the host handed the check
/// the stored answer of the first service. Here the first service is `records.claim`, whose
/// CLAIM_WON is the same number as ENTITLED: the stale answer reads as "entitled". The reuse is a
/// plugin fault: answered FAULT, the second service never reaches the kernel, never the first
/// service's answer, and the instance is quarantined as a forged context is.
#[test]
fn a_handle_reused_for_another_service_is_fault_and_quarantines_never_the_stale_answer() {
    let d = double();
    let (ret, o) = call_claim(&d, &claim_in(1));
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, svc::CLAIM_WON));
    assert!(still_served(&d));

    let check = EntitlementCheckIn {
        head: head(
            op::ENTITLEMENT_CHECK,
            TICKET,
            0,
            size_of::<EntitlementCheckIn>(),
        ),
        target: text("item:card"),
    };
    let mut o = blank();
    let ret =
        HOST_SLOTS.entitlement_check.unwrap()(d.ctx, std::ptr::from_ref(&check).cast(), &mut o);
    assert_eq!(
        (ret.outcome(), o.value),
        (Outcome::Fault, 0),
        "a handle reused for another service is a plugin fault, never the first service's answer"
    );
    assert_eq!(error(&o), HANDLE_REBOUND);
    assert!(
        !d.route
            .provider
            .scoped
            .lock()
            .unwrap()
            .iter()
            .any(|(_, what, _)| *what == "entitlement.check"),
        "the reused handle's service never reaches the kernel"
    );
    assert!(
        !still_served(&d),
        "the instance that reused the handle is quarantined"
    );
}

/// RED (status row 189): a handle is bound to the REQUEST it was first used for, too. The same
/// service on the same handle naming another key is a plugin fault, never the first key's record.
#[test]
fn a_handle_reused_for_another_request_of_one_service_is_fault_and_quarantines() {
    let d = double();
    let get = |key: &'static str, buf: &mut [u8; 16], spans: &mut [ItemSpan; 1]| {
        let i = RecordsGetIn {
            head: head(op::RECORDS_GET, TICKET, 0, size_of::<RecordsGetIn>()),
            kind: text("approval"),
            key: text(key),
            into: bufs(buf, spans),
        };
        let mut o = blank();
        let ret = HOST_SLOTS.records_get.unwrap()(d.ctx, std::ptr::from_ref(&i).cast(), &mut o);
        (ret.outcome(), o)
    };
    let (mut buf, mut spans) = ([0u8; 16], [NO_SPAN; 1]);
    let (outcome, o) = get("k1", &mut buf, &mut spans);
    assert_eq!((outcome, o.value), (Outcome::Ready, svc::FOUND));
    assert_eq!(&buf[..4], b"k1=v");

    let (mut buf, mut spans) = ([0u8; 16], [NO_SPAN; 1]);
    let (outcome, o) = get("k2", &mut buf, &mut spans);
    assert_eq!(
        outcome,
        Outcome::Fault,
        "another request on a used handle is a plugin fault"
    );
    assert_eq!(o.len, 0);
    assert_eq!(
        buf, [0u8; 16],
        "the first request's record is never handed out"
    );
    assert_eq!(
        d.route.provider.scoped.lock().unwrap().len(),
        1,
        "the second request never reaches the kernel"
    );
    assert!(!still_served(&d), "the instance is quarantined");
}

/// GREEN on both sides of row 189: the legitimate re-poll of the SAME request on the same handle
/// (PENDING, then READY once the kernel answers) is the one re-use a handle allows. The plugin may
/// rebuild the request between polls (other buffers, the same bytes); the re-poll reads the stored
/// answer, the kernel is asked once, and the instance is never quarantined for it.
#[test]
fn a_repoll_of_the_same_request_on_its_handle_reads_the_answer_and_is_never_a_fault() {
    let d = double();
    let first = String::from("dest:a.example:443");
    let poll = |dest: &str| {
        let mut i = judge_in("", TICKET, 7, DEST_RESOLVE);
        i.dest = over(dest.as_bytes());
        call_judge(&d, &i)
    };
    assert_eq!(poll(&first).0.outcome(), Outcome::Pending);
    let rebuilt = first.clone();
    drop(first);
    assert_eq!(
        poll(&rebuilt).0.outcome(),
        Outcome::Pending,
        "the same request re-polled before the answer is still running"
    );
    let answer = d.route.provider.held.lock().unwrap().pop().unwrap();
    answer(Stored::ready(DEST_INTERNAL));
    let (ret, o) = poll(&rebuilt);
    assert_eq!((ret.outcome(), o.value), (Outcome::Ready, DEST_INTERNAL));
    assert_eq!(d.route.provider.judged.load(Ordering::SeqCst), 1);
    assert!(still_served(&d), "a re-poll is never a fault");
}

/// A second caller on `d`'s route (its dispatcher's store), with an identity of its own.
fn beside(d: &Double, name: &str) -> HostCtx {
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let dyn_route: Arc<dyn WakeRoute> = d.route.clone();
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    assert!(wake
        .caller
        .set(Caller {
            instance: Arc::from(name),
            plugin: Arc::from("double-plugin"),
            kind: busbar_contract::abi::mechanism::KindCode::Plane,
        })
        .is_ok());
    crate::dispatch::handle::mint(wake).expect("the host mints a handle")
}

/// RED (audit loader-src PL1#4; THE DESIGN `docs/design/BUSBAR-1.6.0.md` l.1602-1603: "A pure op
/// (`arrive`, `refusal`, `project`) or any call made with no ticket that calls a may-pend service
/// gets REFUSED, never PENDING"): a ticket-less crossing that stamps another op's live ticket on
/// its handle is REFUSED and the service never runs; so is a ticketed crossing's call naming a
/// ticket other than its own. RED: only the handle the plugin wrote was read, so the pure op ran
/// the service as a pending call whose completion woke the other op.
#[test]
fn red_a_service_handle_naming_another_crossings_ticket_is_refused_and_never_runs() {
    let d = double();
    let refused = "a service handle names the ticket of the crossing that calls it";
    {
        let _pure = crossing(Ticket::NONE);
        let (ret, o) = call_judge(
            &d,
            &judge_in("https://api.example.com/", TICKET, 0, DEST_RESOLVE),
        );
        assert_eq!(
            ret.outcome(),
            Outcome::Refused,
            "a pure op pended on another op's ticket"
        );
        assert_eq!(error(&o), refused);
    }
    {
        let other = Ticket {
            generation: TICKET.generation ^ 1,
            ..TICKET
        };
        let _ticketed = crossing(other);
        let (ret, o) = call_judge(
            &d,
            &judge_in("https://api.example.com/", TICKET, 0, DEST_RESOLVE),
        );
        assert_eq!(
            ret.outcome(),
            Outcome::Refused,
            "an op pended on another op's ticket"
        );
        assert_eq!(error(&o), refused);
    }
    assert_eq!(
        d.route.provider.judged.load(Ordering::SeqCst),
        0,
        "the service never ran"
    );
    assert!(d.route.wakes.lock().unwrap().is_empty());
    // The GREEN twin: the crossing's own ticket pends.
    let _own = crossing(TICKET);
    let (ret, _) = call_judge(
        &d,
        &judge_in("https://api.example.com/", TICKET, 0, DEST_RESOLVE),
    );
    assert_eq!(ret.outcome(), Outcome::Pending);
}

/// RED (audit loader-src PL1#4; THE DESIGN `docs/design/BUSBAR-1.6.0.md` l.1611: "Every
/// per-instance host registry keys by label"): two instances whose ops share one ticket each count
/// their handles from 0, and each keeps its own result under its own handle 0: the second's call
/// pends on its own request, is not judged a rebound of the first's, and neither reads the other's
/// answer. RED: results were keyed by ticket and handle alone, so the second instance's handle 0
/// named the first's result and the second was quarantined as a rebinder.
#[test]
fn red_two_instances_on_one_ticket_each_keep_their_own_results() {
    let d = double();
    let second = beside(&d, "second");
    let first_in = judge_in("https://a.example.com/", TICKET, 0, DEST_RESOLVE);
    let second_in = judge_in("https://b.example.com/", TICKET, 0, DEST_RESOLVE);
    assert_eq!(call_judge(&d, &first_in).0.outcome(), Outcome::Pending);
    let mut o = blank();
    let f = HOST_SLOTS.dest_judge.unwrap();
    let ret = f(second, std::ptr::from_ref(&second_in).cast(), &mut o);
    assert_eq!(
        ret.outcome(),
        Outcome::Pending,
        "the second instance's own handle 0 was judged a rebound of the first's: {}",
        error(&o)
    );
    assert_eq!(d.route.provider.judged.load(Ordering::SeqCst), 2);
}

/// ONE ALLOCATOR, TWO SPACES: a line's id never sets the top bit and is never `0`; a binding's
/// always sets it; each id names its space. RED arm: no line id and binding id ever coincide.
#[test]
fn a_line_id_and_a_binding_id_are_drawn_from_two_spaces() {
    use crate::dispatch::auth_handle::{next_ref_id, space_of, RefSpace};
    let lines: Vec<u64> = (0..64).map(|_| next_ref_id(RefSpace::Line)).collect();
    let bindings: Vec<u64> = (0..64).map(|_| next_ref_id(RefSpace::Binding)).collect();
    assert!(lines.iter().all(|&i| i != 0 && i & (1 << 63) == 0));
    assert!(bindings.iter().all(|&i| i & (1 << 63) != 0));
    assert!(lines.iter().all(|i| !bindings.contains(i)));
    assert!(lines.iter().all(|&i| space_of(i) == Some(RefSpace::Line)));
    assert!(bindings
        .iter()
        .all(|&i| space_of(i) == Some(RefSpace::Binding)));
    assert_eq!(space_of(0), None);
}

// ── the host auth handle, served: the three services delegate to the installed kernel side ──

use crate::dispatch::auth_handle::{
    AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes,
    RefuseAsk, UnitSecret,
};

/// The kernel side of the handle, as a double: it records what the loader handed it, answers
/// `auth.call` at once or (with `pend` set) keeps its [`AuthDone`], and verifies units against
/// the one secret it minted under.
#[derive(Default)]
struct KernelSide {
    pend: std::sync::atomic::AtomicBool,
    calls: Mutex<Vec<AuthCallAsk>>,
    held: Mutex<Vec<AuthDone>>,
    hands: Mutex<Vec<HandInAsk>>,
    refusals: Mutex<Vec<RefuseAsk>>,
    /// `(owner, unit)` -> its secret.
    units: Mutex<Vec<(u64, u64, UnitSecret)>>,
    /// At the peer point, answer the flow alone (else the names and a unit, as at the head).
    peer_clean: std::sync::atomic::AtomicBool,
    /// Every framing the loader told it ended.
    ended: Mutex<Vec<u64>>,
}

const SIDE_SECRET: [u64; 2] = [0x5eed, 0xc0de];

fn side_answer(unit: UnitRef) -> AuthCallAnswer {
    AuthCallAnswer {
        flow: svc::FLOW_CONTINUE,
        unit,
        strips: vec![
            (
                "authorization".to_string(),
                busbar_contract::abi::auth::FIELD_SENSITIVE,
            ),
            ("key".to_string(), busbar_contract::abi::auth::FIELD_QUERY),
        ],
    }
}

impl AuthHandleHost for KernelSide {
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret> {
        self.units
            .lock()
            .unwrap()
            .iter()
            .find(|(o, u, _)| *o == owner && *u == unit)
            .map(|(_, _, s)| *s)
    }

    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan {
        let minted = mint_unit_ref(SIDE_SECRET, ask.generation, ask.owner, 0, 77).expect("minted");
        self.units.lock().unwrap().push((
            ask.owner,
            77,
            UnitSecret {
                secret: SIDE_SECRET,
                generation: ask.generation,
                line: 0,
            },
        ));
        let unit = if ask.unit.is_none() { minted } else { ask.unit };
        if ask.point == busbar_contract::abi::auth::POINT_PEER
            && self.peer_clean.load(Ordering::SeqCst)
        {
            self.calls.lock().unwrap().push(ask);
            return AuthRan::Now(Ok(AuthCallAnswer {
                flow: svc::FLOW_CONTINUE,
                unit: UnitRef::NONE,
                strips: Vec::new(),
            }));
        }
        self.calls.lock().unwrap().push(ask);
        if self.pend.load(Ordering::SeqCst) {
            self.held.lock().unwrap().push(done);
            return AuthRan::Pending;
        }
        AuthRan::Now(Ok(side_answer(unit)))
    }

    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        let unit = if ask.unit.is_none() {
            UnitRef { id: 78, mac: 1 }
        } else {
            ask.unit
        };
        self.hands.lock().unwrap().push(ask);
        Ok((svc::FLOW_STOP, unit))
    }

    fn framing_ended(&self, framing: u64) {
        self.ended.lock().unwrap().push(framing);
    }

    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        self.refusals.lock().unwrap().push(ask);
        Ok(RefusalBytes {
            status: 404,
            fields: vec![("content-type".to_string(), b"application/json".to_vec())],
            body: b"{\"error\":{}}".to_vec(),
        })
    }
}

/// A double with the kernel side installed on its route.
fn served_double() -> (Double, Arc<KernelSide>) {
    let d = double();
    let side = Arc::new(KernelSide::default());
    let host: Arc<dyn AuthHandleHost> = side.clone();
    assert!(d.route.auth.set(host).is_ok());
    (d, side)
}

fn auth_call_into(
    auth: AuthRef,
    answer: &mut AuthAnswer,
    buf: &mut [u8],
    spans: &mut [FieldSpan],
) -> AuthCallIn {
    AuthCallIn {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
        ..auth_call_in(auth, answer)
    }
}

const NO_FIELD_SPAN: FieldSpan = FieldSpan {
    name: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
    flags: 0,
    _reserved: 0,
};

/// RED (THE DESIGN §6 step 4; #74): with the kernel side installed, `auth.call` reaches it once,
/// with the owner, the ref's id, the point and the request copied, and the transport receives ONLY
/// the flow, the unit, and the NAMES to strip with their flags: no value, no verdict.
#[test]
fn red_auth_call_delegates_to_the_installed_kernel_side_and_answers_names_only() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(svc::check_auth_call(&i, ret, &o), Ok(Filled::Written));
    let calls = side.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (calls[0].owner, calls[0].auth, calls[0].point),
        (owner(&d), 3, POINT_HEAD)
    );
    assert_eq!(calls[0].request.target, "/v1");
    assert_eq!(calls[0].request.method, "GET");
    assert_eq!(slot.flow, svc::FLOW_CONTINUE);
    assert_eq!(slot.unit.id, 77);
    assert_eq!(o.items, 2);
    assert_eq!(o.len, ("authorization".len() + "key".len()) as u64);
    let name = |s: &FieldSpan| {
        std::str::from_utf8(&buf[s.name.offset as usize..(s.name.offset + s.name.len) as usize])
            .unwrap()
            .to_string()
    };
    assert_eq!(name(&spans[0]), "authorization");
    assert_eq!(spans[0].flags, busbar_contract::abi::auth::FIELD_SENSITIVE);
    assert_eq!(name(&spans[1]), "key");
    assert_eq!(spans[1].flags, busbar_contract::abi::auth::FIELD_QUERY);
    for s in &spans[..2] {
        assert_eq!(s.value.offset, check::SPAN_ABSENT, "a value crossed");
        assert_eq!(s.value.len, 0);
    }
}

/// RED (the short-buffer rule for `auth.call`): a buffer too small answers FAILED with the full
/// sizes and writes nothing; the one re-call on the same handle reads the stored answer, and the
/// kernel side ran once.
#[test]
fn red_a_short_auth_call_buffer_earns_one_recall_and_the_kernel_runs_once() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let (mut small, mut few) = ([0u8; 4], [NO_FIELD_SPAN; 1]);
    let i = auth_call_into(r, &mut slot, &mut small, &mut few);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Failed, "{}", error(&o));
    assert_eq!(o.needed_bytes, ("authorization".len() + "key".len()) as u64);
    assert_eq!(o.needed_items, 2);
    assert_eq!(
        slot.size, 0,
        "the answer slot was written on a short answer"
    );
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(o.items, 2);
    assert_eq!(
        side.calls.lock().unwrap().len(),
        1,
        "the kernel side ran twice"
    );
}

/// RED (THE DESIGN §6 step 7: a pending answer parks only its own stream): a kernel side that
/// keeps the call answers PENDING; its answer stores and wakes the ticket; the re-issued handle
/// reads it.
#[test]
fn red_a_pending_auth_call_parks_on_its_ticket_and_reads_the_stored_answer() {
    let (d, side) = served_double();
    side.pend.store(true, Ordering::SeqCst);
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
    let (ret, _) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Pending);
    let done = side
        .held
        .lock()
        .unwrap()
        .pop()
        .expect("the kernel side kept the call");
    done(Ok(side_answer(UnitRef { id: 77, mac: 5 })));
    assert_eq!(d.route.wakes.lock().unwrap().as_slice(), &[TICKET]);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(slot.unit, UnitRef { id: 77, mac: 5 });
    assert_eq!(side.calls.lock().unwrap().len(), 1);
}

/// RED (#74): with the kernel side installed a presented unit is VERIFIED against the secret it
/// was minted under: the unit as minted passes; a flipped mac, another owner's presentation and a
/// unit the kernel holds no record of are refused before the kernel side is called.
#[test]
fn red_a_presented_unit_is_verified_against_the_kernel_sides_secret() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    side.units.lock().unwrap().push((
        owner(&d),
        9,
        UnitSecret {
            secret: SIDE_SECRET,
            generation: generation(),
            line: 2,
        },
    ));
    let unit = mint_unit_ref(SIDE_SECRET, generation(), owner(&d), 2, 9).expect("minted");
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let mut slot = answer_slot();
    let mut i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
    i.unit = unit;
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(side.calls.lock().unwrap().len(), 1);
    for bad in [
        UnitRef {
            mac: unit.mac ^ 1,
            ..unit
        },
        UnitRef { id: 10, ..unit },
        mint_unit_ref(SIDE_SECRET, generation(), owner(&d), 3, 9).expect("minted"),
        mint_unit_ref([1, 1], generation(), owner(&d), 2, 9).expect("minted"),
    ] {
        let mut i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
        i.head.handle.seq = 1 + bad.mac as u32 % 1000;
        i.unit = bad;
        let (ret, o) = call_auth(d.ctx, &i);
        assert_eq!(ret.outcome(), Outcome::Refused, "{bad:?}");
        assert_eq!(error(&o), REF_NOT_MINTED, "{bad:?}");
    }
    assert_eq!(
        side.calls.lock().unwrap().len(),
        1,
        "a bad unit reached the kernel"
    );
}

/// RED: `unit.hand_in` and `unit.refuse` delegate to the installed kernel side; the hand-in's flow
/// and unit land in the answer slot, and the refusal's status, fields and body are lent to the
/// transport, valid past the call.
#[test]
fn red_hand_in_and_refuse_delegate_to_the_installed_kernel_side() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let hand = UnitHandInIn {
        head: head(op::UNIT_HAND_IN, Ticket::NONE, 0, size_of::<UnitHandInIn>()),
        auth: r,
        unit: UnitRef::NONE,
        line: 2,
        _reserved: 0,
        conn: 4,
        stream: 5,
        request: get_view(),
        answer: &mut slot,
    };
    let mut o = blank();
    let ret = HOST_SLOTS.unit_hand_in.unwrap()(d.ctx, std::ptr::from_ref(&hand).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(svc::check_unit_hand_in(&hand, ret, &o), Ok(Filled::Written));
    assert_eq!(slot.flow, svc::FLOW_STOP);
    assert_eq!(slot.unit.id, 78);
    {
        let hands = side.hands.lock().unwrap();
        assert_eq!((hands[0].line, hands[0].auth, hands[0].conn), (2, 3, 4));
    }

    let mut refusal = RefusalAnswer {
        size: 0,
        status: 0,
        _reserved: 0,
        fields: std::ptr::null(),
        fields_len: 0,
        body: no_blob(),
    };
    let refuse = UnitRefuseIn {
        head: head(op::UNIT_REFUSE, Ticket::NONE, 0, size_of::<UnitRefuseIn>()),
        unit: UnitRef::NONE,
        cause: REFUSE_NO_ROUTE,
        line: LINE_NONE,
        conn: 4,
        stream: 5,
        answer: &mut refusal,
        request: get_view(),
    };
    let mut o = blank();
    let ret = HOST_SLOTS.unit_refuse.unwrap()(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(
        svc::check_unit_refuse(&refuse, ret, &o),
        Ok(Filled::Written)
    );
    assert_eq!(refusal.status, 404);
    assert_eq!(refusal.fields_len, 1);
    // SAFETY: the kernel-owned answer, valid until the next call on this connection.
    let (field, body) = unsafe {
        (
            *refusal.fields,
            std::slice::from_raw_parts(refusal.body.ptr, refusal.body.len),
        )
    };
    // SAFETY: as above.
    let name = unsafe { std::slice::from_raw_parts(field.name.ptr, field.name.len) };
    assert_eq!(name, b"content-type");
    assert_eq!(body, b"{\"error\":{}}");
    assert_eq!(side.refusals.lock().unwrap()[0].cause, REFUSE_NO_ROUTE);
    // The request the refusal is for reaches the kernel, its path shaping the bytes (ruling 1).
    assert_eq!(side.refusals.lock().unwrap()[0].request.target, "/v1");
    assert_eq!(side.refusals.lock().unwrap()[0].request.method, "GET");
}

// ── the peer point, the op's deadline, and the refusal's lifetime ────────────────────────────

fn peer_call_in(
    auth: AuthRef,
    answer: &mut AuthAnswer,
    buf: &mut [u8],
    spans: &mut [FieldSpan],
) -> AuthCallIn {
    let mut i = auth_call_into(auth, answer, buf, spans);
    i.point = busbar_contract::abi::auth::POINT_PEER;
    i.request = HeadView {
        method: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        target: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        authority: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        fields: std::ptr::null(),
        fields_len: 0,
        ..get_view()
    };
    i.request.scheme = 0;
    i
}

/// RED (the Peer rule, the answer's side): a peer-point answer is continue or stop alone. A
/// kernel answer naming lines or a unit there is REFUSED with nothing written; the flow alone is
/// READY with no byte and no span.
#[test]
fn red_a_peer_answer_is_the_flow_alone() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let i = peer_call_in(r, &mut slot, &mut buf, &mut spans);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Refused, "{}", error(&o));
    assert_eq!(error(&o), PEER_ANSWER_NAMES);
    assert_eq!(slot.size, 0, "the answer slot was written");
    assert!(
        buf.iter().all(|b| *b == 0),
        "a name was written at the peer point"
    );
    side.peer_clean.store(true, Ordering::SeqCst);
    let mut slot = answer_slot();
    let mut i = peer_call_in(r, &mut slot, &mut buf, &mut spans);
    i.head.handle.seq = 1;
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!((o.len, o.items), (0, 0));
    assert_eq!((slot.flow, slot.unit), (svc::FLOW_CONTINUE, UnitRef::NONE));
    assert_eq!(svc::check_auth_call(&i, ret, &o), Ok(Filled::Written));
}

/// RED (deadline classes): an `auth.call` made inside a framer op's crossing hands the kernel what
/// remains of that op's deadline; a write-behind op's, or none outside an op, hands none.
#[test]
fn red_an_auth_call_carries_its_ops_deadline() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let call = |seq: u32| {
        let mut slot = answer_slot();
        let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
        let mut i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
        i.head.handle.seq = seq;
        let (ret, o) = call_auth(d.ctx, &i);
        assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    };
    let mut head = crate::dispatch::in_head();
    head.deadline_ns = crate::dispatch::now_ns() + 5_000_000_000;
    {
        let _op = op_deadline(&head);
        call(0);
    }
    head.deadline_class = busbar_contract::abi::mechanism::call::DeadlineClass::WriteBehind as u8;
    {
        let _op = op_deadline(&head);
        call(1);
    }
    call(2);
    let calls = side.calls.lock().unwrap();
    let first = calls[0].deadline.expect("the op's deadline");
    assert!(
        first <= std::time::Duration::from_secs(5) && !first.is_zero(),
        "{first:?}"
    );
    assert_eq!(
        calls[1].deadline, None,
        "a write-behind op's deadline was handed on"
    );
    assert_eq!(calls[2].deadline, None, "a deadline outside any op");
}

/// RED (per-call copy-out): the kernel's refusal is lent for the call alone and nothing is kept
/// per connection: N refusals, over N connections and over one, leave at most the last lent.
#[test]
fn red_n_refusals_keep_nothing_per_connection() {
    let (d, _side) = served_double();
    for conn in (1..=8).chain(std::iter::repeat(3).take(8)) {
        let mut refusal = RefusalAnswer {
            size: 0,
            status: 0,
            _reserved: 0,
            fields: std::ptr::null(),
            fields_len: 0,
            body: no_blob(),
        };
        let refuse = UnitRefuseIn {
            conn,
            answer: &mut refusal,
            ..refuse_in()
        };
        let mut o = blank();
        let ret =
            HOST_SLOTS.unit_refuse.unwrap()(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut o);
        assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
        assert_eq!(refusal.status, 404);
        assert!(refusals_held() <= 1, "{} refusals held", refusals_held());
    }
}

/// A no-route `unit.refuse` `in` with no answer slot yet.
fn refuse_in() -> UnitRefuseIn {
    UnitRefuseIn {
        head: head(op::UNIT_REFUSE, Ticket::NONE, 0, size_of::<UnitRefuseIn>()),
        unit: UnitRef::NONE,
        cause: REFUSE_NO_ROUTE,
        line: LINE_NONE,
        conn: 1,
        stream: 1,
        answer: std::ptr::null_mut(),
        request: get_view(),
    }
}

// ── the framing: the host's identity of a connection side ─────────────────────────────────────

/// RED (the framing is the host's): an `auth.call` hands the kernel the framing of the ticket its
/// framer op was made on, never the transport's word for it.
#[test]
fn red_an_auth_call_names_its_tickets_framing() {
    let (d, side) = served_double();
    let r = mint_auth_ref(owner(&d), generation(), 3).expect("minted");
    let mut slot = answer_slot();
    let (mut buf, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let i = auth_call_into(r, &mut slot, &mut buf, &mut spans);
    let (ret, o) = call_auth(d.ctx, &i);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&o));
    assert_eq!(
        side.calls.lock().unwrap()[0].framing,
        crate::dispatch::auth_handle::framing_of(TICKET)
    );
}

/// RED (the host's end notification): the loader tells the installed kernel side when it retires
/// a connection side's ticket, naming that framing; a live ticket's framing is never named.
#[test]
fn red_retiring_a_connection_sides_ticket_ends_its_framing() {
    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let side = Arc::new(KernelSide::default());
    let host: Arc<dyn AuthHandleHost> = side.clone();
    assert!(dispatcher.install_auth_handle(host));
    let live = dispatcher.inline_ticket().expect("a ticket");
    let mut ended = Vec::new();
    for _ in 0..8 {
        let t = dispatcher.inline_ticket().expect("a ticket");
        ended.push(crate::dispatch::auth_handle::framing_of(t.ticket()));
        drop(t);
    }
    assert_eq!(*side.ended.lock().unwrap(), ended);
    assert!(!side
        .ended
        .lock()
        .unwrap()
        .contains(&crate::dispatch::auth_handle::framing_of(live.ticket())));
    let held = crate::dispatch::auth_handle::framing_of(live.ticket());
    drop(live);
    assert_eq!(side.ended.lock().unwrap().last(), Some(&held));
}
