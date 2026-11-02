// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow};
use busbar_contract::abi::auth::{
    AuthPoint, AuthPoints, Ops, FACT_INBOUND_ALL_HEADERS, POINT_HEAD_BODY, POINT_PEER,
};
use busbar_contract::abi::mechanism::call::{AbiStr, RawOutcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Answer, Strip as KitStrip, Verdict, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::Secret;
use std::ffi::c_void;
use std::sync::Condvar;

const FIRST: &str = "x-first";
const SECOND: &str = "x-second";
const SELECTED: &str = "header-selected";
const ALL: &str = "header-all";
const NORMAL: &str = "normal";
const PAUSED_SHORT: &str = "paused-short";
const PENDING: &str = "pending";
const CANCEL: &str = "cancel";
const CANDIDATE: &str = "candidate-secret";
const SUBJECT: &str = "header-subject";
const GROUP: &str = "header-group";
const AUTHORITY: &str = "node.example";
const PATH: &str = "/header-boundary";
const QUERY: &str = "key=value";
const BODY: &[u8] = b"signed\0body\xff";
const PEER: &[u8] = b"peer-facts";
const TIMESTAMP: u64 = 1_700_000_000;
const CONNECTION: u64 = 7;
const UNIT: u64 = 11;
const WAIT: Duration = Duration::from_secs(5);

const LINES: &[(&str, &[u8])] = &[
    ("x-private", b"never-copy-private"),
    ("X-FiRsT", b"first\0\xff"),
    ("x-second", b"second"),
    ("x-FIRST", b"first-again"),
    ("x-first-extra", b"never-copy-prefix"),
    ("x-\u{212a}first", b"never-copy-unicode"),
];

struct Probe {
    second: AtomicBool,
}

impl VerifyPlugin for Probe {
    fn open_refusing(settings: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self {
            second: AtomicBool::new(settings == b"true"),
        })
    }

    fn carriers(&self) -> Option<Vec<String>> {
        Some(vec![if self.second.load(Ordering::Acquire) {
            SECOND.into()
        } else {
            FIRST.into()
        }])
    }

    fn reload(&self, _: &[u8], _: &[&[u8]]) -> Result<u64, Refusal> {
        self.second.fetch_xor(true, Ordering::AcqRel);
        Ok(0)
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        let wide = request.method() == PAUSED_SHORT.as_bytes();
        Answer {
            strips: vec![KitStrip::field(FIRST)],
            ..Verdict::Identity(VerifiedIdentity {
                subject: SUBJECT.into(),
                credential: request
                    .credential()
                    .map(|c| String::from_utf8(c.to_vec()).unwrap().into()),
                groups: if wide {
                    vec![GROUP.into(); IDENTITY_GROUPS as usize + 1]
                } else {
                    Vec::new()
                },
                ..VerifiedIdentity::default()
            })
            .into()
        }
    }
}

const MARKS: &[MarkWord] = &[carrier(FIRST), carrier(SECOND)];
const POINTS: AuthPoints = AuthPoints(POINT_PEER | POINT_HEAD_BODY);

const fn stating(
    name: &'static str,
    tail: &'static busbar_contract::abi::auth::AuthTail,
) -> Statement {
    with_tail(
        Statement {
            mark_words: MARKS.as_ptr(),
            mark_words_len: MARKS.len(),
            ..statement(name, "1.0.0", 8)
        },
        tail,
    )
}

const SELECTED_TAIL: busbar_contract::abi::auth::AuthTail = verify_tail(0, POINTS);
const ALL_TAIL: busbar_contract::abi::auth::AuthTail =
    verify_tail(FACT_INBOUND_ALL_HEADERS, POINTS);

mod selected {
    busbar_contract::auth_verify_door!(
        super::Probe,
        super::stating(super::SELECTED, &super::SELECTED_TAIL)
    );
}

mod all {
    busbar_contract::auth_verify_door!(super::Probe, super::stating(super::ALL, &super::ALL_TAIL));
}

#[derive(Debug, PartialEq, Eq)]
struct Seen {
    lines: Vec<(Vec<u8>, Vec<u8>)>,
    credential: Vec<u8>,
    method: Vec<u8>,
    authority: Vec<u8>,
    path: Vec<u8>,
    query: Vec<u8>,
    timestamp: u64,
    point: u32,
    conn: u64,
    unit: u64,
    body: Vec<u8>,
    peer: Vec<u8>,
}

#[derive(Default)]
struct Gate {
    entered: bool,
    released: bool,
    seen: Vec<Seen>,
}

static GATE: (Mutex<Gate>, Condvar) = (
    Mutex::new(Gate {
        entered: false,
        released: false,
        seen: Vec::new(),
    }),
    Condvar::new(),
);

fn base(door: DoorFn) -> &'static Ops {
    // SAFETY: each fixture's SDK door and complete auth table have static storage.
    unsafe { &*Door::read_parts(door()).ops.cast::<Ops>() }
}

fn crossed(
    ops: &Ops,
    instance: *mut c_void,
    input: *const c_void,
    output: *mut c_void,
) -> RawOutcome {
    // SAFETY: the loader lends complete live frames, and every pointed-to input allocation is
    // held throughout this crossing. Empty blobs/strings may have a null pointer.
    unsafe {
        let request = &*input.cast::<VerifyIn>();
        let bytes = |ptr, len| {
            if len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(ptr, len).to_vec()
            }
        };
        let text = |s: AbiStr| bytes(s.ptr, s.len);
        let octets = |b: Blob| bytes(b.ptr, b.len);
        let method = text(request.request.method);
        let initial = request.head.flags & FLAG_RESUME == 0;
        let pause = initial
            && (method == PENDING.as_bytes()
                || method == CANCEL.as_bytes()
                || (method == PAUSED_SHORT.as_bytes()
                    && request.out_buf.groups_cap == IDENTITY_GROUPS));
        let mut gate = GATE.0.lock().unwrap();
        if pause {
            gate.entered = true;
            GATE.1.notify_all();
            while !gate.released {
                gate = GATE.1.wait(gate).unwrap();
            }
        }

        let lines = if request.lines_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(request.lines, request.lines_len)
                .iter()
                .map(|line| (text(line.name), octets(line.value)))
                .collect()
        };
        gate.seen.push(Seen {
            lines,
            credential: octets(request.credential),
            authority: text(request.request.authority),
            path: text(request.request.canonical_path),
            query: text(request.request.query),
            timestamp: request.request.timestamp,
            point: request.point,
            conn: request.conn,
            unit: request.unit,
            body: octets(request.body),
            peer: octets(request.peer),
            method,
        });
        drop(gate);
        if initial && text(request.request.method) == PENDING.as_bytes() {
            let pending = RawOutcome::of(Outcome::Pending);
            (*output.cast::<IdentifyOut>()).head.outcome = pending;

            (*output.cast::<IdentifyOut>()).head.wake_at_ns = now_ns().max(1);
            return pending;
        }
    }
    // SAFETY: forward the unchanged host-owned VERIFY frames to their original SDK slot.
    unsafe { ops.verify.unwrap()(instance, input, output) }
}

extern "C" fn selected_verify(
    i: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    crossed(base(selected::door), i, input, out)
}

extern "C" fn all_verify(i: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    crossed(base(all::door), i, input, out)
}

fn wrapped(door: DoorFn, verify: busbar_contract::abi::mechanism::call::Op) -> Door {
    let mut ops = *base(door);
    ops.verify = Some(verify);
    // SAFETY: only VERIFY is wrapped; SDK instance ownership, slots and static Statement remain
    // intact, and the wrapper forwards the original complete frames to its original SDK table.
    unsafe {
        let mut parts = Door::read_parts(door());
        parts.ops = std::ptr::from_ref(Box::leak(Box::new(ops))).cast();
        Door::__from_parts(parts)
    }
}

extern "C" fn selected_door() -> &'static Door {
    static DOOR: std::sync::OnceLock<crate::conformance::StaticDoor> = std::sync::OnceLock::new();
    DOOR.get_or_init(|| {
        // SAFETY: wrapped leaks its immutable ops copy; its Statement and every nested range
        // keep the original SDK door's static backing, independent of this owned door.
        unsafe { crate::conformance::StaticDoor::new(wrapped(selected::door, selected_verify)) }
    })
    .get()
}

extern "C" fn all_door() -> &'static Door {
    static DOOR: std::sync::OnceLock<crate::conformance::StaticDoor> = std::sync::OnceLock::new();
    DOOR.get_or_init(|| {
        // SAFETY: wrapped leaks its immutable ops copy; its Statement and every nested range
        // keep the original SDK door's static backing, independent of this owned door.
        unsafe { crate::conformance::StaticDoor::new(wrapped(all::door, all_verify)) }
    })
    .get()
}

fn open(door: DoorFn, second: bool) -> AuthInstance {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        ..DispatchConfig::default()
    }));
    let sink = AuthSink::new(SELECTED);
    let plugin = load_linked::<Auth>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: SELECTED.into(),
            max_inflight_cap: 8,
            sink: sink.bind(),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    AuthInstance::open(
        plugin,
        sink,
        dispatcher,
        SELECTED,
        &serde_json::to_vec(&second).unwrap(),
        Vec::new(),
    )
    .unwrap()
}

fn request(method: &str, point: AuthPoint) -> VerifyRequest {
    VerifyRequest {
        point,
        credential: Some(Secret::new(CANDIDATE.as_bytes().to_vec())),
        lines: LINES
            .iter()
            .map(|(n, v)| ((*n).into(), Secret::new(v.to_vec())))
            .collect(),
        method: method.into(),
        authority: AUTHORITY.into(),
        path: PATH.into(),
        query: Some(QUERY.into()),
        timestamp: TIMESTAMP,
        conn: CONNECTION,
        unit: if point == AuthPoint::Peer { 0 } else { UNIT },
        body: (point == AuthPoint::HeadBody).then(|| BODY.to_vec()),
        peer: (point == AuthPoint::Peer).then(|| PEER.to_vec()),
    }
}

fn reset() {
    *GATE.0.lock().unwrap() = Gate::default();
}

fn entered() {
    let gate = GATE.0.lock().unwrap();
    let (guard, timeout) = GATE
        .1
        .wait_timeout_while(gate, WAIT, |g| !g.entered)
        .unwrap();
    drop(guard);
    assert!(!timeout.timed_out(), "the raw crossing did not enter");
}

fn release_gate() {
    GATE.0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .released = true;
    GATE.1.notify_all();
}

struct ReleaseGate;

impl Drop for ReleaseGate {
    fn drop(&mut self) {
        release_gate();
    }
}

fn answer(answer: VerifyAnswer, wide: bool) {
    let Verified::Identity(identity) = answer.verified else {
        panic!("the SDK must preserve its identity verdict")
    };
    assert_eq!(identity.subject, SUBJECT);
    assert_eq!(
        identity
            .credential
            .unwrap()
            .expose(&busbar_contract::plugin::TestKernelSeal),
        CANDIDATE
    );
    assert_eq!(
        identity.groups.len(),
        if wide {
            IDENTITY_GROUPS as usize + 1
        } else {
            0
        }
    );
    assert_eq!(answer.strips, [Strip::field(FIRST)]);
}

fn observed(names: Option<&[&str]>, method: &str, point: AuthPoint, crossings: usize) {
    let gate = GATE.0.lock().unwrap();
    assert_eq!(gate.seen.len(), crossings);
    let expected: Vec<_> = LINES
        .iter()
        .filter(|(n, _)| names.is_none_or(|names| names.iter().any(|v| v.eq_ignore_ascii_case(n))))
        .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
        .collect();
    for seen in &gate.seen {
        assert_eq!(seen.lines, expected);
        assert_eq!(seen.credential, CANDIDATE.as_bytes());
        assert_eq!(seen.method, method.as_bytes());
        assert_eq!(seen.authority, AUTHORITY.as_bytes());
        assert_eq!(seen.path, PATH.as_bytes());
        assert_eq!(seen.query, QUERY.as_bytes());
        assert_eq!(seen.timestamp, TIMESTAMP);
        assert_eq!(seen.point, point.bit());
        assert_eq!(seen.conn, CONNECTION);
        assert_eq!(seen.unit, if point == AuthPoint::Peer { 0 } else { UNIT });
        assert_eq!(
            seen.body,
            if point == AuthPoint::HeadBody {
                BODY
            } else {
                &[]
            }
        );
        assert_eq!(seen.peer, if point == AuthPoint::Peer { PEER } else { &[] });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_verify_enforces_instance_header_capabilities_and_preserves_call_custody() {
    let first = open(selected_door, false);
    let second = open(selected_door, true);
    let all = open(all_door, false);
    for (calls, names) in [
        (&first, Some(&[FIRST][..])),
        (&second, Some(&[SECOND][..])),
        (&all, None),
    ] {
        for point in [AuthPoint::HeadBody, AuthPoint::Peer] {
            for submitted in [false, true] {
                reset();
                let req = request(NORMAL, point);
                let got = if submitted {
                    Box::into_pin(calls.verify(req)).await
                } else {
                    calls.verify_now(&req).unwrap()
                };
                answer(got, false);
                observed(
                    if point == AuthPoint::Peer {
                        Some(&[])
                    } else {
                        names
                    },
                    NORMAL,
                    point,
                    1,
                );
            }
        }
    }
    first.refresh().unwrap();
    reset();
    answer(
        first
            .verify_now(&request(NORMAL, AuthPoint::HeadBody))
            .unwrap(),
        false,
    );
    observed(Some(&[SECOND]), NORMAL, AuthPoint::HeadBody, 1);

    for submitted in [false, true] {
        let calls = open(selected_door, false);
        reset();
        if submitted {
            let _release = ReleaseGate;
            let pending = calls.verify(request(PAUSED_SHORT, AuthPoint::HeadBody));
            entered();
            let refreshed = calls.refresh();
            release_gate();
            refreshed.unwrap();
            answer(Box::into_pin(pending).await, true);
        } else {
            std::thread::scope(|scope| {
                let _release = ReleaseGate;
                let running = scope.spawn(|| {
                    calls
                        .verify_now(&request(PAUSED_SHORT, AuthPoint::HeadBody))
                        .unwrap()
                });
                entered();
                let refreshed = calls.refresh();
                release_gate();
                refreshed.unwrap();
                answer(running.join().unwrap(), true);
            });
        }
        observed(Some(&[FIRST]), PAUSED_SHORT, AuthPoint::HeadBody, 2);
        close(calls.plugin());
    }

    let calls = open(selected_door, false);
    reset();
    let release = ReleaseGate;
    let pending = calls.verify(request(PENDING, AuthPoint::HeadBody));
    entered();
    let refreshed = calls.refresh();
    release_gate();
    refreshed.unwrap();
    answer(Box::into_pin(pending).await, false);
    observed(Some(&[FIRST]), PENDING, AuthPoint::HeadBody, 2);
    drop(release);

    reset();
    let _release = ReleaseGate;
    let abandoned = calls.verify(request(CANCEL, AuthPoint::HeadBody));
    entered();
    drop(abandoned);
    release_gate();

    answer(
        Box::into_pin(calls.verify(request(NORMAL, AuthPoint::HeadBody))).await,
        false,
    );
    GATE.0
        .lock()
        .unwrap()
        .seen
        .retain(|seen| seen.method == CANCEL.as_bytes());
    observed(Some(&[SECOND]), CANCEL, AuthPoint::HeadBody, 1);

    for instance in [&first, &second, &all, &calls] {
        close(instance.plugin());
    }
}
