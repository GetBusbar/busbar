// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A real HTTP owner's cancellation wakes an actual A2A card-flight waiter.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    RecordWrite, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::records::VirtualKey;
use busbar_kernel::host_units::{UnitRecord, UnitRecords};
use tokio::sync::{oneshot, Notify};

use crate::root::loader::dispatch::{kinds::plane::Plane, Dispatcher, Frame, InlineTicket, Plugin};

const OWNER_REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"plan"}]}}}"#;
pub(super) const WAITER_REQUEST: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"GetExtendedAgentCard","params":{}}"#;
const TARGET: &[u8] = b"/a2a/agents/vendor";

const AGENT_RPC_CLAIM: u32 = 14;
const DEADLINE: Duration = Duration::from_secs(5);

/// One real loopback HTTP peer's card-request counter and single-response gate.
#[derive(Default)]
pub(super) struct CardPeerControl {
    fetches: AtomicUsize,
    endpoint: String,
    hold_next: Mutex<Option<oneshot::Receiver<()>>>,
    held: AtomicBool,
    entered: Notify,
}

impl CardPeerControl {
    pub(super) fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            ..Self::default()
        }
    }

    /// Called only by the parent's real HTTP card handler, immediately before its signed reply.
    pub(super) async fn card_requested(&self) {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let held = self.hold_next.lock().unwrap().take();
        if let Some(release) = held {
            self.held.store(true, Ordering::SeqCst);
            self.entered.notify_one();
            let _ = release.await;
            self.held.store(false, Ordering::SeqCst);
        }
    }
}

struct ReleasePeer<'a> {
    control: &'a CardPeerControl,
    release: Option<oneshot::Sender<()>>,
}

impl Drop for ReleasePeer<'_> {
    fn drop(&mut self) {
        self.control.hold_next.lock().unwrap().take();
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.control.held.store(false, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct WaiterWake {
    count: AtomicUsize,
    notified: Notify,
}

impl Wake for WaiterWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.notified.notify_one();
    }
}

struct RetireWaiter {
    plane: Arc<Plugin<Plane>>,
    ticket: InlineTicket,
    unit: u64,
    records: Arc<UnitRecords>,
    active: bool,
}

impl RetireWaiter {
    fn retire(&mut self) -> Outcome {
        let mut records = [RecordWrite::ZERO; 32];
        let mut arena = [0_u8; 16384];
        let mut input: PlaneCancelIn = blank_in();
        input.cancel.ticket = self.ticket.ticket();
        input.unit = self.unit;
        input.records_buf = records.as_mut_ptr();
        input.records_cap = records.len();
        input.arena_buf = arena.as_mut_ptr();
        input.arena_cap = arena.len();
        let mut frame: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(input, blank_out());
        let outcome = self
            .plane
            .call(
                busbar_contract::abi::mechanism::lifecycle::slot::CANCEL,
                &mut frame,
            )
            .outcome;
        self.records.ended(self.unit);
        self.active = false;
        outcome
    }
}

impl Drop for RetireWaiter {
    fn drop(&mut self) {
        if self.active {
            let _ = self.retire();
        }
    }
}

pub(super) async fn run(
    data: &axum::Router,
    bearer: &str,
    plane: Arc<Plugin<Plane>>,
    dispatcher: Arc<Dispatcher>,
    records: Arc<UnitRecords>,
    principal: Arc<VirtualKey>,
    control: Arc<CardPeerControl>,
) {
    assert!(principal.scope_allowed("agent", "vendor"));
    assert!(!control.held.load(Ordering::SeqCst));
    let (release, held) = oneshot::channel();
    assert!(control.hold_next.lock().unwrap().replace(held).is_none());
    let _release_peer = ReleasePeer {
        control: &control,
        release: Some(release),
    };
    let fetched = control.fetches.load(Ordering::SeqCst);
    let mut owner = Box::pin(super::http_bytes(
        data,
        "/a2a/agents/vendor",
        OWNER_REQUEST.to_vec(),
        ("authorization", bearer),
    ));
    tokio::time::timeout(DEADLINE, async {
        tokio::select! {
            result = &mut owner => panic!("the held card owner completed before cancellation: {result:?}"),
            () = control.entered.notified() => {}
        }
    })
    .await
    .expect("the actual first caller reached the held card response");
    assert!(control.held.load(Ordering::SeqCst));
    assert_eq!(
        control.fetches.load(Ordering::SeqCst),
        fetched + 1,
        "the first caller owns the held card look"
    );

    let unit = crate::root::plane_node::node().mint().get();
    assert!(
        records.get(unit).is_none(),
        "never overwrite an actual live unit"
    );
    let ticket = dispatcher.inline_ticket().expect("an actual waiter ticket");
    records.admitted(
        unit,
        UnitRecord {
            principal: Some(principal.clone()),
            depth: 0,
        },
    );

    let mut reply = vec![0_u8; 64 * 1024];
    let mut units = [UnitCount::ZERO; 32];
    let mut writes = [RecordWrite::ZERO; 32];
    let mut fields = [OutField::ZERO; 32];
    let mut arena = vec![0_u8; 64 * 1024];
    let mut piece: OnPieceIn = blank_in();
    piece.unit = unit;
    piece.claim = AGENT_RPC_CLAIM;
    piece.from = FROM_KERNEL;
    piece.member = AbiStr::of("vendor");

    piece.caller_ref = AbiStr::of("c0ffee01");
    piece.attempt_no = 1;
    piece.bytes = Blob::of(b"");
    piece.reply_buf = reply.as_mut_ptr();
    piece.reply_cap = reply.len();
    piece.units_buf = units.as_mut_ptr();
    piece.units_cap = units.len();
    piece.records_buf = writes.as_mut_ptr();
    piece.records_cap = writes.len();
    piece.fields_buf = fields.as_mut_ptr();
    piece.fields_cap = fields.len();
    piece.arena_buf = arena.as_mut_ptr();
    piece.arena_cap = arena.len();
    let body;
    let mut frame: Frame<OnPieceIn, OnPieceOut> = Frame::new(piece, blank_out());
    let mut waiter = RetireWaiter {
        plane,
        ticket,
        unit,
        records,
        active: true,
    };

    let mut arrival: ArriveIn = blank_in();
    arrival.unit = unit;
    arrival.claim = AGENT_RPC_CLAIM;
    arrival.method = AbiStr::of("POST");
    arrival.target = AbiStr {
        ptr: TARGET.as_ptr(),
        len: TARGET.len(),
    };
    arrival.body = Blob::of(WAITER_REQUEST).with_fmt(BLOB_OCTETS);
    let mut arrived: Frame<ArriveIn, ArriveOut> = Frame::new(arrival, blank_out());
    assert_eq!(
        waiter.plane.call(slot::ARRIVE, &mut arrived).outcome,
        Outcome::Ready,
        "the same actual A2A instance admits the verified waiter's unit"
    );
    let called =
        waiter
            .plane
            .call_inline(waiter.ticket.ticket(), false, slot::ON_PIECE, &mut frame);
    assert_eq!(called.outcome, Outcome::Pending, "{:?}", called.error);
    assert_eq!(
        control.fetches.load(Ordering::SeqCst),
        fetched + 1,
        "the distinct actual Pending unit did not start a competing card look"
    );

    let wake = Arc::new(WaiterWake::default());
    let waker = Waker::from(wake.clone());
    waiter.ticket.register(&waker);

    let called = waiter
        .plane
        .call_inline(waiter.ticket.ticket(), true, slot::ON_PIECE, &mut frame);
    assert_eq!(called.outcome, Outcome::Pending, "{:?}", called.error);
    assert_eq!(wake.count.load(Ordering::SeqCst), 0, "no pre-cancel wake");
    assert!(control.held.load(Ordering::SeqCst));
    assert_eq!(control.fetches.load(Ordering::SeqCst), fetched + 1);

    drop(owner);
    tokio::time::timeout(DEADLINE, async {
        wake.notified.notified().await;
        assert_ne!(
            wake.count.load(Ordering::SeqCst),
            0,
            "the actual waiter ticket was woken"
        );
        loop {
            waiter.ticket.register(&waker);
            let called =
                waiter
                    .plane
                    .call_inline(waiter.ticket.ticket(), true, slot::ON_PIECE, &mut frame);
            match called.outcome {
                Outcome::Pending => wake.notified.notified().await,
                Outcome::Ready => break,
                other => panic!(
                    "the actual card waiter failed: {other:?}: {:?}",
                    called.error
                ),
            }
        }
    })
    .await
    .expect("the cancelled owner's waiter proceeds within five seconds");
    assert!(
        control.held.load(Ordering::SeqCst),
        "the first response stayed held"
    );

    assert_eq!(frame.out.reply_status, 0);
    assert_ne!(frame.out.flags & EMIT_TO_FAR_END, 0);
    let span = |span: busbar_contract::abi::mechanism::call::Span| {
        let start = span.offset as usize;
        &arena[start..start + span.len as usize]
    };
    assert_eq!(span(frame.out.verb), b"POST");
    assert_eq!(span(frame.out.target), b"/agent");
    frame.input.from = FROM_CALLER;
    frame.input.flags = PIECE_LAST;
    frame.input.attempt_no = 0;
    frame.input.bytes = Blob::of(WAITER_REQUEST).with_fmt(BLOB_OCTETS);
    frame.out = blank_out();
    let called =
        waiter
            .plane
            .call_inline(waiter.ticket.ticket(), false, slot::ON_PIECE, &mut frame);
    assert_eq!(called.outcome, Outcome::Ready, "{:?}", called.error);
    assert_ne!(frame.out.flags & EMIT_TO_FAR_END, 0);
    assert_eq!(&reply[..frame.out.emitted as usize], WAITER_REQUEST);
    let response = reqwest::Client::new()
        .post(&control.endpoint)
        .header("content-type", "application/json")
        .body(reply[..frame.out.emitted as usize].to_vec())
        .timeout(DEADLINE)
        .send()
        .await
        .expect("the actual waiter reaches the peer");
    let status = u32::from(response.status().as_u16());
    assert_eq!(status, 200);
    body = response.bytes().await.expect("the actual peer card answer");
    frame.input.from = FROM_FAR_END;
    frame.input.flags = PIECE_LAST | PIECE_HAS_STATUS;
    frame.input.status_code = status;
    frame.input.bytes = Blob {
        ptr: body.as_ptr(),
        len: body.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    frame.out = blank_out();
    let mut resume = false;
    tokio::time::timeout(DEADLINE, async {
        loop {
            waiter.ticket.register(&waker);
            let called = waiter.plane.call_inline(
                waiter.ticket.ticket(),
                resume,
                slot::ON_PIECE,
                &mut frame,
            );
            match called.outcome {
                Outcome::Ready => break,
                Outcome::Pending => {
                    resume = true;
                    wake.notified.notified().await;
                }
                other => panic!(
                    "the actual waiter reply failed: {other:?}: {:?}",
                    called.error
                ),
            }
        }
    })
    .await
    .expect("the actual waiter reply settles");
    assert_eq!(
        frame.out.reply_status, 200,
        "the actual SDK waiter answers OK"
    );
    assert_ne!(frame.out.flags & EMIT_DONE, 0);
    assert!(frame.out.emitted <= reply.len() as u64);
    assert_ne!(frame.out.emitted, 0);
    let answer: serde_json::Value = serde_json::from_slice(&reply[..frame.out.emitted as usize])
        .expect("the actual waiter returns its JSON-RPC card answer");
    assert!(answer.get("result").is_some(), "{answer}");
    assert_eq!(
        control.fetches.load(Ordering::SeqCst) - fetched,
        2,
        "the waiter took over the abandoned flight and looked for itself"
    );
    assert_eq!(waiter.retire(), Outcome::Ready);
}
