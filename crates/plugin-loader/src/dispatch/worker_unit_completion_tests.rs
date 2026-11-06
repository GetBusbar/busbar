// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::plane::{FROM_FAR_END, PIECE_CUT, PIECE_LAST};
use busbar_contract::plane_calls::{PlaneCalls, Retirement};

fn submit(
    d: &Dispatcher,
    p: &Plugin<Plane>,
    ticket: Ticket,
    frame: Frame<OnPieceIn, OnPieceOut>,
) -> Reply<OnPieceIn, OnPieceOut> {
    d.submit(
        p,
        ticket,
        plane_slot::ON_PIECE,
        frame,
        DeadlineClass::Stream,
        0,
    )
}

fn terminal(unit: u64, flags: u32) -> Frame<OnPieceIn, OnPieceOut> {
    let mut frame = frame(unit, 10, flags);
    frame.input.from = FROM_FAR_END;
    frame
}

fn retired(done: &Done<OnPieceIn, OnPieceOut>) {
    assert_eq!(done.retirement, Some(Retirement::UnitCompleted));
    assert!(done.disposition.is_none());
    assert!(done.cancel_writes.is_empty());
    assert_eq!(done.lease, 0);
    if let Some(frame) = &done.frame {
        assert_eq!(
            (
                frame.out.emitted,
                frame.out.units_written,
                frame.out.records_written
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn pending_and_queued_siblings_retire_before_primary_is_consumed() {
    for primary_first in [false, true] {
        let (d, p, c) = rig(DispatchConfig::default());
        let (near, far) = pair(&d, &p, 501);
        let primary = d.mint(0).unwrap();
        d.bind_plane_unit(&p, primary, 501);
        let a = submit(&d, &p, near, frame(501, 10, 0));
        let b = submit(&d, &p, far, frame(501, 10, 0));
        until(|| d.is_pending(near) && d.is_pending(far));
        let queued = submit(&d, &p, far, frame(501, 10, 0));
        let done = submit(&d, &p, primary, frame(501, 10, PIECE_LAST));
        let primary_answer = if primary_first {
            Some(done.wait(WAIT).unwrap())
        } else {
            None
        };
        for sibling in [
            a.wait(WAIT).unwrap(),
            b.wait(WAIT).unwrap(),
            queued.wait(WAIT).unwrap(),
        ] {
            retired(&sibling);
        }
        let primary_answer = primary_answer.unwrap_or_else(|| done.wait(WAIT).unwrap());
        assert_eq!(primary_answer.outcome, Outcome::Ready);
        assert_eq!(primary_answer.retirement, None);
        assert_eq!(primary_answer.frame.unwrap().out.flags, EMIT_DONE);
        assert_eq!(c.pieces.load(Ordering::SeqCst), 3);
        assert!(c.cancels.lock().unwrap().is_empty());
        for ticket in [near, far, primary] {
            d.recycle(ticket);
        }
    }
}

#[test]
fn late_terminal_retirement_survives_more_than_4096_other_completions() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 502);
    // Establish the stream on both tickets before the primary closes it.
    let pending = submit(&d, &p, far, frame(502, 10, 0));
    until(|| d.is_pending(far));
    let primary = submit(&d, &p, near, frame(502, 10, PIECE_LAST));
    retired(&pending.wait(WAIT).unwrap());
    for unit in 1_000..5_097 {
        let ticket = d.mint(0).unwrap();
        d.bind_plane_unit(&p, ticket, unit);
        assert_eq!(
            submit(&d, &p, ticket, frame(unit, 10, PIECE_LAST))
                .wait(WAIT)
                .unwrap()
                .outcome,
            Outcome::Ready
        );
        d.recycle(ticket);
    }
    for flags in [PIECE_LAST, PIECE_LAST | PIECE_CUT] {
        retired(
            &submit(&d, &p, far, terminal(502, flags))
                .wait(WAIT)
                .unwrap(),
        );
    }
    assert_eq!(primary.wait(WAIT).unwrap().retirement, None);
    assert_eq!(c.pieces.load(Ordering::SeqCst), 4_099);
    assert!(c.cancels.lock().unwrap().is_empty());
    d.drop_client(far);
    assert!(answer(d.cancel_plane_unit(&p, far, 502)).is_none());
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn completed_binding_refuses_wrong_stream_payload_direction_and_instance() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 503);
    let pending = submit(&d, &p, far, frame(503, 10, 0));
    until(|| d.is_pending(far));
    let primary = submit(&d, &p, near, frame(503, 10, PIECE_LAST));
    retired(&pending.wait(WAIT).unwrap());
    assert_eq!(primary.wait(WAIT).unwrap().outcome, Outcome::Ready);
    let mut wrong_stream = terminal(503, PIECE_LAST);
    wrong_stream.input.stream = 11;
    let mut nonempty = terminal(503, PIECE_LAST);
    nonempty.input.bytes = Blob {
        ptr: b"x".as_ptr(),
        len: 1,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut fields = terminal(503, PIECE_LAST);
    fields.input.head_fields_len = 1;
    let mut near_terminal = terminal(503, PIECE_LAST);
    near_terminal.input.from = FROM_CALLER;
    for frame in [
        wrong_stream,
        nonempty,
        fields,
        near_terminal,
        terminal(503, 0),
        terminal(504, PIECE_LAST),
    ] {
        let done = submit(&d, &p, far, frame).wait(WAIT).unwrap();
        assert_eq!(done.outcome, Outcome::Refused);
        assert_eq!(done.retirement, None);
    }
    // A newly bound ticket has no custody from the completion, even with the same unit.
    let newcomer = d.mint(0).unwrap();
    d.bind_plane_unit(&p, newcomer, 503);
    let unknown = submit(&d, &p, newcomer, terminal(503, PIECE_LAST))
        .wait(WAIT)
        .unwrap();
    assert_eq!(unknown.outcome, Outcome::Refused);
    assert_eq!(unknown.retirement, None);
    let primary_late = submit(&d, &p, near, terminal(503, PIECE_LAST))
        .wait(WAIT)
        .unwrap();
    assert_eq!(primary_late.outcome, Outcome::Refused);
    assert_eq!(primary_late.retirement, None);
    d.recycle(newcomer);
    let (other, other_control) = plugin(&d);
    let foreign = submit(&d, &other, far, terminal(503, PIECE_LAST))
        .wait(WAIT)
        .unwrap();
    assert_eq!(foreign.outcome, Outcome::Refused);
    assert_eq!(foreign.retirement, None);
    assert_eq!(other_control.pieces.load(Ordering::SeqCst), 0);
    d.recycle(far);
    until(|| !d.slot_state(far).0);
    let stale = submit(&d, &p, far, terminal(503, PIECE_LAST))
        .wait(WAIT)
        .unwrap();
    assert_eq!(stale.outcome, Outcome::Fault);
    assert_eq!(stale.retirement, None);
    assert_eq!(c.pieces.load(Ordering::SeqCst), 2);
    assert!(c.cancels.lock().unwrap().is_empty());
    d.recycle(near);
}

#[test]
fn cancellation_never_acquires_completion_retirement() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 505);
    let pending = submit(&d, &p, far, frame(505, 10, 0));
    until(|| d.is_pending(far));
    assert!(answer(d.cancel_plane_unit(&p, near, 505)).is_some());
    assert_eq!(pending.wait(WAIT).unwrap().retirement, None);
    let late = submit(&d, &p, far, terminal(505, PIECE_LAST))
        .wait(WAIT)
        .unwrap();
    assert_eq!(late.outcome, Outcome::Refused);
    assert_eq!(late.retirement, None);
    assert_eq!(*c.cancels.lock().unwrap(), vec![505]);
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn piece_retirement_is_hidden_until_settlement_and_remains_stable() {
    let (dispatcher, p, c) = rig(DispatchConfig::default());
    let d = Arc::new(dispatcher);
    let (near, far) = pair(&d, &p, 506);
    let plane = super::super::super::super::plane_calls::PlaneInstance::new(p, d.clone(), 0);
    let pending_frame = frame(506, 10, 0);
    let mut pending = plane.on_piece(far, pending_frame.input, pending_frame.out, Arc::new(()));
    assert_eq!(pending.retirement(), None);
    until(|| d.is_pending(far));
    let primary_frame = frame(506, 10, PIECE_LAST);
    let mut primary = plane.on_piece(near, primary_frame.input, primary_frame.out, Arc::new(()));
    until(|| c.pieces.load(Ordering::SeqCst) == 2 && !d.is_pending(far));
    assert_eq!(pending.retirement(), None);
    until(|| pending.settled().is_some());
    assert_eq!(pending.retirement(), Some(Retirement::UnitCompleted));
    assert!(
        pending.out().is_none(),
        "retirement supplies no plugin output"
    );
    for _ in 0..2 {
        assert!(pending.settled().is_some());
        assert_eq!(pending.retirement(), Some(Retirement::UnitCompleted));
    }
    until(|| primary.settled().is_some());
    assert_eq!(primary.retirement(), None);
    assert_eq!(primary.out().unwrap().flags, EMIT_DONE);
    drop(pending);
    drop(primary);
    plane.drop_client(far);
    assert!(answer(plane.cancel_unit(far, 506)).is_none());
    plane.recycle(near);
    plane.recycle(far);
    assert!(c.cancels.lock().unwrap().is_empty());
}
