// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /a2a/push`: AN AGENT REPORTING A TASK IT MOVED, to the callback busbar registered with it
//! (the engine's `pushback::push_notification`; ARCHITECT ruling Q3, 2026-10-04: a public route of
//! the plane, served by its `serve` op, authorised by busbar's own per-task capability, bounded by
//! 1.5.5's push-volume limit).
//!
//! In the engine's order, every step a refusal that costs nothing further:
//!
//! 1. the presented token names a task this instance minted it for, and the host's signature of
//!    that task is the one presented, or `401`;
//! 2. that task's push-volume budget has room ([`crate::push::PushLimiter`]), or `429` with
//!    `retry-after`;
//! 3. the body is at most [`MAX_PUSH_BODY`], or `413`;
//! 4. the task is held for its caller and still live, or `401` (the same sentence as every other
//!    refusal: whether a task exists or has ended is not told here);
//! 5. the body is JSON, or `400`;
//! 6. the state it reports is recorded on the task's own chain through the one transition table
//!    (a re-reported state is a retry, not a move; a move that cannot be recorded is still `202`);
//! 7. the caller's own delivery is queued from busbar's own row, never from the pushed body.

use std::task::Poll;

use busbar_contract::abi::host::service::ItemSpan;
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_contract::abi::plane::{ServeIn, ServeOut, AUDIT_NONE};
use busbar_contract::abi::sdk::{Instance, Lent, Out};
use serde_json::{json, Value};

use crate::a2a::task::Task;
use crate::plane_door::A2aDoor;
use crate::tasks::{self, Halt, Step, Write};

/// The ceiling on a pushed body: one task document (the engine's `MAX_PUSH_BODY`).
pub const MAX_PUSH_BODY: usize = 64 * 1024;

/// The one sentence every authorisation refusal answers with.
pub const UNAUTHORISED: &str =
    "this endpoint is addressed by the push token busbar registered with the agent";

/// The sentence a spent push-volume budget answers with.
pub const RATE_LIMITED: &str = "this task's push volume has exceeded its window budget";

const JSON_FIELDS: &[(&str, &str)] = &[("content-type", crate::arrival::JSON_MEDIA_TYPE)];

/// A refusal in the one shape this endpoint speaks: `{"error":{"message":...}}`, not a JSON-RPC
/// envelope (the caller is an HTTP webhook client).
fn refused(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    status: u32,
    message: &str,
    extra: &[(&str, &str)],
) -> Outcome {
    let body = serde_json::to_vec(&json!({ "error": { "message": message } })).unwrap_or_default();
    let mut fields = JSON_FIELDS.to_vec();
    fields.extend_from_slice(extra);
    out.answer(input, status, &fields, &body, AUDIT_NONE)
}

/// `202`, with no document: the report was taken, the move it recorded written to the task's
/// chain with the answer (SEAM-L(t)).
fn accepted(input: &Lent<'_, ServeIn>, out: &mut Out<'_, ServeOut>, writes: &[Write]) -> Outcome {
    answer(input, out, (202, &[], b""), writes)
}

/// A whole serve answer: `status`, the head `fields`, `body`, and the record `writes` it carries,
/// every span in the one arena; a short buffer answers FAILED with what each needs.
fn answer(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    (status, head, body): (u32, &[(&str, &str)], &[u8]),
    writes: &[Write],
) -> Outcome {
    use busbar_contract::abi::plane::{OutField, RecordWrite, RECORD_PUT};
    let (mut reply, mut fields, mut arena, mut records) = (
        input.reply_buf(),
        input.fields_buf(),
        input.arena_buf(),
        input.records_buf(),
    );
    reply.extend(body);
    for (name, value) in head {
        fields.push(OutField {
            name: arena.span(name.as_bytes()),
            value: arena.span(value.as_bytes()),
        });
    }
    for w in writes {
        records.push(RecordWrite {
            kind: crate::task_door::kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }
    let short = !(reply.fits() && fields.fits() && arena.fits() && records.fits());
    let (rw, rnd) = reply.settle(short);
    let (fw, fnd) = fields.settle(short);
    let (cw, cnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.reply_written, rw as u64);
    out.set(|o| &o.reply_needed, rnd as u64);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.records_written, cw as u32);
    out.set(|o| &o.records_needed, cnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    out.set(|o| &o.status, status);
    out.set(|o| &o.audit, AUDIT_NONE);
    Outcome::Ready
}

/// What a push keeps across its op's PENDING entries: it has already spent its push-volume budget,
/// so a re-entry does not spend it twice.
struct Admitted;

/// The host's signature of `task_id`'s token input, on handle `seq` of the op's ticket.
fn signature(
    plane: &A2aDoor,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    seq: u32,
    task_id: &str,
) -> Option<Vec<u8>> {
    let services = plane.services.as_ref()?;
    let absent = Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    let mut buf = vec![0u8; 1024];
    let mut spans = [ItemSpan {
        key: absent,
        value: absent,
    }; 2];
    let handle = CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    };
    let sig = services
        .sign(
            handle,
            &crate::push::token_input(task_id),
            &mut buf,
            &mut spans,
        )
        .ok()?;
    Some(sig.signature.to_vec())
}

/// `serve` of the push route.
pub(crate) fn serve(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, ServeIn>,
    mut out: Out<'_, ServeOut>,
) -> Outcome {
    let ticket = instance.ticket();
    let fields = input.fields();
    let authorization = fields
        .iter()
        .find(|f| {
            f.field(|f| &f.name)
                .as_str()
                .is_ok_and(|n| n.eq_ignore_ascii_case("authorization"))
        })
        .and_then(|f| f.field(|f| &f.value).as_str().ok())
        .unwrap_or_default();
    // 1. THE CAPABILITY: a token this instance minted, signed again by the host and compared in
    //    constant time.
    let Some((task_id, caller, presented)) = plane.tokens.claim_of_authorization(authorization)
    else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    let verified = signature(plane, ticket, 0, &task_id)
        .is_some_and(|sig| crate::push::verified(&sig, presented));
    if !verified {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    }
    let Some(host) = plane.host.as_ref() else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    let Poll::Ready(Ok(reading)) = host.connector_from(ticket, 1).clock_now() else {
        return Outcome::Failed;
    };
    let now = reading.wall_ns / 1_000_000_000;
    // 2. THE VOLUME BOUND, before any of the cost it bounds; spent once across re-entries.
    let resumed = instance.resume::<Admitted>().is_some();
    if !resumed && !plane.pushes.admit(&task_id, now) {
        let window = crate::push::PUSH_RATE_WINDOW_SECS.to_string();
        return refused(
            &input,
            &mut out,
            429,
            RATE_LIMITED,
            &[("retry-after", window.as_str())],
        );
    }
    // 3. THE BODY'S CEILING.
    let body = input.field(|i| &i.body).bytes();
    if body.len() > MAX_PUSH_BODY {
        return refused(
            &input,
            &mut out,
            413,
            "a push notification is one task document",
            &[],
        );
    }
    let mut via = crate::task_door::Via::new(host, plane.services, ticket, 2, &plane.grown);
    // 4. THE TASK, held and live.
    let pend = || {
        instance.park(Admitted);
        Outcome::Pending
    };
    let held = match tasks::get(&mut via, &caller, &task_id, now) {
        Err(Halt::Pending) => return pend(),
        Err(Halt::Failed(_)) | Ok(None) => {
            return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
        }
        Ok(Some(held)) => held,
    };
    let Ok(task) = Task::from_row(&held.row) else {
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    };
    if task.state.is_terminal() {
        plane.tokens.forget(&task_id);
        return refused(&input, &mut out, 401, UNAUTHORISED, &[]);
    }
    // 5. A JSON DOCUMENT.
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return refused(
            &input,
            &mut out,
            400,
            "a push notification is a JSON task document",
            &[],
        );
    };
    // 6. THE MOVE, through the one transition table, read by the one reader of a task's state.
    let reported = crate::identity::reported_task_state(&document);
    let mut writes = Vec::new();
    let moved = if reported == task.state {
        held.row
    } else {
        let at = Step {
            caller: &caller,
            request_id: "",
            now,
        };
        match tasks::transition(&mut via, &at, &task_id, reported, &mut writes) {
            Err(Halt::Pending) => return pend(),
            // A move that cannot be recorded (commonly a push about a task already terminal) is
            // the agent being redundant: `202` stops its retry loop.
            Err(Halt::Failed(_)) | Ok(None) => return accepted(&input, &mut out, &[]),
            Ok(Some(row)) => row,
        }
    };
    // 7. THE CALLER'S OWN DELIVERY, from busbar's row.
    match crate::push_door::queue_moved(&plane.deliveries, &mut via, &caller, &moved) {
        Err(Halt::Pending) => return pend(),
        Err(Halt::Failed(_)) | Ok(_) => {}
    }
    // The ending spends the token, once the answer is final: forgotten before a PENDING entry,
    // the re-entry would find no token and refuse the very report that ended the task.
    if reported.is_terminal() {
        plane.tokens.forget(&task_id);
    }
    accepted(&input, &mut out, &writes)
}
