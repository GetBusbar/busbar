// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S HALF OF THE TASK VERBS: the host records the task store reads and the destination
//! judge, reached through [`Via`], and `on_piece` for a unit whose verb the plane answers itself
//! ([`crate::local`]).
//!
//! A unit's pieces share its ticket, and the host keeps every service result under its handle until
//! the ticket is recycled. So each piece's connector counts its handles on from what the unit's
//! finished pieces issued ([`Pass`]), and a piece that answers PENDING, or is re-called for a short
//! answer, runs again from the top with the same count and the same stamp: every call it makes is
//! re-issued under its own handle and reads the stored result, so no record is read twice to
//! different effect and no claim is won twice.

use std::task::Poll;

use busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
use busbar_contract::abi::host::service::ItemSpan;
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    OnPieceIn, OnPieceOut, OutField, RecordWrite, EMIT_DONE, FROM_CALLER, RECORD_PUT,
};
use busbar_contract::abi::sdk::conn::{Connector, Host};
use busbar_contract::abi::sdk::{Instance, Keyed, Lent, Out, ServiceError, Services};
use serde_json::Value;

use crate::arrival::{Disposition, JSON_MEDIA_TYPE};
use crate::local::{self, LocalVerb, Reach};
use crate::plane_door::A2aDoor;
use crate::records::HELD_KINDS;
use crate::tasks::{self, Halt, Records, Write};

/// How many tasks one retention sweep touches; the rest wait for the next second's.
const SWEEP_BUDGET: usize = 32;

/// What a unit's pieces carry from one to the next.
#[derive(Debug, Default)]
pub struct Pass {
    /// The host services its finished pieces made: the next piece's handles count on from here.
    pub(crate) issued: u32,
    /// The piece in flight's stamp, kept across its re-entries.
    entry: Option<Entry>,
    /// The reply bytes the last window did not hold.
    rest: Vec<u8>,
}

/// One piece's stamp: its clock, and whether it runs the second's sweep.
#[derive(Debug, Clone, Copy)]
struct Entry {
    now: u64,
    sweep: bool,
}

/// THE HOST RECORDS AND THE DESTINATION JUDGE, for one piece: its connector, and the host services
/// the door was opened with. Every call counts on the piece's one handle sequence.
pub struct Via<'h> {
    host: &'h Host,
    services: Option<Services>,
    ticket: Ticket,
    conn: Connector<'h>,
}

impl<'h> Via<'h> {
    /// The piece's calls, counting on from the `issued` its unit's finished pieces made.
    pub fn new(host: &'h Host, services: Option<Services>, ticket: Ticket, issued: u32) -> Self {
        Self {
            host,
            services,
            ticket,
            conn: host.connector_from(ticket, issued),
        }
    }

    /// The handles this piece has issued, counted from its unit's start.
    pub const fn issued(&self) -> u32 {
        self.conn.issued()
    }

    /// `random.fill` into `buf`, under this piece's next handle.
    ///
    /// # Errors
    /// [`Halt::Failed`] when the host serves no `random.fill` or declined it.
    pub fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        let Some(services) = self.services else {
            return Err(Halt::Failed(format!("{:?}", ServiceError::Unserved)));
        };
        let handle = self.next_handle();
        services
            .random_fill(handle, buf)
            .map_err(|e| Halt::Failed(format!("{e:?}")))
    }

    /// The next handle, for a host service the connector does not wrap.
    fn next_handle(&mut self) -> CompletionHandle {
        let seq = self.conn.issued();
        self.conn = self.host.connector_from(self.ticket, seq + 1);
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }
}

/// TRANSITIONAL: the SDK's host-records wrappers land with K-RECORDS' SDK lane (ARCHITECT ruling on
/// PR #141); until then every records call fails in these words and a local verb answers unreadable.
const RECORDS_UNSERVED: &str = "the host records services are not reachable from the SDK yet";

impl Records for Via<'_> {
    fn get(&mut self, _kind: &str, _key: &str) -> Result<Option<Vec<u8>>, Halt> {
        Err(Halt::Failed(RECORDS_UNSERVED.to_owned()))
    }

    fn list(&mut self, _kind: &str, _prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        Err(Halt::Failed(RECORDS_UNSERVED.to_owned()))
    }

    fn claim(&mut self, _kind: &str, _key: &str, _ttl_ms: u64) -> Result<bool, Halt> {
        Err(Halt::Failed(RECORDS_UNSERVED.to_owned()))
    }
}

impl crate::task_hop::Mint for Via<'_> {
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt> {
        Via::random(self, buf)
    }
}

/// Room for the judged addresses of one destination.
const JUDGED_BYTES: usize = 512;
/// One span per judged address.
const JUDGED_ADDRESSES: usize = 16;

impl Reach for Via<'_> {
    fn judge(&mut self, dest: &str) -> Result<u64, Halt> {
        let Some(services) = self.services else {
            return Err(Halt::Failed(format!("{:?}", ServiceError::Unserved)));
        };
        let handle = self.next_handle();
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let mut bytes = [0u8; JUDGED_BYTES];
        let mut spans = [ItemSpan {
            key: absent,
            value: absent,
        }; JUDGED_ADDRESSES];
        match services.dest_judge(
            handle,
            dest,
            EGRESS_OPEN_WEB,
            Some((&mut bytes[..], &mut spans[..])),
        ) {
            Poll::Pending => Err(Halt::Pending),
            Poll::Ready(Ok(judged)) => Ok(judged.verdict),
            Poll::Ready(Err(e)) => Err(Halt::Failed(format!("{e:?}"))),
        }
    }
}

/// The first caller of each second runs the sweep: `swept` holds the last second swept.
fn claim_sweep(swept: &Keyed<(), u64>, now: u64) -> bool {
    swept.with_all(|m| {
        let due = m.get(&()).is_none_or(|last| now > *last);
        if due {
            m.insert((), now);
        }
        due
    })
}

/// The local verb a unit arrived as.
fn verb_of(disposition: &Disposition) -> Option<LocalVerb> {
    match disposition {
        Disposition::Request { row, .. } => local::verb_of(row.method),
        _ => None,
    }
}

/// `on_piece` for a unit whose verb the plane answers itself; `None` for any other unit.
pub fn on_piece(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, OnPieceIn>,
    mut out: Out<'_, OnPieceOut>,
) -> Option<Outcome> {
    let unit = input.get().unit;
    let (verb, rest, composed) = plane.units.with(&unit, |u| {
        let u = u?;
        Some((
            verb_of(&u.disposition)?,
            std::mem::take(&mut u.pass.rest),
            u.envelope.clone(),
        ))
    })?;
    // The next window of a reply already answered.
    if !rest.is_empty() {
        return Some(window(plane, unit, &input, &mut out, (0, &rest), &[]));
    }
    // The ATTEMPT piece: the caller's body follows, and the answer comes on it.
    if input.get().from != FROM_CALLER {
        return Some(Outcome::Ready);
    }
    let host = plane.host.as_ref()?;
    let Poll::Ready(Ok(reading)) = host.connector(instance.ticket()).clock_now() else {
        return Some(Outcome::Failed);
    };
    let clock = reading.wall_ns / 1_000_000_000;
    let (base, entry) = plane.units.with(&unit, |u| {
        let u = u?;
        let entry = *u.pass.entry.get_or_insert_with(|| Entry {
            now: clock,
            sweep: claim_sweep(&plane.swept, clock),
        });
        Some((u.pass.issued, entry))
    })?;
    let mut via = Via::new(host, plane.services, instance.ticket(), base);
    // An HTTP+JSON unit answers the envelope its request spelled, not the caller's body.
    let raw = composed
        .as_deref()
        .unwrap_or_else(|| input.field(|i| &i.bytes).bytes());
    let envelope: Value = serde_json::from_slice(raw).unwrap_or(Value::Null);
    let caller = input.field(|i| &i.caller_ref).as_str().unwrap_or_default();
    let mut writes = Vec::new();
    if entry.sweep {
        // A sweep that fails leaves nothing behind and does not fail the verb.
        match tasks::sweep(&mut via, entry.now, SWEEP_BUDGET, &mut writes) {
            Err(Halt::Pending) => return Some(Outcome::Pending),
            Err(Halt::Failed(_)) => writes.clear(),
            Ok(()) => {}
        }
    }
    let swept = writes.len();
    let answer = match local::answer(&mut via, verb, &envelope, caller, entry.now, &mut writes) {
        Err(Halt::Pending) => return Some(Outcome::Pending),
        Err(Halt::Failed(_)) => {
            writes.truncate(swept);
            local::unreadable(envelope.get("id").unwrap_or(&Value::Null))
        }
        // TRANSITIONAL: a subscribe to a live task is relayed once the driver serves the relay.
        Ok(None) => return Some(Outcome::Refused),
        Ok(Some(answer)) => answer,
    };
    let issued = via.issued();
    let body = match composed {
        Some(_) => crate::rest::reframe(answer.status, &answer.body),
        None => answer.body,
    };
    let done = window(
        plane,
        unit,
        &input,
        &mut out,
        (answer.status, &body),
        &writes,
    );
    if done == Outcome::Ready {
        plane.units.with(&unit, |u| {
            if let Some(u) = u {
                u.pass.issued = issued;
                u.pass.entry = None;
            }
        });
    }
    Some(done)
}

/// The kind index `kind` is in the tail's record kinds.
pub(crate) fn kind_index(kind: &str) -> u32 {
    HELD_KINDS
        .iter()
        .position(|k| *k == kind)
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(u32::MAX)
}

/// Answer one window of a local reply: as many bytes as the reply buffer holds, and on the first
/// window (`status != 0`) its status, its `content-type` and the record writes. What does not fit
/// is kept for the next window (`more = 1`); a short field, record or arena buffer is a short
/// answer, written nowhere.
fn window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
) -> Outcome {
    let (mut reply, mut fields, mut records, mut arena) = (
        input.reply_buf(),
        input.fields_buf(),
        input.records_buf(),
        input.arena_buf(),
    );
    if status != 0 {
        fields.push(OutField {
            name: arena.span(b"content-type"),
            value: arena.span(JSON_MEDIA_TYPE.as_bytes()),
        });
    }
    for w in writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }
    let short = !(fields.fits() && records.fits() && arena.fits());
    let (fw, fnd) = fields.settle(short);
    let (rw, rnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.records_written, rw as u32);
    out.set(|o| &o.records_needed, rnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    let n = reply.stream(body);
    let rest = &body[n..];
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.reply_status, status);
    if rest.is_empty() {
        out.set(|o| &o.flags, EMIT_DONE);
    } else {
        out.set(|o| &o.more, 1);
        plane.units.with(&unit, |u| {
            if let Some(u) = u {
                u.pass.rest = rest.to_vec();
            }
        });
    }
    Outcome::Ready
}

#[cfg(test)]
#[path = "tests/task_door.rs"]
mod tests;
