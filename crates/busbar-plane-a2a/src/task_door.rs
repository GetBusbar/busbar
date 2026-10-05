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
    OnPieceIn, OnPieceOut, OutField, RecordWrite, UnitCount, EMIT_DONE, FROM_CALLER, RECORD_PUT,
    UNITS_REPORTED,
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
    /// The plane answered the verb itself (the admission passed): the unit is served, and every
    /// window reports its fee unit, as the served engine kept the fee of a verb it answered.
    served: bool,
    /// A card read's answer was written: a later piece answers nothing more.
    answered: bool,
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
    grown: &'h Grown,
}

impl<'h> Via<'h> {
    /// The piece's calls, counting on from the `issued` its unit's finished pieces made; `grown` is
    /// the instance's book of the sizes short records answers named.
    pub fn new(
        host: &'h Host,
        services: Option<Services>,
        ticket: Ticket,
        issued: u32,
        grown: &'h Grown,
    ) -> Self {
        Self {
            host,
            services,
            ticket,
            conn: host.connector_from(ticket, issued),
            grown,
        }
    }

    /// The services the door was opened with.
    fn services(&self) -> Result<Services, Halt> {
        self.services
            .ok_or_else(|| Halt::Failed(format!("{:?}", ServiceError::Unserved)))
    }

    /// The buffer sizes to issue `handle` at: what a short answer on it already named, else
    /// `(bytes, items)`.
    fn sized(&self, handle: CompletionHandle, bytes: usize, items: usize) -> (usize, usize) {
        match self.grown.get(&grown_key(handle)) {
            Some((b, i)) => (
                usize::try_from(b).unwrap_or(usize::MAX).max(bytes),
                usize::try_from(i).unwrap_or(usize::MAX).max(items),
            ),
            None => (bytes, items),
        }
    }

    /// A short answer on `handle` named `bytes` and `items`: kept, so every entry of the piece
    /// issues the handle at that size from now on.
    fn grow(&self, handle: CompletionHandle, bytes: u64, items: u64) {
        self.grown.with_all(|m| {
            if m.len() >= GROWN_MAX {
                m.clear();
            }
            m.insert(grown_key(handle), (bytes, items));
        });
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

/// THE SIZES SHORT RECORDS ANSWERS NAMED, per handle (`ticket slot, ticket generation, handle
/// sequence`). A piece that answers PENDING runs again from the top and re-issues every handle
/// (the replay rule); one the host already answered short is re-issued at the size it named, so no
/// handle is answered short twice (the design's host services, the short-buffer rule: a second
/// short answer on one handle is FAULT). A stale entry only enlarges a buffer; the book is cleared at
/// [`GROWN_MAX`] entries.
pub type Grown = Keyed<(u32, u32, u32), (u64, u64)>;

/// The most entries [`Grown`] holds before it is cleared.
const GROWN_MAX: usize = 4096;

/// Room for one record on its first read: a task row with its history and artifacts. A longer one
/// is re-called once, on the same handle, at the size the host named.
const RECORD_BYTES: usize = 64 * 1024;

/// The records one page of a listing asks for; a page that comes back full asks for the next.
const PAGE_RECORDS: u32 = 64;

/// Room for one page of a listing on its first read.
const PAGE_BYTES: usize = 256 * 1024;

/// The [`Grown`] key of `handle`.
const fn grown_key(handle: CompletionHandle) -> (u32, u32, u32) {
    (handle.ticket.slot, handle.ticket.generation, handle.seq)
}

/// A records answer that is not a value, as the task store reads it.
fn halted(e: ServiceError) -> Halt {
    Halt::Failed(format!("{e:?}"))
}

/// What one issue of a records call answered: its value, PENDING, or short at a size.
enum Issued<T> {
    Value(T),
    Pending,
    Short(u64, u64),
}

impl<T> Issued<T> {
    /// The wrapper's answer, read for the replay and short-buffer rules.
    fn of(answer: Poll<Result<T, ServiceError>>) -> Result<Self, Halt> {
        match answer {
            Poll::Pending => Ok(Issued::Pending),
            Poll::Ready(Ok(v)) => Ok(Issued::Value(v)),
            Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
                Ok(Issued::Short(bytes, items))
            }
            Poll::Ready(Err(e)) => Err(halted(e)),
        }
    }
}

impl Via<'_> {
    /// One records call under this piece's next handle, issued at `(bytes, items)` (or the size a
    /// short answer on the handle already named) and, answered short, re-issued ONCE on the same
    /// handle at the size it names. `call` makes the crossing into the buffers it is handed and
    /// answers an owned value.
    fn issue<T>(
        &mut self,
        (bytes, items): (usize, usize),
        mut call: impl FnMut(
            &Services,
            CompletionHandle,
            &mut [u8],
            &mut [ItemSpan],
        ) -> Poll<Result<T, ServiceError>>,
    ) -> Result<T, Halt> {
        let services = self.services()?;
        let handle = self.next_handle();
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let (b, i) = self.sized(handle, bytes, items);
        let mut buf = vec![0u8; b];
        let mut spans = vec![
            ItemSpan {
                key: absent,
                value: absent,
            };
            i
        ];
        let (need_b, need_i) = match Issued::of(call(&services, handle, &mut buf, &mut spans))? {
            Issued::Value(v) => return Ok(v),
            Issued::Pending => return Err(Halt::Pending),
            Issued::Short(need_b, need_i) => (need_b, need_i),
        };
        self.grow(handle, need_b, need_i);
        let (b, i) = self.sized(handle, bytes, items);
        let mut buf = vec![0u8; b];
        let mut spans = vec![
            ItemSpan {
                key: absent,
                value: absent,
            };
            i
        ];
        match Issued::of(call(&services, handle, &mut buf, &mut spans))? {
            Issued::Value(v) => Ok(v),
            Issued::Pending => Err(Halt::Pending),
            // The host named a size and then answered short at it: its own rule broken.
            Issued::Short(..) => Err(halted(ServiceError::Broken)),
        }
    }
}

impl Records for Via<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.issue((RECORD_BYTES, 1), |services, handle, buf, _| {
            services
                .records_get(handle, kind, key.as_bytes(), buf)
                .map(|r| r.map(|found| found.map(<[u8]>::to_vec)))
        })
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        let mut rows: Vec<(String, Vec<u8>)> = Vec::new();
        loop {
            let after = rows.last().map(|(k, _)| k.clone());
            let page = self.issue(
                (PAGE_BYTES, PAGE_RECORDS as usize),
                |services, handle, buf, spans| {
                    services
                        .records_list(
                            handle,
                            kind,
                            prefix.as_bytes(),
                            after.as_deref().map(str::as_bytes),
                            PAGE_RECORDS,
                            (buf, spans),
                        )
                        .map(|r| {
                            r.and_then(|page| {
                                page.records()
                                    .map(|(k, v)| {
                                        std::str::from_utf8(k)
                                            .map(|k| (k.to_owned(), v.to_vec()))
                                            .map_err(|_| ServiceError::Broken)
                                    })
                                    .collect::<Result<Vec<_>, _>>()
                            })
                        })
                },
            )?;
            let full = page.len() >= PAGE_RECORDS as usize;
            rows.extend(page);
            if !full {
                return Ok(rows);
            }
        }
    }

    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.issue((0, 0), |services, handle, _, _| {
            services.records_claim(handle, kind, key.as_bytes(), ttl_ms)
        })
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
        let services = self.services()?;
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
    let (verb, rest, composed, framed, addressed, section, generation) =
        plane.units.with(&unit, |u| {
            let u = u?;
            Some((
                verb_of(&u.disposition)?,
                std::mem::take(&mut u.pass.rest),
                u.envelope.clone(),
                u.framed,
                u.agent.clone(),
                u.section.clone(),
                u.generation,
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
    let mut via = Via::new(host, plane.services, instance.ticket(), base, &plane.grown);
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
    // THE ADMISSION AND THE CATALOGUE (the engine's `receive::admit`, ahead of its local verbs): a
    // verb routed to an agent that is not `approved`, holds no card, or whose card the request does
    // not fit, is refused in the engine's words.
    let member = input.field(|i| &i.member).as_str().unwrap_or_default();
    let refused = section
        .as_ref()
        .and_then(|s| s.agents.get(member))
        .and_then(|def| {
            crate::plane_door::admit_unit(
                plane,
                (member, def),
                addressed.as_deref(),
                generation,
                Some(&envelope),
            )
            .err()
        });
    let served = refused.is_none();
    let answered = match refused {
        Some(refusal) => Ok(Some(local::Answer {
            status: refusal.status,
            body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
        })),
        None => local::answer(&mut via, verb, &envelope, caller, entry.now, &mut writes),
    };
    let answer = match answered {
        Err(Halt::Pending) => return Some(Outcome::Pending),
        Err(Halt::Failed(_)) => {
            writes.truncate(swept);
            local::unreadable(envelope.get("id").unwrap_or(&Value::Null))
        }
        // A subscribe to a live task is the relay's (`crate::plane_door`'s events hop); one that
        // reached here carried no request the relay could send.
        Ok(None) => return Some(Outcome::Refused),
        Ok(Some(answer)) => answer,
    };
    let issued = via.issued();
    plane.units.with(&unit, |u| {
        if let Some(u) = u {
            u.pass.served = served;
        }
    });
    let done = match (framed, composed) {
        // The gRPC line: the rpc's message, or the status the call ends with.
        (Some(rpc), _) => framed_window(
            plane,
            unit,
            &input,
            &mut out,
            &crate::framed::reply(rpc, answer.status, &answer.body),
            &writes,
        ),
        (None, Some(_)) => window(
            plane,
            unit,
            &input,
            &mut out,
            (
                answer.status,
                &crate::rest::reframe(answer.status, &answer.body),
            ),
            &writes,
        ),
        (None, None) => window(
            plane,
            unit,
            &input,
            &mut out,
            (answer.status, &answer.body),
            &writes,
        ),
    };
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
    answer: (u32, &[u8]),
    writes: &[Write],
) -> Outcome {
    window_with(plane, unit, input, out, answer, writes, &[JSON_HEAD])
}

/// The head a JSON answer starts with.
const JSON_HEAD: (&str, &str) = ("content-type", JSON_MEDIA_TYPE);

/// [`window`], the first window's head fields `head` (each written before its stated length).
fn window_with(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
    head: &[(&str, &str)],
) -> Outcome {
    let first = (status != 0).then_some(Head {
        fields: head,
        length: true,
    });
    window_core(plane, unit, input, out, (status, body), writes, first)
}

/// A WHOLE REPLY ON THE gRPC LINE ([`crate::framed::Reply`]): its status in the line's own
/// numbering (`0` = `OK`), its details field when it has one, and no media type and no length (the
/// grpc transport frames).
fn framed_window(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    reply: &crate::framed::Reply,
    writes: &[Write],
) -> Outcome {
    let details: Vec<(&str, &str)> = reply
        .details
        .as_deref()
        .map(|d| (crate::framed::DETAILS_FIELD, d))
        .into_iter()
        .collect();
    window_core(
        plane,
        unit,
        input,
        out,
        (reply.code, &reply.body),
        writes,
        Some(Head {
            fields: &details,
            length: false,
        }),
    )
}

/// The first window's head: its fields, and whether it states its length.
struct Head<'h> {
    fields: &'h [(&'h str, &'h str)],
    length: bool,
}

/// One window: on the first (`first`), its head; then as many bytes as the reply buffer holds.
fn window_core(
    plane: &A2aDoor,
    unit: u64,
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    (status, body): (u32, &[u8]),
    writes: &[Write],
    first: Option<Head<'_>>,
) -> Outcome {
    let (mut reply, mut fields, mut records, mut arena, mut units) = (
        input.reply_buf(),
        input.fields_buf(),
        input.records_buf(),
        input.arena_buf(),
        input.units_buf(),
    );
    if plane
        .units
        .with(&unit, |u| u.is_some_and(|u| u.pass.served))
    {
        units.push(UnitCount {
            class: crate::door::CLASS_FEE_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
    }
    if let Some(head) = &first {
        for (name, value) in head.fields {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        // A whole answer states its length, so it is sent under it (never chunked), as the
        // engine sent its buffered JSON answer.
        if head.length {
            fields.push(OutField {
                name: arena.span(crate::plane_door::H_CONTENT_LENGTH.as_bytes()),
                value: arena.span(body.len().to_string().as_bytes()),
            });
        }
    }
    for w in writes {
        records.push(RecordWrite {
            kind: kind_index(w.kind),
            op: RECORD_PUT,
            key: arena.span(w.key.as_bytes()),
            value: arena.span(&w.value),
        });
    }
    let short = !(fields.fits() && records.fits() && arena.fits() && units.fits());
    let (fw, fnd) = fields.settle(short);
    let (rw, rnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    let (uw, und) = units.settle(short);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
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

/// THE HOST'S SIGNING SERVICE as a card's [`crate::served_card::Signer`]: the key id read with a
/// first signature (the host names it beside every signature), then the signature, each on its own
/// handle of the piece's ticket.
struct HostSigner<'a> {
    services: Option<&'a Services>,
    ticket: Ticket,
    seq: u32,
}

impl HostSigner<'_> {
    fn signed(&mut self, data: &[u8]) -> Option<(String, Vec<u8>)> {
        let services = self.services?;
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq: self.seq,
            _reserved: 0,
        };
        self.seq += 1;
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let mut buf = vec![0u8; 1024];
        let mut spans = [ItemSpan {
            key: absent,
            value: absent,
        }; 2];
        let sig = services.sign(handle, data, &mut buf, &mut spans).ok()?;
        Some((sig.key_id.to_string(), sig.signature.to_vec()))
    }
}

impl HostSigner<'_> {
    /// `entitlement.check` of the unit's caller for `target` (`<scope kind>:<name>`), on the next
    /// handle; a check the host cannot answer is no entitlement.
    fn entitled(&mut self, target: &str) -> bool {
        let Some(services) = self.services else {
            return false;
        };
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq: self.seq,
            _reserved: 0,
        };
        self.seq += 1;
        services.entitled(handle, target).unwrap_or(false)
    }
}

impl crate::served_card::Signer for HostSigner<'_> {
    fn kid(&mut self) -> Option<String> {
        self.signed(b"").map(|(kid, _)| kid)
    }

    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        self.signed(input).map(|(_, sig)| sig)
    }
}

/// BUSBAR'S EXTENDED CARD for the unit's caller (the engine's `route::extended_agent_card`): one
/// skill per fronted agent the caller's own catalogue holds (granted, approved, its card held),
/// signed, in a JSON-RPC answer; a deployment fronting no agent answers
/// `ExtendedAgentCardNotConfigured`, a card that cannot be built `Internal`.
fn extended_card(
    plane: &A2aDoor,
    signer: &mut HostSigner<'_>,
    section: Option<&crate::a2a::config::AgentsCfg>,
    generation: u64,
    public_url: &str,
    rpc: Value,
) -> (u32, Vec<u8>) {
    use crate::served_card as served;
    let refusal = |status: u32, code: i64, message: &str| {
        let refusal = crate::arrival::Refusal {
            status,
            id: Some(rpc.clone()),
            code,
            message: message.to_string(),
        };
        (
            status,
            serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
        )
    };
    let agents = section.map(|s| &s.agents).filter(|a| !a.is_empty());
    let Some(agents) = agents else {
        return refusal(
            400,
            -32007,
            "this deployment fronts no agents, so there is no extended agent card to serve",
        );
    };
    let mut held = Vec::new();
    for (name, def) in agents {
        if !signer.entitled(&format!("{}:{name}", crate::door::SCOPE)) {
            continue;
        }
        if crate::plane_door::admit_unit(plane, (name, def), None, generation, None).is_err() {
            continue;
        }
        held.push((
            name.as_str(),
            def.url.as_str(),
            plane.cards.at(name, generation),
        ));
    }
    let entitled: Vec<served::EntitledAgent<'_>> = held
        .iter()
        .map(|(agent_id, backend_url, card)| served::EntitledAgent {
            agent_id,
            backend_url,
            card: card.as_deref(),
        })
        .collect();
    match served::extended_card_document(public_url, &entitled)
        .ok_or_else(String::new)
        .and_then(|card| served::sign_card(&card, signer))
    {
        Ok(doc) => (
            200,
            serde_json::to_vec(&serde_json::json!({ "jsonrpc": "2.0", "id": rpc, "result": doc }))
                .unwrap_or_default(),
        ),
        Err(_) => refusal(500, -32603, "the extended agent card could not be built"),
    }
}

/// An error document of the engine's card routes: `{"error": {"code", "message"}}`.
fn card_error(code: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "error": { "code": code, "message": message } }))
        .unwrap_or_default()
}

/// `on_piece` for a card read ([`crate::arrival::CardAsk`]): its first piece (the caller's, for
/// busbar's own card; the ATTEMPT naming the agent, for a fronted agent's) is answered whole, in the
/// engine's words and heads (`receive::well_known_card` and `receive::card`), the card signed with
/// busbar's key through the host's `sign`; a card read is never metered, so it reports no fee unit.
pub fn card_piece(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    input: Lent<'_, OnPieceIn>,
    mut out: Out<'_, OnPieceOut>,
    ask: crate::arrival::CardAsk,
) -> Outcome {
    use crate::served_card::{self as served, OWN_CARD_CACHE_CONTROL, OWN_CARD_MEDIA_TYPE};
    let unit = input.get().unit;
    let Some((rest, answered, agent, section, generation, issued, rpc, composed, framed)) =
        plane.units.with(&unit, |u| {
            u.map(|u| {
                let rpc = match &u.disposition {
                    Disposition::Request { id, .. } => id.clone(),
                    _ => Value::Null,
                };
                (
                    std::mem::take(&mut u.pass.rest),
                    u.pass.answered,
                    u.agent.clone(),
                    u.section.clone(),
                    u.generation,
                    u.pass.issued,
                    rpc,
                    u.envelope.is_some(),
                    u.framed,
                )
            })
        })
    else {
        return Outcome::Refused;
    };
    if !rest.is_empty() {
        return window(plane, unit, &input, &mut out, (0, &rest), &[]);
    }
    if answered {
        return Outcome::Ready;
    }
    let mut signer = HostSigner {
        services: plane.services.as_ref(),
        ticket: instance.ticket(),
        seq: issued,
    };
    let public_url = plane.public_url.clone().unwrap_or_default();
    let own_head = [
        ("cache-control", OWN_CARD_CACHE_CONTROL),
        ("content-type", OWN_CARD_MEDIA_TYPE),
    ];
    let (status, body, own) = match ask {
        crate::arrival::CardAsk::Own => {
            match served::self_card_document(&public_url, Vec::new())
                .ok_or_else(String::new)
                .and_then(|card| served::sign_card(&card, &mut signer))
            {
                Ok(card) => (200, serde_json::to_vec(&card).unwrap_or_default(), true),
                Err(_) => (
                    500,
                    card_error("internal", "the agent card could not be built"),
                    false,
                ),
            }
        }
        crate::arrival::CardAsk::Extended => {
            let (status, body) = extended_card(
                plane,
                &mut signer,
                section.as_deref(),
                generation,
                &public_url,
                rpc,
            );
            // The gRPC line: the card's message, or the status the call ends with.
            if let Some(rpc) = framed {
                let seq = signer.seq;
                plane.units.with(&unit, |u| {
                    if let Some(u) = u {
                        u.pass.answered = true;
                        u.pass.issued = seq;
                    }
                });
                let reply = crate::framed::reply(rpc, status, &body);
                return framed_window(plane, unit, &input, &mut out, &reply, &[]);
            }
            let body = if composed {
                crate::rest::reframe(status, &body)
            } else {
                body
            };
            (status, body, false)
        }
        crate::arrival::CardAsk::Agent => {
            let agent = agent.unwrap_or_default();
            let def = section.as_ref().and_then(|s| s.agents.get(&agent));
            match (def, plane.cards.at(&agent, generation)) {
                (Some(def), Some(held)) => {
                    match served::rewrite_card(&held, &def.url, &public_url, &agent)
                        .map_err(|_| String::new())
                        .and_then(|card| served::sign_card(&card, &mut signer))
                    {
                        Ok(card) => (200, serde_json::to_vec(&card).unwrap_or_default(), false),
                        Err(_) => (
                            502,
                            card_error("upstream_error", "the agent card could not be served"),
                            false,
                        ),
                    }
                }
                _ => (
                    503,
                    card_error(
                        "unavailable",
                        "no agent card has been fetched for this registration yet",
                    ),
                    false,
                ),
            }
        }
    };
    let seq = signer.seq;
    plane.units.with(&unit, |u| {
        if let Some(u) = u {
            u.pass.answered = true;
            u.pass.issued = seq;
        }
    });
    if own {
        window_with(
            plane,
            unit,
            &input,
            &mut out,
            (status, &body),
            &[],
            &own_head,
        )
    } else {
        window(plane, unit, &input, &mut out, (status, &body), &[])
    }
}

#[cfg(test)]
#[path = "tests/task_door.rs"]
mod tests;
