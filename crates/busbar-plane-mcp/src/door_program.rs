// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO SERVERS' LEG, in the door (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): a
//! `transport: stdio` registration is a member of the program need ([`door::NEED_PROGRAM`]); the
//! host keeps one long-lived child per member, and every exchange the door has with it is
//! correlated by id ([`crate::tool_program`]).
//!
//! * Before a call is relayed to a stdio member, its child's generation is GREETED once
//!   ([`ready`]): an exchange that only opens a lease, reads the generation and, for one the door
//!   has not greeted, runs `initialize` and its acknowledgement.
//! * The relayed `tools/call` goes over the kernel's walk on the member's route like any other
//!   member's; its answer is the message carrying the unit's id among everything the child writes
//!   ([`far`]), and a request of the child's own read on the way is answered on a lease of its own
//!   (`ping`, an unknown method, an ungranted ask) or, a granted authority ask, handed up as busbar's
//!   caller's to answer ([`Far::Asked`], Law 11) — the caller of the call FIRST IN THE CHILD'S
//!   LINE ([`Relaying`]): calls to a member whose grants let its asks be relayed reach its child one
//!   at a time, in arrival order, each holding its place until its answer is read (across a relayed
//!   ask's round trip, until its retry or the ask's state lapses); a call behind it waits its turn
//!   within its own deadline ([`in_line`]). An ask raised while no such call is open is refused. The
//!   caller's answer comes back on a retry of the call ([`ProgramRelay::retrying`]): written to the
//!   child under its own request id, and the call the child still owes read on.
//! * Verify-on-call's `tools/list` ([`tools_listed`]), an operator's `connect`, and a further round reach the
//!   same child the same way.

use super::*;
use crate::tool_program::{
    call_id, first_in_line, list_id, AskOwner, Correlator, Exchanged, Peer, ProgramExchange,
};

/// THE LINE OF CALLS RELAYED TO STDIO CHILDREN, by serial (arrival order) (finding 5): every
/// relayed call is entered before its request could reach the kernel's walk and leaves when its
/// relay is dropped (or, holding its place across a relayed ask's round trip, when that lapses).
/// For a member whose asks may be relayed, only the call first in its line is sent ([`in_line`]),
/// so the child serves one such call at a time and its ask is that call's ([`first_in_line`]).
pub(super) type Relaying = Arc<Keyed<u64, InLine>>;

/// One call in a stdio member's line.
#[derive(Debug, Clone)]
pub(super) struct InLine {
    member: String,
    /// The generation its lease reached; `0` before its head.
    generation: u64,
    /// The id the call carries on the child.
    call: u64,
    /// The ticket of its unit while it waits its turn: woken when the call ahead of it leaves.
    ticket: Option<Ticket>,
    /// Held across a relayed ask's round trip until this instant of the host's monotonic clock
    /// (ms): the child still serves the call, so its place is kept for the retry. `0` = a live
    /// relay.
    held_until: u64,
}

/// Whether member `def`'s calls wait their turn on its child: its grants let a child's ask be
/// relayed to a caller (a call whose asks are all refused may share the child freely).
pub(super) fn serialised(def: &crate::tools_config::McpServerDefCfg) -> bool {
    let g = def.grants.as_ask_grants();
    g.sampling || g.elicitation || g.roots
}

/// The sentence a call answers when its deadline passed while another call held the child.
pub(super) const BUSY: &str = "the stdio MCP child was serving another call whose asks are \
                               relayed to its own caller, and this call's deadline passed while it \
                               waited its turn; it was never sent";

/// Where the door's own program exchanges number their host services on a unit's ticket: the
/// greeting before each attempt, [`crate::tool_program::EXCHANGE_SERVICES`] apart per attempt.
const READY_SEQ: u32 = 1 << 31;

/// Where the replies a relayed call owes its child number theirs: one exchange per reply batch,
/// [`crate::tool_program::EXCHANGE_SERVICES`] apart.
const REPLY_SEQ: u32 = (1 << 31) + (1 << 30);

/// The most requests of a child's own the door remembers having answered or put to a call (per
/// member and generation, by id), so two exchanges reading one request decide it once.
const MAX_ANSWERED: usize = 4096;

/// Whether `def` is a `transport: stdio` registration: a member of the program need.
pub(super) fn is_program(def: &crate::tools_config::McpServerDefCfg) -> bool {
    def.transport
        .is_some_and(crate::tools_config::ServerTransport::spawns_child)
}

/// What a door exchange is doing with a unit's program lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    /// Greeting the member's child before the attempt's call.
    Ready,
    /// Verify-on-call's `tools/list`.
    Verify,
}

/// A relayed call to a stdio member, as its far pieces arrive.
pub(super) struct ProgramRelay {
    /// The id the round in flight carries.
    pub(super) wait: u64,
    /// The generation of the child the walk's lease reached.
    pub(super) generation: u64,
    corr: Correlator,
    /// The exchange writing the replies the child is owed, while it pends.
    replying: Option<ProgramExchange>,
    /// How many reply exchanges this call made.
    replies: u32,
    /// The answer (or why there is none), held while the replies are written.
    settled: Option<Result<Vec<u8>, String>>,
    /// A retry answering the child's own requests: the generation that asked, which is the only one
    /// its answers and its wait mean anything to.
    expect: Option<u64>,
    /// Its place in the line ([`Relaying`]), left when it is dropped.
    open: (Relaying, u64),
    /// The host's wake, for the call behind it when it leaves the line.
    wake: Option<busbar_contract::abi::sdk::services::Wake>,
    /// Its asks went to its caller: dropped, it holds its place until this instant (ms).
    hold: u64,
}

impl Drop for ProgramRelay {
    fn drop(&mut self) {
        let (line, serial) = &self.open;
        let hold = self.hold;
        let next = line.with_all(|m| {
            if hold != 0 {
                if let Some(e) = m.get_mut(serial) {
                    e.held_until = hold;
                }
                return None;
            }
            let gone = m.remove(serial)?;
            if m.range(..*serial).any(|(_, e)| e.member == gone.member) {
                return None;
            }
            m.values().find(|e| e.member == gone.member)?.ticket
        });
        if let (Some(wake), Some(ticket)) = (self.wake, next) {
            wake.wake(ticket);
        }
    }
}

impl ProgramRelay {
    /// The relay of a call to member `member` whose round carries `wait`: entered at the end of
    /// the member's line.
    pub(super) fn waiting(plane: &McpDoor, member: &str, wait: u64) -> Self {
        let serial = plane.relaying.with_all(|line| {
            let serial = line.last_key_value().map_or(1, |(k, _)| k.wrapping_add(1));
            line.insert(
                serial,
                InLine {
                    member: member.to_string(),
                    generation: 0,
                    call: wait,
                    ticket: None,
                    held_until: 0,
                },
            );
            serial
        });
        ProgramRelay::at(plane, wait, serial)
    }

    fn at(plane: &McpDoor, wait: u64, serial: u64) -> Self {
        ProgramRelay {
            wait,
            generation: 0,
            corr: Correlator::relaying(),
            replying: None,
            replies: 0,
            settled: None,
            expect: None,
            open: (Arc::clone(&plane.relaying), serial),
            wake: plane.wake,
            hold: 0,
        }
    }

    /// Its asks went to its caller: dropped, it keeps its place in the line until `until` (the
    /// host's monotonic clock, ms), for the retry that answers them.
    pub(super) fn hold(&mut self, until: u64) {
        self.hold = until;
    }

    /// THE RETRY OF A CHILD'S RELAYED ASK: the caller's answers after the first (which the walk's
    /// own lease carries) owed on the child of `generation`, and the call `wait` it still owes read
    /// on, on that generation only. It takes up the place in the line the call held while its
    /// caller answered.
    pub(super) fn retrying(
        plane: &McpDoor,
        member: &str,
        wait: u64,
        generation: u64,
        rest: Vec<Vec<u8>>,
    ) -> Self {
        let held = plane.relaying.with_all(|line| {
            let (serial, e) = line
                .iter_mut()
                .find(|(_, e)| e.held_until != 0 && e.member == member && e.call == wait)?;
            e.held_until = 0;
            Some(*serial)
        });
        let mut relay = match held {
            Some(serial) => ProgramRelay::at(plane, wait, serial),
            None => ProgramRelay::waiting(plane, member, wait),
        };
        relay.expect = Some(generation);
        relay.corr.outbox.extend(rest);
        relay
    }
}

/// The sentence a retry fails with when the child that asked is gone.
pub(super) const RESTARTED: &str = "the stdio MCP child that asked was restarted before the \
                                    caller's answer reached it, so the call it was serving is gone";

/// WHETHER `relay`'s CALL IS FIRST IN ITS MEMBER'S LINE, so may be sent: a place held across a
/// relayed ask's round trip that lapsed by `now` (the host's monotonic clock, ms) is given up first.
/// One that is not waits its turn, its unit's `ticket` woken when the call ahead of it leaves.
pub(super) fn in_line(
    plane: &McpDoor,
    relay: &ProgramRelay,
    now: Option<u64>,
    ticket: Ticket,
) -> bool {
    let serial = relay.open.1;
    plane.relaying.with_all(|line| {
        let Some(member) = line.get(&serial).map(|e| e.member.clone()) else {
            return true;
        };
        if let Some(now) = now {
            line.retain(|_, e| e.member != member || e.held_until == 0 || e.held_until > now);
        }
        let first = line
            .iter()
            .find(|(_, e)| e.member == member)
            .is_none_or(|(s, _)| *s == serial);
        if let Some(e) = line.get_mut(&serial).filter(|_| !first) {
            e.ticket = Some(ticket);
        }
        first
    })
}

/// The door, as an exchange with member `member`'s child needs it.
struct DoorPeer<'a> {
    plane: &'a McpDoor,
    member: &'a str,
    grants: crate::client::jsonrpc::ServerRequestGrants,
}

impl DoorPeer<'_> {
    /// What became of the child's request `id` of `generation`: the call it was put to (`None` =
    /// busbar answered it), decided by `first` when this exchange is the first to read it (`true`).
    fn decide(
        &self,
        generation: u64,
        id: &Value,
        first: impl FnOnce() -> Option<u64>,
    ) -> (Option<u64>, bool) {
        let key = (self.member.to_string(), generation, id.to_string());
        self.plane.answered.with_all(|m| {
            if let Some(owner) = m.get(&key) {
                return (*owner, false);
            }
            while m.len() >= MAX_ANSWERED {
                if m.pop_first().is_none() {
                    break;
                }
            }
            let owner = first();
            m.insert(key, owner);
            (owner, true)
        })
    }
}

impl Peer for DoorPeer<'_> {
    fn grants(&self) -> crate::client::jsonrpc::ServerRequestGrants {
        self.grants
    }

    fn claim(&mut self, generation: u64, id: &Value) -> bool {
        self.decide(generation, id, || None).1
    }

    fn owner(&mut self, generation: u64, id: &Value) -> AskOwner {
        let member = self.member;
        let line = &self.plane.relaying;
        match self.decide(generation, id, || {
            line.with_all(|l| {
                first_in_line(
                    l.values()
                        .filter(|e| e.member == member)
                        .map(|e| (e.call, e.generation)),
                    generation,
                )
            })
        }) {
            (Some(call), _) => AskOwner::Call(call),
            (None, true) => AskOwner::Refuse,
            (None, false) => AskOwner::Refused,
        }
    }

    fn notice(&mut self) {
        // The child's lists moved: the next call re-verifies (the timing, never the content).
        self.plane.checked.remove(&self.member.to_string());
    }
}

/// Drive `exchange` with member `member` on `ticket` from `base`: the door's greeting record kept.
fn exchange_child(
    plane: &McpDoor,
    host: &busbar_contract::abi::sdk::conn::Host,
    ticket: Ticket,
    base: u32,
    member: &str,
    def: &crate::tools_config::McpServerDefCfg,
    exchange: &mut ProgramExchange,
) -> std::task::Poll<Result<Exchanged, String>> {
    let greeted = |g: u64| plane.greeted.get(&member.to_string()) == Some(g);
    let mut peer = DoorPeer {
        plane,
        member,
        grants: def.grants.as_ask_grants(),
    };
    let answer = exchange.drive(host, ticket, base, &greeted, &mut peer);
    if let std::task::Poll::Ready(Ok(done)) = &answer {
        if done.greeted {
            plane.greeted.insert(member.to_string(), done.generation);
        }
    }
    answer
}

/// GREET the member's child before the attempt's call ([`Purpose::Ready`]): once per attempt, a
/// lease that reads the generation and runs the handshake on one the door has not greeted. A child
/// that cannot be reached is the walk's to find: the call goes on and its open answers.
pub(super) fn ready(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    member: &str,
) -> Looked {
    let Some(def) = held.section.servers.get(member).filter(|d| is_program(d)) else {
        return Looked::Fresh;
    };
    let Some(host) = plane.host.as_ref().filter(|h| h.lends_connector()) else {
        return Looked::Fresh;
    };
    if unit.readied == Some(unit.attempt) {
        return Looked::Fresh;
    }
    let mut exchange = match unit.program.take() {
        Some((Purpose::Ready, parked)) => parked,
        _ => ProgramExchange::new(member, door::NEED_PROGRAM, Vec::new(), true),
    };
    let base = READY_SEQ.saturating_add(
        unit.attempt
            .saturating_mul(crate::tool_program::EXCHANGE_SERVICES),
    );
    match exchange_child(plane, host, ticket, base, member, def, &mut exchange) {
        std::task::Poll::Pending => {
            unit.program = Some((Purpose::Ready, exchange));
            Looked::Pending
        }
        std::task::Poll::Ready(_) => {
            unit.readied = Some(unit.attempt);
            Looked::Fresh
        }
    }
}

/// VERIFY-ON-CALL's fetch from a stdio member ([`Purpose::Verify`]): its `tools/list`, on a lease
/// of its own, answered by id, the child greeted first where its generation is new. The answer as
/// the exchange SDK spells one (a child's answer is a success), or why it failed.
pub(super) fn tools_listed(
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    def: &crate::tools_config::McpServerDefCfg,
    server: &str,
    base: u32,
) -> std::task::Poll<Result<(busbar_contract::abi::sdk::exchange::ExchangeResponse, u64), String>> {
    let Some(host) = plane.host.as_ref() else {
        return std::task::Poll::Ready(Err(
            busbar_contract::abi::sdk::conn::ConnFailure::Unarmed.to_string()
        ));
    };
    let id = list_id(unit.key, unit.attempt);
    let mut exchange = match unit.program.take() {
        Some((Purpose::Verify, parked)) => parked,
        _ => ProgramExchange::new(
            server,
            door::NEED_PROGRAM,
            vec![(list_request(id), Some(id))],
            true,
        )
        .timed(def.timeout_ms()),
    };
    match exchange_child(plane, host, ticket, base, server, def, &mut exchange) {
        std::task::Poll::Pending => {
            unit.program = Some((Purpose::Verify, exchange));
            std::task::Poll::Pending
        }
        std::task::Poll::Ready(answer) => std::task::Poll::Ready(answer.map(|done| {
            (
                busbar_contract::abi::sdk::exchange::ExchangeResponse {
                    status: 200,
                    reason: None,
                    fields: Vec::new(),
                    body: done.answer.unwrap_or_default(),
                },
                id,
            )
        })),
    }
}

/// An operator's `connect` to a stdio member: its `tools/list` on the verb's own ticket (the
/// exchange parked on the instance while it pends), correlated by `id`.
pub(super) fn connect_child(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    def: &crate::tools_config::McpServerDefCfg,
    server: &str,
) -> std::task::Poll<(Result<Vec<u8>, String>, u64)> {
    let ticket = instance.ticket();
    let id = list_id(
        (u64::from(ticket.slot) << 32) | u64::from(ticket.generation),
        0,
    );
    let Some(host) = plane.host.as_ref() else {
        return std::task::Poll::Ready((
            Err(busbar_contract::abi::sdk::conn::ConnFailure::Unarmed.to_string()),
            id,
        ));
    };
    let mut exchange = match instance.resume::<ProgramExchange>() {
        Some(parked) => *parked,
        None => ProgramExchange::new(
            server,
            door::NEED_PROGRAM,
            vec![(list_request(id), Some(id))],
            true,
        )
        .timed(def.timeout_ms()),
    };
    match exchange_child(plane, host, ticket, 0, server, def, &mut exchange) {
        std::task::Poll::Pending => {
            instance.park(exchange);
            std::task::Poll::Pending
        }
        std::task::Poll::Ready(answer) => {
            std::task::Poll::Ready((answer.map(|d| d.answer.unwrap_or_default()), id))
        }
    }
}

/// The `tools/list` a stdio member is sent, under `id`.
fn list_request(id: u64) -> Vec<u8> {
    crate::client::jsonrpc::tools_list("", id, None).body
}

/// What a far piece of a stdio member's answer came to.
pub(super) enum Far {
    /// Read; nothing settled yet.
    Taken,
    /// A host service pended (a reply the child is owed): called again on its wake, the piece
    /// already read.
    Pending,
    /// The answer to the call's id, or why there is none.
    Settled(Result<Vec<u8>, String>),
    /// The child asked for something busbar's caller answers (Law 11): its granted requests, in
    /// order, unanswered.
    Asked(Vec<crate::tool_program::ChildAsk>),
}

/// ONE FAR PIECE of a stdio member's answer: the head names the child's generation; each body
/// piece is read for the message carrying the round's id, the child's own requests answered on a
/// lease of their own (only to the same generation) and its progress kept; the end without an
/// answer fails the call in the previous release's words.
#[allow(clippy::too_many_arguments)] // the piece's three facts beside the unit's
pub(super) fn far(
    plane: &McpDoor,
    ticket: Ticket,
    member: &str,
    def: &crate::tools_config::McpServerDefCfg,
    relay: &mut ProgramRelay,
    head: Option<u64>,
    bytes: &[u8],
    last: bool,
) -> Far {
    if relay.replying.is_none() && relay.settled.is_none() {
        if let Some(generation) = head {
            relay.generation = generation;
            plane.relaying.with(&relay.open.1, |e| {
                if let Some(e) = e {
                    e.generation = generation;
                }
            });
            // A retry reaches only the child that asked: a restarted one owes nothing.
            if relay.expect.is_some_and(|g| g != generation) {
                relay.corr.outbox.clear();
                relay.settled = Some(Err(RESTARTED.to_string()));
                return match relay.settled.take() {
                    Some(settled) => Far::Settled(settled),
                    None => Far::Taken,
                };
            }
        }
        let mut peer = DoorPeer {
            plane,
            member,
            grants: def.grants.as_ask_grants(),
        };
        relay.hold = 0;
        match relay
            .corr
            .take(bytes, relay.wait, member, relay.generation, &mut peer)
        {
            Ok(Some(answer)) => relay.settled = Some(Ok(answer)),
            Ok(None) if last => relay.settled = Some(Err(crate::tool_program::CLOSED.to_string())),
            Ok(None) => {}
            Err(reason) => relay.settled = Some(Err(reason)),
        }
        owe(member, relay);
    }
    if replying(plane, ticket, member, def, relay) {
        return Far::Pending;
    }
    match relay.settled.take() {
        Some(settled) => Far::Settled(settled),
        None if !relay.corr.asks.is_empty() => Far::Asked(std::mem::take(&mut relay.corr.asks)),
        None => Far::Taken,
    }
}

/// The replies the child is owed, put on an exchange of their own (to its generation only).
fn owe(member: &str, relay: &mut ProgramRelay) {
    if !relay.corr.outbox.is_empty() {
        let owed: Vec<(Vec<u8>, Option<u64>)> =
            relay.corr.outbox.drain(..).map(|r| (r, None)).collect();
        relay.replying = Some(
            ProgramExchange::new(member, door::NEED_PROGRAM, owed, false).only_on(relay.generation),
        );
        relay.replies += 1;
    }
}

/// The replies' exchange driven: whether it pends.
fn replying(
    plane: &McpDoor,
    ticket: Ticket,
    member: &str,
    def: &crate::tools_config::McpServerDefCfg,
    relay: &mut ProgramRelay,
) -> bool {
    if let Some(mut exchange) = relay.replying.take() {
        if let Some(host) = plane.host.as_ref() {
            let base = REPLY_SEQ.saturating_add(
                relay
                    .replies
                    .saturating_mul(crate::tool_program::EXCHANGE_SERVICES),
            );
            if exchange_child(plane, host, ticket, base, member, def, &mut exchange).is_pending() {
                relay.replying = Some(exchange);
                return true;
            }
        }
    }
    false
}

/// ASKS BUSBAR COULD NOT RELAY, refused on the child's input (`replies`, one per ask: the round
/// cap, or a relay the deployment cannot carry) so the child is never left waiting on an answer
/// nobody will give; the call it serves is read on. `Pending` while the replies are written.
pub(super) fn refuse_asks(
    plane: &McpDoor,
    ticket: Ticket,
    member: &str,
    def: &crate::tools_config::McpServerDefCfg,
    relay: &mut ProgramRelay,
    replies: Vec<Vec<u8>>,
) -> Far {
    relay.corr.outbox.extend(replies);
    if relay.replying.is_none() {
        owe(member, relay);
    }
    if replying(plane, ticket, member, def, relay) {
        Far::Pending
    } else {
        Far::Taken
    }
}

/// The progress frames the relay's reading kept, taken.
pub(super) fn progress(relay: &mut ProgramRelay) -> Vec<Value> {
    std::mem::take(&mut relay.corr.progress)
}

/// The id unit `key`'s call carries on a child, round `round`.
pub(super) fn id_of(key: u64, round: u32) -> u64 {
    call_id(key, round)
}
