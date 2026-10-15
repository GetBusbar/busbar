// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUSH DELIVERY, DRIVEN BY THE DOOR: the host's half of [`crate::push`] (`BUSBAR-1.6.0.md`, the a2a
//! plane rulings on push delivery; TODO TRANSITIONAL row "A2A-PUSH's kernel reach", drained by
//! push delivery folding into the plane).
//!
//! * A relayed task that MOVES queues its notification ([`queue`]): to the push_config host record
//!   the caller registered for it, or else to the callback its row carries (an inline config). A
//!   task with neither queues nothing.
//! * The lifecycle `tick` ([`tick_deliveries`]) attempts ONE due notification per op: the kernel's random
//!   byte for the retry's jitter, then the destination judge over the callback, its name resolved,
//!   then predev's anti-rebinding rule over the judged addresses
//!   ([`crate::push::Deliveries::rebound`]), then one exchange over the plane's outbound `open-web`
//!   need ([`crate::door_statement::NEED_OPEN_WEB`]) landing only on those addresses. An attempt whose
//!   exchange pends ends its `tick` PENDING (a driver ticket's op is never resumed) and goes on
//!   through `drive` ([`drive`]), held in plane memory across the entries, each making the same host
//!   calls in the same order (the replay rule). Its end settles the queue and is OWED to the task's
//!   chain. A queued notification wakes the driver ticket ([`queue`]), so the kernel runs `drive`
//!   and then re-polls `tick` (R-PUSH) to attempt it at once.
//! * A relayed piece of the same caller FILES what is owed ([`file_owed`]), one chain change per
//!   task, never on the task the piece itself moves. A plane's record writes ride `on_piece`'s
//!   answer and nothing else (`BUSBAR-1.6.0.md`, the design's host services and the plane's journal
//!   writes), so a `tick` writes
//!   none and an attempt's outcome reaches its chain on its caller's next relayed answer
//!   (QUESTIONS row Q-FOLD-A2A-2-PUSH-CHAIN, answered by the spec).

use std::task::Poll;

use busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
use busbar_contract::abi::host::service::{
    ItemSpan, DEST_ALLOWED, DEST_REFUSE_PRIVATE, DEST_UNRESOLVABLE,
};
use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
use busbar_contract::abi::sdk::publish::Keyed;
use busbar_contract::abi::sdk::{Instance, Services};

use crate::a2a::task::Task;
use crate::agent_door::A2aDoor;
use crate::door_statement::NEED_OPEN_WEB;
use crate::local::{self, PushConfig};
use crate::push::{Attempted, Deliveries, Delivery, Owed};
use crate::records::KIND_PUSH_CONFIG;
use crate::tasks::{self, Halt, Records, Stamp, Write};
use crate::TaskRow;

/// Room for the judged addresses of one callback.
const JUDGED_BYTES: usize = 512;
/// One span per judged address.
const JUDGED_ADDRESSES: usize = 16;

/// The jitter byte that moves a retry's wait by nothing: used when the host lends no random byte
/// (a delay is a timing nicety, not a security property, as the engine's delivery reads it).
const NO_JITTER: u8 = 128;

/// QUEUE the notification `row`'s move owes: to `config` (the push_config record of the task) when
/// the caller registered one, its credential held for the attempt; else to the row's own callback.
/// Due at once: the next `tick` attempts it. (The book's times are the `tick`'s clock, which a
/// piece does not read, so a first attempt is filed as due at its origin.) Answers whether one was
/// queued.
pub fn queue(deliveries: &Deliveries, row: &TaskRow, config: Option<&PushConfig>) -> bool {
    let Ok(mut task) = Task::from_row(row) else {
        return false;
    };
    if let Some(cfg) = config {
        task.push_callback = Some(cfg.url.clone());
        deliveries.remember_auth(&task.task_id, cfg.authentication.clone());
    }
    let Some(delivery) = Delivery::of(&task) else {
        return false;
    };
    deliveries.enqueue(delivery, 0);
    // The delivery is attempted on this wake of the driver ticket, not at the next scheduled tick.
    deliveries.wake();
    true
}

/// FORGET the webhook credential of every push config `writes` deletes for `caller` (the tombstone
/// of its task's config record): a secret with no config left to present it for does not stay in
/// plane memory (the engine's delete dropped it with the config, `pushdeliver::forget`).
pub fn forget_deleted(deliveries: &Deliveries, caller: &str, writes: &[Write]) {
    let prefix = tasks::task_key(caller, "");
    for w in writes
        .iter()
        .filter(|w| w.kind == KIND_PUSH_CONFIG && w.value.is_empty())
    {
        if let Some(task_id) = w.key.strip_prefix(prefix.as_str()) {
            deliveries.remember_auth(task_id, None);
        }
    }
}

/// [`queue`] for a relayed piece of `caller`'s that moved `row`: the task's push_config record read
/// through the piece's records.
///
/// # Errors
/// [`Halt`] from the read.
pub fn queue_moved(
    deliveries: &Deliveries,
    rec: &mut dyn Records,
    caller: &str,
    row: &TaskRow,
) -> Result<bool, Halt> {
    let config = local::held_config(rec, caller, &row.task_id)?;
    Ok(queue(deliveries, row, config.as_ref()))
}

/// FILE `owed` on the chains it names, for `caller`, stamped `now_s`; the writes go to `out`. One
/// that cannot be filed is dropped: a delivery's record is best-effort, as the engine's is.
///
/// # Errors
/// [`Halt::Pending`] when a records call pends: the piece runs again with the same `owed`.
pub fn file_owed(
    rec: &mut dyn Records,
    caller: &str,
    owed: &[Owed],
    now_s: u64,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    for o in owed.iter().filter(|o| o.caller == caller) {
        // No inbound request originates a delivery: the request id is empty, as the engine's.
        let at = Stamp {
            caller,
            request_id: "",
            now: now_s,
        };
        if let Err(Halt::Pending) = tasks::record_push_delivery(rec, &at, &o.task_id, o.kind, out) {
            return Err(Halt::Pending);
        }
    }
    Ok(())
}

/// One attempt in flight across its `tick` op's PENDING entries.
struct Flight {
    delivery: Delivery,
    exchange: Option<Exchange>,
}

/// The host calls one attempt makes, in their one order: the random byte (handle `0`), the judge
/// (handle `1`), the exchange (from handle `2`).
struct Calls<'h> {
    host: &'h Host,
    services: Services,
    ticket: Ticket,
}

impl Calls<'_> {
    const fn handle(&self, seq: u32) -> CompletionHandle {
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }

    /// The jitter byte, from the kernel's random bytes.
    fn jitter(&self) -> u8 {
        let mut byte = [NO_JITTER];
        match self.services.random_fill(self.handle(0), &mut byte) {
            Ok(()) => byte[0],
            Err(_) => NO_JITTER,
        }
    }
}

/// WHAT ONE ATTEMPT ASKS OF THE HOST after its jitter byte, in its one order: the destination judge
/// over the callback, then the exchange. A seam, so what a verdict stops and what reaches the
/// receiver hold under a test's host as under the kernel's ([`attempt`]).
/// One judgement: the `DEST_*` verdict, the addresses judged, and the set a dial must land within.
type Judgement = (u64, Vec<String>, String);

trait Line {
    /// The destination judge over `url`: its `DEST_*` verdict, the addresses it judged, and the set
    /// a dial must land within; `None` when nothing was checked.
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>>;
    /// One exchange of `ex` to `url`: the receiver's status; `None` when the connection or the
    /// exchange failed.
    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>>;
    /// The jitter byte of a retry's wait.
    fn jitter(&mut self) -> u8;
    /// GIVE UP the connection of an attempt abandoned at its timeout: the host closes `stream` (when
    /// the attempt had established one), so nothing the far end answers later reaches anyone.
    fn abandon(&mut self, stream: Option<u64>);
}

impl Line for Calls<'_> {
    fn jitter(&mut self) -> u8 {
        Calls::jitter(self)
    }

    fn abandon(&mut self, stream: Option<u64>) {
        if let Some(stream) = stream {
            // The close names the stream itself, so it needs nothing the tick's cycle forgot; it
            // never pends on a table, and a close that fails leaves nothing more to do.
            let _ = self.host.connector_from(self.ticket, 2).close(stream);
        }
    }
    fn judge(&mut self, url: &str) -> Poll<Option<Judgement>> {
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let mut bytes = [0u8; JUDGED_BYTES];
        let mut spans = [ItemSpan {
            key: absent,
            value: absent,
        }; JUDGED_ADDRESSES];
        // Private reach refused whatever the deployment's private-address setting, as the engine's
        // delivery guard refused every internal answer with no knob to admit one; the allow-list
        // stands.
        let judged = self.services.dest_judge_as(
            self.handle(1),
            url,
            EGRESS_OPEN_WEB,
            DEST_REFUSE_PRIVATE,
            Some((&mut bytes[..], &mut spans[..])),
        );
        match judged {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Ready(Ok(j)) => Poll::Ready(Some((
                j.verdict,
                j.addresses.names().map(str::to_string).collect(),
                j.within(),
            ))),
        }
    }

    fn send(&mut self, ex: &mut Exchange, url: &str) -> Poll<Option<u16>> {
        let mut conn = self.host.connector_from(self.ticket, 2);
        match exchange(&mut conn, ex, NEED_OPEN_WEB, Some(url)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(reply)) => Poll::Ready(Some(reply.status)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
        }
    }
}

/// One attempt of `flight` over `line`: its end once known, with the addresses its request reached.
/// The destination is judged afresh on EVERY attempt (the engine's delivery re-ran its guard against
/// a fresh resolution before each one): a refusal, the judge's or the anti-rebinding rule's, ends
/// the attempt before anything is framed or sent.
fn attempt(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    flight: &mut Flight,
) -> Poll<(Attempted, Vec<String>)> {
    let url = flight.delivery.url.clone();
    let (verdict, addrs, within) = match line.judge(&url) {
        Poll::Pending => return Poll::Pending,
        // Nothing was checked, so nothing is allowed.
        Poll::Ready(None) => {
            return Poll::Ready((Attempted::Judged(DEST_UNRESOLVABLE), Vec::new()))
        }
        Poll::Ready(Some(judged)) => judged,
    };
    if verdict != DEST_ALLOWED {
        return Poll::Ready((Attempted::Judged(verdict), Vec::new()));
    }
    if let Some(moved) = deliveries.rebound(&url, &addrs) {
        return Poll::Ready((moved, Vec::new()));
    }
    // The credential joins the request only now, after the judge has passed.
    if flight.exchange.is_none() {
        match Exchange::request(deliveries.request(&flight.delivery)) {
            Ok(ex) => flight.exchange = Some(ex.landing_within(within)),
            // A request busbar cannot frame sends nothing.
            Err(_) => return Poll::Ready((Attempted::Judged(DEST_UNRESOLVABLE), Vec::new())),
        }
    }
    let Some(ex) = flight.exchange.as_mut() else {
        return Poll::Ready((Attempted::Transport, Vec::new()));
    };
    match line.send(ex, &url) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Some(status)) => Poll::Ready((Attempted::of_status(status), addrs)),
        Poll::Ready(None) => Poll::Ready((Attempted::Transport, addrs)),
    }
}

/// THE ATTEMPT IN FLIGHT, held in plane memory with the clock of the tick that began it: the
/// instance has one driver ticket, so at most one delivery is attempted at a time. A tick that
/// pends ends there (a driver ticket's op is never resumed: `abi::mechanism::lifecycle`, the
/// dispatcher's driver-ticket note), so what pended goes on through `drive` ([`drive`]).
#[derive(Default)]
pub(crate) struct Attempting(Keyed<(), (Flight, u64)>);

impl Attempting {
    fn take(&self) -> Option<(Flight, u64)> {
        self.0.remove(&())
    }

    /// When the held attempt began (the clock of the tick that started it).
    fn started_ns(&self) -> Option<u64> {
        self.0.with(&(), |h| h.map(|(_, at)| *at))
    }

    /// When the held attempt is abandoned; `0` = none is held.
    pub(crate) fn deadline_ns(&self) -> u64 {
        self.started_ns()
            .map_or(0, |at| at.saturating_add(DELIVERY_TIMEOUT_NS).max(1))
    }

    fn hold(&self, flight: Flight, now_ns: u64) {
        self.0.insert((), (flight, now_ns));
    }
}

/// THE TIME A DELIVERY ATTEMPT MAY TAKE, predev's own: `RELAY_TIMEOUT`, sixty seconds, the request
/// ceiling of `origin/predev:crates/busbar-a2a/src/a2a/transport.rs:92`, which
/// `crates/busbar-a2a/src/a2a/pushdeliver.rs:85` names as the delivery's time ceiling. An attempt
/// held longer than this lost its wake: it is abandoned, then requeued under predev's retry rules
/// (spec :390-393, B3).
const DELIVERY_TIMEOUT_NS: u64 = 60_000_000_000;

/// When the lifecycle tick is next wanted: the earliest waiting delivery, or the moment a held
/// attempt is abandoned; `0` = neither.
pub(crate) fn next_tick_ns(deliveries: &Deliveries, attempting: &Attempting) -> u64 {
    match (deliveries.next_tick_ns(), attempting.deadline_ns()) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => a.min(b),
    }
}

/// `tick`: ONE due notification attempted (see the module note); PENDING while its exchange is,
/// which ends the tick and leaves the attempt to `drive`. While an attempt is held the tick starts
/// no other and makes no host call: the delivery's one request is the held attempt's, and it goes
/// on only through `drive`, so a delivery is never sent by both paths. A door opened without host
/// tables, or a tick that may not pend, attempts nothing.
pub(crate) fn tick_deliveries(
    plane: &A2aDoor,
    instance: &Instance<'_, A2aDoor>,
    now_ns: u64,
) -> Outcome {
    let Some((ticket, mut calls)) = calls_of(plane, instance) else {
        return Outcome::Ready;
    };
    // This op runs on the instance's driver ticket: the one a queued delivery wakes.
    if let Some(host) = plane.host {
        plane.deliveries.arm(|| Box::new(move || host.wake(ticket)));
    }
    tick_over(&mut calls, &plane.deliveries, &plane.attempting, now_ns)
}

/// `drive`: the attempt a `tick` left PENDING goes on, the wake on the driver ticket being its
/// service's (the replay rule: the same host calls in the same order, each completed one answered
/// as it was). With no attempt in flight there is nothing to do.
pub(crate) fn drive(plane: &A2aDoor, instance: &Instance<'_, A2aDoor>) -> Outcome {
    match calls_of(plane, instance) {
        Some((_, mut calls)) => drive_over(&mut calls, &plane.deliveries, &plane.attempting),
        None => Outcome::Ready,
    }
}

/// The driver ticket this op runs on and the host calls it makes, when the door has the host it
/// needs to attempt a delivery.
fn calls_of<'p>(
    plane: &'p A2aDoor,
    instance: &Instance<'_, A2aDoor>,
) -> Option<(Ticket, Calls<'p>)> {
    let (host, services) = (plane.host.as_ref()?, plane.services?);
    let ticket = instance.ticket();
    (!ticket.is_none()).then_some((
        ticket,
        Calls {
            host,
            services,
            ticket,
        },
    ))
}

/// [`tick_deliveries`] over `line`.
fn tick_over(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    attempting: &Attempting,
    now_ns: u64,
) -> Outcome {
    if let Some(started) = attempting.started_ns() {
        // A held attempt belongs to `drive`, until it outlives its timeout (its wake was lost):
        // then it is CANCELLED FIRST (its connection closed, so it can never also complete), and
        // only then requeued under the retry rules, so two attempts for one delivery are never in
        // flight at once.
        if now_ns >= started.saturating_add(DELIVERY_TIMEOUT_NS) {
            if let Some((flight, _)) = attempting.take() {
                line.abandon(flight.exchange.as_ref().and_then(Exchange::stream));
                let jitter = line.jitter();
                deliveries.owe(&flight.delivery, Attempted::Transport);
                let _ = deliveries.settle(
                    &flight.delivery.task_id,
                    Attempted::Transport,
                    now_ns,
                    jitter,
                );
            }
        }
        return Outcome::Ready;
    }
    match deliveries.next_due(now_ns) {
        Some(delivery) => advance_attempt(
            line,
            deliveries,
            attempting,
            Flight {
                delivery,
                exchange: None,
            },
            now_ns,
        ),
        None => Outcome::Ready,
    }
}

/// [`drive`] over `line`.
fn drive_over(line: &mut dyn Line, deliveries: &Deliveries, attempting: &Attempting) -> Outcome {
    match attempting.take() {
        Some((flight, now_ns)) => advance_attempt(line, deliveries, attempting, flight, now_ns),
        None => Outcome::Ready,
    }
}

/// One entry of `flight`'s attempt, begun at `now_ns`: held again while its exchange pends, else
/// settled.
fn advance_attempt(
    line: &mut dyn Line,
    deliveries: &Deliveries,
    attempting: &Attempting,
    mut flight: Flight,
    now_ns: u64,
) -> Outcome {
    let jitter = line.jitter();
    match attempt(line, deliveries, &mut flight) {
        Poll::Pending => {
            attempting.hold(flight, now_ns);
            Outcome::Pending
        }
        Poll::Ready((end, reached)) => {
            deliveries.reached(&flight.delivery.url, &reached);
            deliveries.owe(&flight.delivery, end);
            let _ = deliveries.settle(&flight.delivery.task_id, end, now_ns, jitter);
            Outcome::Ready
        }
    }
}

#[cfg(test)]
#[path = "tests/push_door_tests.rs"]
mod tests;
