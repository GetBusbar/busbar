// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One whole session over the plane port (IF §8.6, §11.3, §12.4, §12.11; PLANE-DRIVER.md slice 9): [`run_session`]
//! composes what slices 2-8 built. `request`; the intents of every answer resolved ([`Task::resolve`]); a FORWARD
//! walked over the members ([`run_attempts`]), and when no member is left the plane told (`P_EXHAUSTED`, one
//! REFUSAL) so it renders the failure, with core's own text when it renders nothing; `end`; and the books
//! ([`Books`]): the AUDIT rows as they come and the unit's end, `Failed` when the plane or the session broke.
//!
//! [`UnitBooks`] is the production books over [`PortMoney`] and the unit's [`UnitCtx`] (the HTTP route's call
//! site); [`AuditOnly`] is the books of a session that is not a billed unit (a line). [`TicketGate`] is the
//! production [`TicketDoor`] over [`Tickets`] under the plane instance's own binding.
//!
//! The calls are synchronous: a driver runs this inside `spawn_blocking` with blocking seams.
//!
//! Not done here (PLANE-DRIVER.md): intents a plane states in a `FROM_UPSTREAM` piece answer are not resolved (the
//! feed in `port_upstream` takes no resolver); a reply is fed whole, so a streamed reply and a mid-stream
//! `checkpoint` are not driven.

use busbar_plugin_abi::fail::refused::R_NO_ROUTE;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{FROM_CORE, P_EXHAUSTED};
use busbar_plugin_abi::records::Reply;
use busbar_plugin_loader::encode::plane::encode_refusal;
use busbar_plugin_loader::ports::plane::PlaneIn;
use std::sync::{Arc, OnceLock};

use super::port_auth::{plain_refusal, TicketDoor};
use super::port_intents::{Detach, Namespace, Resolver};
use super::port_money::{AuditRow, PortMoney};
use super::port_session::{
    hand_out, Answer, Calls, Effects, Forward, SessionError, Task, ToClient,
};
use super::port_upstream::{run_attempts, Attempted, Members, UpSend, Wants};
use super::usage::{Ending, SessionUsage};
use super::AuditSink;
use crate::plane_grants::{TicketAdmitted, TicketDenied, Tickets};
use crate::refusal::RefusalMap;
use crate::teller::UnitCtx;

/// Where a session's accounting goes.
pub trait Books {
    /// The session's end: `End` after `end` ran, `Failed` when the plane or the session broke.
    fn ended(&self, ending: Ending, usage: &SessionUsage);
    /// One AUDIT row the plane stated.
    fn audit(&self, row: &AuditRow);
}

/// The books of a billed unit: the end through the unit's money seam, audit rows under the verified principal.
pub struct UnitBooks<'a> {
    money: &'a PortMoney,
    ctx: &'a UnitCtx,
    principal: Option<&'a str>,
}

impl<'a> UnitBooks<'a> {
    #[must_use]
    pub fn new(money: &'a PortMoney, ctx: &'a UnitCtx, principal: Option<&'a str>) -> Self {
        Self {
            money,
            ctx,
            principal,
        }
    }
}

impl Books for UnitBooks<'_> {
    fn ended(&self, ending: Ending, usage: &SessionUsage) {
        self.money.ended(self.ctx, ending, usage, self.principal);
    }

    fn audit(&self, row: &AuditRow) {
        if self.money.audit(row, self.principal).is_err() {
            tracing::warn!(action = &*row.action, "a plane audit row was not accepted");
        }
    }
}

/// The books of a session that is not a billed unit: AUDIT rows only, usage is not billed.
pub struct AuditOnly<'a> {
    pub sink: &'a dyn AuditSink,
    pub principal: Option<&'a str>,
}

impl Books for AuditOnly<'_> {
    fn ended(&self, _: Ending, _: &SessionUsage) {}

    fn audit(&self, row: &AuditRow) {
        if super::port_money::write_audit(self.sink, row, self.principal).is_err() {
            tracing::warn!(action = &*row.action, "a plane audit row was not accepted");
        }
    }
}

/// The production [`TicketDoor`]: the ticket store asked as the plane instance (plugin and configured name), so a
/// ticket another instance sealed does not open (§12.11).
pub struct TicketGate {
    tickets: Arc<dyn Tickets>,
    who: Namespace,
}

impl TicketGate {
    #[must_use]
    pub fn new(tickets: Arc<dyn Tickets>, who: Namespace) -> Self {
        Self { tickets, who }
    }
}

impl TicketDoor for TicketGate {
    fn is_ticket(&self, credential: &str) -> bool {
        self.tickets.is_ticket(credential)
    }

    fn admit<'a>(
        &'a self,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(async move {
            let who = self.who.caller();
            self.tickets.admit(&who, audience, credential, now_s).await
        })
    }
}

/// A [`TicketDoor`] whose gate is installed after the plane opened: the ticket host key comes from core's own
/// secrets, which resolve only after the plane instances open (IF §11.2). Until [`LateDoor::install`] it fails
/// closed: nothing is a ticket, every admit is `Unavailable`. Clones share the one slot.
#[derive(Clone, Default)]
pub struct LateDoor {
    slot: Arc<OnceLock<Arc<dyn TicketDoor>>>,
}

impl LateDoor {
    /// The door every clone answers through from now on. The first install stays: `false` = one was installed.
    pub fn install(&self, door: Arc<dyn TicketDoor>) -> bool {
        self.slot.set(door).is_ok()
    }
}

impl TicketDoor for LateDoor {
    fn is_ticket(&self, credential: &str) -> bool {
        self.slot
            .get()
            .is_some_and(|door| door.is_ticket(credential))
    }

    fn admit<'a>(
        &'a self,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        match self.slot.get() {
            Some(door) => door.admit(audience, credential, now_s),
            None => Box::pin(core::future::ready(Err(TicketDenied::Unavailable))),
        }
    }
}

/// What one session needs besides the plane.
pub struct Drive<'a> {
    pub resolver: &'a Resolver<'a>,
    /// The member walk and the far end; both or neither. A FORWARD with neither is `NotDriven`.
    pub members: Option<&'a mut dyn Members>,
    pub send: Option<&'a mut dyn UpSend>,
    /// The dialect the plane's `upstream` is asked in.
    pub dialect: &'a str,
    pub refusals: &'a dyn RefusalMap,
    pub effects: &'a dyn Effects,
    pub books: &'a dyn Books,
}

/// What a session produced.
#[derive(Debug, Default)]
pub struct Ran {
    /// What the client sees, in order.
    pub client: Vec<ToClient>,
    /// The last USAGE per (class, source) the session stated.
    pub usage: SessionUsage,
    /// The member that served, when a FORWARD was walked.
    pub member: Option<Box<str>>,
    pub attempts: u32,
    /// The walk found no member: the plane was told and its rendering (or core's text) is in `client`.
    pub exhausted: bool,
    /// WAKE_AT and DETACH, for the session loop (slice 7's left list).
    pub wake_at: Option<u64>,
    pub detach: Option<Detach>,
    /// The plane answered FINISH.
    pub finished: bool,
}

fn absorb(ran: &mut Ran, forward: &mut Option<Forward>, answers: Vec<Answer>, books: &dyn Books) {
    for answer in answers {
        ran.client.extend(answer.client);
        for row in &answer.audits {
            books.audit(row);
        }
        if forward.is_none() {
            *forward = answer.forward;
        }
        if answer.wake_at.is_some() {
            ran.wake_at = answer.wake_at;
        }
        if answer.detach.is_some() {
            ran.detach = answer.detach;
        }
        ran.finished |= answer.finish;
    }
}

/// Runs one session to its end. An error after the session began is booked as `Failed`.
///
/// # Errors
/// The plane refused, failed or faulted, broke a once rule, or stated a FORWARD with nothing to walk.
pub fn run_session<K: Calls + ?Sized>(
    calls: &K,
    req: &PlaneIn<'_>,
    body: &[u8],
    mut drive: Drive<'_>,
) -> Result<Ran, SessionError> {
    let (mut task, first) = Task::begin(calls, req, body, drive.effects)?;
    match drive_task(&mut task, first, req, &mut drive) {
        Ok(ran) => Ok(ran),
        Err(error) => {
            drive.books.ended(Ending::Failed, task.usage());
            Err(error)
        }
    }
}

fn drive_task<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    first: Answer,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_>,
) -> Result<Ran, SessionError> {
    let mut ran = Ran::default();
    let mut forward = None;
    let answers = task.resolve(first, drive.resolver, drive.effects)?;
    absorb(&mut ran, &mut forward, answers, drive.books);
    hand_out(drive.effects, &mut ran.client);
    if let Some(forward) = forward {
        let (Some(members), Some(send)) = (drive.members.as_deref_mut(), drive.send.as_deref_mut())
        else {
            return Err(SessionError::NotDriven);
        };
        let wants = Wants::from_facts(&forward.wants);
        let model = wants.model.clone().unwrap_or_default();
        let walked = run_attempts(
            task,
            &wants,
            drive.dialect,
            &model,
            members,
            send,
            drive.effects,
        )?;
        match walked {
            Attempted::Served {
                client,
                member,
                attempts,
                ..
            } => {
                ran.client.extend(client);
                hand_out(drive.effects, &mut ran.client);
                ran.member = Some(member);
                ran.attempts = attempts;
            }
            Attempted::Exhausted { attempts } => {
                ran.attempts = attempts;
                ran.exhausted = true;
                exhausted(task, req, drive, &mut ran)?;
            }
        }
    }
    let mut last = task.end(drive.effects)?;
    // STORE, COMMIT and PUSH of the end answer apply; a session that has ended can be told no result.
    let end_intents = std::mem::take(&mut last.intents);
    if !end_intents.is_empty() {
        let _ = drive.resolver.resolve(&end_intents, &mut task.held);
    }
    absorb(&mut ran, &mut None, vec![last], drive.books);
    ran.usage = task.usage().clone();
    hand_out(drive.effects, &mut ran.client);
    drive.books.ended(Ending::End, &ran.usage);
    Ok(ran)
}

/// No member is left: the plane is told (one REFUSAL, `P_EXHAUSTED`) and answers the client now.
fn exhausted<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    req: &PlaneIn<'_>,
    drive: &Drive<'_>,
    ran: &mut Ran,
) -> Result<(), SessionError> {
    let refusal = drive.refusals.for_core(req.route, R_NO_ROUTE);
    let mut arg = Reply::new();
    if encode_refusal(&mut arg, refusal.status, refusal.code, &refusal.text).is_err() {
        ran.client.extend(plain_refusal(&refusal));
        return Ok(());
    }
    let answer = task.piece(FROM_CORE, 0, P_EXHAUSTED, arg.as_bytes(), drive.effects)?;
    let answers = task.resolve(answer, drive.resolver, drive.effects)?;
    let before = ran.client.len();
    absorb(ran, &mut None, answers, drive.books);
    if ran.client.len() == before {
        ran.client.extend(plain_refusal(&refusal));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/port_serve_tests.rs"]
mod tests;
