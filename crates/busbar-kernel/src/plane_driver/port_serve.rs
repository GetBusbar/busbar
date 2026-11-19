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
//! The plane's calls are direct synchronous entries; [`run_session`] is a future that makes them on the request's
//! own task and awaits the walk, the far end, the store and the client between them. It is generic over the walk
//! (`M`) and the carrier (`S`), so none of those seams boxes a future.
//!
//! Every USAGE the session accepts reaches the books as it is accepted ([`Books::running`], driven by
//! [`Metered`]), and a session bills exactly the usage it accepted, once, whatever its ending (P087B). A
//! running checkpoint's `Cut` is not acted on mid-stream: the port path has no mid-stream cancel, and the
//! stream runs to its end as before (the ceiling never rewrites what the provider stated).
//!
//! Not done here (PLANE-DRIVER.md): intents a plane states in a `FROM_UPSTREAM` piece answer are not resolved (the
//! feed in `port_upstream` takes no resolver).

use busbar_plugin_abi::fail::refused::R_NO_ROUTE;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{FROM_CORE, P_EXHAUSTED};
use busbar_plugin_abi::records::Reply;
use busbar_ports::codec::plane::encode_refusal;
use busbar_ports::plane::PlaneIn;
use busbar_ports::FactVal;
use std::future::Future;
use std::sync::Arc;

use super::port_auth::{plain_refusal, TicketDoor};
use super::port_carrier::{write_channels, CarrierSession, Mapped};
use super::port_intents::{Detach, Namespace, Resolver};
use super::port_money::{AuditRow, PortMoney};
use super::port_session::{
    hand_out, Answer, Calls, ClientSink, Effects, Forward, SessionError, Task, ToClient, Violation,
};
use super::port_upstream::{run_attempts, Attempted, Members, UpSend, Wants};
use super::usage::{Ending, SessionUsage, UsageInvalid};
use super::AuditSink;
use crate::plane_grants::{TicketAdmitted, TicketDenied, Tickets};
use crate::refusal::RefusalMap;
use crate::teller::UnitCtx;

/// Where a session's accounting goes. Synchronous (no implementation waits); `Sync` because a session's books are
/// borrowed across the awaits of its task.
pub trait Books: Sync {
    /// The session's end: `End` after `end` ran, `Failed` when the plane or the session broke.
    fn ended(&self, ending: Ending, usage: &SessionUsage);
    /// One AUDIT row the plane stated.
    fn audit(&self, row: &AuditRow);

    /// The end user the plane projected on its request answer (PJ_END_USER), once. Default: kept nowhere.
    fn end_user(&self, _user: &str) {}

    /// The session accepted a USAGE: its usage as it now stands goes to the money at once (a running
    /// checkpoint), so a session that never reaches its end, or whose final report cannot be priced, bills
    /// what it accepted (P087B). The money's answer, when there is one. Default: not billed.
    fn running(&self, _usage: &SessionUsage) -> Option<super::Checkpoint> {
        None
    }

    /// [`Self::ended`], where `taken` is the money's answer to the last running checkpoint, taken of exactly
    /// `usage`: the end does not ask the money again. Default: [`Self::ended`].
    fn closed(&self, ending: Ending, usage: &SessionUsage, taken: Option<super::Checkpoint>) {
        let _ = taken;
        self.ended(ending, usage);
    }

    /// The session refused a USAGE the plane stated (`why`); the refused report is never billed and is
    /// audited. Called before the session's `Failed` end. Default: kept nowhere.
    fn refused(&self, _why: UsageInvalid) {}

    /// The session's far end is being dialled: the unit has run. Default: kept nowhere.
    fn dialled(&self) {}
}

/// The books of a billed unit: the end through the unit's money seam, audit rows under the verified principal.
pub struct UnitBooks<'a> {
    money: &'a PortMoney,
    ctx: &'a UnitCtx,
    principal: Option<&'a str>,
    journal: Option<&'a dyn super::HookJournal>,
}

impl<'a> UnitBooks<'a> {
    #[must_use]
    pub fn new(money: &'a PortMoney, ctx: &'a UnitCtx, principal: Option<&'a str>) -> Self {
        Self {
            money,
            ctx,
            principal,
            journal: None,
        }
    }

    /// The node's journal, told the end user the plane projects (`records.user`, ADMIN-API-1.6 §3.5).
    #[must_use]
    pub fn with_journal(mut self, journal: Option<&'a dyn super::HookJournal>) -> Self {
        self.journal = journal;
        self
    }
}

impl Books for UnitBooks<'_> {
    fn ended(&self, ending: Ending, usage: &SessionUsage) {
        self.money.ended(self.ctx, ending, usage, self.principal);
    }

    fn running(&self, usage: &SessionUsage) -> Option<super::Checkpoint> {
        Some(self.money.running(self.ctx, usage))
    }

    fn closed(&self, ending: Ending, usage: &SessionUsage, taken: Option<super::Checkpoint>) {
        self.money
            .ended_taken(self.ctx, ending, usage, taken, self.principal);
    }

    fn refused(&self, why: UsageInvalid) {
        self.money.refused(self.ctx, why, self.principal);
    }

    fn dialled(&self) {
        self.money.dialled(self.ctx);
    }

    fn audit(&self, row: &AuditRow) {
        if self.money.audit(row, self.principal).is_err() {
            tracing::warn!(action = &*row.action, "a plane audit row was not accepted");
        }
    }

    fn end_user(&self, user: &str) {
        if let Some(journal) = self.journal.filter(|journal| journal.keeps_end_user()) {
            journal.end_user(self.ctx.key, user);
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

/// A walk and a carrier that do not exist: the `M` and `S` of a session that walks nothing (its `members` and
/// `send` are `None`). It has no values, so none of its methods can run.
pub enum NoWalk {}

impl Members for NoWalk {
    async fn next(&mut self, _wants: &Wants) -> Option<super::port_upstream::Candidate> {
        match *self {}
    }
    fn declined(&mut self, _member: &super::port_upstream::Candidate) {
        match *self {}
    }
    fn failed(
        &mut self,
        _member: &super::port_upstream::Candidate,
        _failure: &super::port_upstream::Failure,
    ) {
        match *self {}
    }
    fn served(&mut self, _member: &super::port_upstream::Candidate) {
        match *self {}
    }
}

impl UpSend for NoWalk {
    type Rest<'a> = super::port_upstream::Whole;

    async fn open<'a>(
        &'a mut self,
        _member: &'a super::port_upstream::Candidate,
        _exchange: super::port_session::UpExchange,
    ) -> Result<super::port_upstream::UpOpen<Self::Rest<'a>>, super::port_upstream::SendFailed>
    {
        match *self {}
    }
}

/// What one session needs besides the plane: `M` is its member walk and `S` its carrier ([`NoWalk`] when it has
/// none), both static.
pub struct Drive<'a, M: Members = NoWalk, S: UpSend = NoWalk> {
    pub resolver: &'a Resolver<'a>,
    /// The member walk and the far end; both or neither. A FORWARD with neither is `NotDriven`.
    pub members: Option<&'a mut M>,
    pub send: Option<&'a mut S>,
    /// The dialect the plane's `upstream` is asked in.
    pub dialect: &'a str,
    pub refusals: &'a dyn RefusalMap,
    pub effects: &'a dyn Effects,
    pub books: &'a dyn Books,
    /// The carrier of this request: CHANNEL intents attach through it, EX_MSG writes go to the channels it attached,
    /// and a session that holds a channel, a media bridge, a wake time or a DETACH is pumped until it ends
    /// ([`CarrierSession::pump`]). `None` = no carrier: a CHANNEL is `P_ERROR` and the session ends with its walk.
    pub carrier: Option<&'a CarrierSession>,
}

/// A [`Drive`] without its walk: what a step that never touches the walk borrows across an await (a borrow of the
/// whole `Drive` would make the session's future `Send` only for a `Sync` walk).
#[derive(Clone, Copy)]
struct Seams<'a> {
    resolver: &'a Resolver<'a>,
    refusals: &'a dyn RefusalMap,
    effects: &'a dyn Effects,
    books: &'a dyn Books,
}

impl<'a, M: Members, S: UpSend> Drive<'a, M, S> {
    fn seams(&self) -> Seams<'a> {
        Seams {
            resolver: self.resolver,
            refusals: self.refusals,
            effects: self.effects,
            books: self.books,
        }
    }
}

/// One session of a seat's plane, everything but its walk: handed to [`super::port_egress::PortUpstream::walk`],
/// which runs it over the walk's own members and carrier, so the session is compiled for them (static calls).
pub struct SessionRun<'a> {
    pub port: &'a dyn busbar_ports::plane::PlanePort,
    pub req: &'a PlaneIn<'a>,
    pub body: &'a [u8],
    pub resolver: &'a Resolver<'a>,
    pub dialect: &'a str,
    pub refusals: &'a dyn RefusalMap,
    pub effects: &'a dyn Effects,
    pub books: &'a dyn Books,
    pub carrier: Option<&'a CarrierSession>,
}

impl<'a> SessionRun<'a> {
    /// The session to its end over `members` and `send`.
    ///
    /// # Errors
    /// As [`run_session`].
    pub fn run<'m, M: Members, S: UpSend>(
        self,
        members: &'m mut M,
        send: &'m mut S,
    ) -> impl Future<Output = Result<Ran, SessionError>> + Send + use<'a, 'm, M, S>
    where
        'a: 'm,
    {
        self.drive(Some(members), Some(send))
    }

    /// The session to its end with no walk: a FORWARD is `NotDriven`.
    ///
    /// # Errors
    /// As [`run_session`].
    pub fn alone(self) -> impl Future<Output = Result<Ran, SessionError>> + Send + use<'a> {
        self.drive::<NoWalk, NoWalk>(None, None)
    }

    /// `Send` is stated here, where the walk's types are still generic: a caller's future that holds this one is
    /// then `Send` without the compiler re-proving it through every borrow the session holds.
    fn drive<'m, M: Members, S: UpSend>(
        self,
        members: Option<&'m mut M>,
        send: Option<&'m mut S>,
    ) -> impl Future<Output = Result<Ran, SessionError>> + Send + use<'a, 'm, M, S>
    where
        'a: 'm,
    {
        run_session(
            self.port,
            self.req,
            self.body,
            Drive {
                resolver: self.resolver,
                members,
                send,
                dialect: self.dialect,
                refusals: self.refusals,
                effects: self.effects,
                books: self.books,
                carrier: self.carrier,
            },
        )
    }
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

pub(super) fn absorb(
    ran: &mut Ran,
    forward: &mut Option<Forward>,
    answers: impl IntoIterator<Item = Answer>,
    books: &dyn Books,
) {
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
pub async fn run_session<K: Calls + ?Sized, M: Members, S: UpSend>(
    calls: &K,
    req: &PlaneIn<'_>,
    body: &[u8],
    mut drive: Drive<'_, M, S>,
) -> Result<Ran, SessionError> {
    if let Some(pending) = drive.effects.admission() {
        return run_pending_session(calls, req, body, drive, pending).await;
    }
    if let Some(hooks) = drive
        .effects
        .hooks()
        .filter(|hooks| hooks.binder.active(req.route))
    {
        return run_hook_session(calls, req, body, drive, hooks).await;
    }
    let (mut task, first) = Task::begin(calls, req, body, drive.effects)?;
    if let Some(user) = end_user_of(&first) {
        drive.books.end_user(user);
    }
    match drive_task(&mut task, first, req, &mut drive).await {
        Ok(ran) => Ok(ran),
        Err(error) => {
            failed(drive.books, task.usage(), &error);
            Err(error)
        }
    }
}

/// A session that broke after it began: a USAGE it refused is audited (never billed), then it ends `Failed`,
/// which bills the usage it accepted before it broke, once (P087B).
fn failed(books: &dyn Books, usage: &SessionUsage, error: &SessionError) {
    if let SessionError::Violation(Violation::Usage(why)) = error {
        books.refused(*why);
    }
    books.ended(Ending::Failed, usage);
}

async fn run_pending_session<K: Calls + ?Sized, M: Members, S: UpSend>(
    calls: &K,
    req: &PlaneIn<'_>,
    body: &[u8],
    mut drive: Drive<'_, M, S>,
    pending: &super::port_admission::Pending,
) -> Result<Ran, SessionError> {
    use super::port_hooks::stage::{self, Buffered, Observed, When};
    let buffered = Buffered::new(drive.effects);
    // Which step of the pending admission a failure ended in: the request is then answered as
    // failed (`port::drive_session`), and this line says where.
    let at = |step: &'static str| {
        move |error: SessionError| {
            tracing::warn!(step, ?error, "a pending admission ended before its unit opened");
            error
        }
    };
    let (mut task, first) = Task::begin(calls, req, body, &buffered).map_err(at("begin"))?;
    let outcome = async {
        let mut answers = task
            .resolve_before_hooks(first, drive.resolver, &buffered)
            .await
            .map_err(at("screen"))?;
        let wants = answers
            .iter()
            .find_map(|answer| answer.forward.as_ref())
            .map(|forward| Wants::from_facts(&forward.wants));
        // The request's one admission, in three steps and in this order. (1) Its walk is
        // resolved and the key's grant of it judged: a key that may not take the walk is
        // refused here and no hook is shown its request. (2) The route's hooks, when it has
        // any: a hook that refuses has spoken before any unit is opened and before anything is
        // charged, and its refusal drops `resolved` with the monetary callback never run.
        // (3) The money: the unit is opened and held. A route with no hook goes from (1) to (3)
        // with nothing between them: no stage is built, nothing is allocated, no hook is called.
        let resolved = pending
            .resolve_walk(
                drive.members.as_deref_mut(),
                wants.as_ref(),
                task.request_declaration().map_err(at("declaration"))?,
            )
            .map_err(at("walk"))?;
        let stage = match drive
            .effects
            .hooks()
            .filter(|hooks| hooks.binder.active(req.route))
        {
            Some(hooks) => Some(
                stage::enforce(
                    hooks,
                    &mut task,
                    &mut answers,
                    req,
                    &mut drive,
                    &buffered,
                    When::BeforeMoney,
                )
                .await?,
            ),
            None => None,
        };
        // Taken before the money is asked: a money refusal ends the request's admission.
        let completion = stage.as_ref().and_then(|stage| stage.completion());
        if let Err(error) = pending.admit_money(drive.members.as_deref_mut(), resolved) {
            if let (Some(stage), SessionError::AdmissionRefused(refusal)) = (&stage, &error) {
                stage.money_refused(refusal.status, completion.as_ref());
            }
            return Err(at("money")(error));
        }
        task.bind_admission(pending)?;
        if let Some(stage) = &stage {
            // The unit is open: the records its hooks made reach its journal now.
            stage.unit_opened();
        }
        if let Some(user) = answers.iter().find_map(end_user_of) {
            drive.books.end_user(user);
        }
        if let Some(stage) = stage {
            let observed = Observed::new(drive.effects, stage);
            buffered.release();
            let mut resolved = None;
            for answer in answers {
                if let (Some(carrier), Some(forward)) = (drive.carrier, &answer.forward) {
                    carrier.map.point_wanted(&Wants::from_facts(&forward.wants));
                }
                gather(
                    &mut resolved,
                    task.resolve(answer, drive.resolver, &observed).await?,
                );
            }
            let mut allowed = Drive {
                resolver: drive.resolver,
                members: drive.members.take(),
                send: drive.send.take(),
                dialect: drive.dialect,
                refusals: drive.refusals,
                effects: &observed,
                books: drive.books,
                carrier: drive.carrier,
            };
            drive_answers(&mut task, resolved.unwrap_or_default(), req, &mut allowed).await
        } else {
            buffered.release();
            let mut resolved = None;
            for answer in answers {
                if let (Some(carrier), Some(forward)) = (drive.carrier, &answer.forward) {
                    carrier.map.point_wanted(&Wants::from_facts(&forward.wants));
                }
                gather(
                    &mut resolved,
                    task.resolve(answer, drive.resolver, drive.effects).await?,
                );
            }
            drive_answers(&mut task, resolved.unwrap_or_default(), req, &mut drive).await
        }
    }
    .await;
    if let Err(error) = &outcome {
        failed(drive.books, task.usage(), error);
    }
    outcome
}

async fn run_hook_session<K: Calls + ?Sized, M: Members, S: UpSend>(
    calls: &K,
    req: &PlaneIn<'_>,
    body: &[u8],
    mut drive: Drive<'_, M, S>,
    hooks: &super::port_hooks::Invocation,
) -> Result<Ran, SessionError> {
    use super::port_hooks::stage::{self, Buffered, Observed, When};
    drive
        .effects
        .invocation()
        .ok_or(SessionError::HookPrerequisite)?;
    let buffered = Buffered::new(drive.effects);
    let (mut task, first) = Task::begin(calls, req, body, &buffered)?;
    if let Some(user) = end_user_of(&first) {
        drive.books.end_user(user);
    }
    let outcome = async {
        let mut answers = if hooks.binder.enforcing(req.route) {
            task.resolve_before_hooks(first, drive.resolver, &buffered)
                .await?
        } else {
            task.resolve(first, drive.resolver, &buffered).await?
        };
        // This request's unit was open before its session began (it is not a pending admission).
        let stage = stage::enforce(
            hooks,
            &mut task,
            &mut answers,
            req,
            &mut drive,
            &buffered,
            When::UnitOpen,
        )
        .await?;
        let observed = Observed::new(drive.effects, stage);
        buffered.release();
        let mut resolved = None;
        for answer in answers {
            if let (Some(carrier), Some(forward)) = (drive.carrier, &answer.forward) {
                carrier.map.point_wanted(&Wants::from_facts(&forward.wants));
            }
            gather(
                &mut resolved,
                task.resolve(answer, drive.resolver, &observed).await?,
            );
        }
        let mut allowed = Drive {
            resolver: drive.resolver,
            members: drive.members.take(),
            send: drive.send.take(),
            dialect: drive.dialect,
            refusals: drive.refusals,
            effects: &observed,
            books: drive.books,
            carrier: drive.carrier,
        };
        drive_answers(&mut task, resolved.unwrap_or_default(), req, &mut allowed).await
    }
    .await;
    if let Err(error) = &outcome {
        failed(drive.books, task.usage(), error);
    }
    outcome
}

/// The answers resolved so far, gathered without a fresh buffer: the first resolution's own Vec
/// becomes the list (the common one-answer case copies nothing) and later ones extend it.
fn gather(resolved: &mut Option<Vec<Answer>>, more: Vec<Answer>) {
    match resolved {
        Some(held) => held.extend(more),
        None => *resolved = Some(more),
    }
}

/// The end user a plane projected on its request answer (PJ_END_USER), when it stated one.
fn end_user_of(first: &Answer) -> Option<&str> {
    first.facts.iter().find_map(|(key, value)| match value {
        FactVal::Text(user)
            if *key == busbar_plugin_abi::fail::fact::PJ_END_USER && !user.is_empty() =>
        {
            Some(&**user)
        }
        _ => None,
    })
}

async fn drive_task<K: Calls + ?Sized, M: Members, S: UpSend>(
    task: &mut Task<'_, K>,
    first: Answer,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_, M, S>,
) -> Result<Ran, SessionError> {
    if let (Some(carrier), Some(first_forward)) = (drive.carrier, &first.forward) {
        carrier
            .map
            .point_wanted(&Wants::from_facts(&first_forward.wants));
    }
    let answers = task.resolve(first, drive.resolver, drive.effects).await?;
    drive_answers(task, answers, req, drive).await
}

/// The walk of a FORWARD over `members` (recording each pick in the carrier's map when the session has one).
async fn walk<K: Calls + ?Sized, M: Members, S: UpSend>(
    task: &mut Task<'_, K>,
    wants: &Wants,
    model: &str,
    members: &mut M,
    send: &mut S,
    (carrier, dialect, effects): (Option<&CarrierSession>, &str, &dyn Effects),
) -> Result<(Attempted, Option<u32>), SessionError> {
    match carrier {
        Some(carrier) => {
            let mut mapped = Mapped::new(members, &carrier.map);
            let walked =
                run_attempts(task, wants, dialect, model, &mut mapped, send, effects).await?;
            Ok((walked, mapped.retry_after()))
        }
        None => {
            let walked = run_attempts(task, wants, dialect, model, members, send, effects).await?;
            Ok((walked, members.retry_after()))
        }
    }
}

async fn answer_session<K: Calls + ?Sized, M: Members, S: UpSend>(
    task: &mut Task<'_, K>,
    answers: Vec<Answer>,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_, M, S>,
) -> Result<Ran, SessionError> {
    let mut ran = Ran::default();
    let mut forward = None;
    let written = write_channels(task, &answers, drive.resolver, drive.effects).await?;
    absorb(&mut ran, &mut forward, answers, drive.books);
    absorb(&mut ran, &mut None, written, drive.books);
    drive.effects.observed_usage(task.usage());
    hand_out(drive.effects, &mut ran.client).await;
    if let Some(forward) = forward {
        let wants = Wants::from_facts(&forward.wants);
        if task.is_command() {
            let answer = task.command(&wants, drive.dialect, drive.effects)?;
            let answers = task.resolve(answer, drive.resolver, drive.effects).await?;
            let written = write_channels(task, &answers, drive.resolver, drive.effects).await?;
            absorb(&mut ran, &mut None, answers, drive.books);
            absorb(&mut ran, &mut None, written, drive.books);
            drive.effects.observed_usage(task.usage());
            hand_out(drive.effects, &mut ran.client).await;
        } else {
            let (Some(members), Some(send)) = (drive.members.take(), drive.send.take()) else {
                return Err(SessionError::NotDriven);
            };
            let model = wants.model.clone().unwrap_or_default();
            let seams = (drive.carrier, drive.dialect, drive.effects);
            let walked = walk(task, &wants, &model, &mut *members, &mut *send, seams).await;
            drive.members = Some(members);
            drive.send = Some(send);
            let (walked, wait) = walked?;
            match walked {
                Attempted::Served {
                    client,
                    member,
                    attempts,
                    ..
                } => {
                    ran.client.extend(client);
                    drive.effects.observed_usage(task.usage());
                    hand_out(drive.effects, &mut ran.client).await;
                    ran.member = Some(member);
                    ran.attempts = attempts;
                }
                Attempted::Exhausted {
                    attempts,
                    local_quota,
                } => {
                    ran.attempts = attempts;
                    ran.exhausted = true;
                    exhausted(task, req, drive.seams(), &mut ran, wait, local_quota).await?;
                }
            }
        }
    }
    if let Some(carrier) = drive.carrier {
        carrier
            .pump(task, &mut ran, drive.resolver, drive.effects, drive.books)
            .await?;
    }
    let mut last = task.end(drive.effects)?;
    // STORE, COMMIT and PUSH of the end answer apply; a session that has ended can be told no result.
    let end_intents = std::mem::take(&mut last.intents);
    if !end_intents.is_empty() {
        let _ = drive
            .resolver
            .resolve(&end_intents, &last.lent, &mut task.held, &mut task.reads)
            .await;
    }
    absorb(&mut ran, &mut None, [last], drive.books);
    ran.usage = task.usage().clone();
    drive.effects.observed_usage(task.usage());
    hand_out(drive.effects, &mut ran.client).await;
    Ok(ran)
}

/// The session's effects with its money metered: every USAGE the session accepts goes to the books as it is
/// accepted (the effects are told the session's usage after every answer: [`Effects::observed_usage`]), once
/// per change, and a far end dialled is booked as run. Every other effect is the inner one's.
struct Metered<'e> {
    inner: &'e dyn Effects,
    books: &'e dyn Books,
    /// The usage revision the books last took, with the money's answer to it.
    taken: std::sync::Mutex<Option<(u64, Option<super::Checkpoint>)>>,
}

impl Metered<'_> {
    /// The money's answer to the last running checkpoint, when it was taken of exactly `usage`.
    fn taken(&self, usage: &SessionUsage) -> Option<super::Checkpoint> {
        let taken = *self
            .taken
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taken
            .filter(|(revision, _)| *revision == usage.revision())
            .and_then(|(_, verdict)| verdict)
    }
}

impl Effects for Metered<'_> {
    fn admission_owner(&self) -> Option<&Arc<super::port_admission::Pending>> {
        self.inner.admission_owner()
    }
    fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        self.inner.data()
    }
    fn admission(&self) -> Option<&super::port_admission::Pending> {
        self.inner.admission()
    }
    fn hooks(&self) -> Option<&super::port_hooks::Invocation> {
        self.inner.hooks()
    }
    fn routing(&self, attempt: u32, model: &str, remaining: Option<usize>, failed: Option<&str>) {
        self.inner.routing(attempt, model, remaining, failed);
    }
    fn response(&self, status: u16) {
        self.inner.response(status);
    }
    fn observed_usage(&self, usage: &SessionUsage) {
        self.inner.observed_usage(usage);
        if usage.is_empty() {
            return;
        }
        let mut taken = self
            .taken
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if taken.is_some_and(|(revision, _)| revision == usage.revision()) {
            return;
        }
        *taken = Some((usage.revision(), self.books.running(usage)));
    }
    fn dialled(&self) {
        self.inner.dialled();
        self.books.dialled();
    }
    fn invocation(&self) -> Option<&crate::host_services::InvocationContext> {
        self.inner.invocation()
    }
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.inner.emit(carrier, bytes);
    }
    fn client(&self) -> Option<&dyn ClientSink> {
        self.inner.client()
    }
}

/// The session from its resolved answers to its end, its effects [`Metered`]: on its end the books take the
/// usage it accepted, once ([`Books::closed`]).
async fn drive_answers<K: Calls + ?Sized, M: Members, S: UpSend>(
    task: &mut Task<'_, K>,
    answers: Vec<Answer>,
    req: &PlaneIn<'_>,
    drive: &mut Drive<'_, M, S>,
) -> Result<Ran, SessionError> {
    let metered = Metered {
        inner: drive.effects,
        books: drive.books,
        taken: std::sync::Mutex::new(None),
        cut: std::sync::atomic::AtomicBool::new(false),
    };
    let mut metering = Drive {
        resolver: drive.resolver,
        members: drive.members.take(),
        send: drive.send.take(),
        dialect: drive.dialect,
        refusals: drive.refusals,
        effects: &metered,
        books: drive.books,
        carrier: drive.carrier,
    };
    let ran = answer_session(task, answers, req, &mut metering).await?;
    drive
        .books
        .closed(Ending::End, &ran.usage, metered.taken(&ran.usage));
    Ok(ran)
}

/// No member is left: the plane is told (one REFUSAL, `P_EXHAUSTED`) and answers the client now. `wait` is the
/// walk's Retry-After (IF §12.3): the refusal's head carries it unless the plane already stated one (the REFUSAL
/// record has no field for it, so core stamps the head the client gets).
async fn exhausted<K: Calls + ?Sized>(
    task: &mut Task<'_, K>,
    req: &PlaneIn<'_>,
    drive: Seams<'_>,
    ran: &mut Ran,
    wait: Option<u32>,
    local_quota: bool,
) -> Result<(), SessionError> {
    let code = if local_quota {
        busbar_plugin_abi::fail::refused::R_RATE_LIMITED
    } else {
        R_NO_ROUTE
    };
    let refusal = drive.refusals.for_core(req.route, code);
    let before = ran.client.len();
    let mut arg = Reply::new();
    if encode_refusal(&mut arg, refusal.status, refusal.code, &refusal.text).is_err() {
        ran.client.extend(plain_refusal(&refusal));
        stamp_retry_after(&mut ran.client[before..], wait);
        return Ok(());
    }
    let answer = task.piece(FROM_CORE, 0, P_EXHAUSTED, arg.as_bytes(), drive.effects)?;
    let answers = task.resolve(answer, drive.resolver, drive.effects).await?;
    absorb(ran, &mut None, answers, drive.books);
    if ran.client.len() == before {
        ran.client.extend(plain_refusal(&refusal));
    }
    stamp_retry_after(&mut ran.client[before..], wait);
    Ok(())
}

/// The `retry-after` field core adds to an exhausted session's response head.
const RETRY_AFTER: &[u8] = b"retry-after";

/// Adds `retry-after: <wait>` to the first head of `items` when it states none (any case).
fn stamp_retry_after(items: &mut [ToClient], wait: Option<u32>) {
    let Some(wait) = wait else {
        return;
    };
    let Some(ToClient::Head { fields, .. }) = items
        .iter_mut()
        .find(|item| matches!(item, ToClient::Head { .. }))
    else {
        return;
    };
    if fields
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(RETRY_AFTER))
    {
        return;
    }
    fields.push(crate::cold::retry_after_field(RETRY_AFTER, wait));
}

#[cfg(test)]
#[path = "tests/port_serve_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/unbilled_tests.rs"]
mod unbilled_tests;
