// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::auth_handle::{AuthHandleHost, StreamPolicy};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::guest_policy::Open;
use busbar_contract::framing_scope::{AdoptionSource, FramingScope, SessionTransfer};

pub const CONTEXT_REFUSED: &str = "the service does not belong to this live host framing";

static NEXT_LEG: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
enum State {
    Opening(Option<u64>),
    Confirming(u64),
    Ready(u64),
    Closing(Option<u64>),
    Detached(u64),
    Ended,
}

#[derive(Default)]
struct StreamOperations {
    owners: HashMap<u64, Ticket>,
    admitted: HashSet<u64>,
    progress: HashSet<Ticket>,
    cancelled: HashSet<Ticket>,
}

pub struct FramingContext {
    owner: u64,
    listener: u64,
    connection: u64,
    leg: u64,
    state: Mutex<State>,
    retained_input: AtomicU64,
    host: Option<Weak<dyn AuthHandleHost>>,
    opening: Option<StreamPolicy>,
    inherited: Option<SessionTransfer>,
    adoption_reply: Option<Arc<[u8]>>,
    source: Mutex<Option<Arc<dyn FramingScope>>>,
    streams: Mutex<HashMap<u64, StreamPolicy>>,
    ended_streams: Mutex<HashSet<u64>>,
    replies: Mutex<HashMap<Ticket, Arc<[u8]>>>,
    operations: Mutex<StreamOperations>,
}

impl std::fmt::Debug for FramingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramingContext")
            .field("owner", &self.owner)
            .field("listener", &self.listener)
            .field("connection", &self.connection)
            .field("leg", &self.leg)
            .finish_non_exhaustive()
    }
}

impl FramingContext {
    pub fn new(
        owner: u64,
        listener: u64,
        connection: u64,
        host: Option<Weak<dyn AuthHandleHost>>,
    ) -> Result<Arc<Self>, &'static str> {
        if owner == 0 {
            return Err(CONTEXT_REFUSED);
        }
        let leg = NEXT_LEG
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| CONTEXT_REFUSED)?;
        let opening = if listener != 0 {
            match host.as_ref().and_then(Weak::upgrade) {
                Some(host) => host.framing_started(owner, listener, leg)?,
                None => None,
            }
        } else {
            None
        };
        Ok(Arc::new(Self {
            owner,
            listener,
            connection: if connection == 0 { leg } else { connection },
            leg,
            state: Mutex::new(State::Opening(None)),
            retained_input: AtomicU64::new(0),
            host,
            opening,
            inherited: None,
            adoption_reply: None,
            source: Mutex::default(),
            streams: Mutex::default(),
            ended_streams: Mutex::default(),
            replies: Mutex::default(),
            operations: Mutex::default(),
        }))
    }

    pub fn adopt(
        owner: u64,
        source: Arc<dyn FramingScope>,
        host: Option<Weak<dyn AuthHandleHost>>,
    ) -> Result<Arc<Self>, &'static str> {
        if owner == 0 {
            return Err(CONTEXT_REFUSED);
        }
        let from = source.adoption_source().ok_or(CONTEXT_REFUSED)?;
        let leg = NEXT_LEG
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| CONTEXT_REFUSED)?;
        let inherited = if from.listener == 0 {
            None
        } else {
            Some(
                host.as_ref()
                    .and_then(Weak::upgrade)
                    .ok_or(CONTEXT_REFUSED)?
                    .framing_adopting(from, owner, leg)?,
            )
        };
        let adoption_reply = inherited.map(|transfer| {
            Arc::from(busbar_contract::abi::mechanism::extensions::encode(&[(
                busbar_contract::abi::transport::adopted_session::EXT_ADOPTED_SESSION,
                &transfer.session.encode(),
            )]))
        });
        Ok(Arc::new(Self {
            owner,
            listener: source.listener(),
            connection: source.connection(),
            leg,
            state: Mutex::new(State::Opening(None)),
            retained_input: AtomicU64::new(0),
            host,
            opening: None,
            inherited,
            adoption_reply,
            source: Mutex::new(Some(source)),
            streams: Mutex::default(),
            ended_streams: Mutex::default(),
            replies: Mutex::default(),
            operations: Mutex::default(),
        }))
    }

    #[must_use]
    pub fn owner(&self) -> u64 {
        self.owner
    }

    #[must_use]
    pub fn listener(&self) -> u64 {
        self.listener
    }

    #[must_use]
    pub fn connection(&self) -> u64 {
        self.connection
    }

    #[must_use]
    pub fn leg(&self) -> u64 {
        self.leg
    }

    pub fn check(&self, owner: u64, conn: u64, teardown: bool) -> Result<(), &'static str> {
        if owner != self.owner || conn == 0 {
            return Err(CONTEXT_REFUSED);
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut *state {
            State::Opening(_) if self.inherited.is_some() => Err(CONTEXT_REFUSED),
            State::Opening(token) => match *token {
                Some(t) if t != conn => Err(CONTEXT_REFUSED),
                _ => {
                    *token = Some(conn);
                    Ok(())
                }
            },
            State::Ready(t) if *t == conn => Ok(()),
            State::Closing(Some(t)) if teardown && *t == conn => Ok(()),
            _ => Err(CONTEXT_REFUSED),
        }
    }

    pub fn confirm(&self, conn: u64) -> Result<(), &'static str> {
        let first = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match *state {
                State::Opening(token) if conn != 0 && token.is_none_or(|t| t == conn) => {
                    *state = State::Confirming(conn);
                    true
                }
                State::Ready(token) if conn != 0 && token == conn => false,
                _ => return Err(CONTEXT_REFUSED),
            }
        };
        if first {
            let host = self.host.as_ref().and_then(Weak::upgrade);
            let confirmed = if self.inherited.is_some() {
                host.as_ref()
                    .ok_or(CONTEXT_REFUSED)
                    .and_then(|host| host.framing_adopted(self.owner, self.leg, conn))
            } else {
                if let Some(host) = host {
                    host.framing_ready(self.owner, self.leg);
                }
                Ok(())
            };
            if let Err(error) = confirmed {
                self.end();
                return Err(error);
            }
            {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                match *state {
                    State::Confirming(token) if token == conn => *state = State::Ready(conn),
                    _ => return Err(CONTEXT_REFUSED),
                }
            }
            let source = self
                .source
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(source) = source {
                source.end();
            }
        }
        Ok(())
    }

    pub fn detach(&self) -> Result<(), &'static str> {
        let token = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let State::Ready(token) = *state else {
                return Err(CONTEXT_REFUSED);
            };
            *state = State::Closing(Some(token));
            token
        };
        if self.listener != 0 {
            self.host
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or(CONTEXT_REFUSED)?
                .framing_detached(self.owner, self.leg)?;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match *state {
            State::Closing(Some(conn)) if conn == token => {
                *state = State::Detached(token);
                Ok(())
            }
            _ => Err(CONTEXT_REFUSED),
        }
    }

    pub fn closing(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = match *state {
            State::Opening(token) => State::Closing(token),
            State::Confirming(token) => State::Closing(Some(token)),
            State::Ready(token) => State::Closing(Some(token)),
            other => other,
        };
    }

    pub fn end(&self) {
        let notify = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let notify = !matches!(*state, State::Ended);
            *state = State::Ended;
            notify
        };
        if notify {
            if let Some(host) = self.host.as_ref().and_then(Weak::upgrade) {
                host.framing_ended(self.leg);
            }
            let source = self
                .source
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(source) = source {
                source.end();
            }
        }
    }
}

impl Drop for FramingContext {
    fn drop(&mut self) {
        self.end();
    }
}

impl FramingScope for FramingContext {
    fn retained_input(&self) -> u64 {
        self.retained_input.load(Ordering::Acquire)
    }

    fn set_retained_input(&self, bytes: u64) {
        self.retained_input.store(bytes, Ordering::Release);
    }

    fn owner(&self) -> u64 {
        self.owner()
    }
    fn listener(&self) -> u64 {
        self.listener()
    }
    fn connection(&self) -> u64 {
        self.connection()
    }
    fn leg(&self) -> u64 {
        self.leg()
    }
    fn opening_policy(&self) -> Option<Arc<busbar_contract::abi::transport::guest_policy::Policy>> {
        self.opening
            .as_ref()
            .map(|policy| Arc::clone(&policy.policy))
    }
    fn policy_generation(&self, stream: u64, peer: bool) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, State::Ended) {
            return None;
        }
        if self
            .ended_streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&stream)
        {
            return None;
        }
        if let Some(inherited) = self.inherited {
            return (matches!(*state, State::Ready(_))
                && !peer
                && inherited.session.stream == stream)
                .then_some(inherited.generation);
        }
        if peer && matches!(*state, State::Opening(_)) {
            return self.opening.as_ref().map(|loan| loan.policy.generation);
        }
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .map(|loan| loan.policy.generation)
    }
    fn open_stream(&self, ticket: Ticket, open: Open) -> Result<(), &'static str> {
        if self.inherited.is_some() {
            return Err(CONTEXT_REFUSED);
        }
        {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if !matches!(*state, State::Ready(_)) {
                return Err(CONTEXT_REFUSED);
            }
            if self
                .ended_streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&open.stream)
            {
                return Err(CONTEXT_REFUSED);
            }
            let mut operations = self
                .operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if operations.cancelled.contains(&ticket) {
                return Err(CONTEXT_REFUSED);
            }
            if !operations.admitted.contains(&open.stream) {
                match operations.owners.entry(open.stream) {
                    std::collections::hash_map::Entry::Vacant(at) => {
                        at.insert(ticket);
                    }
                    std::collections::hash_map::Entry::Occupied(at) if *at.get() == ticket => {}
                    _ => return Err(CONTEXT_REFUSED),
                }
            }
        }
        let cached = self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&open.stream)
            .cloned();
        let loan = match cached {
            Some(loan) => loan,
            None => self
                .host
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or(CONTEXT_REFUSED)?
                .stream_open(self.owner, self.listener, self.leg, open.stream)?,
        };
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(*state, State::Ready(_)) {
            return Err(CONTEXT_REFUSED);
        }
        if self
            .ended_streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&open.stream)
        {
            return Err(CONTEXT_REFUSED);
        }
        let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        let loan = match streams.entry(open.stream) {
            std::collections::hash_map::Entry::Vacant(at) => {
                self.operations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .progress
                    .insert(ticket);
                at.insert(loan)
            }
            std::collections::hash_map::Entry::Occupied(at) => at.into_mut(),
        };
        let reply = if open.known_generation == loan.policy.generation {
            Arc::clone(&loan.current)
        } else {
            Arc::clone(&loan.full)
        };
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ticket, reply);
        Ok(())
    }
    fn operation_reply(&self, ticket: Ticket) -> Option<Arc<[u8]>> {
        if let Some(reply) = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ticket)
            .cloned()
        {
            return Some(reply);
        }
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        matches!(*state, State::Opening(_))
            .then(|| {
                self.adoption_reply
                    .clone()
                    .or_else(|| self.opening.as_ref().map(|loan| Arc::clone(&loan.full)))
            })
            .flatten()
    }
    fn hold_operation_reply(&self, ticket: Ticket, reply: Arc<[u8]>) {
        let old = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ticket, reply);
        drop(old);
    }
    fn operation_done(&self, ticket: Ticket) {
        let reply = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket);
        drop(reply);
    }
    fn operation_started(&self, ticket: Ticket) {
        self.operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancelled
            .remove(&ticket);
    }
    fn take_control_progress(&self, ticket: Ticket) -> bool {
        self.operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .progress
            .remove(&ticket)
    }
    fn claim_stream_operation(
        &self,
        ticket: Ticket,
        stream: u64,
        generation: u64,
    ) -> Result<(), &'static str> {
        if self.listener == 0 {
            return Ok(());
        }
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(*state, State::Ready(_) | State::Closing(_))
            || self
                .ended_streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&stream)
        {
            return Err(CONTEXT_REFUSED);
        }
        if let Some(inherited) = self.inherited {
            return if inherited.session.stream == stream && inherited.generation == generation {
                Ok(())
            } else {
                Err(CONTEXT_REFUSED)
            };
        }
        if !self
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream)
            .is_some_and(|loan| loan.policy.generation == generation)
        {
            return Err(CONTEXT_REFUSED);
        }
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if operations.cancelled.contains(&ticket) {
            return Err(CONTEXT_REFUSED);
        }
        if operations.admitted.contains(&stream) {
            return Ok(());
        }
        match operations.owners.entry(stream) {
            std::collections::hash_map::Entry::Vacant(at) => {
                at.insert(ticket);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(at) if *at.get() == ticket => Ok(()),
            _ => Err(CONTEXT_REFUSED),
        }
    }
    fn admit_stream(&self, stream: u64) {
        let _state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if self
            .ended_streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&stream)
        {
            return;
        }
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        operations.admitted.insert(stream);
        operations.owners.remove(&stream);
    }
    fn operation_finished(&self, ticket: Ticket, failed: bool) {
        let retired = {
            let _state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let mut operations = self
                .operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            operations.progress.remove(&ticket);
            if failed {
                operations.cancelled.insert(ticket);
            }
            let streams: Vec<_> = operations
                .owners
                .extract_if(|_, owner| *owner == ticket)
                .map(|(stream, _)| stream)
                .collect();
            if failed {
                let mut ended = self
                    .ended_streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let mut loans = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
                streams
                    .into_iter()
                    .map(|stream| {
                        ended.insert(stream);
                        (stream, loans.remove(&stream))
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };
        self.operation_done(ticket);
        if let Some(host) = self.host.as_ref().and_then(Weak::upgrade) {
            for (stream, _) in &retired {
                host.stream_ended(self.owner, self.leg, *stream);
            }
        }
        drop(retired);
    }
    fn stream_ended(&self, stream: u64) {
        let loan = {
            let _state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let mut operations = self
                .operations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            operations.owners.remove(&stream);
            operations.admitted.remove(&stream);
            self.ended_streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(stream);
            self.streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&stream)
        };
        if let Some(host) = self.host.as_ref().and_then(Weak::upgrade) {
            host.stream_ended(self.owner, self.leg, stream);
        }
        drop(loan);
    }
    fn check(&self, owner: u64, conn: u64, teardown: bool) -> Result<(), &'static str> {
        self.check(owner, conn, teardown)
    }
    fn confirm(&self, conn: u64) -> Result<(), &'static str> {
        self.confirm(conn)
    }
    fn detach(&self) -> Result<(), &'static str> {
        self.detach()
    }
    fn adoption_source(&self) -> Option<AdoptionSource> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match *state {
            State::Detached(conn) => Some(AdoptionSource {
                owner: self.owner,
                listener: self.listener,
                leg: self.leg,
                conn,
            }),
            _ => None,
        }
    }
    fn closing(&self) {
        self.closing();
    }
    fn end(&self) {
        self.end();
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<dyn FramingScope>>> = const { RefCell::new(None) };
}

#[must_use]
pub fn current() -> Option<Arc<dyn FramingScope>> {
    CURRENT.with(|c| c.borrow().clone())
}

pub(crate) struct CurrentGuard {
    previous: Option<Arc<dyn FramingScope>>,
    _thread: PhantomData<Rc<()>>,
}

pub(crate) fn enter(context: Option<Arc<dyn FramingScope>>) -> CurrentGuard {
    CurrentGuard {
        previous: CURRENT.with(|c| c.replace(context)),
        _thread: PhantomData,
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| c.replace(self.previous.take()));
    }
}

pub fn with_context<R>(context: Option<Arc<dyn FramingScope>>, call: impl FnOnce() -> R) -> R {
    let _scope = enter(context);
    call()
}

#[cfg(test)]
#[path = "tests/framing_loan_tests.rs"]
mod loan_tests;

#[cfg(test)]
mod adoption_tests {
    use super::*;
    use crate::dispatch::auth_handle::{
        AuthCallAsk, AuthDone, AuthRan, HandInAsk, RefusalBytes, RefuseAsk, UnitSecret,
    };
    use busbar_contract::abi::host::service::UnitRef;
    use busbar_contract::abi::transport::adopted_session::{AdoptedSession, EXT_ADOPTED_SESSION};

    #[derive(Default)]
    struct Host {
        ended: Mutex<Vec<u64>>,
        confirmed: Mutex<Vec<(u64, u64, u64)>>,
        reject: bool,
    }

    impl AuthHandleHost for Host {
        fn unit_secret(&self, _: u64, _: u64) -> Option<UnitSecret> {
            None
        }
        fn auth_call(&self, _: AuthCallAsk, _: AuthDone) -> AuthRan {
            panic!("adoption never reauthenticates")
        }
        fn hand_in(&self, _: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
            Err("unexpected hand-in")
        }
        fn refuse(&self, _: RefuseAsk) -> Result<RefusalBytes, &'static str> {
            Err("unexpected refusal")
        }
        fn framing_detached(&self, _: u64, _: u64) -> Result<(), &'static str> {
            Ok(())
        }
        fn framing_adopting(
            &self,
            source: AdoptionSource,
            owner: u64,
            _: u64,
        ) -> Result<SessionTransfer, &'static str> {
            assert_eq!((source.owner, source.listener, source.conn), (7, 71, 21));
            assert_eq!(owner, 9);
            assert!(!self.ended.lock().unwrap().contains(&source.leg));
            Ok(SessionTransfer {
                session: AdoptedSession {
                    stream: 41,
                    unit: UnitRef { id: 100, mac: 321 },
                },
                generation: 3,
            })
        }
        fn framing_adopted(&self, owner: u64, leg: u64, conn: u64) -> Result<(), &'static str> {
            if self.reject {
                return Err("source retired before confirmation");
            }
            assert!(
                self.ended.lock().unwrap().is_empty(),
                "confirmation precedes source retirement"
            );
            self.confirmed.lock().unwrap().push((owner, leg, conn));
            Ok(())
        }
        fn framing_ended(&self, leg: u64) {
            self.ended.lock().unwrap().push(leg);
        }
    }

    fn source(host: &Arc<Host>) -> Arc<FramingContext> {
        let host: Arc<dyn AuthHandleHost> = host.clone();
        let source = FramingContext::new(7, 71, 0, Some(Arc::downgrade(&host))).unwrap();
        source.confirm(21).unwrap();
        source.detach().unwrap();
        source
    }

    #[test]
    fn adoption_holds_source_and_input_loan_until_ready_confirms_the_new_token() {
        let host = Arc::new(Host::default());
        let source = source(&host);
        let host_trait: Arc<dyn AuthHandleHost> = host.clone();
        let adopted =
            FramingContext::adopt(9, source.clone(), Some(Arc::downgrade(&host_trait))).unwrap();
        assert_eq!(adopted.connection(), source.connection());
        assert_ne!(adopted.leg(), source.leg());
        assert!(adopted.check(9, 82, false).is_err());
        assert!(adopted.check(9, 82, true).is_err());
        assert!(source.check(7, 21, false).is_err());
        let reply = adopted.operation_reply(Ticket::NONE).unwrap();
        let session = AdoptedSession::decode(
            busbar_contract::abi::mechanism::extensions::get(&reply, EXT_ADOPTED_SESSION).unwrap(),
        )
        .unwrap();
        assert_eq!(session.stream, 41);
        adopted.hold_operation_reply(Ticket::NONE, reply.clone());
        drop(reply);
        assert!(host.ended.lock().unwrap().is_empty());
        assert!(
            adopted.operation_reply(Ticket::NONE).is_some(),
            "a pending crossing keeps its input loan"
        );
        adopted.confirm(82).unwrap();
        assert_eq!(*host.confirmed.lock().unwrap(), [(9, adopted.leg(), 82)]);
        assert_eq!(*host.ended.lock().unwrap(), [source.leg()]);
        assert!(adopted.check(9, 82, false).is_ok());
        assert!(adopted.check(7, 82, false).is_err());
        assert!(adopted.check(9, 21, false).is_err());
        assert_eq!(adopted.policy_generation(41, false), Some(3));
        assert_eq!(adopted.policy_generation(42, false), None);
        adopted.operation_done(Ticket::NONE);
        assert!(adopted.operation_reply(Ticket::NONE).is_none());
        assert!(adopted.confirm(21).is_err());
        let leg = adopted.leg();
        drop(adopted);
        drop(source);
        assert_eq!(host.ended.lock().unwrap().len(), 2);
        assert_eq!(host.ended.lock().unwrap().last(), Some(&leg));
    }

    #[test]
    fn cancelled_or_refused_adoption_retires_both_scopes_once() {
        for reject in [false, true] {
            let host = Arc::new(Host {
                reject,
                ..Host::default()
            });
            let source = source(&host);
            let host_trait: Arc<dyn AuthHandleHost> = host.clone();
            let adopted =
                FramingContext::adopt(9, source.clone(), Some(Arc::downgrade(&host_trait)))
                    .unwrap();
            let leg = adopted.leg();
            if reject {
                assert!(adopted.confirm(82).is_err());
                assert!(adopted.check(9, 82, true).is_err());
            } else {
                adopted.closing();
            }
            drop(adopted);
            assert_eq!(*host.ended.lock().unwrap(), [leg, source.leg()]);
            drop(source);
            assert_eq!(host.ended.lock().unwrap().len(), 2);
            assert!(host.confirmed.lock().unwrap().is_empty());
        }
    }
}
