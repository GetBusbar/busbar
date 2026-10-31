// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned framing identity, independent of operation tickets.

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

/// A service did not belong to the live framing that crossed the plugin.
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

/// One host framing leg. Jobs may retain it after logical end without retaining authority.
pub struct FramingContext {
    owner: u64,
    listener: u64,
    connection: u64,
    leg: u64,
    state: Mutex<State>,
    host: Option<Weak<dyn AuthHandleHost>>,
    opening: Option<StreamPolicy>,
    inherited: Option<SessionTransfer>,
    adoption_reply: Option<Arc<[u8]>>,
    source: Mutex<Option<Arc<dyn FramingScope>>>,
    streams: Mutex<HashMap<u64, StreamPolicy>>,
    ended_streams: Mutex<HashSet<u64>>,
    replies: Mutex<HashMap<Ticket, Arc<[u8]>>>,
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
    /// Create a leg for the actual loaded owner and registered listener. `connection == 0`
    /// starts a physical connection; a host-authorized adoption retains its prior incarnation.
    ///
    /// # Errors
    /// A missing owner or an exhausted host identity space.
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
            host,
            opening,
            inherited: None,
            adoption_reply: None,
            source: Mutex::default(),
            streams: Mutex::default(),
            ended_streams: Mutex::default(),
            replies: Mutex::default(),
        }))
    }

    /// Stage a detached source's admitted session for this destination owner.
    /// The original listener registration remains the source's; it is not looked up under
    /// the adopting owner. No ordinary service is permitted before READY confirmation.
    ///
    /// # Errors
    /// An unsealed source, missing admission, or unavailable destination identity.
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
            host,
            opening: None,
            inherited,
            adoption_reply,
            source: Mutex::new(Some(source)),
            streams: Mutex::default(),
            ended_streams: Mutex::default(),
            replies: Mutex::default(),
        }))
    }

    /// The actual loaded plugin owner.
    #[must_use]
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// The listener registration, assigned by the host before acceptance.
    #[must_use]
    pub fn listener(&self) -> u64 {
        self.listener
    }

    /// The physical connection incarnation, retained across authorized adoption.
    #[must_use]
    pub fn connection(&self) -> u64 {
        self.connection
    }

    /// The framing leg incarnation, never an operation ticket or plugin-local token.
    #[must_use]
    pub fn leg(&self) -> u64 {
        self.leg
    }

    /// Check the calling owner and local token. Opening services may provisionally name the
    /// token; only a READY opening confirms it. Closing permits teardown services alone.
    ///
    /// # Errors
    /// A foreign owner, inconsistent token, ended leg, or ordinary service during closing.
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

    /// Confirm the token returned by a READY Begin/Adopt, including any provisional claim.
    ///
    /// # Errors
    /// An inconsistent/zero token or a leg no longer opening.
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

    /// Seal a confirmed source without releasing its admitted request.
    ///
    /// # Errors
    /// The source is not ready or was retired during detachment.
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

    /// Stop admitting ordinary work before cancellation and the final Finish crossing.
    pub fn closing(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = match *state {
            State::Opening(token) => State::Closing(token),
            State::Confirming(token) => State::Closing(Some(token)),
            State::Ready(token) => State::Closing(Some(token)),
            other => other,
        };
    }

    /// End authority exactly once. The owner calls this independently of ticket/Arc disposal;
    /// notification occurs after releasing the state lock.
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
        let loan = streams.entry(open.stream).or_insert(loan);
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
    fn stream_ended(&self, stream: u64) {
        let loan = {
            let _state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
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

/// The framing explicitly installed for this crossing, captured into owned worker metadata
/// before submission and reinstalled on its worker/FFI thread.
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

/// Install owned context for a synchronous crossing/submission and restore the prior scope.
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
