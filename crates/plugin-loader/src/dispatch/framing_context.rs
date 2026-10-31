// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned framing identity, independent of operation tickets.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use super::auth_handle::AuthHandleHost;
use busbar_contract::framing_scope::FramingScope;

/// A service did not belong to the live framing that crossed the plugin.
pub const CONTEXT_REFUSED: &str = "the service does not belong to this live host framing";

static NEXT_LEG: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
enum State {
    Opening(Option<u64>),
    Ready(u64),
    Closing(Option<u64>),
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
        Ok(Arc::new(Self {
            owner,
            listener,
            connection: if connection == 0 { leg } else { connection },
            leg,
            state: Mutex::new(State::Opening(None)),
            host,
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
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match *state {
            State::Opening(token) if conn != 0 && token.is_none_or(|t| t == conn) => {
                *state = State::Ready(conn);
                Ok(())
            }
            State::Ready(token) if conn != 0 && token == conn => Ok(()),
            _ => Err(CONTEXT_REFUSED),
        }
    }

    /// Stop admitting ordinary work before cancellation and the final Finish crossing.
    pub fn closing(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = match *state {
            State::Opening(token) => State::Closing(token),
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
        }
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
    fn check(&self, owner: u64, conn: u64, teardown: bool) -> Result<(), &'static str> {
        self.check(owner, conn, teardown)
    }
    fn confirm(&self, conn: u64) -> Result<(), &'static str> {
        self.confirm(conn)
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
