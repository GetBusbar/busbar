// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Session tickets for ONE listener (TRANSPORT-TLS T1; LINT-RULES R56 `shared-ticketer`, R57
//! `raw-ticketer`).
//!
//! The backend's ticketer never leaves this module. The only way to put facade tickets on a
//! config is [`ListenerTickets::install`], which consumes the value: one `ListenerTickets` is one
//! key domain on exactly one config, so no static, no second listener and no unwrapped ticketer
//! can hold it. The wrapper enforces what rustls does not:
//! - **age** — a ticket is resumed only if this listener sealed it at most [`TICKET_MAX_AGE`] ago
//!   on its own monotonic clock (rustls rotates keys lazily, so an idle listener's old key would
//!   otherwise open an old ticket);
//! - **key failure is never silent** — a seal that fails means resumption is off; it is a WARN on
//!   `busbar::tls::tickets` at once, then at most once a minute with the suppressed count.
//!
//! The raw ticketer is not reachable from outside the facade:
//!
//! ```compile_fail,E0425
//! let _ = busbar_crypto::tls::ticketer();
//! ```
//!
//! and a `ListenerTickets` is not itself a ticketer, so it cannot be shared behind an `Arc`:
//!
//! ```compile_fail,E0277
//! let t = busbar_crypto::tls::ListenerTickets::new("data", || 1).unwrap();
//! let _: std::sync::Arc<dyn rustls::server::ProducesTickets> = std::sync::Arc::new(t);
//! ```

use core::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_crypto_backend as b;
use rustls::server::ProducesTickets;
use rustls::ServerConfig;
use zeroize::Zeroize;

use super::{refused, TlsRefused};

/// The longest a ticket resumes after this listener sealed it. Advertised as the ticket lifetime
/// and enforced on every open.
pub const TICKET_MAX_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// Least time between two key-failure warnings of one listener.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// One listener's session tickets: the backend's ticketer behind this listener's own key domain,
/// age bound and failure warning. Not `Clone`; [`install`](Self::install) consumes it.
pub struct ListenerTickets(Sealed<Host>);

impl ListenerTickets {
    /// Fresh ticket keys for the listener named `listener` (the label its warnings carry).
    ///
    /// `now_ns` is the host's shared monotonic clock in nanoseconds (core's is
    /// `busbar_core_connector::framer::now_ns`): the facade reads no OS clock of its own, and each
    /// seal or open takes one reading of it.
    pub fn new(listener: &str, now_ns: fn() -> u64) -> Result<Self, TlsRefused> {
        let inner = b::ticketer().map_err(refused)?;
        Ok(Self(Sealed::new(inner, listener, Host(now_ns))))
    }

    /// Make these the tickets of `config`, and of no other config.
    pub fn install(self, config: &mut ServerConfig) {
        config.ticketer = Arc::new(self.0);
    }
}

impl fmt::Debug for ListenerTickets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerTickets")
            .field("listener", &self.0.label)
            .finish_non_exhaustive()
    }
}

/// Where a listener's tickets read the time, in monotonic nanoseconds. Production reads the
/// host's shared clock the caller lent; tests move a manual one.
trait Clock: Send + Sync + 'static {
    fn now_ns(&self) -> u64;
}

/// The host's shared monotonic clock, as [`ListenerTickets::new`] was given it.
struct Host(fn() -> u64);

impl Clock for Host {
    fn now_ns(&self) -> u64 {
        (self.0)()
    }
}

/// The installed ticketer. Private: only [`ListenerTickets::install`] builds the `Arc` rustls
/// holds.
struct Sealed<C: Clock> {
    inner: Arc<dyn ProducesTickets>,
    label: Box<str>,
    clock: C,
    /// This listener's epoch (a clock reading): a ticket carries its seal time as whole seconds
    /// since `born`.
    born: u64,
    failing: AtomicBool,
    /// Seconds since `born` of the last warning, plus one (0: never warned).
    warned_at: AtomicU64,
    suppressed: AtomicU64,
}

impl<C: Clock> Sealed<C> {
    fn new(inner: Arc<dyn ProducesTickets>, label: &str, clock: C) -> Self {
        let born = clock.now_ns();
        Self {
            inner,
            label: label.into(),
            clock,
            born,
            failing: AtomicBool::new(false),
            warned_at: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    fn age(&self) -> Duration {
        Duration::from_nanos(self.clock.now_ns().saturating_sub(self.born))
    }

    /// The seal time a ticket carries: whole seconds since `born`, saturating.
    fn stamp(&self) -> u32 {
        u32::try_from(self.age().as_secs()).unwrap_or(u32::MAX)
    }

    fn key_failure(&self) {
        self.failing.store(true, Ordering::Relaxed);
        let now = self.age().as_secs() + 1;
        let last = self.warned_at.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < WARN_EVERY.as_secs() {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self
            .warned_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let suppressed = self.suppressed.swap(0, Ordering::Relaxed);
        tracing::warn!(
            target: "busbar::tls::tickets",
            listener = &*self.label,
            suppressed,
            "TLS session tickets are failing; resumption is off until the key recovers"
        );
    }

    fn recovered(&self) {
        if self.failing.swap(false, Ordering::Relaxed) {
            tracing::info!(
                target: "busbar::tls::tickets",
                listener = &*self.label,
                "TLS session tickets recovered"
            );
        }
    }
}

impl<C: Clock> fmt::Debug for Sealed<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerTickets")
            .field("listener", &self.label)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> ProducesTickets for Sealed<C> {
    fn supports_bounded_output(&self) -> bool {
        self.inner.supports_bounded_output()
    }

    fn encrypt_bounded(
        &self,
        plain: &[u8],
        storage: &rustls::TicketStorage<'_>,
    ) -> Result<Option<rustls::TicketBuffer>, rustls::OutputStorageError> {
        if !self.inner.supports_bounded_output() {
            return Err(rustls::OutputStorageError::UnsupportedProvider);
        }
        let size = plain
            .len()
            .checked_add(4)
            .ok_or(rustls::OutputStorageError::Limit)?;
        let mut stamped = storage.allocate(size)?;
        stamped.extend_from_slice(&self.stamp().to_be_bytes())?;
        stamped.extend_from_slice(plain)?;
        let result = self.inner.encrypt_bounded(stamped.as_ref(), storage);
        // The move-only buffer also wipes on Drop, including every earlier error path.
        stamped.as_mut().zeroize();
        drop(stamped);
        match result? {
            Some(ticket) => {
                self.recovered();
                Ok(Some(ticket))
            }
            None => {
                self.key_failure();
                Ok(None)
            }
        }
    }

    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        TICKET_MAX_AGE.as_secs() as u32
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        // The seal time rides inside the AEAD, so it is authenticated with the session.
        let mut stamped = Vec::with_capacity(4 + plain.len());
        stamped.extend_from_slice(&self.stamp().to_be_bytes());
        stamped.extend_from_slice(plain);
        let sealed = self.inner.encrypt(&stamped);
        stamped.as_mut_slice().zeroize();
        match sealed {
            Some(ticket) => {
                self.recovered();
                Some(ticket)
            }
            None => {
                self.key_failure();
                None
            }
        }
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        // A foreign, forged or expired-key ticket opens nothing: routine, never an event.
        let mut opened = self.inner.decrypt(ticket)?;
        let fresh = opened.first_chunk::<4>().is_some_and(|stamp| {
            let sealed = u64::from(u32::from_be_bytes(*stamp));
            let now = self.age().as_secs();
            sealed <= now && now - sealed <= TICKET_MAX_AGE.as_secs()
        });
        if !fresh {
            opened.as_mut_slice().zeroize();
            return None;
        }
        opened.drain(..4);
        Some(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock the test moves.
    #[derive(Clone)]
    struct Manual(Arc<AtomicU64>);

    impl Manual {
        fn new() -> Self {
            Self(Arc::new(AtomicU64::new(1)))
        }
        fn advance(&self, by: Duration) {
            let by = u64::try_from(by.as_nanos()).unwrap();
            self.0.fetch_add(by, Ordering::Relaxed);
        }
    }

    impl Clock for Manual {
        fn now_ns(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// A fixed-key inner that never rotates: it opens anything it sealed at any age, so only the
    /// wrapper's age check can refuse an old ticket. `fail` makes every seal fail.
    #[derive(Debug, Default)]
    struct Fixed {
        fail: AtomicBool,
    }

    impl ProducesTickets for Fixed {
        fn enabled(&self) -> bool {
            true
        }
        fn lifetime(&self) -> u32 {
            3 * 60 * 60
        }
        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            if self.fail.load(Ordering::Relaxed) {
                return None;
            }
            let mut ticket = Vec::with_capacity(2 + plain.len());
            ticket.extend_from_slice(b"K1");
            ticket.extend_from_slice(plain);
            Some(ticket)
        }
        fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
            ticket.strip_prefix(b"K1").map(|rest| {
                let mut plain = Vec::with_capacity(rest.len());
                plain.extend_from_slice(rest);
                plain
            })
        }
    }

    fn sealed(clock: &Manual) -> (Arc<Fixed>, Sealed<Manual>) {
        let inner = Arc::new(Fixed::default());
        let t = Sealed::new(inner.clone(), "data", clock.clone());
        (inner, t)
    }

    #[test]
    fn a_ticket_resumes_up_to_six_hours_and_not_one_second_more() {
        let clock = Manual::new();
        let (_, t) = sealed(&clock);
        let ticket = t.encrypt(b"session").unwrap();
        assert_eq!(t.decrypt(&ticket).as_deref(), Some(&b"session"[..]));
        clock.advance(TICKET_MAX_AGE);
        assert_eq!(t.decrypt(&ticket).as_deref(), Some(&b"session"[..]));
        clock.advance(Duration::from_secs(1));
        assert_eq!(t.decrypt(&ticket), None);
    }

    #[test]
    fn an_idle_listener_never_resumes_a_ticket_older_than_six_hours() {
        let clock = Manual::new();
        let (_, t) = sealed(&clock);
        clock.advance(Duration::from_secs(3 * 60 * 60 + 61));
        let ticket = t.encrypt(b"session").unwrap();
        clock.advance(TICKET_MAX_AGE + Duration::from_secs(1));
        assert_eq!(t.decrypt(&ticket), None);
    }

    #[test]
    fn the_advertised_lifetime_is_the_enforced_one() {
        let clock = Manual::new();
        let (_, t) = sealed(&clock);
        assert_eq!(u64::from(t.lifetime()), TICKET_MAX_AGE.as_secs());
    }

    #[test]
    fn a_ticket_from_another_key_domain_opens_nothing() {
        let clock = Manual::new();
        let (_, t) = sealed(&clock);
        assert_eq!(t.decrypt(b"K2-another-listener"), None);
        assert_eq!(t.decrypt(b"K1"), None, "a ticket too short for a stamp");
    }

    #[test]
    fn a_key_failure_warns_at_once_then_once_a_minute() {
        let clock = Manual::new();
        let (inner, t) = sealed(&clock);
        inner.fail.store(true, Ordering::Relaxed);
        assert_eq!(t.encrypt(b"session"), None);
        assert!(t.failing.load(Ordering::Relaxed));
        assert_eq!(t.warned_at.load(Ordering::Relaxed), 1, "warned at once");
        assert_eq!(t.encrypt(b"session"), None);
        assert_eq!(t.suppressed.load(Ordering::Relaxed), 1, "inside the minute");
        clock.advance(WARN_EVERY);
        assert_eq!(t.encrypt(b"session"), None);
        assert_eq!(t.warned_at.load(Ordering::Relaxed), 61, "warned again");
        assert_eq!(
            t.suppressed.load(Ordering::Relaxed),
            0,
            "the count went out"
        );
        inner.fail.store(false, Ordering::Relaxed);
        assert!(t.encrypt(b"session").is_some());
        assert!(!t.failing.load(Ordering::Relaxed), "recovered");
    }
}

#[cfg(test)]
#[path = "tickets_funded_tests.rs"]
mod funded_tests;
