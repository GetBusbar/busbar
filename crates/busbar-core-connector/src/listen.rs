// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LISTEN: the host's own listening socket for the root's binds. Each socket it admits under the
//! listener's cap is handed up whole to the kernel's serving loop; nothing here reads or writes it.

use std::future::Future;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::io::{self as reactor, Registered};
use crate::socket;

/// A listener's connection cap when its settings name none (new in 1.6.0).
pub const DEFAULT_MAX_CONNS: usize = 1024;

/// A TLS handshake's bound when its settings name none: 1.5.5's `limits.tls_handshake_timeout_secs`
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 1.5.5's accept-error backoff, on backon: 5 ms doubling to a 250 ms cap, no jitter, no retry
/// limit. `next_delay` answers `None` (retry now) for an aborted or interrupted accept, which also
/// starts the sequence over, and the next delay for anything else (fd exhaustion and the like).
/// The root listener and the connector's `Listening` share this one.
#[derive(Debug, Default)]
pub struct AcceptBackoff(Option<backon::ExponentialBackoff>);

impl AcceptBackoff {
    /// The first delay.
    pub const FIRST: Duration = Duration::from_millis(5);
    /// The cap.
    pub const CAP: Duration = Duration::from_millis(250);
    const DELAYS: backon::ExponentialBuilder = backon::ExponentialBuilder::new()
        .with_min_delay(Self::FIRST)
        .with_max_delay(Self::CAP)
        .without_max_times();

    /// Start the sequence over (an accept succeeded).
    pub fn reset(&mut self) {
        self.0 = None;
    }

    /// `None` = retry now; otherwise how long to wait before accepting again.
    pub fn next_delay(&mut self, e: &std::io::Error) -> Option<Duration> {
        use backon::BackoffBuilder as _;
        if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
        ) {
            self.0 = None;
            return None;
        }
        self.0.get_or_insert_with(|| Self::DELAYS.build()).next()
    }
}

/// The bounds one listener keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptLimits {
    /// The most connections held at once.
    pub max_conns: usize,
    /// The bound on a TLS handshake.
    pub handshake_timeout: Duration,
}

impl Default for AcceptLimits {
    fn default() -> Self {
        Self {
            max_conns: DEFAULT_MAX_CONNS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

/// One of a listener's connection slots, held by the connection it admitted and freed on drop.
#[derive(Debug)]
pub struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// Take a slot of `live` when fewer than `max` are held; `None` = the listener is full.
    // `fetch_update`, not `try_update`: this crate's MSRV floor predates `try_update`. (The
    // toolchain this tree builds with raises no deprecation on it, so nothing is allowed here.)
    #[must_use]
    pub fn take(live: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        live.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(live)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// ONE CONNECTION AN INBOUND LISTENER ADMITTED: the accepted socket, not yet on any worker's reactor
pub struct Admitted {
    /// The accepted socket, non-blocking.
    pub stream: std::net::TcpStream,
    /// The far end.
    pub peer: SocketAddr,
    /// Held for as long as the connection is served.
    pub hold: Option<Box<dyn Send>>,
}

/// AN INBOUND LISTENER, as the accept loop drains it: the next admitted connection. Accept errors,
pub trait Admits: Send {
    /// The next admitted connection.
    fn admit(&mut self) -> impl Future<Output = Admitted> + Send + '_;
}

/// The root's stream listener as the root's accept source (`busbar::root::listener`): each
/// admitted socket is handed up with the slot it holds.
impl Admits for Listening {
    async fn admit(&mut self) -> Admitted {
        let (stream, peer, slot) = futures::future::poll_fn(|cx| self.poll_accept_stream(cx)).await;
        Admitted {
            stream,
            peer,
            hold: Some(Box::new(slot)),
        }
    }
}

/// One STREAM listener: the host's own listening socket on the calling worker's reactor, its cap
/// and its accept backoff.
pub struct Listening {
    sock: Registered<TcpListener>,
    local: SocketAddr,
    max_conns: usize,
    live: Arc<AtomicUsize>,
    backoff: AcceptBackoff,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listening")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Listening {
    /// A STREAM LISTENER, for the root's own binds: `bind` (`ip:port`) on the calling worker's
    /// reactor, address and port reused.
    pub fn bind_stream(bind: &str, limits: AcceptLimits) -> std::io::Result<Self> {
        let l = socket::listen(bind)?;
        let local = l.local_addr()?;
        Ok(Self {
            sock: reactor::register(l)?,
            local,
            max_conns: limits.max_conns,
            live: Arc::new(AtomicUsize::new(0)),
            backoff: AcceptBackoff::default(),
            sleep: None,
        })
    }

    /// The address bound.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// How many connections this listener holds now.
    #[must_use]
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// The next admitted socket, as it arrived, non-blocking: one past the cap is accepted and
    /// closed at once, no byte read or written.
    pub(crate) fn poll_accept_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(TcpStream, SocketAddr, Slot)> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                std::task::ready!(sleep.as_mut().poll(cx));
                self.sleep = None;
            }
            match std::task::ready!(self.sock.poll_accept(cx)) {
                Ok((stream, peer)) => {
                    self.backoff.reset();
                    let Some(slot) = Slot::take(&self.live, self.max_conns) else {
                        drop(stream);
                        continue;
                    };
                    if stream.set_nonblocking(true).is_ok() {
                        return Poll::Ready((stream, peer, slot));
                    }
                }
                Err(e) => {
                    if let Some(d) = self.next_delay(&e) {
                        self.sleep = Some(Box::pin(tokio::time::sleep(d)));
                    }
                }
            }
        }
    }

    /// The listener's [`AcceptBackoff`]: `None` = retry now.
    fn next_delay(&mut self, e: &std::io::Error) -> Option<Duration> {
        self.backoff.next_delay(e)
    }
}

#[cfg(test)]
#[path = "tests/listen_tests.rs"]
mod tests;
