// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE OP'S BODY AS A FUTURE OVER ITS ONE RAW CONNECTION (THE DESIGN, the plugin ABI: every
//! call is Ready or Pending(wake), never a blocking thread; the connections section: the host's
//! connector, no socket of the plugin's own). A store that speaks a wire protocol to a remote
//! backend (a database, a key-value server) writes each op once, as straight-line `async` code
//! over a [`Wire`] ([`Wire::connect`], [`Wire::write_all`], [`Wire::fill`] and
//! [`Wire::upgrade_secure`]), and [`drive`] runs it across the op's entries:
//!
//! * each entry polls the body until it asks the wire for something, then makes that connector
//!   service on the op's ticket ([`Op::checkout`], [`Op::connector`]) and hands the answer back;
//! * a service that answers PENDING parks the body (with its buffers) on the op's ticket and the
//!   op answers PENDING on the connector's wake; the RESUME polls the same body on from where it
//!   stopped, so no request is sent twice and nothing runs afresh;
//! * the body's own failures are its own words: a connector failure reaches it as a
//!   [`ConnFailure`] from the wire call, and the body maps it (`"error connecting to server: …"`).
//!
//! The op's one connection is the SDK's checkout: it is closed when the op answers.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use super::op::{Op, Step};
use crate::abi::sdk::conn::ConnFailure;

/// How much one read asks the connector for.
pub const READ_CHUNK: usize = 16 * 1024;

/// A store op's body, as [`drive`] runs it.
pub type Body<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// What the body asked the wire for, not yet answered.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    Connect { need: u32, target: Option<String> },
    Write,
    Read,
    Upgrade { name: Option<String> },
}

#[derive(Debug, Default)]
struct State {
    ask: Option<Ask>,
    answer: Option<Result<usize, ConnFailure>>,
    stream: Option<u64>,
    /// Bytes the body wrote that the connector has not taken yet.
    out: Vec<u8>,
    /// Bytes read that the body has not consumed yet.
    input: Vec<u8>,
}

/// THE BODY'S WIRE: its one connection's services, each an `async` call [`drive`] answers.
#[derive(Debug, Clone, Default)]
pub struct Wire {
    st: Arc<Mutex<State>>,
}

impl Wire {
    fn state(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ask(&self, ask: Ask) -> Asked<'_> {
        Asked {
            wire: self,
            ask: Some(ask),
        }
    }

    /// Establish the op's one connection: declared need `need` to `target` (`None` = the need's
    /// own target).
    ///
    /// # Errors
    /// The connector's failure (the far end, the egress rules or the need said no).
    pub async fn connect(&self, need: u32, target: Option<&str>) -> Result<(), ConnFailure> {
        self.ask(Ask::Connect {
            need,
            target: target.map(str::to_owned),
        })
        .await
        .map(|_| ())
    }

    /// Write all of `bytes`.
    ///
    /// # Errors
    /// The connector's failure (the connection closed, its deadline passed).
    pub async fn write_all(&self, bytes: &[u8]) -> Result<(), ConnFailure> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.state().out.extend_from_slice(bytes);
        self.ask(Ask::Write).await.map(|_| ())
    }

    /// Read more bytes onto the input ([`Wire::input`]): how many arrived; `0` = the far end
    /// closed the connection.
    ///
    /// # Errors
    /// The connector's failure.
    pub async fn fill(&self) -> Result<usize, ConnFailure> {
        self.ask(Ask::Read).await
    }

    /// Secure the connection from its next byte on (TLS from the first byte, or after the
    /// protocol's own negotiation), offering `name` (`None` = the target's host).
    ///
    /// # Errors
    /// The connector's failure (the handshake or the trust refused).
    pub async fn upgrade_secure(&self, name: Option<&str>) -> Result<(), ConnFailure> {
        self.ask(Ask::Upgrade {
            name: name.map(str::to_owned),
        })
        .await
        .map(|_| ())
    }

    /// The bytes read and not yet consumed, to parse from and drain (a codec consumes a whole
    /// message and leaves the rest).
    pub fn input<R>(&self, f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
        f(&mut self.state().input)
    }
}

/// One wire call: it posts its ask on the first poll and answers when [`drive`] has.
struct Asked<'w> {
    wire: &'w Wire,
    ask: Option<Ask>,
}

impl Future for Asked<'_> {
    type Output = Result<usize, ConnFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut st = self.wire.state();
        if let Some(ask) = self.ask.take() {
            st.ask = Some(ask);
            st.answer = None;
            return Poll::Pending;
        }
        match st.answer.take() {
            Some(a) => Poll::Ready(a),
            None => Poll::Pending,
        }
    }
}

/// What [`drive`] parks on the op's ticket across a PENDING answer.
struct Running<T> {
    body: Mutex<Body<T>>,
    wire: Wire,
}

/// RUN `start`'s body over the op's one connection, across the op's entries: a fresh entry starts
/// it (`start` is called once per op, never on a RESUME), a RESUME polls the parked body on. The
/// op answers the body's output, or PENDING while a connector service is in flight.
///
/// # Panics
/// A RESUME with no body parked (the door answers FAULT: an op never runs afresh on its RESUME), or
/// a body that awaits something other than its [`Wire`] (nothing would wake it).
pub fn drive<T: 'static>(cx: &mut Op<'_>, start: impl FnOnce(Wire) -> Body<T>) -> Step<T> {
    let running = match cx.resume::<Running<T>>() {
        Some(r) => r,
        None if cx.resuming() => {
            panic!("a store op's RESUME found no parked wire body: it is never run afresh")
        }
        None => {
            let wire = Wire::default();
            Running {
                body: Mutex::new(start(wire.clone())),
                wire,
            }
        }
    };
    let waker = Waker::noop();
    let mut poll_cx = Context::from_waker(waker);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let polled = running
            .body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .poll(&mut poll_cx);
        if let Poll::Ready(t) = polled {
            return Step::Ready(t);
        }
        let ask = running.wire.state().ask.clone();
        let Some(ask) = ask else {
            panic!("a store op's wire body awaited something other than its wire");
        };
        let answered = serve(cx, &running.wire, &ask, &mut buf);
        match answered {
            Poll::Ready(a) => {
                let mut st = running.wire.state();
                st.ask = None;
                st.answer = Some(a);
            }
            Poll::Pending => {
                cx.park(running);
                return Step::Pending { wake_at_ns: 0 };
            }
        }
    }
}

/// Make the connector service `ask` names: its answer, or PENDING (the ask stays posted and is
/// made again on the RESUME).
fn serve(
    cx: &mut Op<'_>,
    wire: &Wire,
    ask: &Ask,
    buf: &mut [u8],
) -> Poll<Result<usize, ConnFailure>> {
    if let Ask::Connect { need, target } = ask {
        return match cx.checkout(*need, target.as_deref()) {
            Poll::Ready(Ok(stream)) => {
                wire.state().stream = Some(stream);
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        };
    }
    let Some(stream) = wire.state().stream else {
        return Poll::Ready(Err(ConnFailure::Refused(
            "the store's wire is not connected".into(),
        )));
    };
    let mut services = match cx.connector() {
        Ok(s) => s,
        Err(e) => return Poll::Ready(Err(e)),
    };
    match ask {
        Ask::Connect { .. } => unreachable!("answered above"),
        Ask::Write => loop {
            let out = std::mem::take(&mut wire.state().out);
            let answer = services.write(stream, &out);
            let mut st = wire.state();
            match answer {
                Poll::Ready(Ok(n)) => {
                    let mut out = out;
                    out.drain(..n.min(out.len()));
                    st.out = out;
                    if st.out.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    if n == 0 {
                        return Poll::Ready(Err(ConnFailure::Failed(
                            "the connection took none of the bytes".into(),
                        )));
                    }
                }
                Poll::Ready(Err(e)) => {
                    st.out = out;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    st.out = out;
                    return Poll::Pending;
                }
            }
        },
        Ask::Read => match services.read(stream, buf) {
            Poll::Ready(Ok(n)) => {
                wire.state().input.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            other => other,
        },
        Ask::Upgrade { name } => services
            .upgrade_secure(stream, name.as_deref(), None)
            .map(|r| r.map(|()| 0)),
    }
}
