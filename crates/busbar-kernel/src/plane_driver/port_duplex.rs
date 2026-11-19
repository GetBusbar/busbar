// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MESSAGE SESSION AFTER AN UPGRADE (IF §8.6 MSG, UP_MSG; §12.27 steps 4 and 5; owner decision 18).
//!
//! An upgrade request is an ordinary forwarded session until its plane commits: the plane answers its
//! `request` with FORWARD, core walks the members and dials the member's WebSocket ride, and the far end's
//! handshake answer is fed back as `piece(FROM_UPSTREAM, P_HEAD)`. A far end that refuses the handshake is
//! an attempt verdict like any other (the walk moves on, or ends exhausted with an ordinary HTTP answer).
//! Only an answer that carries RESPOND(101) commits: the caller gets its 101 and, from that answer on, this
//! file relays ([`relay`]).
//!
//! The relay never carries a frame from one socket to the other by itself. Every message goes through the
//! plane, which is what meters it:
//!
//! * a caller's message is `piece(FROM_CLIENT, 0, P_TEXT | P_BINARY [| P_FIN])`;
//! * a far end's message is `piece(FROM_UPSTREAM, 0, P_TEXT | P_BINARY [| P_FIN])`;
//! * the plane's MSG items go to the caller, its UP_MSG items to the far end, in the order it wrote them;
//! * the plane's WAKE_AT is answered with `piece(FROM_CORE, 0, P_TIMER)`;
//! * the caller's close is `piece(FROM_CLIENT, 0, P_END)`, a caller that went away without closing is
//!   `piece(FROM_CORE, 0, P_CLIENT_GONE)`, the far end's close is `piece(FROM_UPSTREAM, 0, P_END)` and a
//!   far end that failed is `piece(FROM_UPSTREAM, 0, P_ERROR)` with one REFUSAL (502).
//!
//! MONEY. The unit was opened and its money admitted before the plane's FORWARD was walked (the pending
//! admission of the request, exactly as for a data request), so nothing here admits anything. Every answer's
//! USAGE is the session's running total ([`Task::usage`]); it is shown to the effects after every answer
//! ([`Effects::observed_usage`]), so a unit cut at any point settles on what was stated up to then. The relay
//! returns on EVERY exit: the plane's FINISH, both sides closed, the caller gone, a plane call that failed.
//! Its caller ([`super::port_upstream::run_attempts`] under [`super::port_serve`]) then ends the session and
//! books it, on the error path too.
//!
//! What the relay refuses: a message for the far end after the far end closed is dropped (the session is
//! ending); UP_BODY on a message exchange is the plane's breach ([`Violation::BadRecords`]).

use std::collections::VecDeque;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_plugin_abi::fail::refused::R_NO_ROUTE;
use busbar_plugin_abi::plane::{
    FROM_CLIENT, FROM_CORE, FROM_UPSTREAM, MSG_BINARY, MSG_FIN, MSG_TEXT, P_BINARY, P_CLIENT_GONE,
    P_END, P_ERROR, P_FIN, P_TEXT, P_TIMER,
};
use busbar_plugin_abi::records::Reply;
use busbar_ports::codec::plane::encode_refusal;

use super::port_session::{
    hand_out, Answer, Calls, Effects, SessionError, Task, ToClient, Violation,
};
use super::port_upstream::{SendFailed, UpChunks};

/// The status that commits an upgrade (RFC 6455 section 4.2.2).
pub const SWITCHING_PROTOCOLS: u16 = 101;

/// The text of the REFUSAL a far end that failed mid-session is told to the plane with.
const UPSTREAM_FAILED: &str = "the upstream failed before the session ended";

/// What the caller's side of an upgraded session hands the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// One piece of a message: `flags` are the transport's `MSG_TEXT` or `MSG_BINARY` on every piece of the
    /// message and `MSG_FIN` on its last.
    Message { flags: u32, bytes: Vec<u8> },
    /// The caller closed the session in order (its close frame arrived).
    Closed,
    /// The caller is gone without closing: its connection dropped, it reset the stream, or the engine cut it.
    Gone,
}

/// Why an upgraded session ends when the end is not the plane's own orderly one. The caller's side maps it
/// to the close it writes (a close code on a WebSocket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The far end failed (its connection, its deadline) after the 101.
    UpstreamFailed,
}

/// The caller's side of an upgraded session, as the relay reads it. The listener's hand-over implements it
/// (the adopted transport session feeds it); a test implements it over a script.
pub trait ClientMessages: Send + Sync {
    /// The next thing the caller did. `Pending` (with `cx`'s waker kept) while it did nothing. After `Closed`
    /// or `Gone` it is not polled again. Cancel-safe: a poll that returned `Pending` took nothing.
    fn poll_message(&self, cx: &mut Context<'_>) -> Poll<ClientEvent>;

    /// The session is ending for `cause`; told before the END item that follows it is handed over.
    fn ending(&self, cause: Ending) {
        let _ = cause;
    }
}

/// One message piece of the far end: `flags` are `MSG_TEXT` or `MSG_BINARY`, with `MSG_FIN` on the last piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpMessage {
    pub flags: u32,
    pub bytes: Vec<u8>,
}

/// The transport's message flags as the piece flags the plane is handed (IF §8.6: the same three facts).
#[must_use]
pub const fn piece_flags(message: u32) -> u32 {
    let mut flags = 0;
    if message & MSG_TEXT != 0 {
        flags |= P_TEXT;
    }
    if message & MSG_BINARY != 0 {
        flags |= P_BINARY;
    }
    if message & MSG_FIN != 0 {
        flags |= P_FIN;
    }
    // A piece that states no kind is bytes: a message is never handed to a plane as a non-message piece.
    if flags & (P_TEXT | P_BINARY) == 0 {
        flags |= P_BINARY;
    }
    flags
}

/// What the answers of a forwarded session asked of its message exchange, gathered by
/// [`super::port_upstream`]'s feed from the first answer on: an ordinary session gathers nothing.
#[derive(Debug, Default)]
pub(super) struct Asked {
    /// UP_MSG items for the far end, in answer order.
    pub(super) to_upstream: Vec<(u32, Vec<u8>)>,
    /// UP_END or UP_CUT: the far end's side is closed after `to_upstream`.
    pub(super) up_end: bool,
    /// FINISH.
    pub(super) finish: bool,
    /// The last WAKE_AT.
    pub(super) wake_at: Option<u64>,
    /// An answer carried RESPOND(101): the upgrade is committed.
    pub(super) switched: bool,
    /// An answer carried END for the caller.
    pub(super) client_end: bool,
    /// The plane wrote body bytes on the message exchange.
    pub(super) breach: bool,
}

impl Asked {
    /// Takes the message-exchange items out of `answer` (its client items stay: the caller hands them out).
    pub(super) fn take(&mut self, answer: &mut Answer) {
        for item in &answer.client {
            match item {
                ToClient::Head { status, .. } if *status == SWITCHING_PROTOCOLS => {
                    self.switched = true;
                }
                ToClient::End => self.client_end = true,
                _ => {}
            }
        }
        for exchange in answer.exchanges.iter_mut().filter(|e| e.id == 0) {
            // After the commit an exchange item is a message, its end or nothing: a body is not a message.
            if self.switched && !exchange.body.is_empty() {
                self.breach = true;
            }
            self.to_upstream.append(&mut exchange.msgs);
            self.up_end |= exchange.end || exchange.cut;
        }
        self.finish |= answer.finish;
        if answer.wake_at.is_some() {
            self.wake_at = answer.wake_at;
        }
    }
}

/// How the relay ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Relayed {
    /// The caller went away (the far end is let go; nothing more is wanted).
    pub(super) gone: bool,
}

enum Event {
    Client(ClientEvent),
    Up(Result<Option<UpMessage>, SendFailed>),
    Timer,
}

struct Relay<'a, R> {
    rest: &'a mut R,
    client: &'a dyn ClientMessages,
    effects: &'a dyn Effects,
    /// The far end still takes and gives messages.
    up_open: bool,
    /// The caller has not closed and is not gone.
    client_open: bool,
    gone: bool,
    /// The far end's failure was told to the plane (once).
    up_failed: bool,
    finished: bool,
    wake_at: Option<u64>,
    /// A message for the far end in pieces: gathered until its last piece, then written whole.
    partial: Option<(u32, Vec<u8>)>,
    /// What the relay itself owes the plane before it waits again.
    owed: VecDeque<Event>,
}

impl<R: UpChunks> Relay<'_, R> {
    fn done(&self) -> bool {
        self.finished || self.gone || (!self.up_open && !self.client_open && self.owed.is_empty())
    }

    /// The far end's side is closed by the engine (its close frame goes out); nothing is read after it.
    async fn close_up(&mut self) {
        if self.up_open {
            self.up_open = false;
            self.partial = None;
            self.rest.close().await;
        }
    }

    /// One answer's message-exchange items and client items, applied in the plane's order: the caller's
    /// items first (they were written before the far end's in every answer the plane writes), then the far
    /// end's messages, then its end.
    async fn apply<K: Calls + ?Sized>(
        &mut self,
        task: &Task<'_, K>,
        mut answer: Answer,
    ) -> Result<(), SessionError> {
        let mut asked = Asked {
            switched: true,
            ..Asked::default()
        };
        asked.take(&mut answer);
        if asked.breach {
            return Err(SessionError::Violation(Violation::BadRecords));
        }
        self.effects.observed_usage(task.usage());
        if !self.gone
            && !answer.client.is_empty()
            && !hand_out(self.effects, &mut answer.client).await
        {
            // The caller's side took nothing more: it is gone. The plane is told once, and the far end is
            // let go.
            if self.client_open {
                self.client_open = false;
                self.owed.push_back(Event::Client(ClientEvent::Gone));
            }
        }
        if asked.client_end {
            self.client_open = false;
        }
        for (flags, bytes) in asked.to_upstream {
            if !self.up_open {
                // The session is ending: a message for a far end that closed has nowhere to go.
                continue;
            }
            let (kind, mut whole) = self.partial.take().unwrap_or((flags, Vec::new()));
            if whole.is_empty() {
                whole = bytes;
            } else {
                whole.extend_from_slice(&bytes);
            }
            if flags & MSG_FIN == 0 {
                self.partial = Some((kind, whole));
                continue;
            }
            let kind = (kind & (MSG_TEXT | MSG_BINARY)) | MSG_FIN;
            if !self.rest.write_message(kind, whole).await {
                self.up_open = false;
                self.partial = None;
                self.owed.push_back(Event::Up(Err(SendFailed)));
                break;
            }
        }
        if asked.up_end {
            self.close_up().await;
        }
        if asked.wake_at.is_some() {
            self.wake_at = asked.wake_at;
        }
        self.finished |= asked.finish;
        Ok(())
    }

    /// The next thing either side did, or the plane's wake time.
    async fn wait(&mut self) -> Event {
        if let Some(owed) = self.owed.pop_front() {
            return owed;
        }
        let client = self.client;
        let client_open = self.client_open;
        let up_open = self.up_open;
        let wake_at = self.wake_at;
        let rest = &mut *self.rest;
        let caller = async {
            if client_open {
                Event::Client(std::future::poll_fn(|cx| client.poll_message(cx)).await)
            } else {
                std::future::pending::<Event>().await
            }
        };
        let far = async {
            if up_open {
                Event::Up(rest.next_message().await)
            } else {
                std::future::pending::<Event>().await
            }
        };
        let timer = async {
            match wake_at {
                Some(at) => {
                    let now = crate::store::monotonic_ns();
                    tokio::time::sleep(Duration::from_nanos(at.saturating_sub(now))).await;
                    Event::Timer
                }
                None => std::future::pending::<Event>().await,
            }
        };
        tokio::select! {
            event = timer => event,
            event = caller => event,
            event = far => event,
        }
    }
}

/// One REFUSAL(502) for the plane: the far end failed mid-session.
fn upstream_failed() -> Result<Reply, SessionError> {
    let mut refusal = Reply::new();
    encode_refusal(&mut refusal, 502, R_NO_ROUTE, UPSTREAM_FAILED)
        .map_err(|_| SessionError::Encode)?;
    Ok(refusal)
}

/// Relays one committed upgrade session to its end (see the module docs). `asked` is what the answers up to
/// and including the commit asked of the message exchange; their client items (the 101 among them) were
/// already handed out by the caller. `queued` are the messages the `upstream` answer wrote for the far end
/// before it answered: they go first.
///
/// # Errors
/// A plane call refused, failed or faulted, or the plane wrote a body on its message exchange. The far end
/// is closed before the error is returned.
pub(super) async fn relay<K: Calls + ?Sized, R: UpChunks>(
    task: &mut Task<'_, K>,
    rest: &mut R,
    client: &dyn ClientMessages,
    asked: Asked,
    effects: &dyn Effects,
) -> Result<Relayed, SessionError> {
    let queued = rest.take_queued();
    let mut relay = Relay {
        rest,
        client,
        effects,
        up_open: true,
        client_open: true,
        gone: false,
        up_failed: false,
        finished: false,
        wake_at: None,
        partial: None,
        owed: VecDeque::new(),
    };
    let outcome = async {
        // The commit's own asks, as an answer with no client items left to hand out.
        let mut first = Answer::default();
        if let Some(open) = first_exchange(&mut first) {
            open.msgs = queued;
            open.msgs.extend(asked.to_upstream);
            open.end = asked.up_end;
        }
        first.finish = asked.finish;
        first.wake_at = asked.wake_at;
        if asked.breach {
            return Err(SessionError::Violation(Violation::BadRecords));
        }
        if asked.client_end {
            // The plane ended the caller's side in the very answer that committed it.
            relay.client_open = false;
        }
        relay.apply(task, first).await?;
        while !relay.done() {
            let answer = match relay.wait().await {
                Event::Client(ClientEvent::Message { flags, bytes }) => {
                    task.piece(FROM_CLIENT, 0, piece_flags(flags), &bytes, effects)?
                }
                Event::Client(ClientEvent::Closed) => {
                    relay.client_open = false;
                    task.piece(FROM_CLIENT, 0, P_END, &[], effects)?
                }
                Event::Client(ClientEvent::Gone) => {
                    relay.client_open = false;
                    relay.gone = true;
                    task.piece(FROM_CORE, 0, P_CLIENT_GONE, &[], effects)?
                }
                Event::Up(Ok(Some(message))) => task.piece(
                    FROM_UPSTREAM,
                    0,
                    piece_flags(message.flags),
                    &message.bytes,
                    effects,
                )?,
                Event::Up(Ok(None)) => {
                    relay.up_open = false;
                    task.piece(FROM_UPSTREAM, 0, P_END, &[], effects)?
                }
                Event::Up(Err(SendFailed)) => {
                    relay.up_open = false;
                    if relay.up_failed {
                        continue;
                    }
                    relay.up_failed = true;
                    // The caller's close says so: this is not the plane's orderly end.
                    client.ending(Ending::UpstreamFailed);
                    let refusal = upstream_failed()?;
                    task.piece(FROM_UPSTREAM, 0, P_ERROR, refusal.as_bytes(), effects)?
                }
                Event::Timer => {
                    relay.wake_at = None;
                    task.piece(FROM_CORE, 0, P_TIMER, &[], effects)?
                }
            };
            relay.apply(task, answer).await?;
        }
        Ok(())
    }
    .await;
    // Every exit lets the far end go: its close frame when it is still open, nothing when it already ended.
    relay.close_up().await;
    effects.observed_usage(task.usage());
    outcome.map(|()| Relayed { gone: relay.gone })
}

/// The exchange 0 of an answer the relay builds for the commit's own asks.
fn first_exchange(answer: &mut Answer) -> Option<&mut super::port_session::UpExchange> {
    answer
        .exchanges
        .push(super::port_session::UpExchange::default());
    answer.exchanges.last_mut()
}

#[cfg(test)]
#[path = "tests/port_duplex_tests.rs"]
mod tests;
