// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STREAM FRAMED BY ITS CLAIM'S FRAMER, on the data listener.
//!
//! One listener port carries every claim's streams, so the data listener's own framer keeps the
//! connection and each stream's head. A door plane's claim whose carrier another framer answers
//! (the claim the stream resolved to, never a transport this file names) has that framer frame the
//! stream alone ([`FramedStream`], `SIDE_ACCEPT_STREAM`): the request body goes in and comes back
//! as the messages the unit arrives with; each reply message goes in and comes back as the body
//! bytes the listener writes; and the close comes back as the stream's closing field block — the
//! unit's final status rendered by the framer, or a refusal — which the listener sends verbatim:
//! as trailers after a head, or as the whole answer before one. The host renders nothing of the
//! claim's wire.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use busbar_contract::caps::ReasonCode;
use busbar_core_connector::compose::HeadWords;
use busbar_core_connector::framed_stream::FramedStream;
use busbar_core_connector::framer::FramerDoor;
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, Rendered, SessionCaller};
use tokio::sync::oneshot;

use super::{refusal_status, stated, IngressCaller, Stated};

/// The framer that frames a stream on `carrier`, where one does: the framer answering it, when its
/// own claim rows state that `carrier` rides a stream. A claim stating neither is a request and its answer, served on the
/// data listener's own route, which frames the connection already. Judged per claim from the
/// Statement, never by a transport's name.
pub(super) fn stream_framer(
    carrier: &str,
    framer_for: impl Fn(&str) -> Option<Arc<dyn FramerDoor>>,
) -> Option<Arc<dyn FramerDoor>> {
    let door = framer_for(carrier)?;
    // A datagram framer's calls carry the datagram lane: the connector's datagram driver drives
    // it over the host's port, never a stream.
    (!door.facts().datagram && door.facts().duplex.contains(&carrier)).then_some(door)
}

/// The stream, shared by the unit's caller side and the answer that may refuse it.
///
/// ITS FRAMER IS CROSSED WITH NO LOCK HELD (`BUSBAR-1.6.0.md` §11: no plugin code runs under a
/// host lock): a write takes the stream out, has it framed, and puts it back; a close takes it and
/// renders its closing block outside the lock. A close made while a write has it out is handed to
/// that write, which makes it on the way back, so a framer crossing that hangs holds up only the
/// one caller inside it.
pub(super) type Shared = Arc<Mutex<Slot>>;

/// A close handed to the write that has the stream out.
type Close = Box<dyn FnOnce(FramedStream) + Send>;

/// Where the stream is.
pub(super) struct Slot {
    /// The stream while nobody has it out; `None` while a write has it, and once it is closed.
    stream: Option<FramedStream>,
    /// A write has the stream out.
    out: bool,
    /// The close made while it was out, for that write to make.
    then: Option<Close>,
}

/// The stream `stream`, shared.
pub(super) fn shared(stream: FramedStream) -> Shared {
    Arc::new(Mutex::new(Slot {
        stream: Some(stream),
        out: false,
        then: None,
    }))
}

fn lock(s: &Shared) -> MutexGuard<'_, Slot> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// CLOSE the stream with `close`: here, with no lock held; or, while a write has it out, by that
/// write as it puts it back. Nothing once it is closed.
fn close_with(s: &Shared, close: impl FnOnce(FramedStream) + Send + 'static) {
    let mut slot = lock(s);
    if let Some(stream) = slot.stream.take() {
        drop(slot);
        close(stream);
        return;
    }
    if slot.out && slot.then.is_none() {
        slot.then = Some(Box::new(close));
    }
}

/// The closing field block `block` sent as the answer's trailers, once.
fn send_trailers(trailers: &Trailers, block: &[HeadWords]) {
    let sender = trailers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        let _gone = sender.send(block_head(block).1);
    }
}

/// Where the closing block's trailers go, once.
type Trailers = Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>;

/// A closing field block as an answer's head: its `:status` line, where it has one, and its
/// fields (every other line, in order; a line the wire cannot carry is not sent).
pub(super) fn block_head(block: &[HeadWords]) -> (Option<StatusCode>, HeaderMap) {
    let mut status = None;
    let mut headers = HeaderMap::new();
    for (name, value) in block {
        if name.as_slice() == b":status" {
            status = std::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .and_then(|v| StatusCode::from_u16(v).ok());
            continue;
        }
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name), HeaderValue::from_bytes(value)) {
            headers.append(n, v);
        }
    }
    (status, headers)
}

/// The stream ended before the unit stated a head: `rendered` (the unit's refusal or failure, or
/// nothing) closes it through its framer, and the closing block is the whole answer. A framer that
/// will not render it leaves the refusal's own status, with nothing else.
pub(super) fn refused(stream: &Shared, rendered: Option<Rendered>) -> Response {
    let (status, body) = rendered.map_or_else(
        || (refusal_status(ReasonCode::PlanePanic), Vec::new()),
        |r| (r.status, r.body),
    );
    // Taken out first: the framer renders the refusal with no lock held. A stream a write has out
    // (or one already closed) answers the refusal's own status.
    let taken = lock(stream).stream.take();
    let block = taken.map(|mut s| s.refuse(&body, status, false));
    match block {
        Some(Ok(block)) => whole(status, &block),
        _ => stated((status, Vec::new()), Body::empty()),
    }
}

/// An answer that is its closing block alone, under the block's `:status` (else `status`).
pub(super) fn whole(status: u32, block: &[HeadWords]) -> Response {
    let (code, headers) = block_head(block);
    let mut response = stated((status, Vec::new()), Body::empty());
    if let Some(code) = code {
        *response.status_mut() = code;
    }
    response.headers_mut().extend(headers);
    response
}

/// THE CALLER'S SIDE OF A FRAMED STREAM: the listener's own caller side, every reply message
/// framed on its way out and the close rendered by the stream's framer and sent as trailers.
pub(super) struct FramedCaller {
    inner: IngressCaller,
    stream: Shared,
    trailers: Trailers,
}

impl FramedCaller {
    pub(super) fn new(
        inner: IngressCaller,
        stream: Shared,
        trailers: oneshot::Sender<HeaderMap>,
    ) -> Self {
        Self {
            inner,
            stream,
            trailers: Arc::new(Mutex::new(Some(trailers))),
        }
    }

    /// Close the stream with the unit's final status: its framer renders the closing block (a
    /// status the claim's numbering does not have is refused before it crosses, and the stream
    /// is closed as a plane fault instead), sent as the answer's trailers.
    fn finish(&self, status: u32, message: &[u8], details: &[u8]) {
        let head_sent = self.inner.stated().is_some();
        let (message, details) = (message.to_vec(), details.to_vec());
        let trailers = Arc::clone(&self.trailers);
        close_with(&self.stream, move |mut s| {
            let block = s
                .finish(status, &message, &details)
                .or_else(|_| s.refuse(&[], refusal_status(ReasonCode::PlanePanic), head_sent));
            if let Ok(block) = block {
                send_trailers(&trailers, &block);
            }
        });
    }

    /// Frame one reply message's bytes (`ends` = they complete it) and write the body bytes. The
    /// stream is out of its slot while its framer is crossed; a close made meanwhile is made here,
    /// as it is put back.
    async fn framed(&self, bytes: &[u8], ends: bool) -> bool {
        let taken = {
            let mut slot = lock(&self.stream);
            let taken = slot.stream.take();
            slot.out = taken.is_some();
            taken
        };
        let Some(mut s) = taken else {
            return false;
        };
        let wire = s.emit(bytes, ends);
        let close = {
            let mut slot = lock(&self.stream);
            slot.out = false;
            match slot.then.take() {
                Some(close) => Some((close, s)),
                None => {
                    slot.stream = Some(s);
                    None
                }
            }
        };
        if let Some((close, s)) = close {
            close(s);
        }
        match wire {
            Ok(w) if w.is_empty() => true,
            Ok(w) => self.inner.write(&w).await,
            Err(_) => false,
        }
    }
}

impl CallerEnd for FramedCaller {
    /// The unit's head, without a stated length: the framed body is the framer's, not the unit's.
    fn head(&self, status: u32, mut fields: HeadFields) {
        fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
        self.inner.head(status, fields);
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.framed(bytes, true).await
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        self.framed(bytes, true).await
    }

    async fn write_piece(&self, bytes: &[u8], _text: bool, message_end: bool) -> bool {
        if bytes.is_empty() && !message_end {
            return true;
        }
        self.framed(bytes, message_end).await
    }

    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        self.finish(status, message, details);
    }
}

impl SessionCaller for FramedCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        self.inner.read().await
    }
}

impl Stated for FramedCaller {
    fn stated(&self) -> Option<u32> {
        self.inner.stated()
    }

    /// A UNIT CUT OR FAILED AFTER ITS HEAD is told to the client (`BUSBAR-1.6.0.md` §7, "a cut is
    /// told to the client"): its stream closes as a refusal in its claim's own numbering, the
    /// framer mapping the refusal's status ([`refusal_status`] of the unit's reason), never as a
    /// stream that ended whole. A unit that stated its own final status has already closed it.
    fn ended(&self, outcome: Option<busbar_contract::caps::Outcome>) {
        let Some(reason) = outcome.and_then(cut_reason) else {
            return;
        };
        if self.inner.stated().is_none() {
            return;
        }
        let trailers = Arc::clone(&self.trailers);
        close_with(&self.stream, move |mut s| {
            if let Ok(block) = s.refuse(&[], refusal_status(reason), true) {
                send_trailers(&trailers, &block);
            }
        });
    }
}

/// The reason a unit that did not complete was cut for: a refused or failed step's own reason,
/// the node's named reason for a cut, a deadline for a step that ran past it, and the plane's
/// fault for a unit another took over. `None` for a unit that completed.
fn cut_reason(outcome: busbar_contract::caps::Outcome) -> Option<ReasonCode> {
    use busbar_contract::caps::{Abort, Outcome};
    match outcome {
        Outcome::Completed => None,
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => Some(reason),
        Outcome::Aborted(Abort::Kernel { reason }) => Some(reason),
        Outcome::Aborted(_) => Some(ReasonCode::PlanePanic),
        Outcome::TimedOut(_) => Some(ReasonCode::DeadlineExceeded),
    }
}

impl Drop for FramedCaller {
    /// A unit that answered with a head and stated no final status ends its stream with none: the
    /// framer closes it as its claim closes a stream that ended whole (status `0`). A unit that
    /// stated no head leaves the stream to the answer, which refuses it.
    fn drop(&mut self) {
        if self.inner.stated().is_some() {
            self.finish(0, b"", b"");
        }
    }
}

#[cfg(test)]
#[path = "tests/serve_framed_lock.rs"]
mod lock_tests;
