// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STREAM FRAMED BY ITS CLAIM'S FRAMER, on the data listener (ARCHITECT 4l, 2026-10-05).
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

/// The framer that frames a stream on `carrier`, where one does: the framer answering it, unless
/// that framer is the data listener's own (it answers `data_carrier` too), which frames the
/// connection already.
pub(super) fn stream_framer(
    carrier: &str,
    data_carrier: &str,
    framer_for: impl Fn(&str) -> Option<Arc<dyn FramerDoor>>,
) -> Option<Arc<dyn FramerDoor>> {
    let door = framer_for(carrier)?;
    (!door.facts().claims.contains(&data_carrier)).then_some(door)
}

/// The stream, shared by the unit's caller side and the answer that may refuse it; `None` once
/// it is closed.
pub(super) type Shared = Arc<Mutex<Option<FramedStream>>>;

fn lock(s: &Shared) -> MutexGuard<'_, Option<FramedStream>> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

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
    let block = lock(stream).take().map(|mut s| s.refuse(&body, status));
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
    trailers: Mutex<Option<oneshot::Sender<HeaderMap>>>,
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
            trailers: Mutex::new(Some(trailers)),
        }
    }

    /// Close the stream with the unit's final status: its framer renders the closing block (a
    /// status the claim's numbering does not have is refused before it crosses, and the stream
    /// is closed as a plane fault instead), sent as the answer's trailers.
    fn finish(&self, status: u32, message: &[u8], details: &[u8]) {
        let Some(mut s) = lock(&self.stream).take() else {
            return;
        };
        let block = s
            .finish(status, message, details)
            .or_else(|_| s.refuse(&[], refusal_status(ReasonCode::PlanePanic)));
        let Ok(block) = block else {
            return;
        };
        let sender = self
            .trailers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(sender) = sender {
            let _gone = sender.send(block_head(&block).1);
        }
    }

    /// Frame one reply message's bytes (`ends` = they complete it) and write the body bytes.
    async fn framed(&self, bytes: &[u8], ends: bool) -> bool {
        let wire = match lock(&self.stream).as_mut() {
            Some(s) => s.emit(bytes, ends),
            None => return false,
        };
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
