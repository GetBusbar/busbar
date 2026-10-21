// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED DATA DOOR'S ANSWER (`BUSBAR-1.6.0.md` l.475-484, INBOUND-LISTEN; status row 192 C):
//! the ONE place a driven unit's reply is shaped for its caller.
//!
//! A unit states its head once and writes its body piece by piece ([`Reply`] is the handler's end
//! of that). Whether the answer goes out WHOLE (collected and sent under the length of what was
//! written), STREAMED (piece by piece as the unit writes, the unit running on its own task once its
//! head is stated), CLOSED BEFORE ITS BODY (a framer's close rendered before the first byte, sent as
//! one header block), or UNRENDERED (the unit ended with no head) is decided here, by
//! [`Reply::shape`], and nowhere else. What the decision is written to is an [`Answer`] sink: the
//! hyper response the old path serves, or the accepted connection's own emits. Both read one
//! decision, so the bytes either path writes for a unit are the same by construction.

use std::future::Future;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_kernel::plane_driver::{HeadFields, Rendered};
/// The stream `Content-Type` every declared protocol states, folded at boot.
use busbar_kernel::proto::streaming_content_types as declared_stream_media;
use tokio::sync::{mpsc, oneshot};

/// A reply head: the status number and the head fields.
pub(crate) type Head = (u32, HeadFields);

/// A unit the data door drives: what it rendered for its caller when it ended before any byte.
pub type DrivenUnit = std::pin::Pin<Box<dyn Future<Output = Option<Rendered>> + Send>>;

/// The handler's end of a caller side: the reply, once the unit states its head.
#[derive(Debug)]
pub struct Reply {
    pub(crate) head: oneshot::Receiver<Head>,
    pub(crate) body: mpsc::Receiver<Bytes>,
    /// The answer's trailers, where a framer renders a close after its body (ARCHITECT 4l).
    pub(crate) trailers: Option<oneshot::Receiver<HeaderMap>>,
}

/// A STREAMED answer's body as the sink is handed it: the pieces the unit writes, in order; the
/// unit's own task once its head is stated ([`Running`]; `None` when the unit already ended); and
/// the trailers a framer's close renders after the last piece, where the answer has them.
pub(crate) struct Streamed {
    pub(crate) body: mpsc::Receiver<Bytes>,
    pub(crate) running: Option<Running>,
    pub(crate) trailers: Option<oneshot::Receiver<HeaderMap>>,
}

/// WHERE ONE SHAPED ANSWER IS WRITTEN: each arm is one of [`Reply::shape`]'s decisions.
pub(crate) trait Answer: Send {
    /// What writing the answer comes to.
    type Out: Send;
    /// A WHOLE answer: `head` (its stated length taken out) and every byte the unit wrote.
    fn whole(self, head: Head, body: Vec<u8>) -> impl Future<Output = Self::Out> + Send;
    /// A framed answer CLOSED BEFORE ITS FIRST BODY BYTE: `head` and the framer's closing block,
    /// as ONE header block, no body.
    fn closed(self, head: Head, block: HeaderMap) -> impl Future<Output = Self::Out> + Send;
    /// A STREAMED answer: `head`, then the body piece by piece.
    fn streamed(self, head: Head, body: Streamed) -> impl Future<Output = Self::Out> + Send;
    /// The unit ended with NO HEAD: what it rendered (a refusal or failure before any byte), or
    /// nothing.
    fn unrendered(self, rendered: Option<Rendered>) -> impl Future<Output = Self::Out> + Send;
}

impl Reply {
    /// The same reply, its body followed by the trailers `trailers` delivers (a framer's close).
    #[must_use]
    pub fn with_trailers(mut self, trailers: oneshot::Receiver<HeaderMap>) -> Self {
        self.trailers = Some(trailers);
        self
    }

    /// THE UNIT, ANSWERED THROUGH `sink`: `unit` runs here until it states its head, then (a
    /// streamed answer) on its own task, so a caller that goes away drops it (the driver's
    /// client-drop path). The one decision, written to whichever sink serves the caller.
    pub(crate) async fn shape<A: Answer>(self, mut unit: DrivenUnit, sink: A) -> A::Out {
        let Reply {
            mut head,
            body,
            mut trailers,
        } = self;
        let first = tokio::select! {
            biased;
            h = &mut head => Ok(h.ok()),
            rendered = &mut unit => Err(rendered),
        };
        match first {
            // A WHOLE ANSWER goes out whole: an answer whose head states its length (one the plane
            // rendered in full) is collected to its end and sent under the length of what was
            // written, as the previous release sent a buffered answer; any other answer goes out
            // piece by piece as the unit writes it.
            Ok(Some(h)) if whole_answer(&h.1) => {
                let whole = collect(body, unit).await;
                sink.whole(unlengthed(h), whole).await
            }
            // A STREAMED ANSWER: the unit runs on, on its own task, once its head is stated
            // (ARCHITECT ruling 2026-10-07, STREAM-CEILING); the body only drains what it writes.
            // A framed answer already closed before its first body byte goes out whole instead,
            // the unit run to its end.
            Ok(Some(h)) => {
                if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                    let _ = unit.await;
                    return sink.closed(h, block).await;
                }
                let running = Running(tokio::spawn(unit));
                sink.streamed(
                    h,
                    Streamed {
                        body,
                        running: Some(running),
                        trailers,
                    },
                )
                .await
            }
            Ok(None) => {
                let rendered = unit.await;
                sink.unrendered(rendered).await
            }
            Err(rendered) => match head.try_recv() {
                // The unit ended in the poll that stated its head: a whole answer is every piece it
                // wrote, sent under its length.
                Ok(h) if whole_answer(&h.1) => {
                    let mut body = body;
                    let mut whole = Vec::new();
                    while let Ok(bytes) = body.try_recv() {
                        whole.extend_from_slice(&bytes);
                    }
                    sink.whole(unlengthed(h), whole).await
                }
                Ok(h) => {
                    if let Some(block) = closed_before_body(&body, trailers.as_mut()) {
                        return sink.closed(h, block).await;
                    }
                    sink.streamed(
                        h,
                        Streamed {
                            body,
                            running: None,
                            trailers,
                        },
                    )
                    .await
                }
                Err(_) => sink.unrendered(rendered).await,
            },
        }
    }
}

/// A FRAMED ANSWER THAT CLOSED BEFORE ITS FIRST BODY BYTE (ARCHITECT ruling on #787): its close is
/// already rendered and nothing of its body was written. The closing block, taken; `None` when the
/// body holds bytes or the answer is still open.
///
/// The probe takes the trailers only when they are ready (`try_recv` leaves an open answer's where
/// it is), and a body with bytes is never asked for its close.
pub(crate) fn closed_before_body(
    body: &mpsc::Receiver<Bytes>,
    trailers: Option<&mut oneshot::Receiver<HeaderMap>>,
) -> Option<HeaderMap> {
    if !body.is_empty() {
        return None;
    }
    trailers?.try_recv().ok()
}

/// Whether a reply head is a WHOLE answer's: it states its length and is no stream (one of the
/// [`streamed_media`] types, which the previous release relayed piece by piece).
pub(crate) fn whole_answer(fields: &HeadFields) -> bool {
    let named = |field: &[u8]| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| String::from_utf8_lossy(value).to_ascii_lowercase())
    };
    named(b"content-length").is_some()
        && !named(b"content-type").is_some_and(|v| streamed_media(&v))
}

/// Whether `content_type` is a stream's, read off the DECLARED ROWS and never spelled here (Law 1;
/// BUSBAR-1.6.0.md: "Dialects are internal to their plane"): the event stream the contract names,
/// or the stream `Content-Type` a declared protocol states on its `ProtocolDecl` row, folded at
/// boot.
pub(crate) fn streamed_media(content_type: &str) -> bool {
    std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media().iter().copied())
        .any(|media| {
            content_type
                .get(..media.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(media))
        })
}

/// A whole answer's head without its stated length: the answer states the length of what was
/// written.
pub(crate) fn unlengthed((status, mut fields): Head) -> Head {
    fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
    (status, fields)
}

/// Every piece the unit writes until it ends, the unit driven meanwhile (its writes wait on this
/// side), then whatever it wrote last.
pub(crate) async fn collect(mut body: mpsc::Receiver<Bytes>, mut unit: DrivenUnit) -> Vec<u8> {
    let mut whole = Vec::new();
    loop {
        tokio::select! {
            biased;
            piece = body.recv() => match piece {
                Some(bytes) => whole.extend_from_slice(&bytes),
                None => {
                    let _ = unit.await;
                    break;
                }
            },
            _ = &mut unit => {
                while let Ok(bytes) = body.try_recv() {
                    whole.extend_from_slice(&bytes);
                }
                break;
            }
        }
    }
    whole
}

/// A UNIT RUNNING ON ITS OWN TASK after its head (ARCHITECT ruling 2026-10-07, STREAM-CEILING): it
/// is driven whether or not its body is read, so a caller that stops reading with its socket open
/// leaves the unit's own deadline able to fire (a plane's stated ceiling) instead of freezing it
/// until the socket closes. Dropping it aborts the task, which drops the unit there: the answer's
/// body was dropped, so its caller is gone, and the unit ends on the driver's client-drop path as
/// it did when the body owned it.
pub(crate) struct Running(pub(crate) tokio::task::JoinHandle<Option<Rendered>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}
