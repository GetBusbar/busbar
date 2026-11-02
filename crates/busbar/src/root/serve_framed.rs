// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub(super) fn stream_framer(
    carrier: &str,
    framer_for: impl Fn(&str) -> Option<Arc<dyn FramerDoor>>,
) -> Option<Arc<dyn FramerDoor>> {
    let door = framer_for(carrier)?;

    (!door.facts().datagram && door.facts().duplex.contains(&carrier)).then_some(door)
}

pub(super) type Shared = Arc<Mutex<Slot>>;

type Close = Box<dyn FnOnce(FramedStream) + Send>;

pub(super) struct Slot {
    stream: Option<FramedStream>,

    out: bool,

    then: Option<Close>,
}

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

fn send_trailers(trailers: &Trailers, block: &[HeadWords]) {
    let sender = trailers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        let _gone = sender.send(block_head(block).1);
    }
}

type Trailers = Arc<Mutex<Option<oneshot::Sender<HeaderMap>>>>;

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

pub(super) fn refused(stream: &Shared, rendered: Option<Rendered>) -> Response {
    let (status, body) = rendered.map_or_else(
        || (refusal_status(ReasonCode::PlanePanic), Vec::new()),
        |r| (r.status, r.body),
    );

    let taken = lock(stream).stream.take();
    let block = taken.map(|mut s| s.refuse(&body, status, false));
    match block {
        Some(Ok(block)) => whole(status, &block),
        _ => stated((status, Vec::new()), Body::empty()),
    }
}

pub(super) fn whole(status: u32, block: &[HeadWords]) -> Response {
    let (code, headers) = block_head(block);
    let mut response = stated((status, Vec::new()), Body::empty());
    if let Some(code) = code {
        *response.status_mut() = code;
    }
    response.headers_mut().extend(headers);
    response
}

pub(super) struct FramedCaller {
    inner: IngressCaller,
    stream: Shared,
    trailers: Trailers,
    opening: HeadFields,
}

impl FramedCaller {
    pub(super) fn new(
        inner: IngressCaller,
        stream: Shared,
        trailers: oneshot::Sender<HeaderMap>,
    ) -> Self {
        let opening = lock(&stream)
            .stream
            .as_ref()
            .map(|stream| stream.opening_fields().to_vec())
            .unwrap_or_default();
        Self {
            inner,
            stream,
            trailers: Arc::new(Mutex::new(Some(trailers))),
            opening,
        }
    }

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
    fn head(&self, status: u32, mut fields: HeadFields) {
        fields.extend(self.opening.iter().cloned());
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
    fn drop(&mut self) {
        if self.inner.stated().is_some() {
            self.finish(0, b"", b"");
        }
    }
}

#[cfg(test)]
#[path = "tests/serve_framed_lock.rs"]
mod lock_tests;
