// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Fixed HTTP operator adapter. Plane admissions use the neutral dispatcher.
use super::*;
use axum::body::Body as AxumBody;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri, Version};
use http_body::{Body as _, Frame};

impl http_body::Body for InboundBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match self.pieces.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(e))) => {
                self.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.ended {
            http_body::SizeHint::with_exact(0)
        } else {
            http_body::SizeHint::default()
        }
    }
}

pub(super) fn request(
    head: &Head,
    block: &[u8],
    secured: bool,
    body: InboundBody,
    timeout: std::time::Duration,
) -> Option<Request<AxumBody>> {
    let body = AxumBody::new(super::super::TimeoutBody::new(body, timeout));
    let method = Method::from_bytes(head.method.as_deref()?).ok()?;
    let target = std::str::from_utf8(head.target.as_deref()?).ok()?;
    let mut headers = HeaderMap::new();
    let mut read = 0;
    for (name, value) in fields::lines(block) {
        read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }
    if read != block.len() {
        return None;
    }
    let authority = head
        .authority
        .as_deref()
        .and_then(|a| std::str::from_utf8(a).ok())
        .filter(|a| !a.is_empty());
    let uri = match authority {
        Some(a) if !headers.contains_key(axum::http::header::HOST) => {
            let scheme = if secured { "https" } else { "http" };
            Uri::try_from(format!("{scheme}://{a}{target}")).ok()?
        }
        _ => Uri::try_from(target).ok()?,
    };
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_11)
        .body(body)
        .ok()?;
    *req.headers_mut() = headers;
    Some(req)
}

pub(super) async fn serve(
    router: Router,
    req: Request<AxumBody>,
    slot: SessionSlot,
    out: Emitter,
    _end: StreamEnd,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    let admission = req
        .extensions()
        .get::<busbar_kernel::inbound::RequestAdmission>()
        .cloned();
    let Ok(response) = {
        use hyper::service::Service as _;
        hyper_util::service::TowerToHyperService::new(router)
            .call(req)
            .await
    };
    // Fixed admin operations have already taken terminal ownership and sealed their
    // existing record. Clean routes without an operation still finish the first-auth unit.
    if let Some(admission) = admission.filter(|admission| admission.begin_execution()) {
        use busbar_contract::caps::{Outcome, PrincipalId};
        crate::root::plane_node::node().unmetered_inbound(
            admission.unit_key(),
            admission.audit_kind(),
            &PrincipalId::new(
                admission
                    .principal_id()
                    .unwrap_or_else(|| "anonymous".into()),
            ),
            Outcome::Completed,
        );
    }
    if let Some(pipe) = slot.take() {
        out.send(Op::Switch { pipe });
        return;
    }
    respond(&out, response).await;
}

pub(super) fn head_block(status: u16, headers: &HeaderMap, exact: Option<u64>) -> Vec<u8> {
    let mut block = field_block(headers);
    let bodyless = status < 200 || status == 204 || status == 304;
    let stated = headers.contains_key(axum::http::header::CONTENT_LENGTH)
        || headers.contains_key(axum::http::header::TRANSFER_ENCODING);
    if let Some(len) =
        exact.filter(|_| !bodyless && !stated && !headers.contains_key(axum::http::header::TRAILER))
    {
        block.extend_from_slice(b"content-length");
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(len.to_string().as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    block
}

pub(super) fn field_block(headers: &HeaderMap) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in headers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    block
}

pub(super) async fn respond(out: &Emitter, response: Response<AxumBody>) {
    let (parts, mut body) = response.into_parts();
    let status = parts.status.as_u16();
    let block = head_block(status, &parts.headers, body.size_hint().exact());
    let end = body.is_end_stream();
    if !out.head(u32::from(status), block, end).await || end {
        return;
    }
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => {
                let _ = out.data(Bytes::new(), true).await;
                return;
            }
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if !data.is_empty() && !out.data(data, false).await {
                        return;
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let _ = out.trailers(field_block(&trailers)).await;
                        return;
                    }
                }
            },
            Some(Err(e)) => {
                tracing::debug!(error = %e, "data door: an answer's body failed after its head");
                out.send(Op::Refuse {
                    status: u32::from(status),
                    head_sent: true,
                });
                return;
            }
        }
    }
}
