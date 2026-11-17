// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE FETCH (IF 13): a hyper client connection, dialled for this request and dropped with it.
//!
//! The judge is asked once for the connection this FETCH dials (an [`Admission`], so a pooled
//! connection is never judged again and a client that pools its own still judges every dial it
//! makes). The request goes out as the plugin stated it; the exchange adds no `Authorization`, no
//! cookie, no proxy and no credential of any kind, follows no redirect (a 3xx is the answer),
//! retries nothing, and holds the response to the header and body caps and to the one deadline
//! the whole exchange shares.
//!
//! The status, then the body (data0), then the headers as PAIR records (data1) go to a [`Reply`]
//! (`NeedOut` in production), so a body never sits in a buffer of its own.

use busbar_plugin_abi::host_side::needs::{NeedErr, NeedOut};
use busbar_plugin_abi::records::Records;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as _, Bytes};
use hyper::client::conn::{http1, http2};
use hyper::header::{HeaderName, HeaderValue};
use hyper_util::rt::TokioIo;

use super::net::{ConnectorIo, Stream};
use super::{Admission, FetchReq, TlsPlan};

/// Where a FETCH answer goes.
pub trait Reply: Send {
    /// The HTTP status.
    fn status(&mut self, status: u16);
    /// The next bytes of the body.
    ///
    /// # Errors
    /// `Limit` when the answer's room is full.
    fn body(&mut self, bytes: &[u8]) -> Result<(), NeedErr>;
    /// One response header (after the whole body).
    ///
    /// # Errors
    /// `Limit` when the answer's room is full.
    fn header(&mut self, name: &str, value: &[u8]) -> Result<(), NeedErr>;
}

impl Reply for NeedOut<'_> {
    fn status(&mut self, status: u16) {
        self.set(u64::from(status), 0);
    }

    fn body(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        self.put0(bytes)
    }

    fn header(&mut self, name: &str, value: &[u8]) -> Result<(), NeedErr> {
        self.pair1(name, value)
    }
}

/// Aborts the task driving a connection when the exchange ends, however it ends.
struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The request headers the plugin stated. Core owns `Host` and `Content-Length` (they are written
/// from the URL and the body, whatever the plugin said); the connection-management headers are the
/// client's alone, so a plugin that states one is refused.
fn request_headers(stated: Records<'_>) -> Result<Vec<(HeaderName, HeaderValue)>, NeedErr> {
    let mut out = Vec::new();
    for rec in stated {
        let (name, value) = rec.and_then(|r| r.pair()).map_err(|_| NeedErr::Invalid)?;
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| NeedErr::Invalid)?;
        match name.as_str() {
            "host" | "content-length" => continue,
            "connection" | "transfer-encoding" | "upgrade" | "te" | "keep-alive"
            | "proxy-connection" | "trailer" => return Err(NeedErr::Invalid),
            _ => {}
        }
        out.push((
            name,
            HeaderValue::from_bytes(value).map_err(|_| NeedErr::Invalid)?,
        ));
    }
    Ok(out)
}

fn hyper_err(e: &hyper::Error) -> NeedErr {
    if e.is_closed() || e.is_incomplete_message() || e.is_canceled() {
        NeedErr::Closed
    } else {
        NeedErr::Unavailable
    }
}

#[derive(Clone)]
struct RuntimeExecutor(tokio::runtime::Handle);
impl<F> hyper::rt::Executor<F> for RuntimeExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.0.spawn(future);
    }
}

/// Send `request` on `stream` as HTTP/1.1 or HTTP/2 and return the response head and body with the
/// guard that keeps the connection driven.
async fn send(
    runtime: &tokio::runtime::Handle,
    stream: Stream,
    h2: bool,
    request: http::Request<Full<Bytes>>,
) -> Result<(http::response::Parts, hyper::body::Incoming, Driver), NeedErr> {
    let io = TokioIo::new(stream);
    if h2 {
        let (mut sender, conn) = http2::handshake(RuntimeExecutor(runtime.clone()), io)
            .await
            .map_err(|e| hyper_err(&e))?;
        let driver = Driver(runtime.spawn(async move {
            let _ = conn.await;
        }));
        let (parts, body) = sender
            .send_request(request)
            .await
            .map_err(|e| hyper_err(&e))?
            .into_parts();
        Ok((parts, body, driver))
    } else {
        let (mut sender, conn) = http1::handshake(io).await.map_err(|e| hyper_err(&e))?;
        let driver = Driver(runtime.spawn(async move {
            let _ = conn.await;
        }));
        let (parts, body) = sender
            .send_request(request)
            .await
            .map_err(|e| hyper_err(&e))?
            .into_parts();
        Ok((parts, body, driver))
    }
}

/// One FETCH, within `req.timeout` in all.
///
/// # Errors
/// `Invalid` for a request that is not one (URL, method, headers, credentials in the URL);
/// whatever the judge refuses; `Tls`, `Unavailable`, `Closed` for the exchange; `Limit` for a
/// response over the header or body cap; `Timeout` when the deadline passes.
pub(super) async fn fetch<P: Reply>(
    io: &ConnectorIo,
    req: FetchReq<'_>,
    admission: &dyn Admission,
    reply: &mut P,
) -> Result<(), NeedErr> {
    let timeout = req.timeout;
    crate::io::timeout_on(io.runtime(), timeout, exchange(io, req, admission, reply))
        .await
        .map_err(|_| NeedErr::Timeout)?
}

/// The `Host` header of an HTTP/1 exchange: the URL's authority as one header value.
fn host_value(authority: &str) -> Result<HeaderValue, NeedErr> {
    HeaderValue::from_str(authority).map_err(|_| NeedErr::Invalid)
}

async fn exchange<P: Reply>(
    io: &ConnectorIo,
    req: FetchReq<'_>,
    admission: &dyn Admission,
    reply: &mut P,
) -> Result<(), NeedErr> {
    let url = super::judge::parse_fetch_url(req.need.url)?;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err(NeedErr::Invalid),
    };
    // No ambient credentials: a URL's userinfo is a credential the plugin did not state as one.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(NeedErr::Invalid);
    }
    let shown = url.host_str().ok_or(NeedErr::Invalid)?;
    let host = shown
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(shown);
    let port = url.port_or_known_default().ok_or(NeedErr::Invalid)?;
    let authority = match url.port() {
        Some(p) => format!("{shown}:{p}"),
        None => shown.to_owned(),
    };
    let method =
        http::Method::from_bytes(req.need.method.as_bytes()).map_err(|_| NeedErr::Invalid)?;
    let headers = request_headers(req.need.headers)?;

    // The one judgement of this exchange's one connection, before a byte is sent.
    let connect_budget = req
        .timeout
        .min(super::dial_policy(req.class).connect_timeout);
    let (stream, h2) = crate::io::timeout_on(io.runtime(), connect_budget, async {
        let route = admission.dial(host, port, https).await?;
        let net = io
            .connect_route(&authority, &route, None, req.timeout)
            .await?;
        let pair = if https {
            let plan = TlsPlan {
                sni: host,
                alpn: "",
                trust: req.trust.clone(),
                cert: req.cert.clone(),
                waive: req.waive,
            };
            let offered = [b"h2".to_vec(), b"http/1.1".to_vec()];
            let dialled = io.secure(net, &plan, &offered, req.timeout).await?;
            let h2 = &*dialled.alpn == "h2";
            (dialled.conn, h2)
        } else {
            (Stream::Plain(net), false)
        };

        Ok::<_, NeedErr>(pair)
    })
    .await
    .map_err(|_| NeedErr::Timeout)??;

    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let scheme = if https { "https" } else { "http" };
    let uri = if h2 {
        format!("{scheme}://{authority}{target}")
    } else {
        target
    };
    let mut request = http::Request::new(Full::new(Bytes::copy_from_slice(req.need.body)));
    *request.method_mut() = method;
    *request.uri_mut() = uri.parse().map_err(|_| NeedErr::Invalid)?;
    let wire = request.headers_mut();
    for (name, value) in headers {
        wire.append(name, value);
    }
    if !h2 {
        wire.insert(http::header::HOST, host_value(&authority)?);
    }

    let (parts, mut body, _driver) = send(io.runtime(), stream, h2, request).await?;

    let held = parts.headers.iter().fold(0usize, |n, (name, value)| {
        n.saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    });
    if held > req.max_headers as usize {
        return Err(NeedErr::Limit);
    }
    if body.size_hint().lower() > req.max_body {
        return Err(NeedErr::Limit);
    }
    reply.status(parts.status.as_u16());
    let mut seen = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| hyper_err(&e))?;
        if let Ok(data) = frame.into_data() {
            seen = seen.saturating_add(data.len() as u64);
            if seen > req.max_body {
                return Err(NeedErr::Limit);
            }
            reply.body(&data)?;
        }
    }
    for (name, value) in &parts.headers {
        reply.header(name.as_str(), value.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/need_exchange_tests.rs"]
mod tests;
