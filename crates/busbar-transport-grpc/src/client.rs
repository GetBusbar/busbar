// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client (dial) side: an HTTP/2 connection to an upstream, opened once, over which every
//! fresh `StreamId` a caller writes to becomes a new gRPC call (bidi streaming, which subsumes
//! unary: a caller that sends one message then stops is a unary caller).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use http::uri::PathAndQuery;

use busbar_contract::wire::TransportError;
use busbar_contract::StreamId;

use crate::codec::RawCodec;
use crate::conn::ConnState;

/// The dial-side HTTP/2 sender. `Clone`-able (it is a cheap handle onto the connection's dispatch
/// channel), so every RPC this connection opens gets its own owned handle rather than sharing a
/// lock.
#[derive(Clone)]
pub(crate) struct Dialer(hyper::client::conn::http2::SendRequest<tonic::body::Body>);

impl tower::Service<http::Request<tonic::body::Body>> for Dialer {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let mut sender = self.0.clone();
        Box::pin(async move { sender.send_request(req).await })
    }
}

/// Connect to `host:port` over raw TCP and complete the HTTP/2 client preface. NOT resolve-then-
/// pin — see this crate's own report: the SSRF guard belongs in front of this transport, in a
/// crate this one may not yet depend on.
pub(crate) async fn dial_h2(host: &str, port: u16) -> Result<(Dialer, http::Uri), TransportError> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|_| TransportError::Refused)?;
    let io = TokioIo::new(tcp);
    let (send_request, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, tonic::body::Body>(io)
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let origin = http::Uri::builder()
        .scheme("http")
        .authority(format!("{host}:{port}"))
        .path_and_query("/")
        .build()
        .map_err(|_| TransportError::AddressRefused)?;
    Ok((Dialer(send_request), origin))
}

/// Open a fresh gRPC call for `stream_id` over `dialer` against `method`, registering its outbound
/// channel and
/// spawning the task that forwards the call's inbound messages into `state`'s shared inbound
/// channel — the client-side mirror of [`crate::server::handle_one_rpc`].
pub(crate) async fn open_stream(
    state: Arc<ConnState>,
    dialer: Dialer,
    origin: http::Uri,
    method: &'static str,
    stream_id: StreamId,
) -> Result<mpsc::UnboundedSender<Vec<u8>>, TransportError> {
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // `with_origin`, not `new`: an HTTP/2 request needs a scheme and an authority (`:authority`
    // pseudo-header) — `Grpc::new` alone leaves both empty, which `hyper`'s h2 client rejects
    // (`MissingUriSchemeAndAuthority`), a real error this crate's own battery caught red before
    // this fix.
    let mut grpc = tonic::client::Grpc::with_origin(dialer, origin);
    grpc.ready().await.map_err(|_| TransportError::Refused)?;
    let path = PathAndQuery::from_static(method);
    let response = grpc
        .streaming(tonic::Request::new(InStream(out_rx)), path, RawCodec)
        .await
        .map_err(|_| TransportError::Refused)?;
    let stream = response.into_inner();
    tokio::spawn(crate::server::forward_inbound(state, stream_id, stream, true));
    Ok(out_tx)
}

/// The outbound request-message stream: raw `Vec<u8>` items, no `Result` wrapping (unlike the
/// server's [`crate::server::OutStream`]) because the client-side `Codec::Encode` item type here
/// is the plain message, per `tonic::client::Grpc::streaming`'s own signature.
struct InStream(mpsc::UnboundedReceiver<Vec<u8>>);

impl Stream for InStream {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}
