// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client (dial) side: an HTTP/2 connection to an upstream, opened once, over which every
//! fresh `StreamId` a caller writes to becomes a new gRPC call (bidi streaming, which subsumes
//! unary: a caller that sends one message then stops is a unary caller).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use http::uri::PathAndQuery;
use hyper_util::rt::{TokioExecutor, TokioIo};

use busbar_contract::StreamId;
use busbar_contract_transport::wire::TransportError;

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
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let mut sender = self.0.clone();
        Box::pin(async move { sender.send_request(req).await })
    }
}

/// Complete the HTTP/2 client preface over a stream the layer below has already established.
///
/// No name is resolved here and no socket is opened: the connection arrives as a stream the lower
/// transport gave up, which is what lets the resolve-then-pin network guard sit in front of the
/// dial, once for the whole stack, instead of inside every carrier.
///
/// The third value fires when the connection itself is over — the upstream gone, the socket shut,
/// the task finished. The dial side has no connection state to hang that on yet (this handshake is
/// what the state is built from), so the completion is handed back for the caller to wire, and what
/// it wires it to is the end of the inbound side: a reader whose upstream has gone must see
/// end-of-stream, not a wait with no end.
///
/// The task below is not the whole of the connection: the HTTP/2 client spawns a driver of its own
/// on the executor, and THAT is what holds the stream. It ends when the stream does — see
/// [`crate::conn::Cut`], which is how a caller closing this connection reaches it.
pub(crate) async fn handshake_h2(
    stream: crate::conn::Cuttable,
    authority: &str,
) -> Result<(Dialer, http::Uri, tokio::sync::oneshot::Receiver<()>), TransportError> {
    let io = TokioIo::new(stream);
    let (send_request, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, tonic::body::Body>(io)
        .await
        .map_err(|_| TransportError::HandshakeFailed)?;
    let (over_tx, over_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = connection.await;
        let _ = over_tx.send(());
    });
    let origin = http::Uri::builder()
        .scheme("http")
        .authority(authority.to_string())
        .path_and_query("/")
        .build()
        .map_err(|_| TransportError::AddressRefused)?;
    Ok((Dialer(send_request), origin, over_rx))
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
    serial: u64,
) -> Result<crate::conn::OutboundTx, TransportError> {
    let (out_tx, out_rx) = crate::conn::outbound_channel();
    // `with_origin`, not `new`: an HTTP/2 request needs a scheme and an authority (`:authority`
    // pseudo-header) — `Grpc::new` alone leaves both empty, which `hyper`'s h2 client rejects
    // (`MissingUriSchemeAndAuthority`), a real error this crate's own battery caught red before
    // this fix.
    let mut grpc = tonic::client::Grpc::with_origin(dialer, origin);
    grpc.ready().await.map_err(|_| TransportError::Refused)?;
    let path = PathAndQuery::try_from(method).map_err(|_| TransportError::AddressRefused)?;
    let response = match grpc
        .streaming(tonic::Request::new(InStream(out_rx)), path, RawCodec)
        .await
    {
        Ok(response) => response,
        Err(status) => {
            // A TRAILERS-ONLY answer — one HEADERS frame with END_STREAM carrying a non-zero
            // `grpc-status`, the standard shape for `UNIMPLEMENTED` or `UNAUTHENTICATED` — arrives
            // here, before any response stream exists. It is still an ANSWER: the upstream read the
            // call and said no. This transport declares its status class at the terminal frame, so
            // that class has to reach the reader as a frame; reporting only the opening failure
            // left a call the upstream had judged posting no status evidence at all, which is the
            // difference between "refused" and "nothing answered" on the leg that decides a fee.
            let frame = crate::server::terminal_frame(stream_id, Some(&status));
            let _ = state.send_inbound(Ok((stream_id, frame))).await;
            return Err(TransportError::Refused);
        }
    };
    let stream = response.into_inner();
    tokio::spawn(async move {
        crate::server::forward_inbound(state.clone(), stream_id, stream, true).await;
        // The upstream's answer has ended, trailer and all: this call is over, and the sender the
        // connection registered for it is one nothing will drain again. By serial, because by the
        // time this runs the id may already have been reused — and THAT call is still live.
        state.end_call(stream_id.0, serial);
    });
    Ok(out_tx)
}

/// The outbound request-message stream: raw `Vec<u8>` items, no `Result` wrapping (unlike the
/// server's [`crate::server::OutStream`]) because the client-side `Codec::Encode` item type here
/// is the plain message, per `tonic::client::Grpc::streaming`'s own signature.
struct InStream(crate::conn::OutboundRx);

impl Stream for InStream {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}
