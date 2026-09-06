// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The server side: one hyper HTTP/2 connection per accepted TCP socket, with a byte-blind
//! per-RPC handler that forwards inbound gRPC messages into the connection's shared inbound
//! channel and drains an outbound channel `write()` feeds, back onto the wire.
//!
//! ## The RPC path: the destination's, with this crate's own as the fallback
//!
//! gRPC's own wire format names every call by an HTTP/2 `:path` of the shape
//! `/package.Service/Method`. A dialled call uses the method the destination named —
//! `UpstreamAddress::Grpc` carries it, and `GrpcTransport::dial` reads it — so two plane operations
//! on one transport can reach two upstream methods. Only a destination naming none falls back to
//! [`RPC_PATH`], which is also the path this byte-blind server answers on: served calls are
//! answered whatever `:path` they arrive with, since the transport reads no meaning from it beyond
//! recording it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tonic::{Request, Response, Status};

use busbar_contract::wire::Frame;
use busbar_contract::{SlabBytes, StreamId};
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::TransportError;

use crate::codec::RawCodec;
use crate::conn::ConnState;

/// The path a dial falls back to when the destination names no method — this crate's own frame
/// method, the only one a byte-blind transport can name for itself. See the module header.
pub(crate) const RPC_PATH: &str = "/busbar.raw/Frames";

/// Serve one stream the layer below handed up as an HTTP/2 gRPC connection until it closes — or
/// until the connection is closed from this side.
///
/// The task is spawned, so the shutdown seam is armed on `state` BEFORE the spawn: a `close` racing
/// the very first poll of the connection must still find something to fire. Firing it asks hyper
/// for a graceful shutdown (a GOAWAY: no new calls, the ones in flight end with their own
/// trailers), and the socket goes with the task.
pub(crate) fn serve_connection(stream: crate::conn::LowerIo, state: Arc<ConnState>) {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    state.arm_shutdown(stop_tx);
    let ending = state.clone();
    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
            let state = state.clone();
            async move { Ok::<_, std::convert::Infallible>(handle_one_rpc(state, req).await) }
        });
        let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc);
        tokio::pin!(conn);
        tokio::select! {
            _ = conn.as_mut() => {}
            _ = stop_rx => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
            }
        }
        // The connection is over, so nothing will ever arrive on it again: end the inbound side so
        // a reader on `frames()` finishes rather than waiting out a deadline for a frame that
        // cannot come.
        ending.end_inbound();
    });
}

/// Handle ONE incoming RPC (one HTTP/2 stream): mint a `StreamId`, register its outbound channel,
/// spawn the inbound-forwarding task, and answer immediately with the response headers plus the
/// live outbound stream — exactly the "unary + multiplexed streams" shape, since a unary caller is
/// just a client that sends one message then half-closes.
async fn handle_one_rpc(
    state: Arc<ConnState>,
    req: hyper::Request<Incoming>,
) -> hyper::Response<tonic::body::Body> {
    state.record_served_path(req.uri().path().to_string());
    let local = state.next_local_stream.fetch_add(1, Ordering::Relaxed);
    let stream_id = StreamId(local);
    let (out_tx, out_rx) = crate::conn::outbound_channel();
    state
        .outbound
        .lock()
        .unwrap()
        .insert(local, crate::conn::opened(out_tx));

    let mut grpc = tonic::server::Grpc::new(RawCodec);
    let handler = RpcHandler {
        state: state.clone(),
        stream_id,
        out_rx: Some(out_rx),
    };
    grpc.streaming(handler, req).await
}

/// The per-RPC handler: reads the inbound `Streaming<Vec<u8>>` in a spawned task (forwarding every
/// message into the connection's shared inbound channel, tagged with this call's `StreamId`), and
/// answers immediately with the outbound stream `write()` feeds.
struct RpcHandler {
    state: Arc<ConnState>,
    stream_id: StreamId,
    out_rx: Option<crate::conn::OutboundRx>,
}

impl tower::Service<Request<tonic::Streaming<Vec<u8>>>> for RpcHandler {
    type Response = Response<OutStream>;
    type Error = Status;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Status>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<tonic::Streaming<Vec<u8>>>) -> Self::Future {
        let state = self.state.clone();
        let stream_id = self.stream_id;
        let out_rx = self.out_rx.take().expect("called at most once per RPC");
        Box::pin(async move {
            // `is_response = false`: this is the REQUEST body, which carries no `grpc-status`
            // trailer — only a gRPC response does. See `forward_inbound`'s own note.
            tokio::spawn(forward_inbound(
                state.clone(),
                stream_id,
                request.into_inner(),
                false,
            ));
            Ok(Response::new(OutStream::new(out_rx, state, stream_id)))
        })
    }
}

/// Drain one RPC's inbound `Streaming<Vec<u8>>`, forwarding every message as a [`Frame`] onto the
/// connection's shared inbound channel, tagged with `stream_id` — this IS the multiplexing: many
/// concurrent RPCs share one channel, told apart only by the tag.
///
/// `is_response` is true only on the CLIENT side, reading the upstream's ANSWER: that stream ends
/// bearing the `grpc-status` trailer (`StatusAt::Terminal` in the architecture's grpc row), which
/// this function reports as a final, zero-length, status-bearing frame — the transport's own
/// honest reading of the trailer, never a decode of what the messages themselves meant. A gRPC
/// REQUEST body carries no such trailer, so the server side never appends one.
pub(crate) async fn forward_inbound(
    state: Arc<ConnState>,
    stream_id: StreamId,
    mut inbound: tonic::Streaming<Vec<u8>>,
    is_response: bool,
) {
    use futures::StreamExt;
    let final_status = loop {
        match inbound.next().await {
            Some(Ok(bytes)) => {
                let slab = SlabBytes::new(Arc::<[u8]>::from(bytes));
                let meta = FrameMeta {
                    bytes: slab.len() as u64,
                    transport_units: None,
                    status: None,
                };
                let frame = Frame {
                    direction: Direction::Inbound,
                    stream: stream_id,
                    bytes: slab,
                    meta,
                };
                if state.send_inbound(Ok((stream_id, frame))).await.is_err() {
                    return; // the connection's frame pump has gone away
                }
            }
            Some(Err(status)) => break Some(status),
            None => break None,
        }
    };
    if is_response {
        let status = final_status.as_ref().map_or(
            busbar_contract_transport::wire::StatusClass::Success,
            map_status,
        );
        let meta = FrameMeta {
            bytes: 0,
            transport_units: None,
            status: Some(status),
        };
        let frame = Frame {
            direction: Direction::Inbound,
            stream: stream_id,
            bytes: SlabBytes::new(Arc::from([])),
            meta,
        };
        let _ = state.send_inbound(Ok((stream_id, frame))).await;
    } else if final_status.is_some() {
        let _ = state.send_inbound(Err(TransportError::Reset)).await;
    }
}

/// The transport's own honest reading of the `grpc-status` trailer, into the closed
/// [`busbar_contract_transport::wire::StatusClass`] — never a judgement about what the RPC's bytes meant.
pub(crate) fn map_status(status: &Status) -> busbar_contract_transport::wire::StatusClass {
    use busbar_contract_transport::wire::StatusClass;
    use tonic::Code;
    match status.code() {
        Code::Ok => StatusClass::Success,
        Code::InvalidArgument
        | Code::NotFound
        | Code::AlreadyExists
        | Code::PermissionDenied
        | Code::Unauthenticated
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::ResourceExhausted => StatusClass::ClientError,
        Code::Internal | Code::Unavailable | Code::DataLoss | Code::Unimplemented => {
            StatusClass::ServerError
        }
        _ => StatusClass::Other,
    }
}

/// The outbound message stream `write()` feeds, one message per queued `Vec<u8>`.
///
/// It carries the connection and the call's id as well as the channel because this stream's life IS
/// the call's: hyper drops it when the RPC ends, and that is the moment the connection's outbound
/// map should stop holding a sender nothing will ever drain again.
pub(crate) struct OutStream {
    rx: crate::conn::OutboundRx,
    state: Arc<ConnState>,
    stream_id: StreamId,
}

impl OutStream {
    pub(crate) fn new(
        rx: crate::conn::OutboundRx,
        state: Arc<ConnState>,
        stream_id: StreamId,
    ) -> Self {
        Self {
            rx,
            state,
            stream_id,
        }
    }
}

/// The call is over when its outbound stream is: the entry the connection registered for it goes
/// with it, so a connection serving many short calls holds senders for the ones still open and no
/// others.
impl Drop for OutStream {
    fn drop(&mut self) {
        self.state
            .outbound
            .lock()
            .unwrap()
            .remove(&self.stream_id.0);
    }
}

impl Stream for OutStream {
    type Item = Result<Vec<u8>, Status>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|opt| opt.map(Ok))
    }
}
