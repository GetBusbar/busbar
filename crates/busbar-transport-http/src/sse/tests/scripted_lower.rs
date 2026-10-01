//! A lower layer that answers what the test scripted, for the `sse` re-segmentation cells.
//!
//! `sse` reads the frames the layer beneath it hands up: a HEAD frame carrying the status leg, then
//! body frames, then (optionally) a trailer frame, then the end. `http` no longer dials (TODO #145:
//! an upstream connection is the connector's), so those frames are scripted here, in exactly the
//! shape `http`'s frame contract states. What is under test is everything `sse` does with them.

use std::sync::{Arc, Mutex};

use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, Direction, FrameMeta, Listener, RawStream,
    TransportError, WireStatusClass,
};
use busbar_contract::{
    Frame, Fut, Kind, Plugin, Refusal, ScratchBytes, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, VerifiedDestination,
};
use tokio::sync::mpsc;

/// One frame from the layer below, or the error that ended its stream.
type Item = Result<(StreamId, Frame), TransportError>;

/// A lower layer whose one dialled connection answers a scripted response.
pub(super) struct ScriptedLower {
    answer: Mutex<Option<mpsc::UnboundedReceiver<Item>>>,
}

impl ScriptedLower {
    /// The response HEAD for `status`, then each of `body` as its own frame, then the end.
    pub(super) fn answering(status: u16, body: &[&[u8]]) -> Arc<Self> {
        let (more, lower) = Self::open(status);
        for piece in body {
            more.send(Ok(body_frame(piece))).unwrap();
        }
        lower
    }

    /// The response HEAD for `status`, and a stream that stays open: the test holds the sender and
    /// writes the body as it chooses. Dropping the sender ends the stream.
    pub(super) fn open(status: u16) -> (mpsc::UnboundedSender<Item>, Arc<Self>) {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(Ok(head_frame(status))).unwrap();
        let lower = Arc::new(Self {
            answer: Mutex::new(Some(rx)),
        });
        (tx, lower)
    }
}

/// A body frame (or a trailer frame: the same shape, no status leg), as the layer below hands it up.
pub(super) fn body_frame(bytes: &[u8]) -> (StreamId, Frame) {
    (
        StreamId(0),
        Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(Arc::from(bytes)),
            meta: FrameMeta {
                bytes: bytes.len() as u64,
                transport_units: None,
                status: None,
                status_code: None,
                retry_after_secs: None,
            },
        },
    )
}

/// The HEAD frame: the only one that carries the status leg.
fn head_frame(status: u16) -> (StreamId, Frame) {
    let class = match status {
        200..=299 => WireStatusClass::Success,
        400..=499 => WireStatusClass::CallerFault,
        500..=599 => WireStatusClass::FarEndFault,
        _ => WireStatusClass::Other,
    };
    let (id, mut frame) = body_frame(format!("HTTP/1.1 {status} \r\n\r\n").as_bytes());
    frame.meta.status = Some(class);
    (id, frame)
}

struct Handle;
impl ConnHandle for Handle {
    fn id(&self) -> u64 {
        0
    }
    fn peer(&self) -> String {
        "scripted".to_string()
    }
}

impl Plugin for ScriptedLower {
    fn key(&self) -> &'static str {
        "http"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        busbar_contract::transport::registry::TRANSPORT_ABI
    }
}

impl Transport for ScriptedLower {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["http"],
        }
    }

    fn listen<'a>(
        &'a self,
        _cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn accept<'a>(&'a self, _l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn dial<'a>(
        &'a self,
        _dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move { Ok(Conn::new(Arc::new(Handle))) })
    }

    fn frames(&self, _conn: Conn) -> busbar_contract::transport::FrameStream {
        let answer = self.answer.lock().unwrap().take();
        Box::pin(futures::stream::unfold(answer, |answer| async move {
            let mut rx = answer?;
            let item = rx.recv().await?;
            Some((item, Some(rx)))
        }))
    }

    fn write<'a>(
        &'a self,
        _conn: &'a Conn,
        _stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        let len = bytes.len();
        Box::pin(async move { Ok(len) })
    }

    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        _body: &[u8],
        _arena: &'a dyn busbar_contract::bounded::PlaneAlloc,
    ) -> Result<busbar_contract::bounded::ScratchBytes<'a>, busbar_contract::wire::Encode> {
        Err(busbar_contract::wire::Encode::ScratchExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn detach(&self, _conn: &Conn) -> Option<RawStream> {
        None
    }

    fn composed_over(&self) -> Option<&'static str> {
        None
    }

    fn close(&self, _conn: Conn, _reason: CloseReason) {}

    fn unit0_refusal<'a>(
        &'a self,
        _conn: Conn,
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        _bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }
}
