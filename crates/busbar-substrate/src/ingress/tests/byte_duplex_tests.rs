// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/ingress/byte_duplex.rs`.

use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// A trivial ECHO plane: no protocol, no wire vocabulary. It echoes an ordinary frame back
/// verbatim, and — to exercise the correlation table — a frame beginning `call` triggers an
/// outbound call whose answer it then re-emits. `classify` recognises a reply solely by the
/// leading marker `reply:<n> `, parsing the bare `CallRef` number the transport minted.
struct EchoPlane;

#[async_trait::async_trait]
impl DuplexPlane for EchoPlane {
    fn classify(&self, frame: &[u8]) -> Option<CallRef> {
        let rest = frame.strip_prefix(b"reply:")?;
        let end = rest.iter().position(|&b| b == b' ')?;
        let n: u64 = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
        Some(CallRef(n))
    }

    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        if frame == b"call" {
            let call = out.mint();
            let outbound = format!("call {}", call.0).into_bytes();
            if let Some(reply) = out.issue(call, outbound).await {
                let mut got = b"got ".to_vec();
                got.extend_from_slice(&reply);
                out.emit(got).await;
            }
        } else {
            out.emit(frame).await; // pure echo
        }
    }
}

/// Drive the pump over an in-memory duplex: frames written to the far end come back echoed,
/// both a mid-stream frame and a final unterminated one, and EOF ends the loop.
#[tokio::test]
async fn echo_round_trips_frames_and_stops_on_eof() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"hello\n").await.unwrap();
    far_w.write_all(b"  \n").await.unwrap(); // a blank line is not a frame
    far_w.write_all(b"world\n").await.unwrap();

    let mut line = String::new();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "hello\n");
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "world\n", "the blank line produced no frame");

    // A final UNTERMINATED line is still one frame; closing the writer is EOF.
    far_w.write_all(b"tail").await.unwrap();
    far_w.shutdown().await.unwrap();
    drop(far_w);
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "tail\n");

    // EOF on the reader ends the pump.
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on EOF")
        .unwrap();
}

/// Drive the correlation table: a `call` frame makes the pump ISSUE an outbound call, the far
/// end answers with a `reply:<n> ...` frame, `classify` maps it to the minted `CallRef`, the
/// transport routes it back to the waiting `issue`, and the answer is re-emitted.
#[tokio::test]
async fn correlation_routes_a_reply_to_its_issuer() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"call\n").await.unwrap();

    // The pump issues its outbound call, naming the CallRef it minted.
    let mut asked = String::new();
    far_r.read_line(&mut asked).await.unwrap();
    assert_eq!(asked, "call 1\n", "the transport minted CallRef 1 first");

    // Answer it, tagged with the same ref so classify can pair it.
    far_w.write_all(b"reply:1 pong\n").await.unwrap();

    // The routed answer is re-emitted by the handler.
    let mut got = String::new();
    far_r.read_line(&mut got).await.unwrap();
    assert_eq!(got, "got reply:1 pong\n");

    far_w.shutdown().await.unwrap();
    drop(far_w);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on EOF")
        .unwrap();
}

/// `CallRef::NONE` is reserved and never minted; the mint is monotonic from 1.
#[tokio::test]
async fn mint_is_monotonic_and_never_none() {
    let (_near, far) = tokio::io::duplex(64);
    let (_r, w) = tokio::io::split(far);
    let shared = new_shared(Box::new(NewlineSink { writer: w }));
    let handle = DuplexHandle { shared };
    let a = handle.mint();
    let b = handle.mint();
    assert_eq!(a, CallRef(1));
    assert_eq!(b, CallRef(2));
    assert!(!a.is_none() && !b.is_none());
    assert!(CallRef::NONE.is_none());
}

/// Drive the pump over an in-memory MESSAGE duplex (each channel item is one frame, no newline
/// convention — the shape an already-upgraded WebSocket presents): frames sent to the near end come
/// back echoed verbatim as whole messages, and the stream ending (close) ends the loop. Mirrors
/// `echo_round_trips_frames_and_stops_on_eof` on the byte path.
#[tokio::test]
async fn message_duplex_round_trips_frames_and_stops_on_close() {
    use futures::channel::mpsc;

    // inbound: what the peer sends the pump; outbound: what the pump emits back.
    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    // A whole message is one frame — no terminator on the wire, unlike the byte path.
    in_tx.send(b"hello".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"hello");

    in_tx.send(b"world".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"world");

    // Closing the inbound stream (dropping the sender) is the message-duplex analogue of EOF.
    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}

/// Drive the correlation table over the MESSAGE duplex: a `call` frame makes the pump ISSUE an
/// outbound call as one message, the peer answers with a `reply:<n> ...` message, `classify` maps
/// it to the minted `CallRef`, the transport routes it back to the waiting `issue`, and the answer
/// is re-emitted — the identical machinery `serve` uses, reached through a different framing.
#[tokio::test]
async fn message_duplex_correlation_routes_a_reply_to_its_issuer() {
    use futures::channel::mpsc;

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    in_tx.send(b"call".to_vec()).await.unwrap();

    // The pump issues its outbound call as one whole message, naming the CallRef it minted.
    assert_eq!(out_rx.next().await.unwrap(), b"call 1");

    // Answer it, tagged with the same ref so classify can pair it.
    in_tx.send(b"reply:1 pong".to_vec()).await.unwrap();

    // The routed answer is re-emitted by the handler.
    assert_eq!(out_rx.next().await.unwrap(), b"got reply:1 pong");

    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}
