// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSE-CODE CELLS — a session's ending, as the client reads it.
//!
//! Until the slot existed, the neutral acceptor's writer sent a BARE close whenever the outbound
//! sink dropped, so a money refusal, a policy refusal and this node's own fault were one silence on
//! the wire. These three cells pin the whole of what the slot changed and, just as importantly, what
//! it did not:
//!
//! 1. NOTHING SET ⇒ the bare close, exactly as before. This is the byte-identity cell: every caller
//!    of `channel`/`accept` that predates the slot is a caller that never sets one.
//! 2. SET ⇒ the code, and the client reads it AFTER the last frame — not instead of it.
//! 3. SET WHILE FRAMES ARE STILL QUEUED ⇒ the frames still go first. This is the cell the design
//!    turns on: the code is read only once the outbound queue has drained, so a code stored mid-drain
//!    cannot preempt answers the session already committed to. A second channel could not have made
//!    that promise, which is why the ending rides a slot.
//!
//! Driven through a REAL upgrade and a real client handshake, because the close frame is a control
//! frame and the acceptor's own neutral stream deliberately drops those: a cell that read the code
//! off anything but a socket would be reading this test's own bookkeeping.

#![cfg(feature = "runtime")]

use busbar_substrate::ingress::duplex_ws::{accept_coded, CloseSlot};
use futures::channel::mpsc::UnboundedSender;
use futures::StreamExt;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

/// What one session did with its sink and its slot, as data, so a test names the ending rather than
/// writing a server.
type Ending = Arc<dyn Fn(UnboundedSender<Vec<u8>>, CloseSlot) + Send + Sync>;

/// Serve ONE session whose ending is `ending`, and return what the client saw: the data frames in
/// order, then the close as the client read it (`None` for a bare close, `Some(code)` otherwise).
async fn one_session(ending: Ending) -> (Vec<Vec<u8>>, Option<u16>) {
    async fn route(
        axum::extract::State(ending): axum::extract::State<Ending>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        accept_coded(upgrade, move |_stream, sink, closing| async move {
            (ending)(sink, closing);
            // The session is over the moment its ending has been written: the sink was moved into
            // `ending` and dropped there, which is what ends the writer's drain.
        })
    }

    let app = axum::Router::new()
        .route("/session", axum::routing::get(route))
        .with_state(ending);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/session"))
        .await
        .expect("the client handshake completes");

    let mut frames = Vec::new();
    let mut closed = None;
    while let Some(Ok(msg)) = client.next().await {
        match msg {
            ClientMessage::Binary(b) => frames.push(b.to_vec()),
            ClientMessage::Text(t) => frames.push(t.as_bytes().to_vec()),
            ClientMessage::Close(frame) => {
                closed = Some(frame.map(|f| u16::from(f.code)));
                break;
            }
            _ => {}
        }
    }
    // `closed` is `None` only if the socket died without a close at all; `Some(None)` is the BARE
    // close and `Some(Some(code))` is a spelled one. Flattening here keeps every assertion below
    // about the code rather than about the shape.
    (frames, closed.flatten())
}

/// Write `frames` onto the sink, without ending the session.
fn write_all(sink: &mut UnboundedSender<Vec<u8>>, frames: &[&[u8]]) {
    for f in frames {
        sink.unbounded_send(f.to_vec()).expect("the sink accepts");
    }
}

/// NOTHING SET ⇒ the bare close this acceptor has always sent.
#[tokio::test]
async fn an_unset_slot_ends_the_session_with_the_bare_close_it_always_did() {
    let (frames, code) = one_session(Arc::new(|mut sink, _closing| {
        write_all(&mut sink, &[b"one", b"two"]);
    }))
    .await;

    assert_eq!(frames, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(
        code, None,
        "a session that spells no code must end EXACTLY as it did before the slot existed — a close \
         carrying no code at all. A number here would be this change reaching a caller that never \
         asked for it"
    );
}

/// SET ⇒ the client reads the code, and reads it after the last frame.
#[tokio::test]
async fn a_spelled_code_reaches_the_client_after_the_last_frame() {
    let (frames, code) = one_session(Arc::new(|mut sink, closing| {
        write_all(&mut sink, &[b"answer"]);
        // A money reason: nothing is wrong with the caller, and the same session opened later may
        // well run. Until the slot, this ending and a policy refusal were the same silence.
        closing.set(1013);
    }))
    .await;

    assert_eq!(
        frames,
        vec![b"answer".to_vec()],
        "the answer the session had already committed to is still written"
    );
    assert_eq!(
        code,
        Some(1013),
        "the client must read the code the session ended for. `None` here is the whole finding: a \
         refusal answered with a silence the client cannot tell from an orderly close"
    );
}

/// SET WHILE FRAMES ARE STILL QUEUED ⇒ every frame goes first.
#[tokio::test]
async fn a_code_stored_mid_drain_does_not_preempt_the_frames_already_queued() {
    // Enough frames that the writer cannot have drained them before the code is stored: the sink is
    // unbounded and the store happens in the same breath as the writes, so the queue is deep when
    // the slot is set and dropped.
    const QUEUED: usize = 256;
    let (frames, code) = one_session(Arc::new(|sink, closing| {
        for i in 0..QUEUED {
            sink.unbounded_send(format!("frame-{i}").into_bytes())
                .expect("the sink accepts");
        }
        closing.set(1008);
    }))
    .await;

    assert_eq!(
        frames.len(),
        QUEUED,
        "every frame the session queued must reach the client BEFORE the ending is spelled — a code \
         that preempted the drain would drop answers the session had already committed to, which is \
         the failure a second close channel could not have ruled out"
    );
    assert_eq!(
        frames.last().map(Vec::as_slice),
        Some(format!("frame-{}", QUEUED - 1).as_bytes()),
        "and the LAST of them is the last one written, so the ordering is the queue's own"
    );
    assert_eq!(code, Some(1008), "the policy ending is still spelled");
}
