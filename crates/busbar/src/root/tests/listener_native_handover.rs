// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The caller's side of an upgrade request's session (§12.27; owner decision 18): HTTP's until the
//! plane commits with a 101, messages after it; what it refuses; what the adopted transport
//! session's items are to the plane session; and what of the upgrade request a second transport
//! is handed.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_core_connector::framed_stream::session::{Inbound, Payload};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use busbar_kernel::plane_driver::port_duplex::{ClientEvent, ClientMessages, Ending};
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_plugin_abi::transport::{MSG_BINARY, MSG_FIN, MSG_TEXT};

use super::{event_of, handed_on, UpgradePipe, ADOPTED_STREAM};

/// The data path's sink, as the pipe sees it: it takes every item (or none more, once `full`).
#[derive(Default)]
struct Http {
    taken: Mutex<Vec<ToClient>>,
    /// The body's one slot is taken: an offered item waits.
    full: Mutex<bool>,
}

impl Http {
    fn taken(&self) -> Vec<ToClient> {
        self.taken.lock().unwrap().clone()
    }
}

impl ClientSink for Http {
    fn poll_items(&self, _: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        if *self.full.lock().unwrap() {
            return Poll::Pending;
        }
        self.taken.lock().unwrap().append(items);
        Poll::Ready(true)
    }
}

fn pipe() -> (Arc<Http>, Arc<UpgradePipe>) {
    let http = Arc::new(Http::default());
    (http.clone(), UpgradePipe::new(http, None))
}

fn hand(pipe: &UpgradePipe, items: Vec<ToClient>) -> Poll<bool> {
    let mut items = items;
    pipe.poll_items(&mut Context::from_waker(Waker::noop()), &mut items)
}

fn head(status: u16) -> ToClient {
    ToClient::Head {
        status,
        fields: vec![(b"sec-websocket-protocol".to_vec(), b"realtime".to_vec())],
    }
}

fn msg(flags: u32, bytes: &[u8]) -> ToClient {
    ToClient::Msg {
        flags,
        bytes: bytes.to_vec(),
    }
}

#[test]
fn before_a_101_the_answer_is_an_ordinary_http_answer() {
    // The plane's own refusal, an exhausted walk's answer, a far end's error relayed.
    let (http, pipe) = pipe();
    let answer = vec![
        head(502),
        ToClient::Body(b"{\"error\":\"upstream\"}".to_vec()),
        ToClient::End,
    ];
    assert_eq!(hand(&pipe, answer.clone()), Poll::Ready(true));
    assert_eq!(http.taken(), answer, "written as handed, nothing added");
    assert!(!pipe.switched(), "no 101 was written");
    assert_eq!(
        pipe.kinds().next(),
        None,
        "an HTTP answer's body states no message"
    );
}

#[test]
fn a_message_with_no_101_before_it_is_refused() {
    let (http, pipe) = pipe();
    assert_eq!(
        hand(&pipe, vec![msg(MSG_TEXT | MSG_FIN, b"early")]),
        Poll::Ready(false),
        "there is no wire to write it on"
    );
    assert!(http.taken().is_empty());
}

#[test]
fn after_the_101_each_message_is_one_body_frame_with_its_flags_stated_in_order() {
    let (http, pipe) = pipe();
    assert_eq!(
        hand(
            &pipe,
            vec![
                head(101),
                msg(MSG_TEXT | MSG_FIN, b"hello"),
                msg(MSG_BINARY, &[1, 2]),
                msg(MSG_BINARY | MSG_FIN, &[3]),
                msg(MSG_TEXT | MSG_FIN, b""),
                ToClient::End,
            ]
        ),
        Poll::Ready(true)
    );
    assert!(pipe.switched());
    assert_eq!(
        http.taken(),
        vec![
            head(101),
            ToClient::Body(b"hello".to_vec()),
            ToClient::Body(vec![1, 2]),
            ToClient::Body(vec![3]),
            ToClient::Body(Vec::new()),
            ToClient::End,
        ],
        "the 101 carries the plane's own pairs; an empty message is still a frame"
    );
    let kinds = pipe.kinds();
    assert_eq!(
        std::iter::from_fn(|| kinds.next()).collect::<Vec<_>>(),
        [
            MSG_TEXT | MSG_FIN,
            MSG_BINARY,
            MSG_BINARY | MSG_FIN,
            MSG_TEXT | MSG_FIN
        ]
    );
}

#[test]
fn a_frame_the_http_side_has_no_room_for_waits_and_is_stated_once() {
    let (http, pipe) = pipe();
    assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(true));
    *http.full.lock().unwrap() = true;
    let mut items = vec![msg(MSG_TEXT | MSG_FIN, b"a")];
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(pipe.poll_items(&mut cx, &mut items), Poll::Pending);
    assert_eq!(pipe.poll_items(&mut cx, &mut items), Poll::Pending);
    *http.full.lock().unwrap() = false;
    assert_eq!(pipe.poll_items(&mut cx, &mut items), Poll::Ready(true));
    assert_eq!(http.taken(), vec![head(101), ToClient::Body(b"a".to_vec())]);
    let kinds = pipe.kinds();
    assert_eq!(kinds.next(), Some(MSG_TEXT | MSG_FIN));
    assert_eq!(kinds.next(), None, "a frame offered twice is stated once");
}

#[test]
fn after_the_101_only_messages_and_the_end_are_written() {
    for wrong in [
        ToClient::Body(b"not a message".to_vec()),
        ToClient::Trailers(Vec::new()),
        head(101),
        head(200),
    ] {
        let (http, pipe) = pipe();
        assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(true));
        assert_eq!(
            hand(&pipe, vec![wrong.clone()]),
            Poll::Ready(false),
            "{wrong:?}"
        );
        assert_eq!(http.taken(), vec![head(101)], "{wrong:?}");
    }
    let (http, pipe) = pipe();
    assert_eq!(
        hand(&pipe, vec![head(101), ToClient::End]),
        Poll::Ready(true)
    );
    assert_eq!(
        hand(&pipe, vec![msg(MSG_TEXT | MSG_FIN, b"late")]),
        Poll::Ready(false),
        "nothing follows END"
    );
    assert_eq!(http.taken(), vec![head(101), ToClient::End]);
}

#[test]
fn an_end_that_is_not_the_planes_orderly_one_is_not_written_as_an_end() {
    // The far end failed mid-session: the answer is left without its END, which the adopted
    // transport writes as a failure's close (1011), never as a normal close (1000).
    let (http, pipe) = pipe();
    assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(true));
    pipe.ending(Ending::UpstreamFailed);
    assert_eq!(hand(&pipe, vec![ToClient::End]), Poll::Ready(false));
    assert_eq!(http.taken(), vec![head(101)]);
}

#[test]
fn the_callers_events_reach_the_plane_session_in_order_and_a_lost_connection_is_gone() {
    let (_http, pipe) = pipe();
    let caller = pipe.caller();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(pipe.poll_message(&mut cx), Poll::Pending);
    let said = ClientEvent::Message {
        flags: MSG_TEXT | MSG_FIN,
        bytes: b"hi".to_vec(),
    };
    caller.try_send(said.clone()).unwrap();
    assert!(
        caller.try_send(ClientEvent::Closed).is_err(),
        "one event is held at a time: the caller is read no faster than the plane takes it"
    );
    assert_eq!(pipe.poll_message(&mut cx), Poll::Ready(said));
    caller.try_send(ClientEvent::Closed).unwrap();
    assert_eq!(pipe.poll_message(&mut cx), Poll::Ready(ClientEvent::Closed));
    assert_eq!(pipe.poll_message(&mut cx), Poll::Pending);
    // The connection's supervisor lets its side go (the connection dropped, or was never adopted):
    // the plane session is told the caller is gone, which is what ends it and settles its unit.
    drop(caller);
    assert_eq!(pipe.poll_message(&mut cx), Poll::Ready(ClientEvent::Gone));
}

// ---- the session's limit ----------------------------------------------------------------------

const LIMIT: Duration = Duration::from_secs(300);

/// A pipe whose session ends `LIMIT` from now, on the test's paused clock.
fn bounded() -> (Arc<Http>, Arc<UpgradePipe>, tokio::time::Instant) {
    let http = Arc::new(Http::default());
    let until = tokio::time::Instant::now() + LIMIT;
    let pipe = UpgradePipe::bounded(http.clone(), None, Some(until));
    (http, pipe, until)
}

async fn next_event(pipe: &UpgradePipe) -> ClientEvent {
    std::future::poll_fn(|cx| pipe.poll_message(cx)).await
}

/// An upgraded session is bounded. A session idle at its limit (a caller that is connected and
/// says nothing) is woken by the limit alone and told the caller is gone, which is the event that
/// ends the plane session and settles its unit; nothing more is written for it, its END included,
/// so the answer's delivery ends cut and the adopted transport closes as for a failure.
#[tokio::test(start_paused = true)]
async fn an_upgraded_session_is_ended_at_its_limit_with_its_plane_told_the_caller_is_gone() {
    let (http, pipe, until) = bounded();
    // The caller's side stays connected throughout: what ends the session is the limit.
    let caller = pipe.caller();
    let in_time = msg(MSG_TEXT | MSG_FIN, b"in time");
    assert_eq!(hand(&pipe, vec![head(101), in_time]), Poll::Ready(true));
    let said = ClientEvent::Message {
        flags: MSG_TEXT | MSG_FIN,
        bytes: b"hi".to_vec(),
    };
    caller.try_send(said.clone()).unwrap();
    assert_eq!(
        next_event(&pipe).await,
        said,
        "inside its limit it is served"
    );
    assert!(!pipe.limited());
    assert_eq!(next_event(&pipe).await, ClientEvent::Gone);
    let now = tokio::time::Instant::now();
    assert!(
        now >= until && now < until + Duration::from_secs(1),
        "at the limit, not before and not later"
    );
    assert!(pipe.limited());
    assert!(
        !caller.is_closed(),
        "the caller did not go: the engine cut it"
    );
    assert_eq!(
        hand(&pipe, vec![msg(MSG_TEXT | MSG_FIN, b"late")]),
        Poll::Ready(false),
        "nothing more is written"
    );
    assert_eq!(
        hand(&pipe, vec![ToClient::End]),
        Poll::Ready(false),
        "a session cut at its limit did not end in order: no END is written for it"
    );
    assert_eq!(
        http.taken(),
        vec![head(101), ToClient::Body(b"in time".to_vec())]
    );
    let kinds = pipe.kinds();
    assert_eq!(kinds.next(), Some(MSG_TEXT | MSG_FIN));
    assert_eq!(kinds.next(), None, "a refused message is not stated");
}

/// The other face: a session that is writing to the caller when its limit passes (the caller
/// closed its side, or the plane is not waiting for it) has the item refused, which its relay
/// reads as the caller gone. A caller that is still talking is cut all the same.
#[tokio::test(start_paused = true)]
async fn a_session_writing_past_its_limit_is_refused_and_a_talking_caller_is_cut_all_the_same() {
    let (http, pipe, _until) = bounded();
    let caller = pipe.caller();
    assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(true));
    tokio::time::advance(LIMIT - Duration::from_secs(1)).await;
    assert_eq!(
        hand(&pipe, vec![msg(MSG_BINARY | MSG_FIN, &[1])]),
        Poll::Ready(true),
        "one second inside the limit"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        hand(&pipe, vec![msg(MSG_BINARY | MSG_FIN, &[2])]),
        Poll::Ready(false)
    );
    assert!(pipe.limited());
    assert_eq!(http.taken(), vec![head(101), ToClient::Body(vec![1])]);
    // The caller has a message waiting: the limit comes first.
    caller
        .try_send(ClientEvent::Message {
            flags: MSG_TEXT | MSG_FIN,
            bytes: b"still here".to_vec(),
        })
        .unwrap();
    assert_eq!(next_event(&pipe).await, ClientEvent::Gone);
}

/// A session is not committed past its limit: the 101 itself is refused, so the caller is never
/// switched to a session that is already over.
#[tokio::test(start_paused = true)]
async fn a_101_past_the_limit_is_not_written() {
    let (http, pipe, _until) = bounded();
    tokio::time::advance(LIMIT).await;
    assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(false));
    assert!(!pipe.switched());
    assert!(http.taken().is_empty());
}

/// Before any 101 the limit is not the pipe's to enforce: the answer is HTTP's, bounded by the
/// request's own deadline on the data path, and a refusal is written whenever it comes.
#[tokio::test(start_paused = true)]
async fn an_http_answer_before_any_101_is_not_cut_by_the_sessions_limit() {
    let (http, pipe, _until) = bounded();
    tokio::time::advance(LIMIT + LIMIT).await;
    let answer = vec![head(504), ToClient::End];
    assert_eq!(hand(&pipe, answer.clone()), Poll::Ready(true));
    assert_eq!(http.taken(), answer);
}

/// A pipe with no limit (no connection stands behind it) is never cut by one.
#[tokio::test(start_paused = true)]
async fn a_pipe_no_connection_stands_behind_has_no_limit() {
    let (_http, pipe) = pipe();
    let caller = pipe.caller();
    assert_eq!(hand(&pipe, vec![head(101)]), Poll::Ready(true));
    tokio::time::advance(LIMIT + LIMIT).await;
    assert_eq!(
        hand(&pipe, vec![msg(MSG_TEXT | MSG_FIN, b"x")]),
        Poll::Ready(true)
    );
    caller.try_send(ClientEvent::Closed).unwrap();
    assert_eq!(next_event(&pipe).await, ClientEvent::Closed);
}

#[test]
fn what_the_adopted_session_hands_up_is_the_callers_message_close_or_loss() {
    let source = ProcessAdmission::new(0).connection_storage(AdmissionClass::Data);
    let body = |stream: u64, flags: u32, bytes: &[u8]| Inbound::Body {
        stream,
        flags,
        bytes: Payload::copy(&source, bytes).unwrap(),
    };
    assert_eq!(
        event_of(body(ADOPTED_STREAM, MSG_TEXT | MSG_FIN, b"hi")),
        ClientEvent::Message {
            flags: MSG_TEXT | MSG_FIN,
            bytes: b"hi".to_vec()
        }
    );
    assert_eq!(
        event_of(body(ADOPTED_STREAM, MSG_BINARY, &[0, 255])),
        ClientEvent::Message {
            flags: MSG_BINARY,
            bytes: vec![0, 255]
        }
    );
    assert_eq!(
        event_of(Inbound::End(ADOPTED_STREAM)),
        ClientEvent::Closed,
        "the caller's close frame"
    );
    assert_eq!(
        event_of(Inbound::Reset {
            stream: ADOPTED_STREAM,
            code: 1006
        }),
        ClientEvent::Gone
    );
    assert_eq!(
        event_of(Inbound::Stalled(ADOPTED_STREAM)),
        ClientEvent::Gone
    );
    assert_eq!(
        event_of(body(3, MSG_TEXT | MSG_FIN, b"x")),
        ClientEvent::Gone,
        "an adopted session has one stream: anything else is not the caller's message"
    );
    assert_eq!(event_of(Inbound::End(3)), ClientEvent::Gone);
}

#[test]
fn a_credential_the_routes_chain_read_is_never_handed_to_the_adopting_transport() {
    let pairs: [(&str, &[u8]); 5] = [
        ("Authorization", b"Bearer secret"),
        ("sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ("X-Api-Key", b"secret"),
        ("sec-websocket-protocol", b"realtime"),
        ("upgrade", b"websocket"),
    ];
    let withheld: Vec<Box<str>> = vec!["authorization".into(), "x-api-key".into()];
    let handed: Vec<&str> = handed_on(pairs.into_iter(), &withheld)
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        handed,
        ["sec-websocket-key", "sec-websocket-protocol", "upgrade"],
        "the handshake's own lines go to the transport that answers them; no credential does"
    );
}
