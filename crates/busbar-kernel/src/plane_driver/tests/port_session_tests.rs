// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §11.3: the once rules and the order of a session's answers, through a scripted plane. The plane
//! itself is exercised by the image arms; these run the part core owns.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::plane::{FROM_CLIENT, FROM_CORE, FROM_UPSTREAM, MSG_FIN, MSG_TEXT};
use busbar_plugin_loader::ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_plugin_loader::ports::{FactRef, FactVal, PortError};

use super::{
    deliver, run_local, Calls, Effects, Origin, SessionError, Task, ToClient, Violation,
};
use crate::plane_driver::{CallerEnd, HeadFields};

/// One scripted sink item.
#[derive(Clone)]
enum It {
    Respond(u16),
    Header(&'static str, &'static [u8]),
    Body(&'static [u8]),
    Msg(u32, &'static [u8]),
    Trailers,
    End,
    Forward,
    Want(u32, u64),
    Emit(u64, &'static [u8]),
    Finish,
    Usage,
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Header(n, v) => PlaneOut::Header(n, v),
            It::Body(b) => PlaneOut::Body(b),
            It::Msg(flags, b) => PlaneOut::Msg {
                flags: *flags,
                bytes: b,
            },
            It::Trailers => PlaneOut::Trailers,
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: true },
            It::Want(k, v) => PlaneOut::Want(*k, FactRef::U(*v)),
            It::Emit(carrier, b) => PlaneOut::Emit {
                carrier: *carrier,
                bytes: b,
            },
            It::Finish => PlaneOut::Finish,
            It::Usage => PlaneOut::Usage {
                class: "tokens",
                amount: 1,
                scale: 0,
                source: 0,
            },
        });
    }
}

/// A session handle that says when it was dropped (a drop without `end` is a cancel).
struct Live(Arc<AtomicBool>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Script {
    request: Vec<It>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    refuse_request: bool,
    dropped: Arc<AtomicBool>,
}

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl Calls for Script {
    type Session = Live;

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        if self.refuse_request {
            return Err(refused());
        }
        play(&self.request, sink);
        Ok(Live(Arc::clone(&self.dropped)))
    }

    fn piece(
        &self,
        _: &mut Live,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let items = self.pieces.lock().unwrap().pop_front().unwrap_or_default();
        play(&items, sink);
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut Live,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, s: Live, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        play(&self.end, sink);
        // `end` consumes the session: it is not a cancel.
        std::mem::forget(s);
        Ok(())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default)]
struct Emitted(Mutex<Vec<(u64, Vec<u8>)>>);

impl Effects for Emitted {
    fn emit(&self, carrier: u64, bytes: &[u8]) {
        self.0.lock().unwrap().push((carrier, bytes.to_vec()));
    }
}

fn req() -> PlaneIn<'static> {
    PlaneIn {
        route: 1,
        flags: 0,
        auth: 1,
        method: "POST",
        path: "/x",
        query: "",
        headers: &[],
        identity: &[],
        request_id: 1,
        carrier: 0,
        work: "",
        ticket_record: &[],
    }
}

fn pieces(script: &Script, answers: Vec<Vec<It>>) {
    *script.pieces.lock().unwrap() = answers.into();
}

#[test]
fn a_forward_with_its_wants_is_one_forward() {
    let script = Script {
        request: vec![It::Forward, It::Want(0x100, 7)],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (task, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    let forward = first.forward.unwrap();
    assert!(forward.stream);
    assert_eq!(forward.wants, vec![(0x100, FactVal::U(7))]);
    assert!(first.client.is_empty());
    assert!(task.open());
}

#[test]
fn a_second_forward_ends_the_session_and_cancels_it() {
    let script = Script {
        request: vec![It::Forward],
        ..Script::default()
    };
    pieces(&script, vec![vec![It::Forward]]);
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    let err = task.piece(FROM_CORE, 0, 0, b"", &fx).unwrap_err();
    assert!(matches!(
        err,
        SessionError::Violation(Violation::SecondForward)
    ));
    assert!(!task.open());
    assert!(script.dropped.load(Ordering::SeqCst), "cancelled by drop");
    assert!(matches!(task.end(&fx), Err(SessionError::Over)));
}

#[test]
fn a_deferred_forward_in_a_from_core_answer_is_the_first_forward() {
    let script = Script::default();
    pieces(&script, vec![vec![It::Forward, It::Want(0x104, 3)]]);
    let fx = Emitted::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert!(first.forward.is_none());
    let answer = task.piece(FROM_CORE, 0, 0, b"", &fx).unwrap();
    assert_eq!(answer.forward.unwrap().wants, vec![(0x104, FactVal::U(3))]);
}

#[test]
fn a_forward_after_the_response_began_is_late() {
    let script = Script {
        request: vec![It::Respond(200)],
        ..Script::default()
    };
    pieces(&script, vec![vec![It::Forward]]);
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    let err = task.piece(FROM_CORE, 0, 0, b"", &fx).unwrap_err();
    assert!(matches!(
        err,
        SessionError::Violation(Violation::LateForward)
    ));
    assert!(script.dropped.load(Ordering::SeqCst));
}

#[test]
fn a_forward_beside_a_to_client_item_is_late() {
    let script = Script {
        request: vec![It::Respond(200), It::Forward],
        ..Script::default()
    };
    let fx = Emitted::default();
    let err = Task::begin(&script, &req(), b"", &fx).err().unwrap();
    assert!(matches!(
        err,
        SessionError::Violation(Violation::LateForward)
    ));
    assert!(script.dropped.load(Ordering::SeqCst));
}

#[test]
fn a_forward_in_a_client_or_upstream_answer_is_out_of_place() {
    for from in [FROM_CLIENT, FROM_UPSTREAM] {
        let script = Script::default();
        pieces(&script, vec![vec![It::Forward]]);
        let fx = Emitted::default();
        let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
        let err = task.piece(from, 0, 0, b"", &fx).unwrap_err();
        assert!(matches!(
            err,
            SessionError::Violation(Violation::ForwardOutOfPlace(Origin::Piece(f))) if f == from
        ));
    }
}

#[test]
fn a_forward_in_the_end_answer_is_out_of_place() {
    let script = Script {
        end: vec![It::Forward],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert!(matches!(
        task.end(&fx),
        Err(SessionError::Violation(Violation::ForwardOutOfPlace(
            Origin::End
        )))
    ));
}

#[test]
fn a_body_after_the_response_end_is_refused() {
    let script = Script {
        request: vec![It::Respond(200), It::End],
        end: vec![It::Body(b"late")],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert!(matches!(
        task.end(&fx),
        Err(SessionError::Violation(Violation::AfterEnd))
    ));
}

#[test]
fn trailers_follow_the_body_and_carry_the_headers_after_them() {
    let script = Script {
        request: vec![
            It::Respond(200),
            It::Header("content-type", b"application/grpc"),
            It::Body(b"b"),
            It::Trailers,
            It::Header("grpc-status", b"0"),
            It::End,
        ],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (_, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert_eq!(
        first.client,
        vec![
            ToClient::Head {
                status: 200,
                fields: vec![(b"content-type".to_vec(), b"application/grpc".to_vec())],
            },
            ToClient::Body(b"b".to_vec()),
            ToClient::Trailers(vec![(b"grpc-status".to_vec(), b"0".to_vec())]),
            ToClient::End,
        ]
    );
}

#[test]
fn a_trailers_only_answer_has_a_head_then_trailers_and_no_body() {
    let script = Script {
        request: vec![
            It::Respond(200),
            It::Header("content-type", b"application/grpc"),
            It::Trailers,
            It::Header("grpc-status", b"7"),
            It::End,
        ],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (_, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert!(matches!(first.client[0], ToClient::Head { status: 200, .. }));
    assert!(matches!(first.client[1], ToClient::Trailers(_)));
    assert_eq!(first.client[2], ToClient::End);
    assert_eq!(first.client.len(), 3);
}

#[test]
fn an_emit_reaches_its_effect_in_sink_order_and_is_not_a_client_item() {
    let script = Script {
        request: vec![It::Emit(5, b"a"), It::Body(b"r"), It::Emit(5, b"b")],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (_, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert_eq!(
        *fx.0.lock().unwrap(),
        vec![(5, b"a".to_vec()), (5, b"b".to_vec())]
    );
    assert_eq!(first.client, vec![ToClient::Body(b"r".to_vec())]);
}

#[test]
fn a_refused_request_has_no_session() {
    let script = Script {
        refuse_request: true,
        ..Script::default()
    };
    let fx = Emitted::default();
    assert!(matches!(
        Task::begin(&script, &req(), b"", &fx).err(),
        Some(SessionError::Port(PortError::Refused { .. }))
    ));
}

#[test]
fn a_local_answer_joins_the_request_and_end_answers_in_order() {
    let script = Script {
        request: vec![It::Respond(200), It::Body(b"a")],
        end: vec![It::Body(b"b"), It::End, It::Finish],
        ..Script::default()
    };
    let fx = Emitted::default();
    let local = run_local(&script, &req(), b"", &fx).unwrap();
    assert_eq!(
        local.client,
        vec![
            ToClient::Head {
                status: 200,
                fields: Vec::new()
            },
            ToClient::Body(b"a".to_vec()),
            ToClient::Body(b"b".to_vec()),
            ToClient::End,
        ]
    );
    assert!(!script.dropped.load(Ordering::SeqCst), "ended, not cancelled");
}

#[test]
fn a_forward_or_an_undriven_item_is_not_a_local_answer() {
    for request in [vec![It::Forward], vec![It::Usage]] {
        let script = Script {
            request,
            ..Script::default()
        };
        let fx = Emitted::default();
        assert!(matches!(
            run_local(&script, &req(), b"", &fx),
            Err(SessionError::NotDriven)
        ));
        assert!(script.dropped.load(Ordering::SeqCst));
    }
}

#[derive(Default)]
struct Client {
    seen: Mutex<Vec<String>>,
}

impl CallerEnd for Client {
    fn head(&self, status: u32, fields: HeadFields) {
        self.seen
            .lock()
            .unwrap()
            .push(format!("head {status} {}", fields.len()));
    }

    fn write<'a>(&'a self, bytes: &'a [u8]) -> impl std::future::Future<Output = bool> + Send + 'a {
        self.seen
            .lock()
            .unwrap()
            .push(format!("write {}", bytes.len()));
        std::future::ready(true)
    }

    fn write_text<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = bool> + Send + 'a {
        self.seen
            .lock()
            .unwrap()
            .push(format!("text {}", bytes.len()));
        std::future::ready(true)
    }

    fn trailers(&self, fields: HeadFields) {
        self.seen
            .lock()
            .unwrap()
            .push(format!("trailers {}", fields.len()));
    }
}

#[tokio::test]
async fn delivery_hands_the_client_head_body_message_and_trailers_in_order() {
    let client = Client::default();
    let items = vec![
        ToClient::Head {
            status: 200,
            fields: vec![(b"a".to_vec(), b"b".to_vec())],
        },
        ToClient::Body(b"xyz".to_vec()),
        ToClient::Msg {
            flags: MSG_TEXT | MSG_FIN,
            bytes: b"hi".to_vec(),
        },
        ToClient::Trailers(vec![(b"s".to_vec(), b"0".to_vec())]),
        ToClient::End,
    ];
    assert!(deliver(&client, items).await);
    assert_eq!(
        *client.seen.lock().unwrap(),
        vec!["head 200 1", "write 3", "text 2", "trailers 1"]
    );
}
