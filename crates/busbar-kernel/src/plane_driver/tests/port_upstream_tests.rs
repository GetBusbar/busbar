// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6 upstream exchanges over the plane port: what an `upstream` or `piece` answer asks core to send, which
//! member is tried next, what the far end's reply is fed back as, and the probe. The plane is scripted; the far
//! end and the member walk are fakes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_plugin_abi::plane::{
    ATT_DECLINE, ATT_HARD, ATT_OK, ATT_RETRY, FC_RATE_LIMIT, FC_SERVER, FROM_CLIENT, FROM_UPSTREAM,
    F_PROBE_OK, P_BODY, P_END, P_HEAD, W_AFFINITY, W_CAPABILITY, W_MAX_TOKENS, W_MODEL, W_STREAM,
    W_UPSTREAM,
};
use busbar_plugin_abi::records::{tag as g, Records};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, FactVal, PortError};

use super::{
    probe_wait, Attempted, Candidate, Failure, Members, ProbeOutcome, SendFailed, UpReply, UpSend,
    Wants, Whole,
};
use crate::plane_driver::port_session::{
    finish, Calls, Effects, Origin, SessionError, Task, ToClient, UpExchange, Violation,
};

/// The attempt walk, driven to its end on a test runtime.
fn run_attempts<K: Calls + ?Sized, M: Members, S: UpSend>(
    task: &mut Task<'_, K>,
    wants: &Wants,
    dialect: &str,
    model: &str,
    members: &mut M,
    send: &mut S,
    effects: &dyn Effects,
) -> Result<Attempted, SessionError> {
    finish(super::run_attempts(
        task, wants, dialect, model, members, send, effects,
    ))
}

/// One probe, driven to its end on a test runtime.
fn probe_member<K: Calls + ?Sized, S: UpSend>(
    calls: &K,
    member: &Candidate,
    dialect: &str,
    model: &str,
    send: &mut S,
    effects: &dyn Effects,
) -> Result<ProbeOutcome, SessionError> {
    finish(super::probe_member(
        calls, member, dialect, model, send, effects,
    ))
}
use crate::retry::{Retry, RetryPolicy, RetrySite};

#[derive(Clone)]
enum It {
    Respond(u16),
    Header(&'static str, &'static [u8]),
    Body(&'static [u8]),
    End,
    Forward,
    UpCarrier(u32, u32),
    UpMethod(&'static str),
    UpPath(&'static str),
    UpScope(&'static str),
    UpBody(&'static [u8]),
    UpEnd,
    UpCut,
    UpNew(u32, u32, u32),
    ExMsg(u32, u32, u64, &'static [u8]),
    Fact(u32, u64),
    Attempt(u32, u32, u64),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Header(n, v) => PlaneOut::Header(n, v),
            It::Body(b) => PlaneOut::Body(b),
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: false },
            It::UpCarrier(carrier, outbound) => PlaneOut::UpCarrier {
                carrier: *carrier,
                outbound: *outbound,
            },
            It::UpMethod(m) => PlaneOut::UpMethod(m),
            It::UpPath(p) => PlaneOut::UpPath(p),
            It::UpScope(s) => PlaneOut::UpScope(s),
            It::UpBody(b) => PlaneOut::UpBody(b),
            It::UpEnd => PlaneOut::UpEnd,
            It::UpCut => PlaneOut::UpCut,
            It::UpNew(exchange, carrier, outbound) => PlaneOut::UpNew {
                exchange: *exchange,
                carrier: *carrier,
                outbound: *outbound,
            },
            It::ExMsg(exchange, flags, stream, b) => PlaneOut::ExMsg {
                exchange: *exchange,
                flags: *flags,
                stream: *stream,
                bytes: b,
            },
            It::Fact(k, v) => PlaneOut::Fact(*k, FactRef::U(*v)),
            It::Attempt(verdict, class, retry_after_s) => PlaneOut::Attempt {
                verdict: *verdict,
                class: *class,
                retry_after_s: *retry_after_s,
                reason: "why",
            },
        });
    }
}

struct Live(Arc<AtomicBool>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The pieces the plane was handed, one entry per call.
type PieceLog = Mutex<Vec<(u32, u32, u32, Vec<u8>)>>;

#[derive(Default)]
struct Plane {
    selected: bool,
    request: Vec<It>,
    upstream: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    probe: Vec<It>,
    piece_log: PieceLog,
    targets: Mutex<Vec<(u32, String, String)>>,
    dropped: Arc<AtomicBool>,
}

fn nope() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl Calls for Plane {
    type Session = Live;

    fn usage_metadata(&self) -> (u64, Arc<[busbar_ports::plane::UsageClass]>, Arc<[Box<str>]>) {
        (
            if self.selected {
                busbar_plugin_abi::plane::FB_PREPARED_ESTIMATES
            } else {
                0
            },
            Arc::default(),
            Arc::default(),
        )
    }

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        play(&self.request, sink);
        Ok(Live(Arc::clone(&self.dropped)))
    }

    fn piece(
        &self,
        _: &mut Live,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.piece_log
            .lock()
            .unwrap()
            .push((from, exchange, flags, bytes.to_vec()));
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
        std::mem::forget(s);
        Ok(())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }

    fn upstream(
        &self,
        _: &mut Live,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.targets
            .lock()
            .unwrap()
            .push((t.attempt, t.upstream.into(), t.model.into()));
        let items = self
            .upstream
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        if self.selected
            && !items
                .iter()
                .any(|item| matches!(item, It::Attempt(ATT_DECLINE, _, _)))
        {
            use busbar_plugin_abi::fallback_usage as wire;
            let selected = wire::selected_from_admission(t.admission).unwrap().unwrap();
            sink(PlaneOut::SelectedResource(selected));
            let mut records = busbar_plugin_abi::records::Reply::new();
            wire::write_prepared_estimates(&mut records, selected, &[]).unwrap();
            let record = Records::new(records.as_bytes()).next().unwrap().unwrap();
            sink(PlaneOut::PreparedEstimates(
                wire::decode_prepared(record).unwrap(),
            ));
        }
        play(&items, sink);
        Ok(())
    }

    fn probe(
        &self,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Live, PortError> {
        self.targets
            .lock()
            .unwrap()
            .push((t.attempt, t.upstream.into(), t.model.into()));
        play(&self.probe, sink);
        Ok(Live(Arc::clone(&self.dropped)))
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
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

fn candidate(name: &str) -> Candidate {
    Candidate {
        pool: "pool".into(),
        qualified_member: "fixture-member".into(),
        identity: crate::plane_driver::port_upstream::TargetIdentity::Registration,
        resource: None,
        upstream: name.into(),
        provider: "{}".into(),
        base_path: "/v1".into(),
        flags: 0,
        params: vec![("region".into(), "eu".into())],
    }
}

fn queue(plane: &Plane, answers: Vec<Vec<It>>) {
    *plane.upstream.lock().unwrap() = answers.into();
}

fn pieces(plane: &Plane, answers: Vec<Vec<It>>) {
    *plane.pieces.lock().unwrap() = answers.into();
}

fn head(status: &str) -> Vec<It> {
    vec![
        It::UpMethod("POST"),
        It::UpPath(Box::leak(format!("/{status}").into_boxed_str())),
    ]
}

#[derive(Default)]
struct Walk {
    queue: VecDeque<Candidate>,
    declined: Vec<String>,
    failed: Vec<(String, u32, u32, u64)>,
    served: Vec<String>,
}

impl Members for Walk {
    async fn next(&mut self, _: &Wants) -> Option<Candidate> {
        self.queue.pop_front()
    }

    fn declined(&mut self, c: &Candidate) {
        self.declined.push(c.upstream.to_string());
    }

    fn failed(&mut self, c: &Candidate, f: &Failure) {
        self.failed
            .push((c.upstream.to_string(), f.verdict, f.class, f.retry_after_s));
    }

    fn served(&mut self, c: &Candidate) {
        self.served.push(c.upstream.to_string());
    }
}

fn walk(names: &[&str]) -> Walk {
    Walk {
        queue: names.iter().map(|n| candidate(n)).collect(),
        ..Walk::default()
    }
}

struct Far {
    replies: VecDeque<Result<UpReply, SendFailed>>,
    sent: Vec<(String, String, String, Vec<u8>)>,
}

impl UpSend for Far {
    type Rest<'a> = Whole;

    async fn open<'a>(
        &'a mut self,
        c: &'a Candidate,
        ex: UpExchange,
    ) -> Result<UpOpen<Whole>, SendFailed> {
        self.sent.push((
            c.upstream.to_string(),
            ex.method.as_deref().unwrap_or_default().to_string(),
            ex.path.as_deref().unwrap_or_default().to_string(),
            ex.body.clone(),
        ));
        self.replies
            .pop_front()
            .unwrap_or(Err(SendFailed))
            .map(UpReply::opened)
    }
}

fn far(replies: Vec<Result<UpReply, SendFailed>>) -> Far {
    Far {
        replies: replies.into(),
        sent: Vec::new(),
    }
}

fn reply(status: u16, body: &[u8]) -> Result<UpReply, SendFailed> {
    Ok(UpReply {
        status,
        headers: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        body: body.to_vec(),
    })
}

#[test]
fn selected_quota_skips_do_not_damage_the_breaker_and_infrastructure_stops() {
    use crate::plane_driver::port_egress::{
        OwnedPreparation, SelectedFailure, SelectedOpen, SelectedSendError,
    };
    struct Refuse(bool);
    impl UpSend for Refuse {
        type Rest<'a> = Whole;

        async fn open<'a>(
            &'a mut self,
            _: &'a Candidate,
            _: UpExchange,
        ) -> Result<UpOpen<Whole>, SendFailed> {
            panic!("no legacy send")
        }
        async fn open_selected<'a>(
            &'a mut self,
            _: OwnedPreparation,
        ) -> Result<SelectedOpen<Whole>, SelectedSendError> {
            Err(SelectedSendError(if self.0 {
                SelectedFailure::Quota
            } else {
                SelectedFailure::Backend
            }))
        }
    }
    for quota in [true, false] {
        let plane = Plane {
            selected: true,
            request: vec![It::Forward],
            upstream: Mutex::new(VecDeque::from([
                vec![It::Attempt(ATT_DECLINE, 0, 0)],
                vec![It::UpMethod("POST"), It::UpPath("/"), It::UpEnd],
                vec![It::UpMethod("POST"), It::UpPath("/"), It::UpEnd],
            ])),
            ..Plane::default()
        };
        let mut members = walk(&["declined", "blocked", "later"]);
        let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
        let result = run_attempts(
            &mut task,
            &Wants::default(),
            "chat",
            "m",
            &mut members,
            &mut Refuse(quota),
            &Quiet,
        );
        if quota {
            assert!(matches!(
                result,
                Ok(Attempted::Exhausted {
                    attempts: 3,
                    local_quota: true
                })
            ));
            assert_eq!(members.declined, ["declined", "blocked", "later"]);
        } else {
            assert!(matches!(result, Err(SessionError::SelectedRefused(_))));
            assert_eq!(members.declined, ["declined"]);
            assert_eq!(members.queue.len(), 1);
        }
        assert!(members.failed.is_empty());
        assert!(members.served.is_empty());
    }
}

fn target() -> TargetIn<'static> {
    TargetIn {
        attempt: 1,
        flags: 0,
        dialect: "chat",
        model: "m",
        base_path: "",
        upstream: "u",
        provider: "{}",
        params: &[],
        admission: &[],
    }
}

// ---- the decoded exchange ------------------------------------------------------------------------------

#[test]
fn an_upstream_answer_is_exchange_zero_with_its_head_fields_and_body() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(
        &plane,
        vec![vec![
            It::UpCarrier(1, 0),
            It::UpMethod("POST"),
            It::UpPath("/v1/chat"),
            It::UpScope("s"),
            It::Header("x-a", b"b"),
            It::UpBody(b"{}"),
            It::UpEnd,
        ]],
    );
    let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
    let answer = task.upstream(&target(), &Quiet).unwrap();
    let ex = &answer.exchanges[0];
    assert_eq!((ex.id, ex.carrier, ex.outbound), (0, 1, 0));
    assert_eq!(ex.method.as_deref(), Some("POST"));
    assert_eq!(ex.path.as_deref(), Some("/v1/chat"));
    assert_eq!(ex.scope.as_deref(), Some("s"));
    assert_eq!(ex.headers, vec![(b"x-a".to_vec(), b"b".to_vec())]);
    assert_eq!(ex.body, b"{}".to_vec());
    assert!(ex.end && !ex.cut);
    assert!(
        answer.client.is_empty(),
        "no header leaks into the client head"
    );
}

#[test]
fn a_new_exchange_and_its_messages_and_a_cut_are_decoded_in_order() {
    let plane = Plane::default();
    pieces(
        &plane,
        vec![vec![
            It::UpNew(2, 3, 1),
            It::UpMethod("GET"),
            It::UpPath("/ws"),
            It::ExMsg(2, 1, 7, b"hi"),
            It::UpCut,
        ]],
    );
    let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
    let answer = task.piece(FROM_CLIENT, 0, 0, b"", &Quiet).unwrap();
    let ex = &answer.exchanges[0];
    assert_eq!((ex.id, ex.carrier, ex.outbound), (2, 3, 1));
    assert!(ex.cut);
    assert_eq!(answer.ex_msgs.len(), 1);
    assert_eq!(
        (
            answer.ex_msgs[0].exchange,
            answer.ex_msgs[0].stream,
            &answer.ex_msgs[0].bytes[..]
        ),
        (2, 7, &b"hi"[..])
    );
}

#[test]
fn client_head_fields_and_an_exchange_s_fields_do_not_mix() {
    let plane = Plane::default();
    pieces(
        &plane,
        vec![vec![
            It::Respond(200),
            It::Header("x-client", b"1"),
            It::UpNew(1, 0, 0),
            It::UpMethod("GET"),
            It::UpPath("/p"),
            It::Header("x-up", b"2"),
        ]],
    );
    let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
    let answer = task.piece(FROM_CLIENT, 0, 0, b"", &Quiet).unwrap();
    assert_eq!(
        answer.client[0],
        ToClient::Head {
            status: 200,
            fields: vec![(b"x-client".to_vec(), b"1".to_vec())]
        }
    );
    assert_eq!(
        answer.exchanges[0].headers,
        vec![(b"x-up".to_vec(), b"2".to_vec())]
    );
}

#[test]
fn a_body_only_piece_answer_belongs_to_the_exchange_the_piece_named() {
    let plane = Plane::default();
    pieces(&plane, vec![vec![It::UpBody(b"more"), It::UpEnd]]);
    let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
    let answer = task.piece(FROM_CLIENT, 3, 0, b"", &Quiet).unwrap();
    assert_eq!(answer.exchanges[0].id, 3);
    assert_eq!(answer.exchanges[0].body, b"more".to_vec());
    assert!(answer.exchanges[0].end);
}

#[test]
fn an_exchange_in_a_request_answer_is_out_of_place() {
    let plane = Plane {
        request: vec![It::UpMethod("GET")],
        ..Plane::default()
    };
    assert!(matches!(
        Task::begin(&plane, &req(), b"", &Quiet).err().unwrap(),
        SessionError::Violation(Violation::UpstreamOutOfPlace(Origin::Request))
    ));
    assert!(plane.dropped.load(Ordering::SeqCst));
}

#[test]
fn exchange_zero_cannot_be_started_by_up_new() {
    let plane = Plane::default();
    pieces(&plane, vec![vec![It::UpNew(0, 0, 0)]]);
    let (mut task, _) = Task::begin(&plane, &req(), b"", &Quiet).unwrap();
    assert!(matches!(
        task.piece(FROM_CLIENT, 0, 0, b"", &Quiet).unwrap_err(),
        SessionError::Violation(Violation::BadExchange)
    ));
}

// ---- wants and the target ---------------------------------------------------------------------------

#[test]
fn wants_are_read_as_typed_facts_and_a_wrong_shape_or_an_unknown_key_is_ignored() {
    let wants = Wants::from_facts(&[
        (W_MODEL, FactVal::Text("gpt".into())),
        (W_STREAM, FactVal::U(1)),
        (W_CAPABILITY, FactVal::Text("vision".into())),
        (W_MAX_TOKENS, FactVal::U(900)),
        (W_UPSTREAM, FactVal::Text("pin".into())),
        (W_AFFINITY, FactVal::Text("k".into())),
        (0x1FF, FactVal::U(5)),
    ]);
    assert_eq!(wants.model.as_deref(), Some("gpt"));
    assert!(wants.stream);
    assert_eq!(wants.capability.as_deref(), Some("vision"));
    assert_eq!(wants.max_tokens, Some(900));
    assert_eq!(wants.upstream.as_deref(), Some("pin"));
    assert_eq!(wants.affinity.as_deref(), Some("k"));
    let wrong = Wants::from_facts(&[
        (W_MODEL, FactVal::U(1)),
        (W_STREAM, FactVal::Text("yes".into())),
        (W_AFFINITY, FactVal::Text("a".repeat(257).into())),
    ]);
    assert_eq!(wrong.model, None);
    assert!(!wrong.stream);
    assert_eq!(wrong.affinity, None);
}

#[test]
fn a_candidate_is_the_plane_s_target_with_its_params() {
    let seen = candidate("openai").with_target(2, "chat", "m", |t| {
        (
            t.attempt,
            t.dialect.to_string(),
            t.model.to_string(),
            t.base_path.to_string(),
            t.upstream.to_string(),
            t.provider.to_string(),
            t.params.len(),
            t.params[0].name.get().to_string(),
            t.params[0].value.get().to_vec(),
        )
    });
    assert_eq!(
        seen,
        (
            2,
            "chat".into(),
            "m".into(),
            "/v1".into(),
            "openai".into(),
            "{}".into(),
            1,
            "region".into(),
            b"eu".to_vec()
        )
    );
}

// ---- the attempt walk ---------------------------------------------------------------------------------

fn begin(plane: &Plane) -> Task<'_, Plane> {
    Task::begin(plane, &req(), b"", &Quiet).unwrap().0
}

#[test]
fn a_member_the_plane_declines_is_never_dialled_and_the_next_is_tried() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(
        &plane,
        vec![vec![It::Attempt(ATT_DECLINE, 0, 0)], head("ok")],
    );
    pieces(
        &plane,
        vec![
            vec![],
            vec![],
            vec![It::Respond(200), It::Body(b"r"), It::End],
        ],
    );
    let mut members = walk(&["a", "b"]);
    let mut far = far(vec![reply(200, b"{}")]);
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &Quiet,
    )
    .unwrap();
    assert_eq!(members.declined, vec!["a"]);
    assert_eq!(members.served, vec!["b"]);
    assert_eq!(far.sent.len(), 1);
    assert_eq!(far.sent[0].0, "b");
    let Attempted::Served {
        client, attempts, ..
    } = out
    else {
        panic!("served");
    };
    assert_eq!(attempts, 2);
    assert_eq!(client[1], ToClient::Body(b"r".to_vec()));
    let numbers: Vec<u32> = plane.targets.lock().unwrap().iter().map(|t| t.0).collect();
    assert_eq!(numbers, vec![1, 2]);
}

#[test]
fn a_retry_verdict_moves_to_the_next_member_and_a_hard_one_names_its_class_and_wait() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(&plane, vec![head("one"), head("two"), head("three")]);
    pieces(
        &plane,
        vec![
            vec![],
            vec![],
            vec![It::Attempt(ATT_RETRY, FC_SERVER, 0)],
            vec![],
            vec![],
            vec![It::Attempt(ATT_HARD, FC_RATE_LIMIT, 30)],
            vec![],
            vec![],
            vec![It::Respond(200), It::End],
        ],
    );
    let mut members = walk(&["a", "b", "c"]);
    let mut far = far(vec![reply(500, b"x"), reply(429, b"y"), reply(200, b"z")]);
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &Quiet,
    )
    .unwrap();
    assert_eq!(
        members.failed,
        vec![
            ("a".to_string(), ATT_RETRY, FC_SERVER, 0),
            ("b".to_string(), ATT_HARD, FC_RATE_LIMIT, 30)
        ]
    );
    assert_eq!(members.served, vec!["c"]);
    assert!(matches!(out, Attempted::Served { attempts: 3, .. }));
}

#[test]
fn the_far_end_s_reply_is_fed_back_as_head_then_body_then_end() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(&plane, vec![head("ok")]);
    pieces(
        &plane,
        vec![vec![], vec![], vec![It::Respond(200), It::End]],
    );
    let mut members = walk(&["a"]);
    let mut far = far(vec![reply(201, b"body")]);
    let mut task = begin(&plane);
    run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &Quiet,
    )
    .unwrap();
    let log = plane.piece_log.lock().unwrap();
    let shape: Vec<(u32, u32, u32)> = log.iter().map(|p| (p.0, p.1, p.2)).collect();
    assert_eq!(
        shape,
        vec![
            (FROM_UPSTREAM, 0, P_HEAD),
            (FROM_UPSTREAM, 0, P_BODY),
            (FROM_UPSTREAM, 0, P_END)
        ]
    );
    assert_eq!(log[1].3, b"body".to_vec());
    let mut recs = Records::new(&log[0].3);
    let status = recs.next().unwrap().unwrap();
    assert_eq!(status.tag, g::H_STATUS);
    assert_eq!(recs.next().unwrap().unwrap().tag, g::PAIR);
}

#[test]
fn a_send_that_fails_before_any_reply_fails_over_without_asking_the_plane() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(&plane, vec![head("one"), head("two")]);
    pieces(
        &plane,
        vec![vec![], vec![], vec![It::Respond(200), It::End]],
    );
    let mut members = walk(&["a", "b"]);
    let mut far = far(vec![Err(SendFailed), reply(200, b"")]);
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &Quiet,
    )
    .unwrap();
    assert_eq!(members.failed.len(), 1);
    assert_eq!(members.failed[0].0, "a");
    assert_eq!(members.failed[0].1, ATT_RETRY);
    assert_eq!(members.served, vec!["b"]);
    assert!(matches!(out, Attempted::Served { attempts: 2, .. }));
    // Nothing was pushed to the plane for the failed send: the first piece is the second member's head.
    assert_eq!(plane.piece_log.lock().unwrap()[0].2, P_HEAD);
}

#[test]
fn an_empty_walk_is_exhaustion() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    let mut members = walk(&[]);
    let mut far = far(vec![]);
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &Quiet,
    )
    .unwrap();
    assert!(matches!(
        out,
        Attempted::Exhausted {
            attempts: 0,
            local_quota: false
        }
    ));
}

#[test]
fn an_ok_verdict_serves_and_the_plane_s_failure_is_the_error() {
    let plane = Plane {
        request: vec![It::Forward],
        ..Plane::default()
    };
    queue(&plane, vec![head("ok")]);
    pieces(
        &plane,
        vec![
            vec![],
            vec![],
            vec![It::Attempt(ATT_OK, 0, 0), It::Respond(200), It::End],
        ],
    );
    let mut members = walk(&["a"]);
    let mut far = far(vec![reply(200, b"x")]);
    let mut task = begin(&plane);
    assert!(matches!(
        run_attempts(
            &mut task,
            &Wants::default(),
            "chat",
            "m",
            &mut members,
            &mut far,
            &Quiet
        )
        .unwrap(),
        Attempted::Served { .. }
    ));
}

// ---- probe -----------------------------------------------------------------------------------------------

#[test]
fn a_probe_sends_the_plane_s_request_and_the_end_answer_says_whether_the_member_is_well() {
    for (ok, want) in [(1, ProbeOutcome::Healthy), (0, ProbeOutcome::Unhealthy)] {
        let plane = Plane {
            probe: head("ping"),
            end: vec![It::Fact(F_PROBE_OK, ok)],
            ..Plane::default()
        };
        pieces(&plane, vec![vec![], vec![], vec![]]);
        let mut far = far(vec![reply(200, b"pong")]);
        let got = probe_member(&plane, &candidate("a"), "chat", "m", &mut far, &Quiet).unwrap();
        assert_eq!(got, want);
        assert_eq!(far.sent[0].2, "/ping");
        assert!(
            !plane.dropped.load(Ordering::SeqCst),
            "ended, not cancelled"
        );
    }
}

#[test]
fn a_probe_the_plane_declines_or_the_far_end_never_answers_is_not_a_verdict() {
    let declining = Plane {
        probe: vec![It::Attempt(ATT_DECLINE, 0, 0)],
        ..Plane::default()
    };
    let mut quiet = far(vec![]);
    assert_eq!(
        probe_member(&declining, &candidate("a"), "chat", "m", &mut quiet, &Quiet).unwrap(),
        ProbeOutcome::Declined
    );
    let silent = Plane {
        probe: head("ping"),
        ..Plane::default()
    };
    let mut none = far(vec![Err(SendFailed)]);
    assert_eq!(
        probe_member(&silent, &candidate("a"), "chat", "m", &mut none, &Quiet).unwrap(),
        ProbeOutcome::Unhealthy
    );
    assert!(
        silent.dropped.load(Ordering::SeqCst),
        "a probe with no reply is cancelled"
    );
}

struct Policy;

impl RetryPolicy for Policy {
    fn next(&self, site: RetrySite, attempt: u32, _: &PortError) -> Retry {
        assert_eq!(site, RetrySite::PlaneProbe);
        if attempt < 3 {
            Retry::After(Duration::from_secs(u64::from(attempt)))
        } else {
            Retry::Stop
        }
    }
}

#[test]
fn a_failed_probe_call_waits_by_the_probe_site_of_the_retry_policy() {
    assert_eq!(
        probe_wait(&Policy, 1, &nope()),
        Some(Duration::from_secs(1))
    );
    assert_eq!(probe_wait(&Policy, 3, &nope()), None);
}

// ---- streamed replies ---------------------------------------------------------------------------------

use super::{Chunk, UpChunks, UpOpen};
use crate::plane_driver::port_session::ClientSink;
use busbar_plugin_abi::plane::{P_ERROR, P_TRAILERS};

/// A client sink that keeps what it was handed, in order.
#[derive(Default)]
struct Tap {
    got: Mutex<Vec<ToClient>>,
    gone: AtomicBool,
}

impl ClientSink for Tap {
    fn poll_items(
        &self,
        _: &mut std::task::Context<'_>,
        items: &mut Vec<ToClient>,
    ) -> std::task::Poll<bool> {
        self.got.lock().unwrap().append(items);
        std::task::Poll::Ready(!self.gone.load(Ordering::SeqCst))
    }
}

struct Streaming(Arc<Tap>);

impl Effects for Streaming {
    fn emit(&self, _: u64, _: &[u8]) {}

    fn client(&self) -> Option<&dyn ClientSink> {
        Some(&*self.0)
    }
}

/// How many items the sink held each time the far end was asked for its next chunk.
type Seen = Arc<Mutex<Vec<usize>>>;

struct Reader {
    items: VecDeque<Result<Chunk, SendFailed>>,
    tap: Arc<Tap>,
    seen: Seen,
}

impl UpChunks for Reader {
    async fn next(&mut self) -> Result<Option<Chunk>, SendFailed> {
        self.seen
            .lock()
            .unwrap()
            .push(self.tap.got.lock().unwrap().len());
        match self.items.pop_front() {
            None => Ok(None),
            Some(Ok(chunk)) => Ok(Some(chunk)),
            Some(Err(e)) => Err(e),
        }
    }
}

/// A carrier that streams: each reply is a status and the chunks it yields after its head.
struct Streamer {
    replies: VecDeque<(u16, Vec<Result<Chunk, SendFailed>>)>,
    tap: Arc<Tap>,
    seen: Seen,
}

impl UpSend for Streamer {
    type Rest<'a> = Reader;

    async fn open<'a>(
        &'a mut self,
        _: &'a Candidate,
        _: UpExchange,
    ) -> Result<UpOpen<Reader>, SendFailed> {
        let (status, chunks) = self.replies.pop_front().ok_or(SendFailed)?;
        Ok(UpOpen {
            status,
            headers: vec![(b"content-type".to_vec(), b"text/event-stream".to_vec())],
            rest: Reader {
                items: chunks.into(),
                tap: Arc::clone(&self.tap),
                seen: Arc::clone(&self.seen),
            },
        })
    }
}

fn streamer(replies: Vec<(u16, Vec<Result<Chunk, SendFailed>>)>) -> (Streamer, Arc<Tap>, Seen) {
    let tap = Arc::new(Tap::default());
    let seen = Seen::default();
    (
        Streamer {
            replies: replies.into(),
            tap: Arc::clone(&tap),
            seen: Arc::clone(&seen),
        },
        tap,
        seen,
    )
}

fn forwarding() -> Plane {
    Plane {
        request: vec![It::Forward],
        ..Plane::default()
    }
}

fn flags_fed(plane: &Plane) -> Vec<u32> {
    plane
        .piece_log
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, flags, _)| *flags)
        .collect()
}

#[test]
fn a_streamed_reply_is_fed_a_chunk_at_a_time_and_reaches_the_client_as_it_is_written() {
    let plane = forwarding();
    queue(&plane, vec![head("ok")]);
    pieces(
        &plane,
        vec![
            vec![
                It::Respond(200),
                It::Header("content-type", b"text/event-stream"),
            ],
            vec![It::Body(b"one")],
            vec![It::Body(b"two")],
            vec![It::End],
        ],
    );
    let mut members = walk(&["a"]);
    let (mut far, tap, seen) = streamer(vec![(
        200,
        vec![
            Ok(Chunk::Body(b"1".to_vec())),
            Ok(Chunk::Body(b"2".to_vec())),
        ],
    )]);
    let effects = Streaming(Arc::clone(&tap));
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(flags_fed(&plane), vec![P_HEAD, P_BODY, P_BODY, P_END]);
    let got = tap.got.lock().unwrap().clone();
    assert!(matches!(got[0], ToClient::Head { status: 200, .. }));
    assert_eq!(
        &got[1..],
        &[
            ToClient::Body(b"one".to_vec()),
            ToClient::Body(b"two".to_vec()),
            ToClient::End
        ]
    );
    let Attempted::Served { client, .. } = out else {
        panic!("served");
    };
    assert!(client.is_empty(), "the sink took every item");
    // Before the far end was asked for its first chunk the head had been handed out, and before its second, the
    // first body: nothing waited for the reply to end.
    assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
}

#[test]
fn a_failing_verdict_on_the_head_hands_the_client_nothing_and_the_next_member_serves() {
    let plane = forwarding();
    queue(&plane, vec![head("one"), head("two")]);
    pieces(
        &plane,
        vec![
            vec![It::Attempt(ATT_RETRY, FC_SERVER, 0)],
            vec![It::Respond(200), It::Body(b"ok"), It::End],
            vec![],
            vec![],
        ],
    );
    let mut members = walk(&["a", "b"]);
    let (mut far, tap, _) = streamer(vec![
        (500, vec![Ok(Chunk::Body(b"boom".to_vec()))]),
        (200, vec![]),
    ]);
    let effects = Streaming(Arc::clone(&tap));
    let mut task = begin(&plane);
    run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(
        members.failed,
        vec![("a".to_string(), ATT_RETRY, FC_SERVER, 0)]
    );
    assert_eq!(members.served, vec!["b"]);
    let got = tap.got.lock().unwrap().clone();
    assert!(
        got.iter()
            .all(|i| !matches!(i, ToClient::Body(b) if b == b"boom")),
        "the failed member's reply never reached the client: {got:?}"
    );
}

#[test]
fn a_reply_cut_before_the_client_response_began_fails_the_member_over() {
    let plane = forwarding();
    queue(&plane, vec![head("one"), head("two")]);
    pieces(
        &plane,
        vec![vec![], vec![], vec![It::Respond(200), It::End]],
    );
    let mut members = walk(&["a", "b"]);
    let (mut far, tap, _) = streamer(vec![(200, vec![Err(SendFailed)]), (200, vec![])]);
    let effects = Streaming(tap);
    let mut task = begin(&plane);
    let out = run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(
        members.failed,
        vec![("a".to_string(), ATT_RETRY, FC_SERVER, 0)]
    );
    assert_eq!(members.served, vec!["b"]);
    assert!(matches!(out, Attempted::Served { attempts: 2, .. }));
}

#[test]
fn a_reply_cut_after_the_client_response_began_is_a_p_error_and_the_member_stays_served() {
    let plane = forwarding();
    queue(&plane, vec![head("one")]);
    pieces(
        &plane,
        vec![vec![It::Respond(200)], vec![It::Body(b"half")], vec![]],
    );
    let mut members = walk(&["a"]);
    let (mut far, tap, _) = streamer(vec![(
        200,
        vec![Ok(Chunk::Body(b"h".to_vec())), Err(SendFailed)],
    )]);
    let effects = Streaming(tap);
    let mut task = begin(&plane);
    run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(flags_fed(&plane), vec![P_HEAD, P_BODY, P_ERROR]);
    let refusal = plane.piece_log.lock().unwrap()[2].3.clone();
    assert!(
        !refusal.is_empty(),
        "one REFUSAL record to render in-stream"
    );
    assert_eq!(members.served, vec!["a"]);
    assert!(members.failed.is_empty());
}

#[test]
fn the_far_end_s_trailing_fields_are_fed_as_pair_records() {
    let plane = forwarding();
    queue(&plane, vec![head("one")]);
    pieces(&plane, vec![vec![It::Respond(200)], vec![], vec![], vec![]]);
    let mut members = walk(&["a"]);
    let (mut far, tap, _) = streamer(vec![(
        200,
        vec![
            Ok(Chunk::Body(b"b".to_vec())),
            Ok(Chunk::Trailers(b"grpc-status: 0\r\n".to_vec())),
        ],
    )]);
    let effects = Streaming(tap);
    let mut task = begin(&plane);
    run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(flags_fed(&plane), vec![P_HEAD, P_BODY, P_TRAILERS, P_END]);
    let trailers = plane.piece_log.lock().unwrap()[2].3.clone();
    let mut found = Vec::new();
    for rec in Records::new(&trailers) {
        let rec = rec.unwrap();
        assert_eq!(rec.tag, g::PAIR);
        found.push(rec);
    }
    assert_eq!(found.len(), 1);
}

#[test]
fn a_client_that_went_away_stops_the_reading() {
    let plane = forwarding();
    queue(&plane, vec![head("one")]);
    pieces(
        &plane,
        vec![vec![It::Respond(200), It::Body(b"x")], vec![It::Body(b"y")]],
    );
    let mut members = walk(&["a"]);
    let (mut far, tap, seen) = streamer(vec![(
        200,
        vec![
            Ok(Chunk::Body(b"1".to_vec())),
            Ok(Chunk::Body(b"2".to_vec())),
        ],
    )]);
    tap.gone.store(true, Ordering::SeqCst);
    let effects = Streaming(Arc::clone(&tap));
    let mut task = begin(&plane);
    run_attempts(
        &mut task,
        &Wants::default(),
        "chat",
        "m",
        &mut members,
        &mut far,
        &effects,
    )
    .unwrap();
    assert_eq!(flags_fed(&plane), vec![P_HEAD]);
    assert!(seen.lock().unwrap().is_empty(), "no chunk was read");
}
