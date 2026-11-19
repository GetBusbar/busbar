// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §11.3: the once rules and the order of a session's answers, through a scripted plane. The plane
//! itself is exercised by the image arms; these run the part core owns.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::plane::{
    ATT_DECLINE, ATT_HARD, ATT_RELAY, ATT_RETRY, AUDIT_APPLIED, AUDIT_REJECTED, FROM_CLIENT,
    FROM_CORE, FROM_UPSTREAM, SRC_ESTIMATED, SRC_REPORTED,
};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::{FactRef, FactVal, PortError};

use super::{render, run_local, Calls, Effects, Origin, SessionError, Task, ToClient, Violation};
use crate::plane_driver::port_auth::refuse;
use crate::plane_driver::usage::UsageInvalid;

#[path = "selected_policy_runtime_tests.rs"]
mod current_policy;

/// One scripted sink item.
#[derive(Clone)]
enum It {
    Prepared(
        &'static [(
            &'static str,
            busbar_plugin_abi::fallback_usage::EstimateValue,
        )],
    ),
    UpMethod,
    UpEnd,
    AttemptUsage,
    SelectedResource,
    ResourceEcho,
    Respond(u16),
    Header(&'static str, &'static [u8]),
    Body(&'static [u8]),
    Conversation(&'static [u8]),
    Trailers,
    End,
    Forward,
    Want(u32, u64),
    /// A text want (e.g. `W_MODEL`).
    WantText(u32, &'static str),
    Emit(u64, &'static [u8]),
    Finish,
    /// An item a later slice drives.
    Lookup,
    Usage(&'static str, u64, u32, u32),
    Expect(&'static str),
    Attempt(u32),
    Audit(u32, &'static str, &'static str),
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        sink(match it {
            It::Prepared(entries) => {
                use busbar_plugin_abi::fallback_usage as wire;
                let mut records = busbar_plugin_abi::records::Reply::new();
                let entries: Vec<_> = entries
                    .iter()
                    .map(|(class, value)| wire::Estimate {
                        class,
                        value: *value,
                    })
                    .collect();
                wire::write_prepared_estimates(
                    &mut records,
                    wire::SelectedResource {
                        attempt: 1,
                        exchange: 0,
                        resource: "configured",
                    },
                    &entries,
                )
                .unwrap();
                let record = busbar_plugin_abi::records::Records::new(records.as_bytes())
                    .next()
                    .unwrap()
                    .unwrap();
                sink(PlaneOut::PreparedEstimates(
                    wire::decode_prepared(record).unwrap(),
                ));
                continue;
            }
            It::UpMethod => PlaneOut::UpMethod("POST"),
            It::UpEnd => PlaneOut::UpEnd,
            It::AttemptUsage => {
                PlaneOut::AttemptUsage(busbar_plugin_abi::fallback_usage::AttemptUsage {
                    attempt: 1,
                    class: "tokens",
                    amount: 7,
                    scale: 0,
                    source: busbar_plugin_abi::fallback_usage::UsageSource::Reported,
                })
            }
            It::SelectedResource => {
                PlaneOut::SelectedResource(busbar_plugin_abi::fallback_usage::SelectedResource {
                    attempt: 1,
                    exchange: 0,
                    resource: "configured",
                })
            }
            It::ResourceEcho => {
                PlaneOut::ResourceEcho(busbar_plugin_abi::resource_admission::DescriptorEcho {
                    invocation: 7,
                    generation: 8,
                    route: 9,
                    descriptor: 10,
                    instance: "seat",
                })
            }
            It::Respond(status) => PlaneOut::Respond { status: *status },
            It::Header(n, v) => PlaneOut::Header(n, v),
            It::Body(b) => PlaneOut::Body(b),
            It::Conversation(b) => PlaneOut::Conversation(b),
            It::Trailers => PlaneOut::Trailers,
            It::End => PlaneOut::End,
            It::Forward => PlaneOut::Forward { stream: true },
            It::Want(k, v) => PlaneOut::Want(*k, FactRef::U(*v)),
            It::WantText(k, v) => PlaneOut::Want(*k, FactRef::Text(v)),
            It::Emit(carrier, b) => PlaneOut::Emit {
                carrier: *carrier,
                bytes: b,
            },
            It::Finish => PlaneOut::Finish,
            It::Lookup => PlaneOut::Lookup {
                flags: 0,
                limit: 1,
                key: b"k",
            },
            It::Usage(class, amount, scale, source) => PlaneOut::Usage {
                class,
                amount: *amount,
                scale: *scale,
                source: *source,
            },
            It::Expect(class) => PlaneOut::Expect {
                class,
                amount: 10,
                scale: 0,
            },
            It::Attempt(verdict) => PlaneOut::Attempt {
                verdict: *verdict,
                class: 0,
                retry_after_s: 0,
                reason: "r",
            },
            It::Audit(verdict, action, resource) => PlaneOut::Audit {
                verdict: *verdict,
                action,
                resource,
            },
        });
    }
}

#[test]
fn command_callback_rejects_trailing_effects_and_duplicate_channels() {
    use busbar_plugin_abi::plane::{CARRIER_STDIO, CH_FRAME_NDJSON};
    for duplicate in [false, true] {
        let effects = Emitted::default();
        let mut once = super::Once::default();
        let mut answer = super::Answer::default();
        let channel = || PlaneOut::Channel {
            exchange: 1,
            carrier: CARRIER_STDIO,
            flags: 0,
            framing: CH_FRAME_NDJSON,
            key: "command",
            head: busbar_plugin_abi::records::Records::new(&[]),
        };
        answer.take(&channel(), Origin::Channel, &mut once, &effects);
        assert_eq!(answer.intents.len(), 1);
        assert!(answer.violation.is_none());
        answer.take(
            &if duplicate {
                channel()
            } else {
                PlaneOut::Emit {
                    carrier: 1,
                    bytes: b"forbidden",
                }
            },
            Origin::Channel,
            &mut once,
            &effects,
        );
        assert!(answer.violation.is_some());
        assert!(effects.0.lock().unwrap().is_empty());
    }
}

#[test]
fn an_unadmitted_resource_echo_cannot_be_ignored_in_request() {
    let script = Script {
        request: vec![It::Emit(5, b"must stay private"), It::ResourceEcho],
        ..Script::default()
    };
    let fx = Emitted::default();
    assert!(Task::begin(&script, &req(), b"", &fx).is_err());
    assert!(fx.0.lock().unwrap().is_empty());
}

#[test]
fn unadmitted_attempt_records_cannot_release_an_answer_prefix() {
    for record in [It::AttemptUsage, It::SelectedResource] {
        let script = Script {
            request: vec![
                It::Emit(1, b"held"),
                It::Usage("tokens", 3, 0, SRC_REPORTED),
                record,
            ],
            ..Script::default()
        };
        let effects = Emitted::default();
        assert!(matches!(
            Task::begin(&script, &req(), b"", &effects),
            Err(SessionError::Violation(Violation::BadRecords))
        ));
        assert!(effects.0.lock().unwrap().is_empty());
        assert!(script.dropped.load(Ordering::SeqCst));
    }
}

#[test]
fn the_actual_resource_echo_is_retained_on_exchange_zero() {
    use busbar_plugin_abi::resource_admission::DescriptorEcho;
    let echo = DescriptorEcho {
        invocation: 7,
        generation: 8,
        route: 9,
        descriptor: 10,
        instance: "seat",
    };
    for echo_first in [false, true] {
        let mut answer = super::Answer::default();
        let mut once = super::Once::default();
        let fx = Emitted::default();
        let mut take = |out| answer.take(&out, Origin::Upstream, &mut once, &fx);
        if echo_first {
            take(PlaneOut::ResourceEcho(echo));
        }
        take(PlaneOut::UpCarrier {
            carrier: 0,
            outbound: 0,
        });
        take(PlaneOut::UpMethod("POST"));
        take(PlaneOut::UpPath("/configured"));
        if !echo_first {
            take(PlaneOut::ResourceEcho(echo));
        }
        take(PlaneOut::UpEnd);
        let answer = answer.seal();
        assert_eq!(answer.violation, None);
        assert_eq!(answer.exchanges.len(), 1);
        assert_eq!(
            answer.exchanges[0]
                .resource_echo
                .as_ref()
                .unwrap()
                .borrowed(),
            echo
        );
    }
}

#[test]
fn an_unsolicited_upstream_echo_releases_neither_emits_nor_usage() {
    let script = Script {
        upstream_items: Mutex::new(VecDeque::from([vec![
            It::Emit(5, b"must stay private"),
            It::Usage("requests", 3, 0, SRC_REPORTED),
            It::ResourceEcho,
        ]])),
        ..Script::default()
    };
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert!(task.upstream(&target(), &fx).is_err());
    assert!(fx.0.lock().unwrap().is_empty());
    assert!(task.usage().is_empty());
    assert!(!task.open());
}

/// A session handle that says when it was dropped (a drop without `end` is a cancel).
#[test]
fn complete_preparation_requires_every_declared_class_before_any_effect() {
    use busbar_plugin_abi::fallback_usage::{self as wire, EstimateValue};
    const COMPLETE: &[(&str, EstimateValue)] = &[
        ("tokens", EstimateValue::Unknown),
        (
            "requests",
            EstimateValue::Known {
                amount: 1,
                scale: 0,
            },
        ),
    ];
    const PARTIAL: &[(&str, EstimateValue)] = &[("tokens", EstimateValue::Unknown)];
    for (entries, valid) in [(PARTIAL, false), (COMPLETE, true)] {
        let script = Script {
            facts: busbar_plugin_abi::plane::FB_PREPARED_ESTIMATES,
            classes: ["tokens", "requests"]
                .into_iter()
                .map(|class| busbar_ports::plane::UsageClass {
                    class: class.into(),
                    unit: 0,
                    expected_units: None,
                })
                .collect(),
            upstream_items: Mutex::new(VecDeque::from([vec![
                It::Emit(1, b"held"),
                It::SelectedResource,
                It::Prepared(entries),
                It::UpMethod,
                It::UpEnd,
            ]])),
            ..Script::default()
        };
        let mut admission = busbar_plugin_abi::records::Reply::new();
        wire::write_selected(
            &mut admission,
            wire::SelectedResource {
                attempt: 1,
                exchange: 0,
                resource: "configured",
            },
        )
        .unwrap();
        let mut input = target();
        input.admission = admission.as_bytes();
        let effects = Emitted::default();
        let (mut task, _) = Task::begin(&script, &req(), b"", &effects).unwrap();
        let result = task.upstream(&input, &effects);
        assert_eq!(result.is_ok(), valid);
        assert_eq!(!effects.0.lock().unwrap().is_empty(), valid);
        if !valid {
            assert!(!task.open());
        }
    }
}

#[test]
fn owned_selected_preparation_retains_complete_actual_estimates() {
    use busbar_plugin_abi::fallback_usage::EstimateValue;
    let script = Script {
        facts: busbar_plugin_abi::plane::FB_PREPARED_ESTIMATES,
        classes: vec![busbar_ports::plane::UsageClass {
            class: "tokens".into(),
            unit: busbar_plugin_abi::plane::UNIT_TOKENS,
            expected_units: None,
        }],
        upstream_items: Mutex::new(VecDeque::from([vec![
            It::SelectedResource,
            It::Prepared(&[("tokens", EstimateValue::Unknown)]),
            It::UpMethod,
            It::UpEnd,
        ]])),
        ..Script::default()
    };
    let candidate = crate::plane_driver::port_upstream::Candidate {
        pool: "actual-pool".into(),
        qualified_member: "seat\u{1f}actual-model".into(),
        identity: crate::plane_driver::port_upstream::TargetIdentity::Model {
            dialect: "actual-dialect".into(),
            model: "actual-wire-model".into(),
        },
        resource: Some("configured".into()),
        upstream: "actual-model".into(),
        provider: "{}".into(),
        base_path: "".into(),
        flags: 0,
        params: vec![],
    };
    let effects = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &effects).unwrap();
    let prepared = task
        .prepare_selected(&candidate, 1, "request-dialect", "request-model", &effects)
        .unwrap()
        .unwrap();
    assert_eq!(prepared.target(), &candidate);
    assert_eq!(prepared.attempt(), 1);
    assert_eq!(prepared.route(), req().route);
    assert_eq!(prepared.exchange().method.as_deref(), Some("POST"));
    assert!(prepared.exchange().end);
    assert!(effects.0.lock().unwrap().is_empty());
}

#[test]
fn selected_sender_has_no_borrowed_legacy_fallback() {
    use crate::plane_driver::port_egress::OwnedPreparation;
    use crate::plane_driver::port_upstream::{
        Candidate, SendFailed, TargetIdentity, UpReply, UpSend,
    };
    struct Legacy;
    impl UpSend for Legacy {
        fn send(&mut self, _: &Candidate, _: super::UpExchange) -> Result<UpReply, SendFailed> {
            panic!("an owned selected preparation must never fall back to legacy send")
        }
    }
    let script = Script {
        upstream_items: Mutex::new(VecDeque::from([vec![It::UpMethod, It::UpEnd]])),
        ..Script::default()
    };
    let effects = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &effects).unwrap();
    let candidate = Candidate {
        pool: "pool".into(),
        qualified_member: "seat\u{1f}member".into(),
        identity: TargetIdentity::Registration,
        resource: None,
        upstream: "member".into(),
        provider: "{}".into(),
        base_path: "".into(),
        flags: 0,
        params: vec![],
    };
    let prepared = task
        .prepare_selected(&candidate, 1, "dialect", "model", &effects)
        .unwrap()
        .unwrap();
    assert!(Legacy
        .open_selected(OwnedPreparation::new(prepared, None))
        .is_err());
}

#[test]
fn later_forward_rejects_prior_attempt_owned_session_usage() {
    let script = Script {
        facts: busbar_plugin_abi::plane::FB_ATTEMPT_USAGE,
        classes: vec![busbar_ports::plane::UsageClass {
            class: "tokens".into(),
            unit: busbar_plugin_abi::plane::UNIT_TOKENS,
            expected_units: None,
        }],
        attempt_classes: vec!["tokens".into()],
        request: vec![It::Usage("tokens", 0, 0, SRC_REPORTED)],
        pieces: Mutex::new(VecDeque::from([vec![It::Emit(1, b"held"), It::Forward]])),
        ..Script::default()
    };
    let effects = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &effects).unwrap();
    assert!(matches!(
        task.piece(FROM_CORE, 0, 0, b"", &effects),
        Err(SessionError::Violation(Violation::BadRecords))
    ));
    assert!(effects.0.lock().unwrap().is_empty());
}

struct Live(Arc<AtomicBool>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Script {
    facts: u64,
    classes: Vec<busbar_ports::plane::UsageClass>,
    attempt_classes: Vec<Box<str>>,
    request: Vec<It>,
    pieces: Mutex<VecDeque<Vec<It>>>,
    end: Vec<It>,
    render: Vec<It>,
    fail_render: bool,
    upstream_items: Mutex<VecDeque<Vec<It>>>,
    refuse_request: bool,
    refuse_rewrite: bool,
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

    fn usage_metadata(&self) -> (u64, Arc<[busbar_ports::plane::UsageClass]>, Arc<[Box<str>]>) {
        (
            self.facts,
            self.classes.as_slice().into(),
            self.attempt_classes.as_slice().into(),
        )
    }

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
        if self.refuse_rewrite {
            return Err(PortError::Refused {
                code: busbar_plugin_abi::fail::refused::R_INVALID,
                text: "rewrite does not fit this request".into(),
                error: None,
            });
        }
        Ok(())
    }

    fn end(&self, s: Live, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        play(&self.end, sink);
        // `end` consumes the session: it is not a cancel.
        std::mem::forget(s);
        Ok(())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<Live, PortError> {
        Err(refused())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        if self.fail_render {
            return Err(refused());
        }
        play(&self.render, sink);
        Ok(())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let items = self
            .upstream_items
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        play(&items, sink);
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
fn a_hook_projection_is_driven_without_exposing_it_to_the_client() {
    let script = Script {
        request: vec![
            It::Conversation(br#"{"messages":[{"role":"user","text":"private"}]}"#),
            It::Forward,
        ],
        ..Script::default()
    };
    let mut request = req();
    request.flags = busbar_plugin_abi::plane::RQ_PROJECT;
    let fx = Emitted::default();
    let (task, first) = Task::begin(&script, &request, b"", &fx).unwrap();
    assert!(!first.later, "CONVERSATION is a native hook projection");
    assert_eq!(
        first.conversation.as_deref(),
        Some(br#"{"messages":[{"role":"user","text":"private"}]}"#.as_slice()),
        "the stage receives the plane's exact projection"
    );
    assert!(first.client.is_empty(), "projection is never client output");
    assert!(first.forward.is_some());
    assert!(task.open());
}

#[test]
fn an_inapplicable_hook_rewrite_keeps_the_original_session() {
    let script = Script {
        request: vec![It::Forward],
        refuse_rewrite: true,
        ..Script::default()
    };
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"original", &fx).unwrap();
    let result = task.rewrite(br#"{"messages":[]}"#, &fx);
    assert!(matches!(
        result,
        Err(SessionError::Port(PortError::Refused {
            code: busbar_plugin_abi::fail::refused::R_INVALID,
            ..
        }))
    ));
    assert!(task.open(), "IF §8.6 keeps the original after R_INVALID");
    assert!(!script.dropped.load(Ordering::SeqCst));
    task.end(&fx).expect("original session still ends normally");
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
    assert!(matches!(
        first.client[0],
        ToClient::Head { status: 200, .. }
    ));
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
    assert!(
        !script.dropped.load(Ordering::SeqCst),
        "ended, not cancelled"
    );
}

#[test]
fn a_forward_or_an_undriven_item_is_not_a_local_answer() {
    for request in [vec![It::Forward], vec![It::Lookup]] {
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

fn denial() -> crate::refusal::ClientRefusal {
    crate::refusal::ClientRefusal {
        status: 401,
        code: 7,
        text: "authentication required".into(),
    }
}

#[test]
fn a_render_is_the_plane_s_own_head_body_and_end() {
    let script = Script {
        render: vec![
            It::Respond(401),
            It::Header("content-type", b"application/json"),
            It::Body(b"{\"error\":1}"),
            It::End,
        ],
        ..Script::default()
    };
    let fx = Emitted::default();
    let items = render(&script, &req(), 1, b"", &fx).unwrap();
    assert!(matches!(items[0], ToClient::Head { status: 401, .. }));
    assert_eq!(items[1], ToClient::Body(b"{\"error\":1}".to_vec()));
    assert_eq!(items[2], ToClient::End);
}

#[test]
fn a_render_that_forwards_or_carries_an_intent_is_refused() {
    for items in [vec![It::Forward], vec![It::Lookup]] {
        let script = Script {
            render: items,
            ..Script::default()
        };
        let fx = Emitted::default();
        assert!(render(&script, &req(), 1, b"", &fx).is_err());
    }
}

#[test]
fn a_refusal_is_rendered_by_the_plane_and_falls_back_to_core_s_text_when_it_cannot() {
    let fx = Emitted::default();
    let rendering = Script {
        render: vec![It::Respond(401), It::Body(b"plane words"), It::End],
        ..Script::default()
    };
    let items = refuse(&rendering, &req(), &denial(), &fx);
    assert_eq!(items[1], ToClient::Body(b"plane words".to_vec()));
    let failing = Script {
        fail_render: true,
        ..Script::default()
    };
    let items = refuse(&failing, &req(), &denial(), &fx);
    assert!(matches!(items[0], ToClient::Head { status: 401, .. }));
    assert_eq!(
        items[1],
        ToClient::Body(b"authentication required".to_vec())
    );
}

const TOKENS: &str = "tokens";

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

#[test]
fn usage_is_cumulative_across_answers_and_the_last_value_stands() {
    let script = Script {
        request: vec![It::Usage(TOKENS, 5, 0, SRC_REPORTED)],
        end: vec![
            It::Usage(TOKENS, 9, 0, SRC_REPORTED),
            It::Usage(TOKENS, 2, 0, SRC_ESTIMATED),
        ],
        ..Script::default()
    };
    pieces(&script, vec![vec![It::Usage(TOKENS, 7, 0, SRC_REPORTED)]]);
    let fx = Emitted::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert_eq!(first.usage.len(), 1);
    task.piece(FROM_CORE, 0, 0, b"", &fx).unwrap();
    assert_eq!(task.usage().last()[0].amount, 7);
    task.end(&fx).unwrap();
    let kept: Vec<(u64, u32)> = task
        .usage()
        .last()
        .iter()
        .map(|r| (r.amount, r.source))
        .collect();
    assert_eq!(kept, vec![(9, SRC_REPORTED), (2, SRC_ESTIMATED)]);
}

#[test]
fn a_usage_the_session_may_not_keep_ends_it() {
    for (item, why) in [
        (It::Usage("Tokens", 1, 0, SRC_REPORTED), UsageInvalid::Class),
        (It::Usage(TOKENS, 1, 10, SRC_REPORTED), UsageInvalid::Scale),
        (It::Usage(TOKENS, 1, 0, 9), UsageInvalid::Source),
    ] {
        let script = Script {
            request: vec![item],
            ..Script::default()
        };
        let fx = Emitted::default();
        let err = Task::begin(&script, &req(), b"", &fx).err().unwrap();
        assert!(
            matches!(err, SessionError::Violation(Violation::Usage(w)) if w == why),
            "{why:?}"
        );
        assert!(script.dropped.load(Ordering::SeqCst));
    }
}

#[test]
fn an_expect_rides_a_forward_and_is_out_of_place_after_upstream_has_answered() {
    let script = Script {
        request: vec![It::Forward, It::Expect(TOKENS)],
        ..Script::default()
    };
    pieces(&script, vec![vec![It::Expect(TOKENS)]]);
    let fx = Emitted::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    assert_eq!(first.expects.len(), 1);
    assert_eq!(&*first.expects[0].class, TOKENS);
    assert_eq!(first.expects[0].amount, 10);
    let err = task.piece(FROM_UPSTREAM, 1, 0, b"", &fx).unwrap_err();
    assert!(matches!(
        err,
        SessionError::Violation(Violation::ForwardOutOfPlace(Origin::Piece(FROM_UPSTREAM)))
    ));
}

#[test]
fn an_attempt_is_the_outcome_of_an_upstream_or_a_from_upstream_answer_only() {
    let script = Script {
        request: vec![It::Forward],
        ..Script::default()
    };
    script
        .upstream_items
        .lock()
        .unwrap()
        .push_back(vec![It::Attempt(ATT_DECLINE)]);
    pieces(&script, vec![vec![It::Attempt(ATT_RETRY)]]);
    let fx = Emitted::default();
    let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
    let declined = task.upstream(&target(), &fx).unwrap();
    assert_eq!(declined.attempt.unwrap().verdict, ATT_DECLINE);
    let retried = task.piece(FROM_UPSTREAM, 0, 0, b"", &fx).unwrap();
    assert_eq!(retried.attempt.unwrap().verdict, ATT_RETRY);

    let elsewhere = Script {
        request: vec![It::Attempt(ATT_RETRY)],
        ..Script::default()
    };
    assert!(matches!(
        Task::begin(&elsewhere, &req(), b"", &fx).err().unwrap(),
        SessionError::Violation(Violation::AttemptOutOfPlace(Origin::Request))
    ));
}

#[test]
fn a_decline_comes_only_from_upstream_and_a_failed_attempt_carries_no_response() {
    let fx = Emitted::default();
    let decline_in_piece = Script::default();
    pieces(&decline_in_piece, vec![vec![It::Attempt(ATT_DECLINE)]]);
    let (mut task, _) = Task::begin(&decline_in_piece, &req(), b"", &fx).unwrap();
    assert!(matches!(
        task.piece(FROM_UPSTREAM, 0, 0, b"", &fx).unwrap_err(),
        SessionError::Violation(Violation::AttemptOutOfPlace(Origin::Piece(FROM_UPSTREAM)))
    ));

    for verdict in [ATT_RETRY, ATT_HARD] {
        for items in [
            vec![It::Respond(502), It::Attempt(verdict)],
            vec![It::Attempt(verdict), It::Body(b"x")],
        ] {
            let script = Script::default();
            pieces(&script, vec![items]);
            let (mut task, _) = Task::begin(&script, &req(), b"", &fx).unwrap();
            assert!(matches!(
                task.piece(FROM_UPSTREAM, 0, 0, b"", &fx).unwrap_err(),
                SessionError::Violation(Violation::AttemptWithResponse)
            ));
        }
    }

    let relay = Script::default();
    pieces(
        &relay,
        vec![vec![
            It::Respond(401),
            It::Body(b"x"),
            It::Attempt(ATT_RELAY),
        ]],
    );
    let (mut task, _) = Task::begin(&relay, &req(), b"", &fx).unwrap();
    let answer = task.piece(FROM_UPSTREAM, 0, 0, b"", &fx).unwrap();
    assert_eq!(answer.attempt.unwrap().verdict, ATT_RELAY);
    assert!(!answer.client.is_empty());

    let unknown = Script::default();
    pieces(&unknown, vec![vec![It::Attempt(0)]]);
    let (mut task, _) = Task::begin(&unknown, &req(), b"", &fx).unwrap();
    assert!(matches!(
        task.piece(FROM_UPSTREAM, 0, 0, b"", &fx).unwrap_err(),
        SessionError::Violation(Violation::BadAttempt)
    ));
}

#[test]
fn audit_rows_are_kept_in_order_and_a_row_with_no_verdict_or_action_is_refused() {
    let script = Script {
        request: vec![
            It::Audit(AUDIT_APPLIED, "plane.thing", "r1"),
            It::Audit(AUDIT_REJECTED, "plane.other", ""),
        ],
        ..Script::default()
    };
    let fx = Emitted::default();
    let (_, first) = Task::begin(&script, &req(), b"", &fx).unwrap();
    let rows: Vec<(u32, &str, &str)> = first
        .audits
        .iter()
        .map(|a| (a.verdict, &*a.action, &*a.resource))
        .collect();
    assert_eq!(
        rows,
        vec![
            (AUDIT_APPLIED, "plane.thing", "r1"),
            (AUDIT_REJECTED, "plane.other", "")
        ]
    );
    for bad in [It::Audit(0, "a", "b"), It::Audit(AUDIT_APPLIED, "", "b")] {
        let script = Script {
            request: vec![bad],
            ..Script::default()
        };
        assert!(matches!(
            Task::begin(&script, &req(), b"", &fx).err().unwrap(),
            SessionError::Violation(Violation::BadAudit)
        ));
    }
}
