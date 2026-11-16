// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §12.5, §12.9, §12.24 (PLANE-DRIVER slice 6): the intents a plane answers with, resolved by core in
//! answer order and delivered back as one `piece(FROM_CORE)` per result kind, through a scripted plane and a
//! scripted host. The plane itself is exercised by the image arms; these run the part core owns.

use std::collections::VecDeque;
use std::sync::Mutex;

use busbar_plugin_abi::fail::refused::{R_DENIED, R_UNSUPPORTED};
use busbar_plugin_abi::plane::{
    CommittedRec, LookupHit, WorkAns, FROM_CORE, LK_CALLER, LK_PREFIX, P_COMMITTED, P_LOOKUP,
    P_STORE_FAILED, P_WORK, WORK_OPEN,
};
use busbar_plugin_abi::records::{commit, tag as g, RecPredRec, RecPutRec, Records, Reply, Writer};
use busbar_plugin_loader::ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_plugin_loader::ports::PortError;

use super::{Hit, IntentHost, Looked, Resolver, WorkIntent, WorkOutcome};
use crate::plane_driver::port_session::{Calls, Effects, SessionError, Task, ToClient};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};

/// One scripted sink item, owned.
#[derive(Clone)]
enum It {
    Respond(u16),
    Lookup {
        flags: u32,
        limit: u32,
        key: Vec<u8>,
    },
    Store {
        flags: u32,
        ttl_s: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        flags: u32,
        key: Vec<u8>,
    },
    Commit {
        ops: Vec<u8>,
    },
    Work {
        op: u32,
        target: Option<&'static str>,
    },
    Push {
        ttl_s: u64,
        recs: Vec<u8>,
    },
    WakeAt(u64),
    Detach {
        ttl_s: u64,
        key: Vec<u8>,
    },
    Signal {
        flags: u32,
        key: Vec<u8>,
    },
}

fn play(items: &[It], sink: &mut dyn FnMut(PlaneOut<'_>)) {
    for it in items {
        match it {
            It::Respond(status) => sink(PlaneOut::Respond { status: *status }),
            It::Lookup { flags, limit, key } => sink(PlaneOut::Lookup {
                flags: *flags,
                limit: *limit,
                key,
            }),
            It::Store {
                flags,
                ttl_s,
                key,
                value,
            } => sink(PlaneOut::Store {
                flags: *flags,
                ttl_s: *ttl_s,
                key,
                value,
            }),
            It::Delete { flags, key } => sink(PlaneOut::Delete { flags: *flags, key }),
            It::Commit { ops } => sink(PlaneOut::Commit {
                check: 5,
                ops: Records::new(ops),
            }),
            It::Work { op, target } => sink(PlaneOut::Work {
                check: 9,
                op: *op,
                target: *target,
                reference: None,
            }),
            It::Push { ttl_s, recs } => sink(PlaneOut::Push {
                ttl_s: *ttl_s,
                recs: Records::new(recs),
            }),
            It::WakeAt(ns) => sink(PlaneOut::WakeAt(*ns)),
            It::Detach { ttl_s, key } => sink(PlaneOut::Detach {
                ttl_s: *ttl_s,
                flags: 0,
                key,
            }),
            It::Signal { flags, key } => sink(PlaneOut::Signal { flags: *flags, key }),
        }
    }
}

/// A handle with nothing in it: the script has no real session.
struct Live;

/// The plane: the request answer, then one answer per `piece`, and every piece it was handed.
#[derive(Default)]
struct Script {
    request: Vec<It>,
    answers: Mutex<VecDeque<Vec<It>>>,
    pieces: Mutex<Vec<(u32, u32, Vec<u8>)>>,
}

impl Script {
    fn answering(self, answers: Vec<Vec<It>>) -> Self {
        *self.answers.lock().unwrap() = answers.into();
        self
    }

    fn got(&self) -> Vec<(u32, u32, Vec<u8>)> {
        self.pieces.lock().unwrap().clone()
    }
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
        play(&self.request, sink);
        Ok(Live)
    }

    fn piece(
        &self,
        _: &mut Live,
        from: u32,
        _: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.pieces
            .lock()
            .unwrap()
            .push((from, flags, bytes.to_vec()));
        let items = self.answers.lock().unwrap().pop_front().unwrap_or_default();
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

    fn end(&self, _: Live, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
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
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }

    fn upstream(
        &self,
        _: &mut Live,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
}

struct Quiet;

impl Effects for Quiet {
    fn emit(&self, _: u64, _: &[u8]) {}
}

/// The host: records what it was asked, in order, and answers from its fields.
#[derive(Default)]
struct Host {
    calls: Mutex<Vec<String>>,
    present: Vec<(Vec<u8>, Vec<u8>)>,
    store_denied: bool,
    conflict_at: Option<u32>,
    commit_denied: bool,
    work: Option<WorkOutcome>,
}

impl Host {
    fn note(&self, what: impl Into<String>) {
        self.calls.lock().unwrap().push(what.into());
    }

    fn seen(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl IntentHost for Host {
    fn lookup(
        &self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &[u8],
    ) -> Result<Looked, RecordsDenied> {
        self.note(format!(
            "lookup {} subject={}",
            String::from_utf8_lossy(key),
            scope.subject.is_some()
        ));
        let hits = self
            .present
            .iter()
            .filter(|(k, _)| {
                if flags & LK_PREFIX != 0 {
                    k.starts_with(key)
                } else {
                    k == key
                }
            })
            .take(limit as usize)
            .map(|(k, v)| Hit {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        Ok(Looked { hits, chain: None })
    }

    fn store(
        &self,
        scope: Scope,
        _: u32,
        ttl_s: u64,
        key: &[u8],
        _: &[u8],
    ) -> Result<(), RecordsDenied> {
        self.note(format!(
            "store {} ttl={ttl_s} subject={}",
            String::from_utf8_lossy(key),
            scope.subject.is_some()
        ));
        if self.store_denied {
            return Err(RecordsDenied::Quota);
        }
        Ok(())
    }

    fn delete(&self, _: Scope, key: &[u8]) -> Result<(), RecordsDenied> {
        self.note(format!("delete {}", String::from_utf8_lossy(key)));
        Ok(())
    }

    fn commit(&self, _: Scope, ops: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        self.note(format!("commit {}", ops.len()));
        if self.commit_denied {
            return Err(RecordsDenied::TooLarge);
        }
        Ok(match self.conflict_at {
            Some(failed) => CommitOutcome::Conflict { failed },
            None => CommitOutcome::Applied,
        })
    }

    fn work(&self, w: &WorkIntent) -> WorkOutcome {
        self.note(format!("work op={} target={:?}", w.op, w.target));
        self.work.clone().unwrap_or_else(WorkOutcome::unsupported)
    }

    fn push(&self, ttl_s: u64, recs: &[u8]) -> Result<(), RecordsDenied> {
        self.note(format!("push ttl={ttl_s} bytes={}", recs.len()));
        Ok(())
    }

    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>) {
        self.note(format!(
            "signal {} subject={}",
            String::from_utf8_lossy(key),
            subject.is_some()
        ));
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

fn lookup(key: &[u8]) -> It {
    It::Lookup {
        flags: 0,
        limit: 4,
        key: key.to_vec(),
    }
}

const SUBJECT: Option<[u8; 32]> = Some([7; 32]);

/// Runs the request answer's intents; every answer, first to last.
fn run(
    script: &Script,
    host: &Host,
    subject: Option<[u8; 32]>,
) -> Result<Vec<crate::plane_driver::port_session::Answer>, SessionError> {
    let (mut task, first) = Task::begin(script, &req(), b"", &Quiet)?;
    task.resolve(first, &Resolver::new(host, subject), &Quiet)
}

fn hits_of(bytes: &[u8]) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    Records::new(bytes)
        .map(|rec| {
            let rec = rec.unwrap();
            assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::LOOKUP_HIT);
            let (head, tail) = rec.pod_tail::<LookupHit>().unwrap();
            let (key, value) = tail.split_at(head.key_len as usize);
            (head.lookup, key.to_vec(), value.to_vec())
        })
        .collect()
}

#[test]
fn a_lookup_hit_comes_back_as_one_p_lookup_piece() {
    let script = Script {
        request: vec![lookup(b"k")],
        ..Script::default()
    };
    let host = Host {
        present: vec![(b"k".to_vec(), b"v".to_vec())],
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    let got = script.got();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_LOOKUP));
    assert_eq!(hits_of(&got[0].2), vec![(0, b"k".to_vec(), b"v".to_vec())]);
}

#[test]
fn a_prefix_lookup_is_a_list_and_the_index_is_the_lookups_place_in_the_answer() {
    let script = Script {
        request: vec![
            lookup(b"none"),
            It::Lookup {
                flags: LK_PREFIX,
                limit: 2,
                key: b"a/".to_vec(),
            },
        ],
        ..Script::default()
    };
    let host = Host {
        present: vec![
            (b"a/1".to_vec(), b"x".to_vec()),
            (b"a/2".to_vec(), b"y".to_vec()),
            (b"a/3".to_vec(), b"z".to_vec()),
        ],
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    let got = script.got();
    assert_eq!(got.len(), 1, "one piece for the whole kind");
    let hits = hits_of(&got[0].2);
    assert_eq!(hits.len(), 2, "limit applies per lookup");
    assert!(
        hits.iter().all(|h| h.0 == 1),
        "the second LOOKUP of the answer"
    );
}

#[test]
fn a_lookup_that_misses_still_answers_with_a_piece() {
    let script = Script {
        request: vec![lookup(b"gone")],
        ..Script::default()
    };
    run(&script, &Host::default(), None).unwrap();
    let got = script.got();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, P_LOOKUP);
    assert!(
        got[0].2.is_empty(),
        "no hit, no bytes: the plane reads that as a miss"
    );
}

#[test]
fn store_delete_and_commit_apply_before_the_lookups_of_the_same_answer_resolve() {
    let mut ops = Reply::new();
    ops.put_pod_tail(
        g::REC_PUT,
        &RecPutRec {
            flags: 0,
            key_len: 1,
            ttl_s: 0,
        },
        b"cv",
    )
    .unwrap();
    let script = Script {
        request: vec![
            lookup(b"k"),
            It::Store {
                flags: 0,
                ttl_s: 30,
                key: b"s".to_vec(),
                value: b"1".to_vec(),
            },
            It::Delete {
                flags: 0,
                key: b"d".to_vec(),
            },
            It::Commit {
                ops: ops.as_bytes().to_vec(),
            },
        ],
        ..Script::default()
    };
    let host = Host::default();
    run(&script, &host, None).unwrap();
    assert_eq!(
        host.seen(),
        [
            "store s ttl=30 subject=false",
            "delete d",
            "commit 1",
            "lookup k subject=false"
        ]
    );
}

#[test]
fn a_store_that_is_not_applied_is_a_store_failed_piece_naming_the_key() {
    let script = Script {
        request: vec![It::Store {
            flags: 0,
            ttl_s: 0,
            key: b"s".to_vec(),
            value: b"1".to_vec(),
        }],
        ..Script::default()
    };
    let host = Host {
        store_denied: true,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert_eq!(
        script.got(),
        vec![(FROM_CORE, P_STORE_FAILED, b"s".to_vec())]
    );
}

#[test]
fn a_commit_answers_applied_conflict_or_a_refusal_in_committed() {
    let mut ops = Reply::new();
    ops.put_pod_tail(
        g::REC_PRED,
        &RecPredRec {
            flags: commit::PRED_ABSENT,
            key_len: 1,
        },
        b"k",
    )
    .unwrap();
    ops.put_pod_tail(
        g::REC_PUT,
        &RecPutRec {
            flags: 0,
            key_len: 1,
            ttl_s: 0,
        },
        b"kv",
    )
    .unwrap();
    let ops = ops.as_bytes().to_vec();
    let committed = |host: Host| {
        let script = Script {
            request: vec![It::Commit { ops: ops.clone() }],
            ..Script::default()
        };
        run(&script, &host, None).unwrap();
        let got = script.got();
        assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_COMMITTED));
        let rec = Records::new(&got[0].2).next().unwrap().unwrap();
        rec.pod::<CommittedRec>().unwrap()
    };
    let applied = committed(Host::default());
    assert_eq!(
        (applied.check, applied.outcome, applied.status),
        (5, commit::APPLIED, 0)
    );
    let conflict = committed(Host {
        conflict_at: Some(0),
        ..Host::default()
    });
    assert_eq!((conflict.outcome, conflict.failed), (commit::CONFLICT, 0));
    let denied = committed(Host {
        commit_denied: true,
        ..Host::default()
    });
    assert_eq!(denied.outcome, 0, "nothing applied");
    assert_ne!(denied.status, 0, "a REFUSED code");
}

#[test]
fn a_caller_scoped_record_needs_a_verified_subject_and_without_one_nothing_runs() {
    let script = Script {
        request: vec![
            It::Lookup {
                flags: LK_CALLER,
                limit: 1,
                key: b"mine".to_vec(),
            },
            It::Store {
                flags: LK_CALLER,
                ttl_s: 0,
                key: b"mine".to_vec(),
                value: b"1".to_vec(),
            },
        ],
        ..Script::default()
    };
    let host = Host::default();
    run(&script, &host, None).unwrap();
    assert!(
        host.seen().is_empty(),
        "never answered from the shared namespace: {:?}",
        host.seen()
    );
    let got = script.got();
    assert!(got.iter().any(|p| p.1 == P_STORE_FAILED && p.2 == b"mine"));

    let host = Host::default();
    let script = Script {
        request: vec![It::Lookup {
            flags: LK_CALLER,
            limit: 1,
            key: b"mine".to_vec(),
        }],
        ..Script::default()
    };
    run(&script, &host, SUBJECT).unwrap();
    assert_eq!(host.seen(), ["lookup mine subject=true"]);
}

#[test]
fn work_without_a_recovery_runtime_is_refused_unsupported_and_with_one_it_is_answered() {
    let work = |host: Host| {
        let script = Script {
            request: vec![It::Work {
                op: WORK_OPEN,
                target: Some("/poll?id=1"),
            }],
            ..Script::default()
        };
        run(&script, &host, SUBJECT).unwrap();
        let got = script.got();
        assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_WORK));
        Records::new(&got[0].2)
            .next()
            .unwrap()
            .unwrap()
            .pod_tail::<WorkAns>()
            .unwrap()
    };
    let (none, _) = work(Host::default());
    assert_eq!((none.check, none.status, none.state), (9, R_UNSUPPORTED, 0));
    let (live, tail) = work(Host {
        work: Some(WorkOutcome {
            status: 0,
            state: busbar_plugin_abi::plane::WORK_LIVE,
            reference: "ref1".into(),
            target: String::new(),
        }),
        ..Host::default()
    });
    assert_eq!(
        (live.status, live.state),
        (0, busbar_plugin_abi::plane::WORK_LIVE)
    );
    let nested = Records::new(tail).next().unwrap().unwrap();
    assert_eq!(nested.tag, busbar_plugin_abi::plane::tag::WK_REF);
    assert_eq!(nested.text().unwrap(), "ref1");
}

#[test]
fn work_with_no_verified_subject_is_denied_before_the_host_hears_of_it() {
    let script = Script {
        request: vec![It::Work {
            op: WORK_OPEN,
            target: Some("/poll"),
        }],
        ..Script::default()
    };
    let host = Host::default();
    run(&script, &host, None).unwrap();
    assert!(host.seen().is_empty());
    let got = script.got();
    let (ans, _) = Records::new(&got[0].2)
        .next()
        .unwrap()
        .unwrap()
        .pod_tail::<WorkAns>()
        .unwrap();
    assert_eq!(ans.status, R_DENIED);
}

#[test]
fn a_push_is_queued_with_its_nested_records_and_answers_nothing() {
    let script = Script {
        request: vec![It::Push {
            ttl_s: 60,
            recs: b"AAAAAAAA".to_vec(),
        }],
        ..Script::default()
    };
    let host = Host::default();
    let answers = run(&script, &host, None).unwrap();
    assert_eq!(host.seen(), ["push ttl=60 bytes=8"]);
    assert!(
        script.got().is_empty(),
        "no piece: the plane learns nothing back"
    );
    assert_eq!(answers.len(), 1);
}

#[test]
fn a_signal_goes_to_the_host_scoped_to_the_subject_only_when_asked() {
    let script = Script {
        request: vec![
            It::Signal {
                flags: 0,
                key: b"all".to_vec(),
            },
            It::Signal {
                flags: LK_CALLER,
                key: b"mine".to_vec(),
            },
        ],
        ..Script::default()
    };
    let host = Host::default();
    run(&script, &host, SUBJECT).unwrap();
    assert_eq!(
        host.seen(),
        ["signal all subject=false", "signal mine subject=true"]
    );
}

#[test]
fn wake_at_and_detach_are_kept_on_the_answer_for_the_session_loop() {
    let script = Script {
        request: vec![
            It::WakeAt(5_000),
            It::Detach {
                ttl_s: 90,
                key: b"task/1".to_vec(),
            },
        ],
        ..Script::default()
    };
    let answers = run(&script, &Host::default(), None).unwrap();
    assert_eq!(answers[0].wake_at, Some(5_000));
    let detach = answers[0].detach.as_ref().unwrap();
    assert_eq!((detach.ttl_s, &*detach.key), (90, &b"task/1"[..]));
    assert!(
        script.got().is_empty(),
        "core answers WAKE_AT when the time passes, not now"
    );
}

#[test]
fn the_answer_to_a_piece_may_carry_intents_and_client_items_in_order() {
    let script = Script {
        request: vec![lookup(b"first")],
        ..Script::default()
    }
    .answering(vec![
        vec![lookup(b"second"), It::Respond(404)],
        vec![It::Respond(200)],
    ]);
    let host = Host {
        present: vec![
            (b"first".to_vec(), b"1".to_vec()),
            (b"second".to_vec(), b"2".to_vec()),
        ],
        ..Host::default()
    };
    let answers = run(&script, &host, None).unwrap();
    assert_eq!(
        host.seen(),
        ["lookup first subject=false", "lookup second subject=false"]
    );
    assert_eq!(script.got().len(), 2);
    let statuses: Vec<u16> = answers
        .iter()
        .flat_map(|a| a.client.iter())
        .filter_map(|c| match c {
            ToClient::Head { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    assert_eq!(statuses, vec![404, 200]);
}

#[test]
fn an_intent_loop_that_never_settles_is_a_violation_not_a_hang() {
    let script = Script {
        request: vec![lookup(b"k")],
        ..Script::default()
    }
    .answering((0..1_000).map(|_| vec![lookup(b"k")]).collect());
    let err = run(&script, &Host::default(), None).unwrap_err();
    assert!(matches!(
        err,
        SessionError::Violation(crate::plane_driver::port_session::Violation::IntentStorm)
    ));
}
