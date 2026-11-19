// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6, §12.5, §12.9, §12.24 (PLANE-DRIVER slice 6): the intents a plane answers with, resolved by core in
//! answer order and delivered back as one `piece(FROM_CORE)` per result kind, through a scripted plane and a
//! scripted host. The plane itself is exercised by the image arms; these run the part core owns.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::fail::refused::{R_DENIED, R_INVALID, R_NOT_FOUND, R_UNSUPPORTED};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::{
    CommittedRec, ConnectAns, LookupHit, MintedRec, ObsReceipt, ObsScopeAns, RefusalRec, SignedRec,
    TrustAns, TrustItemState, UsageRec, WorkAns, CONNECT_BEGIN, CONNECT_STATUS, CONN_READY,
    CONN_REFUSED, DEST_ALLOWED, DEST_INTERNAL, DISTRUST_CHANGED, DISTRUST_NONE,
    DISTRUST_NOT_APPROVED, DISTRUST_UNSIGHTED, FROM_CORE, JUDGE_REFUSE_PRIVATE, JUDGE_RESOLVE,
    LK_CALLER, LK_PREFIX, MINT_ONCE, OBS_ATTACH, OBS_CREATE, OBS_FINAL, OBS_READY, OBS_REFUSED,
    P_COMMITTED, P_CONNECT, P_ENTITLE, P_JUDGED, P_LOOKUP, P_MINTED, P_OBSERVED, P_RENDEZVOUS,
    P_RV_FAILED, P_SIGNED, P_STORE_FAILED, P_TRUST, P_WORK, RV_ACCEPT, RV_REMOTE, SIGNED_ALGORITHM,
    SIGNED_VERIFIED, SIGN_JWS_COMPACT, SIGN_JWS_DETACHED, TRUST_SERVES, TRUST_STATE, TS_APPROVED,
    TS_SIGHTED, WORK_FIND, WORK_LIVE, WORK_OPEN, WORK_SETTLE, WORK_SETTLED,
};
use busbar_plugin_abi::records::{commit, tag as g, RecPredRec, RecPutRec, Records, Reply, Writer};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn};
use busbar_ports::PortError;

use super::{
    DurableDecider, DurableWork, IntentHost, Looked, Namespace, Resolver, TrustItems, WorkDecider,
    WorkIntent, WorkOutcome,
};
use crate::plane_driver::port_channels::Held;
use crate::plane_driver::port_services::ObservationIn;
use crate::plane_driver::port_session::{Calls, Effects, SessionError, Task, ToClient, Violation};
use crate::plane_grants::{SignedJws, TicketMint};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};

/// A held media bridge: writes what the resolver asks of it into the host's call log.
struct Bridge {
    log: std::sync::Arc<Mutex<Vec<String>>>,
    mirrored: Option<&'static str>,
}

impl Held for Bridge {
    fn send(&mut self, _: &[u8], _: bool) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Invalid)
    }
    fn ready(&mut self, _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn remote(&mut self, description: &str) -> Result<(), RecordsDenied> {
        self.log
            .lock()
            .unwrap()
            .push(format!("remote {description}"));
        match self.mirrored {
            Some(_) => Err(RecordsDenied::Invalid),
            None => Ok(()),
        }
    }
    fn refusal(&self) -> Option<String> {
        self.mirrored.map(str::to_owned)
    }
}

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
    Entitle(&'static str),
    Sight {
        catalog: Option<[u8; 32]>,
        items: Vec<(&'static str, [u8; 32])>,
    },
    TrustServes {
        item: Option<(&'static str, Option<[u8; 32]>)>,
    },
    TrustState,
    TrustVerify,
    Rendezvous {
        exchange: u32,
        flags: u32,
        description: &'static str,
    },
    ObsScope {
        op: u32,
        scope: Option<[u8; 32]>,
    },
    Observe,
    Mint {
        flags: u32,
        record: Option<&'static [u8]>,
    },
    Sign {
        flags: u32,
    },
    Connect {
        op: u32,
        return_to: Option<&'static str>,
    },
    Judge {
        dest: &'static str,
        class: u32,
        flags: u32,
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
            It::Entitle(grant) => sink(PlaneOut::Entitle { check: 3, grant }),
            It::Sight { catalog, items } => {
                let mut nested = Reply::new();
                for (name, digest) in items {
                    nested
                        .put_pair(busbar_plugin_abi::plane::tag::TR_ITEM, name, digest)
                        .unwrap();
                }
                sink(PlaneOut::Sight {
                    party: "github",
                    catalog: *catalog,
                    items: Records::new(nested.as_bytes()),
                });
            }
            It::TrustServes { item } => sink(PlaneOut::Trust {
                check: 8,
                op: TRUST_SERVES,
                party: "github",
                item: *item,
            }),
            It::TrustState => sink(PlaneOut::Trust {
                check: 9,
                op: TRUST_STATE,
                party: "github",
                item: None,
            }),
            It::Rendezvous {
                exchange,
                flags,
                description,
            } => sink(PlaneOut::Rendezvous {
                exchange: *exchange,
                flags: *flags,
                description,
            }),
            It::ObsScope { op, scope } => {
                let mut require = Reply::new();
                require
                    .put_text(busbar_plugin_abi::plane::tag::OBS_REQUIRE, "tokens")
                    .unwrap();
                sink(PlaneOut::ObsScope {
                    check: 11,
                    op: *op,
                    scope: *scope,
                    require: Records::new(require.as_bytes()),
                });
            }
            It::Observe => {
                let mut counts = Reply::new();
                counts
                    .put_pod_tail(
                        busbar_plugin_abi::plane::tag::OBS_COUNT,
                        &UsageRec {
                            amount: 42,
                            scale: 3,
                            source: 1,
                        },
                        b"tokens",
                    )
                    .unwrap();
                sink(PlaneOut::Observe {
                    check: 12,
                    state: OBS_FINAL,
                    rated_subject: 0,
                    revision_order: 7,
                    scope: [9; 32],
                    event: b"ev",
                    component: b"comp",
                    revision: Some(b"rev"),
                    counts: Records::new(counts.as_bytes()),
                    evidence: Some(b"evid"),
                });
            }
            It::TrustVerify => sink(PlaneOut::TrustVerify {
                check: 10,
                party: "github",
                payload: b"doc",
                signatures: b"[]",
            }),
            It::Mint { flags, record } => sink(PlaneOut::Mint {
                check: 5,
                flags: *flags,
                ttl_s: 60,
                scope: Some("realtime"),
                audience: Some("ticket"),
                prefix: Some("ek_"),
                record: *record,
            }),
            It::Sign { flags } => sink(PlaneOut::Sign {
                check: 6,
                flags: *flags,
                payload: b"card",
            }),
            It::Connect { op, return_to } => sink(PlaneOut::Connect {
                check: 7,
                op: *op,
                upstream: "github",
                return_to: *return_to,
            }),
            It::Judge { dest, class, flags } => sink(PlaneOut::Judge {
                check: 4,
                class: *class,
                flags: *flags,
                dest,
            }),
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
    calls: std::sync::Arc<Mutex<Vec<String>>>,
    present: Vec<(Vec<u8>, Vec<u8>)>,
    /// A LOOKUP hands over its hits and then fails.
    lookup_torn: bool,
    store_denied: bool,
    conflict_at: Option<u32>,
    commit_denied: bool,
    work: Option<WorkOutcome<'static>>,
    granted: Vec<&'static str>,
    verdict: u32,
    refuse: Option<u32>,
    conn_state: u32,
    distrust: u32,
    signed: (u32, &'static str),
    state_items: Vec<busbar_ports::plane::TrustItem<'static>>,
    sight_denied: bool,
    rendezvous: Option<RecordsDenied>,
    mirrored: Option<&'static str>,
    obs_status: u32,
    work_identity: Mutex<Vec<u8>>,
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
        looked: &mut Looked,
    ) -> Result<(), RecordsDenied> {
        self.note(format!(
            "lookup {} subject={}",
            String::from_utf8_lossy(key),
            scope.subject.is_some()
        ));
        self.present
            .iter()
            .filter(|(k, _)| {
                if flags & LK_PREFIX != 0 {
                    k.starts_with(key)
                } else {
                    k == key
                }
            })
            .take(limit as usize)
            .for_each(|(k, v)| looked.push(&[k.as_slice()], v));
        if self.lookup_torn {
            return Err(RecordsDenied::Unavailable);
        }
        Ok(())
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

    fn work<'a>(&self, w: &WorkIntent<'a>) -> WorkOutcome<'a> {
        *self.work_identity.lock().unwrap() = w.identity.to_vec();
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

    fn signal_command(&self, authority: &crate::channels::authority::ChannelAuthority, key: &[u8]) {
        assert!(authority.is_live());
        self.note(format!("command signal {}", String::from_utf8_lossy(key)));
    }

    fn entitle(&self, identity: &[u8], grant: &str) -> bool {
        self.note(format!(
            "entitle {grant} identity={}",
            String::from_utf8_lossy(identity)
        ));
        self.granted.contains(&grant)
    }

    fn judge(&self, dest: &str, class: u32, flags: u32) -> u32 {
        self.note(format!("judge {dest} class={class} flags={flags}"));
        self.verdict
    }

    fn mint(&self, m: TicketMint<'_>) -> Result<(Box<str>, u64), u32> {
        self.note(format!(
            "mint subject={} scope={} aud={} ttl={} once={} prefix={} record={}",
            m.subject,
            m.scope,
            m.audience,
            m.ttl_s,
            m.once,
            m.prefix,
            m.record.len()
        ));
        match self.refuse {
            Some(code) => Err(code),
            None => Ok((format!("{}bbt1.xyz", m.prefix).into(), 1234)),
        }
    }

    fn sign(&self, payload: &[u8], detached: bool) -> Result<SignedJws, u32> {
        self.note(format!(
            "sign {} detached={detached}",
            String::from_utf8_lossy(payload)
        ));
        match self.refuse {
            Some(code) => Err(code),
            None if detached => Ok(SignedJws::Detached {
                protected: "PROT".into(),
                signature: "SIG".into(),
            }),
            None => Ok(SignedJws::Compact("h.p.s".into())),
        }
    }

    fn sight(
        &self,
        party: &str,
        catalog: Option<[u8; 32]>,
        items: &[(&str, [u8; 32])],
    ) -> Result<(), RecordsDenied> {
        self.note(format!(
            "sight {party} catalog={} items={}",
            catalog.is_some(),
            items.len()
        ));
        if self.sight_denied {
            return Err(RecordsDenied::Unavailable);
        }
        Ok(())
    }

    fn trust_serves(&self, party: &str, item: Option<(&str, Option<[u8; 32]>)>) -> u32 {
        self.note(format!(
            "trust_serves {party} item={:?}",
            item.map(|(name, digest)| (name, digest.is_some()))
        ));
        self.distrust
    }

    fn trust_state(&self, party: &str, items: &mut TrustItems) -> (u32, Option<[u8; 32]>) {
        self.note(format!("trust_state {party}"));
        for item in &self.state_items {
            items.push(item);
        }
        (self.distrust, None)
    }

    fn trust_verify(
        &self,
        party: &str,
        payload: &[u8],
        signatures: &[u8],
        named: &mut String,
    ) -> u32 {
        self.note(format!(
            "trust_verify {party} {} {}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(signatures)
        ));
        named.push_str(self.signed.1);
        self.signed.0
    }

    fn rendezvous_accept(
        &self,
        route: u32,
        offer: &str,
    ) -> Result<(Box<str>, Box<dyn Held>), RecordsDenied> {
        self.note(format!("accept route={route} offer={offer}"));
        match self.rendezvous.clone() {
            Some(denied) => Err(denied),
            None => Ok((
                "local-answer".into(),
                Box::new(Bridge {
                    log: self.calls.clone(),
                    mirrored: self.mirrored,
                }),
            )),
        }
    }

    fn obs_scope(
        &self,
        identity: &[u8],
        op: u32,
        scope: Option<[u8; 32]>,
        require: &[&str],
    ) -> (u32, Option<[u8; 32]>) {
        self.note(format!(
            "obs_scope identity={} op={op} scope={} require={require:?}",
            String::from_utf8_lossy(identity),
            scope.is_some()
        ));
        (self.obs_status, Some([6; 32]))
    }

    fn observe(&self, identity: &[u8], o: &ObservationIn<'_>) -> (u32, Vec<u8>) {
        self.note(format!(
            "observe identity={} scope={} event={} component={} revision={:?} state={} counts={:?} evidence={}",
            String::from_utf8_lossy(identity),
            o.scope == [9; 32],
            String::from_utf8_lossy(o.event),
            String::from_utf8_lossy(o.component),
            o.revision.map(|(r, order)| (String::from_utf8_lossy(r).into_owned(), order)),
            o.state,
            o.counts,
            String::from_utf8_lossy(o.evidence)
        ));
        (self.obs_status, b"receipt".to_vec())
    }

    fn connect(
        &self,
        op: u32,
        subject: &str,
        upstream: &str,
        return_to: Option<&str>,
    ) -> (u32, Option<Box<str>>) {
        self.note(format!(
            "connect op={op} subject={subject} upstream={upstream} return_to={return_to:?}"
        ));
        let url = (op == CONNECT_BEGIN && self.conn_state == CONN_READY)
            .then(|| Box::from("https://idp.example/consent"));
        (self.conn_state, url)
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

/// A read that fails after the host handed hits over is a miss: none of its hits reach the plane.
#[test]
fn a_lookup_that_fails_part_way_reads_as_a_miss_with_none_of_its_hits() {
    let script = Script {
        request: vec![lookup(b"k")],
        ..Script::default()
    };
    let host = Host {
        present: vec![(b"k".to_vec(), b"v".to_vec())],
        lookup_torn: true,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    let got = script.got();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_LOOKUP));
    assert!(hits_of(&got[0].2).is_empty());
}

/// The task's read buffer is cleared between the LOOKUPs of one answer: a miss after a hit repeats nothing.
#[test]
fn a_miss_after_a_hit_in_one_answer_carries_none_of_the_earlier_hits() {
    let script = Script {
        request: vec![
            It::Lookup {
                flags: LK_PREFIX,
                limit: 4,
                key: b"a/".to_vec(),
            },
            lookup(b"none"),
        ],
        ..Script::default()
    };
    let host = Host {
        present: vec![
            (b"a/1".to_vec(), b"x".to_vec()),
            (b"a/2".to_vec(), b"y".to_vec()),
        ],
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    let got = script.got();
    assert_eq!(got.len(), 1);
    assert_eq!(
        hits_of(&got[0].2),
        vec![
            (0, b"a/1".to_vec(), b"x".to_vec()),
            (0, b"a/2".to_vec(), b"y".to_vec()),
        ]
    );
}

/// The read buffer hands back exactly what was pushed, in order, and forgets what a rewind or a clear drops.
#[test]
fn the_lookup_read_buffer_keeps_hits_in_order_and_rewinds_to_a_mark() {
    let mut looked = Looked::default();
    looked.push(&[b"ch".as_slice(), 7u64.to_be_bytes().as_slice()], b"one");
    let mark = looked.mark();
    looked.push(&[b"k".as_slice()], b"");
    assert_eq!(looked.len(), 2);
    let all: Vec<(Vec<u8>, Vec<u8>)> = looked
        .hits()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();
    assert_eq!(
        all,
        vec![
            (
                [b"ch".as_slice(), 7u64.to_be_bytes().as_slice()].concat(),
                b"one".to_vec()
            ),
            (b"k".to_vec(), Vec::new()),
        ]
    );
    looked.rewind(mark);
    assert_eq!(looked.len(), 1);
    assert_eq!(
        looked.hits().next().map(|(_, value)| value),
        Some(&b"one"[..])
    );
    looked.chain = Some((3, 0));
    looked.clear();
    assert!(looked.is_empty());
    assert_eq!(looked.chain, None);
    assert_eq!(looked.hits().count(), 0);
}

/// The trust item buffer hands back each item as it was pushed, in order, and a clear empties it.
#[test]
fn the_trust_item_buffer_keeps_items_in_order() {
    let mut items = TrustItems::default();
    assert!(items.is_empty());
    items.push(&busbar_ports::plane::TrustItem {
        name: "tool",
        verdict: DISTRUST_NONE,
        approved: Some([5; 32]),
        sighted: None,
    });
    items.push(&busbar_ports::plane::TrustItem {
        name: "",
        verdict: DISTRUST_UNSIGHTED,
        approved: None,
        sighted: Some([6; 32]),
    });
    /// An item's name, verdict, approved digest and sighted digest, owned.
    type Row = (String, u32, Option<[u8; 32]>, Option<[u8; 32]>);
    let all: Vec<Row> = items
        .iter()
        .map(|i| (i.name.to_owned(), i.verdict, i.approved, i.sighted))
        .collect();
    assert_eq!(
        all,
        vec![
            ("tool".to_owned(), DISTRUST_NONE, Some([5; 32]), None),
            (String::new(), DISTRUST_UNSIGHTED, None, Some([6; 32])),
        ]
    );
    items.clear();
    assert!(items.is_empty());
    assert_eq!(items.iter().count(), 0);
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
fn an_enforcing_hook_holds_a_mutation_before_a_local_response() {
    let script = Script {
        request: vec![
            It::Store {
                flags: 0,
                ttl_s: 30,
                key: b"s".to_vec(),
                value: b"secret".to_vec(),
            },
            It::Respond(200),
        ],
        ..Script::default()
    };
    let host = Host::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    let held = task
        .resolve_before_hooks(first, &Resolver::new(&host, None), &Quiet)
        .unwrap();
    assert!(
        host.seen().is_empty(),
        "a hook refusal must leave the Store untouched"
    );
    assert_eq!(
        held[0].intents.len(),
        1,
        "the accepted stage releases the original intent once"
    );
}

#[test]
fn a_hook_prerequisite_never_reads_before_its_held_mutation() {
    let script = Script {
        request: vec![
            It::Store {
                flags: 0,
                ttl_s: 30,
                key: b"s".to_vec(),
                value: b"new".to_vec(),
            },
            lookup(b"s"),
        ],
        ..Script::default()
    };
    let host = Host::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    assert!(task
        .resolve_before_hooks(first, &Resolver::new(&host, None), &Quiet)
        .is_err());
    assert!(
        host.seen().is_empty(),
        "neither mutation nor stale read may escape the barrier"
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
        let (answer, tail) = Records::new(&got[0].2)
            .next()
            .unwrap()
            .unwrap()
            .pod_tail::<WorkAns>()
            .unwrap();
        (answer, tail.to_vec())
    };
    let (none, _) = work(Host::default());
    assert_eq!((none.check, none.status, none.state), (9, R_UNSUPPORTED, 0));
    let (live, tail) = work(Host {
        work: Some(WorkOutcome {
            status: 0,
            state: busbar_plugin_abi::plane::WORK_LIVE,
            reference: "ref1".into(),
            target: "".into(),
        }),
        ..Host::default()
    });
    assert_eq!(
        (live.status, live.state),
        (0, busbar_plugin_abi::plane::WORK_LIVE)
    );
    let nested = Records::new(&tail).next().unwrap().unwrap();
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

#[tokio::test]
async fn admitted_command_signal_never_falls_back_to_subject_or_instance_broadcast() {
    use crate::upstreams::{ProgramPin, StdioCommand, UpstreamDef, UpstreamTls};
    let definition = Arc::new(UpstreamDef {
        name: "tool".into(),
        resource: None,
        allow_private: false,
        url: None,
        auth: None,
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        command: Some(StdioCommand {
            argv: vec!["unused-fixture-command".into()],
            env: Vec::new(),
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s: 300,
        }),
    });
    let fixture =
        crate::plane_driver::request_admission::CommandAdmissionFixture::new(definition).await;
    let host = Host::default();
    for flags in [0, LK_CALLER] {
        super::signal_admitted(&host, &fixture.request, flags, b"key", Some([3; 32]));
    }
    assert_eq!(host.seen(), ["command signal key", "command signal key"]);
    fixture.request.context().retire();
    super::signal_admitted(&host, &fixture.request, 0, b"late", None);
    assert_eq!(host.seen().len(), 2);
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

/// Runs the request answer's intents for a request with a verified principal: its ID_SUBJECT text and the
/// identity records the route admitted it with.
fn run_as(
    script: &Script,
    host: &Host,
    identity: &[u8],
) -> Result<Vec<crate::plane_driver::port_session::Answer>, SessionError> {
    let (mut task, first) = Task::begin(script, &req(), b"", &Quiet)?;
    let resolver = Resolver::new(host, None).with_principal("alice", identity);
    task.resolve(first, &resolver, &Quiet)
}

fn entitle_answers(bytes: &[u8]) -> Vec<(u32, u32)> {
    Records::new(bytes)
        .map(|rec| {
            let rec = rec.unwrap();
            assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::ENTITLE_ANS);
            let ans = rec.pod::<busbar_plugin_abi::plane::EntitleAns>().unwrap();
            (ans.check, ans.granted)
        })
        .collect()
}

#[test]
fn entitle_asks_the_host_with_the_requests_identity_and_answers_one_ans_per_intent() {
    let script = Script {
        request: vec![It::Entitle("mcp_tool:search"), It::Entitle("pool:realtime")],
        ..Script::default()
    };
    let host = Host {
        granted: vec!["pool:realtime"],
        ..Host::default()
    };
    run_as(&script, &host, b"ID").unwrap();
    assert_eq!(
        host.seen(),
        [
            "entitle mcp_tool:search identity=ID",
            "entitle pool:realtime identity=ID"
        ]
    );
    let got = script.got();
    assert_eq!(got.len(), 1, "one piece for the whole kind");
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_ENTITLE));
    assert_eq!(entitle_answers(&got[0].2), [(3, 0), (3, 1)]);
}

#[test]
fn entitle_with_no_verified_principal_is_not_granted_and_the_host_is_never_asked() {
    let script = Script {
        request: vec![It::Entitle("pool:realtime")],
        ..Script::default()
    };
    let host = Host {
        granted: vec!["pool:realtime"],
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert!(host.seen().is_empty());
    let got = script.got();
    assert_eq!(got[0].1, P_ENTITLE);
    assert_eq!(entitle_answers(&got[0].2), [(3, 0)]);
}

#[test]
fn judge_hands_the_destination_to_the_host_and_answers_the_verdict_as_p_judged() {
    let script = Script {
        request: vec![It::Judge {
            dest: "http://10.0.0.1/x",
            class: 1,
            flags: JUDGE_REFUSE_PRIVATE,
        }],
        ..Script::default()
    };
    let host = Host {
        verdict: DEST_INTERNAL,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert_eq!(
        host.seen(),
        [format!(
            "judge http://10.0.0.1/x class=1 flags={JUDGE_REFUSE_PRIVATE}"
        )]
    );
    let got = script.got();
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_JUDGED));
    let rec = Records::new(&got[0].2).next().unwrap().unwrap();
    assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::JUDGE_ANS);
    let ans = rec.pod::<busbar_plugin_abi::plane::JudgeAns>().unwrap();
    assert_eq!((ans.check, ans.verdict), (4, DEST_INTERNAL));
}

#[test]
fn judge_with_a_class_past_four_or_an_unknown_flag_is_the_planes_fault_and_asks_nothing() {
    for (class, flags) in [(5, 0), (0, 4), (0, JUDGE_RESOLVE | 8)] {
        let script = Script {
            request: vec![It::Judge {
                dest: "example.com",
                class,
                flags,
            }],
            ..Script::default()
        };
        let host = Host::default();
        let err = run(&script, &host, None).unwrap_err();
        assert!(
            matches!(err, SessionError::Violation(Violation::BadJudge)),
            "class {class} flags {flags}: {err:?}"
        );
        assert!(host.seen().is_empty());
    }
}

#[test]
fn entitle_and_judge_pieces_follow_the_lookup_piece_in_the_if_order() {
    let script = Script {
        request: vec![
            It::Judge {
                dest: "example.com",
                class: 0,
                flags: 0,
            },
            It::Entitle("g"),
            lookup(b"k"),
        ],
        ..Script::default()
    };
    run_as(&script, &Host::default(), b"ID").unwrap();
    let kinds: Vec<u32> = script.got().iter().map(|p| p.1).collect();
    assert_eq!(kinds, [P_LOOKUP, P_ENTITLE, P_JUDGED]);
}

fn only_piece(script: &Script, flags: u32) -> Vec<u8> {
    let got = script.got();
    assert_eq!(got.len(), 1, "one piece for the whole kind");
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, flags));
    got[0].2.clone()
}

#[test]
fn mint_seals_a_ticket_for_the_verified_subject_and_answers_minted_with_its_text_and_expiry() {
    let script = Script {
        request: vec![It::Mint {
            flags: MINT_ONCE,
            record: Some(b"rec"),
        }],
        ..Script::default()
    };
    let host = Host::default();
    run_as(&script, &host, b"ID").unwrap();
    assert_eq!(
        host.seen(),
        ["mint subject=alice scope=realtime aud=ticket ttl=60 once=true prefix=ek_ record=3"]
    );
    let bytes = only_piece(&script, P_MINTED);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::MINTED);
    let (ans, text) = rec.pod_tail::<MintedRec>().unwrap();
    assert_eq!(
        (ans.check, ans.status, ans.expires_at_s, text),
        (5, 0, 1234, &b"ek_bbt1.xyz"[..])
    );
}

#[test]
fn mint_with_no_verified_subject_is_denied_and_the_host_is_never_asked() {
    let script = Script {
        request: vec![It::Mint {
            flags: 0,
            record: None,
        }],
        ..Script::default()
    };
    let host = Host::default();
    run(&script, &host, None).unwrap();
    assert!(host.seen().is_empty());
    let bytes = only_piece(&script, P_MINTED);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, text) = rec.pod_tail::<MintedRec>().unwrap();
    assert_eq!((ans.status, ans.expires_at_s, text.len()), (R_DENIED, 0, 0));
}

#[test]
fn a_mint_the_host_refuses_answers_its_generic_code_and_no_ticket() {
    let script = Script {
        request: vec![It::Mint {
            flags: 0,
            record: None,
        }],
        ..Script::default()
    };
    let host = Host {
        refuse: Some(R_UNSUPPORTED),
        ..Host::default()
    };
    run_as(&script, &host, b"ID").unwrap();
    let bytes = only_piece(&script, P_MINTED);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, text) = rec.pod_tail::<MintedRec>().unwrap();
    assert_eq!((ans.status, text.len()), (R_UNSUPPORTED, 0));
}

#[test]
fn sign_answers_a_compact_jws_or_the_detached_pieces_or_a_refusal() {
    let signed = |flags: u32, refuse: Option<u32>| {
        let script = Script {
            request: vec![It::Sign { flags }],
            ..Script::default()
        };
        let host = Host {
            refuse,
            ..Host::default()
        };
        run(&script, &host, None).unwrap();
        (host.seen(), only_piece(&script, P_SIGNED))
    };
    let (seen, bytes) = signed(SIGN_JWS_COMPACT, None);
    assert_eq!(seen, ["sign card detached=false"]);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::SIGNED);
    let (ans, tail) = rec.pod_tail::<SignedRec>().unwrap();
    assert_eq!((ans.check, ans.status, tail), (6, 0, &b"h.p.s"[..]));

    let (seen, bytes) = signed(SIGN_JWS_DETACHED, None);
    assert_eq!(seen, ["sign card detached=true"]);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, tail) = rec.pod_tail::<SignedRec>().unwrap();
    assert_eq!(ans.status, 0);
    let nested: Vec<(u16, String)> = Records::new(tail)
        .map(|r| {
            let r = r.unwrap();
            (r.tag, r.text().unwrap().to_owned())
        })
        .collect();
    assert_eq!(
        nested,
        [
            (
                busbar_plugin_abi::plane::tag::SG_PROTECTED,
                "PROT".to_owned()
            ),
            (
                busbar_plugin_abi::plane::tag::SG_SIGNATURE,
                "SIG".to_owned()
            )
        ]
    );

    let (_, bytes) = signed(SIGN_JWS_COMPACT, Some(R_UNSUPPORTED));
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, tail) = rec.pod_tail::<SignedRec>().unwrap();
    assert_eq!((ans.status, tail.len()), (R_UNSUPPORTED, 0));
}

#[test]
fn connect_runs_as_the_verified_subject_and_answers_the_state_and_the_begin_url() {
    let connect = |op: u32, subject: bool| {
        let script = Script {
            request: vec![It::Connect {
                op,
                return_to: Some("/done"),
            }],
            ..Script::default()
        };
        let host = Host {
            conn_state: CONN_READY,
            ..Host::default()
        };
        if subject {
            run_as(&script, &host, b"ID").unwrap();
        } else {
            run(&script, &host, None).unwrap();
        }
        (host.seen(), only_piece(&script, P_CONNECT))
    };
    let (seen, bytes) = connect(CONNECT_BEGIN, true);
    assert_eq!(
        seen,
        ["connect op=1 subject=alice upstream=github return_to=Some(\"/done\")"]
    );
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::CONNECT_ANS);
    let (ans, url) = rec.pod_tail::<ConnectAns>().unwrap();
    assert_eq!(
        (ans.check, ans.state, url),
        (7, CONN_READY, &b"https://idp.example/consent"[..])
    );

    // STATUS carries no URL.
    let (_, bytes) = connect(CONNECT_STATUS, true);
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, url) = rec.pod_tail::<ConnectAns>().unwrap();
    assert_eq!((ans.state, url.len()), (CONN_READY, 0));

    // No verified subject: refused here, the host never asked.
    let (seen, bytes) = connect(CONNECT_BEGIN, false);
    assert!(seen.is_empty());
    let rec = Records::new(&bytes).next().unwrap().unwrap();
    let (ans, url) = rec.pod_tail::<ConnectAns>().unwrap();
    assert_eq!((ans.state, url.len()), (CONN_REFUSED, 0));
}

#[test]
fn minted_signed_and_connect_pieces_come_after_entitle_and_judged_in_the_if_order() {
    let script = Script {
        request: vec![
            It::Connect {
                op: CONNECT_STATUS,
                return_to: None,
            },
            It::Sign {
                flags: SIGN_JWS_COMPACT,
            },
            It::Mint {
                flags: 0,
                record: None,
            },
            It::Judge {
                dest: "example.com",
                class: 0,
                flags: 0,
            },
            It::Entitle("g"),
        ],
        ..Script::default()
    };
    run_as(&script, &Host::default(), b"ID").unwrap();
    let kinds: Vec<u32> = script.got().iter().map(|p| p.1).collect();
    assert_eq!(kinds, [P_ENTITLE, P_JUDGED, P_MINTED, P_SIGNED, P_CONNECT]);
}

fn trust_answers(bytes: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
    Records::new(bytes)
        .map(|rec| {
            let rec = rec.unwrap();
            assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::TRUST_ANS);
            let (ans, tail) = rec.pod_tail::<TrustAns>().unwrap();
            (ans.check, ans.verdict, tail.to_vec())
        })
        .collect()
}

#[test]
fn a_sighting_is_recorded_before_the_trust_of_the_same_answer_is_judged() {
    let script = Script {
        request: vec![
            It::TrustServes {
                item: Some(("tool", None)),
            },
            It::Sight {
                catalog: Some([1; 32]),
                items: vec![("tool", [2; 32]), ("other", [3; 32])],
            },
        ],
        ..Script::default()
    };
    let host = Host {
        distrust: DISTRUST_CHANGED,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert_eq!(
        host.seen(),
        [
            "sight github catalog=true items=2",
            "trust_serves github item=Some((\"tool\", false))"
        ]
    );
    let bytes = only_piece(&script, P_TRUST);
    assert_eq!(trust_answers(&bytes), [(8, DISTRUST_CHANGED, vec![])]);
}

#[test]
fn a_sighting_the_book_cannot_record_is_not_answered_and_does_not_end_the_session() {
    let script = Script {
        request: vec![It::Sight {
            catalog: None,
            items: vec![("tool", [2; 32])],
        }],
        ..Script::default()
    };
    let host = Host {
        sight_denied: true,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert!(script.got().is_empty(), "SIGHT has no answer");
}

#[test]
fn trust_serves_state_and_verify_answer_one_trust_ans_each_in_intent_order() {
    let script = Script {
        request: vec![
            It::TrustVerify,
            It::TrustState,
            It::TrustServes {
                item: Some(("tool", Some([4; 32]))),
            },
        ],
        ..Script::default()
    };
    let host = Host {
        distrust: DISTRUST_NOT_APPROVED,
        signed: (SIGNED_ALGORITHM, "ES512"),
        state_items: vec![
            busbar_ports::plane::TrustItem {
                name: "tool",
                verdict: DISTRUST_NONE,
                approved: Some([5; 32]),
                sighted: Some([5; 32]),
            },
            busbar_ports::plane::TrustItem {
                name: "new",
                verdict: DISTRUST_UNSIGHTED,
                approved: None,
                sighted: None,
            },
        ],
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert_eq!(
        host.seen(),
        [
            "trust_verify github doc []",
            "trust_state github",
            "trust_serves github item=Some((\"tool\", true))"
        ]
    );
    let bytes = only_piece(&script, P_TRUST);
    let answers = trust_answers(&bytes);
    assert_eq!(answers.len(), 3);
    // VERIFY: the verdict and the named algorithm as the tail.
    assert_eq!(
        (answers[0].0, answers[0].1, &answers[0].2[..]),
        (10, SIGNED_ALGORITHM, &b"ES512"[..])
    );
    // STATE: the verdict and nested TR_ITEM_STATE*.
    assert_eq!((answers[1].0, answers[1].1), (9, DISTRUST_NOT_APPROVED));
    let states: Vec<(u32, u32, Vec<u8>)> = Records::new(&answers[1].2)
        .map(|rec| {
            let rec = rec.unwrap();
            assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::TR_ITEM_STATE);
            let (st, tail) = rec.pod_tail::<TrustItemState>().unwrap();
            (st.verdict, st.flags, tail.to_vec())
        })
        .collect();
    let mut first = b"tool".to_vec();
    first.extend_from_slice(&[5; 32]);
    first.extend_from_slice(&[5; 32]);
    assert_eq!(
        states,
        [
            (DISTRUST_NONE, TS_APPROVED | TS_SIGHTED, first),
            (DISTRUST_UNSIGHTED, 0, b"new".to_vec())
        ]
    );
    // SERVES: the verdict, no tail.
    assert_eq!(
        (answers[2].0, answers[2].1, answers[2].2.len()),
        (8, DISTRUST_NOT_APPROVED, 0)
    );
}

/// A host that implements only what the trait requires: every service intent keeps its default.
struct Bare;

impl IntentHost for Bare {
    fn lookup(
        &self,
        _: Scope,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut Looked,
    ) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn store(&self, _: Scope, _: u32, _: u64, _: &[u8], _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn delete(&self, _: Scope, _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn commit(&self, _: Scope, _: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        Ok(CommitOutcome::Applied)
    }
    fn push(&self, _: u64, _: &[u8]) -> Result<(), RecordsDenied> {
        Ok(())
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

#[test]
fn a_host_with_no_service_installed_answers_fail_closed() {
    let host = Bare;
    assert!(!host.entitle(b"ID", "g"));
    assert_ne!(host.judge("example.com", 0, 0), DEST_ALLOWED);
    assert!(host
        .mint(TicketMint {
            subject: "alice",
            scope: "",
            audience: "ticket",
            ttl_s: 60,
            once: false,
            prefix: "",
            record: &[],
        })
        .is_err());
    assert!(host.sign(b"x", false).is_err());
    assert_eq!(
        host.connect(CONNECT_STATUS, "alice", "github", None).0,
        CONN_REFUSED
    );
    assert_ne!(host.trust_serves("github", None), DISTRUST_NONE);
    let mut items = TrustItems::default();
    let (verdict, root) = host.trust_state("github", &mut items);
    assert_ne!(verdict, DISTRUST_NONE);
    assert!(items.is_empty());
    assert!(
        root.is_none(),
        "a missing trust service cannot supply a root"
    );
    assert_ne!(
        host.trust_verify("github", b"d", b"[]", &mut String::new()),
        SIGNED_VERIFIED
    );
    assert!(host.sight("github", None, &[]).is_err());
}

fn refusal_of_piece(bytes: &[u8]) -> (u32, u32, String) {
    let rec = Records::new(bytes).next().unwrap().unwrap();
    assert_eq!(rec.tag, busbar_plugin_abi::plane::tag::REFUSAL);
    let (head, text) = rec.pod_tail::<RefusalRec>().unwrap();
    (
        head.status,
        head.code,
        String::from_utf8(text.to_vec()).unwrap(),
    )
}

#[test]
fn a_client_offer_is_accepted_on_the_requests_route_and_the_local_answer_comes_back_on_its_exchange(
) {
    let script = Script {
        request: vec![It::Rendezvous {
            exchange: 4,
            flags: RV_ACCEPT,
            description: "v=0 offer",
        }],
        ..Script::default()
    };
    let host = Host::default();
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    let resolver = Resolver::new(&host, None).with_route(7);
    task.resolve(first, &resolver, &Quiet).unwrap();
    assert_eq!(host.seen(), ["accept route=7 offer=v=0 offer"]);
    assert_eq!(
        script.got(),
        vec![(FROM_CORE, P_RENDEZVOUS, b"local-answer".to_vec())]
    );
    assert!(
        task.held.contains_key(&4),
        "the session holds the bridge under its exchange: dropping it closes the media session"
    );
}

#[test]
fn an_offer_that_cannot_be_accepted_is_p_rv_failed_with_a_refusal_on_that_exchange() {
    let script = Script {
        request: vec![It::Rendezvous {
            exchange: 4,
            flags: RV_ACCEPT,
            description: "offer",
        }],
        ..Script::default()
    };
    let host = Host {
        rendezvous: Some(RecordsDenied::Unavailable),
        ..Host::default()
    };
    let (mut task, first) = Task::begin(&script, &req(), b"", &Quiet).unwrap();
    task.resolve(first, &Resolver::new(&host, None), &Quiet)
        .unwrap();
    let got = script.got();
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_RV_FAILED));
    let (status, code, text) = refusal_of_piece(&got[0].2);
    assert_eq!((status, code), (502, F_UNAVAILABLE));
    assert!(!text.is_empty(), "core's own fixed text");
    assert!(task.held.is_empty());
}

#[test]
fn the_far_ends_answer_goes_to_the_held_bridge_and_a_mirror_failure_is_p_rv_failed_with_its_text() {
    let remote = |mirrored: Option<&'static str>| {
        let script = Script {
            request: vec![It::Rendezvous {
                exchange: 4,
                flags: RV_ACCEPT,
                description: "offer",
            }],
            ..Script::default()
        }
        .answering(vec![vec![It::Rendezvous {
            exchange: 4,
            flags: RV_REMOTE,
            description: "far answer",
        }]]);
        let host = Host {
            mirrored,
            ..Host::default()
        };
        run(&script, &host, None).unwrap();
        (host.seen(), script.got())
    };
    let (seen, got) = remote(None);
    assert_eq!(seen, ["accept route=0 offer=offer", "remote far answer"]);
    assert_eq!(got.len(), 1, "an accepted answer is not answered");

    let (_, got) = remote(Some(
        "line 0 is `audio` on the caller's leg and `video` upstream",
    ));
    assert_eq!(got.len(), 2);
    assert_eq!((got[1].0, got[1].1), (FROM_CORE, P_RV_FAILED));
    let (status, code, text) = refusal_of_piece(&got[1].2);
    assert_eq!((status, code), (400, R_INVALID));
    assert_eq!(
        text,
        "line 0 is `audio` on the caller's leg and `video` upstream"
    );
}

#[test]
fn a_far_end_answer_for_an_exchange_with_no_bridge_is_p_rv_failed() {
    let script = Script {
        request: vec![It::Rendezvous {
            exchange: 9,
            flags: RV_REMOTE,
            description: "far answer",
        }],
        ..Script::default()
    };
    run(&script, &Host::default(), None).unwrap();
    let got = script.got();
    assert_eq!((got[0].0, got[0].1), (FROM_CORE, P_RV_FAILED));
    assert_eq!(refusal_of_piece(&got[0].2).1, R_INVALID);
}

fn observed(bytes: &[u8]) -> Vec<(u16, u32, u32, Vec<u8>)> {
    Records::new(bytes)
        .map(|rec| {
            let rec = rec.unwrap();
            match rec.tag {
                busbar_plugin_abi::plane::tag::OBS_SCOPE_ANS => {
                    let (a, t) = rec.pod_tail::<ObsScopeAns>().unwrap();
                    (rec.tag, a.check, a.status, t.to_vec())
                }
                busbar_plugin_abi::plane::tag::OBS_RECEIPT => {
                    let (a, t) = rec.pod_tail::<ObsReceipt>().unwrap();
                    (rec.tag, a.check, a.status, t.to_vec())
                }
                other => panic!("unexpected tag {other:#x}"),
            }
        })
        .collect()
}

#[test]
fn obs_scope_and_observe_run_as_the_verified_principal_and_answer_in_intent_order_in_one_p_observed(
) {
    let script = Script {
        request: vec![
            It::ObsScope {
                op: OBS_CREATE,
                scope: None,
            },
            It::Observe,
        ],
        ..Script::default()
    };
    let host = Host {
        obs_status: OBS_READY,
        ..Host::default()
    };
    run_as(&script, &host, b"ID").unwrap();
    assert_eq!(
        host.seen(),
        [
            "obs_scope identity=ID op=1 scope=false require=[\"tokens\"]",
            "observe identity=ID scope=true event=ev component=comp revision=Some((\"rev\", 7)) state=2 counts=[(\"tokens\", 42, 3)] evidence=evid"
        ]
    );
    let bytes = only_piece(&script, P_OBSERVED);
    assert_eq!(
        observed(&bytes),
        [
            (
                busbar_plugin_abi::plane::tag::OBS_SCOPE_ANS,
                11,
                OBS_READY,
                vec![6; 32]
            ),
            (
                busbar_plugin_abi::plane::tag::OBS_RECEIPT,
                12,
                OBS_READY,
                b"receipt".to_vec()
            )
        ]
    );
}

#[test]
fn custody_is_the_verified_principals_so_without_one_it_is_refused_and_the_host_never_asked() {
    let script = Script {
        request: vec![
            It::ObsScope {
                op: OBS_ATTACH,
                scope: Some([6; 32]),
            },
            It::Observe,
        ],
        ..Script::default()
    };
    let host = Host {
        obs_status: OBS_READY,
        ..Host::default()
    };
    run(&script, &host, None).unwrap();
    assert!(host.seen().is_empty());
    let bytes = only_piece(&script, P_OBSERVED);
    assert_eq!(
        observed(&bytes),
        [
            (
                busbar_plugin_abi::plane::tag::OBS_SCOPE_ANS,
                11,
                OBS_REFUSED,
                vec![]
            ),
            (
                busbar_plugin_abi::plane::tag::OBS_RECEIPT,
                12,
                OBS_REFUSED,
                vec![]
            )
        ]
    );
}

#[test]
fn p_observed_comes_after_p_committed_and_before_p_work() {
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
            It::Work {
                op: WORK_OPEN,
                target: Some("/poll"),
            },
            It::Observe,
            It::Commit {
                ops: ops.as_bytes().to_vec(),
            },
            It::Rendezvous {
                exchange: 2,
                flags: RV_ACCEPT,
                description: "o",
            },
            It::Connect {
                op: CONNECT_STATUS,
                return_to: None,
            },
        ],
        ..Script::default()
    };
    run_as(&script, &Host::default(), b"ID").unwrap();
    let kinds: Vec<u32> = script.got().iter().map(|p| p.1).collect();
    assert_eq!(
        kinds,
        [P_COMMITTED, P_OBSERVED, P_WORK, P_CONNECT, P_RENDEZVOUS]
    );
}

#[test]
fn a_host_with_no_media_or_observation_service_answers_fail_closed() {
    let host = Bare;
    assert!(host.rendezvous_accept(1, "offer").is_err());
    assert_eq!(host.obs_scope(b"ID", OBS_CREATE, None, &[]).0, OBS_REFUSED);
    let o = ObservationIn {
        scope: [0; 32],
        event: b"e",
        component: b"c",
        revision: None,
        state: OBS_FINAL,
        counts: &[],
        rated_subject: 0,
        evidence: b"",
    };
    assert_eq!(host.observe(b"ID", &o).0, OBS_REFUSED);
}

/// A scripted `DurableWork`: what it was asked, and its canned answers.
#[derive(Default)]
struct Ledger {
    asked: Mutex<Vec<String>>,
    open: Option<u32>,
    found: Option<(u32, &'static str)>,
    refuse: Option<u32>,
}

impl DurableWork for Ledger {
    fn open<'a>(
        &'a self,
        _: &'a Caller<'_>,
        principal: &'a [u8],
        target: &'a str,
    ) -> BoxFut<'a, Result<Box<str>, u32>> {
        self.asked.lock().unwrap().push(format!(
            "open {} {target}",
            String::from_utf8_lossy(principal)
        ));
        let answer = match self.open.or(self.refuse) {
            Some(code) => Err(code),
            None => Ok("ref-1".into()),
        };
        Box::pin(async move { answer })
    }

    fn find<'a>(
        &'a self,
        _: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(u32, Box<str>), u32>> {
        self.asked.lock().unwrap().push(format!(
            "find {} {reference}",
            String::from_utf8_lossy(principal)
        ));
        let answer = match (self.refuse, self.found) {
            (Some(code), _) => Err(code),
            (None, Some((state, target))) => Ok((state, target.into())),
            (None, None) => Err(R_NOT_FOUND),
        };
        Box::pin(async move { answer })
    }

    fn settle<'a>(
        &'a self,
        _: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(), u32>> {
        self.asked.lock().unwrap().push(format!(
            "settle {} {reference}",
            String::from_utf8_lossy(principal)
        ));
        let answer = self.refuse.map_or(Ok(()), Err);
        Box::pin(async move { answer })
    }

    fn recoverable<'a>(
        &'a self,
        _: &'a Caller<'_>,
    ) -> BoxFut<'a, Result<Vec<crate::host_services::RecoveryWork>, &'static str>> {
        self.asked.lock().unwrap().push("recoverable".to_owned());
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn namespace() -> Namespace {
    Namespace {
        plugin: "plane-llm".into(),
        name: "llm".into(),
        instance: 1,
        slot: 0,
    }
}

/// Runs `decide` for `intent` as the principal `ID` against `ledger`; recovery routes match `/poll...`.
fn decide<'a>(
    ledger: Arc<Ledger>,
    op: u32,
    target: Option<&'a str>,
    reference: Option<&'a str>,
) -> WorkOutcome<'a> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let decider = DurableDecider::new(
        ledger,
        Box::new(|target: &str| target.starts_with("/poll")),
        rt.handle().clone(),
    );
    decider.decide(
        &namespace(),
        &WorkIntent {
            op,
            target,
            reference,
            identity: b"ID",
        },
    )
}

#[test]
fn work_open_on_a_recovery_route_opens_durable_work_for_the_principal_and_answers_live_with_its_reference(
) {
    let ledger = Arc::new(Ledger::default());
    let out = decide(ledger.clone(), WORK_OPEN, Some("/poll?id=1"), None);
    assert_eq!(*ledger.asked.lock().unwrap(), ["open ID /poll?id=1"]);
    assert_eq!(
        (out.status, out.state, &*out.reference, &*out.target),
        (0, WORK_LIVE, "ref-1", "")
    );
}

#[test]
fn work_open_for_a_target_on_no_recovery_route_or_with_none_is_invalid_and_the_ledger_is_not_touched(
) {
    let ledger = Arc::new(Ledger::default());
    for target in [Some("/data/x"), None] {
        let out = decide(ledger.clone(), WORK_OPEN, target, None);
        assert_eq!(out.status, R_INVALID, "target {target:?}");
    }
    assert!(ledger.asked.lock().unwrap().is_empty());
}

#[test]
fn work_open_core_cannot_recover_is_unsupported_so_the_plane_sends_no_paid_create() {
    let ledger = Arc::new(Ledger {
        open: Some(R_UNSUPPORTED),
        ..Ledger::default()
    });
    let out = decide(ledger, WORK_OPEN, Some("/poll"), None);
    assert_eq!((out.status, out.state), (R_UNSUPPORTED, 0));
    assert!(out.reference.is_empty());
}

#[test]
fn work_find_answers_the_state_the_reference_and_the_target_and_passes_a_refusal_through() {
    let ledger = Arc::new(Ledger {
        found: Some((WORK_SETTLED, "/poll?id=1")),
        ..Ledger::default()
    });
    let out = decide(ledger.clone(), WORK_FIND, None, Some("ref-1"));
    assert_eq!(*ledger.asked.lock().unwrap(), ["find ID ref-1"]);
    assert_eq!(
        (out.status, out.state, &*out.reference, &*out.target),
        (0, WORK_SETTLED, "ref-1", "/poll?id=1")
    );
    // Another principal's row, or an unknown one.
    for code in [R_DENIED, R_NOT_FOUND] {
        let ledger = Arc::new(Ledger {
            refuse: Some(code),
            ..Ledger::default()
        });
        let out = decide(ledger, WORK_FIND, None, Some("ref-1"));
        assert_eq!((out.status, out.state), (code, 0));
        assert!(out.reference.is_empty() && out.target.is_empty());
    }
}

#[test]
fn work_settle_settles_durably_and_answers_settled() {
    let ledger = Arc::new(Ledger::default());
    let out = decide(ledger.clone(), WORK_SETTLE, None, Some("ref-1"));
    assert_eq!(*ledger.asked.lock().unwrap(), ["settle ID ref-1"]);
    assert_eq!((out.status, out.state), (0, WORK_SETTLED));
}

#[test]
fn work_find_and_settle_without_a_reference_and_an_unknown_op_are_invalid() {
    let ledger = Arc::new(Ledger::default());
    for (op, reference) in [(WORK_FIND, None), (WORK_SETTLE, None), (99, Some("ref-1"))] {
        let out = decide(ledger.clone(), op, None, reference);
        assert_eq!(out.status, R_INVALID, "op {op}");
    }
    assert!(ledger.asked.lock().unwrap().is_empty());
}

#[test]
fn work_reaches_the_host_with_the_requests_identity() {
    let script = Script {
        request: vec![It::Work {
            op: WORK_OPEN,
            target: Some("/poll"),
        }],
        ..Script::default()
    };
    let host = Host::default();
    run_as(&script, &host, b"ID-RECORDS").unwrap();
    assert_eq!(*host.work_identity.lock().unwrap(), b"ID-RECORDS");
}
