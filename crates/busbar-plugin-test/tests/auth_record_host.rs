// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The safe auth host's explicit deployment, scoped record CAS and restart/failure fixtures.
//! Run in an isolated process: the production HOST deployment is process-wide and keep-once.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use busbar_plugin_abi::auth;
use busbar_plugin_abi::fail::{refused::R_CONFIG, Fail};
use busbar_plugin_abi::host::{Host, HostExt};
use busbar_plugin_abi::host_side::needs::NeedErr;
use busbar_plugin_abi::need::{self, ChainBytes, Commit, Mut, Pred, Record, RecordOut};
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_plugin_test::fake_needs::RecordStep;
use busbar_plugin_test::suites::harness::Harness;
use busbar_plugin_test::FakeNeeds;
use busbar_ports::auth::{AuthPort, LoginAnswer, LoginIn};
use busbar_ports::{CallCx, PortError};

const ID: [u8; 16] = *b"record-host-id16";
const KEY: &[u8] = b"state";

struct RecordAuth;
impl Open for RecordAuth {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        config.with(valid)?;
        Ok(Self)
    }
    fn check(_h: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        valid(config)?;
        ends.fetch("https://fixture.test/state", 0);
        Ok(())
    }
    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.facts(auth::FB_LOGIN_CREDENTIAL);
    }
}
fn valid(config: &[u8]) -> Result<(), Fail> {
    if config == b"{}" {
        Ok(())
    } else {
        Err(Fail::refused(R_CONFIG))
    }
}
impl busbar_plugin_abi::Auth for RecordAuth {
    async fn login(&self, h: &'static Host, _step: u32, input: ChainBytes) -> Result<Reply, Fail> {
        let command = input.with(|bytes| {
            Records::new(bytes)
                .filter_map(Result::ok)
                .find(|r| r.tag == auth::tag::L_USERNAME)
                .map(|r| String::from_utf8_lossy(r.body).into_owned())
                .unwrap()
        });
        let subject = if command == "deployment" {
            if h.deployment_id().map(|id| id.0) == Some(ID) {
                "known".to_owned()
            } else {
                "pending".to_owned()
            }
        } else if command == "get" {
            match need::record(Record::Get { key: KEY }).await? {
                RecordOut::Value(Some(value)) => String::from_utf8(value).unwrap(),
                RecordOut::Value(None) => "absent".to_owned(),
                _ => panic!("GET answer"),
            }
        } else {
            let words: Vec<_> = command.split('/').collect();
            let predicates = if words[0] == "absent" {
                vec![Pred::Absent { key: KEY }]
            } else {
                vec![
                    Pred::Present { key: KEY },
                    Pred::Equals {
                        key: KEY,
                        value: words[1].as_bytes(),
                    },
                ]
            };
            let mutations = [
                Mut::Put {
                    key: KEY,
                    value: words.last().unwrap().as_bytes(),
                    ttl_s: 0,
                },
                Mut::Put {
                    key: b"companion",
                    value: b"committed",
                    ttl_s: 0,
                },
            ];
            match need::record(Record::Commit(&Commit {
                preds: &predicates,
                muts: &mutations,
            }))
            .await?
            {
                RecordOut::Committed(Ok(())) => "applied".to_owned(),
                RecordOut::Committed(Err(index)) => format!("conflict/{index}"),
                _ => panic!("COMMIT answer"),
            }
        };
        let mut reply = Reply::new();
        reply.put(tag::ID_SUBJECT, subject.as_bytes())?;
        Ok(reply)
    }
}
busbar_plugin_abi::plugin!(Auth, RecordAuth, name: "fixture-record-auth");

fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: 1,
        stack: Default::default(),
    }
}
async fn request(port: &dyn AuthPort, command: &str) -> Result<String, PortError> {
    match port
        .login(
            cx(),
            LoginIn::Credential {
                username: command,
                password: b"",
            },
        )
        .await?
    {
        LoginAnswer::Identity(identity) => Ok(identity.subject().to_owned()),
        _ => panic!("fixture returns an identity, never a grant"),
    }
}
fn call(h: &Harness, p: &dyn AuthPort, command: &str) -> String {
    h.block_on(request(p, command)).expect("login")
}

#[test]
fn auth_record_host_preserves_atomic_state_and_observations() {
    let h = Harness::admit(PLUGIN.plugin(), FakeNeeds::new()).expect("admit");
    h.check("one", b"{}").expect("check");
    assert_eq!(h.declared().len(), 1);
    assert!(h.check("bad", b"not-json").is_err());
    assert_eq!(h.refusals().len(), 1);
    let port = h.open_auth("one", b"{}").expect("open");
    assert_eq!(call(&h, port.as_ref(), "deployment"), "pending");
    h.set_deployment(ID);
    assert_eq!(call(&h, port.as_ref(), "deployment"), "known");
    assert_eq!(call(&h, port.as_ref(), "get"), "absent");

    let answers = h.block_on(async {
        tokio::join!(
            request(port.as_ref(), "absent/first"),
            request(port.as_ref(), "absent/second")
        )
    });
    let mut answers = [answers.0.expect("first"), answers.1.expect("second")];
    answers.sort();
    assert_eq!(answers, ["applied", "conflict/0"]);
    let winner = call(&h, port.as_ref(), "get");
    assert!(winner == "first" || winner == "second");
    let before = h.records();
    assert_eq!(
        call(&h, port.as_ref(), "equals/wrong/changed"),
        "conflict/1"
    );
    assert_eq!(
        h.records(),
        before,
        "failed second predicate writes nothing"
    );

    let other = h.open_auth("two", b"{}").expect("second instance");
    assert_eq!(call(&h, other.as_ref(), "get"), "absent");
    h.needs()
        .script_record(RecordStep::Error(NeedErr::Unavailable));
    assert!(h.block_on(request(port.as_ref(), "get")).is_err());
    assert_eq!(h.records(), before);

    h.needs().script_record(RecordStep::BeforeCommit {
        key: KEY.to_vec(),
        value: b"racer".to_vec(),
    });
    assert_eq!(
        call(&h, port.as_ref(), &format!("equals/{winner}/changed")),
        "conflict/1"
    );
    assert_eq!(call(&h, port.as_ref(), "get"), "racer");
    h.needs()
        .script_record(RecordStep::CommitThenError(NeedErr::Timeout));
    assert!(h
        .block_on(request(port.as_ref(), "equals/racer/terminal"))
        .is_err());
    assert_eq!(
        call(&h, port.as_ref(), "get"),
        "terminal",
        "unknown acknowledgement preserves applied state"
    );
    assert!(h
        .needs()
        .record_calls()
        .iter()
        .all(|call| call.plugin == "fixture-record-auth"));
    assert!(h
        .needs()
        .record_calls()
        .iter()
        .any(|call| call.instance == "two"));
    assert!(h.undeclared_needs().is_empty());
    assert_eq!(h.refusals().len(), 1);
    let snapshot = h.needs().records();
    drop(other);
    drop(port);
    drop(h);

    let needs = FakeNeeds::new();
    for (plugin, instance, key, value) in snapshot {
        needs.seed_record(&plugin, &instance, &key, &value);
    }
    let reopened = Harness::admit(PLUGIN.plugin(), needs).expect("reopen registry");
    reopened.set_deployment(ID);
    let port = reopened.open_auth("one", b"{}").expect("reopen instance");
    assert_eq!(call(&reopened, port.as_ref(), "get"), "terminal");
    reopened
        .needs()
        .seed_record("another-plugin", "one", KEY, b"foreign");
    assert_eq!(call(&reopened, port.as_ref(), "get"), "terminal");
    reopened
        .needs()
        .seed_record("fixture-record-auth", "one", KEY, &[0xff, 0, 1]);
    assert!(
        reopened
            .records()
            .iter()
            .any(|r| r.plugin == "fixture-record-auth" && r.key == KEY && r.value == [0xff, 0, 1]),
        "opaque malformed consumer data is preserved verbatim"
    );
}
