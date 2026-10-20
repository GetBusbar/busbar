// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{FramedFacts, StreamFacts};
use busbar_contract::conn::DeclaredConns;
use std::sync::Arc;

/// `stand_in.json` reads, and states a transport for each double.
#[test]
fn the_stand_in_facts_read_from_data() {
    let (stream, framed) = (StreamFacts::stand_in(), FramedFacts::stand_in());
    assert!(!stream.transport.is_empty() && !stream.local_prefix.is_empty());
    assert!(!framed.transport.is_empty() && !framed.secure_scheme.is_empty());
    assert_ne!(stream.transport, framed.transport);
}

/// RED: each double serves exactly the transport its facts name. Handed planted facts, it serves
/// the planted word and refuses the one `stand_in.json` names, so no word is the code's own.
#[test]
fn a_double_serves_only_the_transport_its_facts_name() {
    let framed = crate::https_conns::HttpsConns::framing(FramedFacts {
        transport: "planted-framed".into(),
        secure_scheme: "planted-secure".into(),
        default_port: 1,
    });
    assert!(framed.serves_scheme("planted-framed"));
    assert!(!framed.serves_scheme(&FramedFacts::stand_in().transport));
    assert!(!framed.serves_scheme(""));

    let stream = crate::tcp_conns::TcpConns::serving(
        StreamFacts {
            transport: "planted-stream".into(),
            local_prefix: "planted:".into(),
        },
        Arc::new(|_, _| {}),
    );
    assert!(stream.serves_scheme("planted-stream"));
    assert!(!stream.serves_scheme(&StreamFacts::stand_in().transport));
    assert!(!stream.serves_scheme(""));

    let default = crate::https_conns::HttpsConns::new();
    assert!(default.serves_scheme(&FramedFacts::stand_in().transport));
}

/// A need over the framed transport, its target and anchor read from `target_from` and
/// `trust_from`.
fn framed_need(
    target_from: &str,
    trust_from: &str,
) -> busbar_contract::abi::mechanism::rendering::ReadNeed {
    busbar_contract::abi::mechanism::rendering::ReadNeed {
        direction: busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: FramedFacts::stand_in().transport,
        auth: String::new(),
        target_from: target_from.into(),
        trust_from: trust_from.into(),
        details: busbar_contract::abi::mechanism::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// THE FAR-END TABLE, as the connector reads a need: a member-target need (`settings.*.<key>`)
/// declares with no one target or anchor, and dials each URL the plugin names; a URL the table
/// declares answers, and one it does not declare is REFUSED as an unreachable far end is (RED: no
/// dial reaches anything the inputs did not state). A single-target path that resolved to nothing
/// still refuses the need at declaration.
#[test]
fn the_far_end_table_answers_declared_urls_and_refuses_every_other() {
    use busbar_contract::conn::{ConnError, Conns, InstanceId, NeedId, OpenDesc};
    let table = crate::https_conns::HttpsConns::new();
    table.serve("https://far.example/doc", None, 200, "{}");
    let (me, member) = (InstanceId(1), NeedId(0));
    let member_need = framed_need("settings.*.url", "settings.*.anchor");
    assert_eq!(table.declare(me, member, &member_need, None, None), Ok(()));
    let open = |target: &str| {
        table.open(
            me,
            member,
            &OpenDesc {
                target,
                ..OpenDesc::default()
            },
        )
    };
    let reached = open("https://far.example/doc").expect("a declared far end answers");
    table.close(me, reached).expect("closed");
    assert_eq!(
        open("https://far.example/other").map(|_| ()),
        Err(ConnError::Refused),
        "an undeclared URL is refused"
    );
    assert_eq!(
        open("https://elsewhere.example/doc").map(|_| ()),
        Err(ConnError::Refused),
        "an undeclared host is refused"
    );
    let single = framed_need("settings.url", "");
    assert_eq!(
        table.declare(me, NeedId(1), &single, None, None),
        Err(ConnError::Refused),
        "a single target that resolved to nothing refuses the need"
    );
}
