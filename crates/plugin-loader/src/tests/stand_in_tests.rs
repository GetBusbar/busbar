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

/// RED: a scheme the deployment serves beside the framed one, named unreached, passes the boot's
/// scheme match, and a need over it is refused at declare, so no open reaches anything; a scheme
/// not named stays unserved.
#[test]
fn an_unreached_scheme_is_served_at_boot_and_reaches_nothing() {
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, InstanceId, NeedId};
    let framed = crate::https_conns::HttpsConns::framing(FramedFacts {
        transport: "planted-framed".into(),
        secure_scheme: "planted-secure".into(),
        default_port: 1,
    })
    .unreached(["planted-unreached".to_string(), String::new()]);
    assert!(framed.serves_scheme("planted-framed"));
    assert!(framed.serves_scheme("planted-unreached"));
    assert!(!framed.serves_scheme("planted-other"));
    assert!(!framed.serves_scheme(""));
    let need = ReadNeed {
        direction: 0,
        egress_class: 0,
        transport: "planted-unreached".into(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    };
    let (owner, id) = (InstanceId(7), NeedId(0));
    assert_eq!(
        framed.declare(owner, id, &need, None, None),
        Err(ConnError::Refused)
    );
    assert_eq!(framed.declared(owner, id), Some(Err(ConnError::Refused)));
}
