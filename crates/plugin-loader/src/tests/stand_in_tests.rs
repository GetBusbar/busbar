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
