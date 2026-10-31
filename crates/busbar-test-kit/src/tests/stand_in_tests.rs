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
/// scheme match, and a need over it is DECLARED as the connector declares a need over a loaded
/// transport (the loader refuses the load on a refused config-free need, kind-secret K17), while
/// every open on it is refused, so no open reaches anything; a scheme not named stays unserved.
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
    assert_eq!(framed.declare(owner, id, &need, None, None), Ok(()));
    assert_eq!(framed.declared(owner, id), Some(Ok(())));
    assert_eq!(
        busbar_contract::conn::Conns::open(
            &framed,
            owner,
            id,
            &busbar_contract::conn::OpenDesc::default()
        ),
        Err(ConnError::Refused),
        "an open on an unreached scheme reaches nothing"
    );
}

/// AN UNREACHED SCHEME IS A NAMED, REASONED, COVERED CLAIM, or the suite fails (row 114: no silent
/// skip). Each entry names its scheme, says why, and cites the `path::fn` test cells in the
/// plugin's own repo that exercise it; the scheme is one a declared need names and not the framed
/// table's own. RED before the fix: the entries were bare names, judged by nothing.
#[test]
fn an_unreached_scheme_is_named_reasoned_and_covered() {
    use crate::https_conns::judge_unreached;
    let dir = std::env::temp_dir().join(format!("unreached-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("cells")).unwrap();
    std::fs::write(
        dir.join("cells/carried.rs"),
        "#[test]\nfn the_scheme_is_carried() {}\nfn not_a_test() {}\n",
    )
    .unwrap();
    let why = "the plane suite frames one transport; the scheme's own cells carry this binding";
    let entry = |scheme: &str, why: &str, cells: &[&str]| serde_json::json!([{ "scheme": scheme, "why": why, "covered_by": cells }]);
    let needs = [
        "planted-unreached".to_string(),
        "planted-framed".to_string(),
    ];
    let ok = judge_unreached(
        &entry(
            "planted-unreached",
            why,
            &["cells/carried.rs::the_scheme_is_carried"],
        ),
        "planted-framed",
        &needs,
        &dir,
    )
    .expect("a named, reasoned, covered scheme is accepted");
    assert_eq!(ok, ["planted-unreached".to_string()]);
    for (value, names) in [
        (serde_json::json!(["planted-unreached"]), "an object"),
        (
            entry(
                "planted-unreached",
                "too short",
                &["cells/carried.rs::the_scheme_is_carried"],
            ),
            "why",
        ),
        (entry("planted-unreached", why, &[]), "covered_by"),
        (
            entry(
                "planted-unreached",
                why,
                &["cells/carried.rs::no_such_cell"],
            ),
            "no_such_cell",
        ),
        (
            entry("planted-unreached", why, &["cells/carried.rs::not_a_test"]),
            "not_a_test",
        ),
        (
            entry(
                "planted-unreached",
                why,
                &["cells/missing.rs::the_scheme_is_carried"],
            ),
            "cells/missing.rs",
        ),
        (
            entry(
                "planted-framed",
                why,
                &["cells/carried.rs::the_scheme_is_carried"],
            ),
            "framed",
        ),
        (
            entry(
                "planted-stale",
                why,
                &["cells/carried.rs::the_scheme_is_carried"],
            ),
            "no declared need",
        ),
    ] {
        let refused = judge_unreached(&value, "planted-framed", &needs, &dir)
            .expect_err("the entry is refused");
        assert!(refused.contains(names), "{value}: {refused}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// AN OPEN ON AN UNREACHED SCHEME IS COUNTED, so the suite can assert none was made: the claim is
/// that the fold never touches the scheme. RED before the fix: such an open left no trace.
#[test]
fn an_open_on_an_unreached_scheme_is_counted() {
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, Conns, InstanceId, NeedId, OpenDesc};
    let framed = crate::https_conns::HttpsConns::framing(FramedFacts {
        transport: "planted-framed".into(),
        secure_scheme: "planted-secure".into(),
        default_port: 1,
    })
    .unreached(["planted-unreached".to_string()]);
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
    assert!(framed.declare(owner, id, &need, None, None).is_ok());
    assert!(framed.unreached_opens().is_empty());
    let desc = OpenDesc::default();
    assert_eq!(framed.open(owner, id, &desc), Err(ConnError::Refused));
    assert_eq!(
        framed.unreached_opens(),
        [("planted-unreached".to_string(), 1)]
    );
}

/// THE FRAMED TABLE DECLARES AS THE CONNECTOR DECLARES (busbar-core-connector `declare`): a
/// member-target need (`settings.*.<key>`) is pinned by no one target, each member's route being
/// sealed at its own, so it is declared with none, and a member-scoped or OWNED (optional) trust
/// path that resolved to nothing leaves the public roots alone; a single-target need whose target
/// resolved to nothing is still refused. RED before the fix: the suite's table refused every need
/// whose paths resolved to nothing, so a plane's member needs could never be opened in its suite.
#[test]
fn a_member_need_is_declared_with_no_one_target_as_the_connector_declares_it() {
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, InstanceId, NeedId};
    let framed = crate::https_conns::HttpsConns::framing(FramedFacts::stand_in());
    let need = |target_from: &str, trust_from: &str| ReadNeed {
        direction: 0,
        egress_class: 0,
        transport: FramedFacts::stand_in().transport,
        auth: String::new(),
        target_from: target_from.into(),
        trust_from: trust_from.into(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    };
    let owner = InstanceId(9);
    for (i, (target, trust)) in [
        ("settings.*.url", "settings.*.client_identity"),
        ("settings.*.url", ""),
        ("", "owned.push.ca"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = NeedId(u32::try_from(i).unwrap());
        assert_eq!(
            framed.declare(owner, id, &need(target, trust), None, None),
            Ok(()),
            "{target} / {trust}"
        );
    }
    assert_eq!(
        framed.declare(owner, NeedId(7), &need("settings.url", ""), None, None),
        Err(ConnError::Refused)
    );
    assert_eq!(
        framed.declare(owner, NeedId(8), &need("", "settings.ca"), None, None),
        Err(ConnError::Refused)
    );
}

/// RED: THE FAR-END TABLE REACHES ONLY WHAT IT DECLARES. A member need opens each URL the plugin
/// names; a declared far end answers, and a URL or host the table does not declare is refused as
/// an unreachable far end is, so no dial in a suite reaches anything its inputs did not state.
#[test]
fn an_undeclared_far_end_is_refused() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, Conns, InstanceId, NeedId, OpenDesc};
    let table = crate::https_conns::HttpsConns::framing(FramedFacts::stand_in());
    table.serve("https://far.example/doc", None, 200, "{}");
    let need = ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: FramedFacts::stand_in().transport,
        auth: String::new(),
        target_from: "settings.*.url".into(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    };
    let (me, member) = (InstanceId(1), NeedId(0));
    assert_eq!(table.declare(me, member, &need, None, None), Ok(()));
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
    for undeclared in ["https://far.example/other", "https://elsewhere.example/doc"] {
        assert_eq!(
            open(undeclared).map(|_| ()),
            Err(ConnError::Refused),
            "{undeclared}"
        );
    }
}
