// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const OWNER: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

/// A declared need is answered with the shell's refusal, never a silent success; an undeclared one
/// is refused as undeclared.
#[test]
fn a_declared_need_is_refused_until_a_transport_is_composed() {
    let c = Connector::new();
    c.declare(OWNER, NeedId(0));
    let desc = OpenDesc {
        target: "127.0.0.1:1",
        ..OpenDesc::default()
    };
    assert_eq!(c.open(OWNER, NeedId(0), &desc), Err(NO_TRANSPORT_YET));
    assert_eq!(
        c.open(OWNER, NeedId(1), &desc),
        Err(ConnError::UndeclaredNeed)
    );
    assert_eq!(
        c.open(OTHER, NeedId(0), &desc),
        Err(ConnError::UndeclaredNeed)
    );
}

/// No id is live in the shell, so every id-taking operation answers closed, never a fault.
#[test]
fn an_id_the_shell_never_opened_is_closed() {
    let c = Connector::new();
    let mut buf = [0_u8; 4];
    assert_eq!(
        c.write(OWNER, ConnId(1), b"x", true),
        Err(ConnError::Closed)
    );
    assert_eq!(
        c.read(OWNER, ConnId(1), 0, &mut buf),
        Err(ConnError::Closed)
    );
    assert_eq!(c.wait(OWNER, &[ConnId(1)], 0), Err(ConnError::Closed));
    assert_eq!(c.facts(OWNER, ConnId(1)), Err(ConnError::Closed));
    assert_eq!(c.close(OWNER, ConnId(1)), Err(ConnError::Closed));
}

/// A declared need whose target is a cloud metadata host is refused before any dial.
#[test]
fn a_metadata_target_is_refused_before_any_dial() {
    let c = Connector::new();
    c.declare(OWNER, NeedId(0));
    let desc = OpenDesc {
        target: "169.254.169.254:80",
        ..OpenDesc::default()
    };
    assert_eq!(c.open(OWNER, NeedId(0), &desc), Err(ConnError::Refused));
    assert!(endpoint::check(desc.target).is_err());
}
