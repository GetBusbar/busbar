// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THERE IS NO UNIX TRANSPORT (`BUSBAR-1.6.0.md` kind table: "there is no unix transport"). The

use busbar_contract::conn::{ConnError, Conns, InstanceId, NeedId, OpenDesc};
use busbar_core_connector::endpoint::{self, EndpointRefusal};
use busbar_core_connector::Connector;

const OWNER: InstanceId = InstanceId(1);
const SOCKET: &str = "unix:///run/busbar.sock";

/// A need declared over `unix` is refused at its declaration (no entry serves the scheme; the

#[test]
fn a_need_over_a_unix_scheme_is_refused() {
    let c = Connector::new();
    assert_eq!(
        c.declare_over(OWNER, NeedId(0), "unix"),
        Err(ConnError::Refused)
    );
    let desc = OpenDesc {
        target: SOCKET,
        ..OpenDesc::default()
    };
    assert_eq!(
        c.open(OWNER, NeedId(0), &desc),
        Err(ConnError::UndeclaredNeed)
    );
}

/// A `unix://` target names no host, so the endpoint check refuses it before any transport is asked

#[test]
fn a_unix_target_names_no_host_and_is_refused_before_any_dial() {
    assert_eq!(
        endpoint::check(SOCKET),
        Err(EndpointRefusal::NoHost {
            target: SOCKET.to_owned(),
        })
    );
}
