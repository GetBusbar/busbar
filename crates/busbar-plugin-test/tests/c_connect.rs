// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CONNECT (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10
//! lands the results; plane serving delivers them).
//!
//! W1-K10: CONNECT(BEGIN) in a mixed answer comes back last of the result kinds, as P_CONNECT CONN_PENDING with
//! the authorization URL; after the browser's callback, CONNECT(STATUS) answers CONN_READY, and no piece ever
//! carries the grant.

use std::sync::Arc;

use busbar_plugin_abi::plane::{
    tag, ConnectAns, CONNECT_BEGIN, CONNECT_STATUS, CONN_PENDING, CONN_READY, P_CONNECT,
};

use crate::k10_rig::{
    if_order, order, piece, records_of, resolve, runtime, Deployment, CALLBACK, GRANT,
};

#[test]
fn connect_results_arrive_first_in_order() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let connections = Arc::new(deployment.connections());
    let host = deployment.intents(&rt, Arc::clone(&connections));

    let pieces = resolve(&host, CONNECT_BEGIN);
    assert_eq!(order(&pieces), if_order());
    let begun = records_of::<ConnectAns>(piece(&pieces, P_CONNECT), tag::CONNECT_ANS);
    assert_eq!(begun.len(), 1);
    let (ans, url) = &begun[0];
    assert_eq!((ans.check, ans.state), (5, CONN_PENDING));
    let url = std::str::from_utf8(url).expect("URL text");
    let seen = deployment.seen();
    let challenge = seen.challenge.expect("BEGIN carried L_CODE_CHALLENGE");
    assert!(
        url.contains(&format!("code_challenge={challenge}")),
        "{url}"
    );

    let state = seen.state_key.expect("BEGIN carried core's state key");
    let back = rt.block_on(connections.callback(
        CALLBACK,
        &format!("code=c0de&iss=https://as.example&state={state}"),
    ));
    assert_eq!(
        back,
        busbar_kernel::connections::CallbackAnswer::Connected {
            location: "/settings/connections".into()
        }
    );

    let pieces = resolve(&host, CONNECT_STATUS);
    assert_eq!(order(&pieces), if_order());
    let status = records_of::<ConnectAns>(piece(&pieces, P_CONNECT), tag::CONNECT_ANS);
    assert_eq!(status.len(), 1);
    assert_eq!((status[0].0.check, status[0].0.state), (5, CONN_READY));
    assert!(status[0].1.is_empty(), "STATUS carries no tail");
    for p in &pieces {
        assert!(
            !p.bytes.windows(GRANT.len()).any(|w| w == GRANT),
            "no plane piece carries the grant"
        );
    }
}
