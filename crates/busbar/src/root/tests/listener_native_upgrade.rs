// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What core does with a verified upgrade request before any 101 (§12.27 steps 1 and 2; owner
//! decision 18: the hand-over is built for 1.6.0). The judgement is made on the head and is
//! answered only to a caller the route's chain verified (the one 401 comes first, in the data
//! admission); it is the same whichever plane the route belongs to.

use std::sync::Arc;
use std::time::Duration;

use busbar_kernel::auth::admission_table::Refusal;
use busbar_kernel::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS;

use super::{judge, session_ends, session_limit};
use crate::root::min3_boot::transports::tests::framer;
use crate::root::min3_boot::transports::ServedTransport;

fn websocket() -> ServedTransport {
    ServedTransport {
        instance: Arc::from("transport-ws"),
        port: framer(&["websocket"]),
    }
}

#[test]
fn a_request_that_does_not_ask_to_switch_is_refused_400_whatever_the_listener_has() {
    let carrier = websocket();
    for websocket in [None, Some(&carrier)] {
        let terms = judge(false, websocket, 1);
        assert_eq!(terms.refused, Some(Refusal::NotAnUpgrade));
        assert!(terms.carrier.is_none());
        assert_eq!(Refusal::NotAnUpgrade.row(true).status, 400);
    }
}

#[test]
fn with_no_websocket_transport_an_upgrade_is_refused_501() {
    let terms = judge(true, None, 1);
    assert_eq!(terms.refused, Some(Refusal::NoUpgradeTransport));
    assert!(terms.carrier.is_none());
    assert_eq!(Refusal::NoUpgradeTransport.row(true).status, 501);
}

/// The known wrong behaviour this line replaces: with a websocket transport admitted on the
/// listener, an admitted upgrade was still answered 501 ("no hand-over is linked").
#[test]
fn an_admitted_upgrade_is_handed_to_the_listeners_websocket_transport_not_refused_501() {
    let carrier = websocket();
    let terms = judge(true, Some(&carrier), 1);
    assert_eq!(
        terms.refused, None,
        "an upgrade the listener can carry is not refused"
    );
    let handed = terms.carrier.expect("the transport the connection goes to");
    assert!(
        Arc::ptr_eq(&handed.port, &carrier.port),
        "that exact admitted instance"
    );
    assert_eq!(&*handed.instance, "transport-ws");
}

/// An upgraded session is bounded by the stricter of the plane's session ceiling and the stream
/// ceiling; a side that states none (0) does not loosen the other, and with neither stated the
/// deployment's default stands: there is no unbounded session.
#[test]
fn an_upgraded_sessions_limit_is_the_stricter_of_the_two_ceilings_and_never_none() {
    for (plane, stream, limit) in [
        (0, 300, 300),
        (600, 300, 300),
        (120, 300, 120),
        (120, 0, 120),
        (300, 300, 300),
        (0, 0, DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS),
    ] {
        assert_eq!(
            session_limit(plane, stream),
            Duration::from_secs(limit),
            "plane {plane}, stream {stream}"
        );
    }
}

/// The limit runs from the request and never reaches past the request's own deadline; a limit
/// the clock cannot hold does not become no limit.
#[test]
fn an_upgraded_session_ends_at_its_limit_or_its_requests_deadline_whichever_is_first() {
    let now = tokio::time::Instant::now();
    let limit = Duration::from_secs(300);
    assert_eq!(session_ends(now, None, limit), now + limit);
    let sooner = now + Duration::from_secs(60);
    assert_eq!(session_ends(now, Some(sooner), limit), sooner);
    let later = now + Duration::from_secs(3600);
    assert_eq!(session_ends(now, Some(later), limit), now + limit);
    assert_eq!(
        session_ends(now, None, Duration::MAX),
        now + Duration::from_secs(DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS)
    );
    assert_eq!(session_ends(now, Some(sooner), Duration::MAX), sooner);
}

/// The adopting session serves the upgraded answer as its stream 1, and the delivery entry of an
/// answer on any other stream cannot be renamed yet: such a request is refused before any 101
/// (and before its unit is opened), never switched and then cut.
#[test]
fn an_upgrade_on_a_later_request_of_its_connection_is_refused_before_any_101() {
    let carrier = websocket();
    for stream in [0, 2, 3, 7] {
        let terms = judge(true, Some(&carrier), stream);
        assert_eq!(
            terms.refused,
            Some(Refusal::NoUpgradeTransport),
            "stream {stream}"
        );
        assert!(terms.carrier.is_none());
    }
}
