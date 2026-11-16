// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ROUTE-CRED-HEADER (ABI-MIN3-INTERFACE §14): D_ROUTE_CRED_HEADER routes and `routes.<id>.auth_instances`
//! (§12.11; K8 + L8). The plane-streaming image arm is on #217.
//!
//! W1-K8B's arms are the effective-chain rule at config load (`busbar_kernel::auth::route_chain`): (c) which
//! instances reach the twilio route and which reach a data-chain route, (d) and (e) the two CONFIG texts. Arms
//! (a), (b), (f) and (g) need the plane-streaming and auth-webhook-signature images.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_kernel::auth::route_chain::{effective_chain, ConfiguredAuth, RouteAuth};

fn headers(names: &[&str]) -> Vec<Box<str>> {
    names.iter().map(|n| (*n).into()).collect()
}

fn twilio_route<'a>(auth_instances: Option<&'a [Box<str>]>) -> RouteAuth<'a> {
    RouteAuth {
        plane: "streaming",
        id: "twilio",
        cred_header: Some("x-twilio-signature"),
        auth_instances,
    }
}

#[test]
fn the_route_header_selects_its_readers_and_never_joins_the_data_chain() {
    let twilio = headers(&["x-twilio-signature"]);
    let standard = headers(&["webhook-signature", "webhook-id", "webhook-timestamp"]);
    let key = headers(&["authorization"]);
    let configured = [
        ConfiguredAuth { name: "key", cred_headers: &key },
        ConfiguredAuth { name: "twilio", cred_headers: &twilio },
        ConfiguredAuth { name: "standard-webhooks", cred_headers: &standard },
    ];
    assert_eq!(effective_chain(twilio_route(None), &configured, &["key"]), Ok(vec!["twilio"]));
    assert_eq!(
        effective_chain(twilio_route(None), &configured, &[]),
        Ok(vec!["twilio"]),
        "a config with no data chain still serves the twilio route"
    );
    let realtime = RouteAuth { plane: "streaming", id: "realtime", cred_header: None, auth_instances: None };
    assert_eq!(
        effective_chain(realtime, &configured, &["key"]),
        Ok(vec!["key"]),
        "(c) a data-chain route runs the data chain only; the twilio verifier never reaches it"
    );
}

#[test]
fn auth_instances_wins_and_names_only_configured_instances() {
    let twilio = headers(&["x-twilio-signature"]);
    let key = headers(&["authorization"]);
    let configured =
        [ConfiguredAuth { name: "key", cred_headers: &key }, ConfiguredAuth { name: "twilio", cred_headers: &twilio }];
    let listed = headers(&["twilio"]);
    assert_eq!(effective_chain(twilio_route(Some(listed.as_slice())), &configured, &["key"]), Ok(vec!["twilio"]));
    let ordered = headers(&["twilio", "key"]);
    assert_eq!(
        effective_chain(twilio_route(Some(ordered.as_slice())), &configured, &[]),
        Ok(vec!["twilio", "key"]),
        "run in the listed order"
    );
    let unknown = headers(&["twilio", "nobody"]);
    assert_eq!(
        effective_chain(twilio_route(Some(unknown.as_slice())), &configured, &[]),
        Err("routes.twilio.auth_instances names 'nobody', which is not a configured auth instance".to_owned())
    );
}

#[test]
fn a_route_header_no_instance_reads_refuses_config() {
    let key = headers(&["authorization"]);
    let configured = [ConfiguredAuth { name: "key", cred_headers: &key }];
    assert_eq!(
        effective_chain(twilio_route(None), &configured, &["key"]),
        Err("route 'streaming/twilio' takes its credential in 'x-twilio-signature' and no configured auth \
             instance reads it; configure one or set routes.twilio.auth_instances"
            .to_owned())
    );
}

#[test]
#[ignore = "owner: W2-SW-PLANE (arms (a), (b), (f), (g): the plane-streaming and auth-webhook-signature images, #217)"]
fn route_credential_header_core_arms() {
    todo!("owner: W2-SW-PLANE (C-ROUTE-CRED-HEADER image arms)")
}
