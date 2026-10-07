// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A subscription: the acknowledgement first and narrowed, a change only when what THIS caller can
//! see changed, the permission re-asked on every frame, a keepalive when quiet, and its bound.

use serde_json::json;

use super::*;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}},
    "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}
  }
}"#;

const SECTION_MORE: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}, "stat": {"schema_hash": "sha256:cc"}},
    "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}
  }
}"#;

fn catalogue(generation: u64, section: &[u8]) -> Catalogue {
    Catalogue::build(
        generation,
        &crate::door::read_tools_section(section).expect("the section reads"),
    )
}

fn everything(_: &str, _: &str) -> bool {
    true
}

#[test]
fn the_acknowledgement_is_first_and_carries_the_accepted_subset() {
    let params = json!({ "notifications": {
        "toolsListChanged": true,
        "resourceSubscriptions": ["file:///readme", "file:///hidden", "file:///readme"]
    }});
    let mut l =
        Listen::open(Some(&params), json!("sub"), 0, |u| u == "file:///readme").expect("opened");
    assert_eq!(
        l.accepted().resources,
        Some(vec!["file:///readme".to_string()])
    );
    let Step::Frames(frames) = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1)
    else {
        panic!("the acknowledgement is owed first");
    };
    assert_eq!(frames[0]["method"], ACKNOWLEDGED);
    assert_eq!(frames[0]["params"]["_meta"][SUBSCRIPTION_ID], "sub");
    assert_eq!(
        frames[0]["params"]["notifications"],
        json!({ "toolsListChanged": true, "resourceSubscriptions": ["file:///readme"] })
    );
}

#[test]
fn a_subscription_that_can_deliver_nothing_is_refused_and_too_many_uris_are_refused() {
    let nothing = json!({ "notifications": { "resourceSubscriptions": ["file:///hidden"] } });
    assert!(Listen::open(Some(&nothing), json!(1), 0, |_| false).is_err());
    let uris: Vec<String> = (0..=MAX_SUBSCRIBED_URIS)
        .map(|i| format!("file:///{i}"))
        .collect();
    let many = json!({ "notifications": { "resourceSubscriptions": uris } });
    let refused = Listen::open(Some(&many), json!(1), 0, |_| true).expect_err("too many");
    assert_eq!(refused["error"]["code"], INVALID_PARAMS);
}

#[test]
fn a_change_the_caller_can_see_notifies_and_one_it_cannot_does_not() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);
    // A new generation that adds a tool this caller can see.
    let Step::Frames(frames) = l.step(
        &catalogue(2, SECTION_MORE),
        &everything,
        &Standing::Live,
        &[],
        2,
    ) else {
        panic!("a visible change notifies");
    };
    assert_eq!(frames[0]["method"], "notifications/tools/list_changed");
    // A new generation whose change this caller cannot see (it is entitled to nothing new).
    let only_read =
        |kind: &str, name: &str| kind != crate::door::SCOPE_TOOL || name.ends_with("read_file");
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &only_read, &Standing::Live, &[], 1);
    assert_eq!(
        l.step(
            &catalogue(2, SECTION_MORE),
            &only_read,
            &Standing::Live,
            &[],
            2
        ),
        Step::Quiet
    );
}

#[test]
fn a_lapsed_permission_ends_the_stream_on_that_frame_and_the_bound_ends_it_gracefully() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);
    let lapsed = Standing::Lapsed {
        message: "the key was revoked".to_string(),
        reason: "identity_not_live".to_string(),
    };
    let Step::End(frames) = l.step(&catalogue(1, SECTION), &everything, &lapsed, &[], 2) else {
        panic!("a lapsed permission ends the stream");
    };
    assert_eq!(frames[0]["error"]["data"]["reason"], "identity_not_live");
    assert_eq!(
        l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 3),
        Step::Closed
    );
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);
    assert_eq!(
        l.step(
            &catalogue(1, SECTION),
            &everything,
            &Standing::Live,
            &[],
            KEEPALIVE_NS + 1
        ),
        Step::Keepalive
    );
    let Step::End(frames) = l.step(
        &catalogue(1, SECTION),
        &everything,
        &Standing::Live,
        &[],
        MAX_LIFETIME_NS,
    ) else {
        panic!("the bound ends the stream");
    };
    assert_eq!(frames[0]["result"]["resultType"], "complete");
}

#[test]
fn an_upstream_announcement_reaches_only_a_subscriber_entitled_to_the_announcing_servers_resource()
{
    let params = json!({ "notifications": { "resourceSubscriptions": ["file:///readme"] } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| true).expect("opened");
    let cat = catalogue(1, SECTION);
    let _ack = l.step(&cat, &everything, &Standing::Live, &[], 1);
    let other = [("db".to_string(), "file:///readme".to_string())];
    assert_eq!(
        l.step(&cat, &everything, &Standing::Live, &other, 2),
        Step::Quiet
    );
    let own = [("fs".to_string(), "file:///readme".to_string())];
    let Step::Frames(frames) = l.step(&cat, &everything, &Standing::Live, &own, 3) else {
        panic!("the announcing server's own resource is relayed");
    };
    assert_eq!(frames[0]["method"], "notifications/resources/updated");
}

/// CHOKE POINT J (OPEN-AND-TRUSTED): a subscription is a long-lived response, and it holds NO
/// principal it resolved at open. It is opened from the request alone (`Listen::open` takes no
/// identity), and every frame is judged under the permission the door re-asks that frame (the
/// kernel's live re-resolution, `ENTITLEMENT_STANDING`): the same open stream that wrote frames
/// while its principal stood ends on the first frame after it stops standing, with the identity
/// refusal, and writes nothing after.
#[test]
fn the_long_lived_response_holds_no_principal_it_resolved_at_open() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!("sub"), 0, |_| false).expect("opened");
    let cat = catalogue(1, SECTION);
    assert!(matches!(
        l.step(&cat, &everything, &Standing::Live, &[], 1),
        Step::Frames(_)
    ));
    assert_eq!(
        l.step(
            &catalogue(2, SECTION_MORE),
            &everything,
            &Standing::Live,
            &[],
            2
        ),
        Step::Frames(vec![json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": { "_meta": { SUBSCRIPTION_ID: "sub" } },
        })]),
        "while the principal stands, what changed is written"
    );
    let lapsed = Standing::Lapsed {
        message: "`agent` is no longer live".to_string(),
        reason: "identity_not_live".to_string(),
    };
    let Step::End(frames) = l.step(&catalogue(3, SECTION), &everything, &lapsed, &[], 3) else {
        panic!("the frame after the principal stopped standing ends the stream");
    };
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["id"], "sub");
    assert_eq!(frames[0]["error"]["data"]["reason"], "identity_not_live");
    assert_eq!(
        l.step(
            &catalogue(4, SECTION_MORE),
            &everything,
            &Standing::Live,
            &[],
            4
        ),
        Step::Closed,
        "an ended stream writes nothing more, whatever a later frame would say"
    );
}
