// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's own answers on the child-process carrier, as the served engine gives them.

use serde_json::{json, Value};

use super::*;

fn read(b: Vec<u8>) -> Value {
    serde_json::from_slice(&b).expect("a document")
}

#[test]
fn initialize_names_the_one_revision_and_busbar() {
    let v = read(initialize(&json!("i")));
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "i");
    assert_eq!(v["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(v["result"]["serverInfo"]["name"], "busbar");
    assert_eq!(
        v["result"]["serverInfo"]["version"],
        crate::plane_door::VERSION
    );
    assert_eq!(
        v["result"]["capabilities"]["resources"],
        json!({"listChanged": true, "subscribe": true})
    );
    assert!(v["result"]["instructions"]
        .as_str()
        .expect("instructions")
        .contains("no handshake is required"));
}

#[test]
fn ping_is_an_empty_result() {
    assert_eq!(
        read(ping(&json!(1))),
        json!({"jsonrpc": "2.0", "id": 1, "result": {}})
    );
}

#[test]
fn set_level_takes_the_level_or_refuses_without_one() {
    let p = json!({"level": "debug"});
    assert_eq!(set_level(&json!(1), Some(&p)), Ok("debug".to_string()));
    let r = set_level(&json!(1), Some(&json!({}))).unwrap_err();
    assert_eq!((r.status, r.code), (400, -32602));
    assert!(r.message.starts_with("`params.level` is required"));
}

#[test]
fn a_subscription_takes_its_baseline_and_an_unsubscribe_drops_it() {
    let mut s = Subscriptions::default();
    let p = json!({"uri": "file:///a"});
    assert_eq!(s.apply(&json!(1), true, Some(&p), |_| Some(7)), Ok(()));
    assert_eq!(s.entries().get("file:///a"), Some(&Some(7)));
    assert_eq!(s.apply(&json!(2), false, Some(&p), |_| None), Ok(()));
    assert!(s.entries().is_empty());
}

#[test]
fn a_subscription_with_no_uri_or_an_over_long_one_is_refused() {
    let mut s = Subscriptions::default();
    let r = s
        .apply(&json!(1), true, Some(&json!({})), |_| None)
        .unwrap_err();
    assert_eq!((r.status, r.code), (400, -32602));
    assert!(r.message.starts_with("`params.uri` is required"));
    let long = json!({ "uri": "x".repeat(MAX_RESOURCE_SUB_URI_BYTES + 1) });
    let r = s.apply(&json!(1), true, Some(&long), |_| None).unwrap_err();
    assert!(r
        .message
        .starts_with("`params.uri` is longer than this session retains"));
}

/// The set is bounded, and a uri already held is always admitted.
#[test]
fn the_set_stops_at_its_ceiling_but_admits_a_uri_it_holds() {
    let mut s = Subscriptions::default();
    for i in 0..MAX_RESOURCE_SUBS {
        let p = json!({ "uri": format!("file:///{i}") });
        assert_eq!(s.apply(&json!(i), true, Some(&p), |_| None), Ok(()));
    }
    let over = json!({"uri": "file:///over"});
    let r = s.apply(&json!(0), true, Some(&over), |_| None).unwrap_err();
    assert!(r.message.starts_with("this session already holds"));
    let held = json!({"uri": "file:///0"});
    assert_eq!(s.apply(&json!(0), true, Some(&held), |_| Some(1)), Ok(()));
}
