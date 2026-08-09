// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-abi/src/hook.rs`.

use super::*;

/// The op-discriminated request round-trips through JSON unchanged (the variant is the op tag).
#[test]
fn request_json_roundtrip() {
    let projection = serde_json::json!({
        "request": {"pool": "p", "message_count": 1},
        "candidates": [{"idx": 0, "model": "m"}],
        "context": {}
    });
    let reqs = vec![
        HookRequest::Decide {
            payload: projection.clone(),
        },
        HookRequest::Transform {
            payload: projection.clone(),
        },
        HookRequest::Notify {
            payload: projection,
        },
        HookRequest::Configure(ConfigureBody {
            hook: "h".into(),
            settings: serde_json::Map::new(),
            settings_version: 7,
            busbar_version: "1.5.0".into(),
        }),
        HookRequest::Describe,
        HookRequest::Status,
    ];
    for r in reqs {
        let j = serde_json::to_vec(&r).unwrap();
        let back: HookRequest = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}

/// The `op` field is the discriminant a plugin matches on — pin the wire tag names so a plugin
/// written against them cannot silently break.
#[test]
fn request_op_tag_is_stable() {
    let v = serde_json::to_value(HookRequest::Decide {
        payload: serde_json::json!({}),
    })
    .unwrap();
    assert_eq!(v["op"], "decide");
    let v = serde_json::to_value(HookRequest::Configure(ConfigureBody {
        hook: "h".into(),
        settings: serde_json::Map::new(),
        settings_version: 1,
        busbar_version: "x".into(),
    }))
    .unwrap();
    assert_eq!(v["op"], "configure");
}

/// `Failed` is a DISTINCT wire shape from an empty `Reply`, which is the whole point: the
/// engine must be able to tell "my dependency is down" from "I have no opinion". If these two
/// ever encoded alike, a gate configured to fail closed would silently fail open again.
#[test]
fn failed_is_distinguishable_from_an_empty_abstain_reply() {
    let failed = serde_json::to_value(HookReply::Failed {
        message: "upstream timed out".into(),
    })
    .unwrap();
    let abstain = serde_json::to_value(HookReply::Reply(serde_json::json!({}))).unwrap();
    assert_ne!(failed, abstain);
    assert_eq!(failed["Failed"]["message"], "upstream timed out");
    // ...and it survives the round trip the transport does.
    let back: HookReply = serde_json::from_slice(
        &serde_json::to_vec(&HookReply::Failed {
            message: "x".into(),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(back, HookReply::Failed { .. }));
}

/// The reply round-trips: an opaque reply object, a configure ack, and the notify empty.
#[test]
fn reply_json_roundtrip() {
    for r in [
        HookReply::Reply(serde_json::json!({"order": [1, 0]})),
        HookReply::ConfigureAck {
            settings_version: 9,
        },
        HookReply::None,
    ] {
        let j = serde_json::to_vec(&r).unwrap();
        let back: HookReply = serde_json::from_slice(&j).unwrap();
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }
}

/// `HookReply` has NO `#[serde(...)]` attribute (unlike the `op`-tagged `HookRequest`), so it
/// uses serde's default externally-tagged enum representation verbatim. Pin the three literal
/// JSON forms a plugin author in any language must match on the fire-and-forget `notify` /
/// `configure` reply path, where a shape mismatch fails silently (nothing errors). A future
/// `#[serde(...)]` addition (e.g. to match `HookRequest`'s tagging) would change these values,
/// and this test catches it — see `HookReply`'s doc comment.
#[test]
fn hook_reply_json_encoding_is_pinned() {
    assert_eq!(
        serde_json::to_value(HookReply::None).unwrap(),
        serde_json::json!("None")
    );
    assert_eq!(
        serde_json::to_value(HookReply::ConfigureAck {
            settings_version: 42
        })
        .unwrap(),
        serde_json::json!({"ConfigureAck": {"settings_version": 42}})
    );
    assert_eq!(
        serde_json::to_value(HookReply::Reply(serde_json::json!({"order": [1, 0]}))).unwrap(),
        serde_json::json!({"Reply": {"order": [1, 0]}})
    );
}
