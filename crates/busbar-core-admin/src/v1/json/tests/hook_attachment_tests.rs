// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 8: the attach point grammar and the list edits behind
//! `PUT|DELETE /hooks/{name}/attachments/{target}`.

use super::hook_attachments::{attach, attachments_in, detach, Point};
use crate::v1::contract::{HookAttachment, HookPosition, HookPositionWord};

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

const LAST: HookPosition = HookPosition::Word(HookPositionWord::Last);

#[test]
fn attach_is_idempotent() {
    let once = attach(&list(&["a"]), "h", LAST).unwrap().unwrap();
    assert_eq!(once, list(&["a", "h"]));
    assert_eq!(
        attach(&once, "h", LAST).unwrap(),
        None,
        "a repeat changes nothing"
    );
    assert_eq!(
        attach(&once, "h", HookPosition::Index(1)).unwrap(),
        None,
        "the same place changes nothing"
    );
    assert_eq!(
        attach(&once, "h", HookPosition::Index(0)).unwrap(),
        Some(list(&["h", "a"])),
        "a different place moves the hook, never duplicates it"
    );
}

#[test]
fn attach_refuses_a_place_past_the_end() {
    let refused = attach(&list(&["a"]), "h", HookPosition::Index(2));
    assert!(matches!(
        refused,
        Err(crate::v1::contract::AdminError::Validation(_))
    ));
    assert_eq!(
        attach(&list(&["a"]), "h", HookPosition::Index(1)).unwrap(),
        Some(list(&["a", "h"]))
    );
}

#[test]
fn detach_observable() {
    let attached = list(&["a", "h", "b"]);
    let after = detach(&attached, "h").unwrap();
    assert_eq!(after, list(&["a", "b"]));
    assert!(attachments_in(vec![(Point::Pools, after.clone())], "h").is_empty());
    assert_eq!(
        detach(&after, "h"),
        None,
        "a hook that is not attached has nothing to detach"
    );
}

#[test]
fn attachments_cover_all_points() {
    for (target, point, pointer) in [
        ("pools", Point::Pools, "/pools/hooks"),
        (
            "pools.fast",
            Point::Pool("fast".into()),
            "/pools/fast/hooks",
        ),
        ("tools", Point::Section("tools".into()), "/tools/hooks"),
        (
            "tools.search",
            Point::Instance("tools".into(), "search".into()),
            "/tools/search/hooks",
        ),
    ] {
        assert_eq!(Point::parse(target).unwrap(), point, "{target}");
        assert_eq!(point.pointer(), pointer, "{target}");
    }
    assert_eq!(
        Point::parse("pools.a/b~c").unwrap().pointer(),
        "/pools/a~1b~0c/hooks"
    );
    for bad in ["", "pools.", ".x", "x."] {
        assert!(Point::parse(bad).is_err(), "`{bad}` is not an attach point");
    }

    let views = attachments_in(
        vec![
            (Point::Pools, list(&["x", "h"])),
            (Point::Pool("fast".into()), list(&["h"])),
            (Point::Section("tools".into()), list(&["h", "y"])),
            (
                Point::Instance("tools".into(), "search".into()),
                list(&["y", "h"]),
            ),
            (Point::Pool("slow".into()), list(&["y"])),
        ],
        "h",
    );
    assert_eq!(
        views,
        vec![
            HookAttachment {
                target: "pools".into(),
                instance: None,
                position: 1
            },
            HookAttachment {
                target: "pools.fast".into(),
                instance: None,
                position: 0
            },
            HookAttachment {
                target: "tools".into(),
                instance: None,
                position: 0
            },
            HookAttachment {
                target: "tools.search".into(),
                instance: Some("search".into()),
                position: 1
            },
        ]
    );
}

#[test]
fn position_wire_forms() {
    use crate::v1::contract::HookAttachRequest;
    let last: HookAttachRequest = serde_json::from_str(r#"{"position":"last"}"#).unwrap();
    assert_eq!(last.position, LAST);
    let third: HookAttachRequest = serde_json::from_str(r#"{"position":2}"#).unwrap();
    assert_eq!(third.position, HookPosition::Index(2));
    for bad in [
        r#"{"position":"first"}"#,
        r#"{"position":-1}"#,
        r#"{"position":1.5}"#,
        r#"{}"#,
        r#"{"position":0,"extra":1}"#,
    ] {
        assert!(
            serde_json::from_str::<HookAttachRequest>(bad).is_err(),
            "{bad}"
        );
    }
}
