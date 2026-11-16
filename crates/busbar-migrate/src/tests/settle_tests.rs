// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LIFT, C-STORE-BAGS and the core arm of C-MIGRATE (IF §14, §12.10, MIGRATE-ON-BOOT r42 §4): what
//! an instance's `open` settled (its canonical bag, the core config its old bag held) is filed into
//! core's own sections by `config::file_core_cfg`, uninterpreted, before step 5 writes. The fixtures
//! name sections, never plugins.

use std::path::Path;

use busbar_contract::yaml::{self, Value, ValueExt};

use crate::scratch::{no_env, Scratch};
use crate::settle::{section, CoreCfg, Settled};
use crate::{apply_settled, Applied, Refusal};

const STAMPED: &str = "config_version: 1\nstore: {module: m, settings: {url: old}}\nauth:\n  ldap: {module: l, settings: {bind_service_password: hunter2}}\n";

fn json(text: &str) -> Value {
    yaml::from_str(text).expect("a JSON value")
}

fn cfg(section: u32, name: &str, value: &str) -> CoreCfg {
    CoreCfg {
        section,
        name: name.to_owned(),
        value: json(value),
    }
}

fn store(index: u32, settings: Option<&str>, core_cfg: Vec<CoreCfg>) -> Settled {
    Settled {
        index,
        path: vec!["store".to_owned()],
        settings: settings.map(busbar_contract::secure::SecureString::from),
        core_cfg,
        placement: crate::settle::BagPlacement::Settings,
        allowed_lifts: Default::default(),
    }
}

fn apply(text: &str, settled: &[Settled], stamped: bool) -> Result<Applied, Refusal> {
    let scratch = Scratch::new();
    let path = scratch.config(text);
    apply_settled(text, &path, settled, stamped, no_env)
}

fn tree(applied: &Applied) -> Value {
    yaml::from_str(applied.text()).expect("the written document parses")
}

#[test]
fn the_settled_bag_replaces_the_bag_and_nothing_else_moves() {
    let applied = apply(
        STAMPED,
        &[store(0, Some(r#"{"url": "new", "extra": 1}"#), vec![])],
        true,
    )
    .unwrap();
    let tree = tree(&applied);
    assert_eq!(
        tree.at("store").at("settings").at("url").as_str(),
        Some("new")
    );
    assert_eq!(tree.at("store").at("module").as_str(), Some("m"));
    assert_eq!(
        tree.at("auth")
            .at("ldap")
            .at("settings")
            .at("bind_service_password")
            .as_str(),
        Some("hunter2")
    );
    assert!(applied.text().starts_with("config_version: 1\n"));
}

#[test]
fn an_answer_that_changes_nothing_writes_the_same_bytes() {
    let applied = apply(
        STAMPED,
        &[store(0, Some(r#"{"url": "old"}"#), vec![])],
        true,
    )
    .unwrap();
    assert_eq!(applied.text(), STAMPED, "equal bytes: nothing to write");
    let absent = apply(STAMPED, &[store(0, None, vec![])], true).unwrap();
    assert_eq!(absent.text(), STAMPED, "absent = the bag as written");
}

#[test]
fn limits_carry_an_empty_name_once_and_a_plaintext_key_is_not_a_mapping_target() {
    let named = cfg(section::LIMITS, "x", r#"{"timeout_ms": 1}"#);
    assert_eq!(
        apply(STAMPED, &[store(3, None, vec![named])], false)
            .unwrap_err()
            .word(),
        "CONFIG"
    );
    let twice = vec![
        cfg(section::LIMITS, "", r#"{"timeout_ms": 1}"#),
        cfg(section::LIMITS, "", r#"{"timeout_ms": 2}"#),
    ];
    let refused = apply(STAMPED, &[store(3, None, twice)], false).unwrap_err();
    assert!(refused.to_string().contains("instance 3"), "{refused}");
    let not_a_map = cfg(section::LIMITS, "", "7");
    assert_eq!(
        apply(STAMPED, &[store(0, None, vec![not_a_map])], false)
            .unwrap_err()
            .word(),
        "CONFIG"
    );
}

#[test]
fn an_unknown_or_retired_section_is_refused_naming_the_instance_index() {
    for retired in [0, 5, 6, 8, 99] {
        let refused = apply(
            STAMPED,
            &[store(4, None, vec![cfg(retired, "", "{}")])],
            false,
        )
        .unwrap_err();
        assert_eq!(refused.word(), "CONFIG", "section {retired}");
        assert!(refused.to_string().contains("instance 4"), "{refused}");
    }
}

#[test]
fn a_current_config_moves_nothing() {
    let frag = cfg(section::LIMITS, "", r#"{"timeout_ms": 1}"#);
    let refused = apply(STAMPED, &[store(0, None, vec![frag])], true).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("instance 0"), "{refused}");
}

#[test]
fn retired_named_filings_leave_equal_different_and_operator_values_unchanged() {
    let same = |index| Settled {
        placement: crate::settle::BagPlacement::Settings,
        allowed_lifts: Default::default(),
        index,
        path: vec!["auth".to_owned(), "ldap".to_owned()],
        settings: None,
        core_cfg: vec![cfg(section::ROUTE_MEDIA, "12", r#"{"url": "https://dc1"}"#)],
    };
    let applied = apply(
        STAMPED,
        &[
            store(
                0,
                None,
                vec![cfg(section::ROUTE_MEDIA, "12", r#"{"url": "https://dc1"}"#)],
            ),
            same(1),
        ],
        false,
    )
    .unwrap();
    assert_eq!(applied.text(), STAMPED);
    let differs = Settled {
        core_cfg: vec![cfg(
            section::ROUTE_MEDIA,
            "12",
            r#"{"url": "https://other"}"#,
        )],
        ..same(1)
    };
    let different = apply(
        STAMPED,
        &[
            store(
                0,
                None,
                vec![cfg(section::ROUTE_MEDIA, "12", r#"{"url": "https://dc1"}"#)],
            ),
            differs,
        ],
        false,
    )
    .unwrap();
    assert_eq!(different.text(), STAMPED);
    let operator =
        "config_version: 1\nroutes: {'12': {media: {url: 'https://mine'}}}\nstore: {module: m}\n";
    let clash = apply(
        operator,
        &[store(
            0,
            None,
            vec![cfg(section::ROUTE_MEDIA, "12", r#"{"url": "https://dc1"}"#)],
        )],
        false,
    )
    .unwrap();
    assert_eq!(clash.text(), operator);
}

/// C-LIFT: the slot's exact bytes become a planned 0600 secret file beside config.yaml and the slot a
/// `{file: <path>}` reference; the value never enters a report or the written document.
#[test]
fn a_lifted_literal_becomes_a_secret_file_reference_and_never_a_report_line() {
    let settled = Settled {
        placement: crate::settle::BagPlacement::Settings,
        allowed_lifts: ["/bind_service_password".to_owned()].into_iter().collect(),
        index: 2,
        path: vec!["auth".to_owned(), "ldap".to_owned()],
        settings: Some(busbar_contract::secure::SecureString::from(
            r#"{"bind_service_password": "hunter2", "url": "ldaps://dc"}"#,
        )),
        core_cfg: vec![cfg(section::LIFT, "", "\"/bind_service_password\"")],
    };
    let scratch = Scratch::new();
    let path = scratch.config(STAMPED);
    let applied = apply_settled(STAMPED, &path, &[settled], false, no_env).unwrap();
    assert!(!applied.text().contains("hunter2"), "{}", applied.text());
    assert!(applied
        .report()
        .iter()
        .all(|line| !line.contains("hunter2")));
    let tree = tree(&applied);
    let slot = tree
        .at("auth")
        .at("ldap")
        .at("settings")
        .at("bind_service_password")
        .at("file");
    let file = Path::new(slot.as_str().expect("a file reference"));
    assert!(
        file.starts_with(scratch.dir()),
        "{file:?} lies under the config directory"
    );
    let [secret] = applied.secrets() else {
        panic!("one planned secret file")
    };
    assert_eq!(secret.path(), file);
    assert_eq!(secret.bytes(), b"hunter2");
    assert!(
        !format!("{secret:?}").contains("hunter2"),
        "Debug never prints the bytes"
    );
}

#[test]
fn a_lift_names_a_string_slot_once_with_an_empty_name() {
    let lift = |name: &str, pointer: &str| cfg(section::LIFT, name, pointer);
    let with = |frags: Vec<CoreCfg>, settings: &str| {
        let mut answer = store(1, Some(settings), frags);
        answer.allowed_lifts = ["/token", "/missing", "/a/0/b", "/a~1b"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        apply(STAMPED, &[answer], false).map(|applied| applied.text().to_owned())
    };
    assert_eq!(
        with(vec![lift("x", "\"/token\"")], r#"{"token": "t"}"#)
            .unwrap_err()
            .word(),
        "CONFIG"
    );
    assert_eq!(
        with(vec![lift("", "\"/token\"")], r#"{"token": 7}"#)
            .unwrap_err()
            .word(),
        "CONFIG"
    );
    assert_eq!(
        with(vec![lift("", "\"/missing\"")], r#"{"token": "t"}"#)
            .unwrap_err()
            .word(),
        "CONFIG"
    );
    let twice = with(
        vec![lift("", "\"/token\""), lift("", "\"/token\"")],
        r#"{"token": "t"}"#,
    )
    .unwrap_err();
    assert!(twice.to_string().contains("instance 1"), "{twice}");
    assert!(
        with(vec![lift("", "\"/a/0/b\"")], r#"{"a": [{"b": "t"}]}"#).is_ok(),
        "array indices are pointer steps"
    );
    assert!(
        with(vec![lift("", "\"/a~1b\"")], r#"{"a/b": "t"}"#).is_ok(),
        "~1 is a slash"
    );
}

/// C-STORE-BAGS: a 1.5.5 store bag the store converted (`{url, junk}` -> `{url}`) is written back as
/// the store answered, key order of the document kept.
#[test]
fn a_converted_store_bag_is_written_as_answered() {
    let text = "config_version: 1\nstore:\n  module: m\n  settings: {url: 'redis://x', junk: 1}\nlisten: y\n";
    let applied = apply(
        text,
        &[store(0, Some(r#"{"url": "redis://x"}"#), vec![])],
        true,
    )
    .unwrap();
    assert!(
        applied.text().contains("settings: {url: 'redis://x'}")
            || applied.text().contains("url: 'redis://x'")
    );
    assert!(!applied.text().contains("junk"));
    assert!(applied.text().ends_with("listen: y\n"));
}

#[test]
fn an_upstream_core_fragment_is_retired_even_during_conversion() {
    let answer = store(
        4,
        None,
        vec![cfg(1, "endpoint", r#"{"url":"https://example.test"}"#)],
    );
    let refused = apply(STAMPED, &[answer], false).expect_err("r3 retires section 1");
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("instance 4"));
}

#[test]
fn a_literal_string_does_not_authorize_its_own_lift() {
    let answer = store(
        4,
        Some(r#"{"display_name":"not a secret"}"#),
        vec![cfg(section::LIFT, "", r#""/display_name""#)],
    );
    let refused = apply(STAMPED, &[answer], false)
        .expect_err("no described secret path authorizes this slot");
    assert_eq!(refused.word(), "CONFIG");
    assert!(!refused.to_string().contains("not a secret"));
}

#[test]
fn authorized_lifts_still_require_exact_rfc6901_pointers_and_existing_strings() {
    for (pointer, bag) in [
        ("/bad~2", r#"{"bad~2":"secret"}"#),
        ("/bad~", r#"{"bad~":"secret"}"#),
        ("/items/01", r#"{"items":["first","secret"]}"#),
        ("/items/+1", r#"{"items":["first","secret"]}"#),
        ("/missing", r#"{}"#),
        ("/value", r#"{"value":{"file":"already-a-reference"}}"#),
    ] {
        let mut answer = store(
            8,
            Some(bag),
            vec![cfg(section::LIFT, "", &format!("\"{pointer}\""))],
        );
        answer.allowed_lifts.insert(pointer.to_owned());
        let refused = apply(STAMPED, &[answer], false)
            .expect_err("authorization does not relax pointer or value grammar");
        assert_eq!(refused.word(), "CONFIG");
        assert!(!refused.to_string().contains("secret"));
    }
}

#[test]
fn a_plane_settles_its_whole_top_level_bag_and_lifts_only_admitted_slots() {
    let source = "config_version: 1\nplane: {old: true}\nstore: {module: m}\n";
    let mut answer = store(
        2,
        Some(r#"{"member":{"secret":"literal"}}"#),
        vec![cfg(section::LIFT, "", r#""/member/secret""#)],
    );
    answer.path = vec!["plane".to_owned()];
    answer.placement = crate::settle::BagPlacement::Block;
    answer.allowed_lifts.insert("/member/secret".to_owned());
    let applied = apply(source, &[answer], false).unwrap();
    let doc = tree(&applied);
    assert!(doc.at("plane").get("settings").is_none());
    assert!(doc.at("plane").get("old").is_none());
    assert!(doc
        .at("plane")
        .at("member")
        .at("secret")
        .get("file")
        .is_some());
    assert_eq!(applied.secrets()[0].bytes(), b"literal");
}

/// The settled LIMITS, TRUST_APPROVAL and ROUTE_MEDIA answers are never filed into config.yaml: the grammar has no
/// `limits`, `trust` or `routes` key, so writing one would break the next boot. The document comes out as it went in.
#[test]
fn settled_limits_trust_and_route_media_are_not_written_to_the_config() {
    let text = "config_version: 1\nstore: {module: m, settings: {url: old}}\n";
    let frags = vec![
        cfg(
            section::LIMITS,
            "",
            r#"{"timeout_ms": 3000, "max_inflight": 8}"#,
        ),
        cfg(section::TRUST_APPROVAL, "up1", r#"{"root": "r"}"#),
        cfg(section::ROUTE_MEDIA, "12", r#"{"inline": true}"#),
    ];
    let applied = apply(text, &[store(0, None, frags)], false).unwrap();
    let written = applied.text();
    for key in ["limits", "trust", "routes", "timeout_ms", "inline"] {
        assert!(!written.contains(key), "`{key}` was filed:\n{written}");
    }
    assert_eq!(written, text, "nothing else moved");
}
