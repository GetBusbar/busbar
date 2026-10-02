// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's declarations: the tail the loader judges, the trust keys it states against the
//! grammar's own table, the settings reader and each generation's snapshot.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::plane::check::check_tail;
use busbar_contract::abi::plane::{
    CLAIM_EXACT, CLAIM_OPEN, MECHANISM_ROOT, TRUST_PIN, TRUST_REVERIFY_TTL,
};
use busbar_contract::plane::TrustRole;

use super::*;

/// A good section: one fronted server.
const GOOD: &[u8] =
    br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
/// A registration the grammar refuses: a server id holding the routing-key separator.
const BAD: &[u8] =
    br#"{"my_fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;

/// A tail string read back through the `&'static str` it was built from: the tail's strings are
/// constants of this crate, so a string this test knows is found by address and length.
fn text(a: AbiStr) -> String {
    if a.ptr.is_null() {
        return String::new();
    }
    [
        "pin",
        "verify_ttl",
        crate::config::DEFAULT_MCP_VERIFY_TTL,
        "pinned_pubkey",
        "cert_spki",
        "mtls",
        "unpinned",
        crate::records::KIND_CALL,
        crate::records::KIND_DEMOTION,
        crate::meta::CLASS_TOOL_CALLS.as_str(),
        crate::meta::CLASS_BYTES.as_str(),
    ]
    .into_iter()
    .find(|c| c.as_ptr() == a.ptr && c.len() == a.len)
    .expect("a tail string this test knows")
    .to_string()
}

#[test]
fn the_tail_is_one_the_loader_accepts() {
    assert_eq!(check_tail(TAIL), Ok(()));
}

/// The tail's trust keys are the grammar's own table, key by key, in its order: the kernel judges
/// what the plane declares, so the two may not drift.
#[test]
fn the_tails_trust_keys_are_the_grammars() {
    assert_eq!(TRUST_KEYS.len(), crate::config::TRUST_KEYS.len());
    for (abi, decl) in TRUST_KEYS.iter().zip(crate::config::TRUST_KEYS) {
        assert_eq!(text(abi.key), decl.key);
        let role = match decl.role {
            TrustRole::Pin => TRUST_PIN,
            TrustRole::ReverifyTtl => TRUST_REVERIFY_TTL,
            TrustRole::RecoveryBackoff => panic!("the plane declares no recovery-backoff key"),
        };
        assert_eq!(abi.role, role, "{}", decl.key);
        assert_eq!(
            (!abi.default.ptr.is_null()).then(|| text(abi.default)),
            decl.default.map(str::to_string),
            "{}",
            decl.key
        );
        assert_eq!(abi.mechanisms_len, decl.mechanisms.len(), "{}", decl.key);
    }
    for (abi, decl) in PIN_MECHANISMS
        .iter()
        .zip(crate::config::TRUST_KEYS[0].mechanisms)
    {
        assert_eq!(text(abi.token), decl.token);
        assert_eq!(abi.flags & MECHANISM_ROOT != 0, decl.root, "{}", decl.token);
    }
}

/// The record kinds and billable classes are the plane's own symbols, stated once.
#[test]
fn the_tail_names_the_planes_own_classes_and_kinds() {
    let kinds: Vec<String> = RECORD_KINDS.iter().map(|k| text(*k)).collect();
    assert_eq!(kinds, crate::records::RECORD_KINDS);
    let classes: Vec<String> = BILLABLE_CLASSES.iter().map(|c| text(c.class)).collect();
    assert_eq!(
        classes,
        [
            crate::meta::CLASS_TOOL_CALLS.as_str(),
            crate::meta::CLASS_BYTES.as_str()
        ]
    );
}

#[test]
fn an_empty_blob_is_the_empty_section() {
    assert_eq!(read_settings(b""), Ok(crate::config::ToolsCfg::default()));
}

#[test]
fn a_good_section_reads_and_a_bad_one_is_refused_in_the_grammars_words() {
    let cfg = read_settings(GOOD).expect("one fronted server reads");
    assert_eq!(cfg.servers.len(), 1);
    let err = read_settings(BAD).expect_err("a separator in the id is refused");
    assert!(
        err.starts_with("`tools.my_fs`: an MCP server id may not contain `_`."),
        "{err}"
    );
}

/// With no public base there is no audience and nothing is claimed; with one, the endpoint and its
/// metadata document are absolute and every route is claimed, the discovery document open.
#[test]
fn a_generation_claims_its_routes_only_with_a_public_base() {
    let none = snapshot_spec(None);
    assert!(none.claims.is_empty());
    assert_eq!(none.audience, None);
    assert_eq!(none.admin_routes.len(), ADMIN_VERBS.len());

    let some = snapshot_spec(Some("https://gw.example/"));
    assert_eq!(some.audience.as_deref(), Some("https://gw.example/mcp"));
    assert_eq!(
        some.resource_metadata.as_deref(),
        Some("https://gw.example/.well-known/oauth-protected-resource/mcp")
    );
    assert_eq!(some.claims.len(), ROUTES.len());
    assert_eq!(some.claims[0].flags, CLAIM_EXACT | CLAIM_OPEN);
    assert!(some.claims[1..].iter().all(|c| c.flags == CLAIM_EXACT));
}

/// The Statement's version is the crate's: read from the manifest, as the plane reads no build
/// environment.
#[test]
fn the_statement_version_is_the_crates() {
    let manifest = include_str!("../../Cargo.toml");
    assert!(
        manifest.contains(&format!("version = \"{}\"", crate::plane_door::VERSION)),
        "the Statement names {} and the manifest does not",
        crate::plane_door::VERSION
    );
}
