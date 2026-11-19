// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECURITY-OWED rows S-R7, S-R8 and S-R17 (ci/owed/LEDGER.tsv), proven over the native interface.
//!
//! A native plane's member TLS bundle and its owned trust anchor are D_TRUST_PATH positions of its
//! config bag (IF §12.7). Both are judged by the kernel's one config binder
//! ([`crate::plugin_config::Binder`]): at boot when the instance opens, and at every apply or
//! reload when the candidate instance opens, before the swap (plugin-loader `instance.rs`:
//! "Reconfigure = open new, swap, drop old"). So the rule the boot judges an anchor by is the rule
//! the candidate is judged by, and a refused candidate leaves the running instance's bound trust
//! untouched. The operator principal is reserved by `config_validate::validate`, the rule every
//! boot, apply and dry run reads a configuration through.

use std::sync::Arc;

use busbar_contract::json::{json, Value};
use busbar_contract::secret_ref::Sugars;

use crate::plugin_config::{BindError, Binder, ConfigBinder};

/// A PEM certificate bundle the binder takes as a trust anchor.
const GOOD_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

/// Texts no D_TRUST_PATH position may hold: not PEM, empty, a private key where a CA belongs, a
/// certificate section whose body does not decode, and a value that is not text.
fn refused_anchors() -> Vec<(&'static str, Value)> {
    vec![
        ("not PEM", json!("not a pem")),
        ("empty", json!("")),
        (
            "a private key",
            json!("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"),
        ),
        (
            "an undecodable certificate",
            json!("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n"),
        ),
        ("not text", json!(42)),
    ]
}

/// The members' TLS bundle a native plane selects (member registrations are an array, IF §8).
const MEMBER_TLS: &[&str] = &["/members/*/tls/ca_cert_pem"];

/// The plane's owned trust anchor.
const OWNED_ANCHOR: &[&str] = &["/owned/tls/ca_cert_pem"];

fn binder() -> Binder {
    Binder::new(Arc::new(Sugars::default()), Vec::new())
}

fn bytes(v: &Value) -> Vec<u8> {
    busbar_contract::json::to_vec(v).expect("json")
}

fn bind(b: &Binder, instance: u64, cfg: &Value, trust: &[&str]) -> Result<Vec<u8>, BindError> {
    b.bind(instance, &bytes(cfg), &[], trust, &[], &[])
}

fn refused_at(result: Result<Vec<u8>, BindError>, want: &str, what: &str) {
    match result {
        Err(BindError::BadPem { pointer }) => {
            assert_eq!(&*pointer, want, "{what}: the refusal names the position");
        }
        Err(other) => panic!("{what}: refused as {other:?}, not as a bad trust anchor"),
        Ok(_) => panic!("{what}: admitted"),
    }
}

/// S-R7 `member_tls_rules_reject_candidate_before_apply_and_ignore_unselected_sections`.
#[test]
fn member_tls_rules_reject_candidate_before_apply_and_ignore_unselected_sections() {
    let b = binder();
    let running = json!({"members": [
        {"name": "a", "tls": {"ca_cert_pem": GOOD_PEM}},
        {"name": "b"},
    ]});
    bind(&b, 1, &running, MEMBER_TLS).expect("the running members' bundle binds");
    let held = b.trust(1, 1).expect("the running member's anchor is held");

    for (what, bad) in refused_anchors() {
        let candidate = json!({"members": [
            {"name": "a", "tls": {"ca_cert_pem": GOOD_PEM}},
            {"name": "b", "tls": {"ca_cert_pem": bad}},
        ]});
        refused_at(
            bind(&b, 2, &candidate, MEMBER_TLS),
            "/members/1/tls/ca_cert_pem",
            what,
        );
        assert!(
            b.trust(2, 1).is_none(),
            "{what}: nothing of a refused candidate is held"
        );
        let still = b.trust(1, 1).expect("the running anchor stays");
        assert_eq!(
            (still.sha256, &still.der),
            (held.sha256, &held.der),
            "{what}: the running member's trust is untouched"
        );
    }

    // A plane that selects no member TLS bundle: the same text is its own config, never an anchor.
    let unselected = json!({"members": [{"name": "b", "tls": {"ca_cert_pem": "not a pem"}}]});
    let out = bind(&b, 3, &unselected, &[]).expect("an unselected section is not judged");
    assert_eq!(
        busbar_contract::json::parse_value(&out).expect("json"),
        unselected,
        "an unselected section binds as written"
    );
    assert!(b.trust(3, 1).is_none(), "and holds no trust anchor");
}

/// S-R8 `an_owned_anchor_the_boot_would_refuse_is_refused_by_the_same_rule`: the boot's open and
/// the apply's candidate open bind through the one binder rule, so each anchor the boot refuses
/// the apply refuses at the same position, and the running generation's anchor stays.
#[test]
fn an_owned_anchor_the_boot_would_refuse_is_refused_by_the_same_rule() {
    let at = "/owned/tls/ca_cert_pem";
    let good = json!({"owned": {"tls": {"ca_cert_pem": GOOD_PEM}}});

    let running = binder();
    bind(&running, 1, &good, OWNED_ANCHOR).expect("the boot binds a usable anchor");
    let held = running.trust(1, 1).expect("the running anchor is held");
    bind(&running, 2, &good, OWNED_ANCHOR).expect("the apply binds the anchor the boot bound");
    assert_eq!(
        running.trust(2, 1).expect("the candidate's anchor").sha256,
        held.sha256,
        "boot and apply read one anchor from one text"
    );

    for (n, (what, bad)) in (3u64..).zip(refused_anchors()) {
        let cfg = json!({"owned": {"tls": {"ca_cert_pem": bad}}});
        refused_at(bind(&binder(), 1, &cfg, OWNED_ANCHOR), at, what);
        refused_at(bind(&running, n, &cfg, OWNED_ANCHOR), at, what);
        assert!(
            running.trust(n, 1).is_none(),
            "{what}: the refused candidate holds no anchor"
        );
        assert_eq!(
            running
                .trust(1, 1)
                .expect("the running anchor stays")
                .sha256,
            held.sha256,
            "{what}: the running anchor is untouched"
        );
    }
}

/// S-R17 `a_role_shadowing_the_operator_principal_is_refused`: with the operator bound, a role
/// binding named as the operator principal is refused by name; any other role name is not.
#[test]
fn a_role_shadowing_the_operator_principal_is_refused() {
    use crate::config::{AuthCfg, AuthChainEntry, RoleBindingCfg, KEYS_MODULE};
    crate::test_hooks::operator::bind();
    let principal = crate::config::operator_principal_id();
    assert!(
        !principal.is_empty(),
        "the bound operator states a principal"
    );

    let errors_with_role = |role: &str| {
        let deploy: crate::config::DeployCfg =
            busbar_contract::json::from_value(&json!({"providers": {}, "models": {}}))
                .expect("the config parses");
        let mut cfg =
            crate::config::resolve(&deploy, &Default::default()).expect("the config resolves");
        let mut auth = AuthCfg::default_none();
        auth.chain = vec![AuthChainEntry::bare(KEYS_MODULE)];
        auth.role_bindings.insert(
            KEYS_MODULE.to_string(),
            std::iter::once((role.to_string(), RoleBindingCfg::default())).collect(),
        );
        cfg.auth = Some(auth);
        super::validate(&cfg).err().unwrap_or_default()
    };
    let shadows = |errors: &[String], role: &str| {
        errors.iter().any(|e| {
            e.contains(&format!("role_bindings.{KEYS_MODULE}"))
                && e.contains(&format!("'{role}'"))
                && e.contains("shadows the reserved operator principal id")
        })
    };

    let errors = errors_with_role(principal);
    assert!(
        shadows(&errors, principal),
        "a role named as the operator principal is refused by name; got: {errors:?}"
    );
    let other = format!("{principal}-ops");
    let errors = errors_with_role(&other);
    assert!(
        !shadows(&errors, &other),
        "a role with another name does not shadow the operator; got: {errors:?}"
    );
}
