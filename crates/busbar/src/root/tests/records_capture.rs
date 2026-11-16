// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `records.user` and `records.labels` (ADMIN-API-1.6 §3.5, §3.6): off costs nothing, a
//! pseudonym is the published derivation and stable, and only allow-listed headers are kept.

use busbar_kernel::config::{RecordsCfg, RecordsUser};

use crate::root::records_capture::{Capture, USER_KEY_INFO, VALUE_MAX};

fn configured(user: RecordsUser, labels: &[&str]) -> Capture {
    Capture::of(&RecordsCfg {
        user,
        labels: labels.iter().map(|name| (*name).to_owned()).collect(),
    })
}

fn field(name: &str, value: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (name.as_bytes().to_vec(), value.to_vec())
}

/// RED (§3.6 `user_off_zero_work`): with both switches off (the default) a unit's capture does
/// no work: nothing is kept and not one allocation is made, however many units pass.
#[test]
fn user_off_zero_work() {
    let off = Capture::of(&RecordsCfg::default());
    assert_eq!(
        RecordsCfg::default().user,
        RecordsUser::Off,
        "off by default"
    );
    assert!(
        RecordsCfg::default().labels.is_empty(),
        "no label by default"
    );
    assert!(!off.keeps_user());
    assert!(!off.keeps_labels());

    let fields = vec![
        field("x-team", b"payments"),
        field("user-agent", b"curl/8"),
        field("authorization", b"Bearer sk-live"),
    ];
    let key = [7u8; 32];
    #[cfg(not(target_env = "msvc"))]
    let before = crate::GLOBAL.stats();
    let mut kept = 0usize;
    for _ in 0..1_000 {
        kept += usize::from(off.user_of(Some(&key), "alice@example.com").is_some());
        kept += off.labels_of(&fields).len();
    }
    #[cfg(not(target_env = "msvc"))]
    let after = crate::GLOBAL.stats();
    assert_eq!(kept, 0, "off keeps nothing");
    #[cfg(not(target_env = "msvc"))]
    assert_eq!(
        (after.allocations + after.reallocations) - (before.allocations + before.reallocations),
        0,
        "off allocates nothing per unit"
    );
    assert!(
        busbar_kernel_audit::RecordFacts::default().is_empty(),
        "an unset record frames no records tail"
    );
}

/// RED (§3.5, §3.6 `user_pseudonym_stable`): `pseudonymous` is
/// `"u_" + hex(HMAC-SHA256(K_user, utf8(value))[..16])` with
/// `K_user = HKDF-SHA256(ikm = keyset seed, salt = deployment_id, info = "busbar.records.user.v1")`:
/// the same user always reads the same, another deployment reads another, and with no key the
/// raw value is never kept instead.
#[test]
fn user_pseudonym_stable() {
    assert_eq!(USER_KEY_INFO, b"busbar.records.user.v1");
    let seed = [0x42u8; 32];
    let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&seed);
    let deployment = b"dep_0123456789abcdef";
    let key = signer.derived_key(deployment, USER_KEY_INFO);
    let mut published = [0u8; 32];
    busbar_contract::crypto::hkdf_sha256(deployment, &seed, USER_KEY_INFO, &mut published)
        .expect("HKDF-SHA256 over a 32-byte key");
    assert_eq!(key, published, "K_user is the published HKDF derivation");

    let on = configured(RecordsUser::Pseudonymous, &[]);
    assert!(on.keeps_user());
    let first = on
        .user_of(Some(&key), "alice@example.com")
        .expect("a pseudonym");
    let again = on
        .user_of(Some(&key), "alice@example.com")
        .expect("a pseudonym");
    assert_eq!(first, again, "stable");
    let mac = busbar_contract::crypto::hmac_sha256(&key, b"alice@example.com").unwrap();
    assert_eq!(first, format!("u_{}", hex::encode(&mac[..16])));
    assert_eq!(first.len(), 2 + 32);
    assert!(
        !first.contains("alice"),
        "the value is not in its pseudonym"
    );
    assert_ne!(on.user_of(Some(&key), "bob@example.com").unwrap(), first);

    let elsewhere = signer.derived_key(b"dep_fedcba9876543210", USER_KEY_INFO);
    assert_ne!(
        on.user_of(Some(&elsewhere), "alice@example.com").unwrap(),
        first,
        "pseudonyms differ across deployments"
    );
    assert_eq!(
        on.user_of(None, "alice@example.com"),
        None,
        "no key: nothing, never the plain value"
    );

    let plain = configured(RecordsUser::Plain, &[]);
    assert_eq!(
        plain.user_of(None, "alice@example.com").as_deref(),
        Some("alice@example.com")
    );
    let long = "é".repeat(100);
    let cut = plain.user_of(None, &long).expect("a plain user");
    assert_eq!(cut.len(), VALUE_MAX, "128 bytes");
    assert!(long.starts_with(&cut), "cut on a char boundary");
    let odd = format!("a{}", "é".repeat(100));
    let cut = plain.user_of(None, &odd).expect("a plain user");
    assert_eq!(cut.len(), VALUE_MAX - 1, "never inside a character");
}

/// RED (§3.5, §3.6 `labels_allow_list_only`): only the configured headers are kept, named in
/// lower case, the first occurrence verbatim and cut to 128 bytes, in the allow-list's order; a
/// value that is not UTF-8 is not kept, and no allow-list keeps nothing.
#[test]
fn labels_allow_list_only() {
    let capture = configured(RecordsUser::Off, &["X-Cost-Center", "x-team"]);
    assert!(capture.keeps_labels());
    let long = "v".repeat(200);
    let fields = vec![
        field("x-team", b"payments"),
        field("X-COST-CENTER", long.as_bytes()),
        field("x-other", b"not allow-listed"),
        field("authorization", b"Bearer sk-live"),
        field("x-team", b"second"),
    ];
    let labels = capture.labels_of(&fields);
    let got: Vec<(&str, &str)> = labels
        .iter()
        .map(|(name, value)| (&**name, value.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("x-cost-center", &long[..VALUE_MAX]),
            ("x-team", "payments")
        ]
    );

    assert!(
        configured(RecordsUser::Plain, &[])
            .labels_of(&fields)
            .is_empty(),
        "no allow-list keeps no header"
    );
    assert!(
        capture
            .labels_of(&[field("x-team", &[0xff, 0xfe])])
            .is_empty(),
        "a value that is not UTF-8 is not kept"
    );
    assert!(
        capture.labels_of(&[field("x-teams", b"near")]).is_empty(),
        "names match exactly, case aside"
    );
}
