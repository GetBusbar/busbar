// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn grants() -> BTreeMap<Box<str>, BTreeSet<Box<str>>> {
    BTreeMap::from([("reader".into(), BTreeSet::from(["signed".into()]))])
}

fn instance(name: &str, id: u64, kind: Option<&str>) -> GrantInstance<'_> {
    GrantInstance {
        name,
        id,
        kind,
        verifies: true,
    }
}

#[test]
fn issued_grants_require_explicit_matching_instance_kind_and_custody() {
    let allowed =
        resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], true).unwrap();
    assert_eq!(
        allowed,
        BTreeMap::from([(41, BTreeSet::from(["signed".into()]))])
    );
    let no_grants = resolve_grants(
        &BTreeMap::new(),
        [instance("reader", 41, Some("signed"))],
        false,
    )
    .unwrap();
    assert!(no_grants.is_empty(), "a describe grants nothing");
    for opened in [
        vec![],
        vec![instance("other", 41, Some("signed"))],
        vec![instance("reader", 41, Some("other"))],
        vec![instance("reader", 41, None)],
        vec![instance("reader", 0, Some("signed"))],
        vec![GrantInstance {
            verifies: false,
            ..instance("reader", 41, Some("signed"))
        }],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    assert!(resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], false).is_err());
}

#[test]
fn issued_grants_refuse_duplicate_runtime_reservations_and_builtin_keys() {
    for opened in [
        vec![
            instance("reader", 41, Some("signed")),
            instance("reader", 42, Some("signed")),
        ],
        vec![
            instance("reader", 41, Some("signed")),
            instance("other", 41, Some("signed")),
        ],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    let keys = BTreeMap::from([(
        busbar_kernel::config::KEYS_MODULE.into(),
        BTreeSet::from(["signed".into()]),
    )]);
    assert!(resolve_grants(
        &keys,
        [instance(
            busbar_kernel::config::KEYS_MODULE,
            41,
            Some("signed")
        )],
        true
    )
    .is_err());
}

#[test]
fn issued_grants_keep_explicit_empty_policy_without_inventing_custody() {
    let empty = BTreeMap::from([("reader".into(), BTreeSet::new())]);
    assert!(
        resolve_grants(&empty, [instance("reader", 41, None)], false)
            .unwrap()
            .get(&41)
            .unwrap()
            .is_empty()
    );
    assert!(
        resolve_grants(&empty, [], false).is_err(),
        "explicit policy still names an actual instance"
    );
}
