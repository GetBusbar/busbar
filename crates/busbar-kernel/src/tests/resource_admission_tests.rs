// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-NATIVE-ROUTE-CLASSES test 1 (#462): an empty selection never admits a key.

use std::num::NonZeroU64;

use busbar_contract::abi::mechanism::KindCode;

use super::*;

fn key(allowed_scopes: Option<Vec<ScopeRef>>) -> VirtualKey {
    VirtualKey {
        id: "payer".into(),
        enabled: true,
        allowed_scopes,
        ..Default::default()
    }
}

/// Built in-module: `select` refuses zero tuples, so only a private construction reaches
/// `scope_allowed` with nothing selected.
fn empty_selection() -> SelectedResources {
    let caller = Caller::for_test(Arc::from("plane/test"), KindCode::Plane);
    let inventory = Arc::new(ResourceInventory {
        instance: caller.incarnation().clone(),
        namespace: Arc::clone(caller.namespace()),
        epoch: 7,
        scopes: BTreeSet::from([("pool".to_owned(), "a".to_owned())]),
        descriptors: BTreeMap::new(),
    });
    SelectedResources {
        inventory,
        request: Arc::new(FrozenRequest::new(
            InvocationId::from_request_id(NonZeroU64::new(1).unwrap()),
            3,
            "POST".into(),
            "/requests".into(),
            "".into(),
            vec![],
            b"request".to_vec(),
        )),
        scopes: BTreeSet::new(),
    }
}

#[test]
fn an_empty_selection_admits_no_key() {
    let selected = empty_selection();
    for allowed in [Some(vec![ScopeRef::pool("a")]), Some(vec![]), None] {
        assert!(
            !selected.scope_allowed(&key(allowed.clone())),
            "an empty selection admitted a key with allowed_scopes {allowed:?}"
        );
    }
}
