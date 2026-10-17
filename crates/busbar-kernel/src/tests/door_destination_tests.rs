// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's VERIFY guards over a fixed deployment, in their one order.

use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct View {
    key: bool,
    scoped: bool,
    allowed: Vec<&'static str>,
    fallback: BTreeMap<&'static str, &'static str>,
    configured: Vec<&'static str>,
    unpriced: Vec<&'static str>,
}

impl PoolView for View {
    fn has_key(&self) -> bool {
        self.key
    }
    fn key_is_scoped(&self) -> bool {
        self.scoped
    }
    fn pool_allowed(&self, pool: &str) -> bool {
        self.allowed.contains(&pool)
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallback.get(pool).map(|p| (*p).to_owned())
    }
    fn is_configured(&self, name: &str) -> bool {
        self.configured.contains(&name)
    }
    fn is_unpriced(&self, name: &str) -> bool {
        self.unpriced.contains(&name)
    }
}

#[test]
fn no_key_passes_every_guard() {
    let v = View {
        unpriced: vec!["a"],
        ..View::default()
    };
    assert_eq!(destination_guard(&v, "a"), Ok(()));
}

#[test]
fn a_pool_outside_the_key_allow_list_is_not_authorized() {
    let v = View {
        key: true,
        allowed: vec!["b"],
        ..View::default()
    };
    assert_eq!(
        destination_guard(&v, "a"),
        Err(VerifyRefusal::NotAuthorized)
    );
}

#[test]
fn a_reachable_fallback_pool_outside_the_allow_list_is_not_authorized() {
    let v = View {
        key: true,
        scoped: true,
        allowed: vec!["a", "b"],
        fallback: BTreeMap::from([("a", "b"), ("b", "c")]),
        ..View::default()
    };
    assert_eq!(
        destination_guard(&v, "a"),
        Err(VerifyRefusal::NotAuthorized)
    );
}

#[test]
fn a_fallback_cycle_ends_the_walk_without_a_refusal() {
    let v = View {
        key: true,
        scoped: true,
        allowed: vec!["a", "b"],
        fallback: BTreeMap::from([("a", "b"), ("b", "a")]),
        ..View::default()
    };
    assert_eq!(destination_guard(&v, "a"), Ok(()));
}

#[test]
fn an_unconfigured_unpriced_name_has_no_rate_and_the_acl_is_asked_first() {
    let v = View {
        key: true,
        allowed: vec!["m"],
        unpriced: vec!["m"],
        ..View::default()
    };
    assert_eq!(
        destination_guard(&v, "m"),
        Err(VerifyRefusal::NoRate {
            name: "m".to_owned()
        })
    );
    let denied = View {
        key: true,
        unpriced: vec!["m"],
        ..View::default()
    };
    assert_eq!(
        destination_guard(&denied, "m"),
        Err(VerifyRefusal::NotAuthorized)
    );
    let configured = View {
        key: true,
        allowed: vec!["m"],
        configured: vec!["m"],
        unpriced: vec!["m"],
        ..View::default()
    };
    assert_eq!(destination_guard(&configured, "m"), Ok(()));
}

#[test]
fn each_refusal_names_its_status_kind_and_reason() {
    let na = VerifyRefusal::NotAuthorized;
    assert_eq!(
        (na.status(), na.kind()),
        (403, busbar_contract::protocol::KIND_PERMISSION)
    );
    assert_eq!(na.reason(), ReasonCode::PoolNotPermitted);
    let nr = VerifyRefusal::NoRate {
        name: "m".to_owned(),
    };
    assert_eq!(
        (nr.status(), nr.kind()),
        (400, busbar_contract::protocol::KIND_INVALID_REQUEST)
    );
    assert_eq!(nr.message(), "no configured rate for model 'm'");
    assert_eq!(nr.reason(), ReasonCode::NoRate);
}
