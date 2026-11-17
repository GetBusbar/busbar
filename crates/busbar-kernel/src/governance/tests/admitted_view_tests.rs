// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::groups::GroupCfg;
use crate::cost::CostModel;
use busbar_contract::records::VirtualKey;
use std::collections::BTreeMap;

#[test]
fn admitted_chain_refuses_a_plan_for_another_key_chain() {
    let cost = CostModel::resolve_parts(None, 0, &BTreeMap::from([
        ("a".into(), GroupCfg::default()), ("b".into(), GroupCfg::default()),
    ]));
    let a = VirtualKey { id: "a".into(), group: Some("a".into()), ..Default::default() };
    let b = VirtualKey { id: "b".into(), group: Some("b".into()), ..Default::default() };
    let plan = cost.plan_chain(&a).unwrap();
    assert!(cost.admitted_chain(&a, &plan).is_some());
    assert!(cost.admitted_chain(&b, &plan).is_none(), "an admitted reader must not resolve b's replacement chain");
}

#[test]
fn admitted_chain_does_not_reinterpret_indices_after_reload() {
    let old = CostModel::resolve_parts(None, 0, &BTreeMap::from([("a".into(), GroupCfg::default())]));
    let new = CostModel::resolve_parts(None, 0, &BTreeMap::from([("other".into(), GroupCfg::default())]));
    let key = VirtualKey { id: "payer".into(), group: Some("a".into()), ..Default::default() };
    let plan = old.plan_chain(&key).unwrap();
    assert!(old.admitted_chain(&key, &plan).is_some());
    assert!(new.admitted_chain(&key, &plan).is_none());
}
