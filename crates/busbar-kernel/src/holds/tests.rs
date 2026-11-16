// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::directory::{HoldSet, Holds};

/// The index is process-wide: tests that publish take this lock.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn index() -> Arc<Published> {
    let ann = HoldSet::for_test(&["ann"]);
    let empty = HoldSet::for_test(&[]);
    let holds = Holds::for_test(vec![(7, vec![empty, ann])]);
    let ids = HashMap::from([("oidc".into(), 7u64)]);
    Arc::new(Published::new(holds, ids))
}

#[test]
fn a_held_principal_of_a_linked_inbound_is_refused_by_id_and_by_name() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    publish(Some(index()));
    assert!(held_by_id(7, "ann"));
    assert!(held_now("oidc", "ann"));
    publish(None);
}

#[test]
fn an_unheld_principal_and_an_unlinked_inbound_are_not_probed() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    publish(Some(index()));
    assert!(!held_by_id(7, "bob"));
    assert!(!held_by_id(8, "ann"), "no link.auth names instance 8");
    assert!(
        !held_now("keys", "ann"),
        "an unknown instance name has no entry"
    );
    publish(None);
}

#[test]
fn nothing_published_holds_nobody() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    publish(None);
    assert!(!held_by_id(7, "ann"));
    assert!(!held_now("oidc", "ann"));
}

#[test]
fn the_first_holding_set_wins_and_none_means_no_probe() {
    let sets = [HoldSet::for_test(&[]), HoldSet::for_test(&["ann"])];
    assert!(held_by(Some(&sets), "ann").is_some());
    assert!(held_by(Some(&sets), "bob").is_none());
    assert!(held_by(None, "ann").is_none());
}
