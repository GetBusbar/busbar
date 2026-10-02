// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`AuthRows`] over the registry: what it answers, and what it refuses to open.

use std::sync::Arc;
use std::time::Duration;

use super::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::PluginRegistry;

fn empty() -> AuthRows {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }));
    AuthRows::new(Box::leak(Box::new(PluginRegistry::empty())), d)
}

#[test]
fn a_module_no_row_answers_is_refused_by_name() {
    let rows = empty();
    assert!(!rows.answers("nobody"));
    assert!(!rows.linked("nobody"));
    assert!(rows.linked_names().is_empty());
    let err = rows
        .open("nobody", "nobody", &serde_json::json!({}))
        .err()
        .expect("refused");
    assert_eq!(err, "no `kind: auth` plugin answers to 'nobody'");
}
