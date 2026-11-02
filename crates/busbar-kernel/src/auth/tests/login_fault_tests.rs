// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

type Fields = BTreeMap<String, String>;

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Fields>>>);

impl<S: tracing::Subscriber> Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct Values(Fields);
        impl tracing::field::Visit for Values {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        let mut values = Values(Fields::new());
        event.record(&mut values);
        self.0.lock().unwrap().push(values.0);
    }
}

#[test]
fn a_faulting_login_plugin_is_rejected_and_says_it_panicked_and_a_declining_one_says_nothing() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let rows = [
        ("idp", "begin_login"),
        ("idp", "complete_login"),
        ("test-login-double", "complete_login"),
    ];
    tracing::subscriber::with_default(subscriber, || {
        for (method, op) in rows {
            let result = finish_door_login(
                method,
                op,
                true,
                LoginOutcome::Identify(Principal::from_id("alice")),
            );
            assert_eq!(
                result,
                LoginOutcome::Reject,
                "a faulted step fails closed even if it supplied an identity"
            );
        }
    });
    let actual = events.0.lock().unwrap();
    assert_eq!(
        actual.len(),
        3,
        "one 4003 per faulted begin/callback/credential step: {actual:?}"
    );
    for (event, (method, op)) in actual.iter().zip(rows) {
        assert_eq!(event.get("diag").map(String::as_str), Some("BUSBAR-4003"));
        assert_eq!(event.get("method").map(String::as_str), Some(method));
        assert_eq!(event.get("op").map(String::as_str), Some(op));
        assert_eq!(
            event.get("error").map(String::as_str),
            Some("the login plugin faulted")
        );
        assert_eq!(
            event.get("message").map(String::as_str),
            Some("login plugin call panicked; rejecting (fail-closed)")
        );
    }
}

#[test]
fn a_nonfault_decline_or_identity_passes_through_without_a_panic_diagnostic() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        for outcome in [
            LoginOutcome::Reject,
            LoginOutcome::SecurityCheckFailed,
            LoginOutcome::Identify(Principal::from_id("alice")),
        ] {
            let result = finish_door_login("idp", "complete_login", false, outcome.clone());
            assert_eq!(result, outcome, "a normal answer retains its exact value");
        }
    });
    assert!(
        events.0.lock().unwrap().is_empty(),
        "a declining plugin emits no 4003"
    );
}
