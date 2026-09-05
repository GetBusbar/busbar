// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.5 deployment on a published store plugin (ABI 2: sqlite / postgres / mysql / valkey)
//! keeps booting and serving byte-identically once the engine grows the 1.6.0-only store verbs.
//!
//! Binding: every 1.6.0-only store operation invoked against an ABI-2 store answers from a
//! node-local default. Never an error on the request path, never a log line, never a boot
//! refusal. Meanwhile the 1.5.5 base verbs the boot and the request path actually use keep
//! answering with the plugin's real rows.
//!
//! The ABI-2 plugin is modelled the only way it can be from this side of the seam: the in-tree
//! store example plugin with its `call` seam faked to answer `STATUS_UNSUPPORTED` for the verbs
//! it predates. The example plugin really does load at the `supported_abi` floor of 2, so the
//! `DynStore` path exercised is the one a real 1.5.x plugin lands on.
//!
//! The log-line half is captured with a thread-local `tracing` subscriber on the calling thread —
//! the thread `DynStore`'s own diagnostics fire on. (The FFI call itself runs on a loader-owned
//! worker thread; nothing on that side logs on the unsupported path, and the transport layer is
//! covered by its own tests.)
//!
//! `redeem_plane_token` is out of scope here by design: it is the single verb whose safe default is
//! fail-CLOSED (anti-replay), and a 1.5.5-shaped deployment never mints the single-use tokens that
//! would call it. Its behaviour is pinned in `legacy_default_tests`.

use super::*;
use std::sync::{Arc, Mutex};

/// Every `tracing` event that fired on this thread while a subscriber built from this was
/// installed, rendered as `LEVEL message field=value ...`.
#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Vec<String>>>);

impl EventLog {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl tracing::Subscriber for EventLog {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Render(String);
        impl tracing::field::Visit for Render {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }
        let mut r = Render(format!("{}", event.metadata().level()));
        event.record(&mut r);
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(r.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Point the fake plugin at the crisp "I do not know this variant" answer.
fn answer_unsupported() {
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_UNSUPPORTED, b"unknown variant")));
}

/// Point the fake plugin at a real serialized answer.
fn answer_ok(resp: &StoreResponse) {
    let bytes = serde_json::to_vec(resp).expect("StoreResponse serializes");
    let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_OK, leaked)));
}

fn record(kind: &str, id: &str) -> PlaneRecord {
    PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent: Some("p".to_string()),
        seq: 1,
        ts: 1_700_000_000,
        disposition: busbar_api::PlaneDisposition::Active,
        body: b"{}".to_vec(),
    }
}

/// The 1.5.5 base rows a boot reads back from the plugin: one enabled key.
fn one_key() -> VirtualKey {
    VirtualKey {
        id: "vk_1".to_string(),
        generation_hash: "gen".to_string(),
        name: "legacy".to_string(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

/// Every 1.6.0-only store verb, called against an ABI-2 store, answers its node-local default
/// with no error and no log line, while the 1.5.5 base verbs keep answering the plugin's rows.
/// The sequence mirrors a boot (read keys, denylist, audit tail) followed by serving (a key
/// lookup, then the plane verbs a compiled-in plane would issue).
#[test]
fn every_1_6_0_only_store_op_on_an_abi_2_store_defaults_with_no_error_and_no_log_line() {
    let Some(store) = dyn_example_store_with_fake_call() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let log = EventLog::default();
    let mut failures: Vec<String> = Vec::new();

    tracing::subscriber::with_default(log.clone(), || {
        // Boot-time reads: the plugin has real answers for the base verbs. `list_denylist` and the
        // audit tail are 1.5.x additive verbs; a plugin predating them defaults, which is the
        // 1.5.5 rule too (see the legacy-default tests). Here the plugin knows them.
        answer_ok(&StoreResponse::Keys(vec![one_key()]));
        match store.list_keys() {
            Ok(keys) if keys.len() == 1 && keys[0].id == "vk_1" => {}
            other => failures.push(format!("list_keys must return the plugin's row: {other:?}")),
        }
        answer_ok(&StoreResponse::Denylist(Vec::new()));
        if let Err(e) = store.list_denylist() {
            failures.push(format!("list_denylist: {e:?}"));
        }
        answer_ok(&StoreResponse::Audit(Vec::new()));
        if let Err(e) = store.list_audit_tail(100) {
            failures.push(format!("list_audit_tail: {e:?}"));
        }
        answer_ok(&StoreResponse::CredentialSecrets(Vec::new()));
        if let Err(e) = store.list_credentials_since(0) {
            failures.push(format!("list_credentials_since: {e:?}"));
        }

        // Serving: the base verbs still hit the plugin.
        answer_ok(&StoreResponse::Key(Some(one_key())));
        match store.get_key("vk_1") {
            Ok(Some(k)) if k.id == "vk_1" => {}
            other => failures.push(format!("get_key must return the plugin's row: {other:?}")),
        }

        // The 1.6.0-only verbs: the plugin predates every one of them.
        let rec = record("task", "t-1");
        answer_unsupported();
        match store.upsert_plane_record(&rec) {
            Ok(()) => {}
            Err(e) => failures.push(format!("upsert_plane_record: {e:?}")),
        }
        answer_unsupported();
        match store.get_plane_record("task", "t-1") {
            Ok(None) => {}
            other => failures.push(format!("get_plane_record must default to None: {other:?}")),
        }
        answer_unsupported();
        match store.append_plane_record(&record("event", "e-1")) {
            Ok(()) => {}
            Err(e) => failures.push(format!("append_plane_record: {e:?}")),
        }
        answer_unsupported();
        match store.list_plane_records("event", &PlaneSelector::Parent("t-1".into())) {
            Ok(v) if v.is_empty() => {}
            other => failures.push(format!(
                "list_plane_records must default to empty: {other:?}"
            )),
        }
        answer_unsupported();
        match store.list_plane_records("task", &PlaneSelector::All) {
            Ok(v) if v.is_empty() => {}
            other => failures.push(format!(
                "list_plane_records(All) must default to empty: {other:?}"
            )),
        }
        answer_unsupported();
        match store.list_plane_record_parents("event") {
            Ok(v) if v.is_empty() => {}
            other => failures.push(format!(
                "list_plane_record_parents must default to empty: {other:?}"
            )),
        }
        answer_unsupported();
        match store.purge_plane_records_before("task", u64::MAX) {
            Ok(0) => {}
            other => failures.push(format!(
                "purge_plane_records_before must default to 0: {other:?}"
            )),
        }
        answer_unsupported();
        match store.delete_plane_record("task", "t-1") {
            Ok(()) => {}
            Err(e) => failures.push(format!("delete_plane_record: {e:?}")),
        }

        // And the base verbs are unaffected afterwards: the plugin is still the source of truth.
        answer_ok(&StoreResponse::Keys(vec![one_key()]));
        match store.list_keys() {
            Ok(keys) if keys.len() == 1 => {}
            other => failures.push(format!("list_keys after the sweep: {other:?}")),
        }
    });

    assert!(
        failures.is_empty(),
        "an ABI-2 store must answer every 1.6.0-only verb with its default and keep serving the \
         base verbs; failures:\n{}",
        failures.join("\n")
    );
    let lines = log.lines();
    assert!(
        lines.is_empty(),
        "no log line may fire for a 1.6.0-only verb on an ABI-2 store (1.5.5 never logged here); \
         captured:\n{}",
        lines.join("\n")
    );
}

/// The same sweep, repeated, stays quiet: the defaults are not a warn-once latch that merely
/// happened to be silent on the first pass.
#[test]
fn repeated_1_6_0_only_ops_on_an_abi_2_store_stay_silent() {
    let Some(store) = dyn_example_store_with_fake_call() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let log = EventLog::default();
    let mut errors = 0usize;
    tracing::subscriber::with_default(log.clone(), || {
        for i in 0..25u64 {
            let id = format!("t-{i}");
            answer_unsupported();
            errors += store.upsert_plane_record(&record("task", &id)).is_err() as usize;
            answer_unsupported();
            errors += store.get_plane_record("task", &id).is_err() as usize;
            answer_unsupported();
            errors += store
                .list_plane_records("task", &PlaneSelector::All)
                .is_err() as usize;
            answer_unsupported();
            errors += store.purge_plane_records_before("task", i).is_err() as usize;
        }
    });
    assert_eq!(errors, 0, "no 1.6.0-only verb may error on an ABI-2 store");
    assert!(
        log.lines().is_empty(),
        "no log line across repeated calls; captured:\n{}",
        log.lines().join("\n")
    );
}
