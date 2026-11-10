// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::export::CHECK_PHASE_INSTANCES;
use busbar_contract::abi::mechanism::door::DoorFn;

use super::*;
use crate::both_ways;
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};
use crate::neutral_export;
use crate::sign::Manifest;

#[test]
fn trace_diagnostics_mask_userinfo_even_when_the_endpoint_is_malformed() {
    let mask = busbar_contract::abi::sdk::mask::mask_url;
    assert_eq!(
        mask("https://user:secret@collector:bad/v1/traces"),
        "https://***@collector:bad/v1/traces"
    );
    assert_eq!(
        mask("https://user:secret@/v1/traces"),
        "https://***@/v1/traces"
    );
    assert_eq!(
        mask("https://collector/v1/traces"),
        "https://collector/v1/traces"
    );
    assert!(!mask("https://user:secret@collector/v1/traces").contains("secret"));
}

fn manifest(name: &str) -> Manifest {
    let v = busbar_contract::abi::export::ABI_VERSION;
    both_ways::statement("export", name, name, v)
}

fn both(name: &str, door: DoorFn, path: std::path::PathBuf) -> [PluginRegistry; 2] {
    let lib = std::fs::read(path).expect("read the neutral SDK cdylib");
    let linked = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(name), door)])
        .expect("the linked door admits the sink");
    let mut stated = manifest(name);
    stated.statement = Some(hex::encode(
        rendering_of(door).expect("the door renders its Statement"),
    ));
    let dropped = both_ways::dropped(name, stated, &lib);
    [linked, dropped]
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ))
}

#[test]
fn the_trace_binding_answers_the_same_through_either_door() {
    let row = neutral_export::NAME;
    let doors = both(row, neutral_export::door, neutral_export::cdylib());
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_conns(crate::dispatch::test_admissions(Arc::new(
                crate::needs_restated::Inert,
            )));
        let module = row;
        let good = serde_json::json!({ "target": "http://127.0.0.1:4318/v1/traces" });
        let (streams, clean, _) = rows
            .probe(module, "trace", &crate::dispatch::test_settings(&good))
            .expect("an export row");
        assert_eq!(streams, Some(neutral_export::STREAMS.to_vec()));
        assert!(clean.is_empty(), "{clean:?}");
        let bad = serde_json::json!({ "target": "http://127.0.0.1:4318", "bogus": 1 });
        let (_, refused, _) = rows
            .probe(module, "trace", &crate::dispatch::test_settings(&bad))
            .expect("an export row");
        assert_eq!(
            refused,
            vec!["export.trace.settings: witness refused".to_string()]
        );
        let sink = rows
            .open(
                module,
                "export.trace",
                &crate::export_axis::test_opening(&good),
            )
            .expect("the sink opens");
        format!("{refused:?} {:?}", sink.streams())
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

#[test]
fn the_log_binding_answers_the_same_through_either_door() {
    let row = neutral_export::NAME;
    let doors = both(row, neutral_export::door, neutral_export::cdylib());
    let transcripts = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_conns(crate::dispatch::test_admissions(Arc::new(
                crate::needs_restated::Inert,
            )));
        let module = row;
        let good = serde_json::json!({ "target": "https://collector.example.com/v1/logs" });
        let (streams, clean, _) = rows
            .probe(module, "audit", &crate::dispatch::test_settings(&good))
            .expect("an export row");
        assert_eq!(streams, Some(neutral_export::STREAMS.to_vec()));
        assert!(clean.is_empty(), "{clean:?}");
        let bad = serde_json::json!({ "target": "https://collector.example.com", "bogus": 1 });
        let (_, refused, _) = rows
            .probe(module, "audit", &crate::dispatch::test_settings(&bad))
            .expect("an export row");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with("export.audit.settings: witness refused"),
            "{refused:?}"
        );
        let sink = rows
            .open(
                module,
                "export.audit",
                &crate::export_axis::test_opening(&good),
            )
            .expect("the sink opens");
        format!("{refused:?} {:?}", sink.streams())
    });
    assert_eq!(transcripts[0], transcripts[1], "both doors answer the same");
}

#[test]
fn check_runs_when_the_first_instance_does_not_open() {
    let row = neutral_export::NAME;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(
            manifest(row),
            neutral_export::door,
        )])
        .expect("the linked door admits the sink");
    let rows = ExportRows::new(&registry, dispatcher())
        .with_disk(crate::dispatch::test_disk_authority())
        .with_conns(crate::dispatch::test_admissions(Arc::new(
            crate::needs_restated::Inert,
        )));
    let findings = rows
        .check(
            row,
            busbar_contract::abi::export::CHECK_PHASE_LIMITS,
            &[
                (
                    "metrics".into(),
                    &crate::dispatch::test_settings(&serde_json::json!({ "bogus": 1 })),
                ),
                (
                    "second".into(),
                    &crate::dispatch::test_settings(&serde_json::json!({ "case": "second" })),
                ),
            ],
        )
        .expect("an export row");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].starts_with("export.second: witness second phase "),
        "{findings:?}"
    );
}

#[test]
fn a_module_no_row_answers_is_not_on_the_axis() {
    let registry = PluginRegistry::empty();
    let rows =
        ExportRows::new(&registry, dispatcher()).with_disk(crate::dispatch::test_disk_authority());
    assert!(rows
        .probe(
            "nothing",
            "x",
            &crate::dispatch::test_settings(&serde_json::json!({}))
        )
        .is_none());
    assert!(rows.check("nothing", 0, &[]).is_none());
    let Err(refused) = rows.open(
        "nothing",
        "export.x",
        &crate::export_axis::test_opening(&serde_json::json!({})),
    ) else {
        panic!("no row answers");
    };
    assert_eq!(refused, "no `kind: export` plugin answers to 'nothing'");
}

#[test]
fn an_export_door_stating_ready_is_awaited_when_it_starts() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME, READIES};
    use std::sync::atomic::Ordering;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(NAME), door)])
        .expect("the linked witness admits");
    let rows = ExportRows::new(&registry, dispatcher())
        .with_disk(crate::dispatch::test_disk_authority())
        .with_conns(crate::dispatch::test_admissions(Arc::new(
            crate::needs_restated::Inert,
        )));
    let refused = serde_json::json!({ "ready": "err:the target is refused" });
    let before = READIES.load(Ordering::SeqCst);
    let _ = rows.check(
        NAME,
        CHECK_PHASE_INSTANCES,
        &[("audit".into(), &crate::dispatch::test_settings(&refused))],
    );
    assert_eq!(
        READIES.load(Ordering::SeqCst),
        before,
        "check's instance is never asked"
    );
    let sink = rows
        .open(
            NAME,
            "export.audit",
            &crate::export_axis::test_opening(&refused),
        )
        .expect("the instance opens; it is not asked yet");
    assert_eq!(READIES.load(Ordering::SeqCst), before, "open does not ask");
    let failed = sink.start().expect_err("a refused ready refuses the start");
    assert!(failed.contains("the target is refused"), "{failed}");
    assert_eq!(READIES.load(Ordering::SeqCst), before + 1);
    rows.open(
        NAME,
        "export.audit",
        &crate::export_axis::test_opening(&serde_json::json!({ "ready": "fine" })),
    )
    .expect("the sink opens")
    .start()
    .expect("a READY ready starts the sink");
    assert_eq!(READIES.load(Ordering::SeqCst), before + 2);
}

#[test]
fn an_export_instance_is_bound_by_its_own_inflight_clamped_to_one() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME};
    const DECLARED: u32 = 4;
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(NAME), door)])
        .expect("the linked witness admits");
    let rows = ExportRows::new(&registry, dispatcher())
        .with_disk(crate::dispatch::test_disk_authority())
        .with_conns(crate::dispatch::test_admissions(Arc::new(
            crate::needs_restated::Inert,
        )));
    let row = rows.row(NAME).expect("an export row");
    let bound = |stated: Option<u64>| {
        let mut settings = serde_json::json!({ "ready": "fine" });
        if let Some(n) = stated {
            settings["max_inflight_deliveries"] = n.into();
        }
        let admitted = crate::export_axis::test_opening(&settings);
        rows.load(row, "export.audit", Some(admitted.max_inflight()))
            .expect("the sink binds")
            .max_inflight()
    };
    assert_eq!(
        bound(Some(0)),
        1,
        "a stated 0 runs at one permit, as 1.5.5 clamped it"
    );
    assert_eq!(
        bound(Some(3)),
        3,
        "each instance is bound by its own figure"
    );
    assert_eq!(
        bound(None),
        busbar_contract::export_calls::DEFAULT_INFLIGHT.min(DECLARED),
        "none stated: the default, within the declared concurrency"
    );
}

#[test]
fn an_export_opening_requires_the_host_settings_seal() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME};
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest(NAME), door)])
        .expect("the linked witness admits");
    let rows = ExportRows::new(
        &registry,
        Arc::new(Dispatcher::new_unlent(DispatchConfig::default())),
    )
    .with_disk(crate::dispatch::test_disk_authority());
    let settings = crate::export_axis::test_opening(
        &serde_json::json!({"ready":"fine","password":"unlent-canary"}),
    );
    let error = rows
        .open(NAME, "export.unlent", &settings)
        .err()
        .expect("unlent settings refused");
    assert!(error.contains("host settings seal"), "{error}");
    assert!(!error.contains("unlent-canary"), "{error}");
}

#[test]
fn a_check_on_a_row_that_will_not_load_answers_why() {
    let row = "export-unloadable";
    let registry = both_ways::dropped(row, manifest(row), b"not a library");
    let rows =
        ExportRows::new(&registry, dispatcher()).with_disk(crate::dispatch::test_disk_authority());
    let findings = rows
        .check(
            row,
            CHECK_PHASE_INSTANCES,
            &[(
                "audit".into(),
                &crate::dispatch::test_settings(&serde_json::json!({})),
            )],
        )
        .expect("an export row");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].starts_with(&format!("export `module: {row}`: "))
            && findings[0].contains(NO_DOOR),
        "{findings:?}"
    );
}

extern "C" fn pl_src_1_unopened_door() -> *const busbar_contract::abi::mechanism::door::Door {
    std::ptr::null()
}

#[test]
fn a_linked_row_of_another_kind_is_not_a_linked_export() {
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::auth_door_named_raw(
            "busbar-auth-pl-src-1",
            "pl-src-1-not-export",
            pl_src_1_unopened_door,
        )])
        .expect("the auth row registers");
    let rows =
        ExportRows::new(&registry, dispatcher()).with_disk(crate::dispatch::test_disk_authority());
    assert!(
        !rows.linked("pl-src-1-not-export"),
        "a linked auth row must not answer as a linked export"
    );
}

#[test]
fn declared_disk_destinations_require_kernel_authority_before_open() {
    use crate::dispatch::ready::ready_plugins::export::{door, NAME};
    let mut stated = manifest(NAME);
    stated.declares.destinations = vec!["output".into()];
    let registry = PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(stated, door)])
        .expect("the kind witness admits");
    let rows = ExportRows::new(&registry, dispatcher());
    let settings = crate::export_axis::test_opening(&serde_json::json!({
        "ready":"fine", "output":"unadmitted-filesystem-canary"
    }));
    let error = rows
        .open(NAME, "export.unadmitted-disk", &settings)
        .err()
        .expect("missing authority refuses before plugin open");
    assert!(error.contains("kernel admission authority"), "{error}");
    assert!(!error.contains("unadmitted-filesystem-canary"), "{error}");
}
