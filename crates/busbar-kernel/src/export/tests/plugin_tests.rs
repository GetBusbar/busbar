// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the export axis (`export/plugin.rs`). The kernel names no export plugin, so the axis
//! here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL `kind:
//! export` rows whose library bytes are not a library — enough for every question the kernel asks
//! of the axis (does this module resolve, is it an export) and for the open to fail the way a
//! broken plugin fails. The dropped-in plugin that actually SERVES is driven end to end by the
//! composition root (`crates/busbar/tests/export_plugin_dropped_in_serves.rs`).

use super::*;
use crate::config::{resolve_export, ExportDefCfg, ExportDefs};

use crate::export::scrape::tests::installed_axis;

fn def(module: &str) -> ExportDefCfg {
    serde_json::from_value(serde_json::json!({ "module": module })).expect("a minimal definition")
}

/// THE CONTROL OF ITEM 141 at the config layer: a `module:` naming a `kind: export` row on the axis
/// — by its name or its alias — RESOLVES to an instance the boot will open, and one naming nothing
/// on the axis is refused in exactly 1.5.5's words, so a config without plugins reads as it always did.
#[test]
fn a_module_on_the_axis_resolves_and_an_unregistered_one_is_refused_as_before() {
    installed_axis();
    for module in ["k9-axis-sink", "k9-tail"] {
        let mut defs = ExportDefs::new();
        defs.insert("audit-tail".to_string(), def(module));
        let mut errors = Vec::new();
        let cfg = resolve_export(&defs, &mut errors);
        assert!(errors.is_empty(), "{module}: {errors:?}");
        assert_eq!(cfg.plugins.len(), 1, "{module}");
        assert_eq!(cfg.plugins[0].name, "audit-tail");
        // The sink's streams are not known until it is opened, so the compute gate provisionally
        // wants what this release produces — `logs` among them — rather than nothing.
        assert!(cfg.projection_union().wants_stream(ExportStream::Logs));
    }

    let mut defs = ExportDefs::new();
    defs.insert("audit-tail".to_string(), def("k9-never-registered"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(cfg.plugins.is_empty());
    assert_eq!(
        errors,
        vec![
            "export.audit-tail.module: unknown exporter 'k9-never-registered'; the built-in export \
             modules are prometheus | request-log-webhook | request-log-file | otlp"
                .to_string()
        ]
    );
}

/// A sink that will not open refuses the boot, naming the instance and carrying the loader's reason
/// — a configured sink is never silently absent.
#[test]
fn a_sink_that_will_not_open_refuses_naming_the_instance() {
    installed_axis();
    let mut defs = ExportDefs::new();
    defs.insert("tail".to_string(), def("k9-axis-sink"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let refusal = open(&cfg).expect_err("bytes that are not a library do not open");
    assert!(refusal.starts_with("export.tail: "), "{refusal}");
}

/// THE SHED CAP (PB-12): a plugin sink that states no admission is held to the host's
/// [`MAX_INFLIGHT_PLUGIN_DELIVERIES`] — the 65th delivery in flight is SHED, never queued, and a
/// released slot admits again; a sink that states its bound is held to exactly that. RED arm, in
/// the same test: a stated bound of 0 is the host's cap, never a gate that admits nothing (or
/// everything).
#[test]
fn a_plugin_sink_sheds_deliveries_beyond_its_inflight_cap() {
    assert_eq!(MAX_INFLIGHT_PLUGIN_DELIVERIES, 64);
    let fill = |a: &Admission, n: usize| -> Vec<_> {
        (0..n)
            .map(|i| {
                a.gate
                    .try_enter()
                    .unwrap_or_else(|| panic!("slot {i} is within the cap"))
            })
            .collect()
    };
    let host = Admission::of("k9-tail", None);
    assert!(host.live);
    let held = fill(&host, MAX_INFLIGHT_PLUGIN_DELIVERIES);
    assert!(
        host.gate.try_enter().is_none(),
        "the delivery past the cap is shed"
    );
    drop(held);
    assert!(
        host.gate.try_enter().is_some(),
        "a released slot admits again"
    );

    let stated = Admission::of("k9-tail", Some((true, 3, "webhook".into())));
    let held = fill(&stated, 3);
    assert!(
        stated.gate.try_enter().is_none(),
        "a stated bound is the cap"
    );
    drop(held);

    // RED ARM: `inflight: 0` states no bound — the host's cap, not zero.
    let zero = Admission::of("k9-tail", Some((true, 0, String::new())));
    let _held = fill(&zero, MAX_INFLIGHT_PLUGIN_DELIVERIES);
    assert!(zero.gate.try_enter().is_none());
    // A sink that is not live keeps its gate but takes nothing.
    assert!(!Admission::of("k9-tail", Some((false, 0, String::new()))).live);
}

/// Each configured instance holds its OWN admission gate: one saturated instance never consumes a
/// sibling's budget (the per-instance posture the request-log webhook always had).
#[test]
fn each_plugin_sink_instance_gets_its_own_admission_gate() {
    let a = Admission::of("request-log-webhook", Some((true, 1, "webhook".into())));
    let b = Admission::of("request-log-webhook", Some((true, 1, "webhook".into())));
    let _held = a.gate.try_enter().expect("a admits one");
    assert!(a.gate.try_enter().is_none(), "a is saturated");
    assert!(
        b.gate.try_enter().is_some(),
        "b is untouched by a's saturation"
    );
}
