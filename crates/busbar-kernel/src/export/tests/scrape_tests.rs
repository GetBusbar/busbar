// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{ExportCfg, ExportDefs};
#[test]
fn an_explicit_neutral_declaration_selects_the_recorder_consumer() {
    let defs: ExportDefs = serde_yaml::from_str(
        "metrics: { module: arbitrary-sink, settings: { vendor_option: opaque } }\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let mut cfg = ExportCfg::default();
    for (name, def) in defs {
        let projection = crate::export::projection::resolve_projection(
            &name,
            &def.module,
            Some(&[busbar_contract::abi::export::ExportStream::Metrics]),
            def.streams.as_deref(),
            def.fields.as_deref(),
            def.durable,
            &mut errors,
        );
        let (scrape, recorder) = super::super::plugin::scrape_instance(
            projection,
            Some(&[busbar_contract::abi::export::ExportStream::Metrics]),
            Some(busbar_contract::export_calls::RecorderRequirements {
                retention_seconds: 60,
                key_gauge_limit: 7,
            }),
            cfg.plugins.iter().any(|plugin| plugin.scrape),
        )
        .expect("explicit declaration admits");
        if scrape {
            cfg.recorder = recorder;
        }
        cfg.plugins.push(crate::config::PluginExportSettings {
            name,
            def,
            projection,
            scrape,
        });
    }
    assert!(errors.is_empty(), "{errors:?}");
    let scraped: Vec<_> = cfg
        .plugins
        .iter()
        .filter(|p| p.scrape)
        .map(|p| &p.name)
        .collect();
    assert_eq!(scraped, ["metrics"]);
    assert_eq!(
        cfg.recorder
            .as_ref()
            .map(|r| (r.retention_seconds, r.key_gauge_limit)),
        Some((60, 7)),
        "the recorder's settings ride on the scrape sink's instance"
    );
}

#[test]
fn no_scrape_instance_declares_no_route() {
    assert!(crate::export::route_decls(&ExportCfg::default()).is_empty());
}

#[tokio::test]
async fn an_ungranted_crossing_reads_no_snapshot() {
    assert_eq!(read(0).await, Snapshot::Refused(NOT_GRANTED));
    assert_eq!(
        read(SNAPSHOT_SCOPE_HOOKS).await,
        Snapshot::Refused(NOT_GRANTED)
    );
}

#[tokio::test]
async fn the_snapshot_lend_is_captured_inside_the_crossing() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let outside = read(SNAPSHOT_SCOPE_HOOKS);
    let (whole, hooks, unknown) = lend(None, || {
        (
            read(SNAPSHOT_SCOPE_WHOLE),
            read(SNAPSHOT_SCOPE_HOOKS),
            read(7),
        )
    });
    assert!(matches!(whole.await, Snapshot::Families(_)));
    assert_eq!(hooks.await, Snapshot::Families(Vec::new()));
    assert_eq!(unknown.await, Snapshot::Refused(UNKNOWN_SCOPE));
    assert_eq!(outside.await, Snapshot::Refused(NOT_GRANTED));
    assert_eq!(read(0).await, Snapshot::Refused(NOT_GRANTED));
}

#[tokio::test]
async fn nested_and_panicking_crossings_restore_the_prior_lend() {
    let (unknown, hooks) = lend(None, || {
        let panic = std::panic::catch_unwind(|| {
            lend(None, || panic!("a crossing unwinds"));
        });
        assert!(panic.is_err());
        (read(7), read(SNAPSHOT_SCOPE_HOOKS))
    });
    assert_eq!(unknown.await, Snapshot::Refused(UNKNOWN_SCOPE));
    assert_eq!(hooks.await, Snapshot::Families(Vec::new()));
    assert_eq!(read(0).await, Snapshot::Refused(NOT_GRANTED));
}

#[test]
fn recorder_admission_needs_a_declaration_and_rejects_competing_or_invalid_requests() {
    use busbar_contract::abi::export::ExportStream;
    use busbar_contract::export_calls::RecorderRequirements;
    let declared = [ExportStream::Metrics];
    let mut errors = Vec::new();
    let projection = crate::export::projection::resolve_projection(
        "neutral",
        "any-module",
        Some(&declared),
        None,
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty());
    let admit = |recorder, already| {
        super::super::plugin::scrape_instance(projection, Some(&declared), recorder, already)
    };
    assert_eq!(admit(None, false).unwrap(), (false, None));
    let valid = RecorderRequirements {
        retention_seconds: 60,
        key_gauge_limit: 7,
    };
    assert_eq!(admit(Some(valid), false).unwrap(), (true, Some(valid)));
    assert!(admit(Some(valid), true).is_err());
    assert!(admit(
        Some(RecorderRequirements {
            retention_seconds: 0,
            ..valid
        }),
        false
    )
    .is_err());
    assert!(super::super::plugin::scrape_instance(projection, None, Some(valid), false).is_err());
    let excluded = crate::export::projection::resolve_projection(
        "neutral",
        "any-module",
        Some(&declared),
        Some(&[]),
        None,
        false,
        &mut errors,
    );
    assert_eq!(
        super::super::plugin::scrape_instance(excluded, Some(&declared), Some(valid), false)
            .unwrap(),
        (false, None)
    );
}
