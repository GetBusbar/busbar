// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{ExportCfg, ExportDefs};
#[test]
fn the_metrics_instance_is_the_scrape_sink() {
    let defs: ExportDefs = serde_yaml::from_str(
        "metrics: { module: prometheus, settings: { buffer_seconds: 60, key_gauge_limit: 7 } }\n",
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
            true,
            cfg.plugins.iter().any(|plugin| plugin.scrape),
            serde_json::Value::Object(def.settings.clone()),
        );
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
            .map(|r| (r.buffer_seconds, r.key_gauge_limit)),
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
