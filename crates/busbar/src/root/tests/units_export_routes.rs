// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE-DECLARATION FACE, measured at the composition root.
//!
//! What is measured here is the ROOT's half: the declarer production hands the engine, the mapping
//! from a sink's own words into this process's router vocabulary, and the sink's policy arriving on
//! the wire unaltered. The ENGINE's half — that a declared route is mounted and reached, and that a
//! path nobody declared is answered exactly as it was before anything was declared — is measured
//! over a fake export beside the mount itself, where the table lives.

use super::*;

/// An `export:` block with one `prometheus` instance, minted through the REAL config path — the
/// only way to obtain one at all, and the same resolution boot runs on the operator's document.
fn prometheus_cfg() -> config::ExportCfg {
    let mut defs = config::ExportDefs::new();
    defs.insert(
        "p".to_string(),
        serde_json::from_value(
            serde_json::json!({ "module": "prometheus", "settings": { "buffer_seconds": 60 } }),
        )
        .expect("a well-formed export instance"),
    );
    let mut errors = Vec::new();
    let cfg = config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");
    cfg
}

/// THE COMPOSED `prometheus` SINK IS DECLARED ONLY WHEN THE OPERATOR CONFIGURED ONE, and what it
/// declares is the well-known scrape path behind the data-plane bar.
///
/// This drives the REAL declarer production hands the engine, so the mapping from the sink's own
/// words into this process's router vocabulary is what is measured.
#[test]
fn the_prometheus_sink_declares_the_well_known_scrape_path_only_when_configured() {
    let declarer = super::declarer();

    assert!(
        declarer(&config::ExportCfg::default()).is_empty(),
        "no configured instance declares no route"
    );

    let cfg = prometheus_cfg();
    let decls = declarer(&cfg);
    assert_eq!(decls.len(), 1);
    assert_eq!(decls[0].owner, "prometheus");
    assert_eq!(decls[0].kind, RouteKind::Export);
    assert_eq!(decls[0].route.path, "/metrics");
    assert_eq!(decls[0].route.method, RouteMethod::Get);
    assert_eq!(
        decls[0].route.auth,
        RouteAuth::Key,
        "the scrape keeps the data-plane bar it has always carried"
    );
}

/// THE SINK'S POLICY REACHES THE WIRE THROUGH THE FACE, unchanged: a process with no registry
/// installed answers a scrape with the sink's refusal, not with an empty success.
#[test]
fn a_scrape_of_a_process_with_no_registry_is_refused_through_the_face() {
    struct NoRegistry;
    impl ProcessSnapshot for NoRegistry {
        fn metrics(&self) -> Option<String> {
            None
        }
    }
    let cfg = prometheus_cfg();
    let decls = super::declarer()(&cfg);
    let resp = decls[0].dispatch.handle_http(
        &HttpEndpointRequest {
            method: "GET".into(),
            path: "/metrics".into(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        },
        &NoRegistry,
    );
    assert_eq!(resp.status, 503);
    assert!(resp.body.is_empty());
    assert_eq!(
        resp.headers,
        vec![("retry-after".to_string(), "1".to_string())]
    );
}

/// THE EXPOSITION'S CONTENT TYPE IS ONE STRING, spelled in two crates that may not name each other.
///
/// The sink owns the response shape, so the header value is ITS constant; the recorder that renders
/// the body lives in the substrate and carries the same string for the same format. A crate of kind
/// `export` may name neither the substrate nor the engine, so the two spellings cannot be made one
/// by construction — the composer, which names both, holds them equal here. Change either and this
/// fails, which is the only place that comparison can be made at all.
#[test]
fn the_sinks_content_type_is_the_recorders_content_type() {
    assert_eq!(
        busbar_export_prometheus::CONTENT_TYPE,
        busbar_substrate::metrics::PROMETHEUS_CONTENT_TYPE,
        "the scrape's content type is pinned by the 1.5.5 golden and is one string, not two"
    );
}
