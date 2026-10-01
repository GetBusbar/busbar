// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAL TABLE IS PUBLISHED AT THE COMMIT, NEVER DURING THE BUILD.
//!
//! A configuration's metadata lists judge its provider URLs twice: when it is validated, and again
//! over every address a provider's name resolves to when the pooled egress client dials it. The
//! second judgement reads the process's dial table, which `InstalledLimits::keep` replaces. An apply
//! that never commits leaves the running lists in force; one that commits is read by the next dial,
//! including a client built before it. A provider's own `allow_metadata_hosts` carves out its host
//! and no other.
//!
//! A test BINARY of its own, because the dial table it publishes is process-wide.

mod linked;

use std::sync::Arc;

use busbar_kernel::egress::engine::{build_client, egress_request, Dns, EngineSpec, ResolveNames};
use busbar_kernel::egress::fixtures::{spawn_http, CannedResponse, RebindingResolver};

fn build(port: u16) -> busbar_kernel::InstalledLimits {
    let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
        busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_DIAL_TABLE_COMMIT"),
    );
    cfg.blocked_metadata_hosts = vec!["127.0.0.1".to_string()];
    let template = cfg.providers.values().next().expect("a provider").clone();
    let mut carved = template.clone();
    carved.base_url = format!("http://carved.localhost:{port}");
    carved.allow_metadata_hosts = vec!["127.0.0.1".to_string()];
    let mut plain = template;
    plain.base_url = format!("http://plain.localhost:{port}");
    cfg.providers.insert("carved".to_string(), carved);
    cfg.providers.insert("plain".to_string(), plain);
    let (_app, _rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
    )
    .expect("the app builds");
    limits
}

/// Dial `host` on a fresh pooled client whose names answer the fixture's loopback address.
async fn dial(names: &Arc<RebindingResolver>, host: &str, port: u16) -> Result<u16, String> {
    let spec = EngineSpec {
        dns: Dns::Custom(Arc::clone(names) as Arc<dyn ResolveNames>),
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    let client = build_client(&spec).expect("builds");
    client
        .request(egress_request(
            format!("http://{host}:{port}/v1/x").parse().expect("uri"),
            http::HeaderMap::new(),
            bytes::Bytes::new(),
        ))
        .await
        .map(|resp| resp.status().as_u16())
        .map_err(|e| busbar_kernel::egress::with_cause(&e))
}

#[tokio::test]
async fn the_dial_table_is_published_at_the_commit_with_its_carve_outs() {
    busbar_kernel::metrics::init();
    linked::install();
    let fixture = spawn_http(CannedResponse::ok("served"), 16);
    let port = fixture.addr.port();
    let names = Arc::new(RebindingResolver::counting(fixture.addr));

    // No configuration committed yet: loopback is admitted, as it is at configuration time.
    assert_eq!(dial(&names, "plain.localhost", port).await, Ok(200));

    // THE PERSIST FAILED: the build's handle falls out of scope unkept, and the lists it carried
    // never reach a dial.
    drop(build(port));
    assert_eq!(
        dial(&names, "plain.localhost", port).await,
        Ok(200),
        "an apply that never committed changed what a dial is judged by"
    );

    // THE APPLY LANDED: the operator's blocked address is refused for every host but the one
    // whose provider carved it out.
    build(port).keep();
    let refused = dial(&names, "plain.localhost", port)
        .await
        .expect_err("the blocked address is refused once the apply commits");
    assert!(refused.contains("127.0.0.1"), "{refused}");
    assert_eq!(
        dial(&names, "carved.localhost", port).await,
        Ok(200),
        "the provider's own carve-out admits its host"
    );
}
