// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAW 7 — CONFIG-GATED LOADING (docs/design/BUSBAR-1.6.0.md: "Core loads a plugin **iff** its
//! configuration section is present … A plugin that loads (or costs anything) without its verb
//! configured is a bug"; Part 0: the new planes are "purely additive and off by default").
//!
//! Items 39/40: every non-LLM plane is LINKED into the default build (Part 2 #17 is locked), so the
//! gate is config, never a feature flag. Before this, `boot::hydrate_all` / `boot::start_planes`
//! folded EVERY linked plane's hooks and `appbuild` asked EVERY linked plane to `build` its slot, so
//! a plane with no config section still restored, started and — given a `public_url:` — mounted and
//! admitted. These drive the core folds over a probe plane that counts every hook it is handed: an
//! unconfigured probe must be handed NOTHING, a configured one everything.

mod linked;

use busbar_kernel::plane::registry::{PlaneDecl, PlaneDeclaration, TestRegistryIsolation};
use std::sync::atomic::{AtomicUsize, Ordering};

static HYDRATED: AtomicUsize = AtomicUsize::new(0);
static STARTED: AtomicUsize = AtomicUsize::new(0);
static BUILT: AtomicUsize = AtomicUsize::new(0);

const PROBE_SECTION: &str = "law7-probe";

/// A linked plane that records every core call. Its section is `law7-probe`; nothing else names it.
static PROBE: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "law7probe",
        fallback: false,
        config_section: PROBE_SECTION,
        scope_kinds: &["law7probe"],
        subject_noun: "probe",
        admin_noun: "probe",
        audit_kind: "law7probe",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        served_op_classes: &[],
    },
    wire_format_names: || &["law7probe"],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| {
        BUILT.fetch_add(1, Ordering::SeqCst);
        Some(std::sync::Arc::new(()))
    },
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: Some(|_| {
        HYDRATED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }),
    start: Some(|_| {
        STARTED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }),
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
};

/// Run hydrate + start over an App whose configured plane sections are exactly `sections`, and
/// return how many times the probe's two boot hooks ran.
fn boot_hooks_run(sections: &[&'static str]) -> (usize, usize) {
    let _iso = TestRegistryIsolation::seeded(&[&PROBE]);
    let (h0, s0) = (
        HYDRATED.load(Ordering::SeqCst),
        STARTED.load(Ordering::SeqCst),
    );
    let app = busbar_kernel::test_support::TestApp::new()
        .plane_sections(sections)
        .build();
    busbar_kernel::boot::hydrate_all(&app).expect("hydrate");
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));
    busbar_kernel::boot::start_planes(&handle).expect("start");
    (
        HYDRATED.load(Ordering::SeqCst) - h0,
        STARTED.load(Ordering::SeqCst) - s0,
    )
}

/// A 1.5.5 config names no plane section: a linked plane restores nothing and starts nothing.
#[test]
fn an_unconfigured_plane_hydrates_and_starts_nothing() {
    assert_eq!(
        boot_hooks_run(&[]),
        (0, 0),
        "a plane whose config section is absent must never have its hydrate/start hooks run (Law 7)"
    );
}

/// Positive control: the same plane with its section configured hydrates and starts exactly once.
#[test]
fn a_configured_plane_still_hydrates_and_starts() {
    assert_eq!(
        boot_hooks_run(&[PROBE_SECTION]),
        (1, 1),
        "a plane whose config section is present must hydrate and start"
    );
}

/// The per-generation build: an unconfigured plane is never asked to build its slot, so it claims,
/// admits and mounts nothing; configured, it builds and its slot is present. The fallback plane is
/// never gated.
#[test]
fn only_a_configured_plane_builds_its_slot() {
    // The test-linked fallback plane, read back from the registry BEFORE the isolation seeds it.
    let fallback = linked::fallback();
    let _iso = TestRegistryIsolation::seeded(&[fallback, &PROBE]);
    let build = |sections: &[&'static str]| {
        let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::none(),
        );
        cfg.plane_sections = sections.iter().copied().collect();
        let b0 = BUILT.load(Ordering::SeqCst);
        let app = busbar_kernel::test_support::build_once(cfg, None).expect("build");
        (
            BUILT.load(Ordering::SeqCst) - b0,
            app.plane_slots.contains_key(PROBE.key),
            app.plane_configured(&PROBE),
            app.plane_configured(fallback),
        )
    };
    assert_eq!(
        build(&[]),
        (0, false, false, true),
        "unconfigured: no build call, no slot; the fallback plane stays configured"
    );
    assert_eq!(
        build(&[PROBE_SECTION]),
        (1, true, true, true),
        "configured: built once, slot present"
    );
}

/// `resolve` derives the configured set from the document itself: a 1.5.5-shaped config (no plane
/// section) configures none; each plane section — and the endpoint door the `tools:` plane declares
/// it owns (read back from its declaration) — configures its own.
#[test]
fn resolve_reads_the_configured_plane_sections_off_the_config() {
    let tools_plane = linked::owning("tools");
    let door = linked::door_section(tools_plane);
    assert_ne!(
        door, tools_plane.config_section,
        "the `tools:` plane declares an endpoint door of its own"
    );
    let sections = |extra: &str| {
        let yaml = format!(
            "providers:\n  acme: {{ api_key: none }}\nmodels:\n  m: {{ provider: acme }}\n{extra}"
        );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("parse");
        let mut defs = std::collections::HashMap::new();
        defs.insert(
            "acme".to_string(),
            serde_yaml::from_str("protocol: anthropic\nbase_url: https://api.example.com\n")
                .expect("provider def"),
        );
        busbar_kernel::config::resolve(&deploy, &defs)
            .expect("resolve")
            .plane_sections
            .into_iter()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        sections("public_url: https://gw.example.com\n"),
        Vec::<&str>::new(),
        "a 1.5.5-shaped config (public_url included) configures no plane"
    );
    assert_eq!(
        sections(
            "tools:\n  t1: { url: \"https://t.example/t\", pin: { mechanism: unpinned } }\n\
             agents:\n  a1: { url: \"https://a.example/a\", pin: { mechanism: unpinned } }\n"
        ),
        vec!["agents", "tools"]
    );
    assert_eq!(
        sections(&format!(
            "{door}:\n  canonical_uri: \"https://gw.example.com/{}\"\n  authorization_servers: [\"https://as.example.com\"]\n",
            tools_plane.key
        )),
        vec![tools_plane.config_section],
        "the `{door}:` door configures the plane that owns it"
    );
}
