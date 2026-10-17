// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE'S RUNTIME SLOT HOLDS THAT PLANE'S OWN RUNTIME, on every App, whenever it was built.
//!
//! The slot under `runtime_slot_key(K)` is plane `K`'s state (BUSBAR-1.6.0.md Part 3 §6: "Plane
//! allocates state … core stores in `plane_slots`"). App composition also keys the FALLBACK plane's
//! runtime, and it once derived that key (`runtime_slot_key(fallback_key())`) and that runtime
//! (`plane_decl_for(fallback_key()).build_runtime`) from separate reads of the plane registry.
//! `fallback_key()` degrades to the first registered plane's key while no plane declares itself the
//! fallback, and a test binary's registry grows while it runs, so an App built across the
//! registration of a fallback plane read "no fallback" for the key and "fallback" for the runtime:
//! the fallback plane's runtime replaced a sibling's own under the sibling's key (merge-group run
//! 37567965022; fixed in #521 by `plane::fallback_decl`, one read for both).
//!
//! #521's regression probe hung on the legacy MCP engine's runtime slot, a crate P3 FLIP-MCP deletes.
//! The fix is the kernel's, so its probe is the kernel's too, over two neutral planes this file
//! declares: a sibling whose own runtime is installed in its slot, and a fallback plane whose
//! `build_runtime` answers a different object. The shape is #521's: one App first (so the sibling is
//! registered BEFORE any fallback plane, the order the defect needed), then 8 threads building 32
//! Apps each while the fallback plane registers mid-stream. It can fail only when composition keys
//! one plane's runtime under another's. It is a race probe: the window exists only in a process
//! where the fallback plane was not registered yet, which this binary guarantees (its one test, and
//! a kernel whose built-in plane list is empty).

use busbar_kernel::plane::registry::{register_test_plane, PlaneDecl, PlaneDeclaration};
use busbar_kernel::plane_host::runtime_slot_key;
use busbar_kernel::test_support::TestApp;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Threads building Apps while the fallback plane registers.
const BUILDERS: usize = 8;
/// Apps each builder builds; the registration lands once the builders are under way.
const BUILDS: usize = 32;

/// The sibling plane's own runtime object.
struct SiblingRuntime;
/// The fallback plane's runtime object, which must never sit under the sibling's key.
struct FallbackRuntime;

/// A plane that is not the fallback; its runtime is installed by the fixture, as a plane's
/// test-kit installs its own.
static SIBLING: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "slotsibling",
        fallback: false,
        config_section: "slot-sibling",
        scope_kinds: &["slotsibling"],
        subject_noun: "sibling",
        admin_noun: "sibling",
        audit_kind: "slotsibling",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    },
    wire_format_names: || &["slotsibling"],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
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

/// The plane that declares itself the fallback; App composition builds its runtime through its
/// `build_runtime`.
static FALLBACK: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "slotfallback",
        fallback: true,
        config_section: "slot-fallback",
        scope_kinds: &["slotfallback"],
        subject_noun: "fallback",
        admin_noun: "fallback",
        audit_kind: "slotfallback",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    },
    wire_format_names: || &["slotfallback"],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
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
    build_runtime: Some(|_, _| Arc::new(FallbackRuntime)),
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
};

/// An App with the sibling's own runtime installed in its slot.
fn build() -> Arc<busbar_kernel::state::App> {
    let mut app = TestApp::new();
    app.install_plane_runtime(runtime_slot_key(SIBLING.key), Arc::new(SiblingRuntime));
    app.build()
}

/// Whether the App's slot under `key` holds a `T`.
fn slot_holds<T: 'static>(app: &busbar_kernel::state::App, key: &str) -> bool {
    app.plane_slot(runtime_slot_key(key))
        .is_some_and(|slot| slot.as_ref().downcast_ref::<T>().is_some())
}

#[test]
fn an_app_built_while_a_fallback_plane_registers_keeps_each_planes_own_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime for the builders");
    register_test_plane(&SIBLING);
    // The precondition the defect needed: no plane declares itself the fallback yet, so the
    // degrading key names the sibling.
    assert_eq!(
        busbar_kernel::plane::fallback_key(),
        SIBLING.key,
        "this binary must start with no fallback plane registered, or the probe has no window"
    );
    {
        let _entered = rt.enter();
        assert!(slot_holds::<SiblingRuntime>(&build(), SIBLING.key));
    }
    let built = Arc::new(AtomicUsize::new(0));
    let builders: Vec<_> = (0..BUILDERS)
        .map(|_| {
            let built = Arc::clone(&built);
            let runtime = rt.handle().clone();
            std::thread::spawn(move || {
                let _entered = runtime.enter();
                for _ in 0..BUILDS {
                    let app = build();
                    assert!(
                        slot_holds::<SiblingRuntime>(&app, SIBLING.key),
                        "the sibling's slot holds the sibling's own runtime, never the fallback's"
                    );
                    built.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    // Register while every builder is mid-stream, at whatever point of a build it happens to be.
    while built.load(Ordering::SeqCst) < BUILDERS {
        std::thread::yield_now();
    }
    register_test_plane(&FALLBACK);
    for builder in builders {
        builder
            .join()
            .expect("every App built across the registration carries each plane's own runtime");
    }
    // Positive control: once registered, the fallback plane's runtime rides under its OWN key.
    let _entered = rt.enter();
    let app = build();
    assert!(slot_holds::<SiblingRuntime>(&app, SIBLING.key));
    assert!(
        slot_holds::<FallbackRuntime>(&app, FALLBACK.key),
        "the fallback plane's runtime is under its own key"
    );
}
