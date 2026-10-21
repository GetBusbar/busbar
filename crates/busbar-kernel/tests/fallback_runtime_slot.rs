// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE'S RUNTIME SLOT HOLDS THAT PLANE'S OWN RUNTIME, on every App, whatever table it was lent.
//!
//! The slot under `runtime_slot_key(K)` is plane `K`'s state (BUSBAR-1.6.0.md Part 3 §6: "Plane
//! allocates state … core stores in `plane_slots`"). App composition also keys the FALLBACK plane's
//! runtime, and it once derived that key (`runtime_slot_key(fallback_key())`) and that runtime
//! (`plane_decl_for(fallback_key()).build_runtime`) from separate reads of one process-wide plane
//! list. `fallback_key()` degrades to the first plane's key while no plane declares itself the
//! fallback, and that list grew while a test binary ran, so an App built across the arrival of a
//! fallback plane read "no fallback" for the key and "fallback" for the runtime: the fallback
//! plane's runtime replaced a sibling's own under the sibling's key (merge-group run 37567965022;
//! fixed in #521 by one read of the fallback decl for both).
//!
//! The kernel now holds no such list: each App reads the door table it was lent
//! ([`busbar_kernel::plane_driver::doors::Doors`], status row 82, D2), so the key and the runtime
//! are two reads of ONE table. The probe keeps #521's shape over two neutral planes this file
//! declares — a sibling whose own runtime is installed in its slot, and a fallback plane whose
//! `build_runtime` answers a different object — and its two tables: one with the sibling alone
//! (where the degrading key names the sibling, the window the defect needed) and one with both.
//! 8 threads build 32 Apps each, alternating the two tables, so Apps of either table are built
//! concurrently with Apps of the other. It can fail only when composition keys one plane's runtime
//! under another's, or when an App reads a table it was not lent.

use busbar_kernel::plane_driver::doors::Doors;
use busbar_kernel::plane_driver::row::PlaneDecl;
use busbar_kernel::plane_driver::row::PlaneDeclaration;
use busbar_kernel::plane_host::runtime_slot_key;
use busbar_kernel::test_support::TestApp;
use std::sync::Arc;

/// Threads building Apps, each alternating the two tables.
const BUILDERS: usize = 8;
/// Apps each builder builds.
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
    wire_format_names: |_| &["slotsibling"],
    provider_dialects: |_| &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_, _| None,
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
    door: None,
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
    wire_format_names: |_| &["slotfallback"],
    provider_dialects: |_| &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_, _| None,
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
    door: None,
};

/// An App lent `doors`, with the sibling's own runtime installed in its slot.
fn build(doors: Doors) -> Arc<busbar_kernel::state::App> {
    let mut app = TestApp::new().doors(doors);
    app.install_plane_runtime(runtime_slot_key(SIBLING.key), Arc::new(SiblingRuntime));
    app.build()
}

/// Whether the App's slot under `key` holds a `T`.
fn slot_holds<T: 'static>(app: &busbar_kernel::state::App, key: &str) -> bool {
    app.plane_slot(runtime_slot_key(key))
        .is_some_and(|slot| slot.as_ref().downcast_ref::<T>().is_some())
}

/// What an App built from `doors` must hold: the sibling's own runtime under the sibling's key,
/// always; the fallback plane's runtime under the fallback's OWN key exactly when the table it was
/// lent declares that plane.
fn assert_own_runtimes(app: &busbar_kernel::state::App, doors: Doors) {
    assert_eq!(app.doors, doors, "the App reads the table it was lent");
    assert!(
        slot_holds::<SiblingRuntime>(app, SIBLING.key),
        "the sibling's slot holds the sibling's own runtime, never the fallback's"
    );
    assert_eq!(
        slot_holds::<FallbackRuntime>(app, FALLBACK.key),
        doors.fallback_decl().is_some(),
        "the fallback plane's runtime is under its own key, and only on an App lent that plane"
    );
}

#[test]
fn apps_lent_a_table_with_and_without_a_fallback_plane_keep_each_planes_own_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime for the builders");
    let sibling_only = Doors::for_test(&[&SIBLING]);
    let with_fallback = Doors::for_test(&[&SIBLING, &FALLBACK]);
    // The precondition the defect needed: in the sibling-only table no plane declares itself the
    // fallback, so the degrading key names the sibling.
    assert_eq!(
        sibling_only.fallback_key(),
        SIBLING.key,
        "the sibling-only table has no fallback plane, or the probe has no window"
    );
    assert_eq!(with_fallback.fallback_key(), FALLBACK.key);
    {
        let _entered = rt.enter();
        assert_own_runtimes(&build(sibling_only), sibling_only);
        assert_own_runtimes(&build(with_fallback), with_fallback);
    }
    let builders: Vec<_> = (0..BUILDERS)
        .map(|b| {
            let runtime = rt.handle().clone();
            std::thread::spawn(move || {
                let _entered = runtime.enter();
                for i in 0..BUILDS {
                    let doors = if (b + i) % 2 == 0 {
                        sibling_only
                    } else {
                        with_fallback
                    };
                    assert_own_runtimes(&build(doors), doors);
                }
            })
        })
        .collect();
    for builder in builders {
        builder
            .join()
            .expect("every App, of either table, carries each plane's own runtime");
    }
}
