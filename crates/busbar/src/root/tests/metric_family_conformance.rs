// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A PLANE'S METRIC FAMILY, BOTH DOORS, ONE SERIES** — the `counter_add` seam (ABI minor 25,
//! ARCHITECT RULING S2-c; #2 rule (2), #30, #65) at the composition root.
//!
//! `busbar-plugin-example-plane` declares, in its `#[repr(C)]` decl, the first-party family
//! `busbar_billing_tap_decode_fail_total{protocol,reason}` — a series the host lists as one a plane
//! may carry. The plane is taken through BOTH doors — LINKED (its `PLANE_DECL`) and DROPPED IN (its
//! signed cdylib, found by the boot scan) — into the row [`plane_rows`] installs, and each row's
//! plane adds to the family through the kernel's own host vtable, under the host's attribution.
//!
//! The scrape is the proof. The host's OWN emitter (the substrate's usage-tap fault counter, the
//! path that series has always taken) writes the golden line first; then each door's add must land
//! on that SAME series — one line, its value stepping 1 → 2 → 3. A seam that rendered a different
//! name, other keys, the keys in another order or a provenance label would open a SECOND line and
//! leave the golden one at 1.
//!
//! RED ARMS, both doors: a family the plane did not declare is refused, and the old seam
//! (`metrics_emit`) cannot carry the series at all. And a plane declaring a `busbar_` family the host
//! does not list is refused at registration: it never gets a row to add through.

use super::tests::{dropped, linked, LINKED_HOT};
use super::*;
use busbar_kernel::plane::registry::TestRegistryIsolation;
use busbar_plugin_loader::HotDeclStr;

/// The carried family the example plane declares.
const FAMILY: &str = "busbar_billing_tap_decode_fail_total";

/// This test's label values — a protocol no other test in the binary faults on.
const PROTOCOL: &str = "metric-family-conformance";

/// THE GOLDEN LINE (without its value): the series as the host's own emitter renders it.
const GOLDEN: &str =
    "busbar_billing_tap_decode_fail_total{protocol=\"metric-family-conformance\",reason=\"decode\"}";

/// The one row `plane_rows` installs for a table holding only the example plane.
fn row(linked_door: bool, dropped_in: Vec<DynPlane>) -> &'static PlaneDecl {
    let hot: &'static [&'static HotPlaneDecl] = if linked_door { &LINKED_HOT } else { &[] };
    let rows = plane_rows(&linked(&[], hot), dropped_in).expect("the example plane is admitted");
    assert_eq!(rows.len(), 1);
    rows[0]
}

/// Add `delta` to `family` with `values` through the kernel's own `counter_add`, the host attributing
/// the call to `row`'s plane — the mint every HOT-lane dispatch rides.
fn add(row: &'static PlaneDecl, family: &str, values: &[&'static str]) -> StatusClass {
    let _registry = TestRegistryIsolation::seeded(&[row]);
    let app = busbar_kernel::test_support::TestApp::new().build();
    let scope = busbar_kernel::plane_host::DispatchScope::new();
    let values: Vec<HotDeclStr> = values.iter().map(|v| HotDeclStr::new(v)).collect();
    busbar_kernel::plane_host::with_borrowed_host_as(row.key, &app, &scope, |host, vt| {
        let add = vt.counter_add.expect("the host wires counter_add");
        add(
            host,
            family.as_ptr(),
            family.len(),
            values.as_ptr(),
            values.len(),
            1,
        )
    })
}

/// Every exposition line of the golden series, values included.
fn golden_lines() -> Vec<String> {
    let scrape = busbar_kernel::metrics::render();
    let lines = scrape.lines().filter(|l| l.starts_with(GOLDEN));
    lines.map(str::to_string).collect()
}

/// THE EXIT TEST: the host's own write, then a linked plane's, then a dropped-in plane's — one
/// series, byte-identical, three adds.
#[test]
fn a_linked_and_a_dropped_in_plane_add_to_the_hosts_own_series_byte_for_byte() {
    let Some(dropped_in) = dropped("counter-add") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    busbar_kernel::metrics::init();
    let _ =
        busbar_substrate_values::handlers::usage_tap_decode_fail_should_warn(PROTOCOL, "decode");
    assert_eq!(
        golden_lines(),
        [format!("{GOLDEN} 1")],
        "the host's own line"
    );

    let linked_row = row(true, Vec::new());
    assert_eq!(
        add(linked_row, FAMILY, &[PROTOCOL, "decode"]),
        StatusClass::Ok
    );
    assert_eq!(
        golden_lines(),
        [format!("{GOLDEN} 2")],
        "after the linked add"
    );

    let dropped_row = row(false, dropped_in);
    assert_eq!(
        add(dropped_row, FAMILY, &[PROTOCOL, "decode"]),
        StatusClass::Ok
    );
    assert_eq!(
        golden_lines(),
        [format!("{GOLDEN} 3")],
        "after the dropped-in add"
    );

    // One family, one TYPE line, still a counter.
    let scrape = busbar_kernel::metrics::render();
    let typed = format!("# TYPE {FAMILY} counter");
    assert_eq!(
        scrape
            .lines()
            .filter(|l| l.starts_with(&format!("# TYPE {FAMILY} ")))
            .count(),
        1
    );
    assert!(scrape.lines().any(|l| l == typed), "{scrape}");
}

/// RED ARM, both doors: a family the plane did not declare is refused — and so is the declared one
/// with a label value missing — and the scrape does not move.
#[test]
fn either_door_is_refused_a_family_its_plane_did_not_declare() {
    let Some(dropped_in) = dropped("counter-add-undeclared") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    busbar_kernel::metrics::init();
    for row in [row(true, Vec::new()), row(false, dropped_in)] {
        assert_eq!(
            add(row, "example_undeclared_total", &[]),
            StatusClass::Refused
        );
        assert_eq!(add(row, FAMILY, &[PROTOCOL]), StatusClass::Refused);
        assert_eq!(
            add(row, "example_dispatches_total", &["red-arm"]),
            StatusClass::Ok
        );
    }
    let scrape = busbar_kernel::metrics::render();
    assert!(!scrape.contains("example_undeclared_total"), "{scrape}");
    assert!(
        scrape
            .lines()
            .any(|l| l == "example_dispatches_total{carrier=\"red-arm\"} 2"),
        "the plane's own declared family adds, both doors, as declared:\n{scrape}"
    );
}

/// RED ARM: a `busbar_` family the host does not list is refused at registration — the plane never
/// gets a row to add through — and so is a listed one re-keyed or re-ordered. The guard runs over
/// every row `plane_rows` installs, whichever door or lane it came in by: here a linked Rust-hook row
/// ahead of the example plane's linked HOT-lane row.
#[test]
fn a_plane_declaring_an_unlisted_first_party_family_is_refused_a_row() {
    for label_keys in [
        &["protocol", "reason"][..],
        &["reason", "protocol"],
        &["protocol"],
    ] {
        for name in ["busbar_minted_total", FAMILY] {
            if name == FAMILY && label_keys == ["protocol", "reason"] {
                continue; // the listed row itself: admitted, see the exit test
            }
            let families: &'static [MetricFamily] = Box::leak(Box::new([MetricFamily {
                name,
                kind: busbar_contract::plane::COUNTER,
                label_keys: label_keys.to_vec().leak(),
            }]));
            let declaration = PlaneDeclaration {
                key: "minting",
                fallback: false,
                config_section: "minting",
                scope_kinds: &[],
                subject_noun: "minting",
                admin_noun: "minting",
                audit_kind: "minting",
                card_signing_domain: None,
                card_kid_prefix: None,
                owned_config_sections: &[],
                billable_classes: &[],
                fee_units: &[],
                metric_families: families,
                served_op_classes: &[],
            };
            let native: &'static [PlaneDecl] = Box::leak(Box::new([PlaneDecl::assemble(
                declaration,
                HOT_PLANE_HOOKS,
            )]));
            let Err(refusal) = plane_rows(&linked(native, &LINKED_HOT), Vec::new()) else {
                panic!("{name} {label_keys:?} was admitted a row");
            };
            assert!(
                refusal.contains("plane `minting`") && refusal.contains("reserved `busbar_`"),
                "{name} {label_keys:?}: {refusal}"
            );
        }
    }
}
