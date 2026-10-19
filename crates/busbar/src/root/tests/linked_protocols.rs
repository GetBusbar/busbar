// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FALLBACK PLANE'S DECLARED DIALECTS AS THE SHIPPED BUILD LINKS IT — the metric labels and the
//! provider protocols the composition reads off the fallback door's Statement, held to fixture DATA
//! (`fixtures/linked_protocols.json`, ARCHITECT F-T), so this source names no plane.
//!
//! The protocol-declaration registry these tests also covered is gone: the kernel holds no dialect
//! and the root links no `protocols` axis (Q128 contract p11 finding 1); a dialect's detection,
//! verbs and codec are its plane's suite.
//!
//! Compiled only in a build that links every plane (`linked_every_plane`): the fixture is the shipped
//! composition's, and a single-plane build links a different set.

use serde_json::Value;
use std::sync::LazyLock;

/// The fixture the assertions below are held to.
static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/linked_protocols.json"))
        .expect("the linked-protocols fixture is JSON")
});

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string"))
        .collect()
}

// ══ THE METRIC LABELS ARE DECLARED DATA (ARCHITECT ruling 2026-10-16 item 4) ═════════════════════════

/// The fallback plane every linked door row folds to, as the composition root folds it: the one
/// linked door whose Statement tail flags it the fallback.
fn fallback_door_row() -> &'static busbar_kernel::plane::registry::PlaneDecl {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    let mut fallbacks: Vec<_> = crate::LINKED
        .plane_doors
        .iter()
        .map(|door| registration(linked_probe(*door, "fallback-dialects")).expect("binds"))
        .filter(|reg| reg.fallback)
        .collect();
    assert_eq!(fallbacks.len(), 1, "one linked door is the fallback plane");
    busbar_kernel::plane::door::fold(fallbacks.remove(0)).expect("the door folds")
}

/// **THE `/metrics` LABEL VOCABULARY IS UNCHANGED FROM 1.5.5.** The kernel banks
/// `busbar_requests_total{ingress_protocol,..}`, `busbar_request_duration_seconds{ingress_protocol,..}`
/// and `busbar_translations_total{from,to}` over the fallback plane's DECLARED dialects (its door's
/// Statement tail, read through its registry row), never a codec list; telemetry indexes the families
/// by position, so the order is load-bearing too. Held to the 1.5.5 list (the fixture's
/// `protocol_order`, the published binary's). RED arm: a fallback door that declared a different
/// list, or one in another order, renames or renumbers every banked series.
#[test]
fn the_fallback_doors_declared_dialects_are_the_1_5_5_metric_labels() {
    let row = fallback_door_row();
    assert_eq!(
        (row.wire_format_names)(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the banked ingress_protocol / from / to labels, and their order, are 1.5.5's"
    );
}

/// **THE PROVIDER PROTOCOLS ARE DECLARED DATA, AND 1.5.5'S** (ARCHITECT ruling 2026-10-16 item 3). The
/// boot accepts a provider whose `protocol` a registered plane declares provider-capable (its
/// door's `dialect_auth` lines flagged `DIALECT_PROVIDER`), and the validator's `must be one of:`
/// tail and the lane build's `(supported: …)` list are that declaration, in order. Held to the 1.5.5
/// list (the fixture's `protocol_order`); `tests/cli_validate.rs` holds the binary's refusal bytes.
/// RED arm: a fallback door that flagged no dialect refuses every provider, and one that flagged
/// them in another order reorders the operator's refusal.
#[test]
fn the_fallback_doors_provider_dialects_are_the_1_5_5_provider_protocols() {
    let row = fallback_door_row();
    assert_eq!(
        (row.provider_dialects)(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the provider protocols a config may name, and their order, are 1.5.5's"
    );
}
