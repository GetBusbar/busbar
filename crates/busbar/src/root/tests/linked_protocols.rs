//! THE LINKED PLANES' DIALECT FACTS AS THE SHIPPED BUILD LINKS THEM — read off each plane's door
//! (its Statement tail, its `declares` section), never off a plane's Rust values and never named
//! (BUSBAR-1.6.0.md l.4965: kernel and root users go via the plane ABI).
//!
//! What these assertions prove is a property of the composition — what this build links — so the
//! root holds them. The protocol names and media types they are held to are fixture DATA
//! (`fixtures/linked_protocols.json`, ARCHITECT F-T), so this source names no plane. How a plane
//! detects and serves its own dialects is the plane's cell (`busbar-plane-llm`,
//! `declared_dialects_tests`): the kernel and the root hold no protocol set (spec Part 1, Law 5).
//!
//! Compiled only in a build that links every plane (`linked_every_plane`): the fixture is the shipped
//! composition's, and a single-plane build links a different protocol set.

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

// ══ THE SURFACE THAT MUST NOT MOVE ═══════════════════════════════════════════════════════════════

/// The stream media the root relays piece by piece ([`crate::root::linked::stream_media`]) are the
/// contract's event stream and the content types the linked planes' `declares` sections state
/// (ARCHITECT ruling on the stream-media carrier, BUSBAR-1.6.0.md l.246). RED arm: a plane whose
/// `declares` drops its `stream_media` entry has its lengthed event-stream replies sent whole.
#[test]
fn the_linked_stream_media_are_the_declared_event_content_types() {
    assert_eq!(
        crate::root::linked::stream_media(&crate::LINKED, None).expect("every declares reads"),
        strs(&FIXTURE["event_content_types"]),
        "the event-stream content types the linked planes declare"
    );
}

// ══ THE METRIC LABELS ARE DECLARED DATA (ARCHITECT ruling 2026-10-16 item 4) ═════════════════════════

/// The fallback plane every linked door row folds to, as the composition root folds it: the one
/// linked door whose Statement tail flags it the fallback.
fn fallback_door_row() -> &'static busbar_kernel::plane_driver::row::PlaneDecl {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    let mut fallbacks: Vec<_> = crate::LINKED
        .plane_doors
        .iter()
        .map(|door| registration(linked_probe(*door, "fallback-dialects")).expect("binds"))
        .filter(|reg| reg.fallback)
        .collect();
    assert_eq!(fallbacks.len(), 1, "one linked door is the fallback plane");
    busbar_kernel::plane_driver::door::fold(fallbacks.remove(0)).expect("the door folds")
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
        (row.wire_format_names)(row),
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
        (row.provider_dialects)(row),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the provider protocols a config may name, and their order, are 1.5.5's"
    );
}
