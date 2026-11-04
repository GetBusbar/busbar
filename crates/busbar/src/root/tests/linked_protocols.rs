use serde_json::Value;
use std::sync::LazyLock;

static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/linked_protocols.json"))
        .expect("the linked-protocols fixture is JSON")
});

include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));

fn provider_protocols() -> &'static [&'static str] {
    let row = fallback_door_row();
    (row.provider_dialects)(row)
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string"))
        .collect()
}

#[test]
fn the_derived_protocol_list_is_byte_identical_to_the_const_it_replaced() {
    assert_eq!(
        provider_protocols(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the protocol name set AND ITS ORDER are operator-visible: the order indexes telemetry's \
         metric families and the set is what the config validator accepts"
    );
}

#[test]
fn the_derived_protocol_list_is_not_empty() {
    assert!(
        !provider_protocols().is_empty(),
        "the codec-protocol list is derived from the declarations; an empty one means the built-in \
         table stopped being read, and every operator config would be refused with no cause named"
    );
}

fn fallback_door_row() -> &'static busbar_kernel::plane_driver::registry::PlaneDecl {
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

#[test]
fn the_fallback_doors_declared_dialects_are_the_1_5_5_metric_labels() {
    let row = fallback_door_row();
    assert_eq!(
        (row.wire_format_names)(row),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the banked ingress_protocol / from / to labels, and their order, are 1.5.5's"
    );
}

#[test]
fn the_fallback_doors_provider_dialects_are_the_1_5_5_provider_protocols() {
    let row = fallback_door_row();
    assert_eq!(
        (row.provider_dialects)(row),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the provider protocols a config may name, and their order, are 1.5.5's"
    );
}
