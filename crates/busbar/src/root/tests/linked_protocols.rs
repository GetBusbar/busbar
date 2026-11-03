use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;
use serde_json::Value;
use std::sync::LazyLock;

static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/linked_protocols.json"))
        .expect("the linked-protocols fixture is JSON")
});

include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));

fn linked_decls() -> Vec<&'static ProtocolDecl> {
    TEST_LINKED_PROTOCOLS
        .iter()
        .flat_map(|decls| decls.iter().copied())
        .collect()
}

fn provider_protocols() -> &'static [&'static str] {
    let row = fallback_door_row();
    (row.provider_dialects)(row)
}

fn declared_verbs() -> Vec<OpVerb> {
    linked_decls()
        .into_iter()
        .flat_map(|decl| decl.verbs.iter().copied())
        .collect()
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

#[test]
fn the_absorbed_sweeps_produce_the_sets_they_produced_before() {
    let declarations = linked_decls();
    let mut event_content_types: Vec<_> = declarations
        .iter()
        .filter_map(|decl| decl.streaming_content_type)
        .collect();
    event_content_types.sort_unstable();
    event_content_types.dedup();
    assert_eq!(
        event_content_types,
        strs(&FIXTURE["event_content_types"]),
        "the absorbed event-stream content types"
    );
    let mut array_stream_shim_keys: Vec<_> = declarations
        .iter()
        .filter_map(|decl| decl.array_stream_shim_key)
        .collect();
    array_stream_shim_keys.sort_unstable();
    array_stream_shim_keys.dedup();
    assert_eq!(
        array_stream_shim_keys,
        strs(&FIXTURE["array_stream_shim_keys"]),
        "absorbed proto::array_stream_shim_keys()"
    );
    let mut head_keys: Vec<_> = ["model", "stream", "stream_options", "system"]
        .into_iter()
        .chain(array_stream_shim_keys.iter().copied())
        .chain(
            declarations
                .iter()
                .flat_map(|decl| decl.head_keys.iter().copied()),
        )
        .collect();
    head_keys.sort_unstable();
    head_keys.dedup();
    assert_eq!(
        head_keys,
        strs(&FIXTURE["head_keys"]),
        "the four core keys plus every declared shim key, sorted and deduped"
    );
}

#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    for decl in linked_decls() {
        let handler = decl
            .handler
            .unwrap_or_else(|| panic!("{} declares no handler", decl.name));
        let mut candidates: Vec<OpVerb> = OpVerb::ALL
            .iter()
            .chain(declared_verbs().iter())
            .copied()
            .collect();
        candidates.sort_unstable_by_key(|op| op.name());
        candidates.dedup_by_key(|op| op.name());
        let mut served: Vec<&'static str> = candidates
            .iter()
            .filter(|op| handler.operation_handler(**op).is_some())
            .map(|op| op.name())
            .collect();
        let mut declared: Vec<&'static str> = decl.verbs.iter().map(|v| v.name()).collect();
        declared.sort_unstable();
        served.sort_unstable();
        assert_eq!(
            declared, served,
            "{}'s declaration and its handler disagree about which verbs it serves",
            decl.name
        );
        assert_eq!(
            handler.protocol_name(),
            decl.name,
            "a handler filed under a name it does not answer to is a registry key that means nothing"
        );
    }
}

#[test]
fn every_declared_verb_has_a_serving_handler() {
    assert!(
        !declared_verbs().is_empty(),
        "the registry must declare at least the linked planes' verbs"
    );
    for decl in linked_decls() {
        let Some(handler) = decl.handler else {
            continue;
        };
        for verb in decl.verbs {
            assert!(
                handler.operation_handler(*verb).is_some(),
                "{} declares verb '{}' but its handler serves no cell for it",
                decl.name,
                verb.name(),
            );
        }
    }
}

#[test]
fn a_declaration_without_a_codec_dispatches_but_is_not_a_provider_protocol() {
    assert!(
        !provider_protocols().is_empty(),
        "the exclusion below is asserted against a NON-EMPTY codec fold"
    );
    let codec_less: Vec<&'static ProtocolDecl> = linked_decls()
        .into_iter()
        .filter(|d| d.codec.is_none())
        .collect();
    for decl in codec_less {
        let d = linked_decls()
            .into_iter()
            .find(|row| row.name == decl.name)
            .expect("it declares itself");
        assert!(d.codec.is_none());
        assert!(d.handler.is_some(), "{} serves operations", d.name);
        assert!(
            !provider_protocols().contains(&d.name),
            "a provider lane cannot name {}, which has no wire codec",
            d.name
        );
    }
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
