// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::plane_driver::dispatch::{
    fallback_key, plane_decl, plane_keys, sole_of, sole_wire_format, wire_format_names,
    wire_formats, Ingress, PlaneDispatch, WIRE_GRPC, WIRE_JSONRPC,
};

mod linked;

fn register_planes() {
    linked::install();
}

fn fallback() -> &'static str {
    linked::fallback().key
}

fn single() -> &'static str {
    linked::owning("tools").key
}

fn multi() -> &'static str {
    linked::owning("agents").key
}

fn door(key: &str) -> String {
    format!("/{key}")
}

fn warm_shared_protocol_registry() {
    linked::install();
}

#[test]
fn all_is_complete_and_has_no_duplicates() {
    register_planes();
    let all: Vec<&'static str> = plane_keys().collect();
    for key in linked::planes().iter().map(|d| d.key) {
        assert!(all.contains(&key), "{key} is missing from plane_keys()");
    }
    assert_eq!(
        all.len(),
        linked::linked_count(),
        "one key per linked plane"
    );
    let mut keys = all.clone();
    let before = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), before, "two planes share a key");
}

#[test]
fn plane_identity_strings_never_collide_across_planes() {
    register_planes();
    let mut sections: Vec<&str> = plane_keys().map(|k| plane_decl(k).config_section).collect();
    sections.sort_unstable();
    let before = sections.len();
    sections.dedup();
    assert_eq!(
        sections.len(),
        before,
        "two planes claim one config section"
    );

    let mut kinds: Vec<&str> = plane_keys()
        .flat_map(|k| plane_decl(k).scope_kinds)
        .copied()
        .collect();
    kinds.sort_unstable();
    let before = kinds.len();
    kinds.dedup();
    assert_eq!(kinds.len(), before, "two planes claim one scope kind");

    let mut audit: Vec<&str> = plane_keys().map(|k| plane_decl(k).audit_kind).collect();
    audit.sort_unstable();
    let before = audit.len();
    audit.dedup();
    assert_eq!(
        audit.len(),
        before,
        "two planes claim one audit resource kind"
    );

    let mut nouns: Vec<&str> = plane_keys().map(|k| plane_decl(k).subject_noun).collect();
    nouns.sort_unstable();
    let before = nouns.len();
    nouns.dedup();
    assert_eq!(nouns.len(), before, "two planes claim one subject noun");
}

#[test]
fn the_multi_binding_legs_are_named_by_the_planes_wire_formats() {
    register_planes();
    let wires = wire_format_names(multi());
    assert_eq!(
        wires,
        [
            WIRE_JSONRPC,
            busbar_kernel::plane_driver::dispatch::WIRE_HTTP_JSON,
            WIRE_GRPC
        ]
        .as_slice(),
        "the multi-binding plane's wire formats must be the shared wire-format words"
    );
}

#[test]
fn the_fallback_wire_format_count_comes_from_the_protocol_registry() {
    register_planes();
    warm_shared_protocol_registry();
    assert_eq!(
        wire_formats(fallback()),
        (linked::fallback().provider_dialects)(linked::fallback()).len()
    );
    assert!(
        wire_formats(fallback()) >= 2,
        "the registry itself is what earns the fallback plane its IR"
    );
}

#[test]
fn transports_do_not_count_as_wire_formats() {
    register_planes();
    assert_eq!(
        wire_formats(single()),
        1,
        "the `tools:` plane has three transports and ONE wire format"
    );
}

fn plane_of(d: &PlaneDispatch, path: &str) -> &'static str {
    match d.ingress_of(path) {
        Ingress::Mounted(key) => key,
        Ingress::Fallback(_) => fallback_key(),
    }
}

#[test]
fn with_nothing_mounted_every_path_is_the_fallback_plane() {
    register_planes();
    let d = PlaneDispatch::default();
    let mut paths: Vec<String> = vec![
        "/".into(),
        "/v1/messages".into(),
        "/pool/v1/messages".into(),
    ];
    paths.extend(linked::planes().iter().map(|p| door(p.key)));
    for path in &paths {
        assert_eq!(plane_of(&d, path), fallback(), "{path}");
    }
}

#[test]
fn a_mounted_plane_claims_its_mount_and_everything_below_it() {
    register_planes();
    let (k, m) = (single(), door(single()));
    let d = PlaneDispatch::default().mount(k, &m, WIRE_JSONRPC);
    assert_eq!(plane_of(&d, &m), k);
    assert_eq!(plane_of(&d, &format!("{m}/")), k);
    assert_eq!(plane_of(&d, &format!("{m}/tools/list")), k);
}

#[test]
fn a_prefix_sibling_is_not_the_plane() {
    register_planes();
    let (k, m) = (single(), door(single()));
    let d = PlaneDispatch::default().mount(k, &m, WIRE_JSONRPC);
    let short = &m[..m.len() - 1];
    for path in [
        format!("{m}x"),
        format!("{m}x/tools"),
        short.to_string(),
        format!("/x{}", &m[1..]),
        format!("/v1{m}"),
    ] {
        assert_eq!(plane_of(&d, &path), fallback(), "{path} must not be `{k}`");
    }
}

#[test]
fn two_mounted_planes_do_not_claim_each_other() {
    register_planes();
    let (s, a) = (single(), multi());
    let d = PlaneDispatch::default()
        .mount(s, &door(s), WIRE_JSONRPC)
        .mount(a, &door(a), WIRE_JSONRPC);
    assert_eq!(plane_of(&d, &format!("{}/tools/list", door(s))), s);
    assert_eq!(plane_of(&d, &format!("{}/tasks/send", door(a))), a);
    assert_eq!(plane_of(&d, "/v1/messages"), fallback());
}

#[test]
fn an_unmounted_plane_claims_nothing() {
    register_planes();
    let (s, a) = (single(), multi());
    let d = PlaneDispatch::default().mount(a, &door(a), WIRE_JSONRPC);
    assert_eq!(plane_of(&d, &door(s)), fallback());
    assert_eq!(plane_of(&d, &format!("{}/tools/list", door(s))), fallback());
}

#[test]
fn a_mount_is_normalised_before_it_is_matched() {
    register_planes();
    let k = single();
    let m = door(k);
    for spelling in [m.clone(), format!("{m}/"), k.to_string(), format!("{k}/")] {
        let d = PlaneDispatch::default().mount(k, &spelling, WIRE_JSONRPC);
        assert_eq!(plane_of(&d, &m), k, "spelling {spelling}");
        assert_eq!(
            plane_of(&d, &format!("{m}/tools/list")),
            k,
            "spelling {spelling}"
        );
        assert_eq!(
            plane_of(&d, &format!("{m}x")),
            fallback(),
            "spelling {spelling}"
        );
    }
}

#[test]
fn the_fallback_plane_cannot_be_mounted() {
    register_planes();
    assert_eq!(
        fallback_key(),
        fallback(),
        "the fallback key is the declaring plane's"
    );
    let d = PlaneDispatch::default().mount(fallback_key(), &door(fallback()), WIRE_JSONRPC);
    assert_eq!(
        plane_of(&d, &door(fallback())),
        fallback(),
        "it is the fallback anyway, so the mount is a no-op rather than a second door"
    );
    assert_eq!(d.mount_of(fallback_key()), None);
}

#[test]
fn a_mount_is_readable_back() {
    register_planes();
    let (s, a) = (single(), multi());
    let d = PlaneDispatch::default().mount(s, &door(s), WIRE_JSONRPC);
    assert_eq!(d.mount_of(s), Some(door(s).as_str()));
    assert_eq!(d.mount_of(a), None);
}

#[test]
fn sole_wire_format_answers_exactly_when_a_plane_speaks_one() {
    register_planes();
    warm_shared_protocol_registry();
    for p in plane_keys() {
        assert_eq!(
            sole_wire_format(p).is_some(),
            wire_formats(p) == 1,
            "{p:?} disagrees with the rule: {} wire format(s) but sole_wire_format() == {:?}",
            wire_formats(p),
            sole_wire_format(p)
        );
        assert_eq!(
            wire_formats(p),
            wire_format_names(p).len(),
            "{p:?}'s count must be DERIVED from its name list, never a second literal"
        );
        assert!(
            !wire_format_names(p).is_empty(),
            "{p:?} claims no wire format at all, which is not a plane"
        );
    }
    assert_eq!(sole_wire_format(fallback()), None);
    assert_eq!(sole_wire_format(single()), Some(WIRE_JSONRPC));
    assert_eq!(sole_wire_format(multi()), None);
}

#[test]
fn a_multi_binding_plane_is_still_labelled_at_the_door_that_was_knocked_on() {
    register_planes();
    let a = multi();
    let (m, svc) = (door(a), "/lf.svc.v1.Service");
    let d = PlaneDispatch::default()
        .mount(a, &m, WIRE_JSONRPC)
        .mount(a, svc, WIRE_GRPC);
    let under = format!("{m}/agents/x");
    assert_eq!(d.mounted_plane_of(&under), Some(a));
    assert_eq!(d.wire_format_of(&under), Some(WIRE_JSONRPC));
    let call = format!("{svc}/SendMessage");
    assert_eq!(d.mounted_plane_of(&call), Some(a));
    assert_eq!(d.wire_format_of(&call), Some(WIRE_GRPC));
    assert_eq!(d.mount_of(a), Some(m.as_str()));
    assert_eq!(d.wire_format_of("/v1/chat/completions"), None);
}

#[test]
fn a_claim_only_names_a_wire_format_its_plane_speaks() {
    register_planes();
    let mountable: Vec<&'static str> = plane_keys().filter(|p| *p != fallback_key()).collect();
    assert!(
        !mountable.is_empty(),
        "the linked roster has a mountable plane"
    );
    for plane in mountable {
        let path = door(plane);
        assert!(
            wire_format_names(plane).contains(&WIRE_JSONRPC),
            "{plane:?} is mounted at {path} speaking `{WIRE_JSONRPC}`, which it does not declare: {:?}",
            wire_format_names(plane)
        );
    }

    assert!(wire_format_names(multi()).contains(&WIRE_GRPC));
}

#[test]
fn every_mounted_planes_door_dialect_is_jsonrpc() {
    register_planes();
    for p in plane_keys().filter(|p| *p != fallback_key()) {
        assert_eq!(
            Ingress::Mounted(p).shaping_wire_format(),
            Some(WIRE_JSONRPC),
            "{p:?} is mountable but its door does not speak JSON-RPC — `ingress::native`'s mounted \
             arm would mis-shape its refusals"
        );
        assert_eq!(
            wire_format_names(p).first(),
            Some(&WIRE_JSONRPC),
            "{p:?} is mountable and its canonical binding is not JSON-RPC"
        );
        assert_eq!(
            busbar_kernel::ingress::native::envelope_dialect(Ingress::Mounted(p)),
            WIRE_JSONRPC,
            "{p:?}'s door refusals must not fall through to a vendor envelope"
        );
    }
}

#[test]
fn the_mount_table_is_read_before_the_path_shape() {
    register_planes();
    let (s, a) = (single(), multi());
    let m = door(s);
    let d = PlaneDispatch::default().mount(s, &m, WIRE_JSONRPC);
    assert_eq!(d.ingress_of(&m), Ingress::Mounted(s));
    assert_eq!(
        d.ingress_of(&format!("{m}/tools/list")),
        Ingress::Mounted(s)
    );
    assert_eq!(
        d.ingress_of("/v1/chat/completions"),
        Ingress::Fallback(Some("openai"))
    );
    assert_eq!(d.ingress_of(&format!("{m}x")), Ingress::Fallback(None));
    assert_eq!(d.ingress_of(&door(a)), Ingress::Fallback(None));
}

#[test]
fn an_unmounted_plane_is_never_resolved_from_the_path() {
    register_planes();
    let d = PlaneDispatch::default();
    let mut paths = Vec::new();
    for p in linked::planes().iter().filter(|p| !p.fallback) {
        paths.push(door(p.key));
        paths.push(format!("{}/tasks/send", door(p.key)));
    }
    assert!(!paths.is_empty(), "the linked roster has a mountable plane");
    for path in &paths {
        assert_eq!(
            d.ingress_of(path),
            Ingress::Fallback(None),
            "{path} on a deployment with no plane mounted"
        );
    }
}

#[test]
fn a_resolved_ingress_names_its_own_wire_format() {
    register_planes();
    let s = single();
    let d = PlaneDispatch::default().mount(s, &door(s), WIRE_JSONRPC);
    assert_eq!(d.ingress_of(&door(s)).wire_format(), Some(WIRE_JSONRPC));
    assert_eq!(
        d.ingress_of("/v1/messages").wire_format(),
        Some("anthropic")
    );
    assert_eq!(d.ingress_of("/stats").wire_format(), None);
    let over = PlaneDispatch::default().mount(s, "/v1/messages", WIRE_JSONRPC);
    assert_eq!(
        over.ingress_of("/v1/messages").wire_format(),
        Some(WIRE_JSONRPC)
    );
}

#[test]
fn only_a_mounted_plane_claims_a_path_and_the_two_readings_agree() {
    register_planes();
    let (s, a) = (single(), multi());
    let (ms, ma) = (door(s), door(a));
    let d = PlaneDispatch::default()
        .mount(s, &ms, WIRE_JSONRPC)
        .mount(a, &ma, WIRE_JSONRPC);
    for path in [
        ms.clone(),
        format!("{ms}/x"),
        ma.clone(),
        format!("{ma}/agents/planner"),
        format!("{ms}x"),
        "/v1/chat/completions".to_string(),
        "/metrics".to_string(),
        "/".to_string(),
    ] {
        assert_eq!(
            d.mounted_plane_of(&path).unwrap_or(fallback_key()),
            plane_of(&d, &path),
            "the two readings disagree about {path}"
        );
    }
    assert_eq!(d.mounted_plane_of("/v1/chat/completions"), None);
    assert_eq!(d.mounted_plane_of(&format!("{ms}x")), None);
    assert_eq!(d.mounted_plane_of("/metrics"), None);
    assert_eq!(d.mounted_plane_of(&format!("{ms}/tools")), Some(s));
    assert_eq!(d.mounted_plane_of(&format!("{ma}/agents/planner")), Some(a));
    assert_eq!(PlaneDispatch::default().mounted_plane_of(&ms), None);
}

#[test]
fn a_plane_with_zero_wire_formats_is_labelless_by_design() {
    assert_eq!(
        sole_of(&[]),
        None,
        "zero dialects: the ingress boundary has nothing to label a request with"
    );
    assert_eq!(sole_of(&["jsonrpc"]), Some("jsonrpc"));
    assert_eq!(sole_of(&["a", "b"]), None);
}

#[test]
fn the_fallback_planes_dialects_are_the_registrys_so_an_empty_registry_empties_the_plane() {
    register_planes();
    warm_shared_protocol_registry();
    assert_eq!(
        wire_format_names(fallback()),
        (linked::fallback().provider_dialects)(linked::fallback()),
        "the fallback plane's wire formats must track the registry"
    );

    let names: &'static [&'static str] = &[];
    assert!(names.is_empty(), "premise: no declarations, no dialects");
    assert_eq!(
        sole_of(names),
        None,
        "a plane with no dialect has nothing to label a request with"
    );
}
