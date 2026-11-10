// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{HeaderMap, StatusCode};

include!(concat!(env!("OUT_DIR"), "/source_scan_needles.rs"));

pub(super) fn rendered(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> String {
    let mut out = format!(
        "{} {}\n",
        status.as_str(),
        status.canonical_reason().unwrap_or_default()
    );
    for (name, value) in headers {
        out.push_str(&format!(
            "{}: {}\n",
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    out.push('\n');
    out.push_str(&String::from_utf8_lossy(body));
    out
}

pub(super) fn source_needles() -> Vec<String> {
    SOURCE_SCAN_NEEDLES
        .iter()
        .flat_map(|json| {
            let needles: Vec<String> =
                serde_json::from_str(json).expect("the source owner's scan needles are strings");
            assert!(
                !needles.is_empty() && needles.iter().all(|needle| !needle.trim().is_empty()),
                "the source owner's scan needles must not be empty"
            );
            needles
        })
        .collect()
}

pub(super) fn source_in(render: &str, needles: &[String]) -> Vec<String> {
    let lower = render.to_ascii_lowercase();
    needles
        .iter()
        .filter(|needle| !needle.is_empty() && lower.contains(&needle.to_ascii_lowercase()))
        .cloned()
        .collect()
}

pub(super) fn assert_clean(
    case: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    needles: &[String],
) {
    let render = rendered(status, headers, body);
    println!("SECRET-SOURCE {case}: {}", render.replace('\n', " | "));
    let found = source_in(&render, needles);
    assert!(
        found.is_empty(),
        "{case}: the caller was handed the secret's source {found:?}:\n{render}"
    );
}

pub(super) fn statement_name(door: busbar_contract::abi::mechanism::door::DoorFn) -> String {
    let row = crate::root::loader::dispatch::LinkedRow::of(door).expect("the door states itself");
    busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name
}

#[test]
fn every_linked_door_plane_is_driven() {
    let driven = super::door_cells_secret_driven();
    for door in crate::LINKED.plane_doors {
        let name = statement_name(*door);
        assert!(
            driven.contains(&name),
            "the linked door plane '{name}' is not driven by the secret-source scan: add its \
             driver to that plane owner's root cells (a failing secret reference on its members, \
             its caller-facing renders scanned)"
        );
    }
}
