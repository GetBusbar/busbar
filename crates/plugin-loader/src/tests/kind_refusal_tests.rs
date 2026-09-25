// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seventh kind: `transport` is compiled-in only, and a dropped-in `kind: transport` tarball is
//! refused with a reason that says so rather than with a bare "not in this list".

use crate::registry::{kind_refusal_note, supported_abi};
use crate::sign::{validate_structure, HookNeeds, Manifest};

fn manifest(kind: &str) -> Manifest {
    Manifest {
        name: "my-transport".to_string(),
        alias: "my-transport".to_string(),
        kind: kind.to_string(),
        version: "1.0.0".to_string(),
        publisher: "acme".to_string(),
        abi_version: 1,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: HookNeeds::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

#[test]
fn a_dropped_in_transport_is_refused_as_compiled_in_only() {
    assert!(supported_abi("transport").is_empty());
    let err = validate_structure(&manifest("transport"), b"lib", &supported_abi, "")
        .expect_err("a transport is never loaded from the plugins folder");
    assert!(
        err.starts_with("manifest kind 'transport' is not one of"),
        "the refusal keeps its established prefix: {err}"
    );
    assert!(
        err.contains("transports are in-tree only"),
        "the refusal must say WHY a transport cannot be dropped in: {err}"
    );
}

#[test]
fn an_unknown_kind_is_refused_without_the_transport_note() {
    let err = validate_structure(&manifest("gizmo"), b"lib", &supported_abi, "")
        .expect_err("an unknown kind is refused");
    assert!(!err.contains("in-tree only"), "{err}");
    assert_eq!(kind_refusal_note("store"), "");
}
