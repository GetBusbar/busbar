// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REF-PATH (ABI-MIN3-INTERFACE §14): D_REF_PATH bindings and `resolve_refs` (§12.7).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7; re-checked 2026-11-16: the K7 binder is on dev (busbar-kernel plugin_config/binder.rs, unit-tested in plugin_config/tests.rs), but this crate's Harness binds through MemBinder, which stubs set_sugars/set_ref_schemas and ignores ref_paths (src/suites/harness.rs:246-267, registry lane MR !2680), and the arm runs through the --validate and boot path (min3_boot.rs ref_schemas()/sugars_of(), HOST-LAYERING: boot wiring through the MIN-3 Registry); it also needs the real store-sqlite and export-otlp images (plugin repos); covered at kernel level by a_ref_path_reference_resolves_before_open_and_unbinds_to_its_text, an_undeclared_shorthand_at_a_ref_path_refuses and a_plain_string_at_a_ref_path_is_left_and_no_refs_means_no_io, and more_than_max_bindings_is_too_many"]
fn ref_path_bindings() {
    todo!("owner: W1-K7 (C-REF-PATH)")
}

/// Generic registry clauses only: the real store/export images, sugar declaration validation and
/// instance scrub registration remain part of the full case above.
#[test]
fn declared_refs_reach_check_and_open_as_text_and_missing_values_refuse_before_entry() {
    use std::sync::atomic::Ordering;

    use busbar_plugin_loader::instance::OpenError;
    use busbar_plugin_test::{fake_needs::FakeNeeds, suites::harness::Harness};

    let mut needs = FakeNeeds::new();
    needs.secret("/db_path", b"/tmp/x.db");
    needs.secret("/url", b"https://collector.example/v1");
    let h = Harness::admit(fixture::PLUGIN.plugin(), needs).expect("admit ref-path fixture");
    let references = br#"{"db_path":{"env":"DB"},"url":{"env":"U"}}"#;
    let literal = br#"{"db_path":"/tmp/x.db","url":"https://collector.example/v1"}"#;
    for (name, config) in [("references", references.as_slice()), ("literal", literal.as_slice())] {
        h.check(name, config).expect("check sees resolved text");
        drop(h.open_secret(name, config).expect("open sees resolved text"));
    }
    assert_eq!(fixture::CHECKS.load(Ordering::SeqCst), 2);
    assert_eq!(fixture::OPENS.load(Ordering::SeqCst), 2);

    let unresolved = Harness::admit(fixture::PLUGIN.plugin(), FakeNeeds::new())
        .expect("admit without scripted values");
    let check = unresolved.check("missing", references).expect_err("no resolution");
    let open = unresolved.open_secret("missing", references).err().expect("no resolution");
    for error in [check, open] {
        assert!(matches!(error, OpenError::Config { .. }), "{error:?}");
    }
    assert_eq!(fixture::CHECKS.load(Ordering::SeqCst), 2, "no check on unresolved input");
    assert_eq!(fixture::OPENS.load(Ordering::SeqCst), 2, "no open on unresolved input");
}
