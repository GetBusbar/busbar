// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The nested-destination resolution ([`plane_serving`]) and its one-server guard
//! ([`check_served_op_classes`]): a plane names the operation CLASS it needs one level down, and
//! the host answers with the registered plane that declares it serves that class — never a plane
//! the requester named.

use super::*;

/// The class a requesting plane names.
const CLASS: OpClassId = OpClassId::new("summarize");

/// A declaration keyed `key` serving exactly `served`.
fn decl(key: &'static str, served: &'static [ServedOpClass]) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        served_op_classes: served,
    }
}

/// A row serving [`CLASS`] under the display name `Summarizer`.
const SERVES_CLASS: &[ServedOpClass] = &[ServedOpClass {
    op: CLASS,
    name: "Summarizer",
}];

/// A row serving a DIFFERENT class.
const SERVES_OTHER: &[ServedOpClass] = &[ServedOpClass {
    op: OpClassId::new("translate"),
    name: "Translator",
}];

#[test]
fn the_host_answers_with_the_plane_that_declares_the_class_and_its_declared_name() {
    let a = decl("alpha", &[]);
    let b = decl("beta", SERVES_OTHER);
    let c = decl("gamma", SERVES_CLASS);
    assert_eq!(
        plane_serving(CLASS, [&a, &b, &c]),
        Some(("gamma", SERVES_CLASS[0])),
        "the answer is the plane that DECLARES the class, whatever its key or position"
    );
    assert_eq!(
        plane_serving(CLASS, [&c]).map(|(_, s)| s.name),
        Some("Summarizer")
    );
}

/// THE RED ARM: a registered plane that does not declare the class is not the answer, however many
/// planes are registered and whatever else they serve — the requester then refuses.
#[test]
fn a_plane_that_does_not_declare_the_class_serves_no_nested_destination() {
    let a = decl("alpha", &[]);
    let b = decl("beta", SERVES_OTHER);
    assert_eq!(plane_serving(CLASS, [&a, &b]), None);
    assert_eq!(plane_serving(CLASS, []), None, "no registered plane at all");
}

#[test]
fn one_class_has_one_server() {
    let b = decl("beta", SERVES_CLASS);
    let c = decl("gamma", SERVES_CLASS);
    let o = decl("omega", SERVES_OTHER);
    assert_eq!(check_served_op_classes(&[&b, &o]), Ok(()));
    let refused = check_served_op_classes(&[&b, &o, &c]).unwrap_err();
    assert!(
        refused.contains("`gamma`") && refused.contains("`beta`") && refused.contains("summarize"),
        "the refusal names both planes and the class: {refused}"
    );
}

/// ARCHITECT RULING (b): a plane keeps exactly the record kinds it declares — the verdict the
/// administrative `plane_record_write` verb takes before it writes.
#[test]
fn a_plane_declares_the_record_kinds_it_keeps_and_no_other() {
    let keeps = PlaneDeclaration {
        record_kinds: &["task", "task_event"],
        ..decl("keeper", &[])
    };
    assert!(declares_record_kind(&keeps, "task"));
    assert!(declares_record_kind(&keeps, "task_event"));
    assert!(
        !declares_record_kind(&keeps, "call"),
        "another plane's kind"
    );
    assert!(
        !declares_record_kind(&decl("none", &[]), "task"),
        "a plane that keeps none"
    );
}
