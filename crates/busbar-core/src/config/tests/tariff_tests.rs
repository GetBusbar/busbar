// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SCOPES RESOLVE MOST SPECIFIC FIRST, FIELD BY FIELD.**
//!
//! Four scopes, one order — tier, pool, plane, default — and the whole point of the fold is that a
//! deployment which wants one number different for one pool writes that one number and keeps
//! everything else it had. A whole-cell pick would hand that pool a cell of type defaults for every
//! field it did not mention, which is a deployment silently un-configuring itself.
//!
//! Every case below is written as a YAML fragment, because the grammar is the thing under test and
//! a struct literal would skip the half of it an operator actually writes.

use super::super::tariff::{DisputePolicyCfg, TariffCfg};

/// Parse one `tariff:` block from the text an operator would write.
fn parse(yaml: &str) -> TariffCfg {
    serde_yaml::from_str(yaml).expect("the fragment is the grammar under test")
}

/// A node that has configured nothing is charged the previous release's schedule at every scope:
/// no entry fee, and the uniform dispute rule this release ships.
#[test]
fn an_absent_section_answers_the_shipped_cell_for_every_plane() {
    let empty = TariffCfg::default();
    for plane in [
        "llm",
        "mcp",
        "a2a",
        "voice",
        "admin",
        "a-plane-that-does-not-exist",
    ] {
        let cell = empty.cell(plane, None, None);
        assert!(!cell.entry_enabled, "{plane}");
        assert!(!cell.disputed_charges_transaction, "{plane}");
        assert!(cell.disputed_charges_units, "{plane}");
    }
}

/// **EACH SCOPE OVERRIDES THE ONE OUTSIDE IT, AND MOVES ONE NUMBER.**
///
/// The same unit, resolved four times against a section that answers at a different depth each
/// time. Every step changes exactly the field the scope named.
#[test]
fn tier_beats_pool_beats_plane_beats_default() {
    let scoped = crate::plane::plane_keys()
        .next()
        .expect("a registered plane");
    let unscoped = crate::plane::plane_keys()
        .nth(1)
        .expect("a second registered plane, so a miss has somewhere to fall through from");
    let section = parse(&format!(
        r#"
default:
  dispute_policy: entry_plus_units
plane:
  {scoped}:
    dispute_policy: full
pool:
  pool-a:
    dispute_policy: entry_only
tier:
  gold:
    dispute_policy: entry_plus_units
"#
    ));
    // default, reached by a plane no scope names
    let d = section.cell(unscoped, None, None);
    assert_eq!(
        (d.disputed_charges_transaction, d.disputed_charges_units),
        (false, true)
    );
    // the plane scope
    let p = section.cell(scoped, None, None);
    assert_eq!(
        (p.disputed_charges_transaction, p.disputed_charges_units),
        (true, true)
    );
    // the pool scope beats the plane scope
    let q = section.cell(scoped, Some("pool-a"), None);
    assert_eq!(
        (q.disputed_charges_transaction, q.disputed_charges_units),
        (false, false)
    );
    // the tier scope beats the pool scope
    let t = section.cell(scoped, Some("pool-a"), Some("gold"));
    assert_eq!(
        (t.disputed_charges_transaction, t.disputed_charges_units),
        (false, true)
    );
}

/// **AN UNSET FIELD INHERITS; IT DOES NOT RESET.**
///
/// The pool names the door fee and says nothing about disputes. It must keep the plane's dispute
/// rule — the field-wise fold is exactly this, and a whole-cell pick would fail here.
#[test]
fn a_scope_that_names_one_field_keeps_every_other_field_it_inherited() {
    let scoped = crate::plane::plane_keys()
        .next()
        .expect("a registered plane");
    let section = parse(&format!(
        r#"
plane:
  {scoped}:
    dispute_policy: full
pool:
  pool-a:
    entry_fee: {{ enabled: true }}
"#
    ));
    let cell = section.cell(scoped, Some("pool-a"), None);
    assert!(cell.entry_enabled, "the pool's own field");
    assert!(
        cell.disputed_charges_transaction,
        "the plane's field must survive a pool that never mentioned it"
    );
}

/// A scope keyed by a name this unit does not carry is not this unit's scope. Written out because
/// "the map has an entry" and "the entry applies" are two different facts.
#[test]
fn a_scope_keyed_by_another_name_does_not_apply() {
    let section = parse(
        r#"
pool:
  pool-a:
    entry_fee: { enabled: true }
"#,
    );
    let any = crate::plane::plane_keys()
        .next()
        .expect("a registered plane");
    assert!(!section.cell(any, Some("pool-b"), None).entry_enabled);
    assert!(!section.cell(any, None, None).entry_enabled);
    assert!(section.cell(any, Some("pool-a"), None).entry_enabled);
}

/// The three policies are spelled the way the CHANGELOG spells them, and nothing else parses.
#[test]
fn the_policy_names_are_the_three_the_release_documents() {
    for (text, transaction, units) in [
        ("entry_only", false, false),
        ("entry_plus_units", false, true),
        ("full", true, true),
    ] {
        let section = parse(&format!("default: {{ dispute_policy: {text} }}"));
        let cell = section.cell(
            crate::plane::plane_keys()
                .next()
                .expect("a registered plane"),
            None,
            None,
        );
        assert_eq!(
            (
                cell.disputed_charges_transaction,
                cell.disputed_charges_units
            ),
            (transaction, units),
            "{text}"
        );
    }
    assert!(
        serde_yaml::from_str::<TariffCfg>("default: { dispute_policy: the-frame-the-client-saw }")
            .is_err(),
        "a policy nobody defined must not parse as one somebody did"
    );
    assert_eq!(
        DisputePolicyCfg::default(),
        DisputePolicyCfg::EntryPlusUnits
    );
}

/// The section refuses a key it does not know, which is what makes a typo a boot refusal rather
/// than a schedule that silently did nothing.
#[test]
fn an_unknown_key_anywhere_in_the_section_is_refused() {
    for text in [
        "defualt: { dispute_policy: full }",
        "default: { dispute_polciy: full }",
        "default: { entry_fee: { enalbed: true } }",
    ] {
        assert!(
            serde_yaml::from_str::<TariffCfg>(text).is_err(),
            "accepted {text}"
        );
    }
}

/// Every scope a section names, with the map it was named in — what validation checks against the
/// pools, the groups and the planes this build registers.
#[test]
fn every_named_scope_is_reported_for_validation() {
    let scoped = crate::plane::plane_keys()
        .next()
        .expect("a registered plane");
    let section = parse(&format!(
        r#"
plane: {{ {scoped}: {{}} }}
pool:  {{ pool-a: {{}}, pool-b: {{}} }}
tier:  {{ gold: {{}} }}
"#
    ));
    let mut named = section.named_scopes();
    named.sort_unstable();
    assert_eq!(
        named,
        vec![
            ("plane", scoped),
            ("pool", "pool-a"),
            ("pool", "pool-b"),
            ("tier", "gold"),
        ]
    );
}
