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

/// **AN AMOUNT NOBODY WROTE IS THE FIGURE THE PREVIOUS RELEASE CHARGED.**
///
/// The whole of the compatibility claim in one cell: a deployment with no `tariff:` block is
/// charged its own `per_request_fee:` for a transaction and for a visit, because the amounts
/// INHERIT that figure rather than defaulting to a second number nobody configured.
#[test]
fn an_unset_amount_inherits_the_previous_releases_own_fee() {
    let empty = TariffCfg::default();
    for fee in [0i64, 3, 250] {
        let a = empty.amounts("llm", None, None, fee);
        assert_eq!(
            a.entry_cents, fee,
            "the door inherits the one configured fee"
        );
        assert_eq!(a.transaction_flat_cents, fee);
        assert!(
            a.per_units.is_empty(),
            "nothing prices a dimension but the card"
        );
        assert_eq!(a.minimum_cents, 0);
        assert_eq!(a.maximum_cents, None, "uncapped is not a cap of zero");
        assert_eq!(
            a.rounding,
            super::super::tariff::RoundingCfg::Bankers,
            "the teller's rule, declared"
        );
    }
}

/// **THE AMOUNTS RESOLVE BY THE SAME FOUR SCOPES, FIELD BY FIELD**, and a scope that names one
/// number keeps every other number it had.
///
/// The FOLD is total over all four scopes, and that is what is under test here. What a deployment
/// is allowed to WRITE is narrower today and is refused at boot rather than silently unapplied:
/// amounts live on the node's dated card and a posting records no scope to resolve one by, so an
/// amount outside `default` is a configuration error (`config_validate`'s own cell). The fold is
/// written total anyway, because the day a posting carries its scope the resolver is the thing that
/// must already be right, not the thing that then has to be taught the other three scopes.
#[test]
fn an_amount_set_at_a_scope_moves_that_number_and_no_other() {
    let scoped = crate::plane::plane_keys()
        .next()
        .expect("a registered plane");
    let section = parse(&format!(
        r#"
default:
  transaction_fee: {{ flat_cents: 7 }}
  minimum_cents: 2
plane:
  {scoped}:
    entry_fee: {{ enabled: true, amount_cents: 11 }}
pool:
  pool-a:
    maximum_cents: 40
tier:
  gold:
    rounding: up
"#
    ));
    // the default scope answers what it names and inherits the fee for what it does not
    let d = section.amounts("a-plane-nothing-names", None, None, 250);
    assert_eq!((d.transaction_flat_cents, d.entry_cents), (7, 250));
    assert_eq!((d.minimum_cents, d.maximum_cents), (2, None));

    // the plane scope adds the door's amount and keeps the default's flat and minimum
    let p = section.amounts(scoped, None, None, 250);
    assert_eq!((p.entry_cents, p.transaction_flat_cents), (11, 7));
    assert_eq!(
        p.minimum_cents, 2,
        "an unset field inherits, it does not reset"
    );

    // the pool caps, and changes nothing else
    let pool = section.amounts(scoped, Some("pool-a"), None, 250);
    assert_eq!(pool.maximum_cents, Some(40));
    assert_eq!((pool.entry_cents, pool.transaction_flat_cents), (11, 7));

    // the tier declares the rounding, and changes nothing else
    let t = section.amounts(scoped, Some("pool-a"), Some("gold"), 250);
    assert_eq!(t.rounding, super::super::tariff::RoundingCfg::Up);
    assert_eq!(t.maximum_cents, Some(40));
    assert_eq!((t.entry_cents, t.transaction_flat_cents), (11, 7));
}

/// **PER N UNITS OF A DIMENSION A PLANE DECLARED**, and the tariff names no dimension of its own.
#[test]
fn a_per_unit_rate_is_read_back_as_it_was_written() {
    let section = parse(
        r#"
default:
  transaction_fee:
    flat_cents: 0
    per_units:
      - { dimension: tool_calls, per: 1, cents: 2 }
      - { dimension: bytes, per: 1024, cents: 1 }
"#,
    );
    let a = section.amounts("mcp", None, None, 0);
    let read: Vec<(&str, u64, i64)> = a
        .per_units
        .iter()
        .map(|u| (u.dimension.as_str(), u.per, u.cents))
        .collect();
    assert_eq!(read, vec![("tool_calls", 1, 2), ("bytes", 1024, 1)]);
}

/// **ONE FEE, TWO NUMBERS, AND THE NODE REFUSES.**
///
/// The conflict is reported with BOTH spellings and BOTH figures, at the scope that carries it.
/// A zero `per_request_fee:` is not a second number: it is the key's own serde default, it is
/// indistinguishable from absence in a parsed configuration, and it is the identity of the sum.
#[test]
fn a_fee_named_twice_for_one_scope_is_a_conflict_by_name() {
    let section = parse(
        r#"
default:
  transaction_fee: { flat_cents: 5 }
  entry_fee: { enabled: true, amount_cents: 9 }
"#,
    );
    let none_prices = |_: &str| false;
    assert!(
        section.amount_conflicts(0, &none_prices).is_empty(),
        "a deployment that never wrote the old key may write the new one"
    );
    let clashes = section.amount_conflicts(3, &none_prices);
    let named: Vec<(String, String, i64, i64)> = clashes
        .iter()
        .map(|c| (c.scope.clone(), c.key.clone(), c.new_amount, c.old_amount))
        .collect();
    assert_eq!(
        named,
        vec![
            ("default".into(), "entry_fee.amount_cents".into(), 9, 3),
            ("default".into(), "transaction_fee.flat_cents".into(), 5, 3),
        ]
    );
}

/// A per-unit rate for a dimension the card already prices is the same offence: two prices for one
/// unit of one thing.
#[test]
fn a_per_unit_rate_the_card_already_prices_is_a_conflict() {
    let section = parse(
        r#"
default:
  transaction_fee:
    per_units:
      - { dimension: tokens_in, per: 1, cents: 1 }
      - { dimension: tool_calls, per: 1, cents: 1 }
"#,
    );
    let clashes = section.amount_conflicts(0, &|d| d == "tokens_in");
    assert_eq!(clashes.len(), 1, "{clashes:?}");
    assert_eq!(clashes[0].key, "transaction_fee.per_units[tokens_in]");
    assert!(clashes[0].old_key.contains("rate_card"));
}

/// **A KEY THIS GRAMMAR DOES NOT NAME IS A REFUSAL, NOT A SHRUG.** Every level of it.
#[test]
fn an_unknown_key_is_refused_at_every_level_of_the_section() {
    for fragment in [
        "default:\n  entry_fee: { enabled: true, amount: 5 }\n",
        "default:\n  transaction_fee: { flat: 5 }\n",
        "default:\n  transaction_fee:\n    per_units:\n      - { dimension: bytes, per: 1, cents: 1, currency: USD }\n",
        "default:\n  minimum: 5\n",
        "plane:\n  llm:\n    cap_cents: 5\n",
    ] {
        assert!(
            serde_yaml::from_str::<TariffCfg>(fragment).is_err(),
            "the grammar accepted a key it does not name: {fragment}"
        );
    }
}
