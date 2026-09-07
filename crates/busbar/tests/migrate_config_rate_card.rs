// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.6.0 config is a 1.5.5 config plus the plane sections. `rate_card:` is not one of them.
//!
//! ## Why this is a test and not a review note
//!
//! The rate-card history is a change to what a price MEANS — a card becomes the first entry of a
//! dated, append-only history rather than a live value re-read on every request — and a change of
//! that size is exactly the kind that arrives with a config migration attached. It must not. The
//! operator's `rate_card:` block IS the opening entry; a migrator that rewrote it, re-keyed it,
//! normalised its numbers or moved it under a new section would be silently restating the prices a
//! deployment has been billing at, and the whole point of the history is that a price is never
//! restated without a record of who did it and why.
//!
//! So the upgrade path is: change nothing. The same file that booted the previous release boots this
//! one, and the card it names becomes entry zero of the history, effective from instant zero.
//!
//! ## What is asserted
//!
//! That the migrator hands the `rate_card:` block back unchanged — the same models, in the order
//! written, each with the same classes in the same order at the same configured numbers, still a
//! top-level block of the same shape — and does not report having changed it. Not "an equivalent
//! card": a rate a migrator rounded, reordered or re-spelled is a rate an operator did not write.
//!
//! The one difference a round-trip through the YAML serializer makes is how a float RENDERS —
//! `2.50` comes back as `2.5`. It is the same number through the one decimal-to-integer conversion
//! the cost unit owns, and it is asserted here as a known, bounded difference rather than left to be
//! found later.

use busbar_core::config::migrate::migrate_config;

/// A 1.5.5-shaped config carrying a real, hand-written rate card: two models, all four token
/// classes on one of them, a partial card on the other, awkward numbers that a normaliser would be
/// tempted to tidy, and a flat per-request fee beside it.
const A_1_5_5_CONFIG_WITH_A_CARD: &str = r#"
listen: "127.0.0.1:8080"
admin_listen: "127.0.0.1:8081"
rate_card:
  gpt-4o:
    input_utok: 2.50
    output_utok: 10.00
    cache_read_utok: 1.25
    cache_write_utok: 3.125
  claude-3-5-sonnet:
    input_utok: 3.0
    output_utok: 15.0
per_request_fee: 2
pools:
  op:
    members:
      - model: gpt-4o
"#;

/// The `rate_card:` block, lifted out of a document as the exact lines it occupies.
fn card_block(yaml: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in yaml.lines() {
        if line.starts_with("rate_card:") {
            inside = true;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if inside {
            // The block ends at the next line that starts in column zero and is not a continuation.
            if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!out.is_empty(), "the document names no rate_card: block");
    out
}

/// The card as a document reader sees it: models in the order written, each with its classes in the
/// order written and its configured number.
fn card_of(yaml: &str) -> Vec<(String, Vec<(String, f64)>)> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).expect("the document parses");
    let card = doc
        .get("rate_card")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("the document names a rate_card mapping");
    card.iter()
        .map(|(model, classes)| {
            let classes = classes
                .as_mapping()
                .expect("a model's entry is a mapping of classes")
                .iter()
                .map(|(class, rate)| {
                    (
                        class.as_str().expect("a class name").to_string(),
                        rate.as_f64().expect("a configured rate"),
                    )
                })
                .collect();
            (model.as_str().expect("a model name").to_string(), classes)
        })
        .collect()
}

/// **THE INVARIANT.** `--migrate-config` leaves the card exactly as written: the same models, in the
/// same order, each with the same classes in the same order, at the same configured numbers.
///
/// Every clause is load-bearing. A model dropped or added changes which lanes are priced at all; a
/// class dropped changes a priced quantity into an unpriced one, which reads as a lane the operator
/// gives away for free; and a NUMBER moved is a price restated with nothing on the record saying so,
/// which is precisely what the amend verb exists to make impossible.
#[test]
fn migrate_config_leaves_the_1_5_5_rate_card_untouched() {
    let migrated =
        migrate_config(A_1_5_5_CONFIG_WITH_A_CARD).expect("a 1.5.5 config migrates without error");

    assert_eq!(
        card_of(&migrated.yaml),
        card_of(A_1_5_5_CONFIG_WITH_A_CARD),
        "the operator's card is the opening entry of the history; a migrator that rewrote it would \
         be restating prices a deployment has been billing at, with no record of having done it"
    );
}

/// The card comes back as a `rate_card:` block at the top level, under that name, in one piece.
///
/// The structural check above would still pass if the migrator had moved the card under a new
/// section, or split it, and left something that re-read the same. It must not: a 1.6.0 config is a
/// 1.5.5 config plus the plane sections, and `rate_card:` is not one of them, so the same file an
/// operator is holding boots this release unedited.
#[test]
fn the_card_is_still_a_top_level_rate_card_block() {
    let migrated = migrate_config(A_1_5_5_CONFIG_WITH_A_CARD).expect("migrates");
    let before = card_block(A_1_5_5_CONFIG_WITH_A_CARD);
    let after = card_block(&migrated.yaml);
    assert_eq!(
        after.lines().count(),
        before.lines().count(),
        "same block, same lines — not re-nested, not split, not annotated:\n{after}"
    );
    // The one difference a round-trip through a YAML serializer is allowed to make is how a float
    // RENDERS: `2.50` comes back as `2.5`. That is the same number — it converts to the same integer
    // nano-rate through the one conversion the cost unit owns — and it is asserted as a known,
    // bounded difference here rather than left to be discovered as a surprise.
    for (line_after, line_before) in after.lines().zip(before.lines()) {
        let normalise = |l: &str| l.trim_end_matches('0').trim_end_matches('.').to_string();
        assert_eq!(
            normalise(line_after),
            normalise(line_before),
            "the only permitted difference is trailing zeros on a float"
        );
    }
}

/// And it does not CLAIM to have touched it either. A change line naming the card would tell an
/// operator to go and check a block that did not move, which is how a real change in the same list
/// gets skimmed past.
#[test]
fn the_migrator_reports_no_change_to_the_card() {
    let migrated = migrate_config(A_1_5_5_CONFIG_WITH_A_CARD).expect("migrates");
    let mentions: Vec<&String> = migrated
        .changes
        .iter()
        .chain(migrated.warnings.iter())
        .chain(migrated.todos.iter())
        .filter(|line| line.contains("rate_card"))
        .collect();
    assert!(
        mentions.is_empty(),
        "nothing was done to the card, so nothing is reported about it: {mentions:?}"
    );
}

/// The per-request fee is the card's other half — it is the flat fee the card carries in minor
/// units — and it does not move either.
#[test]
fn the_per_request_fee_is_left_as_written() {
    let migrated = migrate_config(A_1_5_5_CONFIG_WITH_A_CARD).expect("migrates");
    assert!(
        migrated.yaml.contains("per_request_fee: 2"),
        "the fee an operator configured is the fee the opening entry carries:\n{}",
        migrated.yaml
    );
}

/// A config that already carries a card needs NO decision from a human about pricing. A
/// `TODO(migrate)` against the card would mean the upgrade path is "1.5.5 config plus a judgement
/// call", which is not the path this release promises.
#[test]
fn upgrading_a_priced_deployment_asks_the_operator_nothing_about_price() {
    let migrated = migrate_config(A_1_5_5_CONFIG_WITH_A_CARD).expect("migrates");
    assert!(
        !migrated
            .todos
            .iter()
            .any(|t| t.contains("rate_card") || t.contains("per_request_fee")),
        "no pricing decision is owed on upgrade: {:?}",
        migrated.todos
    );
}
