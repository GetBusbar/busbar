// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST RECIPE, as published contract rather than as an implementation detail.

/// The recipe's version name. Goes in every published body so a verifier never has to guess which

pub const DIGEST_RECIPE: &str = "busbar.audit.digest.v4";

/// The name of the recipe `v2`: `v3` plus `currency`, so `v4` less `incarnation` and `node`, plus

pub const DIGEST_RECIPE_V2: &str = "busbar.audit.digest.v2";

/// WHICH RECIPE A RECORD WAS SEALED UNDER — and so the rules it verifies by.
///
/// A record carries this rather than the chain, because a chain that crossed a recipe change holds
/// records of both, and each verifies only by its own rules. It is not itself digested and does not
/// need to be: moving a record between the arms changes the field list (a `v2` record relabelled
/// `v4` loses `currency` and gains `incarnation` and `node`), so the relabelled record no longer
/// hashes to its sealed digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipe {
    /// `busbar.audit.digest.v2`, which digested a `currency` text between `fee_count` and
    /// `rate_card_version`. The text is kept HERE, as the preimage byte the record was sealed
    /// over, and nowhere else: no price reads it and no new record carries it.
    V2 {
        /// The text the `v2` preimage framed in the `currency` position.
        currency: String,
    },
    /// `busbar.audit.digest.v4`: every record this build seals.
    V4,
}

impl Recipe {
    /// The published name of this recipe.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Recipe::V2 { .. } => DIGEST_RECIPE_V2,
            Recipe::V4 => DIGEST_RECIPE,
        }
    }
}

/// One value as the digest consumes it.
///
/// Two arms, because the framing has two: text is length-prefixed bytes, and a number is its
/// big-endian eight-byte form. The distinction is not cosmetic — `d.num(7)` and `d.text("7")`
/// produce different bytes, so a verifier that guessed wrong gets a different digest and reports a
/// good chain as tampered.
///
/// The range read publishes BOTH arms as JSON strings: a number goes out as its canonical decimal
/// text, because a `u64` above 2^53 does not survive a JSON reader that maps numbers to doubles. So
/// the JSON type does not carry the arm; the published recipe page's kind column does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestValue {
    /// A length-prefixed run of bytes.
    Text(String),
    /// An unsigned 64-bit integer, big-endian. Published as its decimal text.
    Num(u64),
}

/// One field of the recipe: the name a published body carries it under, and the value.
///
/// The name is part of the contract too. A verifier reading the range read gets the fields by name,
/// in this order, and does not have to know how this crate's types are shaped — which is the whole
/// point of publishing values already reduced to what the digest eats. A third party should not
/// have to reimplement `outcome_tag` to check a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestField {
    /// The published member name.
    pub name: &'static str,
    /// The value, in the form the digest takes it.
    pub value: DigestValue,
}

impl DigestField {
    fn text(name: &'static str, value: impl Into<String>) -> Self {
        DigestField {
            name,
            value: DigestValue::Text(value.into()),
        }
    }

    fn num(name: &'static str, value: u64) -> Self {
        DigestField {
            name,
            value: DigestValue::Num(value),
        }
    }
}

/// EVERY FIELD THAT GOES INTO ONE RECORD'S DIGEST, IN ORDER.

#[must_use]
pub fn digest_fields(record: &crate::record::AuditRecord) -> Vec<DigestField> {
    use crate::record::{finish_tag, outcome_tag, quantity_source_tag, subject_tag, subject_value};

    let mut f = Vec::with_capacity(48);
    f.push(DigestField::text("prev_hash", record.prev_hash.clone()));
    f.push(DigestField::num("seq", record.seq));
    f.push(DigestField::text(
        "subject_tag",
        subject_tag(&record.subject),
    ));
    f.push(DigestField::text(
        "subject_value",
        subject_value(&record.subject),
    ));
    f.push(DigestField::num("unit_key", record.what.unit_key.get()));

    if record.recipe == Recipe::V4 {
        f.push(DigestField::num("incarnation", record.what.incarnation));
    }
    f.push(DigestField::text("op_class", record.what.op_class.as_str()));
    f.push(DigestField::text(
        "destination",
        record.what.destination.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::num(
        "parent",
        record.what.parent.map(|p| p.get()).unwrap_or(0),
    ));
    f.push(DigestField::text(
        "pre_hook_head",
        record.what.pre_hook_head.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::text(
        "post_hook_head",
        record.what.post_hook_head.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::num("wall", record.wall));
    f.push(DigestField::num("mono", record.mono));

    if record.recipe == Recipe::V4 {
        f.push(DigestField::num("node", record.node));
    }
    f.push(DigestField::text("origin_kind", record.origin_kind));
    f.push(DigestField::text(
        "outcome",
        outcome_tag(record.outcome.unit_end),
    ));
    f.push(DigestField::text(
        "step",
        record
            .outcome
            .step
            .map(|s| s.as_str().to_string())
            .unwrap_or_default(),
    ));
    f.push(DigestField::text(
        "finish",
        finish_tag(record.outcome.finish),
    ));
    f.push(DigestField::num(
        "hook_failed",
        u64::from(record.outcome.hook_failed),
    ));
    f.push(DigestField::text(
        "emission_delta",
        record.outcome.emission_delta.to_string(),
    ));
    f.push(DigestField::num(
        "stale_policy",
        u64::from(record.outcome.stale_policy),
    ));
    f.push(DigestField::num(
        "lines_count",
        record.usage.lines.len() as u64,
    ));
    for line in &record.usage.lines {
        f.push(DigestField::text("lines[].class", line.class.as_str()));
        f.push(DigestField::num("lines[].quantity", line.quantity));
        f.push(DigestField::text(
            "lines[].source",
            quantity_source_tag(&line.source),
        ));
        f.push(DigestField::num(
            "lines[].estimated",
            u64::from(line.estimated),
        ));
    }
    f.push(DigestField::num("tier_bp", u64::from(record.usage.tier_bp)));
    f.push(DigestField::num(
        "fee_count",
        u64::from(record.usage.fee_count),
    ));

    if let Recipe::V2 { currency } = &record.recipe {
        f.push(DigestField::text("currency", currency.clone()));
    }
    f.push(DigestField::num(
        "rate_card_version",
        record.usage.rate_card_version,
    ));
    f.push(DigestField::text(
        "bucket_chain_ref",
        record.usage.bucket_chain_ref.clone(),
    ));
    f.push(DigestField::text(
        "hold_ref",
        record.controls.hold_ref.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::text(
        "settle_ref",
        record.controls.settle_ref.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::text(
        "slice_ref",
        record.controls.slice_ref.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::text(
        "lease_ref",
        record.controls.lease_ref.as_deref().unwrap_or(""),
    ));
    f.push(DigestField::num("lease_epoch", record.controls.lease_epoch));
    f.push(DigestField::num(
        "policy_epoch",
        record.controls.policy_epoch,
    ));
    f.push(DigestField::num(
        "hooks_count",
        record.controls.hooks_applied.len() as u64,
    ));
    for hook in &record.controls.hooks_applied {
        f.push(DigestField::text("hooks[].hook", hook.hook.clone()));

        if record.recipe == Recipe::V4 {
            f.push(DigestField::text("hooks[].head", hook.head.as_str()));
            f.push(DigestField::num("hooks[].failed", u64::from(hook.failed)));
        }
    }
    f.push(DigestField::num(
        "replayed",
        u64::from(record.controls.replayed),
    ));
    f.push(DigestField::num(
        "children_count",
        record.controls.children.len() as u64,
    ));
    for child in &record.controls.children {
        f.push(DigestField::num("children[]", child.get()));
    }
    f.push(DigestField::text(
        "correlation_hash",
        record.correlation_hash.as_deref().unwrap_or(""),
    ));
    f
}

/// Hash one field list under the record chain's framing.

#[must_use]
pub fn digest_over(fields: &[DigestField]) -> String {
    let mut d = crate::digest::Digest::new(crate::digest::Framing::LengthPrefixed);
    for field in fields {
        match &field.value {
            DigestValue::Text(s) => {
                d.text(s);
            }
            DigestValue::Num(n) => {
                d.num(*n);
            }
        }
    }
    d.finish()
}
