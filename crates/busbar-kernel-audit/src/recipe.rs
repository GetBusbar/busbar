// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST RECIPE, as published contract rather than as an implementation detail.

/// The recipe's version name. Goes in every published body so a verifier never has to guess which
pub const DIGEST_RECIPE: &str = "busbar.audit.digest.v5";

/// Exact scale-six quantities, with canonical decimal text in the quantity field.
pub const DIGEST_RECIPE_V6: &str = "busbar.audit.digest.v6";

/// The recipe every new record is sealed under (ADMIN-API-1.6 §3.2): `v6`'s exact decimal
/// quantities for every line, whole or fractional, plus the per-unit facts `/records` serves.
pub const DIGEST_RECIPE_V7: &str = "busbar.audit.digest.v7";

/// The unchanged legacy recipe with a chain-local rate-card ordinal.
pub const DIGEST_RECIPE_V4: &str = "busbar.audit.digest.v4";

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
        /// The exact ordinal byte framed by this old recipe, never a current history key.
        legacy_rate_card_version: u64,
    },
    /// The unchanged legacy v4 recipe and its original ordinal preimage field.
    V4 {
        /// The exact ordinal byte framed by this old recipe, never a current history key.
        legacy_rate_card_version: u64,
    },
    /// The keyed recipe retained for whole-count seals.
    V5,
    /// The keyed recipe with exact decimal quantity text, retained for verification.
    V6,
    /// The recipe this build seals under: every quantity as exact decimal text, plus
    /// [`crate::record::UnitFacts`] after the `v6` fields.
    V7,
}

impl Recipe {
    /// The published name of this recipe.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Recipe::V2 { .. } => DIGEST_RECIPE_V2,
            Recipe::V4 { .. } => DIGEST_RECIPE_V4,
            Recipe::V5 => DIGEST_RECIPE,
            Recipe::V6 => DIGEST_RECIPE_V6,
            Recipe::V7 => DIGEST_RECIPE_V7,
        }
    }

    /// Whether the recipe frames the incarnation, the node and the hook heads (`v4` on).
    #[must_use]
    pub(crate) fn keyed_frame(&self) -> bool {
        !matches!(self, Recipe::V2 { .. })
    }

    /// Whether the recipe frames each quantity as exact decimal text (`v6` on).
    #[must_use]
    pub(crate) fn exact_quantities(&self) -> bool {
        matches!(self, Recipe::V6 | Recipe::V7)
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

/// Where the recipe's fields go, in order, as they are read off a record: a digest frames them, the
/// range read prints them. Nothing is built in between — text is lent, and a tag is formatted
/// straight into whatever the sink writes.
pub trait FieldSink {
    /// A text field.
    fn text(&mut self, name: &'static str, value: &str);
    /// A text field whose text is `value`, formatted.
    fn text_fmt(&mut self, name: &'static str, value: std::fmt::Arguments<'_>);
    /// A number field.
    fn num(&mut self, name: &'static str, value: u64);
}

/// The record chain's digest takes the fields as framed bytes.
impl FieldSink for crate::digest::Digest {
    fn text(&mut self, _name: &'static str, value: &str) {
        crate::digest::Digest::text(self, value);
    }

    fn text_fmt(&mut self, _name: &'static str, value: std::fmt::Arguments<'_>) {
        crate::digest::Digest::text_fmt(self, value);
    }

    fn num(&mut self, _name: &'static str, value: u64) {
        crate::digest::Digest::num(self, value);
    }
}

/// EVERY FIELD THAT GOES INTO ONE RECORD'S DIGEST, IN ORDER, handed to `f`.
pub fn visit_fields(record: &crate::record::AuditRecord, f: &mut impl FieldSink) {
    use crate::record::{
        finish_tag, subject_tag, HexBytes, OutcomeTag, QuantitySourceTag, Subject,
    };

    f.text("prev_hash", &record.prev_hash);
    f.num("seq", record.seq);
    f.text("subject_tag", subject_tag(&record.subject));
    match &record.subject {
        Subject::PrincipalId(p) => f.text("subject_value", p),
        Subject::Arrival | Subject::Aggregate => f.text("subject_value", ""),
        Subject::Node(id) => f.text_fmt("subject_value", format_args!("{id}")),
    }
    f.num("unit_key", record.what.unit_key.get());

    if record.recipe.keyed_frame() {
        f.num("incarnation", record.what.incarnation);
    }
    f.text("op_class", record.what.op_class.as_str());
    f.text(
        "destination",
        record.what.destination.as_deref().unwrap_or(""),
    );
    f.num("parent", record.what.parent.map(|p| p.get()).unwrap_or(0));
    f.text(
        "pre_hook_head",
        record.what.pre_hook_head.as_deref().unwrap_or(""),
    );
    f.text(
        "post_hook_head",
        record.what.post_hook_head.as_deref().unwrap_or(""),
    );
    f.num("wall", record.wall);
    f.num("mono", record.mono);

    if record.recipe.keyed_frame() {
        f.num("node", record.node);
    }
    f.text("origin_kind", record.origin_kind);
    f.text_fmt(
        "outcome",
        format_args!("{}", OutcomeTag(record.outcome.unit_end)),
    );
    f.text(
        "step",
        record.outcome.step.map(|s| s.as_str()).unwrap_or_default(),
    );
    f.text("finish", finish_tag(record.outcome.finish));
    f.num("hook_failed", u64::from(record.outcome.hook_failed));
    f.text_fmt(
        "emission_delta",
        format_args!("{}", record.outcome.emission_delta),
    );
    f.num("stale_policy", u64::from(record.outcome.stale_policy));
    f.num("lines_count", record.usage.lines.len() as u64);
    for line in &record.usage.lines {
        f.text("lines[].class", line.class.as_str());
        if record.recipe.exact_quantities() {
            f.text_fmt("lines[].quantity", format_args!("{}", line.quantity));
        } else {
            f.num(
                "lines[].quantity",
                line.quantity
                    .whole_u64()
                    .expect("legacy recipe has whole quantities"),
            );
        }
        f.text_fmt(
            "lines[].source",
            format_args!("{}", QuantitySourceTag(&line.source)),
        );
        f.num("lines[].estimated", u64::from(line.estimated));
    }
    f.num("tier_bp", u64::from(record.usage.tier_bp));
    f.num("fee_count", u64::from(record.usage.fee_count));

    if let Recipe::V2 { currency, .. } = &record.recipe {
        f.text("currency", currency);
    }
    match record.recipe {
        Recipe::V2 {
            legacy_rate_card_version,
            ..
        }
        | Recipe::V4 {
            legacy_rate_card_version,
        } => {
            f.num("rate_card_version", legacy_rate_card_version);
        }
        Recipe::V5 | Recipe::V6 | Recipe::V7 => {
            f.num(
                "rate_card_key_present",
                u64::from(record.usage.rate_card_version.is_some()),
            );
            match &record.usage.rate_card_version {
                Some(key) => f.text_fmt("rate_card_version", format_args!("{}", HexBytes(key))),
                None => f.text("rate_card_version", ""),
            }
        }
    }
    f.text("bucket_chain_ref", &record.usage.bucket_chain_ref);
    f.text(
        "hold_ref",
        record.controls.hold_ref.as_deref().unwrap_or(""),
    );
    f.text(
        "settle_ref",
        record.controls.settle_ref.as_deref().unwrap_or(""),
    );
    f.text(
        "slice_ref",
        record.controls.slice_ref.as_deref().unwrap_or(""),
    );
    f.text(
        "lease_ref",
        record.controls.lease_ref.as_deref().unwrap_or(""),
    );
    f.num("lease_epoch", record.controls.lease_epoch);
    f.num("policy_epoch", record.controls.policy_epoch);
    f.num("hooks_count", record.controls.hooks_applied.len() as u64);
    for hook in &record.controls.hooks_applied {
        f.text("hooks[].hook", &hook.hook);

        if record.recipe.keyed_frame() {
            f.text("hooks[].head", hook.head.as_str());
            f.num("hooks[].failed", u64::from(hook.failed));
        }
    }
    f.num("replayed", u64::from(record.controls.replayed));
    f.num("children_count", record.controls.children.len() as u64);
    for child in &record.controls.children {
        f.num("children[]", child.get());
    }
    f.text(
        "correlation_hash",
        record.correlation_hash.as_deref().unwrap_or(""),
    );
    if matches!(record.recipe, Recipe::V7) {
        visit_unit_facts(&record.unit, f);
    }
}

/// The fields recipe `v7` appends, in order (`docs/audit-chain-digest-v7.md`, positions 46 on).
fn visit_unit_facts(unit: &crate::record::UnitFacts, f: &mut impl FieldSink) {
    use crate::record::HexBytes;
    f.num("wall_ms", unit.wall_ms);
    f.text("attribution", &unit.attribution);
    f.text_fmt("boot_nonce", format_args!("{}", HexBytes(&unit.boot_nonce)));
    f.num("status", u64::from(unit.status));
    f.num("ttft_us", unit.ttft_us);
    f.num("total_us", unit.total_us);
    f.num("attempts_count", unit.attempts_used().count() as u64);
    for attempt in unit.attempts_used() {
        f.text("attempts[].outcome", attempt.outcome.as_str());
        f.text("attempts[].target", &attempt.target);
        f.text("attempts[].reason", &attempt.reason);
        f.num("attempts[].us", attempt.us);
    }
    f.num("attempts_total", u64::from(unit.attempts_total));
}

/// Hash one record under the record chain's framing, field by field, as [`visit_fields`] reads it.
#[must_use]
pub fn digest_record(record: &crate::record::AuditRecord) -> String {
    let mut d = crate::digest::Digest::new(crate::digest::Framing::LengthPrefixed);
    visit_fields(record, &mut d);
    d.finish()
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
