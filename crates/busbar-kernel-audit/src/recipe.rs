// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST RECIPE, as published contract rather than as an implementation detail.
//!
//! ## Why this is a module and not a comment
//!
//! If only busbar can verify busbar's chain then the chain is a CLAIM, not evidence. An auditor who
//! has to run our binary to check our records has checked nothing they could not have checked by
//! asking us. So the exact field order, the exact framing and the exact spelling of every value are
//! a versioned public contract, written down at `docs/audit-chain-digest-v4.md`, and reproduced by
//! a verifier that has never seen this repository.
//!
//! This module is what makes that promise checkable instead of aspirational. It is the ONE place
//! the order lives: [`crate::record::AuditChain::digest_of`] walks this list, the range read
//! ([`crate::expose`]) emits this list, and the published document describes this list. There is no
//! second copy to drift, which matters more here than anywhere else in the crate — a digest recipe
//! that drifted from its documentation would make every third-party verification fail and look, to
//! the third party, exactly like a tampered chain.
//!
//! ## Length-prefixed, NOT separator-joined
//!
//! Carried forward from the record's own framing rule, because a published recipe that omitted
//! the reason invites a reimplementation that "simplifies" it. Every field goes in as its
//! big-endian eight-byte length followed by its bytes; integers go in as their big-endian
//! eight-byte form (which is its own length prefix of 8). Fields are NOT joined by a separator.
//!
//! These fields hold arbitrary caller-named text — an operation class a caller named, a bucket
//! chain reference, a destination — and a separator-joined digest is only safe while no field can
//! contain the separator. That is a property of today's field VALUES, not of the code, and it stops
//! being true the first time somebody names a tool with a bar in it. Length prefixes make the split
//! between fields unforgeable whatever the fields hold: a caller who controls one field's bytes
//! cannot make the same byte stream read as a different split.

/// The recipe's version name. Goes in every published body so a verifier never has to guess which
/// rules to apply, and so a future recipe can exist beside this one instead of replacing it.
///
/// `v3` is `v2` less `currency` (#34, OWNER 2026-09-29: remove and migrate). Money is unitless
/// abstract cost (#66: no currency type and no symbol), so a denomination in the signed preimage
/// was a claim the node does not make. `v2` is not rewritten: its page,
/// `docs/audit-chain-digest-v2.md`, stays published beside this one, and a record sealed under it
/// carries [`Recipe::V2`] with the text it digested, so it still verifies by the rules it was sealed
/// under. `v2` is `v1` less the three priced figures (`pre_tier`, `priced`,
/// `hooks[].priced_delta`); `v1` stays published too, and no node retains a `v1` record.
///
/// `v4` is `v3` plus `incarnation`, directly after `unit_key`. A unit key restarts at every boot of
/// a node, so `unit_key` alone named two different units across two boots; the boot the unit ran in
/// (`What::incarnation`) makes the pair unique. `v3` is not rewritten: its page,
/// `docs/audit-chain-digest-v3.md`, stays published, and a record sealed under it carries
/// [`Recipe::V3`] and verifies by `v3`'s rules.
pub const DIGEST_RECIPE: &str = "busbar.audit.digest.v4";

/// The name of the recipe before [`DIGEST_RECIPE`]: `v4` less `incarnation`.
pub const DIGEST_RECIPE_V3: &str = "busbar.audit.digest.v3";

/// The name of the recipe before [`DIGEST_RECIPE_V3`]: `v3` plus `currency`.
pub const DIGEST_RECIPE_V2: &str = "busbar.audit.digest.v2";

/// WHICH RECIPE A RECORD WAS SEALED UNDER — and so the rules it verifies by.
///
/// A record carries this rather than the chain, because a chain that crossed a recipe change holds
/// records of both, and each verifies only by its own rules. It is not itself digested and does not
/// need to be: moving a record between the arms changes the field list (a `v2` record relabelled
/// `v3` loses a field, a `v3` record relabelled `v2` gains one), so the relabelled record no longer
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
    /// `busbar.audit.digest.v3`: `v4` without `incarnation`. Kept so a record sealed under it
    /// still verifies.
    V3,
    /// `busbar.audit.digest.v4`: every record this build seals.
    V4,
}

impl Recipe {
    /// The published name of this recipe.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Recipe::V2 { .. } => DIGEST_RECIPE_V2,
            Recipe::V3 => DIGEST_RECIPE_V3,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestValue {
    /// A length-prefixed run of bytes.
    Text(String),
    /// An unsigned 64-bit integer, big-endian.
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
///
/// This is the recipe. `digest_of` hashes exactly this, the range read publishes exactly this, and
/// the document at `docs/audit-chain-digest-v4.md` describes exactly this — for a record sealed
/// under [`Recipe::V4`] (`docs/audit-chain-digest-v3.md` for [`Recipe::V3`]). A record sealed
/// under [`Recipe::V2`] gets the `v2` list, which `docs/audit-chain-digest-v2.md` describes.
///
/// The repeated groups — the usage lines, the hooks that ran, the child units — are each preceded
/// by their COUNT, which is what stops two different groupings from digesting identically. Their
/// members are named with the position folded in (`lines[0].class`) so that a published body can
/// carry them as arrays and a verifier can still walk the flat order.
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
    // `v4` names the boot the unit ran in beside its key: a unit key restarts at every boot.
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
    // `v2` framed a `currency` text here; `v3` does not (#34).
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
///
/// The other half of "there is one recipe": this is the only function that turns fields into a
/// digest, so a caller cannot accidentally hash them under the legacy bar-joined framing and get an
/// answer that looks plausible.
#[must_use]
pub fn digest_over(fields: &[DigestField]) -> String {
    let mut d = crate::legacy::Digest::new(crate::legacy::Framing::LengthPrefixed);
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
