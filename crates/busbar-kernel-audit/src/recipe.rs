// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST RECIPE, as published contract rather than as an implementation detail.
//!
//! ## Why this is a module and not a comment
//!
//! If only busbar can verify busbar's chain then the chain is a CLAIM, not evidence. An auditor who
//! has to run our binary to check our records has checked nothing they could not have checked by
//! asking us. So the exact field order, the exact framing and the exact spelling of every value are
//! a versioned public contract, written down at `docs/audit-chain-digest-v1.md`, and reproduced by
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
pub const DIGEST_RECIPE: &str = "busbar.audit.digest.v1";

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
/// the document at `docs/audit-chain-digest-v1.md` describes exactly this.
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
        record.amount.lines.len() as u64,
    ));
    for line in &record.amount.lines {
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
    f.push(DigestField::text(
        "pre_tier",
        record.amount.pre_tier.to_string(),
    ));
    f.push(DigestField::text(
        "priced",
        record.amount.priced.to_string(),
    ));
    f.push(DigestField::num(
        "tier_bp",
        u64::from(record.amount.tier_bp),
    ));
    f.push(DigestField::num(
        "fee_count",
        u64::from(record.amount.fee_count),
    ));
    f.push(DigestField::text(
        "currency",
        record.amount.currency.clone(),
    ));
    f.push(DigestField::num(
        "rate_card_version",
        record.amount.rate_card_version,
    ));
    f.push(DigestField::text(
        "bucket_chain_ref",
        record.amount.bucket_chain_ref.clone(),
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
        f.push(DigestField::text(
            "hooks[].priced_delta",
            hook.priced_delta.to_string(),
        ));
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
