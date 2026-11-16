// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! New records use `audit.v7` (recipe `busbar.audit.digest.v7`). Records sealed under `v5` and
//! `v6` keep `audit.v5` and `audit.v6`, and legacy records keep their original bytes.

use busbar_contract::caps::UnitKey;

use crate::record::{
    direction_tag, finish_tag, step_tag, AuditRecord, OutcomeTag, QuantitySource, SubjectValue,
};

// The read-back half (a journalled body decoded at restore or by an admin read) runs off the
// request path.
pub use crate::off_path::journal::{from_journal_body, head_from_journal_body, JournalHead};

/// The tag for keyed audit records with legacy whole-count framing.
pub const JOURNAL_TAG: &str = "audit.v5";

/// Journal encoding for explicitly versioned exact decimal quantities.
pub(crate) const JOURNAL_TAG_V6: &str = "audit.v6";

/// Journal encoding for recipe `v7`: the `v6` body plus the unit facts after it.
pub(crate) const JOURNAL_TAG_V7: &str = "audit.v7";

/// Journal encoding for the link-only line ([`crate::recipe::Recipe::V8`], SEALING-FIX §3.1; the
/// design's "v7 line", renamed because `audit.v7` is the record recipe's): the `v7` content behind a
/// fixed header of raw fingerprints and `linked_ms`, with no signature.
pub(crate) const JOURNAL_TAG_V8: &str = "audit.v8";

/// The original journal format retained for legacy digest recipes.
pub(crate) const JOURNAL_TAG_V4: &str = "audit.v4";

/// A text field longer than the body's length prefix can say (more than `u32::MAX` bytes).
///
/// The body is REFUSED whole rather than cut: a field cut to fit — possibly inside a UTF-8
/// sequence — makes a journalled record that either fails to decode at boot or decodes to a record
/// that no longer hashes to its own digest, and nothing would have said so when it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldTooLong;

impl std::fmt::Display for FieldTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an audit record field is longer than the journal body's length prefix can say")
    }
}

impl std::error::Error for FieldTooLong {}

/// The journal body of one sealed record.
pub fn journal_body(record: &AuditRecord) -> Result<Vec<u8>, FieldTooLong> {
    let mut w = Writer::new();
    w.text(match record.recipe {
        crate::recipe::Recipe::V8 => JOURNAL_TAG_V8,
        crate::recipe::Recipe::V7 => JOURNAL_TAG_V7,
        crate::recipe::Recipe::V6 => JOURNAL_TAG_V6,
        crate::recipe::Recipe::V5 => JOURNAL_TAG,
        _ => JOURNAL_TAG_V4,
    });
    w.text(record.recipe.name());
    if let crate::recipe::Recipe::V2 { currency, .. } = &record.recipe {
        w.text(currency);
    }
    w.num(record.seq);
    if record.recipe.is_link() {
        // The link line's fixed header: both fingerprints as 32 raw bytes (the genesis
        // predecessor as zeros), then the date it was linked. No signature: a stamp vouches.
        w.bytes(&link_bytes(&record.prev_hash).0);
        w.bytes(&link_bytes(&record.hash).0);
        w.num(record.linked_ms);
    } else {
        w.text(&record.prev_hash);
        w.text(&record.hash);
        w.opt_text(record.signature.as_deref());
        w.opt_text(record.key_id.as_deref());
    }
    w.text(crate::record::subject_tag(&record.subject));
    w.text_fmt(format_args!("{}", SubjectValue(&record.subject)));
    w.num(record.what.unit_key.get());
    w.num(record.what.incarnation);
    w.text(record.what.op_class.as_str());
    w.opt_text(record.what.destination.as_deref());
    w.opt_num(record.what.parent.map(UnitKey::get));
    w.opt_text(record.what.pre_hook_head.as_deref());
    w.opt_text(record.what.post_hook_head.as_deref());
    w.num(record.wall);
    w.num(record.mono);
    w.num(record.node);
    w.text(record.origin_kind);
    w.text_fmt(format_args!("{}", OutcomeTag(record.outcome.unit_end)));
    w.opt_text(record.outcome.step.map(step_tag));
    w.text(finish_tag(record.outcome.finish));
    w.num(u64::from(record.outcome.hook_failed));
    w.text_fmt(format_args!("{}", record.outcome.emission_delta));
    w.num(u64::from(record.outcome.stale_policy));
    w.num(record.usage.lines.len() as u64);
    for line in &record.usage.lines {
        w.text(line.class.as_str());
        if record.recipe.exact_quantities() {
            w.text_fmt(format_args!("{}", line.quantity));
        } else {
            w.num(
                line.quantity
                    .whole_u64()
                    .expect("legacy recipe has whole quantities"),
            );
        }
        write_source(&mut w, &line.source);
        w.num(u64::from(line.estimated));
    }
    w.num(u64::from(record.usage.tier_bp));
    w.num(u64::from(record.usage.fee_count));
    match record.recipe {
        crate::recipe::Recipe::V2 {
            legacy_rate_card_version,
            ..
        }
        | crate::recipe::Recipe::V4 {
            legacy_rate_card_version,
        } => w.num(legacy_rate_card_version),
        crate::recipe::Recipe::V5
        | crate::recipe::Recipe::V6
        | crate::recipe::Recipe::V7
        | crate::recipe::Recipe::V8 => {
            w.num(u64::from(record.usage.rate_card_version.is_some()));
            if let Some(key) = &record.usage.rate_card_version {
                w.bytes(key);
            }
        }
    }
    w.text(&record.usage.bucket_chain_ref);
    let c = &record.controls;
    w.opt_text(c.hold_ref.as_deref());
    w.opt_text(c.settle_ref.as_deref());
    w.opt_text(c.slice_ref.as_deref());
    w.opt_text(c.lease_ref.as_deref());
    w.num(c.lease_epoch);
    w.num(c.policy_epoch);
    w.num(c.hooks_applied.len() as u64);
    for hook in &c.hooks_applied {
        w.text(&hook.hook);
        w.text(hook.head.as_str());
        w.num(u64::from(hook.failed));
    }
    w.num(u64::from(c.replayed));
    w.num(c.children.len() as u64);
    for child in &c.children {
        w.num(child.get());
    }
    w.opt_text(record.correlation_hash.as_deref());
    if record.recipe.carries_unit_facts() {
        write_unit_facts(&mut w, &record.unit);
    }
    w.finish()
}

/// A link line's fingerprint text as its 32 body bytes. Every link line [`crate::link`] builds holds
/// 64 lowercase hex characters here, and the genesis predecessor the empty text (zeros).
fn link_bytes(text: &str) -> crate::link::Fingerprint {
    let parsed = crate::link::Fingerprint::from_hex(text);
    debug_assert!(parsed.is_some(), "a link line holds a fingerprint");
    parsed.unwrap_or(crate::link::Fingerprint::ZERO)
}

/// The `v7` tail, in the recipe's order.
fn write_unit_facts(w: &mut Writer, unit: &crate::record::UnitFacts) {
    w.num(unit.wall_ms);
    w.text(&unit.attribution);
    w.bytes(&unit.boot_nonce);
    w.num(u64::from(unit.status));
    w.num(unit.ttft_us);
    w.num(unit.total_us);
    w.num(unit.attempts_used().count() as u64);
    for attempt in unit.attempts_used() {
        w.text(attempt.outcome.as_str());
        w.text(&attempt.target);
        w.text(&attempt.reason);
        w.num(attempt.us);
    }
    w.num(u64::from(unit.attempts_total));
}

fn write_source(w: &mut Writer, source: &QuantitySource) {
    match source {
        QuantitySource::Count => w.num(0),
        QuantitySource::TransportUnits => w.num(1),
        QuantitySource::KernelElapsedMono => w.num(2),
        QuantitySource::KernelBytes { divisor } => {
            w.num(3);
            w.num(*divisor);
        }
        QuantitySource::KernelFrames { factor } => {
            w.num(4);
            w.num(*factor);
        }
        QuantitySource::Locator { direction, ptr } => {
            w.num(5);
            w.text(direction_tag(*direction));
            w.text(ptr.as_str());
        }
        QuantitySource::PlaneCount { content_fact_key } => {
            w.num(6);
            w.text(content_fact_key);
        }
    }
}

/// The body writer. A text longer than `limit` (the length prefix's own bound, `u32::MAX`, outside
pub(crate) struct Writer {
    out: Vec<u8>,
    limit: usize,
    too_long: bool,
}

impl Writer {
    fn new() -> Self {
        Writer::within(u32::MAX as usize)
    }

    pub(crate) fn within(limit: usize) -> Self {
        Writer {
            out: Vec::new(),
            limit,
            too_long: false,
        }
    }

    pub(crate) fn text(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    /// A text field formatted straight into the body: the same bytes as [`Writer::text`] over the
    /// formatted string, with no string built first.
    pub(crate) fn text_fmt(&mut self, value: std::fmt::Arguments<'_>) {
        /// Formats into the body's bytes.
        struct Onto<'a>(&'a mut Vec<u8>);
        impl std::fmt::Write for Onto<'_> {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }
        }
        let prefix = self.out.len();
        self.out.extend_from_slice(&[0; 4]);
        let _ = std::fmt::Write::write_fmt(&mut Onto(&mut self.out), value);
        let len = self.out.len() - prefix - 4;
        match u32::try_from(len).ok().filter(|_| len <= self.limit) {
            Some(len) => self.out[prefix..prefix + 4].copy_from_slice(&len.to_be_bytes()),
            None => {
                self.out.truncate(prefix);
                self.too_long = true;
            }
        }
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        match u32::try_from(bytes.len())
            .ok()
            .filter(|_| bytes.len() <= self.limit)
        {
            Some(len) => {
                self.out.extend_from_slice(&len.to_be_bytes());
                self.out.extend_from_slice(bytes);
            }
            None => self.too_long = true,
        }
    }

    pub(crate) fn num(&mut self, n: u64) {
        self.out.extend_from_slice(&n.to_be_bytes());
    }

    /// The body, or [`FieldTooLong`] when any text did not fit.
    pub(crate) fn finish(self) -> Result<Vec<u8>, FieldTooLong> {
        if self.too_long {
            return Err(FieldTooLong);
        }
        Ok(self.out)
    }

    fn opt_text(&mut self, s: Option<&str>) {
        match s {
            None => self.num(0),
            Some(s) => {
                self.num(1);
                self.text(s);
            }
        }
    }

    fn opt_num(&mut self, n: Option<u64>) {
        match n {
            None => self.num(0),
            Some(n) => {
                self.num(1);
                self.num(n);
            }
        }
    }
}
