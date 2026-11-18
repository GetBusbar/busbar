// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The audit journal's read-back half: a journalled body decoded into the record (or the head) it
//! keeps, at restore or for an admin read, never per request.

use busbar_contract::caps::{Abort, MeterClassId, Outcome, ReasonCode, StepName, UnitKey};

use crate::journal::{
    JOURNAL_TAG, JOURNAL_TAG_V4, JOURNAL_TAG_V6, JOURNAL_TAG_V7, JOURNAL_TAG_V8, JOURNAL_TAG_V9,
};
use crate::link::Fingerprint;
use crate::record::{
    direction_tag, displays_as, finish_tag, step_tag, AbortTag, Attempt, AttemptOutcome,
    AuditRecord, Controls, FinishClass, HookApplied, HookHead, OpClassId, OutcomeFacts, OutcomeTag,
    QuantitySource, ReasonTag, Subject, UnitFacts, Usage, UsageLine, What, ATTEMPT_SLOTS,
    LABEL_SLOTS,
};

/// Read a journal body back into the record it keeps.
pub fn from_journal_body(
    bytes: &[u8],
    class: &dyn Fn(&str) -> Option<MeterClassId>,
) -> Result<Option<AuditRecord>, String> {
    if Reader::new(bytes).bytes() == Some(JOURNAL_TAG_V9.as_bytes())
        && bytes.len() > crate::record::billing::BILLING_RECORD_BYTES
    {
        return Err("selected audit body exceeds its byte bound".into());
    }
    let mut r = Reader { bytes, at: 0 };
    let Some(keyed) = journal_kind(&mut r) else {
        return Ok(None);
    };
    decode(&mut r, class, keyed).map(Some)
}

/// The independently retained head fields of one journalled audit record.
pub struct JournalHead {
    /// The original record's published position, digest, signature, key identifier and wall clock.
    pub head: crate::heads::SignedHead,
    /// That record's claimed predecessor digest, for checking sequence/link continuity.
    pub prev_hash: String,
    /// The node that sealed the original audit record.
    pub node: u64,
}

/// Read audit head metadata without resolving the historical plane's meter vocabulary.
pub fn head_from_journal_body(bytes: &[u8]) -> Result<Option<JournalHead>, String> {
    if let Some(record) = crate::notary_key::notary_key_from_journal_body(bytes)? {
        return Ok(Some(JournalHead {
            head: crate::heads::SignedHead {
                seq: record.seq,
                hash: record.fingerprint.to_string(),
                signature: None,
                key_id: None,
                wall: record.linked_ms / 1_000,
            },
            prev_hash: prev_text(record.prev_link),
            node: record.node,
        }));
    }
    let mut r = Reader { bytes, at: 0 };
    let Some(keyed) = journal_kind(&mut r) else {
        return Ok(None);
    };
    let bad = || "an audit head prefix does not decode".to_string();
    match r.text().as_deref().ok_or_else(bad)? {
        crate::recipe::DIGEST_RECIPE if keyed == 5 => {}
        crate::recipe::DIGEST_RECIPE_V6 if keyed == 6 => {}
        crate::recipe::DIGEST_RECIPE_V7 if keyed == 7 => {}
        crate::recipe::LINK_RECIPE if keyed == 8 => {}
        crate::recipe::LINK_RECIPE_V2 if keyed == 9 => {}
        crate::recipe::DIGEST_RECIPE_V4 if keyed == 4 => {}
        crate::recipe::DIGEST_RECIPE_V2 if keyed == 4 => {
            r.skip_text().ok_or_else(bad)?;
        }
        other if matches!(keyed, 8 | 9) => return Err(link_recipe_unsupported(other)),
        _ => return Err("an audit head names an unknown recipe".into()),
    }
    let seq = r.num().ok_or_else(bad)?;
    let (prev_hash, hash, signature, key_id) = if matches!(keyed, 8 | 9) {
        let prev = r.fingerprint().ok_or_else(bad)?;
        let hash = r.fingerprint().ok_or_else(bad)?;
        r.num().ok_or_else(bad)?;
        (prev_text(prev), hex::encode(hash.0), None, None)
    } else {
        let prev_hash = r.text().ok_or_else(bad)?;
        let hash = r.text().ok_or_else(bad)?;
        let signature = r.opt_text().ok_or_else(bad)?;
        let key_id = r
            .opt_text()
            .ok_or_else(bad)?
            .map(std::sync::Arc::<str>::from);
        (prev_hash, hash, signature, key_id)
    };
    r.skip_text().ok_or_else(bad)?;
    r.skip_text().ok_or_else(bad)?;
    r.num().ok_or_else(bad)?;
    r.num().ok_or_else(bad)?;
    r.skip_text().ok_or_else(bad)?;
    r.skip_opt_text().ok_or_else(bad)?;
    r.opt_num().ok_or_else(bad)?;
    r.skip_opt_text().ok_or_else(bad)?;
    r.skip_opt_text().ok_or_else(bad)?;
    let wall = r.num().ok_or_else(bad)?;
    r.num().ok_or_else(bad)?;
    let node = r.num().ok_or_else(bad)?;
    Ok(Some(JournalHead {
        head: crate::heads::SignedHead {
            seq,
            hash,
            signature,
            key_id,
            wall,
        },
        prev_hash,
        node,
    }))
}

fn journal_kind(r: &mut Reader<'_>) -> Option<u8> {
    match r.text().as_deref()? {
        JOURNAL_TAG => Some(5),
        JOURNAL_TAG_V6 => Some(6),
        JOURNAL_TAG_V7 => Some(7),
        JOURNAL_TAG_V8 => Some(8),
        JOURNAL_TAG_V9 => Some(9),
        JOURNAL_TAG_V4 => Some(4),
        _ => None,
    }
}

/// `AUDIT_RECIPE_UNSUPPORTED` (SEALING-FIX §3.1): a link line written under a recipe this build
/// cannot recompute is refused with the crypto layer's reason, never read as verified.
fn link_recipe_unsupported(recipe: &str) -> String {
    let why = match crate::link::line_hasher(recipe) {
        Err(unsupported) => unsupported.to_string(),
        Ok(_) => "this build reads link lines under one recipe only".to_string(),
    };
    format!(
        "AUDIT_RECIPE_UNSUPPORTED: an audit line written under the link recipe {recipe:?} is refused: {why}"
    )
}

/// A link line's predecessor as the record holds it: the genesis predecessor (zeros) is empty.
fn prev_text(prev: Fingerprint) -> String {
    if prev == Fingerprint::ZERO {
        String::new()
    } else {
        hex::encode(prev.0)
    }
}

fn decode(
    r: &mut Reader<'_>,
    class: &dyn Fn(&str) -> Option<MeterClassId>,
    keyed: u8,
) -> Result<AuditRecord, String> {
    let bad = |what: &str| format!("an audit record whose {what} does not decode");
    let mut recipe = match r.text().ok_or_else(|| bad("recipe"))?.as_str() {
        crate::recipe::DIGEST_RECIPE if keyed == 5 => crate::recipe::Recipe::V5,
        crate::recipe::DIGEST_RECIPE_V6 if keyed == 6 => crate::recipe::Recipe::V6,
        crate::recipe::DIGEST_RECIPE_V7 if keyed == 7 => crate::recipe::Recipe::V7,
        crate::recipe::LINK_RECIPE if keyed == 8 => crate::recipe::Recipe::V8,
        crate::recipe::LINK_RECIPE_V2 if keyed == 9 => crate::recipe::Recipe::V9,
        other if matches!(keyed, 8 | 9) => return Err(link_recipe_unsupported(other)),
        crate::recipe::DIGEST_RECIPE_V4 if keyed == 4 => crate::recipe::Recipe::V4 {
            legacy_rate_card_version: 0,
        },
        crate::recipe::DIGEST_RECIPE_V2 if keyed == 4 => crate::recipe::Recipe::V2 {
            currency: r.text().ok_or_else(|| bad("currency"))?,
            legacy_rate_card_version: 0,
        },
        other => {
            let refusal = format!("an audit record sealed under an unknown recipe {other:?}");
            return Err(refusal);
        }
    };
    let seq = r.num().ok_or_else(|| bad("seq"))?;
    let (prev_hash, hash, linked_ms, signature, key_id) = if recipe.is_link() {
        let prev = r.fingerprint().ok_or_else(|| bad("prev_hash"))?;
        let hash = r.fingerprint().ok_or_else(|| bad("hash"))?;
        let linked_ms = r.num().ok_or_else(|| bad("linked_ms"))?;
        (prev_text(prev), hex::encode(hash.0), linked_ms, None, None)
    } else {
        let prev_hash = r.text().ok_or_else(|| bad("prev_hash"))?;
        let hash = r.text().ok_or_else(|| bad("hash"))?;
        let signature = r.opt_text().ok_or_else(|| bad("signature"))?;
        let key_id = r
            .opt_text()
            .ok_or_else(|| bad("key_id"))?
            .map(std::sync::Arc::<str>::from);
        (prev_hash, hash, 0, signature, key_id)
    };
    let subject = subject_of(
        &r.text().ok_or_else(|| bad("subject"))?,
        &r.text().ok_or_else(|| bad("subject"))?,
    )
    .ok_or_else(|| bad("subject"))?;
    let what = What {
        unit_key: UnitKey::new(r.num().ok_or_else(|| bad("unit_key"))?),
        incarnation: r.num().ok_or_else(|| bad("incarnation"))?,
        op_class: OpClassId::new(r.text().ok_or_else(|| bad("op_class"))?),
        destination: r.opt_text().ok_or_else(|| bad("destination"))?,
        parent: r.opt_num().ok_or_else(|| bad("parent"))?.map(UnitKey::new),
        pre_hook_head: r.opt_text().ok_or_else(|| bad("pre_hook_head"))?,
        post_hook_head: r.opt_text().ok_or_else(|| bad("post_hook_head"))?,
    };
    let wall = r.num().ok_or_else(|| bad("wall"))?;
    let mono = r.num().ok_or_else(|| bad("mono"))?;
    let node = r.num().ok_or_else(|| bad("node"))?;
    let origin_kind =
        origin_of(&r.text().ok_or_else(|| bad("origin"))?).ok_or_else(|| bad("origin"))?;
    let unit_end =
        outcome_of(&r.text().ok_or_else(|| bad("outcome"))?).ok_or_else(|| bad("outcome"))?;
    let step = match r.opt_text().ok_or_else(|| bad("step"))? {
        None => None,
        Some(tag) => Some(step_of(&tag).ok_or_else(|| bad("step"))?),
    };
    let finish = finish_of(&r.text().ok_or_else(|| bad("finish"))?).ok_or_else(|| bad("finish"))?;
    let outcome = OutcomeFacts {
        unit_end,
        step,
        finish,
        hook_failed: r.flag().ok_or_else(|| bad("hook_failed"))?,
        emission_delta: r
            .text()
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| bad("emission_delta"))?,
        stale_policy: r.flag().ok_or_else(|| bad("stale_policy"))?,
    };
    let n = r.num().ok_or_else(|| bad("lines"))?;
    if keyed == 9 && n != 0 {
        return Err(bad("selected legacy usage lines"));
    }
    let mut lines = Vec::new();
    for _ in 0..n {
        let name = r.text().ok_or_else(|| bad("line class"))?;
        let resolved = class(&name).ok_or_else(|| {
            format!("an audit record names the class {name:?}, which no plane declares here")
        })?;
        lines.push(UsageLine {
            class: resolved,
            quantity: if recipe.exact_quantities() {
                let raw = r.text().ok_or_else(|| bad("line quantity"))?;
                let count =
                    busbar_contract::count::read_count(&raw).map_err(|_| bad("line quantity"))?;
                if count.to_decimal_string() != raw {
                    return Err(bad("noncanonical line quantity"));
                }
                count
            } else {
                r.num().ok_or_else(|| bad("line quantity"))?.into()
            },
            source: read_source(r).ok_or_else(|| bad("line source"))?,
            estimated: r.flag().ok_or_else(|| bad("line estimate"))?,
        });
    }
    let tier_bp =
        u32::try_from(r.num().ok_or_else(|| bad("tier_bp"))?).map_err(|_| bad("tier_bp"))?;
    let fee_count =
        u32::try_from(r.num().ok_or_else(|| bad("fee_count"))?).map_err(|_| bad("fee_count"))?;
    let rate_card_version = match &mut recipe {
        crate::recipe::Recipe::V5
        | crate::recipe::Recipe::V6
        | crate::recipe::Recipe::V7
        | crate::recipe::Recipe::V8
        | crate::recipe::Recipe::V9 => {
            if r.flag().ok_or_else(|| bad("rate_card_key_present"))? {
                Some(
                    r.bytes()
                        .and_then(|key| key.try_into().ok())
                        .ok_or_else(|| bad("rate_card_version key"))?,
                )
            } else {
                None
            }
        }
        crate::recipe::Recipe::V2 {
            legacy_rate_card_version,
            ..
        }
        | crate::recipe::Recipe::V4 {
            legacy_rate_card_version,
        } => {
            *legacy_rate_card_version = r.num().ok_or_else(|| bad("legacy_rate_card_version"))?;
            None
        }
    };
    let usage = Usage {
        lines,
        tier_bp,
        fee_count,
        rate_card_version,
        bucket_chain_ref: r.text().ok_or_else(|| bad("bucket_chain_ref"))?,
    };
    let mut controls = Controls {
        hold_ref: r.opt_text().ok_or_else(|| bad("hold_ref"))?,
        settle_ref: r.opt_text().ok_or_else(|| bad("settle_ref"))?,
        slice_ref: r.opt_text().ok_or_else(|| bad("slice_ref"))?,
        lease_ref: r.opt_text().ok_or_else(|| bad("lease_ref"))?,
        lease_epoch: r.num().ok_or_else(|| bad("lease_epoch"))?,
        policy_epoch: r.num().ok_or_else(|| bad("policy_epoch"))?,
        ..Controls::default()
    };
    for _ in 0..r.num().ok_or_else(|| bad("hooks"))? {
        controls.hooks_applied.push(HookApplied {
            hook: crate::off_path::read_text(
                r.bytes()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .ok_or_else(|| bad("hook"))?,
            ),
            head: r
                .text()
                .as_deref()
                .and_then(HookHead::from_tag)
                .ok_or_else(|| bad("hook head"))?,
            failed: r.flag().ok_or_else(|| bad("hook failed"))?,
        });
    }
    controls.replayed = r.flag().ok_or_else(|| bad("replayed"))?;
    for _ in 0..r.num().ok_or_else(|| bad("children"))? {
        controls
            .children
            .push(UnitKey::new(r.num().ok_or_else(|| bad("child"))?));
    }
    let correlation_hash = r.opt_text().ok_or_else(|| bad("correlation_hash"))?;
    let unit = if recipe.carries_unit_facts() {
        read_unit_facts(r, keyed == 9).ok_or_else(|| bad("unit facts"))?
    } else {
        UnitFacts::default()
    };
    if r.at != r.bytes.len() {
        return Err(bad("tail"));
    }
    let record = AuditRecord {
        subject,
        what,
        wall,
        mono,
        node,
        origin_kind,
        outcome,
        usage,
        controls,
        correlation_hash,
        unit,
        linked_ms,
        seq,
        prev_hash,
        recipe,
        hash,
        signature,
        key_id,
    };
    if !crate::record::billing::record_valid(&record) {
        return Err(bad("billing representation"));
    }
    Ok(record)
}

/// The `v7` tail, as [`crate::journal::journal_body`] writes it. More attempts than there are
/// slots, an unknown outcome or a nonce that is not 16 bytes refuses the record.
fn read_unit_facts(r: &mut Reader<'_>, billing: bool) -> Option<UnitFacts> {
    let mut unit = UnitFacts {
        wall_ms: r.num()?,
        attribution: r.text()?,
        boot_nonce: r.bytes()?.try_into().ok()?,
        status: u16::try_from(r.num()?).ok()?,
        ttft_us: r.num()?,
        total_us: r.num()?,
        ..UnitFacts::default()
    };
    let used = usize::try_from(r.num()?).ok()?;
    if used > ATTEMPT_SLOTS {
        return None;
    }
    for slot in unit.attempts.iter_mut().take(used) {
        *slot = Some(Attempt {
            outcome: AttemptOutcome::from_tag(&r.text()?)?,
            target: crate::off_path::read_text(std::str::from_utf8(r.bytes()?).ok()?),
            reason: crate::off_path::read_text(std::str::from_utf8(r.bytes()?).ok()?),
            us: r.num()?,
        });
    }
    unit.attempts_total = u32::try_from(r.num()?).ok()?;
    // The optional records tail (§3.5): present only when the record keeps a user or a label, so
    // a body that ends here is a `v7` body with neither. An empty tail is refused: it is not how
    // the writer frames anything, and a second spelling of one record is not admitted.
    if billing || !r.done() {
        unit.records.user = if billing {
            let present = r.flag()?;
            let text = r.bounded_text(4096)?;
            if present {
                Some(text)
            } else {
                if !text.is_empty() {
                    return None;
                }
                None
            }
        } else {
            r.opt_text()?
        };
        let labels = usize::try_from(r.num()?).ok()?;
        if labels > LABEL_SLOTS {
            return None;
        }
        unit.records.labels.reserve_exact(labels);
        for _ in 0..labels {
            let name = if billing {
                r.bounded_text(4096)?
            } else {
                r.text()?
            };
            let value = if billing {
                r.bounded_text(4096)?
            } else {
                r.text()?
            };
            unit.records
                .labels
                .push((std::sync::Arc::from(name), value));
        }
        if unit.records.is_empty() && !billing {
            return None;
        }
    }
    if billing {
        unit.billing = Some(crate::record::billing::PartitionedBillingV1::read(r)?);
    }
    Some(unit)
}

fn read_source(r: &mut Reader<'_>) -> Option<QuantitySource> {
    use busbar_contract::ClassDirection;
    Some(match r.num()? {
        0 => QuantitySource::Count,
        1 => QuantitySource::TransportUnits,
        2 => QuantitySource::KernelElapsedMono,
        3 => QuantitySource::KernelBytes { divisor: r.num()? },
        4 => QuantitySource::KernelFrames { factor: r.num()? },
        5 => {
            let tag = r.text()?;
            let direction = [
                ClassDirection::Input,
                ClassDirection::Response,
                ClassDirection::CacheRead,
                ClassDirection::CacheWrite,
                ClassDirection::Kernel,
            ]
            .into_iter()
            .find(|d| direction_tag(*d) == tag)?;
            QuantitySource::Locator {
                direction,
                ptr: busbar_contract::caps::LocatorPtr::new(r.text()?),
            }
        }
        6 => QuantitySource::PlaneCount {
            content_fact_key: r.text()?,
        },
        _ => return None,
    })
}

/// The subject a sealed body's two frozen fields name — through the ONE decoder the amendment
pub(crate) fn subject_of(tag: &str, value: &str) -> Option<Subject> {
    crate::amend::subject_from_fields(tag, value)
}

fn origin_of(name: &str) -> Option<&'static str> {
    use busbar_contract::caps::OriginKind;
    let parent = UnitKey::new(0);
    [
        OriginKind::Client,
        OriginKind::Provider,
        OriginKind::Tick,
        OriginKind::Arrival,
        OriginKind::Handshake,
        OriginKind::Bootstrap,
        OriginKind::Nested { parent },
        OriginKind::Delivery { parent },
    ]
    .into_iter()
    .map(OriginKind::as_str)
    .find(|s| *s == name)
}

fn step_of(tag: &str) -> Option<StepName> {
    StepName::ALL.into_iter().find(|s| step_tag(*s) == tag)
}

fn reason_of(tag: &str) -> Option<ReasonCode> {
    ReasonCode::ALL
        .iter()
        .copied()
        .find(|r| displays_as(ReasonTag(*r), tag))
}

fn finish_of(tag: &str) -> Option<FinishClass> {
    [
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Partial,
        FinishClass::Error,
    ]
    .into_iter()
    .find(|f| finish_tag(*f) == tag)
}

/// The inverse of [`OutcomeTag`](crate::record::OutcomeTag), checked by re-rendering: an outcome is accepted only when it
pub(crate) fn outcome_of(tag: &str) -> Option<Outcome> {
    let outcome = if tag == "Completed" {
        Outcome::Completed
    } else if let Some(inner) = tag
        .strip_prefix("TimedOut(")
        .and_then(|t| t.strip_suffix(')'))
    {
        Outcome::TimedOut(step_of(inner)?)
    } else if let Some(inner) = tag
        .strip_prefix("Refused(")
        .and_then(|t| t.strip_suffix(')'))
    {
        let (step, reason) = inner.split_once(", ")?;
        Outcome::Refused(step_of(step)?, reason_of(reason)?)
    } else if let Some(inner) = tag
        .strip_prefix("Failed(")
        .and_then(|t| t.strip_suffix(')'))
    {
        let (step, reason) = inner.split_once(", ")?;
        Outcome::Failed(step_of(step)?, reason_of(reason)?)
    } else {
        let inner = tag.strip_prefix("Aborted(")?.strip_suffix(')')?;
        Outcome::Aborted(abort_of(inner)?)
    };
    displays_as(OutcomeTag(outcome), tag).then_some(outcome)
}

fn abort_of(tag: &str) -> Option<Abort> {
    let abort = if let Some(reason) = tag
        .strip_prefix("Kernel { reason: ")
        .and_then(|t| t.strip_suffix(" }"))
    {
        Abort::Kernel {
            reason: reason_of(reason)?,
        }
    } else {
        let by = tag
            .strip_prefix("Superseded { by: UnitKey(")
            .and_then(|t| t.strip_suffix(") }"))?;
        Abort::Superseded {
            by: UnitKey::new(by.parse().ok()?),
        }
    };
    displays_as(AbortTag(abort), tag).then_some(abort)
}

/// The body reader: the inverse of [`crate::journal::Writer`].
pub(crate) struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Reader<'b> {
    /// A reader at the start of `bytes`.
    pub(crate) fn new(bytes: &'b [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    /// Whether every byte has been read.
    pub(crate) fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    pub(crate) fn num(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A length-prefixed run of exactly 32 bytes.
    pub(crate) fn fingerprint(&mut self) -> Option<Fingerprint> {
        Some(Fingerprint(self.bytes()?.try_into().ok()?))
    }

    fn flag(&mut self) -> Option<bool> {
        match self.num()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub(crate) fn bytes(&mut self) -> Option<&[u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        self.take(len)
    }

    pub(crate) fn text(&mut self) -> Option<String> {
        let text = String::from_utf8(self.bytes()?.to_vec()).ok();
        text
    }

    pub(crate) fn bounded_text(&mut self, limit: usize) -> Option<String> {
        let bytes = self.bytes()?;
        if bytes.len() > limit {
            return None;
        }
        Some(std::str::from_utf8(bytes).ok()?.into())
    }

    fn skip_text(&mut self) -> Option<()> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        std::str::from_utf8(self.take(len)?).ok()?;
        Some(())
    }

    fn skip_opt_text(&mut self) -> Option<()> {
        match self.num()? {
            0 => Some(()),
            1 => self.skip_text(),
            _ => None,
        }
    }

    fn opt_text(&mut self) -> Option<Option<String>> {
        match self.num()? {
            0 => Some(None),
            1 => Some(Some(self.text()?)),
            _ => None,
        }
    }

    fn opt_num(&mut self) -> Option<Option<u64>> {
        match self.num()? {
            0 => Some(None),
            1 => Some(Some(self.num()?)),
            _ => None,
        }
    }
}
