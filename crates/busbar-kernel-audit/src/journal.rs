// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed record, as the node's journal keeps it: `audit.v4`.
//!
//! The journal is the source of truth for the fixed audit chain. A node keeps its newest records in
//! memory as a cache and answers an older window by decoding them back off the journal, so this
//! body carries the WHOLE record — every field the digest frames, in a lossless form, plus the
//! recipe it was sealed under, its digest, its signature and the key that made it. Decoding one
//! and recomputing its digest must give the digest it carries; a record that does not is tampered,
//! and the chain walk says so.
//!
//! The framing is this crate's own and deliberately dull: a text is a big-endian `u32` length and
//! its bytes, a number is a big-endian `u64`, an optional value is a presence number and then the
//! value. The body opens with [`JOURNAL_TAG`], so a journal record that is not an audit record is
//! told apart before anything is parsed.
//!
//! One thing the body cannot carry by value is a usage line's CLASS: the record holds the
//! registered static name ([`busbar_contract::MeterClassId`]), never an owned string, so a class is
//! resolved against the node's registered vocabulary on the way back in. A class the vocabulary does
//! not hold is an error the caller reports — never a line dropped.

use busbar_contract::caps::{Abort, MeterClassId, Outcome, ReasonCode, StepName, UnitKey};

use crate::record::{
    abort_tag, direction_tag, finish_tag, outcome_tag, reason_tag, step_tag, AuditRecord, Controls,
    FinishClass, HookApplied, OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine,
    What,
};

/// The tag every journalled audit record opens with.
pub const JOURNAL_TAG: &str = "audit.v4";

/// The journal body of one sealed record.
#[must_use]
pub fn journal_body(record: &AuditRecord) -> Vec<u8> {
    let mut w = Writer::default();
    w.text(JOURNAL_TAG);
    w.text(record.recipe.name());
    if let crate::recipe::Recipe::V2 { currency } = &record.recipe {
        w.text(currency);
    }
    w.num(record.seq);
    w.text(&record.prev_hash);
    w.text(&record.hash);
    w.opt_text(record.signature.as_deref());
    w.opt_text(record.key_id.as_deref());
    w.text(crate::record::subject_tag(&record.subject));
    w.text(&crate::record::subject_value(&record.subject));
    w.num(record.what.unit_key.get());
    w.num(record.what.incarnation);
    w.text(record.what.op_class.as_str());
    w.opt_text(record.what.destination.as_deref());
    w.opt_num(record.what.parent.map(UnitKey::get));
    w.opt_text(record.what.pre_hook_head.as_deref());
    w.opt_text(record.what.post_hook_head.as_deref());
    w.num(record.wall);
    w.num(record.mono);
    w.text(record.origin_kind);
    w.text(&outcome_tag(record.outcome.unit_end));
    w.opt_text(record.outcome.step.map(step_tag));
    w.text(finish_tag(record.outcome.finish));
    w.num(u64::from(record.outcome.hook_failed));
    w.text(&record.outcome.emission_delta.to_string());
    w.num(u64::from(record.outcome.stale_policy));
    w.num(record.usage.lines.len() as u64);
    for line in &record.usage.lines {
        w.text(line.class.as_str());
        w.num(line.quantity);
        write_source(&mut w, &line.source);
        w.num(u64::from(line.estimated));
    }
    w.num(u64::from(record.usage.tier_bp));
    w.num(u64::from(record.usage.fee_count));
    w.num(record.usage.rate_card_version);
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
    }
    w.num(u64::from(c.replayed));
    w.num(c.children.len() as u64);
    for child in &c.children {
        w.num(child.get());
    }
    w.opt_text(record.correlation_hash.as_deref());
    w.0
}

/// Read a journal body back into the record it keeps.
///
/// `Ok(None)` is a body that is not an audit record at all. `class` resolves a usage line's class
/// name to the registered static name; a class it cannot resolve, and any body that does not parse
/// to the end, is an `Err` naming what was wrong.
///
/// # Errors
///
/// The body opens with [`JOURNAL_TAG`] and does not decode, or names a class `class` cannot resolve.
pub fn from_journal_body(
    bytes: &[u8],
    class: &dyn Fn(&str) -> Option<MeterClassId>,
) -> Result<Option<AuditRecord>, String> {
    let mut r = Reader { bytes, at: 0 };
    if r.text().as_deref() != Some(JOURNAL_TAG) {
        return Ok(None);
    }
    decode(&mut r, class).map(Some)
}

fn decode(
    r: &mut Reader<'_>,
    class: &dyn Fn(&str) -> Option<MeterClassId>,
) -> Result<AuditRecord, String> {
    let bad = |what: &str| format!("an audit record whose {what} does not decode");
    let recipe = match r.text().ok_or_else(|| bad("recipe"))?.as_str() {
        crate::recipe::DIGEST_RECIPE => crate::recipe::Recipe::V4,
        crate::recipe::DIGEST_RECIPE_V3 => crate::recipe::Recipe::V3,
        crate::recipe::DIGEST_RECIPE_V2 => crate::recipe::Recipe::V2 {
            currency: r.text().ok_or_else(|| bad("currency"))?,
        },
        other => {
            return Err(format!(
                "an audit record sealed under an unknown recipe {other:?}"
            ))
        }
    };
    let seq = r.num().ok_or_else(|| bad("seq"))?;
    let prev_hash = r.text().ok_or_else(|| bad("prev_hash"))?;
    let hash = r.text().ok_or_else(|| bad("hash"))?;
    let signature = r.opt_text().ok_or_else(|| bad("signature"))?;
    let key_id = r.opt_text().ok_or_else(|| bad("key_id"))?;
    let subject = subject_of(
        &r.text().ok_or_else(|| bad("subject"))?,
        r.text().ok_or_else(|| bad("subject"))?,
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
    let mut lines = Vec::new();
    for _ in 0..n {
        let name = r.text().ok_or_else(|| bad("line class"))?;
        let resolved = class(&name).ok_or_else(|| {
            format!("an audit record names the class {name:?}, which no plane declares here")
        })?;
        lines.push(UsageLine {
            class: resolved,
            quantity: r.num().ok_or_else(|| bad("line quantity"))?,
            source: read_source(r).ok_or_else(|| bad("line source"))?,
            estimated: r.flag().ok_or_else(|| bad("line estimate"))?,
        });
    }
    let usage = Usage {
        lines,
        tier_bp: u32::try_from(r.num().ok_or_else(|| bad("tier_bp"))?)
            .map_err(|_| bad("tier_bp"))?,
        fee_count: u32::try_from(r.num().ok_or_else(|| bad("fee_count"))?)
            .map_err(|_| bad("fee_count"))?,
        rate_card_version: r.num().ok_or_else(|| bad("rate_card_version"))?,
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
            hook: r.text().ok_or_else(|| bad("hook"))?,
        });
    }
    controls.replayed = r.flag().ok_or_else(|| bad("replayed"))?;
    for _ in 0..r.num().ok_or_else(|| bad("children"))? {
        controls
            .children
            .push(UnitKey::new(r.num().ok_or_else(|| bad("child"))?));
    }
    let correlation_hash = r.opt_text().ok_or_else(|| bad("correlation_hash"))?;
    if r.at != r.bytes.len() {
        return Err(bad("tail"));
    }
    Ok(AuditRecord {
        subject,
        what,
        wall,
        mono,
        origin_kind,
        outcome,
        usage,
        controls,
        correlation_hash,
        seq,
        prev_hash,
        recipe,
        hash,
        signature,
        key_id,
    })
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

fn subject_of(tag: &str, value: String) -> Option<Subject> {
    Some(match tag {
        "principal" => Subject::PrincipalId(value),
        "arrival" => Subject::Arrival,
        "aggregate" => Subject::Aggregate,
        "node" => Subject::Node(value.parse().ok()?),
        _ => return None,
    })
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
        .find(|r| reason_tag(*r) == tag)
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

/// The inverse of [`outcome_tag`], checked by re-rendering: an outcome is accepted only when it
/// renders back to exactly the tag that was read.
fn outcome_of(tag: &str) -> Option<Outcome> {
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
    (outcome_tag(outcome) == tag).then_some(outcome)
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
    (abort_tag(abort) == tag).then_some(abort)
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn text(&mut self, s: &str) {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(&s.as_bytes()[..len as usize]);
    }

    fn num(&mut self, n: u64) {
        self.0.extend_from_slice(&n.to_be_bytes());
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

struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn num(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn flag(&mut self) -> Option<bool> {
        match self.num()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn text(&mut self) -> Option<String> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        String::from_utf8(self.take(len)?.to_vec()).ok()
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
