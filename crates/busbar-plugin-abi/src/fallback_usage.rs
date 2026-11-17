// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Typed selected preparation and cumulative attempt facts. No policy, pricing or host authority.

use crate::plane::{self as p, tag};
use crate::records::{Full, Rec, RecErr, Records, Reply, Writer};

pub const MAX_CLASSES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EstimateValue {
    Known { amount: u64, scale: u32 },
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageSource {
    Reported,
    Estimated,
    Floor,
}

impl UsageSource {
    pub const fn code(self) -> u32 {
        match self {
            Self::Reported => p::SRC_REPORTED,
            Self::Estimated => p::SRC_ESTIMATED,
            Self::Floor => p::SRC_FLOOR,
        }
    }

    pub fn from_code(code: u32) -> Result<Self, RecErr> {
        match code {
            p::SRC_REPORTED => Ok(Self::Reported),
            p::SRC_ESTIMATED => Ok(Self::Estimated),
            p::SRC_FLOOR => Ok(Self::Floor),
            _ => Err(RecErr::Size),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    Partial,
    Unknown,
}

impl Completeness {
    pub const fn code(self) -> u32 {
        match self {
            Self::Complete => 1,
            Self::Partial => 2,
            Self::Unknown => 3,
        }
    }

    pub fn from_code(code: u32) -> Result<Self, RecErr> {
        match code {
            1 => Ok(Self::Complete),
            2 => Ok(Self::Partial),
            3 => Ok(Self::Unknown),
            _ => Err(RecErr::Size),
        }
    }
}

/// Correlation metadata only. The host separately retains its selected/prepared authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedResource<'a> {
    pub attempt: u32,
    pub exchange: u32,
    pub resource: &'a str,
}

impl SelectedResource<'_> {
    pub fn validate(self) -> Result<(), RecErr> {
        check(
            self.exchange == 0
                && self.resource.len() <= 128
                && !self.resource.chars().any(char::is_control),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estimate<'a> {
    pub class: &'a str,
    pub value: EstimateValue,
}

#[derive(Clone, Copy, Debug)]
pub struct PreparedEstimates<'a> {
    pub attempt: u32,
    pub exchange: u32,
    entries: &'a [u8],
}

impl<'a> PreparedEstimates<'a> {
    pub fn entries(&self) -> impl Iterator<Item = Result<Estimate<'a>, RecErr>> + 'a {
        Records::new(self.entries).map(|record| decode_estimate(record?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptUsage<'a> {
    /// Target.attempt: host preparation ordinal, including unsent preparations; never dispatch count.
    pub attempt: u32,
    pub class: &'a str,
    pub amount: u64,
    pub scale: u32,
    pub source: UsageSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptEnd {
    /// The current Target.attempt preparation ordinal, not an arbitrary retained partition selector.
    pub attempt: u32,
    pub completeness: Completeness,
}

pub fn class_text(bytes: &[u8]) -> Result<&str, RecErr> {
    check(
        (1..=64).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':')),
    )?;
    core::str::from_utf8(bytes).map_err(|_| RecErr::Utf8)
}

fn check(ok: bool) -> Result<(), RecErr> {
    if ok { Ok(()) } else { Err(RecErr::Size) }
}

fn require_tag(rec: &Rec<'_>, tag: u16) -> Result<(), RecErr> {
    if rec.tag == tag {
        Ok(())
    } else {
        Err(RecErr::Unknown(rec.tag))
    }
}

pub fn decode_selected(rec: Rec<'_>) -> Result<SelectedResource<'_>, RecErr> {
    require_tag(&rec, tag::SELECTED_RESOURCE)?;
    let (head, tail) = rec.pod_tail::<p::SelectedResourceRec>()?;
    let selected = SelectedResource {
        attempt: head.attempt,
        exchange: head.exchange,
        resource: core::str::from_utf8(tail).map_err(|_| RecErr::Utf8)?,
    };
    selected.validate()?;
    Ok(selected)
}

/// Read this feature's one selected input from the shared Target.admission record block.
/// Other owner-assigned records are left to their owning validator.
pub fn selected_from_admission(bytes: &[u8]) -> Result<Option<SelectedResource<'_>>, RecErr> {
    let mut selected = None;
    for record in Records::new(bytes) {
        let record = record?;
        if record.tag == tag::SELECTED_RESOURCE {
            check(selected.replace(decode_selected(record)?).is_none())?;
        }
    }
    Ok(selected)
}

fn decode_estimate(rec: Rec<'_>) -> Result<Estimate<'_>, RecErr> {
    require_tag(&rec, tag::PREPARED_ESTIMATE)?;
    let (head, tail) = rec.pod_tail::<p::PreparedEstimateRec>()?;
    let class = class_text(tail)?;
    let value = match head.knowledge {
        1 if head.scale <= 9 => EstimateValue::Known {
            amount: head.amount,
            scale: head.scale,
        },
        2 if head.amount == 0 && head.scale == 0 => EstimateValue::Unknown,
        _ => return Err(RecErr::Size),
    };
    Ok(Estimate { class, value })
}

pub fn decode_prepared(rec: Rec<'_>) -> Result<PreparedEstimates<'_>, RecErr> {
    require_tag(&rec, tag::PREPARED_ESTIMATES)?;
    let (head, tail) = rec.pod_tail::<p::PreparedEstimatesRec>()?;
    check(head.exchange == 0)?;
    let view = PreparedEstimates {
        attempt: head.attempt,
        exchange: head.exchange,
        entries: tail,
    };
    let mut names = [None; MAX_CLASSES];
    for (index, entry) in view.entries().enumerate() {
        let entry = entry?;
        check(index < MAX_CLASSES && !names.contains(&Some(entry.class)))?;
        names[index] = Some(entry.class);
    }
    Ok(view)
}

pub fn decode_attempt_usage(rec: Rec<'_>) -> Result<AttemptUsage<'_>, RecErr> {
    require_tag(&rec, tag::ATTEMPT_USAGE)?;
    let (head, tail) = rec.pod_tail::<p::AttemptUsageRec>()?;
    if head._r != 0 {
        return Err(RecErr::Reserved);
    }
    check(head.usage.scale <= 9)?;
    Ok(AttemptUsage {
        attempt: head.attempt,
        class: class_text(tail)?,
        amount: head.usage.amount,
        scale: head.usage.scale,
        source: UsageSource::from_code(head.usage.source)?,
    })
}

pub fn decode_attempt_end(rec: Rec<'_>) -> Result<AttemptEnd, RecErr> {
    require_tag(&rec, tag::ATTEMPT_USAGE_END)?;
    let head = rec.pod::<p::AttemptUsageEndRec>()?;
    Ok(AttemptEnd {
        attempt: head.attempt,
        completeness: Completeness::from_code(head.completeness)?,
    })
}

#[derive(Debug)]
pub enum EncodeError {
    Invalid(RecErr),
    Full,
}

impl From<RecErr> for EncodeError {
    fn from(error: RecErr) -> Self {
        Self::Invalid(error)
    }
}

impl From<Full> for EncodeError {
    fn from(_: Full) -> Self {
        Self::Full
    }
}

pub fn write_selected(
    writer: &mut impl Writer,
    selected: SelectedResource<'_>,
) -> Result<(), EncodeError> {
    selected.validate()?;
    Ok(writer.put_pod_tail(
        tag::SELECTED_RESOURCE,
        &p::SelectedResourceRec {
            attempt: selected.attempt,
            exchange: selected.exchange,
        },
        selected.resource.as_bytes(),
    )?)
}

/// Encode one complete-view container atomically. The host checks exact declared coverage.
pub fn write_prepared_estimates(
    writer: &mut impl Writer,
    selected: SelectedResource<'_>,
    entries: &[Estimate<'_>],
) -> Result<(), EncodeError> {
    selected.validate()?;
    check(entries.len() <= MAX_CLASSES)?;
    let mut tail = Reply::new();
    for (index, entry) in entries.iter().enumerate() {
        class_text(entry.class.as_bytes())?;
        check(!entries[..index].iter().any(|old| old.class == entry.class))?;
        let (amount, scale, knowledge) = match entry.value {
            EstimateValue::Known { amount, scale } if scale <= 9 => (amount, scale, 1),
            EstimateValue::Unknown => (0, 0, 2),
            _ => return Err(RecErr::Size.into()),
        };
        tail.put_pod_tail(
            tag::PREPARED_ESTIMATE,
            &p::PreparedEstimateRec {
                amount,
                scale,
                knowledge,
            },
            entry.class.as_bytes(),
        )?;
    }
    Ok(writer.put_pod_tail(
        tag::PREPARED_ESTIMATES,
        &p::PreparedEstimatesRec {
            attempt: selected.attempt,
            exchange: selected.exchange,
        },
        tail.as_bytes(),
    )?)
}

pub fn write_attempt_usage(
    writer: &mut impl Writer,
    usage: AttemptUsage<'_>,
) -> Result<(), EncodeError> {
    class_text(usage.class.as_bytes())?;
    check(usage.scale <= 9)?;
    Ok(writer.put_pod_tail(
        tag::ATTEMPT_USAGE,
        &p::AttemptUsageRec {
            attempt: usage.attempt,
            _r: 0,
            usage: p::UsageRec {
                amount: usage.amount,
                scale: usage.scale,
                source: usage.source.code(),
            },
        },
        usage.class.as_bytes(),
    )?)
}

pub fn write_attempt_end(writer: &mut impl Writer, end: AttemptEnd) -> Result<(), EncodeError> {
    Ok(writer.put_pod(
        tag::ATTEMPT_USAGE_END,
        &p::AttemptUsageEndRec {
            attempt: end.attempt,
            completeness: end.completeness.code(),
        },
    )?)
}

pub fn write_attempt_class(writer: &mut impl Writer, class: &str) -> Result<(), EncodeError> {
    class_text(class.as_bytes())?;
    Ok(writer.put_text(tag::D_ATTEMPT_CLASS, class)?)
}
