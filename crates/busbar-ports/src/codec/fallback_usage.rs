// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Validation against one frozen plane declaration. No routing, mutable accounting or settlement.

use busbar_plugin_abi::fallback_usage::{self as wire, MAX_CLASSES};
pub use busbar_plugin_abi::fallback_usage::{
    AttemptEnd, AttemptUsage, Completeness, Estimate, EstimateValue, PreparedEstimates,
    SelectedResource, UsageSource,
};
use busbar_plugin_abi::plane::{self as p, tag};
use busbar_plugin_abi::records::{RecErr, Records};

use crate::plane::UsageClass;

/// Borrowed from the same admitted instance generation; never reconstructed from output facts.
#[derive(Clone, Copy)]
pub struct Declaration<'a> {
    facts: u64,
    classes: &'a [UsageClass],
    attempt_classes: &'a [Box<str>],
}

/// Host lifecycle facts. This validator does not mint the selected/prepared/committed seal.
#[derive(Clone, Copy)]
pub struct AttemptState {
    /// The preparation ordinal bound by the host's current active attempt seal.
    pub attempt: u32,
    pub exchange: u32,
    pub sealed: bool,
}

fn check(ok: bool) -> Result<(), RecErr> {
    if ok {
        Ok(())
    } else {
        Err(RecErr::Size)
    }
}

impl<'a> Declaration<'a> {
    pub const fn legacy() -> Self {
        Self {
            facts: 0,
            classes: &[],
            attempt_classes: &[],
        }
    }

    pub fn new(
        facts: u64,
        classes: &'a [UsageClass],
        attempt_classes: &'a [Box<str>],
    ) -> Result<Self, RecErr> {
        let usage = facts & p::FB_ATTEMPT_USAGE != 0;
        check(usage != attempt_classes.is_empty())?;
        if facts & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0 {
            check(classes.len() <= MAX_CLASSES)?;
            for (index, class) in classes.iter().enumerate() {
                wire::class_text(class.class.as_bytes())?;
                check(!classes[..index].iter().any(|old| old.class == class.class))?;
            }
        }
        check(attempt_classes.len() <= MAX_CLASSES)?;
        for (index, class) in attempt_classes.iter().enumerate() {
            wire::class_text(class.as_bytes())?;
            check(
                !attempt_classes[..index].contains(class)
                    && classes.iter().any(|declared| declared.class == *class),
            )?;
        }
        if usage {
            check(
                classes
                    .iter()
                    .filter(|class| class.unit == p::UNIT_TOKENS)
                    .all(|class| attempt_classes.contains(&class.class)),
            )?;
        }
        Ok(Self {
            facts,
            classes,
            attempt_classes,
        })
    }

    pub const fn facts(self) -> u64 {
        self.facts
    }

    pub fn is_attempt_class(self, class: &str) -> bool {
        self.attempt_classes
            .iter()
            .any(|declared| &**declared == class)
    }

    /// Physical token identities from this exact validated instance generation. Native names
    /// remain borrowed here; a retained attempt owns bounded copies, never a global intern.
    pub fn physical_classes(self) -> impl Iterator<Item = &'a str> {
        self.classes
            .iter()
            .filter(|class| class.unit == p::UNIT_TOKENS)
            .map(|class| class.class.as_ref())
    }

    /// Validate all preparation facts before any callback or candidate estimate replacement.
    pub fn validate_preparation<'r>(
        self,
        expected: Option<SelectedResource<'_>>,
        records: Records<'r>,
    ) -> Result<Option<PreparedEstimates<'r>>, RecErr> {
        let enabled = self.facts & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0;
        let mut selected = None;
        let mut prepared = None;
        let mut declined = false;
        for record in records {
            let record = record?;
            match record.tag {
                tag::SELECTED_RESOURCE => {
                    check(enabled && selected.is_none())?;
                    selected = Some(wire::decode_selected(record)?);
                }
                tag::PREPARED_ESTIMATES => {
                    check(self.facts & p::FB_PREPARED_ESTIMATES != 0 && prepared.is_none())?;
                    prepared = Some(wire::decode_prepared(record)?);
                }
                tag::ATTEMPT => {
                    let (attempt, _) = record.pod_tail::<p::AttemptRec>()?;
                    declined |= attempt.verdict == p::ATT_DECLINE;
                }
                _ => {}
            }
        }
        if !enabled || declined {
            check(selected.is_none() && prepared.is_none())?;
            return Ok(None);
        }
        let expected = expected.ok_or(RecErr::Size)?;
        expected.validate()?;
        check(selected == Some(expected))?;
        if self.facts & p::FB_PREPARED_ESTIMATES == 0 {
            return Ok(None);
        }
        let prepared = prepared.ok_or(RecErr::Size)?;
        check(prepared.attempt == expected.attempt && prepared.exchange == expected.exchange)?;
        let mut count = 0;
        for entry in prepared.entries() {
            let entry = entry?;
            check(
                self.classes
                    .iter()
                    .any(|class| &*class.class == entry.class),
            )?;
            count += 1;
        }
        // Structural decoding already rejected duplicates. Equal cardinality now proves complete coverage.
        check(count == self.classes.len())?;
        Ok(Some(prepared))
    }

    /// Call for every session USAGE, OBS_COUNT and observation-scope class binding in an opted-in
    /// forwarded session, before creating/attaching a paid scope or publishing any side effect.
    pub fn validate_session_class(self, class: &str) -> Result<(), RecErr> {
        check(!self.is_attempt_class(class))
    }

    pub fn validate_observation_counts(self, records: Records<'_>) -> Result<(), RecErr> {
        for record in records {
            let record = record?;
            check(record.tag == tag::OBS_COUNT)?;
            let (usage, tail) = record.pod_tail::<p::UsageRec>()?;
            check(usage.scale <= 9)?;
            UsageSource::from_code(usage.source)?;
            self.validate_session_class(wire::class_text(tail)?)?;
        }
        Ok(())
    }

    fn validate_current(self, state: AttemptState, attempt: u32) -> Result<(), RecErr> {
        check(
            self.facts & p::FB_ATTEMPT_USAGE != 0
                && !state.sealed
                && state.exchange == 0
                && attempt == state.attempt,
        )
    }

    pub fn validate_attempt_usage(
        self,
        state: AttemptState,
        usage: AttemptUsage<'_>,
    ) -> Result<(), RecErr> {
        self.validate_current(state, usage.attempt)?;
        check(usage.scale <= 9 && self.is_attempt_class(usage.class))
    }

    /// `reported_classes` must be the current partition's staged SRC_REPORTED presence, including
    /// explicit zero. Floors/estimates must never enter this set. Validate the whole answer first.
    pub fn validate_attempt_end(
        self,
        state: AttemptState,
        end: AttemptEnd,
        reported_classes: &[&str],
    ) -> Result<(), RecErr> {
        self.validate_current(state, end.attempt)?;
        if end.completeness == Completeness::Complete {
            check(
                self.classes
                    .iter()
                    .filter(|class| class.unit == p::UNIT_TOKENS)
                    .all(|class| reported_classes.contains(&class.class.as_ref())),
            )?;
        }
        Ok(())
    }
}
