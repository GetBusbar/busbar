// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHETHER A HANDED HEAD IS THE UNIT'S OWN, WITH ITS STRIPS APPLIED.
//!
//! LINT-RULES R23 (derive-once): the stripped view of a unit's original head is derived here
//! only, by [`handin_state_matches`]. [`Head::stripped`] is private to this module, so no other
//! production code can strip the raw head a second time.

use busbar_contract::auth_calls::{Strip, StripPlace};

use super::{same_request, HandIn, Head};

impl Head {
    fn stripped(&self, strips: &[Strip]) -> Option<Self> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::StripScan);
        // Only the kept field lines are copied: a stripped credential is never duplicated.
        let mut head = Self {
            method: self.method.clone(),
            target: self.target.clone(),
            authority: self.authority.clone(),
            query: self.query.clone(),
            fields: Vec::with_capacity(self.fields.len()),
        };
        head.fields.extend(
            self.fields
                .iter()
                .filter(|(name, _)| {
                    !strips.iter().any(|strip| {
                        strip.place == StripPlace::Field && strip.name.eq_ignore_ascii_case(name)
                    })
                })
                .cloned(),
        );
        let is_key = |key: &str| {
            strips
                .iter()
                .any(|strip| strip.place == StripPlace::Query && &*strip.name == key)
        };
        if strips.iter().any(|strip| strip.place == StripPlace::Query) {
            if let Some(stripped) = head
                .query
                .as_deref()
                .and_then(|query| crate::auth::without_query_text_where(query, &is_key))
            {
                let original =
                    std::mem::replace(&mut head.query, (!stripped.is_empty()).then_some(stripped));
                if let Some(query) = original {
                    // Into custody, whose drop wipes it.
                    drop(busbar_contract::secure::SecureString::from(query));
                }
            }
        }
        Some(head)
    }

    /// The tests build stripped heads the way the hand-in check does.
    #[cfg(test)]
    pub(super) fn stripped_for_test(&self, strips: &[Strip]) -> Option<Self> {
        self.stripped(strips)
    }
}

pub(super) fn handin_state_matches(
    unit_line: u32,
    generation: u64,
    signed_pending: bool,
    original: Option<&Head>,
    strips: &[Strip],
    h: &HandIn,
) -> bool {
    if unit_line != h.line || generation != h.generation || signed_pending {
        return false;
    }
    if let Some(original) = original {
        if !original
            .stripped(strips)
            .is_some_and(|original| same_request(&original, &h.head))
        {
            return false;
        }
    }
    true
}
