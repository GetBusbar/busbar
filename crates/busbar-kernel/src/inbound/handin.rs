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
        use zeroize::Zeroize as _;
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::StripScan);
        let mut head = self.duplicate();
        head.fields.retain_mut(|(name, value)| {
            let remove = strips.iter().any(|strip| {
                strip.place == StripPlace::Field && strip.name.eq_ignore_ascii_case(name)
            });
            if remove {
                value.zeroize();
            }
            !remove
        });
        let keys: Vec<&str> = strips
            .iter()
            .filter(|strip| strip.place == StripPlace::Query)
            .map(|strip| strip.name.as_ref())
            .collect();
        if !keys.is_empty() {
            if let Some(stripped) = head
                .query
                .as_deref()
                .and_then(|query| crate::auth::without_query_keys_text(query, &keys))
            {
                let mut original =
                    std::mem::replace(&mut head.query, (!stripped.is_empty()).then_some(stripped));
                if let Some(query) = &mut original {
                    query.zeroize();
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
