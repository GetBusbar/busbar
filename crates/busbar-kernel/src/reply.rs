// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which reply wakes which waiting unit.
//!
//! A leg planned as [`ClientMode::AwaitReply`] does not finish when it is sent; it finishes when an
//! answer carrying the right correlation comes back. Deciding *which* answer is the whole of this
//! file, and it is the kernel's job rather than a plane's because a plane sees one unit at a time
//! and the collision it has to avoid is between two of them.
//!
//! ## The two halves of a correlation, and why they are separate
//!
//! The sealed destination names the KEY (`&'static str`) and nothing else. It has to: a verified
//! destination is sealed and outlives the frame that planned it, so it can hold no arena bytes at
//! all. The VALUE lives on the unit's own draft, as `UnitDraft::correlation_out` — a
//! `CorrelationRef<'u>` borrowed from the per-unit arena, which is where a provider's tool call
//! identifier honestly is.
//!
//! The two are joined here, at registration, which happens while the leg is being planned — inside
//! the frame that built it, with the arena alive. What this table then keeps is the kernel's OWN
//! copy of the identifier, owned outright, so nothing in the table borrows a unit's arena either.
//!
//! ## Whole values, never a digest
//!
//! Matching compares the declared key and the whole value. A fold of a string identifier into
//! sixty-four bits would be one collision away from paying a tool call's hold out against another
//! call's answer, on the same session, for the same principal — the exact pair a correlation exists
//! to tell apart. So there is no digest here, and there is nowhere else on the path for one to be:
//! the value the leg waits on and the value a reply carries are both the identifier itself.

use std::collections::HashMap;

use busbar_contract::dest::ClientMode;
use busbar_contract::ids::{CorrelationRef, CorrelationValue, UnitKey};

/// A correlation the kernel owns outright, lifted out of a unit's arena at registration.
///
/// The arena-borrowed [`CorrelationValue`] cannot be kept: the unit's arena is reclaimed when the
/// frame that planned the leg is done, and the wait outlives it by a deadline. So a string
/// identifier is copied into the kernel's own memory, once, at the one moment it is guaranteed
/// readable. A numeric one is copied by being what it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OwnedCorrelation {
    /// A whole number identifier, used as itself.
    Num(u64),
    /// A string identifier, copied out of the arena it was decoded into.
    Str(String),
}

impl OwnedCorrelation {
    /// Lift an arena-borrowed value into the kernel's own memory.
    #[must_use]
    pub fn of(value: CorrelationValue<'_>) -> Self {
        match value {
            CorrelationValue::Num(n) => Self::Num(n),
            CorrelationValue::Str(s) => Self::Str(s.to_owned()),
        }
    }

    /// Whether an arena-borrowed value is this same identifier.
    ///
    /// A `Num` and a `Str` never match, even where the string spells the number: they came off two
    /// different wire shapes, and a protocol that sends `7` and a protocol that sends `"7"` are not
    /// agreeing about anything.
    #[must_use]
    pub fn is(&self, value: CorrelationValue<'_>) -> bool {
        match (self, value) {
            (Self::Num(a), CorrelationValue::Num(b)) => *a == b,
            (Self::Str(a), CorrelationValue::Str(b)) => a == b,
            _ => false,
        }
    }
}

/// One unit's outstanding wait: the key its leg named, and the value its draft minted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiting {
    /// The declared fact key, as the sealed leg named it.
    pub fact_key: &'static str,
    /// The identifier an answer must carry under that key.
    pub value: OwnedCorrelation,
    /// The wall the wait ends at, on the kernel's monotonic clock.
    pub deadline: crate::Millis,
}

/// Why a leg could not be registered as waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotWaiting {
    /// The leg delivers and moves on; there is nothing to wait for.
    Delivers,
    /// The leg waits, but the unit's draft minted no correlation for an answer to carry. A wait
    /// with no identity is the constant-zero collision by another name, so it is refused rather
    /// than entered.
    NoCorrelationOut,
    /// The draft's correlation is carried under a different key than the leg named. One of the two
    /// is wrong and the kernel cannot tell which, so it enters neither.
    KeyMismatch,
}

/// Every unit on this node waiting on a reply leg.
///
/// Keyed by unit, not by correlation: two units may legitimately wait on identifiers that are
/// equal across sessions, and a table keyed the other way would have to answer which one a reply
/// belongs to before it had the session to answer it with. Waking walks the waits of one session's
/// units, which is bounded by that session's open turn.
#[derive(Debug, Default)]
pub struct AwaitingReplies {
    waits: HashMap<UnitKey, Waiting>,
}

impl AwaitingReplies {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter a unit's reply leg as waiting.
    ///
    /// `correlation_out` is the unit's own draft field, still borrowed from its arena; the value is
    /// copied here and the borrow is not kept.
    ///
    /// # Errors
    /// Returns why the leg is not a wait: it delivers, its unit minted no correlation, or the
    /// draft's key is not the one the leg named.
    pub fn enter(
        &mut self,
        unit: UnitKey,
        mode: ClientMode,
        correlation_out: Option<CorrelationRef<'_>>,
        now: crate::Millis,
    ) -> Result<(), NotWaiting> {
        let ClientMode::AwaitReply {
            correlation_key,
            deadline_secs,
        } = mode
        else {
            return Err(NotWaiting::Delivers);
        };
        let out = correlation_out.ok_or(NotWaiting::NoCorrelationOut)?;
        if out.fact_key != correlation_key {
            return Err(NotWaiting::KeyMismatch);
        }
        self.waits.insert(
            unit,
            Waiting {
                fact_key: correlation_key,
                value: OwnedCorrelation::of(out.value),
                deadline: now + crate::Millis::from(deadline_secs) * 1000,
            },
        );
        Ok(())
    }

    /// How many units are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.waits.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.waits.is_empty()
    }

    /// What one unit is waiting on, where it is waiting at all.
    #[must_use]
    pub fn waiting(&self, unit: UnitKey) -> Option<&Waiting> {
        self.waits.get(&unit)
    }

    /// The unit this reply answers, taken out of the table.
    ///
    /// `correlates` is the inbound reply's own correlation, as the plane read it off the bytes.
    /// Both the key and the whole value must match. A reply that answers nothing here wakes
    /// nothing: it returns `None` rather than the first or the only wait, because "the only one
    /// open" is exactly the reasoning that pays one call's hold out against another's answer as
    /// soon as a second call opens.
    pub fn wake(&mut self, correlates: CorrelationRef<'_>) -> Option<UnitKey> {
        let unit = *self.waits.iter().find_map(|(unit, waiting)| {
            (waiting.fact_key == correlates.fact_key && waiting.value.is(correlates.value))
                .then_some(unit)
        })?;
        self.waits.remove(&unit);
        Some(unit)
    }

    /// Drop the waits whose deadline has passed, and say which units they belonged to.
    ///
    /// A wait that is never woken is a hold that is never settled, so the sweep that ends it is
    /// part of the table rather than something a caller is trusted to remember.
    pub fn expired(&mut self, now: crate::Millis) -> Vec<UnitKey> {
        let done: Vec<UnitKey> = self
            .waits
            .iter()
            .filter(|(_, waiting)| waiting.deadline <= now)
            .map(|(unit, _)| *unit)
            .collect();
        for unit in &done {
            self.waits.remove(unit);
        }
        done
    }
}
