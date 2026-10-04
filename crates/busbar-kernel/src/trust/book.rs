// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TRUST STATE, per instance and counterparty: what `trust.sight` judges a reported
//! catalogue hash against, what `trust.due` answers from, and the root key `trust.verify` reads.
//! The lifecycle is the kernel's; a plane only reports hashes and hands signatures.
//!
//! * **The policy** is the instance's [`TrustEntry`] map, as [`super::section`] parsed it from the
//!   plane's declared trust keys. A counterparty the map does not name is refused, never judged.
//! * **The pin.** A declared fingerprint is the pin from the start; with none, the first sighting
//!   pins what it reports ([`Sight::New`]).
//! * **Drift.** A hash other than the pin answers [`Sight::Drifted`] once and demotes the
//!   counterparty; every sighting after that answers [`Sight::Quarantined`] until the pin is seen
//!   again. That clean sighting clears the demotion, unless the declared recovery backoff since the
//!   last drift has not elapsed (or the clock went backwards since it), in which case it is held,
//!   by the same rule as [`super::reverify::settle`]. Demotion is never held. A demotion replayed
//!   for a counterparty with no declared pin has no pin to clear it by, and stays until the operator
//!   declares one.
//! * **Re-verification.** The kernel's tick marks a counterparty due by [`super::reverify::due`]
//!   under its declared cadence; a cadence of zero declares none and is never marked by the timer.
//!   `trust.due` answers the marks; a sighting clears its counterparty's mark, so a mark outlives a
//!   short answer and is answered until the plane re-sights the counterparty.
//! * **Durability.** Demotion and clearing are effects the caller writes through the durable
//!   demotion record; [`TrustBook::admit`] replays the demotions it was handed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use super::reverify::{self, Ledger};
use super::section::TrustEntry;

/// What a sighting answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    /// Never seen before, and pinned now.
    New,
    /// The pinned catalogue.
    Same,
    /// The catalogue moved from its pin; the counterparty is demoted from now on.
    Drifted,
    /// The counterparty is demoted.
    Quarantined,
}

/// What a sighting asks the caller to write through the durable demotion record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Nothing.
    None,
    /// Record the demotion.
    Demote,
    /// Clear the demotion.
    Clear,
}

/// Why a sighting was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unjudged {
    /// The instance was never admitted.
    UnknownInstance,
    /// The instance declares no such counterparty.
    UnknownCounterparty,
}

/// One counterparty's state.
#[derive(Debug, Clone, Default)]
struct Subject {
    pinned: Option<String>,
    quarantined: bool,
    ledger: Ledger,
    due: bool,
}

impl Subject {
    fn declared(entry: &TrustEntry) -> Self {
        Self {
            pinned: declared_pin(entry),
            ..Self::default()
        }
    }
}

fn declared_pin(entry: &TrustEntry) -> Option<String> {
    entry.pin.as_ref().and_then(|p| p.fingerprint.clone())
}

#[derive(Debug, Default)]
struct Book {
    entries: BTreeMap<String, TrustEntry>,
    subjects: BTreeMap<String, Subject>,
}

/// THE TRUST STATE of every admitted instance.
#[derive(Debug, Default)]
pub struct TrustBook {
    inner: Mutex<HashMap<Arc<str>, Book>>,
}

impl TrustBook {
    fn lock(&self) -> MutexGuard<'_, HashMap<Arc<str>, Book>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admit (or re-admit) `instance` with its parsed trust entries. `demoted` are the durable
    /// demotions to replay, `(counterparty, recorded at, ms)`; one for a counterparty the entries do
    /// not name is ignored. On a re-admit a counterparty keeps its state unless its declared pin
    /// changed, which is the operator's re-approval and starts it afresh.
    pub fn admit<'a>(
        &self,
        instance: &Arc<str>,
        entries: impl IntoIterator<Item = (String, TrustEntry)>,
        demoted: impl IntoIterator<Item = (&'a str, u64)>,
    ) {
        let entries: BTreeMap<String, TrustEntry> = entries.into_iter().collect();
        let mut map = self.lock();
        let old = map.remove(instance).unwrap_or_default();
        let mut subjects = BTreeMap::new();
        for (name, entry) in &entries {
            let kept = old
                .subjects
                .get(name)
                .filter(|_| old.entries.get(name).map(declared_pin) == Some(declared_pin(entry)));
            subjects.insert(
                name.clone(),
                kept.cloned().unwrap_or_else(|| Subject::declared(entry)),
            );
        }
        for (name, at_ms) in demoted {
            if let Some(s) = subjects.get_mut(name) {
                s.quarantined = true;
                s.ledger.last_drift_ms =
                    Some(s.ledger.last_drift_ms.map_or(at_ms, |d| d.max(at_ms)));
            }
        }
        map.insert(Arc::clone(instance), Book { entries, subjects });
    }

    /// Judge `hash`, reported for `counterparty` of `instance`, at `now_ms` on the kernel's clock.
    ///
    /// # Errors
    ///
    /// [`Unjudged`] for an instance never admitted or a counterparty it does not declare.
    pub fn sight(
        &self,
        instance: &str,
        counterparty: &str,
        hash: &str,
        now_ms: u64,
    ) -> Result<(Sight, Effect), Unjudged> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Unjudged::UnknownInstance)?;
        let entry = book
            .entries
            .get(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        let backoff = entry.policy.recovery_backoff_ms;
        let s = book
            .subjects
            .entry(counterparty.to_string())
            .or_insert_with(|| Subject::declared(entry));
        s.ledger.last_checked_ms = Some(now_ms);
        s.due = false;
        let pinned = s.pinned.as_deref();
        if pinned.is_none() && s.quarantined {
            // A replayed demotion with no pin to judge a clean answer by: held until the operator
            // declares one. A restart is never the way out of a quarantine.
            return Ok((Sight::Quarantined, Effect::None));
        }
        if pinned.is_none() {
            s.pinned = Some(hash.to_string());
            return Ok((Sight::New, Effect::None));
        }
        if pinned != Some(hash) {
            s.ledger.drift_observations += 1;
            s.ledger.last_drift_ms = Some(now_ms);
            if s.quarantined {
                return Ok((Sight::Quarantined, Effect::None));
            }
            s.quarantined = true;
            return Ok((Sight::Drifted, Effect::Demote));
        }
        if !s.quarantined {
            return Ok((Sight::Same, Effect::None));
        }
        let held = s
            .ledger
            .last_drift_ms
            .is_some_and(|drifted| now_ms < drifted || now_ms - drifted < backoff);
        if held {
            return Ok((Sight::Quarantined, Effect::None));
        }
        s.quarantined = false;
        Ok((Sight::Same, Effect::Clear))
    }

    /// The root key `instance` declares for `counterparty`: its pin's material when the pin is an
    /// authenticity root, else `None`.
    ///
    /// # Errors
    ///
    /// [`Unjudged`] for an instance never admitted or a counterparty it does not declare.
    pub fn root_key(&self, instance: &str, counterparty: &str) -> Result<Option<String>, Unjudged> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Unjudged::UnknownInstance)?;
        let entry = book
            .entries
            .get(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        Ok(entry
            .pin
            .as_ref()
            .filter(|p| p.root)
            .and_then(|p| p.key.clone()))
    }

    /// The kernel tick: mark every counterparty whose declared cadence says it is due at `now_ms`.
    pub fn mark_due(&self, now_ms: u64) {
        for book in self.lock().values_mut() {
            let Book { entries, subjects } = book;
            for (name, entry) in entries.iter() {
                if entry.policy.ttl_ms == 0 {
                    continue;
                }
                let s = subjects
                    .entry(name.clone())
                    .or_insert_with(|| Subject::declared(entry));
                if reverify::due(&s.ledger, &entry.policy, now_ms, false).should_check() {
                    s.due = true;
                }
            }
        }
    }

    /// The counterparties of `instance` marked due, in name order; `None` for an instance never
    /// admitted.
    #[must_use]
    pub fn due(&self, instance: &str) -> Option<Vec<String>> {
        self.lock().get(instance).map(|b| {
            b.subjects
                .iter()
                .filter(|(_, s)| s.due)
                .map(|(n, _)| n.clone())
                .collect()
        })
    }
}

#[cfg(test)]
#[path = "tests/book_tests.rs"]
mod tests;
