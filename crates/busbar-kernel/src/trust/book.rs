// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TRUST STATE, per instance and counterparty: what `trust.sight` judges a reported
//! catalogue hash against, what `trust.due` answers from, and the root key `trust.verify` reads.
//! The lifecycle is the kernel's; a plane only reports hashes and hands signatures.
//!
//! * **The policy** is the instance's [`TrustEntry`] map, as [`super::section`] parsed it from the
//!   plane's declared trust keys. A counterparty the map does not name is refused, never judged.
//! * **The pin.** A declared fingerprint is the pin from the start. With none, a counterparty is
//!   NEW until the operator approves it (`POST /api/v1/admin/trust/approve`, [`TrustBook::decide`]),
//!   which pins the catalogue it last reported: a first sighting pins nothing (ARCHITECT
//!   2026-10-06), and every sighting before the approval answers [`Sight::New`].
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
//! * **Approve.** The kernel's Approve step judges the trust facts a plane STATES for a unit
//!   ([`TrustFacts`]: a counterparty, and optionally an item there at the digest it is offered at)
//!   by [`TrustBook::judge`]; a plane judges none (ARCHITECT 2026-10-06: trust is the kernel's
//!   Approve step). Item-less facts need the counterparty approved (pinned); an item needs itself
//!   approved at the digest offered. An item's approval is the operator's: the configured one
//!   ([`TrustEntry::approved`], re-read at every admit) under the core-admin decision
//!   ([`TrustBook::decide`]), which wins.
//! * **Unreachable.** A sighting the plane could not make ([`TrustBook::last_verdict`]) answers
//!   the last verdict and changes nothing: an upstream that stopped answering is neither drifted
//!   nor cleared by it.

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
    /// The approved catalogue hash: the declared fingerprint, or the one the operator approved.
    pinned: Option<String>,
    /// The catalogue hash the last sighting reported.
    last_seen: Option<String>,
    quarantined: bool,
    /// The operator revoked the counterparty: nothing at it is trusted until it is approved again.
    revoked: bool,
    /// A sighting has matched the pin since it was set.
    confirmed: bool,
    ledger: Ledger,
    due: bool,
    /// The operator's item decisions (core-admin): `Some(digest)` approved at it, `None` revoked.
    /// Each wins over the item's configured approval.
    granted: BTreeMap<String, Option<String>>,
    /// Each item's last SIGHTING: the digest the plane's live re-fetch reported it offered at.
    items: BTreeMap<String, String>,
}

/// THE TRUST FACTS a plane states for one unit, as the kernel's Approve reads them: neutral words
/// only, opaque to the kernel beyond equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustFacts<'a> {
    /// The counterparty the unit rests on: a name among the instance's declared trust entries.
    pub counterparty: &'a str,
    /// The item the unit uses there; `None` = the counterparty as a whole.
    pub item: Option<&'a str>,
    /// The digest the item is offered at now; `None` = none observed.
    pub digest: Option<&'a str>,
}

/// Why the kernel's Approve does not trust a unit's stated facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distrust {
    /// The instance declares no such counterparty (or was never admitted).
    Unknown,
    /// The counterparty was never sighted: nothing is pinned to judge by.
    Unsighted,
    /// The counterparty is quarantined: its last sighting drifted from its pin.
    Quarantined,
    /// The item was never approved at this counterparty.
    NotApproved,
    /// The item is offered at another digest than the one approved (or at none).
    Changed,
    /// The item was never sighted at this counterparty: an unknown item.
    UnknownItem,
}

impl Subject {
    fn declared(entry: &TrustEntry) -> Self {
        Self {
            pinned: declared_pin(entry),
            ..Self::default()
        }
    }

    /// The digest `item` is approved at: the operator's decision, else the configured approval.
    fn approval<'a>(&'a self, entry: &'a TrustEntry, item: &str) -> Option<&'a str> {
        match self.granted.get(item) {
            Some(decided) => decided.as_deref(),
            None => entry.approved.get(item).map(String::as_str),
        }
    }

    /// The verdict a sighting of the pinned state answers, without one being made.
    fn verdict(&self) -> Sight {
        if self.quarantined {
            Sight::Quarantined
        } else if self.pinned.is_none() || self.revoked {
            Sight::New
        } else {
            Sight::Same
        }
    }

    /// The counterparty's administrative state.
    fn state(&self) -> KeyState {
        if self.quarantined {
            if self.last_seen.is_some() && self.last_seen != self.pinned {
                KeyState::Drifted
            } else {
                KeyState::Quarantined
            }
        } else if self.pinned.is_none() || self.revoked {
            KeyState::New
        } else if self.confirmed {
            KeyState::Same
        } else {
            KeyState::Approved
        }
    }

    /// One item's administrative state.
    fn item_state(&self, entry: &TrustEntry, item: &str) -> KeyState {
        if self.quarantined {
            return KeyState::Quarantined;
        }
        match (self.approval(entry, item), self.items.get(item)) {
            _ if self.revoked => KeyState::New,
            (None, _) => KeyState::New,
            (Some(_), None) => KeyState::Approved,
            (Some(at), Some(seen)) if at == seen => KeyState::Same,
            (Some(_), Some(_)) => KeyState::Drifted,
        }
    }
}

/// THE ADMINISTRATIVE STATE of one trust key, as `GET /api/v1/admin/trust` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Sighted (or declared) and never approved, or revoked: refused.
    New,
    /// Approved, and its last sighting is what was approved.
    Same,
    /// Approved, and its last sighting moved from what was approved: refused until re-approved.
    Drifted,
    /// The counterparty is quarantined: refused until re-approved (or its pin is seen again).
    Quarantined,
    /// Approved, and not sighted since.
    Approved,
}

impl KeyState {
    /// The word the admin surface writes.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            KeyState::New => "new",
            KeyState::Same => "same",
            KeyState::Drifted => "drifted",
            KeyState::Quarantined => "quarantined",
            KeyState::Approved => "approved",
        }
    }
}

/// One trust key and its state: a counterparty of an instance, or one item there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// The instance label.
    pub instance: String,
    /// The counterparty.
    pub counterparty: String,
    /// The item, for an item key.
    pub item: Option<String>,
    /// Its state.
    pub state: KeyState,
    /// What it is approved at: the pinned catalogue hash, or the item's approved digest.
    pub approved: Option<String>,
    /// What it was last sighted at.
    pub seen: Option<String>,
}

impl KeyRow {
    /// The key, `<instance>/<counterparty>[/<item>]`.
    #[must_use]
    pub fn key(&self) -> String {
        match &self.item {
            Some(item) => format!("{}/{}/{item}", self.instance, self.counterparty),
            None => format!("{}/{}", self.instance, self.counterparty),
        }
    }
}

/// What the operator decides about one trust key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Approve it at what it was last sighted at (a counterparty: its last catalogue hash, which
    /// clears its quarantine; an item: its last digest).
    Approve,
    /// Revoke it: refused until approved again.
    Revoke,
}

/// Why a decision was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undecided {
    /// No such key: no admitted instance declares the counterparty, or the item was never sighted
    /// or approved there.
    NoSuchKey,
    /// The key exists but nothing was ever sighted for it to be approved at.
    NothingSighted,
}

/// THE DURABLE FACT a decision leaves: what the operator decided about one key. Replayed at admit
/// ([`TrustBook::admit_decided`]), so an approval or revocation outlives the process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionRow {
    /// The instance label.
    pub instance: String,
    /// The counterparty.
    pub counterparty: String,
    /// The item, for an item key.
    pub item: Option<String>,
    /// `Some(at)` approved at it; `None` revoked.
    pub approved: Option<String>,
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
        s.last_seen = Some(hash.to_string());
        let pinned = s.pinned.as_deref();
        if pinned.is_none() && s.quarantined {
            // A replayed demotion with no pin to judge a clean answer by: held until the operator
            // approves one. A restart is never the way out of a quarantine.
            return Ok((Sight::Quarantined, Effect::None));
        }
        if pinned.is_none() {
            // NEW until the operator approves what it reports: a first sighting pins nothing.
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
            s.confirmed = true;
            return Ok((
                if s.revoked { Sight::New } else { Sight::Same },
                Effect::None,
            ));
        }
        let held = s
            .ledger
            .last_drift_ms
            .is_some_and(|drifted| now_ms < drifted || now_ms - drifted < backoff);
        if held {
            return Ok((Sight::Quarantined, Effect::None));
        }
        s.quarantined = false;
        s.confirmed = true;
        Ok((Sight::Same, Effect::Clear))
    }

    /// THE LAST VERDICT for `counterparty` of `instance`, for a sighting the plane could NOT make
    /// (its re-fetch failed: `TRUST_UNREACHABLE`). Nothing changes: an upstream that stopped
    /// answering has neither drifted nor recovered, and its re-verification mark stands.
    ///
    /// # Errors
    ///
    /// [`Unjudged`] for an instance never admitted or a counterparty it does not declare.
    pub fn last_verdict(&self, instance: &str, counterparty: &str) -> Result<Sight, Unjudged> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Unjudged::UnknownInstance)?;
        let entry = book
            .entries
            .get(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        Ok(book
            .subjects
            .get(counterparty)
            .map_or_else(|| Subject::declared(entry).verdict(), Subject::verdict))
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

    /// THE OPERATOR'S DECISION about one trust key (`POST /api/v1/admin/trust/approve` and
    /// `/revoke`): `item: None` decides the counterparty, `Some` one item there. Idempotent: the
    /// same decision twice leaves the same state and answers the same row.
    ///
    /// * Approving a counterparty pins the catalogue hash it last reported (else its declared one)
    ///   and clears its quarantine and any revocation; revoking it refuses everything at it.
    /// * Approving an item adopts the digest it was last sighted at (else the one it is approved
    ///   at); revoking it refuses it, over its configured approval.
    ///
    /// Answers the key's row and the durable fact to keep.
    ///
    /// # Errors
    ///
    /// [`Undecided::NoSuchKey`] for a key no admitted instance has; [`Undecided::NothingSighted`]
    /// for an approval with nothing ever sighted (or declared) to approve at.
    pub fn decide(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        decision: Decision,
    ) -> Result<(KeyRow, DecisionRow), Undecided> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Undecided::NoSuchKey)?;
        let entry = book.entries.get(counterparty).ok_or(Undecided::NoSuchKey)?;
        let s = book
            .subjects
            .entry(counterparty.to_string())
            .or_insert_with(|| Subject::declared(entry));
        let approved = match (item, decision) {
            (None, Decision::Approve) => {
                let at = s
                    .last_seen
                    .clone()
                    .or_else(|| declared_pin(entry))
                    .or_else(|| s.pinned.clone())
                    .ok_or(Undecided::NothingSighted)?;
                s.confirmed = s.pinned.as_ref() == Some(&at) && s.confirmed;
                s.pinned = Some(at.clone());
                s.quarantined = false;
                s.revoked = false;
                s.ledger.last_drift_ms = None;
                Some(at)
            }
            (None, Decision::Revoke) => {
                s.revoked = true;
                s.confirmed = false;
                None
            }
            (Some(item), decision) => {
                let known = s.items.contains_key(item)
                    || s.granted.contains_key(item)
                    || entry.approved.contains_key(item);
                if !known {
                    return Err(Undecided::NoSuchKey);
                }
                let at = match decision {
                    Decision::Approve => Some(
                        s.items
                            .get(item)
                            .cloned()
                            .or_else(|| s.approval(entry, item).map(str::to_string))
                            .or_else(|| entry.approved.get(item).cloned())
                            .ok_or(Undecided::NothingSighted)?,
                    ),
                    Decision::Revoke => None,
                };
                s.granted.insert(item.to_string(), at.clone());
                at
            }
        };
        let row = row_of(instance, counterparty, item, entry, s);
        let fact = DecisionRow {
            instance: instance.to_string(),
            counterparty: counterparty.to_string(),
            item: item.map(str::to_string),
            approved,
        };
        Ok((row, fact))
    }

    /// Replay the operator's durable decisions for `instance` (each [`DecisionRow`] naming it), in
    /// order, onto its state: what [`Self::decide`] did before the restart. A row for a
    /// counterparty the instance no longer declares is ignored.
    pub fn admit_decided<'a>(
        &self,
        instance: &str,
        rows: impl IntoIterator<Item = &'a DecisionRow>,
    ) {
        let mut map = self.lock();
        let Some(book) = map.get_mut(instance) else {
            return;
        };
        for row in rows.into_iter().filter(|r| r.instance == instance) {
            let Some(entry) = book.entries.get(&row.counterparty) else {
                continue;
            };
            let s = book
                .subjects
                .entry(row.counterparty.clone())
                .or_insert_with(|| Subject::declared(entry));
            match (&row.item, &row.approved) {
                (Some(item), at) => {
                    s.granted.insert(item.clone(), at.clone());
                }
                (None, Some(at)) => {
                    s.pinned = Some(at.clone());
                    s.revoked = false;
                }
                (None, None) => s.revoked = true,
            }
        }
    }

    /// EVERY TRUST KEY of every admitted instance and its state, ordered by instance, counterparty
    /// and item (each counterparty before its items): the counterparties every instance declares,
    /// and the items each has sighted or approved.
    #[must_use]
    pub fn rows(&self) -> Vec<KeyRow> {
        let map = self.lock();
        let mut instances: Vec<_> = map.iter().collect();
        instances.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::new();
        for (instance, book) in instances {
            for (name, entry) in &book.entries {
                let declared;
                let s = match book.subjects.get(name) {
                    Some(s) => s,
                    None => {
                        declared = Subject::declared(entry);
                        &declared
                    }
                };
                out.push(row_of(instance, name, None, entry, s));
                let mut items: std::collections::BTreeSet<&str> =
                    s.items.keys().map(String::as_str).collect();
                items.extend(s.granted.keys().map(String::as_str));
                items.extend(entry.approved.keys().map(String::as_str));
                for item in items {
                    out.push(row_of(instance, name, Some(item), entry, s));
                }
            }
        }
        out
    }

    /// Record the digest one ITEM of `counterparty` is offered at now, from the plane's live
    /// re-fetch: the per-item sighting the kernel judges drift by. [`Sight::New`] the first,
    /// [`Sight::Same`] the last one's digest, [`Sight::Drifted`] another, [`Sight::Quarantined`]
    /// when the counterparty is (the sighting is still recorded).
    ///
    /// # Errors
    ///
    /// [`Unjudged`] for an instance never admitted or a counterparty it does not declare.
    pub fn sight_item(
        &self,
        instance: &str,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Result<Sight, Unjudged> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Unjudged::UnknownInstance)?;
        let entry = book
            .entries
            .get(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        let s = book
            .subjects
            .entry(counterparty.to_string())
            .or_insert_with(|| Subject::declared(entry));
        let before = s.items.insert(item.to_string(), digest.to_string());
        Ok(if s.quarantined {
            Sight::Quarantined
        } else {
            match before {
                None => Sight::New,
                Some(d) if d == digest => Sight::Same,
                Some(_) => Sight::Drifted,
            }
        })
    }

    /// THE KERNEL'S APPROVE over the trust facts a plane stated for a unit of `instance`: the
    /// counterparty is declared, sighted (pinned) and not quarantined, and a named item is
    /// approved there at exactly the digest it is offered at.
    ///
    /// # Errors
    ///
    /// The [`Distrust`] that refuses the unit.
    pub fn judge(&self, instance: &str, facts: &TrustFacts<'_>) -> Result<(), Distrust> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Distrust::Unknown)?;
        if !book.entries.contains_key(facts.counterparty) {
            return Err(Distrust::Unknown);
        }
        let entry = &book.entries[facts.counterparty];
        let declared;
        let s = match book.subjects.get(facts.counterparty) {
            Some(s) => s,
            None => {
                declared = Subject::declared(entry);
                &declared
            }
        };
        if s.quarantined {
            return Err(Distrust::Quarantined);
        }
        if s.revoked {
            return Err(Distrust::NotApproved);
        }
        let Some(item) = facts.item else {
            // Item-less: the counterparty's catalogue must be approved (pinned).
            return match (&s.pinned, &s.last_seen) {
                (Some(_), _) => Ok(()),
                (None, None) => Err(Distrust::Unsighted),
                (None, Some(_)) => Err(Distrust::NotApproved),
            };
        };
        let offered = facts
            .digest
            .or_else(|| s.items.get(item).map(String::as_str));
        match s.approval(entry, item) {
            None if facts.digest.is_none()
                && !s.items.contains_key(item)
                && !s.granted.contains_key(item)
                && !entry.approved.contains_key(item) =>
            {
                Err(Distrust::UnknownItem)
            }
            None => Err(Distrust::NotApproved),
            Some(at) if Some(at) == offered => Ok(()),
            Some(_) => Err(Distrust::Changed),
        }
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

/// One key's row.
fn row_of(
    instance: &str,
    counterparty: &str,
    item: Option<&str>,
    entry: &TrustEntry,
    s: &Subject,
) -> KeyRow {
    let (state, approved, seen) = match item {
        None => (s.state(), s.pinned.clone(), s.last_seen.clone()),
        Some(item) => (
            s.item_state(entry, item),
            s.approval(entry, item).map(str::to_string),
            s.items.get(item).cloned(),
        ),
    };
    KeyRow {
        instance: instance.to_string(),
        counterparty: counterparty.to_string(),
        item: item.map(str::to_string),
        state,
        approved,
        seen,
    }
}

#[cfg(test)]
#[path = "tests/book_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/serve_gate_tests.rs"]
mod serve_gate_tests;
