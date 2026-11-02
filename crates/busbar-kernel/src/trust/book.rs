// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use super::reverify::Ledger;
use super::section::{DeclaredPin, TrustEntry};

/// What a sighting answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    /// Not approved: never approved, approved at nothing yet, revoked, or a declared fingerprint
    /// the operator has not approved. A sighting pins nothing.
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
    /// Identity of the local mutation boundary. Snapshots keep the old allocation alive, so a
    /// completed mutation cannot wrap a counter or reuse an identity underneath a fleet read.
    decision_epoch: Arc<()>,
    /// The catalogue hash sightings are judged against: the declared fingerprint, or the one the
    /// operator approved.
    pinned: Option<String>,
    /// The pin is a declared fingerprint the operator has not approved: intent, not an approval.
    /// Every sighting answers [`Sight::New`] and drifts nothing, and the Approve step refuses the
    /// counterparty and every item there, until [`TrustBook::decide`] approves it.
    pending: bool,
    /// The catalogue hash the last sighting reported.
    last_seen: Option<String>,
    quarantined: bool,
    /// The operator revoked the counterparty: nothing at it is trusted until it is approved again.
    revoked: bool,
    /// A sighting has matched the pin since it was set.
    confirmed: bool,
    ledger: Ledger,
    /// The operator's item decisions (core-admin): `Some(digest)` approved at it, `None` revoked.
    /// Each wins over the item's configured approval.
    granted: BTreeMap<String, Option<String>>,
    /// Each item's last SIGHTING: the digest the plane's live re-fetch reported it offered at.
    items: BTreeMap<String, String>,
    /// THE ITEMS DEMOTED BY DRIFT: sighted at another digest than the one they were approved at.
    /// Refused ([`Distrust::Changed`]) whatever they are offered at after, a revert included,
    /// until the operator decides the item again; kept durably ([`RulingRow::demoted`]).
    demoted: std::collections::BTreeSet<String>,
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
        let pinned = declared_pin(entry);
        Self {
            pending: pinned.is_some(),
            pinned,
            ..Self::default()
        }
    }

    fn unroot(&mut self) {
        self.pinned = None;
        self.pending = false;
        self.confirmed = false;
        self.granted.retain(|_, at| at.is_none());
    }

    fn approval<'a>(&'a self, entry: &'a TrustEntry, item: &str) -> Option<&'a str> {
        match self.granted.get(item) {
            Some(decided) => decided.as_deref(),
            None => entry.approved.get(item).map(String::as_str),
        }
    }

    fn unapproved(&self) -> bool {
        self.pinned.is_none() || self.revoked || self.pending
    }

    fn verdict(&self) -> Sight {
        if self.quarantined {
            Sight::Quarantined
        } else if self.unapproved() {
            Sight::New
        } else {
            Sight::Same
        }
    }

    fn state(&self) -> KeyState {
        if self.quarantined {
            if self.last_seen.is_some() && self.last_seen != self.pinned {
                KeyState::Drifted
            } else {
                KeyState::Quarantined
            }
        } else if self.unapproved() {
            KeyState::New
        } else if self.confirmed {
            KeyState::Same
        } else {
            KeyState::Approved
        }
    }

    fn item_state(&self, entry: &TrustEntry, item: &str) -> KeyState {
        if self.quarantined {
            return KeyState::Quarantined;
        }
        if self.demoted.contains(item) {
            return match (self.approval(entry, item), self.items.get(item)) {
                (Some(at), Some(seen)) if at == seen => KeyState::Quarantined,
                _ => KeyState::Drifted,
            };
        }
        match (self.approval(entry, item), self.items.get(item)) {
            _ if self.revoked || self.pending => KeyState::New,
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
pub enum Ruling {
    /// Approve it at what it was last sighted at (a counterparty: its last catalogue hash, which
    /// clears its quarantine; an item: its last digest).
    Approve,
    /// Revoke it: refused until approved again.
    Revoke,
}

pub const UNVERIFIED_SIGHTING: &str = "unverified";

/// Why a decision was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undecided {
    /// No such key: no admitted instance declares the counterparty, or the item was never sighted
    /// or approved there.
    NoSuchKey,
    /// The key exists but nothing was ever sighted for it to be approved at.
    NothingSighted,
    /// The counterparty declares no authenticity root: nothing at it can be approved.
    Rootless,
    /// The fingerprint the caller approves is not the key's current sighting, or another local
    /// mutation currently owns its durable decision key.
    Stale,
    /// The key's current sighting is a document that failed its verification
    /// ([`UNVERIFIED_SIGHTING`]): there is nothing verified to approve.
    Unverified,
}

/// THE DURABLE FACT a decision leaves: what the operator decided about one key. Replayed at admit
/// ([`TrustBook::admit_decided`]), so an approval or revocation outlives the process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RulingRow {
    /// The instance label.
    pub instance: String,
    /// The counterparty.
    pub counterparty: String,
    /// The item, for an item key.
    pub item: Option<String>,
    /// `Some(at)` approved at it; `None` revoked.
    pub approved: Option<String>,
    /// THE DECLARATION THE DECISION WAS MADE UNDER: the registration's whole declared pin
    /// (mechanism, root, key and fingerprint), `None` for one that declares no pin. A kept decision
    /// replays only over the same declaration, so an approval never rides a declaration that
    /// changed while the process was down, exactly as an in-process re-admit starts the
    /// counterparty afresh (THE DESIGN §11.12 l.1617-1619, the trust lifecycle is kernel state). A
    /// row kept before this field existed reads `None` and so replays only over a pinless
    /// registration.
    #[serde(default)]
    pub declared: Option<DeclaredPin>,
    /// THE KERNEL DEMOTED THE ITEM: a sighting moved from its approval (`approved` = the approval
    /// it moved from). Replays as the item's demotion; only the operator's next decision about the
    /// item replaces it. `false` for every operator decision, and for a row kept before the field.
    #[serde(default)]
    pub demoted: bool,
}

fn declared_pin(entry: &TrustEntry) -> Option<String> {
    entry.pin.as_ref().and_then(|p| p.fingerprint.clone())
}

#[derive(Debug, Default)]
struct Book {
    entries: BTreeMap<String, TrustEntry>,
    subjects: BTreeMap<String, Subject>,
    /// Only live owners occupy this set; a removed declaration leaves no permanent tombstone.
    deciding: std::collections::BTreeSet<(String, Option<String>)>,
}

pub(crate) struct DecisionPermit {
    trust: TrustBook,
    instance: String,
    key: (String, Option<String>),
    invalidate_on_drop: bool,
}

impl DecisionPermit {
    pub(crate) fn demoted(&mut self) {
        self.invalidate_on_drop = true;
    }

    pub(crate) fn apply(&self, fact: &RulingRow) -> Result<KeyRow, Undecided> {
        if fact.instance != self.instance
            || fact.counterparty != self.key.0
            || fact.item != self.key.1
        {
            return Err(Undecided::Stale);
        }
        self.trust.apply_owned(fact)
    }
}

impl Drop for DecisionPermit {
    fn drop(&mut self) {
        let mut map = self.trust.lock();
        if let Some(book) = map.get_mut(self.instance.as_str()) {
            book.deciding.remove(&self.key);
            if self.invalidate_on_drop {
                if let Some(s) = book.subjects.get_mut(&self.key.0) {
                    s.decision_epoch = Arc::new(());
                }
            }
        }
    }
}

pub(crate) struct DecisionSnapshot(HashMap<Arc<str>, BTreeMap<String, Arc<()>>>);

impl Book {
    fn subject(&self, name: &str) -> Option<(&TrustEntry, Cow<'_, Subject>)> {
        let entry = self.entries.get(name)?;
        let s = self
            .subjects
            .get(name)
            .map_or_else(|| Cow::Owned(Subject::declared(entry)), Cow::Borrowed);
        Some((entry, s))
    }

    fn subject_mut(&mut self, name: &str) -> Option<(&TrustEntry, &mut Subject)> {
        let entry = self.entries.get(name)?;
        let s = self
            .subjects
            .entry(name.to_string())
            .or_insert_with(|| Subject::declared(entry));
        Some((entry, s))
    }
}

fn replay_decision(book: &mut Book, row: &RulingRow) {
    if book
        .deciding
        .contains(&(row.counterparty.clone(), row.item.clone()))
    {
        return;
    }
    let Some((entry, s)) = book.subject_mut(&row.counterparty) else {
        return;
    };
    if row.declared != entry.pin || (row.approved.is_some() && entry.rootless()) {
        return;
    }

    if row.approved.as_deref() == Some(UNVERIFIED_SIGHTING) {
        return;
    }
    match (&row.item, &row.approved) {
        (Some(item), _) if row.demoted => {
            s.demoted.insert(item.clone());
        }
        (Some(item), at) => {
            s.granted.insert(item.clone(), at.clone());
            s.demoted.remove(item);
        }
        (None, Some(at)) => {
            s.pinned = Some(at.clone());
            s.pending = false;
            s.revoked = false;
        }
        (None, None) => s.revoked = true,
    }
}

/// THE TRUST STATE of every admitted instance.
#[derive(Debug, Default)]
pub struct TrustBook {
    inner: Arc<Mutex<HashMap<Arc<str>, Book>>>,
}

impl TrustBook {
    fn lock(&self) -> MutexGuard<'_, HashMap<Arc<str>, Book>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn begin_decision(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
    ) -> Result<DecisionPermit, Undecided> {
        self.begin_mutation(instance, counterparty, item, true)
    }

    pub(crate) fn begin_sighting(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
    ) -> Result<DecisionPermit, Undecided> {
        self.begin_mutation(instance, counterparty, item, false)
    }

    fn begin_mutation(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        invalidate_on_drop: bool,
    ) -> Result<DecisionPermit, Undecided> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Undecided::NoSuchKey)?;
        if !book.entries.contains_key(counterparty) {
            return Err(Undecided::NoSuchKey);
        }
        let key = (counterparty.to_string(), item.map(str::to_string));
        if !book.deciding.insert(key.clone()) {
            return Err(Undecided::Stale);
        }
        if invalidate_on_drop {
            if let Some((_, s)) = book.subject_mut(counterparty) {
                s.decision_epoch = Arc::new(());
            }
        }
        Ok(DecisionPermit {
            trust: TrustBook {
                inner: Arc::clone(&self.inner),
            },
            instance: instance.to_string(),
            key,
            invalidate_on_drop,
        })
    }

    pub(crate) fn decision_snapshot(&self) -> DecisionSnapshot {
        DecisionSnapshot(
            self.lock()
                .iter()
                .map(|(instance, book)| {
                    (
                        Arc::clone(instance),
                        book.subjects
                            .iter()
                            .map(|(name, s)| (name.clone(), Arc::clone(&s.decision_epoch)))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    pub(crate) fn resync_decided(&self, snapshot: &DecisionSnapshot, rows: &[RulingRow]) {
        let mut map = self.lock();
        for row in rows {
            let Some(book) = map.get_mut(row.instance.as_str()) else {
                continue;
            };
            let epoch = snapshot
                .0
                .get(row.instance.as_str())
                .and_then(|subjects| subjects.get(&row.counterparty));
            let unchanged = book
                .subjects
                .get(&row.counterparty)
                .is_some_and(|s| epoch.is_some_and(|epoch| Arc::ptr_eq(epoch, &s.decision_epoch)));
            if unchanged {
                replay_decision(book, row);
            }
        }
    }

    pub fn admit<'a>(
        &self,
        instance: &Arc<str>,
        entries: impl IntoIterator<Item = (String, TrustEntry)>,
        demoted: impl IntoIterator<Item = (&'a str, u64)>,
    ) {
        self.admit_with_decisions(instance, entries, demoted, &[]);
    }

    pub(crate) fn admit_with_decisions<'a>(
        &self,
        instance: &Arc<str>,
        entries: impl IntoIterator<Item = (String, TrustEntry)>,
        demoted: impl IntoIterator<Item = (&'a str, u64)>,
        decided: &[RulingRow],
    ) {
        let entries: BTreeMap<String, TrustEntry> = entries.into_iter().collect();
        let mut map = self.lock();
        let old = map.remove(instance).unwrap_or_default();
        let mut subjects = BTreeMap::new();
        for (name, entry) in &entries {
            let kept = old
                .subjects
                .get(name)
                .filter(|_| old.entries.get(name).map(|e| &e.pin) == Some(&entry.pin));
            let mut s = kept.cloned().unwrap_or_else(|| Subject::declared(entry));
            s.decision_epoch = Arc::new(());
            if entry.rootless() {
                s.unroot();
            }
            subjects.insert(name.clone(), s);
        }
        for (name, at_ms) in demoted {
            if let Some(s) = subjects.get_mut(name) {
                s.quarantined = true;
                s.ledger.last_drift_ms =
                    Some(s.ledger.last_drift_ms.map_or(at_ms, |d| d.max(at_ms)));
            }
        }
        let mut book = Book {
            entries,
            subjects,
            deciding: old.deciding,
        };
        for row in decided.iter().filter(|r| r.instance == instance.as_ref()) {
            replay_decision(&mut book, row);
        }
        map.insert(Arc::clone(instance), book);
    }

    pub fn sight(
        &self,
        instance: &str,
        counterparty: &str,
        hash: &str,
        now_ms: u64,
    ) -> Result<(Sight, Effect), Unjudged> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Unjudged::UnknownInstance)?;
        let (entry, s) = book
            .subject_mut(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        let backoff = entry.policy.recovery_backoff_ms;
        s.ledger.last_checked_ms = Some(now_ms);
        s.last_seen = Some(hash.to_string());
        let pinned = s.pinned.as_deref();
        if pinned.is_none() && s.quarantined {
            return Ok((Sight::Quarantined, Effect::None));
        }
        if pinned.is_none() {
            return Ok((Sight::New, Effect::None));
        }
        let at_pin = pinned == Some(hash);
        if s.pending && !s.quarantined {
            s.confirmed = at_pin;
            return Ok((Sight::New, Effect::None));
        }
        if !at_pin {
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
        Ok((
            if s.pending { Sight::New } else { Sight::Same },
            Effect::Clear,
        ))
    }

    pub fn last_verdict(&self, instance: &str, counterparty: &str) -> Result<Sight, Unjudged> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Unjudged::UnknownInstance)?;
        let (_, s) = book
            .subject(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        Ok(s.verdict())
    }

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

    pub fn decide(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        decision: Ruling,
        expected: Option<&str>,
    ) -> Result<(KeyRow, RulingRow), Undecided> {
        let permit = self.begin_decision(instance, counterparty, item)?;
        let fact = self.rule(instance, counterparty, item, decision, expected)?;
        let row = permit.apply(&fact)?;
        Ok((row, fact))
    }

    pub fn rule(
        &self,
        instance: &str,
        counterparty: &str,
        item: Option<&str>,
        decision: Ruling,
        expected: Option<&str>,
    ) -> Result<RulingRow, Undecided> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Undecided::NoSuchKey)?;
        let (entry, s) = book.subject(counterparty).ok_or(Undecided::NoSuchKey)?;
        if decision == Ruling::Approve && entry.rootless() {
            return Err(Undecided::Rootless);
        }

        if let (Ruling::Approve, Some(expected)) = (decision, expected) {
            let current = match item {
                None => s.last_seen.as_deref(),
                Some(item) => s.items.get(item).map(String::as_str),
            };
            match current {
                None => return Err(Undecided::NothingSighted),
                Some(c) if c != expected => return Err(Undecided::Stale),
                Some(_) => {}
            }
        }
        let approved = match (item, decision) {
            (None, Ruling::Approve) => Some(
                s.last_seen
                    .clone()
                    .or_else(|| declared_pin(entry))
                    .or_else(|| s.pinned.clone())
                    .ok_or(Undecided::NothingSighted)?,
            ),
            (None, Ruling::Revoke) => None,
            (Some(item), decision) => {
                let known = s.items.contains_key(item)
                    || s.granted.contains_key(item)
                    || entry.approved.contains_key(item);
                if !known {
                    return Err(Undecided::NoSuchKey);
                }
                match decision {
                    Ruling::Approve => Some(
                        s.items
                            .get(item)
                            .cloned()
                            .or_else(|| s.approval(entry, item).map(str::to_string))
                            .or_else(|| entry.approved.get(item).cloned())
                            .ok_or(Undecided::NothingSighted)?,
                    ),
                    Ruling::Revoke => None,
                }
            }
        };

        if approved.as_deref() == Some(UNVERIFIED_SIGHTING) {
            return Err(Undecided::Unverified);
        }
        Ok(RulingRow {
            instance: instance.to_string(),
            counterparty: counterparty.to_string(),
            item: item.map(str::to_string),
            approved,
            declared: entry.pin.clone(),
            demoted: false,
        })
    }

    pub fn apply(&self, fact: &RulingRow) -> Result<KeyRow, Undecided> {
        let permit =
            self.begin_decision(&fact.instance, &fact.counterparty, fact.item.as_deref())?;
        permit.apply(fact)
    }

    fn apply_owned(&self, fact: &RulingRow) -> Result<KeyRow, Undecided> {
        let mut map = self.lock();
        let book = map
            .get_mut(fact.instance.as_str())
            .ok_or(Undecided::NoSuchKey)?;
        let entry = book
            .entries
            .get(&fact.counterparty)
            .ok_or(Undecided::NoSuchKey)?;
        if entry.pin != fact.declared {
            return Err(Undecided::Stale);
        }
        if fact.approved.is_some() && entry.rootless() {
            return Err(Undecided::Rootless);
        }
        let (entry, s) = book
            .subject_mut(&fact.counterparty)
            .ok_or(Undecided::NoSuchKey)?;
        match (&fact.item, &fact.approved) {
            (None, Some(at)) => {
                s.confirmed = s.pinned.as_ref() == Some(at) && s.confirmed;
                s.pinned = Some(at.clone());
                s.pending = false;
                s.quarantined = false;
                s.revoked = false;
                s.ledger.last_drift_ms = None;
            }
            (None, None) => {
                s.revoked = true;
                s.confirmed = false;
            }
            (Some(item), at) => {
                s.granted.insert(item.clone(), at.clone());
                s.demoted.remove(item);
            }
        }
        Ok(row_of(
            &fact.instance,
            &fact.counterparty,
            fact.item.as_deref(),
            entry,
            s,
        ))
    }

    pub fn admit_decided<'a>(&self, instance: &str, rows: impl IntoIterator<Item = &'a RulingRow>) {
        let mut map = self.lock();
        let Some(book) = map.get_mut(instance) else {
            return;
        };
        for row in rows.into_iter().filter(|r| r.instance == instance) {
            replay_decision(book, row);
            if let Some(s) = book.subjects.get_mut(&row.counterparty) {
                s.decision_epoch = Arc::new(());
            }
        }
    }

    #[must_use]
    pub fn rows(&self) -> Vec<KeyRow> {
        let map = self.lock();
        let mut instances: Vec<_> = map.iter().collect();
        instances.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::new();
        for (instance, book) in instances {
            for name in book.entries.keys() {
                let Some((entry, s)) = book.subject(name) else {
                    continue;
                };
                let s = &*s;
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

    pub fn sight_item(
        &self,
        instance: &str,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Result<Sight, Unjudged> {
        self.sight_item_kept(instance, counterparty, item, digest)
            .map(|(sight, _)| sight)
    }

    pub fn sight_item_kept(
        &self,
        instance: &str,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Result<(Sight, Option<RulingRow>), Unjudged> {
        let mut map = self.lock();
        let book = map.get_mut(instance).ok_or(Unjudged::UnknownInstance)?;
        let (entry, s) = book
            .subject_mut(counterparty)
            .ok_or(Unjudged::UnknownCounterparty)?;
        let before = s.items.insert(item.to_string(), digest.to_string());
        let moved = s
            .approval(entry, item)
            .filter(|at| *at != digest && !s.demoted.contains(item))
            .map(str::to_string);
        let demotion = moved.map(|at| {
            s.decision_epoch = Arc::new(());
            s.demoted.insert(item.to_string());
            RulingRow {
                instance: instance.to_string(),
                counterparty: counterparty.to_string(),
                item: Some(item.to_string()),
                approved: Some(at),
                declared: entry.pin.clone(),
                demoted: true,
            }
        });
        let sight = if s.quarantined {
            Sight::Quarantined
        } else {
            match before {
                None => Sight::New,
                Some(d) if d == digest => Sight::Same,
                Some(_) => Sight::Drifted,
            }
        };
        Ok((sight, demotion))
    }

    pub fn judge(&self, instance: &str, facts: &TrustFacts<'_>) -> Result<(), Distrust> {
        let map = self.lock();
        let book = map.get(instance).ok_or(Distrust::Unknown)?;
        let (entry, s) = book.subject(facts.counterparty).ok_or(Distrust::Unknown)?;
        if s.quarantined {
            return Err(Distrust::Quarantined);
        }
        if s.revoked || s.pending {
            return Err(Distrust::NotApproved);
        }
        let Some(item) = facts.item else {
            return match (&s.pinned, &s.last_seen) {
                (Some(_), _) => Ok(()),
                (None, None) => Err(Distrust::Unsighted),
                (None, Some(_)) => Err(Distrust::NotApproved),
            };
        };
        if s.demoted.contains(item) {
            return Err(Distrust::Changed);
        }
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

            Some(_) if offered.is_none() => Err(Distrust::Unsighted),
            Some(at) if Some(at) == offered => Ok(()),
            Some(_) => Err(Distrust::Changed),
        }
    }

    #[must_use]
    pub fn due(&self, instance: &str) -> Option<Vec<String>> {
        self.lock().get(instance).map(|_| Vec::new())
    }
}

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
