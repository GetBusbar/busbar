// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Kernel-owned price persistence. Preparation, activation authorization and
//! publication are distinct durable facts. Native candidates are immutable and
//! retained through uncertainty; only their original Applied decision authorizes
//! local publication. No legacy record/chunk size limits apply to these records.

pub mod legacy;
pub mod runtime;

use crate::{
    config::card::{CardFields, sha256},
    persistence::{
        commit::SubmitResult,
        facade::{AccessError, CoreStore, PendingId, Submission},
        fences::scan_guard,
    },
};
use busbar_contract::{
    Secret,
    persistence::{
        Address, CANDIDATE_VERSION, Candidate, Decision, ExpectedValue, Failure, Mutation,
        NamespaceId, Predicate, PreparedCandidate, Read, ReadResult,
    },
};
use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History, RateCard};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

pub const PRICES: NamespaceId = NamespaceId(*b"busbar.prices1\0\0");

/// Why an entry exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntryAuthor {
    /// The opening entry, written only when the history is empty: the booting node's card,
    /// effective from instant zero.
    Opening {},
    /// A change of the card a configuration resolved (boot, reload, apply, settings, plugin reload
    /// or rollback, overlay or named-map write); the entry's `actor` names which, and who.
    Change,
    /// A bounded amend (the audited admin verb).
    Amend {
        /// Hex SHA-256 of the stated reason.
        reason: String,
    },
    /// Copied from a node's journal by the PR-B first-boot migration.
    Migrated {
        /// The journal node it was copied from.
        node: u64,
        /// Its sequence number on that node's chain.
        node_seq: u64,
        /// Whether it was that chain's opening entry.
        opening: bool,
        /// A migrated amendment's reason digest, hex; `None` for a configured card.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// One entry of the fleet-shared history, as the store holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEntry {
    /// The entry's key: its identity.
    pub key: EntryKey,
    /// The first instant it prices, inclusive.
    pub effective_from: u64,
    /// The first instant it does not, exclusive; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When it was appended, wall-clock milliseconds.
    pub appended_at: u64,
    /// Why it exists.
    pub author: EntryAuthor,
    /// Who or what wrote it: "config/reload by <actor>", "boot of node <id>", ... The entry is
    /// the audited record of a card change.
    pub actor: String,
    /// The key of the head it extended.
    pub base: Option<EntryKey>,
    /// The writer's durable node id.
    pub writer: u64,
    /// The card fields that changed from the entry it extended (`rate_card`, `per_request_fee`,
    /// `planes.<p>.rate_card`, ...).
    pub set_fields: Vec<String>,
    /// The whole card.
    pub card: CardFields,
    /// An optional signed-correction envelope, as opaque bytes.
    pub correction: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryJson {
    v: u32,
    from: u64,
    #[serde(default)]
    until: Option<u64>,
    appended_at: u64,
    author: EntryAuthor,
    actor: String,
    #[serde(default)]
    base: Option<String>,
    writer: u64,
    #[serde(default)]
    set: Vec<String>,
    card: serde_json::Value,
    #[serde(default)]
    correction: Option<String>,
}

impl StoredEntry {
    #[must_use]
    pub fn value(&self) -> Vec<u8> {
        let card: serde_json::Value =
            serde_json::from_slice(&self.card.to_bytes()).unwrap_or(serde_json::Value::Null);
        let json = EntryJson {
            v: 1,
            from: self.effective_from,
            until: self.effective_until,
            appended_at: self.appended_at,
            author: self.author.clone(),
            actor: self.actor.clone(),
            base: self.base.map(|k| k.hex()),
            writer: self.writer,
            set: self.set_fields.clone(),
            card,
            correction: self.correction.as_deref().map(hex::encode),
        };
        serde_json::to_vec(&json).unwrap_or_default()
    }

    pub fn from_value(key: EntryKey, value: &[u8]) -> std::result::Result<Self, String> {
        let json: EntryJson = serde_json::from_slice(value)
            .map_err(|e| format!("card entry {key}: not an entry: {e}"))?;
        if json.v != 1 {
            return Err(format!("card entry {key}: version {} is not known", json.v));
        }
        let card = CardFields::from_bytes(
            &serde_json::to_vec(&json.card).map_err(|e| format!("card entry {key}: {e}"))?,
        )?;
        let base = match json.base {
            Some(hex) => Some(
                EntryKey::parse_hex(&hex)
                    .ok_or_else(|| format!("card entry {key}: base `{hex}` is not a key"))?,
            ),
            None => None,
        };
        let correction = match json.correction {
            Some(h) => Some(
                hex::decode(&h)
                    .map_err(|e| format!("card entry {key}: correction envelope: {e}"))?,
            ),
            None => None,
        };
        Ok(StoredEntry {
            key,
            effective_from: json.from,
            effective_until: json.until,
            appended_at: json.appended_at,
            author: json.author,
            actor: json.actor,
            base,
            writer: json.writer,
            set_fields: json.set,
            card,
            correction,
        })
    }
}
/// A VOID: the entry `voided` is never in force, and its id stays known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoidRecord {
    /// The voided entry's key, hex.
    pub voided: String,
    /// The voiding node's durable id.
    pub voider: u64,
    /// When it was voided, wall-clock milliseconds.
    pub at_ms: u64,
    /// Who voided it.
    pub actor: String,
    /// Why it was voided (`void`).
    pub why: String,
}

/// The authorized cutover, separate from the immutable authored time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub effective_from: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Activating,
    Active,
    Retiring,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    version: u32,
    digest: [u8; 32],
    own: bool,
    phase: Phase,
    activation: Option<Activation>,
}

#[derive(Debug, Clone)]
pub struct StoredIntent {
    pub entry: StoredEntry,
    pub own: bool,
    pub phase: Phase,
    pub activation: Option<Activation>,
}

/// A fully validated, coherent observation. Prepared and retiring originals are
/// retained for explicit recovery and never appear in `entries`.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub entries: BTreeMap<EntryKey, StoredEntry>,
    pub intents: BTreeMap<EntryKey, StoredIntent>,
    pub activations: BTreeMap<EntryKey, Activation>,
    pub voids: Vec<VoidRecord>,
    pub head: Option<EntryKey>,
}

impl Snapshot {
    /// Preserve the old key ordering, opening arbitration, amendments and voids.
    /// The runtime supplies its existing rate/class registration conversion.
    pub fn history(&self, rate_card: impl Fn(&CardFields) -> RateCard) -> History {
        self.resolve(None, &rate_card)
    }

    /// A node keeps its own configured prices while still seeing amendments.
    pub fn node_history(
        &self,
        node: u64,
        own: Option<EntryKey>,
        rate_card: impl Fn(&CardFields) -> RateCard,
    ) -> History {
        let opening = own
            .and_then(|key| self.entries.get(&key))
            .filter(|e| is_opening(e))
            .map(|e| e.key);
        let mut history = self.resolve(opening, &rate_card);
        if let Some(own) = own {
            for entry in self.entries.range(own..).skip(1).map(|(_, e)| e) {
                if entry.writer != node && matches!(entry.author, EntryAuthor::Change) {
                    history.void(&entry.key);
                }
            }
        }
        history
    }

    fn resolve(
        &self,
        own_opening: Option<EntryKey>,
        rate_card: &impl Fn(&CardFields) -> RateCard,
    ) -> History {
        let winner =
            own_opening.or_else(|| self.entries.values().find(|e| is_opening(e)).map(|e| e.key));
        let mut history = History::new();
        for entry in self.entries.values() {
            let author = match &entry.author {
                EntryAuthor::Opening {} | EntryAuthor::Migrated { opening: true, .. } => {
                    Author::Opening
                }
                EntryAuthor::Amend { reason }
                | EntryAuthor::Migrated {
                    reason: Some(reason),
                    ..
                } => Author::Amend {
                    // Validation has already established the complete reason hash.
                    reason_hash: hex::decode(reason)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .unwrap_or([0; 32]),
                },
                _ => Author::Config { policy_epoch: 0 },
            };
            history.insert(
                entry.key,
                CardEntryDraft {
                    effective_from: self
                        .activations
                        .get(&entry.key)
                        .map_or(entry.effective_from, |a| a.effective_from),
                    effective_until: entry.effective_until,
                    card: rate_card(&entry.card),
                    appended_at: entry.appended_at,
                    author,
                },
            );
        }
        for entry in self
            .entries
            .values()
            .filter(|e| is_opening(e) && Some(e.key) != winner)
        {
            history.void(&entry.key);
        }
        for void in &self.voids {
            if let Some(key) = EntryKey::parse_hex(&void.voided) {
                history.void(&key);
            }
        }
        history
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Corrupt,
    Conflict,
    Missing,
    WrongPhase,
    Access(AccessError),
    Backend(Failure),
}
type Result<T> = std::result::Result<T, Error>;
impl From<AccessError> for Error {
    fn from(e: AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Backend(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Conflict,
    OpIdConflict,
    Pending(PendingId),
    Reconcile(PendingId),
    Busy(PendingId),
    NoEffect(Failure),
}

/// An exact native operation. Keep this owner until it resolves. The pending id
/// is installed before awaiting the first send, including cancellation paths.
/// Preparing a replacement does not resolve this operation.
pub struct PricePlan {
    attachment: usize,
    candidate: PreparedCandidate,
    pending: Option<PendingId>,
    decided: Option<Outcome>,
    publication: Option<StoredIntent>,
}
impl PricePlan {
    /// Publication is available only after this exact operation returned Applied.
    /// A durable activation intent alone never grants publication.
    pub fn publication(&self) -> Option<&StoredIntent> {
        (self.decided == Some(Outcome::Applied))
            .then_some(self.publication.as_ref())
            .flatten()
    }
    pub fn pending_id(&self) -> Option<PendingId> {
        self.pending
    }
}

pub struct Prices<'a> {
    store: &'a CoreStore,
}
impl CoreStore {
    pub fn prices(&self) -> Prices<'_> {
        Prices { store: self }
    }
}

fn at(tag: u8, key: Option<EntryKey>) -> Address {
    let mut bytes = vec![tag];
    if let Some(key) = key {
        bytes.extend_from_slice(key.as_bytes());
    }
    Address {
        namespace: PRICES.0,
        key: bytes,
    }
}
fn encode<T: Serialize>(v: &T) -> Result<Secret<Vec<u8>>> {
    serde_json::to_vec(v)
        .map(Secret::new)
        .map_err(|_| Error::Invalid)
}
fn decode<T: serde::de::DeserializeOwned>(v: &Secret<Vec<u8>>) -> Result<T> {
    serde_json::from_slice(v.expose(&crate::seal::lend())).map_err(|_| Error::Corrupt)
}
fn is_opening(entry: &StoredEntry) -> bool {
    matches!(
        entry.author,
        EntryAuthor::Opening {} | EntryAuthor::Migrated { opening: true, .. }
    )
}
fn validate_entry(entry: &StoredEntry) -> Result<()> {
    if entry
        .effective_until
        .is_some_and(|until| until <= entry.effective_from)
        || entry.base == Some(entry.key)
    {
        return Err(Error::Corrupt);
    }
    if let EntryAuthor::Amend { reason }
    | EntryAuthor::Migrated {
        reason: Some(reason),
        ..
    } = &entry.author
    {
        if !hex::decode(reason).is_ok_and(|v| v.len() == 32) {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
fn validated(
    key: EntryKey,
    value: &Secret<Vec<u8>>,
    status: &Secret<Vec<u8>>,
) -> Result<(StoredEntry, Status)> {
    let bytes = value.expose(&crate::seal::lend());
    let entry = StoredEntry::from_value(key, bytes).map_err(|_| Error::Corrupt)?;
    validate_entry(&entry)?;
    let status: Status = decode(status)?;
    if status.version != 1
        || status.digest != sha256(bytes)
        || (!status.own && (status.phase != Phase::Active || status.activation.is_some()))
        || (status.own
            && matches!(status.phase, Phase::Activating | Phase::Active)
                != status.activation.is_some())
    {
        return Err(Error::Corrupt);
    }
    if let Some(a) = status.activation {
        if is_opening(&entry) != (a.effective_from == 0)
            || entry
                .effective_until
                .is_some_and(|until| a.effective_from >= until)
        {
            return Err(Error::Corrupt);
        }
    }
    Ok((entry, status))
}
fn head_value(value: Option<&Secret<Vec<u8>>>) -> Result<Option<EntryKey>> {
    value
        .map(|v| {
            let bytes = v.expose(&crate::seal::lend());
            let key = bytes.as_slice().try_into().map_err(|_| Error::Corrupt)?;
            Ok(EntryKey(key))
        })
        .transpose()
}
fn intent(entry: StoredEntry, status: &Status) -> StoredIntent {
    StoredIntent {
        entry,
        own: status.own,
        phase: status.phase,
        activation: status.activation,
    }
}

impl Prices<'_> {
    async fn read(&self, addresses: Vec<Address>) -> Result<Vec<Option<Secret<Vec<u8>>>>> {
        let count = addresses.len();
        let result = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses,
                time: None,
            }))
            .await?;
        match result {
            ReadResult::Values {
                observed_at,
                values,
            } if observed_at.authority == self.store.info().clock_authority
                && values.len() == count =>
            {
                Ok(values)
            }
            _ => Err(Error::Corrupt),
        }
    }

    fn plan(
        &self,
        guards: Vec<(Address, Option<Secret<Vec<u8>>>)>,
        changes: Vec<(Address, Secret<Vec<u8>>)>,
        publication: Option<StoredIntent>,
    ) -> Result<PricePlan> {
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates: guards
                .into_iter()
                .map(|(address, value)| Predicate {
                    address,
                    expected: value.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                })
                .collect(),
            mutations: changes
                .into_iter()
                .map(|(address, value)| Mutation::Put { address, value })
                .collect(),
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        Ok(PricePlan {
            attachment: self.store as *const CoreStore as usize,
            candidate,
            pending: None,
            decided: None,
            publication,
        })
    }

    /// Persist the full original. Own configured prices are inert until activated;
    /// historical amendments/imports publish with this operation's Applied decision.
    /// `base` remains the author's actual predecessor, which can differ from the
    /// fleet's newest entry; both its bytes and the observed head are guarded.
    pub async fn prepare(&self, entry: StoredEntry, own: bool) -> Result<PricePlan> {
        validate_entry(&entry).map_err(|_| Error::Invalid)?;
        let mut addresses = vec![
            at(b'E', Some(entry.key)),
            at(b'S', Some(entry.key)),
            at(b'H', None),
        ];
        if let Some(base) = entry.base {
            addresses.push(at(b'E', Some(base)));
            addresses.push(at(b'S', Some(base)));
        }
        let values = self.read(addresses.clone()).await?;
        if values[0].is_some() || values[1].is_some() {
            return Err(Error::Conflict);
        }
        let head = head_value(values[2].as_ref())?;
        if let Some(base) = entry.base {
            let (_, status) = validated(
                base,
                values[3].as_ref().ok_or(Error::Missing)?,
                values[4].as_ref().ok_or(Error::Missing)?,
            )?;
            if status.phase != Phase::Active {
                return Err(Error::WrongPhase);
            }
        }
        let bytes = Secret::new(entry.value());
        // Validate the encoded form too; never persist a lossy/default encoding.
        let status = Status {
            version: 1,
            digest: sha256(bytes.expose(&crate::seal::lend())),
            own,
            phase: if own { Phase::Prepared } else { Phase::Active },
            activation: None,
        };
        let status_bytes = encode(&status)?;
        validated(entry.key, &bytes, &status_bytes)?;
        let mut changes = vec![
            (at(b'E', Some(entry.key)), bytes),
            (at(b'S', Some(entry.key)), status_bytes),
        ];
        if !own && head.is_none_or(|head| entry.key > head) {
            changes.push((at(b'H', None), Secret::new(entry.key.as_bytes().to_vec())));
        }
        let publication = (!own).then(|| intent(entry, &status));
        self.plan(
            addresses.into_iter().zip(values).collect(),
            changes,
            publication,
        )
    }

    /// Persist authorization and the immutable cutover before final publication.
    /// Once activation is authorized, retirement is prohibited; explicit recovery
    /// must finish that activation before superseding it.
    pub async fn authorize_activation(
        &self,
        key: EntryKey,
        activation: Activation,
    ) -> Result<PricePlan> {
        self.transition(key, Phase::Prepared, Phase::Activating, Some(activation))
            .await
    }
    pub async fn activate(&self, key: EntryKey) -> Result<PricePlan> {
        self.transition(key, Phase::Activating, Phase::Active, None)
            .await
    }
    /// Retirement authorization is itself durable, preventing restart from
    /// reinterpreting an uncertain retirement as permission to activate.
    pub async fn authorize_retirement(&self, key: EntryKey) -> Result<PricePlan> {
        self.transition(key, Phase::Prepared, Phase::Retiring, None)
            .await
    }
    pub async fn retire(&self, key: EntryKey) -> Result<PricePlan> {
        self.transition(key, Phase::Retiring, Phase::Retired, None)
            .await
    }
    async fn transition(
        &self,
        key: EntryKey,
        from: Phase,
        to: Phase,
        activation: Option<Activation>,
    ) -> Result<PricePlan> {
        let addresses = vec![at(b'E', Some(key)), at(b'S', Some(key)), at(b'H', None)];
        let values = self.read(addresses.clone()).await?;
        let bytes = values[0].as_ref().ok_or(Error::Missing)?;
        let (entry, mut status) = validated(key, bytes, values[1].as_ref().ok_or(Error::Missing)?)?;
        if !status.own || status.phase != from {
            return Err(Error::WrongPhase);
        }
        let head = head_value(values[2].as_ref())?;
        status.phase = to;
        if activation.is_some() {
            status.activation = activation;
        }
        let status_bytes = encode(&status)?;
        validated(key, bytes, &status_bytes).map_err(|_| Error::Invalid)?;
        let mut changes = vec![(at(b'S', Some(key)), status_bytes)];
        if to == Phase::Active && head.is_none_or(|head| key > head) {
            changes.push((at(b'H', None), Secret::new(key.as_bytes().to_vec())));
        }
        let publication = (to == Phase::Active).then(|| intent(entry, &status));
        self.plan(
            addresses.into_iter().zip(values).collect(),
            changes,
            publication,
        )
    }

    /// Persist a future-only void, retaining its audit fields and target identity.
    /// `now_ms` is the owning node's clock, as in the existing price API.
    pub async fn void(&self, record: VoidRecord, now_ms: u64) -> Result<PricePlan> {
        let key = EntryKey::parse_hex(&record.voided).ok_or(Error::Invalid)?;
        if record.why != "void" || record.at_ms > now_ms {
            return Err(Error::Invalid);
        }
        let void_at = void_address(key, record.voider);
        let addresses = vec![at(b'E', Some(key)), at(b'S', Some(key)), void_at.clone()];
        let values = self.read(addresses.clone()).await?;
        let (entry, status) = validated(
            key,
            values[0].as_ref().ok_or(Error::Missing)?,
            values[1].as_ref().ok_or(Error::Missing)?,
        )?;
        if status.phase != Phase::Active
            || status
                .activation
                .map_or(entry.effective_from, |a| a.effective_from)
                <= now_ms
        {
            return Err(Error::WrongPhase);
        }
        if values[2].is_some() {
            return Err(Error::Conflict);
        }
        self.plan(
            addresses.into_iter().zip(values).collect(),
            vec![(void_at, encode(&record)?)],
            None,
        )
    }

    pub async fn submit(&self, plan: &mut PricePlan) -> Result<Outcome> {
        if let Some(outcome) = plan.decided {
            return Ok(outcome);
        }
        // Detect accidentally retargeting a retained plan to another attachment.
        if plan.attachment != self.store as *const CoreStore as usize
            || plan.candidate.candidate().id.dataset != self.store.info().dataset
        {
            return Err(Error::Invalid);
        }
        let submission = if let Some(id) = plan.pending {
            self.store.retry(id).await?
        } else {
            // CoreStore registers synchronously before the native future yields.
            // Keep the operation id here before awaiting, so cancellation resumes
            // this original instead of allocating a replacement attempt.
            plan.pending = Some(PendingId(plan.candidate.candidate().id.operation));
            match self.store.submit(plan.candidate.clone()).await {
                Ok(submission) => submission,
                Err(error) => {
                    plan.pending = None;
                    return Err(error.into());
                }
            }
        };
        let outcome = outcome(submission)?;
        match outcome {
            Outcome::Applied | Outcome::Conflict | Outcome::OpIdConflict => {
                plan.decided = Some(outcome);
                plan.pending = None;
            }
            Outcome::NoEffect(_) => plan.pending = None,
            _ => {}
        }
        Ok(outcome)
    }

    /// Startup/rescan observes canonical atomic facts, never legacy partial rows.
    /// Live publishers must first resolve their retained PricePlans; a read does
    /// not resolve an original unknown operation or replace its Applied decision.
    pub async fn snapshot(&self) -> Result<Snapshot> {
        let found = self.store.scan(PRICES, vec![], None).await?;
        let guard = scan_guard(PRICES, found.generation);
        let mut rows: BTreeMap<_, _> = found.rows.into_iter().collect();
        let head = head_value(rows.remove(&at(b'H', None)).as_ref())?;
        let mut snapshot = Snapshot {
            head,
            ..Snapshot::default()
        };
        let entry_addresses: Vec<_> = rows
            .keys()
            .filter(|a| a.key.first() == Some(&b'E'))
            .cloned()
            .collect();
        for address in entry_addresses {
            let key = EntryKey(address.key[1..].try_into().map_err(|_| Error::Corrupt)?);
            let bytes = rows.remove(&address).ok_or(Error::Corrupt)?;
            let status_bytes = rows.remove(&at(b'S', Some(key))).ok_or(Error::Corrupt)?;
            let (entry, status) = validated(key, &bytes, &status_bytes)?;
            if status.phase == Phase::Active {
                if let Some(activation) = status.activation {
                    snapshot.activations.insert(key, activation);
                }
                snapshot.entries.insert(key, entry.clone());
            }
            snapshot.intents.insert(key, intent(entry, &status));
        }
        for (address, bytes) in rows {
            let record: VoidRecord = decode(&bytes)?;
            let key = EntryKey::parse_hex(&record.voided).ok_or(Error::Corrupt)?;
            if address != void_address(key, record.voider)
                || record.why != "void"
                || !snapshot.entries.contains_key(&key)
            {
                return Err(Error::Corrupt);
            }
            snapshot.voids.push(record);
        }
        if head != snapshot.entries.keys().next_back().copied() {
            return Err(Error::Corrupt);
        }
        for stored in snapshot.intents.values() {
            if stored
                .entry
                .base
                .is_some_and(|base| !snapshot.entries.contains_key(&base))
            {
                return Err(Error::Corrupt);
            }
        }
        if !self.store.guards_hold(&[guard]).await? {
            return Err(Error::Conflict);
        }
        Ok(snapshot)
    }
}
fn void_address(key: EntryKey, voider: u64) -> Address {
    let mut address = at(b'V', Some(key));
    address.key.extend_from_slice(&voider.to_be_bytes());
    address
}
fn outcome(submission: Submission) -> Result<Outcome> {
    Ok(match submission.result {
        SubmitResult::Decided(d) => match d.as_ref() {
            Decision::Applied(_) => Outcome::Applied,
            Decision::ConditionConflict => Outcome::Conflict,
            Decision::OpIdConflict => Outcome::OpIdConflict,
            Decision::ExpiredUnknown => Outcome::Reconcile(submission.id),
            _ => return Err(Error::Corrupt),
        },
        SubmitResult::NoEffect(f) => Outcome::NoEffect(f),
        SubmitResult::Uncertain => Outcome::Pending(submission.id),
        SubmitResult::Reconcile => Outcome::Reconcile(submission.id),
        SubmitResult::Busy => Outcome::Busy(submission.id),
    })
}

#[cfg(test)]
#[path = "prices_tests.rs"]
pub(crate) mod tests;
