// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-owned records. Core fences every commit with [`fences`] and judges every control
//! mutation in [`admit`]; a store runs M1 and never decodes, judges or proves anything here.

use std::ops::RangeInclusive;

use super::{
    Address, Candidate, DatasetId, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
    PreparedCandidate, CANDIDATE_VERSION,
};
use crate::redacted::Secret;

/// Reserved metadata namespace, inaccessible to plugin host-record callers.
pub const NAMESPACE: NamespaceId = NamespaceId(*b"busbar.fence.v1\0");
/// Singleton dataset fence key within [`NAMESPACE`].
pub const DATASET_KEY: &[u8] = b"d";

/// Adapter-maintained namespace generation records. The key is the namespace's
/// exact sixteen bytes and a present value is its nonzero little-endian u64.
/// A missing record means generation zero. Ordinary candidates may predicate on
/// these records but must never mutate them directly. Each committed candidate
/// advances every mutated namespace once, atomically with its effects and slot row.
pub const GENERATION_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.scan.v1\0\0");

/// The 1.5.5 import namespace (MIGRATE-ON-BOOT's `IMPORT_NS`). A store's migrate writes it
/// with its own driver before admission, so it holds no receipt; core consumes it after Register.
pub const IMPORT_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.import.r0");

/// Per-writer slot records (G1), key `writer16 ‖ slot u32 BE`. A store keeps them in its own home,
/// never among the records, so a read or scan here sees nothing. Core never Puts, Deletes or
/// predicates them: the only mutation is the `DeleteRange{writer16, 20}` that [`writer_put`] adds
/// when a writer closes, the store's per-writer delete.
pub const SLOT_NS: NamespaceId = NamespaceId(*b"busbar.slot.v1\0\0");

/// Most execution epochs one writer holds live at once. A roll admits `e + 1` only from a
/// one-epoch window, so [`Writer::encode`] refuses a wider one and a transition moves at most two
/// epoch rows each way.
pub const MAX_LIVE_EPOCHS: u64 = 2;

/// The value of a live epoch row ([`Key::Epoch`]).
pub const EPOCH_VALUE: &[u8] = b"BSE1";

/// Slot keys are `writer16 ‖ slot u32 BE`.
const SLOT_KEY_LENGTH: u64 = 20;

/// The live epochs of a closed or absent writer row.
const NONE_LIVE: RangeInclusive<u64> = RangeInclusive::new(1, 0);

/// Whether a record in `namespace` makes a dataset non-empty for Initialize's emptiness proof.
/// Every namespace counts except the reserved import set R = {[`IMPORT_NAMESPACE`]}; receipts
/// always count.
#[must_use]
pub fn counts_toward_empty(namespace: NamespaceId) -> bool {
    namespace != IMPORT_NAMESPACE
}

/// Known control keys; an unrecognized key is not an extensible grant format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Dataset-wide writer generation.
    Dataset,
    /// One registered writer's execution epochs.
    Writer([u8; 16]),
    /// One live execution epoch of a writer, `'e' ‖ writer ‖ epoch u64 BE`: present iff
    /// `retired_through < epoch <= admitted_through` for that writer.
    Epoch([u8; 16], u64),
}

impl Key {
    /// Parse exactly one known control key, rejecting zero writer identities and epoch zero.
    pub fn decode(key: &[u8]) -> Option<Self> {
        if key == DATASET_KEY {
            return Some(Self::Dataset);
        }
        let (&tag, rest) = key.split_first()?;
        let (writer, epoch) = rest.split_at_checked(16)?;
        let writer: [u8; 16] = writer.try_into().ok()?;
        if writer == [0; 16] {
            return None;
        }
        match tag {
            b'w' if epoch.is_empty() => Some(Self::Writer(writer)),
            b'e' => {
                let epoch = u64::from_be_bytes(epoch.try_into().ok()?);
                (epoch != 0).then_some(Self::Epoch(writer, epoch))
            }
            _ => None,
        }
    }
}

/// Validate a normal conditional control-record replacement. The caller must
/// read `previous` and publish the replacement under the same native transaction.
/// Deletes/range deletes are forbidden. Dataset creation is restricted to the
/// separately validated initialization below; no missing root becomes a grant.
pub fn replacement(
    key: Key,
    dataset: DatasetId,
    previous: Option<&[u8]>,
    next: &[u8],
) -> Result<(), Failure> {
    match key {
        Key::Dataset => {
            let old = Dataset::decode(previous.ok_or(Failure::Refused)?).ok_or(Failure::Corrupt)?;
            if old.id != dataset {
                return Err(Failure::Corrupt);
            }
            let next = Dataset::decode(next).ok_or(Failure::Refused)?;
            old.permits_successor(next)
                .then_some(())
                .ok_or(Failure::Refused)
        }
        Key::Writer(writer) => {
            if writer == [0; 16] {
                return Err(Failure::Refused);
            }
            let next = Writer::decode(next).ok_or(Failure::Refused)?;
            let permitted = match previous {
                Some(old) => Writer::decode(old)
                    .ok_or(Failure::Corrupt)?
                    .permits_successor(next),
                None => {
                    next == Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                }
            };
            permitted.then_some(()).ok_or(Failure::Refused)
        }
        // An epoch row is created once, while its epoch is live, and only ever deleted after.
        Key::Epoch(..) => (previous.is_none() && next == EPOCH_VALUE)
            .then_some(())
            .ok_or(Failure::Refused),
    }
}

/// Recognize initial authority together with opaque initial records. This validates
/// the candidate shape only: every address has one Absent predicate and one Put.
/// Exactly the dataset root and initial writer occupy the control namespace;
/// additional records cannot use either reserved adapter namespace.
///
/// Core fences it with `Absent(root)`; no store check.
#[must_use]
pub fn initialization<O>(prepared: &PreparedCandidate<O>, dataset: DatasetId) -> bool {
    // The prepared candidate is already validated (LINT-RULES R26); this reads its shape only.
    let candidate = prepared.candidate();
    if candidate.codec != CANDIDATE_VERSION
        || candidate.id.dataset != dataset
        || candidate.id.writer_epoch != 1
        || candidate.id.execution_epoch != 1
        || candidate.predicates.len() < 2
        || candidate.predicates.len() != candidate.mutations.len()
        || !candidate.result.0.is_empty()
        || candidate.time.is_some()
    {
        return false;
    }
    let classify = |namespace, key: &[u8]| {
        if namespace == GENERATION_NAMESPACE.0 {
            return None;
        }
        if namespace != NAMESPACE.0 {
            return Some(0);
        }
        match Key::decode(key)? {
            Key::Dataset => Some(1),
            Key::Writer(writer) if writer == candidate.id.writer => Some(2),
            _ => None,
        }
    };
    let mut addresses = Vec::new();
    if addresses
        .try_reserve_exact(candidate.predicates.len())
        .is_err()
    {
        return false;
    }
    for predicate in &candidate.predicates {
        if !matches!(predicate.expected, ExpectedValue::Absent)
            || classify(predicate.address.namespace, &predicate.address.key).is_none()
        {
            return false;
        }
        addresses.push(&predicate.address);
    }
    addresses.sort();
    let mut controls = 0;
    for mutation in &candidate.mutations {
        let Mutation::Put { address, value } = mutation else {
            return false;
        };
        if addresses.binary_search(&address).is_err() {
            return false;
        }
        let Some(kind) = classify(address.namespace, &address.key) else {
            return false;
        };
        let valid = match kind {
            0 => true,
            1 => {
                Dataset::decode(&value.0)
                    == Some(Dataset {
                        id: dataset,
                        writer_epoch: 1,
                    })
            }
            2 => {
                Writer::decode(&value.0)
                    == Some(Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    })
            }
            _ => false,
        };
        if !valid {
            return false;
        }
        controls |= kind;
    }
    controls == 3
}

/// Per-writer fence key; identifiers are never reused after restore.
#[must_use]
pub fn writer_key(writer: [u8; 16]) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = b'w';
    key[1..].copy_from_slice(&writer);
    key
}

/// Epoch-row key ([`Key::Epoch`]): `'e' ‖ writer ‖ epoch u64 BE`.
#[must_use]
pub fn epoch_key(writer: [u8; 16], epoch: u64) -> [u8; 25] {
    let mut key = [0; 25];
    key[0] = b'e';
    key[1..17].copy_from_slice(&writer);
    key[17..].copy_from_slice(&epoch.to_be_bytes());
    key
}

/// The address of `writer`'s epoch row for `epoch`.
#[must_use]
pub fn epoch_row(writer: [u8; 16], epoch: u64) -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: epoch_key(writer, epoch).to_vec(),
    }
}

/// The live epochs of an optional writer row; an absent row has none.
#[must_use]
pub fn live(writer: Option<Writer>) -> RangeInclusive<u64> {
    writer.map_or(NONE_LIVE, Writer::live)
}

fn root_address() -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: DATASET_KEY.to_vec(),
    }
}

/// The FENCE conditions of `prepared` (N9): `Absent(root)` for an Initialize, else the exact
/// root at the candidate's writer epoch and the stamping writer's epoch row at its execution
/// epoch. Only the store encode calls it, right after [`admit`]; equal candidates carry equal
/// fences, so they never enter the candidate fingerprint.
#[must_use]
pub fn fences<O>(prepared: &PreparedCandidate<O>) -> Vec<Predicate> {
    let id = prepared.candidate().id;
    if initialization(prepared, id.dataset) {
        return vec![Predicate {
            address: root_address(),
            expected: ExpectedValue::Absent,
        }];
    }
    let root = Dataset {
        id: id.dataset,
        writer_epoch: id.writer_epoch,
    };
    vec![
        Predicate {
            address: root_address(),
            expected: ExpectedValue::Exact(Secret::new(root.bytes().to_vec())),
        },
        Predicate {
            address: epoch_row(id.writer, id.execution_epoch),
            expected: ExpectedValue::Exact(Secret::new(EPOCH_VALUE.to_vec())),
        },
    ]
}

/// The mutations of one writer-row transition: Put `writer`'s row, Put the epoch rows in
/// `live(next) ∖ live(old)` and Delete those in `live(old) ∖ live(next)`. When `next` is closed
/// (`live(next)` empty, i.e. `retired_through == admitted_through`) add
/// `DeleteRange{SLOT_NS, writer, 20}`, whatever `old` is: a repeat deletes nothing. The caller
/// guards the writer row (`Absent` or `Exact(old)`) and [`admit`] judges the transition. `None`
/// for a zero writer or a row that does not encode.
#[must_use]
pub fn writer_put(writer: [u8; 16], old: Option<Writer>, next: Writer) -> Option<Vec<Mutation>> {
    if writer == [0; 16] {
        return None;
    }
    if let Some(old) = old {
        old.encode()?;
    }
    let row = next.encode()?;
    let mut mutations = vec![Mutation::Put {
        address: Address {
            namespace: NAMESPACE.0,
            key: writer_key(writer).to_vec(),
        },
        value: Secret::new(row.to_vec()),
    }];
    transition(writer, old, next, |effect| {
        mutations.push(effect.mutation())
    });
    Some(mutations)
}

/// One epoch-row or slot effect of a writer transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    /// Put the epoch row: the epoch became live.
    Admit([u8; 16], u64),
    /// Delete the epoch row: the epoch retired.
    Retire([u8; 16], u64),
    /// Delete the closed writer's slot records.
    Close([u8; 16]),
}

impl Effect {
    fn mutation(self) -> Mutation {
        match self {
            Self::Admit(writer, epoch) => Mutation::Put {
                address: epoch_row(writer, epoch),
                value: Secret::new(EPOCH_VALUE.to_vec()),
            },
            Self::Retire(writer, epoch) => Mutation::Delete(epoch_row(writer, epoch)),
            Self::Close(writer) => Mutation::DeleteRange {
                namespace: SLOT_NS,
                prefix: writer.to_vec(),
                exact_key_length: SLOT_KEY_LENGTH,
            },
        }
    }
}

/// Emit the effects of `writer` moving from `old` to `next`: admitted epochs, then retired ones,
/// then the closure. Each live window holds at most [`MAX_LIVE_EPOCHS`] epochs.
fn transition(writer: [u8; 16], old: Option<Writer>, next: Writer, mut emit: impl FnMut(Effect)) {
    let (before, after) = (live(old), next.live());
    for epoch in after.clone() {
        if !before.contains(&epoch) {
            emit(Effect::Admit(writer, epoch));
        }
    }
    for epoch in before {
        if !after.contains(&epoch) {
            emit(Effect::Retire(writer, epoch));
        }
    }
    if after.is_empty() {
        emit(Effect::Close(writer));
    }
}

/// Judge every control and slot mutation of `prepared` before its first byte reaches a store.
/// The store adapter's `commit`, the one path every store commit takes, runs it.
///
/// (i) An Initialize passes [`initialization`]. (ii) Otherwise every control-namespace mutation
/// is a Put of a known key or a Delete of an epoch row; a root or writer row is only Put, guarded
/// `Absent` or `Exact(old)` on its own address, and passes [`replacement`] (a writer row within
/// [`MAX_LIVE_EPOCHS`]). (iii) The epoch-row and [`SLOT_NS`] mutations are exactly those
/// [`writer_put`] derives from the writer Puts, no predicate names [`SLOT_NS`], and
/// [`GENERATION_NAMESPACE`] is never mutated. (iv) A Put of the stamping writer's own row still
/// admits the candidate's execution epoch, so no transition closes the writer that stamps it.
/// Every refusal is [`Failure::Refused`].
pub fn admit<O>(prepared: &PreparedCandidate<O>) -> Result<(), Failure> {
    let candidate = prepared.candidate();
    if candidate
        .predicates
        .iter()
        .any(|predicate| predicate.address.namespace == SLOT_NS.0)
    {
        return Err(Failure::Refused);
    }
    if initialization(prepared, candidate.id.dataset) {
        // `initialization` judges the whole shape: every record is an Absent-guarded Put, so a
        // slot record among its opaque ones would need the SLOT_NS predicate refused above.
        return Ok(());
    }
    let mut claimed = Vec::new();
    let mut derived = Vec::new();
    for mutation in &candidate.mutations {
        match mutation {
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => {
                if *namespace == SLOT_NS && *exact_key_length == SLOT_KEY_LENGTH {
                    let writer: [u8; 16] =
                        prefix.as_slice().try_into().map_err(|_| Failure::Refused)?;
                    claimed.push(Effect::Close(writer));
                } else if [NAMESPACE, SLOT_NS, GENERATION_NAMESPACE].contains(namespace) {
                    return Err(Failure::Refused);
                }
            }
            Mutation::Put { address, .. } | Mutation::Delete(address)
                if address.namespace == SLOT_NS.0
                    || address.namespace == GENERATION_NAMESPACE.0 =>
            {
                return Err(Failure::Refused);
            }
            Mutation::Delete(address) if address.namespace == NAMESPACE.0 => {
                match Key::decode(&address.key) {
                    Some(Key::Epoch(writer, epoch)) => claimed.push(Effect::Retire(writer, epoch)),
                    _ => return Err(Failure::Refused),
                }
            }
            Mutation::Put { address, value } if address.namespace == NAMESPACE.0 => {
                match Key::decode(&address.key).ok_or(Failure::Refused)? {
                    Key::Epoch(writer, epoch) if value.0 == EPOCH_VALUE => {
                        claimed.push(Effect::Admit(writer, epoch));
                    }
                    Key::Epoch(..) => return Err(Failure::Refused),
                    key => judge(candidate, key, address, &value.0, &mut derived)?,
                }
            }
            Mutation::Put { .. } | Mutation::Delete(_) => {}
        }
    }
    claimed.sort();
    derived.sort();
    (claimed == derived).then_some(()).ok_or(Failure::Refused)
}

/// `admit` (ii) and (iv) for one root or writer row Put, adding a writer's derived effects.
fn judge<O>(
    candidate: &Candidate<O>,
    key: Key,
    address: &Address,
    value: &[u8],
    derived: &mut Vec<Effect>,
) -> Result<(), Failure> {
    let previous = match candidate
        .predicates
        .iter()
        .find(|predicate| predicate.address == *address)
        .map(|predicate| &predicate.expected)
    {
        Some(ExpectedValue::Absent) => None,
        Some(ExpectedValue::Exact(old)) => Some(old.0.as_slice()),
        None => return Err(Failure::Refused),
    };
    replacement(key, candidate.id.dataset, previous, value).map_err(|_| Failure::Refused)?;
    if let Key::Writer(writer) = key {
        let next = Writer::decode(value).ok_or(Failure::Refused)?;
        let old = match previous {
            Some(old) => Some(Writer::decode(old).ok_or(Failure::Refused)?),
            None => None,
        };
        if writer == candidate.id.writer && !next.admits(candidate.id.execution_epoch) {
            return Err(Failure::Refused);
        }
        transition(writer, old, next, |effect| derived.push(effect));
    }
    Ok(())
}

/// Dataset-wide writer generation, independent of the application's semver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dataset {
    /// Must equal the opened physical dataset's identity.
    pub id: DatasetId,
    /// Monotonically increasing writer generation; zero never grants execution.
    pub writer_epoch: u64,
}

impl Dataset {
    /// Fixed versioned representation; rejects unregistered identities.
    pub fn encode(self) -> Option<[u8; 32]> {
        (self.id.0 != [0; 16] && self.writer_epoch != 0).then(|| self.bytes())
    }

    /// The representation, unchecked: a validated candidate's identity always encodes.
    fn bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(b"BSD1");
        bytes[8..24].copy_from_slice(&self.id.0);
        bytes[24..].copy_from_slice(&self.writer_epoch.to_le_bytes());
        bytes
    }

    /// Unknown versions, nonzero reserved bytes and trailing input are errors.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 || &bytes[..8] != b"BSD1\0\0\0\0" {
            return None;
        }
        let value = Self {
            id: DatasetId(bytes[8..24].try_into().ok()?),
            writer_epoch: u64::from_le_bytes(bytes[24..].try_into().ok()?),
        };
        value.encode()?;
        Some(value)
    }

    /// A conditional replacement may preserve or advance the generation only.
    #[must_use]
    pub fn permits_successor(self, next: Self) -> bool {
        self.encode().is_some()
            && next.encode().is_some()
            && self.id == next.id
            && next.writer_epoch >= self.writer_epoch
    }
}

/// Contiguous execution epochs admitted to a registered writer.
///
/// Epochs at or below the retired floor never execute again, including after
/// writer closure. Epochs above the admitted ceiling have not been granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Writer {
    /// Irreversible lower fence; it never decreases.
    pub retired_through: u64,
    /// Highest epoch ever admitted; it never decreases or wraps.
    pub admitted_through: u64,
}

impl Writer {
    /// Whether an unseen candidate has execution authority under this record.
    #[must_use]
    pub fn admits(self, epoch: u64) -> bool {
        self.retired_through <= self.admitted_through
            && epoch > self.retired_through
            && epoch <= self.admitted_through
    }

    /// The epochs with a live epoch row, `retired_through + 1 ..= admitted_through`: empty
    /// exactly when the writer is closed (`retired_through == admitted_through`).
    #[must_use]
    pub fn live(self) -> RangeInclusive<u64> {
        match self.retired_through.checked_add(1) {
            Some(first) => first..=self.admitted_through,
            None => NONE_LIVE,
        }
    }

    /// Fixed versioned representation, independent of backend physical format. A window of more
    /// than [`MAX_LIVE_EPOCHS`] live epochs has none.
    pub fn encode(self) -> Option<[u8; 24]> {
        if self.admitted_through == 0
            || self.retired_through > self.admitted_through
            || self.admitted_through - self.retired_through > MAX_LIVE_EPOCHS
        {
            return None;
        }
        let mut bytes = [0; 24];
        bytes[..4].copy_from_slice(b"BSW1");
        bytes[8..16].copy_from_slice(&self.retired_through.to_le_bytes());
        bytes[16..].copy_from_slice(&self.admitted_through.to_le_bytes());
        Some(bytes)
    }

    /// Decode exactly one known-version fence; malformed state never grants access.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 24 || &bytes[..8] != b"BSW1\0\0\0\0" {
            return None;
        }
        let value = Self {
            retired_through: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            admitted_through: u64::from_le_bytes(bytes[16..].try_into().ok()?),
        };
        value.encode()?;
        Some(value)
    }

    /// Core may admit future epochs or retire old ones, never reopen an old epoch.
    #[must_use]
    pub fn permits_successor(self, next: Self) -> bool {
        self.encode().is_some()
            && next.encode().is_some()
            && next.retired_through >= self.retired_through
            && next.admitted_through >= self.admitted_through
    }
}

#[cfg(test)]
#[path = "tests/control_d299_tests.rs"]
mod d299_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// `initialization` over a candidate the way a store sees it: prepared (validated once)
    /// first. A candidate `PreparedCandidate::new` refuses is never an initialization.
    fn init(candidate: Candidate, dataset: DatasetId) -> bool {
        PreparedCandidate::new(candidate).is_ok_and(|prepared| initialization(&prepared, dataset))
    }

    pub(super) fn initial() -> Candidate {
        use super::super::{Address, AttemptId, Predicate};
        use crate::Secret;
        let dataset = DatasetId([1; 16]);
        let root = Address {
            namespace: NAMESPACE.0,
            key: DATASET_KEY.to_vec(),
        };
        let writer = Address {
            namespace: NAMESPACE.0,
            key: writer_key([2; 16]).to_vec(),
        };
        Candidate {
            id: AttemptId {
                dataset,
                writer: [2; 16],
                operation: [3; 16],
                writer_epoch: 1,
                execution_epoch: 1,
            },
            codec: CANDIDATE_VERSION,
            predicates: vec![
                Predicate {
                    address: root.clone(),
                    expected: ExpectedValue::Absent,
                },
                Predicate {
                    address: writer.clone(),
                    expected: ExpectedValue::Absent,
                },
            ],
            mutations: vec![
                Mutation::Put {
                    address: root,
                    value: Secret::new(
                        Dataset {
                            id: dataset,
                            writer_epoch: 1,
                        }
                        .encode()
                        .unwrap()
                        .to_vec(),
                    ),
                },
                Mutation::Put {
                    address: writer,
                    value: Secret::new(
                        Writer {
                            retired_through: 0,
                            admitted_through: 1,
                        }
                        .encode()
                        .unwrap()
                        .to_vec(),
                    ),
                },
            ],
            time: None,
            result: Secret::new(Vec::new()),
        }
    }

    #[test]
    fn initialization_grants_only_one_absent_root_and_initial_writer() {
        use super::super::Address;
        use crate::Secret;
        let dataset = initial().id.dataset;
        assert!(init(initial(), dataset));
        let mut candidate = initial();
        candidate.id.execution_epoch = 2;
        assert!(!init(candidate, dataset));
        let mut candidate = initial();
        candidate.predicates[0].expected = ExpectedValue::Exact(Secret::new(Vec::new()));
        assert!(!init(candidate, dataset));
        let mut candidate = initial();
        candidate.mutations.push(Mutation::Delete(Address {
            namespace: [8; 16],
            key: Vec::new(),
        }));
        assert!(!init(candidate, dataset));
    }

    fn initial_with_record() -> Candidate {
        use super::super::{Address, Predicate};
        let mut candidate = initial();
        let address = Address {
            namespace: [8; 16],
            key: b"opaque-initial-record".to_vec(),
        };
        candidate.predicates.push(Predicate {
            address: address.clone(),
            expected: ExpectedValue::Absent,
        });
        candidate.mutations.push(Mutation::Put {
            address,
            value: crate::Secret::new(vec![255, 0, 1]),
        });
        candidate
    }

    #[test]
    fn initialization_accepts_atomic_opaque_records_without_interpreting_them() {
        let mut candidate = initial_with_record();
        // Matching is by exact address, independent of either list's order.
        candidate.predicates.rotate_left(1);
        candidate.mutations.reverse();
        let dataset = candidate.id.dataset;
        assert!(init(candidate, dataset));
        assert!(
            init(initial(), dataset),
            "inactive migration bootstrap remains control-only"
        );
    }

    #[test]
    fn initialization_rejects_unmatched_reserved_and_noninitial_effects() {
        use super::super::{Address, Predicate, TimeGuard};
        use crate::Secret;
        let rejected = |change: fn(&mut Candidate)| {
            let mut candidate = initial_with_record();
            change(&mut candidate);
            let dataset = candidate.id.dataset;
            assert!(!init(candidate, dataset));
        };
        rejected(|c| c.predicates[2].expected = ExpectedValue::Exact(Secret::new(Vec::new())));
        rejected(|c| c.predicates[2].address.key.push(0));
        rejected(|c| {
            c.predicates.pop();
        });
        rejected(|c| {
            c.predicates.push(Predicate {
                address: c.predicates[2].address.clone(),
                expected: ExpectedValue::Absent,
            });
        });
        rejected(|c| {
            c.mutations.push(Mutation::Put {
                address: c.predicates[2].address.clone(),
                value: Secret::new(Vec::new()),
            });
        });
        rejected(|c| {
            c.predicates.push(Predicate {
                address: c.predicates[2].address.clone(),
                expected: ExpectedValue::Absent,
            });
            c.mutations.push(Mutation::Put {
                address: c.predicates[2].address.clone(),
                value: Secret::new(vec![]),
            });
        });
        rejected(|c| {
            c.predicates.push(Predicate {
                address: Address {
                    namespace: [8; 16],
                    key: b"unmatched".to_vec(),
                },
                expected: ExpectedValue::Absent,
            });
            c.mutations.push(Mutation::Put {
                address: c.predicates[2].address.clone(),
                value: Secret::new(vec![]),
            });
        });
        rejected(|c| c.mutations[2] = Mutation::Delete(c.predicates[2].address.clone()));
        rejected(|c| {
            c.mutations[2] = Mutation::DeleteRange {
                namespace: NamespaceId([8; 16]),
                prefix: vec![],
                exact_key_length: 1,
            }
        });
        rejected(|c| {
            let address = Address {
                namespace: NAMESPACE.0,
                key: writer_key([7; 16]).to_vec(),
            };
            c.predicates[2].address = address.clone();
            c.mutations[2] = Mutation::Put {
                address,
                value: Secret::new(
                    Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            };
        });
        rejected(|c| {
            let address = Address {
                namespace: GENERATION_NAMESPACE.0,
                key: vec![8; 16],
            };
            c.predicates[2].address = address.clone();
            c.mutations[2] = Mutation::Put {
                address,
                value: Secret::new(1u64.to_le_bytes().to_vec()),
            };
        });
        rejected(|c| {
            c.time = Some(TimeGuard {
                not_before: None,
                before: None,
            })
        });
        rejected(|c| c.result = Secret::new(vec![1]));
        rejected(|c| {
            c.mutations[0] = Mutation::Put {
                address: c.predicates[0].address.clone(),
                value: Secret::new(
                    Dataset {
                        id: c.id.dataset,
                        writer_epoch: 2,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            }
        });
        rejected(|c| {
            c.mutations[1] = Mutation::Put {
                address: c.predicates[1].address.clone(),
                value: Secret::new(
                    Writer {
                        retired_through: 0,
                        admitted_through: 2,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            }
        });
        rejected(|c| c.id.writer_epoch = 2);
        rejected(|c| c.id.execution_epoch = 2);
    }

    #[test]
    fn normal_control_writes_cannot_initialize_or_reopen_retired_authority() {
        let dataset = DatasetId([1; 16]);
        let root = Dataset {
            id: dataset,
            writer_epoch: 1,
        }
        .encode()
        .unwrap();
        assert_eq!(
            replacement(Key::Dataset, dataset, None, &root),
            Err(Failure::Refused)
        );
        assert_eq!(
            replacement(Key::Dataset, dataset, Some(b"broken"), &root),
            Err(Failure::Corrupt)
        );
        let initial = Writer {
            retired_through: 0,
            admitted_through: 1,
        }
        .encode()
        .unwrap();
        let closed = Writer {
            retired_through: 1,
            admitted_through: 1,
        }
        .encode()
        .unwrap();
        assert_eq!(
            replacement(Key::Writer([2; 16]), dataset, None, &initial),
            Ok(())
        );
        assert_eq!(
            replacement(Key::Writer([2; 16]), dataset, Some(&initial), &closed),
            Ok(())
        );
        assert_eq!(
            replacement(Key::Writer([2; 16]), dataset, Some(&closed), &initial),
            Err(Failure::Refused)
        );
        assert_eq!(
            replacement(Key::Writer([2; 16]), dataset, None, &closed),
            Err(Failure::Refused)
        );
        assert!(Key::decode(&writer_key([0; 16])).is_none());
        assert!(Key::decode(b"unknown").is_none());
    }

    #[test]
    fn retirement_stays_closed_when_future_epochs_are_opened() {
        let first = Writer {
            retired_through: 0,
            admitted_through: 2,
        };
        let retired = Writer {
            retired_through: 1,
            admitted_through: 2,
        };
        let extended = Writer {
            retired_through: 1,
            admitted_through: 3,
        };
        assert!(first.permits_successor(retired));
        assert!(retired.permits_successor(extended));
        assert!(!retired.permits_successor(first));
        assert!(!extended.admits(0));
        assert!(!extended.admits(1));
        assert!(extended.admits(2));
        assert!(extended.admits(3));
        assert!(!extended.admits(4));
        assert_eq!(Writer::decode(&extended.encode().unwrap()), Some(extended));
        let closed = Writer {
            retired_through: u64::MAX,
            admitted_through: u64::MAX,
        };
        assert!(!closed.admits(u64::MAX));
        assert!(!closed.permits_successor(first));
    }

    #[test]
    fn malformed_and_cross_dataset_fences_do_not_grant_authority() {
        let dataset = Dataset {
            id: DatasetId([1; 16]),
            writer_epoch: 2,
        };
        let encoded = dataset.encode().unwrap();
        assert_eq!(Dataset::decode(&encoded), Some(dataset));
        assert!(!dataset.permits_successor(Dataset {
            writer_epoch: 1,
            ..dataset
        }));
        assert!(!dataset.permits_successor(Dataset {
            id: DatasetId([2; 16]),
            ..dataset
        }));
        for length in 0..encoded.len() {
            assert!(Dataset::decode(&encoded[..length]).is_none());
        }
        let mut bad = encoded;
        bad[4] = 1;
        assert!(Dataset::decode(&bad).is_none());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(Dataset::decode(&trailing).is_none());
        assert!(Writer {
            retired_through: 2,
            admitted_through: 1
        }
        .encode()
        .is_none());
        assert!(Writer {
            retired_through: 0,
            admitted_through: 0
        }
        .encode()
        .is_none());
        assert_eq!(&writer_key([7; 16])[1..], &[7; 16]);
    }

    #[test]
    fn only_import_records_are_excepted_from_the_emptiness_proof() {
        assert!(!counts_toward_empty(IMPORT_NAMESPACE));
        assert_eq!(&IMPORT_NAMESPACE.0, b"busbar.import.r0");
        for namespace in [NAMESPACE, GENERATION_NAMESPACE, NamespaceId([0; 16])] {
            assert!(counts_toward_empty(namespace), "{namespace:?}");
        }
        let mut near = IMPORT_NAMESPACE;
        near.0[15] ^= 1;
        assert!(counts_toward_empty(near));
    }
}
