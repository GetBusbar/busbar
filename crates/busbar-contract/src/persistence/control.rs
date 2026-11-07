// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Generic execution-fence records, shared by the host and Store adapters.
//!
//! These records carry no domain policy. The adapter reads them at its atomic
//! serialization point, after receipt lookup. Core prepares changes through
//! ordinary conditional commits. A successful prior receipt precedes all fences.
//! Adapters must reject deletion, range deletion, malformed replacements and
//! backwards transitions in this namespace; an absent control record is never an
//! implicit grant. Dataset initialization requires a separately proven empty
//! logical dataset (records and receipts), not merely an absent key in an
//! existing dataset. Physical backend identity metadata grants no execution authority.

use super::{
    Candidate, DatasetId, ExpectedValue, Failure, Mutation, NamespaceId, CANDIDATE_VERSION,
};

/// Reserved metadata namespace, inaccessible to plugin host-record callers.
pub const NAMESPACE: NamespaceId = NamespaceId(*b"busbar.fence.v1\0");
/// Singleton dataset fence key within [`NAMESPACE`].
pub const DATASET_KEY: &[u8] = b"d";

/// Adapter-maintained namespace generation records. The key is the namespace's
/// exact sixteen bytes and a present value is its nonzero little-endian u64.
/// A missing record means generation zero. Ordinary candidates may predicate on
/// these records but must never mutate them directly. Each committed candidate
/// advances every mutated namespace once, atomically with its effects and receipt.
pub const GENERATION_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.scan.v1\0\0");

/// Known control keys; an unrecognized key is not an extensible grant format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Dataset-wide writer generation.
    Dataset,
    /// One registered writer's execution epochs.
    Writer([u8; 16]),
}

impl Key {
    /// Parse exactly one known control key, rejecting zero writer identities.
    pub fn decode(key: &[u8]) -> Option<Self> {
        if key == DATASET_KEY {
            return Some(Self::Dataset);
        }
        if key.len() != 17 || key[0] != b'w' {
            return None;
        }
        let writer: [u8; 16] = key[1..].try_into().ok()?;
        (writer != [0; 16]).then_some(Self::Writer(writer))
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
    }
}

/// Recognize initial authority together with opaque initial records. This validates
/// the candidate shape only: every address has one Absent predicate and one Put.
/// Exactly the dataset root and initial writer occupy the control namespace;
/// additional records cannot use either reserved adapter namespace.
///
/// The adapter must additionally prove, under the same native atomic guard, that
/// the canonical dataset has no records, receipts or previous authority. Legacy
/// or partially initialized data is never fresh. Receipt lookup still comes first.
#[must_use]
pub fn initialization<O>(candidate: &Candidate<O>, dataset: DatasetId) -> bool {
    if candidate.codec != CANDIDATE_VERSION
        || candidate.id.dataset != dataset
        || candidate.id.writer_epoch != 1
        || candidate.id.execution_epoch != 1
        || candidate.predicates.len() < 2
        || candidate.predicates.len() != candidate.mutations.len()
        || !candidate.result.0.is_empty()
        || candidate.time.is_some()
        || candidate.validate().is_err()
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
    addresses.sort_unstable();
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
        if self.id.0 == [0; 16] || self.writer_epoch == 0 {
            return None;
        }
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(b"BSD1");
        bytes[8..24].copy_from_slice(&self.id.0);
        bytes[24..].copy_from_slice(&self.writer_epoch.to_le_bytes());
        Some(bytes)
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
/// receipt collection. Epochs above the admitted ceiling have not been granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Writer {
    /// Irreversible lower fence; receipts may outlive it but it never decreases.
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

    /// Fixed versioned representation, independent of backend physical format.
    pub fn encode(self) -> Option<[u8; 24]> {
        if self.admitted_through == 0 || self.retired_through > self.admitted_through {
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
mod tests {
    use super::*;

    fn initial() -> Candidate {
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
        let mut candidate = initial();
        let dataset = candidate.id.dataset;
        assert!(initialization(&candidate, dataset));
        candidate.id.execution_epoch = 2;
        assert!(!initialization(&candidate, dataset));
        candidate.id.execution_epoch = 1;
        candidate.predicates[0].expected = ExpectedValue::Exact(Secret::new(Vec::new()));
        assert!(!initialization(&candidate, dataset));
        candidate.predicates[0].expected = ExpectedValue::Absent;
        candidate.mutations.push(Mutation::Delete(Address {
            namespace: [8; 16],
            key: Vec::new(),
        }));
        assert!(!initialization(&candidate, dataset));
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
        assert!(initialization(&candidate, candidate.id.dataset));
        assert!(
            initialization(&initial(), candidate.id.dataset),
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
            assert!(!initialization(&candidate, candidate.id.dataset));
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
}
