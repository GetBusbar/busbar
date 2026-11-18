// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_ledger::cost::{EntryId, RawRateEra};
use serde::{Deserialize, Serialize};

/// The original parent's monetary fee authority; never reconstructed from a delivered attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeBasis {
    pub lane: Option<String>,
    #[serde(with = "era")]
    pub era: RawRateEra,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeResult {
    Charged,
    Refunded,
}

/// Written internally tagged by `state`. Read through [`CapturedFeeWire`], never through serde's
/// internally tagged reader: that one buffers the object and replays every number through
/// `deserialize_any`, where the exact-number JSON facade hands it as a token map, so the basis
/// era's `effective_from` would be refused as "a map, expected u64".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[serde(try_from = "CapturedFeeWire")]
pub enum CapturedFee {
    NotOwner { basis: FeeBasis },
    PendingOwner { basis: FeeBasis },
    ResolvedOwner { basis: FeeBasis, result: FeeResult },
    RecoveredUnknown { basis: FeeBasis },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FeeState {
    NotOwner,
    PendingOwner,
    ResolvedOwner,
    RecoveredUnknown,
}

/// The same object [`CapturedFee`] writes, read field by field: `result` belongs to
/// `resolved_owner` alone (required there, refused elsewhere, never `null`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedFeeWire {
    state: FeeState,
    basis: FeeBasis,
    #[serde(default, deserialize_with = "present_result")]
    result: Option<FeeResult>,
}

fn present_result<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<FeeResult>, D::Error> {
    FeeResult::deserialize(decoder).map(Some)
}

impl TryFrom<CapturedFeeWire> for CapturedFee {
    type Error = &'static str;

    fn try_from(wire: CapturedFeeWire) -> Result<Self, Self::Error> {
        let CapturedFeeWire {
            state,
            basis,
            result,
        } = wire;
        match (state, result) {
            (FeeState::ResolvedOwner, Some(result)) => Ok(Self::ResolvedOwner { basis, result }),
            (FeeState::ResolvedOwner, None) => Err("a resolved_owner fee requires its result"),
            (_, Some(_)) => Err("only a resolved_owner fee carries a result"),
            (FeeState::NotOwner, None) => Ok(Self::NotOwner { basis }),
            (FeeState::PendingOwner, None) => Ok(Self::PendingOwner { basis }),
            (FeeState::RecoveredUnknown, None) => Ok(Self::RecoveredUnknown { basis }),
        }
    }
}

/// The money owner's nonparticipating completion observer: the one cell the fee account publishes its
/// final result into, after its refund mutations (arch lints section 3.1: one concrete type). Holding it
/// cannot refund, admit, increment a child count or recreate a FeeParticipation.
#[derive(Debug, Default)]
pub struct SelectedFeeCompletion(std::sync::Mutex<Option<FeeResult>>);

impl SelectedFeeCompletion {
    /// The completed result, or None while the fee is still pending.
    pub fn observe(&self) -> Option<FeeResult> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish the final result (the fee account, once its refund mutations are done).
    pub(crate) fn complete(&self, result: FeeResult) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
    }
}

impl CapturedFee {
    pub fn basis(&self) -> &FeeBasis {
        match self {
            Self::NotOwner { basis }
            | Self::PendingOwner { basis }
            | Self::ResolvedOwner { basis, .. }
            | Self::RecoveredUnknown { basis } => basis,
        }
    }
    pub fn pending(&self) -> bool {
        matches!(self, Self::PendingOwner { .. })
    }
    pub(super) fn recover(&mut self) {
        if let Self::PendingOwner { basis } = self {
            *self = Self::RecoveredUnknown {
                basis: basis.clone(),
            };
        }
    }
    pub(super) fn follows(&self, old: &Self) -> bool {
        self == old
            || (matches!(old, Self::PendingOwner { .. })
                && matches!(
                    self,
                    Self::ResolvedOwner { .. } | Self::RecoveredUnknown { .. }
                )
                && self.basis() == old.basis())
    }
}

mod era {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        effective_from: u64,
        entry_id: Option<[u8; 12]>,
    }
    pub fn serialize<S: serde::Serializer>(
        era: &RawRateEra,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Wire {
            effective_from: era.effective_from,
            entry_id: era.entry_id.map(|id| id.0),
        }
        .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        decoder: D,
    ) -> Result<RawRateEra, D::Error> {
        let wire = Wire::deserialize(decoder)?;
        Ok(RawRateEra {
            effective_from: wire.effective_from,
            entry_id: wire.entry_id.map(EntryId),
        })
    }
}
