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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapturedFee {
    NotOwner { basis: FeeBasis },
    PendingOwner { basis: FeeBasis },
    ResolvedOwner { basis: FeeBasis, result: FeeResult },
    RecoveredUnknown { basis: FeeBasis },
}

/// Implemented by the money owner's nonparticipating Arc observer. It cannot refund, admit,
/// increment a child count or recreate a FeeParticipation.
pub trait SelectedFeeCompletion: Send + Sync {
    fn observe(&self) -> Option<FeeResult>;
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
