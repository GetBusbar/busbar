// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Byte-identical slot-row plumbing every store shares (STORE-TRANSACTIONS decision
//! 185 addendum, §3). Typed codes and codecs only: no rule lives here.

use crate::persistence::{ClockObservation, Decision, Failure};
use crate::redacted::Secret;

/// The physical format of every store built for the slot-row commit rule (rehomed to
/// [`crate::persistence::PHYSICAL_VERSION`]; kept here only for the v4 stores until #274 deletes this wire).
pub use crate::persistence::PHYSICAL_VERSION;
/// The receipt-era physical format every store refuses at open.
pub const RECEIPT_ERA_VERSION: u32 = 1;
/// The one explanation every store gives for a receipt-era dataset.
pub const RECEIPT_ERA_REFUSAL: &str =
    "pre-release receipt-era dataset; recreate it or re-run the 1.5.5 migration";

/// A recorded evaluation, stored as the wire `COMMIT_*` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `COMMIT_APPLIED`.
    Applied = 1,
    /// `COMMIT_CONDITION_CONFLICT`.
    Conflict = 2,
    /// `COMMIT_TIME_GUARD_FAILED`.
    TimeGuard = 3,
}

impl Verdict {
    /// The stored byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stored byte; anything else is a corrupt row.
    ///
    /// # Errors
    /// `Corrupt` for an unknown code.
    pub fn from_u8(code: u8) -> Result<Self, Failure> {
        match code {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::TimeGuard),
            _ => Err(Failure::Corrupt),
        }
    }
}

/// One (writer, slot) row: the last evaluated sequence, its fingerprint, verdict and
/// serialization time. A missing row is `seq == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotRow {
    /// Last evaluated lease sequence.
    pub seq: u64,
    /// Candidate fingerprint of that evaluation.
    pub fp: [u8; 32],
    /// Its verdict.
    pub verdict: Verdict,
    /// Its serialization time, in Unix seconds.
    pub observed: u64,
}

const PACKED_MAGIC: &[u8; 4] = b"BVS1";
/// Length of [`SlotRow::encode_packed`].
pub const PACKED_LEN: usize = 4 + 8 + 32 + 1 + 8;

impl SlotRow {
    /// The recorded answer an equal-sequence replay returns, at its original time.
    #[must_use]
    pub fn replay<O>(&self, authority: [u8; 16]) -> (Decision<O>, ClockObservation) {
        let observed_at = ClockObservation {
            authority,
            unix_seconds: self.observed,
        };
        let decision = match self.verdict {
            Verdict::Applied => Decision::Applied(Secret::default()),
            Verdict::Conflict => Decision::ConditionConflict,
            Verdict::TimeGuard => Decision::TimeGuardFailed { observed_at },
        };
        (decision, observed_at)
    }

    /// Packed value for key-value stores: `'BVS1' ‖ seq LE8 ‖ fp32 ‖ verdict u8 ‖ observed LE8`.
    #[must_use]
    pub fn encode_packed(&self) -> [u8; PACKED_LEN] {
        let mut out = [0; PACKED_LEN];
        out[..4].copy_from_slice(PACKED_MAGIC);
        out[4..12].copy_from_slice(&self.seq.to_le_bytes());
        out[12..44].copy_from_slice(&self.fp);
        out[44] = self.verdict.to_u8();
        out[45..].copy_from_slice(&self.observed.to_le_bytes());
        out
    }

    /// Decode [`Self::encode_packed`].
    ///
    /// # Errors
    /// `Corrupt` for any other length, magic or verdict.
    pub fn decode_packed(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() != PACKED_LEN || &bytes[..4] != PACKED_MAGIC {
            return Err(Failure::Corrupt);
        }
        let word = |at: usize| {
            u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed packed width"))
        };
        Ok(Self {
            seq: word(4),
            fp: bytes[12..44].try_into().expect("fixed packed width"),
            verdict: Verdict::from_u8(bytes[44])?,
            observed: word(45),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_are_the_wire_codes_and_unknown_is_corrupt() {
        use crate::abi::store::v4 as wire;
        assert_eq!(u32::from(Verdict::Applied.to_u8()), wire::COMMIT_APPLIED);
        assert_eq!(
            u32::from(Verdict::Conflict.to_u8()),
            wire::COMMIT_CONDITION_CONFLICT
        );
        assert_eq!(
            u32::from(Verdict::TimeGuard.to_u8()),
            wire::COMMIT_TIME_GUARD_FAILED
        );
        for code in [1, 2, 3] {
            assert_eq!(Verdict::from_u8(code).unwrap().to_u8(), code);
        }
        for code in [0, 4, 5, 6, 255] {
            assert_eq!(Verdict::from_u8(code), Err(Failure::Corrupt));
        }
    }

    #[test]
    fn packed_rows_round_trip_and_refuse_corruption() {
        let row = SlotRow {
            seq: u64::MAX - 1,
            fp: [7; 32],
            verdict: Verdict::TimeGuard,
            observed: 1_700_000_000,
        };
        let bytes = row.encode_packed();
        assert_eq!(&bytes[..4], b"BVS1");
        assert_eq!(SlotRow::decode_packed(&bytes), Ok(row));
        assert_eq!(
            SlotRow::decode_packed(&bytes[..PACKED_LEN - 1]),
            Err(Failure::Corrupt)
        );
        let mut bad = bytes;
        bad[0] = b'X';
        assert_eq!(SlotRow::decode_packed(&bad), Err(Failure::Corrupt));
        bad = bytes;
        bad[44] = 9;
        assert_eq!(SlotRow::decode_packed(&bad), Err(Failure::Corrupt));
        let (decision, at) = row.replay::<crate::redacted::Kernel>([3; 16]);
        assert!(matches!(decision, Decision::TimeGuardFailed { observed_at } if observed_at == at));
        assert_eq!(at.unix_seconds, 1_700_000_000);
    }
}
