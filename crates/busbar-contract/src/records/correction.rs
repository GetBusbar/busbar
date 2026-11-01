// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact atomic raw-usage correction. All comparisons observe one pre-state; replacements and
//! the applied receipt commit together under the same authority as ordinary ledger writers.
//! Receipt lookup precedes predicates. A condition conflict writes neither rows nor receipt.

use super::{MeteringRow, UsageLedger};
use crate::abi::store::OpId;

/// Correction request and result version.
pub const VERSION: u32 = 1;
/// Statement capability; its value is `b"1"`.
pub const CAPABILITY: &str = "busbar.store.usage-correction/1";
/// ADD_USAGE_BATCH input extension.
pub const INTENT: &str = "busbar.store.usage-correction";
/// Correlated leased READY result extension.
pub const RESULT: &str = "busbar.store.usage-correction.result";
/// Raw rows accumulating positive corrections.
pub const ADJUST_UP_BUCKET: &str = "adjust:usage+";
/// Raw rows accumulating negative correction magnitudes.
pub const ADJUST_DOWN_BUCKET: &str = "adjust:usage-";
/// Separator between key, lane and historical era in adjustment model identities.
pub const SLOT_SEP: char = '\u{1e}';

/// One raw usage row's address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct UsageAddress {
    /// Opaque bucket identity.
    pub bucket_id: String,
    /// The window's opening Unix second.
    pub window_start: u64,
}

/// Exact compare-and-replace of a whole raw usage row. Absence compares as an empty ledger.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageChange {
    /// Row being compared and replaced.
    pub address: UsageAddress,
    /// Exact pre-state.
    pub expected: UsageLedger,
    /// Exact post-state, without signed narrowing or saturation.
    pub replacement: UsageLedger,
}

/// One immutable candidate. Every affected plain, dated and adjustment row belongs in `usage`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u32,
    /// Exact identity retained with this body after unknown outcomes.
    #[serde(with = "op_id_wire")]
    pub op_id: OpId,
    /// Key that must remain live at acceptance.
    pub key_id: String,
    /// Metering selection's UTC-day opening Unix second.
    pub day_start: u64,
    /// Complete key/day selection, preserving C4 and historical pricing fields.
    pub metering: Vec<MeteringRow>,
    /// Distinct addresses in ascending order; canonical model identities within each row.
    pub usage: Vec<UsageChange>,
}

/// A definitive decision, separate from an operation-id conflict or unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Every replacement and receipt committed, or that exact receipt was replayed.
    Applied,
    /// The live key, metering selection or usage pre-state changed; nothing was written.
    ConditionConflict,
}

impl Request {
    /// Check immutable selectors and exact canonical rows before backend effects.
    ///
    /// # Errors
    /// Unknown version, missing key/rows, duplicate or unordered addresses/models/identities,
    /// or a metering row outside the selected key.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("unsupported usage correction version");
        }
        if self.key_id.is_empty() || self.usage.is_empty() {
            return Err("usage correction requires a key and usage rows");
        }
        let mut previous = None;
        for row in &self.usage {
            if previous.is_some_and(|address| address >= &row.address) {
                return Err("usage correction addresses must be distinct and ordered");
            }
            previous = Some(&row.address);
            validate_ledger(&row.expected)?;
            validate_ledger(&row.replacement)?;
        }
        if self.metering.iter().any(|row| row.key_id != self.key_id) {
            return Err("usage correction metering key mismatch");
        }
        if self
            .metering
            .windows(2)
            .any(|pair| metering_identity(&pair[0]) >= metering_identity(&pair[1]))
        {
            return Err("usage correction metering identities must be distinct and ordered");
        }
        Ok(())
    }

    /// Encode the complete immutable request within the existing ABI byte bound.
    ///
    /// # Errors
    /// Invalid request or encoding exceeding the existing ABI bound.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "invalid usage correction encoding")?;
        if crate::abi::mechanism::extensions::entry_len(INTENT, &bytes) as u64
            > crate::abi::mechanism::check::HARD_MAX_BYTES
        {
            return Err("usage correction exceeds ABI byte bound");
        }
        Ok(bytes)
    }

    /// Decode one complete bounded request; integer counters remain exact `u64` values.
    ///
    /// # Errors
    /// Invalid wire bytes, request semantics or byte bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() as u64 > crate::abi::mechanism::check::HARD_MAX_BYTES {
            return Err("usage correction exceeds ABI byte bound");
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| "invalid usage correction encoding")?;
        request.validate()?;
        Ok(request)
    }

    /// Fingerprint binding the complete canonical request, including operation identity.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::Digest as _;
        let bytes = serde_json::to_vec(self).expect("usage correction contains only JSON values");
        sha2::Sha256::digest(bytes).into()
    }
}

/// Canonicalize one complete raw ledger, rejecting duplicate model identities.
///
/// # Errors
/// Duplicate model identities, whose fold could otherwise lose exact counts.
pub fn canonical_ledger(row: &mut UsageLedger) -> Result<(), &'static str> {
    row.models.sort_by(|a, b| a.model.cmp(&b.model));
    if row
        .models
        .windows(2)
        .any(|pair| pair[0].model == pair[1].model)
    {
        return Err("duplicate usage correction model identity");
    }
    for model in &mut row.models {
        model.usage_units.retain(|_, count| *count != 0);
    }
    row.models.retain(|model| !model.usage_units.is_empty());
    validate_ledger(row)
}

fn validate_ledger(row: &UsageLedger) -> Result<(), &'static str> {
    if row.models.iter().any(|model| {
        model.usage_units.is_empty() || model.usage_units.values().any(|count| *count == 0)
    }) {
        return Err("usage correction models must contain nonzero counters");
    }
    if row
        .models
        .windows(2)
        .any(|pair| pair[0].model >= pair[1].model)
    {
        return Err("usage correction models must be distinct and ordered");
    }
    Ok(())
}

fn metering_identity(row: &MeteringRow) -> (&str, &str, &str, &str, &str, u64) {
    (
        &row.key_id,
        &row.model,
        &row.provider,
        &row.key_group_at_use,
        &row.pricing_version,
        row.priced_from_ms,
    )
}

/// Canonicalize a complete metering selection by every identity field, retaining all counts.
pub fn canonical_metering(rows: &mut [MeteringRow]) {
    rows.sort_by(|a, b| metering_identity(a).cmp(&metering_identity(b)));
}

/// Whether legacy unconditional writes must refuse this reserved adjustment bucket.
#[must_use]
pub fn reserved_bucket(bucket: &str) -> bool {
    matches!(bucket, ADJUST_UP_BUCKET | ADJUST_DOWN_BUCKET)
}

mod op_id_wire {
    use super::OpId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(id: &OpId, serializer: S) -> Result<S::Ok, S::Error> {
        id.0.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OpId, D::Error> {
        <[u8; 16]>::deserialize(deserializer).map(OpId)
    }
}
