// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Stable operation fingerprints and replay comparison shared by core and plugin adapters.
//! Historical domain tags are retained verbatim to preserve existing receipt bytes.

use sha2::{Digest as _, Sha256};

use crate::records::{
    MeteringDelta, ModelTokensDelta, PlaneDisposition, PlaneRecordRef, UsageDelta,
};

/// What a store records per applied `op_id`: SHA-256 of the op's value fields (module doc).
pub type Body = [u8; 32];

/// The tag the body's encoding starts with; the version of the encoding.
const TAG: &str = "busbar.store.op/1";

/// An `op_id`-carrying write's value fields, as its slot was handed them.
#[derive(Debug, Clone, Copy)]
enum Values<'a> {
    Usage(&'a [(&'a str, u64, UsageDelta)]),
    Metering(&'a [MeteringDelta]),
    Append(PlaneRecordRef<'a>),
    UsageCorrection(&'a super::correction::Request),
}

/// Whether an `op_id` is new, a replay of the op that recorded it, or a conflict with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// No body is recorded under the `op_id`: apply the op and record its body.
    New,
    /// The recorded body is this op's: apply nothing, answer done.
    Replay,
    /// The recorded body is a different op's: apply nothing and report an operation-id conflict.
    Conflict,
}

/// One operation's owned digest. Only the current raw or hexadecimal SHA-256 receipt
/// formats can prove a replay; malformed or development-format receipts conflict.
#[derive(Debug, Clone, Copy)]
pub struct Dedupe {
    pub(crate) body: Body,
}

impl Dedupe {
    /// `add_usage_batch`'s cells `(bucket, window, delta)`.
    #[must_use]
    pub fn usage(cells: &[(&str, u64, UsageDelta)]) -> Self {
        Self::of(Values::Usage(cells))
    }

    /// `add_metering_batch`'s deltas.
    #[must_use]
    pub fn metering(deltas: &[MeteringDelta]) -> Self {
        Self::of(Values::Metering(deltas))
    }

    /// `append_plane_record`'s record.
    #[must_use]
    pub fn append(record: PlaneRecordRef<'_>) -> Self {
        Self::of(Values::Append(record))
    }

    /// Complete raw-usage correction, including every precondition and replacement.
    #[must_use]
    pub fn usage_correction(request: &super::correction::Request) -> Self {
        Self::of(Values::UsageCorrection(request))
    }

    fn of(values: Values<'_>) -> Self {
        let mut f = Feed(Sha256::new());
        let quantities = matches!(values, Values::Usage(_) | Values::Metering(_));
        // Quantity receipts use a distinct domain and signed 16-byte mantissas.
        // A narrow-format receipt cannot prove this operation and must conflict.
        f.text(if quantities { "busbar.store.op/3" } else { TAG });
        match values {
            Values::UsageCorrection(request) => {
                f.text(super::correction::INTENT);
                f.bytes(&request.fingerprint());
            }
            Values::Usage(cells) => {
                f.text("add_usage_batch");
                f.count(cells.len());
                for (bucket, window, delta) in cells {
                    f.text(bucket);
                    f.u64(*window);
                    f.usage(delta);
                }
            }
            Values::Metering(deltas) => {
                f.text("add_metering_batch");
                f.count(deltas.len());
                for d in deltas {
                    f.metering(d);
                }
            }
            Values::Append(record) => {
                f.text("append_plane_record");
                f.record(record);
            }
        }
        Self {
            body: f.0.finalize().into(),
        }
    }

    /// The body a NEW op records: its 32 bytes.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// The body a NEW op records, for a text column: 64 lower-case hex digits.
    #[must_use]
    pub fn body_hex(&self) -> String {
        hex::encode(self.body)
    }

    /// What the body recorded under the op's `op_id` (`None`: nothing is) makes of this op. A body
    #[must_use]
    pub fn seen(&self, recorded: Option<&[u8]>) -> Seen {
        let Some(recorded) = recorded else {
            return Seen::New;
        };
        let same = match recorded.len() {
            32 => recorded == self.body,
            64 if recorded
                .iter()
                .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                hex::decode(recorded).is_ok_and(|r| r == self.body)
            }
            _ => false,
        };
        if same {
            Seen::Replay
        } else {
            Seen::Conflict
        }
    }
}

/// The body's encoding (module doc), fed straight into the digest.
pub(crate) struct Feed(pub(crate) Sha256);

impl Feed {
    pub(crate) fn u64(&mut self, v: u64) {
        self.0.update(v.to_le_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.0.update(v.to_le_bytes());
    }

    fn i128(&mut self, v: i128) {
        self.0.update(v.to_le_bytes());
    }

    pub(crate) fn count(&mut self, n: usize) {
        self.u64(n as u64);
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.count(b.len());
        self.0.update(b);
    }

    pub(crate) fn text(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    fn usage(&mut self, d: &UsageDelta) {
        let UsageDelta {
            requests,
            billable_requests,
            models,
        } = d;
        self.i64(*requests);
        self.i64(*billable_requests);
        self.count(models.len());
        for ModelTokensDelta {
            model,
            usage_units,
            scale,
        } in models
        {
            self.u64(u64::from(*scale));
            self.text(model);
            self.count(usage_units.len());
            for (unit, n) in usage_units {
                self.text(unit);
                self.i128(*n);
            }
        }
    }

    fn metering(&mut self, d: &MeteringDelta) {
        let MeteringDelta {
            scale,
            key_id,
            bucket,
            model,
            provider,
            tokens_input,
            tokens_output,
            tokens_cache_read,
            tokens_cache_write,
            requests,
            billable_requests,
            key_group_at_use,
            pricing_version,
            priced_from_ms,
            usage_units,
        } = d;
        self.u64(u64::from(*scale));
        self.text(key_id);
        self.u64(*bucket);
        self.text(model);
        self.text(provider);
        for n in [
            tokens_input,
            tokens_output,
            tokens_cache_read,
            tokens_cache_write,
        ] {
            self.i128(*n);
        }
        self.u64(*requests);
        self.u64(*billable_requests);
        self.text(key_group_at_use);
        self.text(pricing_version);
        self.u64(*priced_from_ms);
        self.count(usage_units.len());
        for (unit, n) in usage_units {
            self.text(unit);
            self.i128(*n);
        }
    }

    fn record(&mut self, r: PlaneRecordRef<'_>) {
        let PlaneRecordRef {
            kind,
            id,
            parent,
            seq,
            ts,
            disposition,
            body,
        } = r;
        self.text(kind);
        self.text(id);
        match parent {
            None => self.0.update([0]),
            Some(p) => {
                self.0.update([1]);
                self.text(p);
            }
        }
        self.u64(seq);
        self.u64(ts);
        self.0.update([match disposition {
            PlaneDisposition::Active => 0,
            PlaneDisposition::Terminal => 1,
        }]);
        self.bytes(body);
    }
}
