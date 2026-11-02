// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `op_id` DEDUPE, ONCE FOR EVERY STORE (`abi::store` S1-S5). A store keeps, per `op_id` it

use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use super::{OpRefused, OpResult};
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
    RecordTransaction(&'a super::conditional::Request),
    UsageCorrection(&'a super::correction::Request),
}

/// Whether an `op_id` is new, a replay of the op that recorded it, or a conflict with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// No body is recorded under the `op_id`: apply the op and record its body.
    New,
    /// The recorded body is this op's: apply nothing, answer done.
    Replay,
    /// The recorded body is a different op's: apply nothing, [`OpRefused::Conflict`].
    Conflict,
}

/// ONE `op_id`-CARRYING WRITE'S DEDUPE: its values and their [`Body`], made once when the slot is
/// entered.
#[derive(Debug, Clone, Copy)]
pub struct Dedupe<'a> {
    values: Values<'a>,
    body: Body,
}

impl<'a> Dedupe<'a> {
    /// `add_usage_batch`'s cells `(bucket, window, delta)`.
    #[must_use]
    pub fn usage(cells: &'a [(&'a str, u64, UsageDelta)]) -> Self {
        Self::of(Values::Usage(cells))
    }

    /// `add_metering_batch`'s deltas.
    #[must_use]
    pub fn metering(deltas: &'a [MeteringDelta]) -> Self {
        Self::of(Values::Metering(deltas))
    }

    /// `append_plane_record`'s record.
    #[must_use]
    pub fn append(record: PlaneRecordRef<'a>) -> Self {
        Self::of(Values::Append(record))
    }

    /// Atomic conditional-record request; version, predicates and all mutations form its body.
    #[must_use]
    pub fn record_transaction(request: &'a super::conditional::Request) -> Self {
        Self::of(Values::RecordTransaction(request))
    }

    /// Complete raw-usage correction, including every precondition and replacement.
    #[must_use]
    pub fn usage_correction(request: &'a super::correction::Request) -> Self {
        Self::of(Values::UsageCorrection(request))
    }

    fn of(values: Values<'a>) -> Self {
        let mut f = Feed(Sha256::new());
        f.text(TAG);
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
            Values::RecordTransaction(request) => {
                f.text("record_transaction");
                f.u64(u64::from(request.version));
                f.count(request.predicates.len());
                for predicate in &request.predicates {
                    f.text(&predicate.schema);
                    f.bytes(&predicate.key);
                    match &predicate.expected {
                        super::conditional::Expected::Absent => f.0.update([0]),
                        super::conditional::Expected::Bytes(bytes) => {
                            f.0.update([1]);
                            f.bytes(bytes);
                        }
                    }
                }
                f.count(request.mutations.len());
                for mutation in &request.mutations {
                    let (schema, key) = mutation.address();
                    match mutation {
                        super::conditional::Mutation::Put { value, .. } => {
                            f.0.update([0]);
                            f.text(schema);
                            f.bytes(key);
                            f.bytes(value);
                        }
                        super::conditional::Mutation::Delete { .. } => {
                            f.0.update([1]);
                            f.text(schema);
                            f.bytes(key);
                        }
                        super::conditional::Mutation::DeleteRange {
                            exact_key_length, ..
                        } => {
                            f.0.update([2]);
                            f.text(schema);
                            f.bytes(key);
                            f.u64(*exact_key_length);
                        }
                    }
                }
            }
        }
        Self {
            values,
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
            _ => self.older_form_is(recorded),
        };
        if same {
            Seen::Replay
        } else {
            Seen::Conflict
        }
    }

    /// The op's answer from what its async body found: `None` = it applied the op and recorded its

    pub fn answer<B: AsRef<[u8]>>(&self, ran: OpResult<Option<B>>) -> OpResult<()> {
        let found = ran?;
        match self.seen(found.as_ref().map(|b| b.as_ref())) {
            Seen::Conflict => Err(OpRefused::Conflict),
            Seen::New | Seen::Replay => Ok(()),
        }
    }

    /// RUN THE OP DEDUPED over the store's log `log`, in ONE atomic step the store holds (its lock,

    pub fn run<L, B: AsRef<[u8]>>(
        &self,
        log: &mut L,
        recorded: impl FnOnce(&mut L) -> OpResult<Option<B>>,
        apply: impl FnOnce(&mut L, &Body) -> OpResult<()>,
    ) -> OpResult<()> {
        let found = recorded(log)?;
        match self.seen(found.as_ref().map(|b| b.as_ref())) {
            Seen::New => apply(log, &self.body),
            Seen::Replay => Ok(()),
            Seen::Conflict => Err(OpRefused::Conflict),
        }
    }

    /// Whether `recorded` is this op's body in the form builds before this one recorded: the slot's

    fn older_form_is(&self, recorded: &[u8]) -> bool {
        let mut older = String::new();
        match self.values {
            Values::RecordTransaction(_) | Values::UsageCorrection(_) => return false,
            Values::Usage(cells) => {
                let _ = write!(older, "add_usage_batch:{cells:?}");
            }
            Values::Metering(deltas) => {
                let _ = write!(older, "add_metering_batch:{deltas:?}");
            }
            Values::Append(record) => {
                let _ = write!(older, "append_plane_record:{record:?}");
                if recorded == older.as_bytes() {
                    return true;
                }
                older.clear();
                let _ = write!(older, "append_plane_record:{:?}", record.to_record());
            }
        }
        recorded == older.as_bytes()
    }
}

/// The body's encoding (module doc), fed straight into the digest.
struct Feed(Sha256);

impl Feed {
    fn u64(&mut self, v: u64) {
        self.0.update(v.to_le_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.0.update(v.to_le_bytes());
    }

    fn count(&mut self, n: usize) {
        self.u64(n as u64);
    }

    fn bytes(&mut self, b: &[u8]) {
        self.count(b.len());
        self.0.update(b);
    }

    fn text(&mut self, s: &str) {
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
        for ModelTokensDelta { model, usage_units } in models {
            self.text(model);
            self.count(usage_units.len());
            for (unit, n) in usage_units {
                self.text(unit);
                self.i64(*n);
            }
        }
    }

    fn metering(&mut self, d: &MeteringDelta) {
        let MeteringDelta {
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
        self.text(key_id);
        self.u64(*bucket);
        self.text(model);
        self.text(provider);
        for n in [
            tokens_input,
            tokens_output,
            tokens_cache_read,
            tokens_cache_write,
            requests,
            billable_requests,
        ] {
            self.u64(*n);
        }
        self.text(key_group_at_use);
        self.text(pricing_version);
        self.u64(*priced_from_ms);
        self.count(usage_units.len());
        for (unit, n) in usage_units {
            self.text(unit);
            self.u64(*n);
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

#[cfg(test)]
#[path = "../tests/store_dedupe_tests.rs"]
mod tests;
