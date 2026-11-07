// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral logical operation fingerprints and replay-result adapters.

/// Why an `op_id`-carrying write answered without applying anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRefused {
    /// The same `op_id` arrived with different value fields: REFUSED with
    /// [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT), nothing applied.
    Conflict,
    /// The write could not be applied (a fork at a used `seq`, a backend error): FAILED with this
    /// text, nothing applied, nothing recorded under the `op_id`. A host cannot tell a backend error
    /// from a commit whose answer was lost, so it replays the same `op_id` (S5); a fork it never
    /// replays.
    Failed(String),
    /// The write was decided before commit and refused (a value its columns cannot hold, a
    /// constraint, a script error before any write): REFUSED with this text, PROVABLY nothing
    /// applied and nothing recorded under the `op_id` (S3, S5). A host may split or re-send the
    /// write under a new `op_id`.
    Refused(String),
}

/// An `op_id`-carrying write's answer.
pub type OpResult<T> = Result<T, OpRefused>;

use crate::records::dedupe::Feed;
pub use crate::records::dedupe::{Body, Dedupe, Seen};
use sha2::{Digest as _, Sha256};

impl Dedupe {
    /// Atomic v3 conditional-record request; version, predicates and mutations form its body.
    #[must_use]
    pub fn record_transaction(request: &super::conditional::Request) -> Self {
        let mut f = Feed(Sha256::new());
        f.text("busbar.store.op/1");

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
        Self {
            body: f.0.finalize().into(),
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
            Seen::New => apply(log, self.body()),
            Seen::Replay => Ok(()),
            Seen::Conflict => Err(OpRefused::Conflict),
        }
    }
}

#[cfg(test)]
#[path = "../abi/sdk/tests/store_dedupe_tests.rs"]
mod tests;
