// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHECKPOINT SEALER: the node's totals sealed into a checkpoint on a fixed cadence, signed with
//! the audit chain's own key, and put on the journal (OWNER Q71(3); spec #82; checkpoint cadence
//! per ARCHITECTURE.md §4.7).
//!
//! ## One keyset, two seams
//!
//! The ledger holds no key and has no cryptographic opinion: it asks a [`CheckpointSecret`] to sign
//! and a [`CheckpointVerifier`] to check. Q71(3) binds both to the ONE keyset the audit chain signs
//! its records with (#82), so this file is where the two meet: [`ChainSecret`] signs a checkpoint
//! body through [`AuditChain::sign_checkpoint_body`] and [`KeySetVerifier`] checks one through
//! [`AuditKeySet::verify_checkpoint_body`]. A chain given no key signs nothing — [`ChainSecret::of`]
//! answers `None`, the seal goes down UNSIGNED, and the checkpoints read says so in its own words.
//! A seal is never refused for want of a key: an unsigned checkpoint still fixes the figures and
//! their position on the chain, which is what the identity is measured from.
//!
//! ## The cadence is two fixed constants, whichever comes first
//!
//! [`CHECKPOINT_ENTRIES`] records or [`CHECKPOINT_INTERVAL_SECS`] seconds since the last seal —
//! ARCHITECTURE.md §4.7's defaults, fixed in 1.6.0 (architect ruling 2026-09-26: no config key).
//! The interval half seals only ON CHANGE: a node that journaled nothing since its last seal has no
//! new figure to fix, and sealing it again would be a record saying nothing happened. The entry
//! half is checked after every serving append, so a busy node seals every [`CHECKPOINT_ENTRIES`]
//! records rather than once per tick; the interval half is checked by the root's tick as well, so
//! an idle node's last postings are sealed within one interval.
//!
//! ## Armed, never implied
//!
//! A book seals on cadence only after [`Durability::arm_checkpoints`]. The boot arms the process's
//! one book once it is composed; a book a test or a tool builds does not seal behind its back.

use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditVerifyingKey};
use busbar_kernel_ledger::checkpoint::{
    ChainHead, CheckpointSecret, CheckpointVerifier, SignError, Signature,
};
use busbar_kernel_ledger::migration::OPENING_CHECKPOINT_SEQ;

use super::*;

/// How many journal records a checkpoint may trail by (ARCHITECTURE.md §4.7 `checkpoint_entries`).
pub const CHECKPOINT_ENTRIES: u64 = 10_000;

/// How many seconds a changed book may go unsealed (ARCHITECTURE.md §4.7 `checkpoint_interval`).
pub const CHECKPOINT_INTERVAL_SECS: u64 = 60;

/// How often the root's tick asks whether the interval has run out (ARCHITECTURE.md §4.7
/// `tick_interval`), so an idle node's last change is sealed at most this long after the interval.
pub const CHECKPOINT_TICK_SECS: u64 = 1;

/// Signs a checkpoint body with the audit chain's own key (Q71(3): one keyset).
pub struct ChainSecret<'a> {
    chain: &'a AuditChain,
}

impl std::fmt::Debug for ChainSecret<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainSecret")
            .field("key_id", &self.chain.signing_key_id())
            .finish()
    }
}

impl<'a> ChainSecret<'a> {
    /// The chain's signer, if the chain was given a key. `None` is a node that signs nothing, and a
    /// seal handed `None` goes down unsigned rather than failing.
    #[must_use]
    pub fn of(chain: &'a AuditChain) -> Option<Self> {
        chain.signing_key_id().map(|_| ChainSecret { chain })
    }
}

impl CheckpointSecret for ChainSecret<'_> {
    fn sign(&self, body: &[u8]) -> Result<Signature, SignError> {
        self.chain
            .sign_checkpoint_body(body)
            .map(Signature::new)
            .ok_or_else(|| {
                SignError::KeyUnavailable(
                    "this node's audit chain holds no signing key".to_string(),
                )
            })
    }
}

/// Checks a checkpoint signature against the audit keyset (Q71(3): one keyset).
#[derive(Debug, Clone, Default)]
pub struct KeySetVerifier {
    keys: AuditKeySet,
}

impl KeySetVerifier {
    /// Verify against these keys.
    #[must_use]
    pub fn new(keys: AuditKeySet) -> Self {
        KeySetVerifier { keys }
    }
}

impl CheckpointVerifier for KeySetVerifier {
    fn verify(&self, body: &[u8], signature: &Signature) -> Result<(), String> {
        self.keys
            .verify_checkpoint_body(body, signature.bytes())
            .map_err(|e| e.to_string())
    }
}

/// The public half of the key this chain signs with, as a set — empty when the chain was given
/// none, because a set must never carry a key the node does not sign with.
#[must_use]
pub fn keyset_of(chain: &AuditChain) -> AuditKeySet {
    let mut keys = AuditKeySet::new();
    if let Some(key) = chain
        .public_key_hex()
        .and_then(|hex| AuditVerifyingKey::from_hex(&hex).ok())
    {
        keys.insert(key);
    }
    keys
}

/// Where the book stands against the cadence: what the last seal covered, and when it was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// The journal's next sequence number just after the last seal went on it.
    sealed_through: u64,
    /// When the last seal was made (or the cadence armed), wall seconds.
    sealed_at: u64,
    /// The sequence number the next checkpoint takes.
    next_checkpoint_seq: u64,
}

impl Cadence {
    /// A cadence starting now, from the journal's position, numbering from `next_checkpoint_seq`.
    #[must_use]
    pub fn starting(next_seq: u64, now: u64, next_checkpoint_seq: u64) -> Self {
        Cadence {
            sealed_through: next_seq,
            sealed_at: now,
            next_checkpoint_seq,
        }
    }

    /// Whether a checkpoint is due: [`CHECKPOINT_ENTRIES`] records since the last seal, or
    /// [`CHECKPOINT_INTERVAL_SECS`] seconds and at least one record — whichever first.
    #[must_use]
    pub fn due(&self, next_seq: u64, now: u64) -> bool {
        let entries = next_seq.saturating_sub(self.sealed_through);
        entries >= CHECKPOINT_ENTRIES
            || (entries > 0 && now.saturating_sub(self.sealed_at) >= CHECKPOINT_INTERVAL_SECS)
    }

    /// The sequence number the next checkpoint takes.
    #[must_use]
    pub fn next_checkpoint_seq(&self) -> u64 {
        self.next_checkpoint_seq
    }
}

/// Why a checkpoint did not make it onto the journal.
#[derive(Debug)]
pub enum CheckpointFailed {
    /// The signer refused.
    Sign(SignError),
    /// The journal could not make it durable.
    Lost(DurabilityLost),
}

impl std::fmt::Display for CheckpointFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointFailed::Sign(e) => write!(f, "the checkpoint could not be signed: {e}"),
            CheckpointFailed::Lost(lost) => write!(
                f,
                "the journal could not make the checkpoint durable at step {}",
                lost.step().as_str()
            ),
        }
    }
}

/// The sequence number the first cadence checkpoint takes on a chain: one past the highest the
/// chain already carries, else one past the migration's opening.
pub(super) fn next_checkpoint_seq_on(records: &[busbar_kernel_wal::JournalRecord]) -> u64 {
    records
        .iter()
        .filter(|r| r.class == RecordClass::Checkpoint)
        .filter_map(|r| BodyReader::new(&r.body).num())
        .max()
        .unwrap_or(OPENING_CHECKPOINT_SEQ)
        .saturating_add(1)
}

impl Durability {
    /// ARM THE CADENCE: from now on this book seals a checkpoint whenever one is due.
    ///
    /// `now` is wall seconds. The checkpoint numbering continues from the highest sequence number
    /// the chain already carries, so a restart never re-uses one.
    pub fn arm_checkpoints(&mut self, now: u64) {
        let next_checkpoint_seq = match self.journal.replay() {
            Ok(Ok(records)) => next_checkpoint_seq_on(&records),
            _ => OPENING_CHECKPOINT_SEQ.saturating_add(1),
        };
        self.cadence = Some(Cadence::starting(
            self.journal.next_seq(),
            now,
            next_checkpoint_seq,
        ));
    }

    /// The cadence, if armed.
    #[must_use]
    pub fn cadence(&self) -> Option<Cadence> {
        self.cadence
    }

    /// SEAL A CHECKPOINT NOW: this node's totals, as of the pinned rate-card history, signed with
    /// the chain's key when it has one, then journaled.
    ///
    /// # Errors
    ///
    /// [`CheckpointFailed`]: the signer refused, or the journal could not make the checkpoint
    /// durable. Either way the sequence number is spent, so no two checkpoints ever share one.
    pub fn seal_checkpoint(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        now: u64,
    ) -> Result<Checkpoint, CheckpointFailed> {
        let mut cadence = self.cadence.unwrap_or_else(|| {
            Cadence::starting(
                self.journal.next_seq(),
                now,
                OPENING_CHECKPOINT_SEQ.saturating_add(1),
            )
        });
        let checkpoint_seq = cadence.next_checkpoint_seq;
        cadence.next_checkpoint_seq = checkpoint_seq.saturating_add(1);
        // The journal numbers from one, so its last record is one below the next; a chain still at
        // genesis (an all-zero head) has no record and cross-links nothing.
        let high_water = self.journal.next_seq().saturating_sub(1);
        // This node's chain is the one head it holds.
        let heads = (self.journal.head() != [0u8; 32])
            .then(|| ChainHead {
                node: self.journal.node(),
                node_seq: high_water,
                hash: self.journal.head(),
            })
            .into_iter()
            .collect();
        let totals = self.ledger.book().snapshot();
        let secret = ChainSecret::of(&self.record);
        let secret = secret.as_ref().map(|s| s as &dyn CheckpointSecret);
        let pinned = (self.history)();
        let sealed = match pinned.as_ref().map(PinnedHistory::seq) {
            Some(history_seq) => Checkpoint::seal_as_of(
                checkpoint_seq,
                self.journal.node(),
                now,
                heads,
                totals,
                // No backup has been taken under this release; claiming one would let retention
                // discard a segment on the strength of a backup that never happened.
                0,
                high_water,
                history_seq,
                secret,
            ),
            None => Checkpoint::seal(
                checkpoint_seq,
                self.journal.node(),
                now,
                heads,
                totals,
                0,
                high_water,
                secret,
            ),
        };
        let outcome = sealed
            .map_err(CheckpointFailed::Sign)
            .and_then(|checkpoint| {
                self.journal_checkpoint(&checkpoint, token, at)
                    .map(|_| checkpoint)
                    .map_err(CheckpointFailed::Lost)
            });
        cadence.sealed_through = self.journal.next_seq();
        cadence.sealed_at = now;
        self.cadence = Some(cadence);
        outcome
    }

    /// Seal a checkpoint if the armed cadence says one is due at `now` (wall seconds). `None` when
    /// the cadence is not armed or nothing is due.
    pub fn seal_if_due(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        now: u64,
    ) -> Option<Result<Checkpoint, CheckpointFailed>> {
        let cadence = self.cadence?;
        cadence
            .due(self.journal.next_seq(), now)
            .then(|| self.seal_checkpoint(token, at, now))
    }

    /// THE CADENCE CHECK every serving append and the root's tick make: seal if due, on the
    /// process clock, and say so at ERROR if the seal did not make it — never a refusal of the
    /// append that triggered it.
    pub fn seal_on_cadence(&mut self) {
        if self.cadence.is_none() {
            return;
        }
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        let now = busbar_substrate_values::store::now();
        match self.seal_if_due(&token, StepName::Meter, now) {
            Some(Ok(checkpoint)) => tracing::debug!(
                checkpoint_seq = checkpoint.checkpoint_seq,
                signed = checkpoint.signature.is_some(),
                "the ledger sealed a checkpoint"
            ),
            Some(Err(failed)) => {
                tracing::error!(failed = %failed, "the ledger checkpoint was not sealed")
            }
            None => {}
        }
    }
}

#[cfg(test)]
#[path = "../tests/checkpoint_seal.rs"]
mod tests;
