// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The checkpoint: the totals sealed, signed, and put somewhere the node cannot rewrite.
//!
//! ## What a checkpoint is for
//!
//! It is the point the identity is measured FROM. Without one, checking the books means walking
//! every posting since the deployment started, which is a thing nobody does twice. With one, the
//! check is a subtraction between two snapshots, and an auditor who trusts the signature on the
//! older snapshot only has to look at what happened since.
//!
//! ## Signing and anchoring are two different jobs, so they are two traits
//!
//! SIGNING says "this node wrote these figures". ANCHORING says "these figures were seen somewhere
//! this node cannot reach". A node that signs its own checkpoints and files them on its own disk has
//! proved nothing to anybody: it can rewrite the whole history consistently and every signature will
//! still verify. That is why the anchor is a trait with a deliberately awkward requirement attached
//! — the sink must lie outside every node's write authority — and why the crate states plainly that
//! the requirement is a trust assumption rather than something the code enforces. The default local
//! anchor is self-attestation and calling it anything else would be dishonest.
//!
//! ## Repeated anchor failures are themselves a fact
//!
//! An anchor that has been failing for a week is a deployment whose tamper-evidence stopped a week
//! ago, silently. [`AnchorState`] counts consecutive failures so that the count can be alarmed on
//! and journaled rather than living in a log line nobody greps for.

use std::collections::BTreeMap;

use crate::totals::{Totals, TotalsKey, WindowStart};

/// One node chain's head, as a checkpoint cross-links it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainHead {
    /// Which node.
    pub node: u64,
    /// That node's last sequence number.
    pub node_seq: u64,
    /// The hash of that entry.
    pub hash: [u8; 32],
}

/// A signature over a checkpoint body. Opaque: which scheme produced it is the secret plugin's
/// business, and a ledger that knew would be a ledger with a cryptographic opinion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wrap the bytes a signer produced.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Signature(bytes.into())
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a checkpoint could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The key this deployment signs with is not available.
    KeyUnavailable(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::KeyUnavailable(why) => write!(f, "the signing key is not available: {why}"),
        }
    }
}

impl std::error::Error for SignError {}

/// Signs checkpoint bodies. Implemented by whatever holds the deployment's keys.
pub trait CheckpointSecret {
    /// Sign these bytes.
    fn sign(&self, body: &[u8]) -> Result<Signature, SignError>;
}

/// Why a checkpoint could not be anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// The sink could not be reached or refused the checkpoint.
    Unavailable(String),
    /// The sink took it, but reading it back did not give the same thing.
    ReadBackDiffers,
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorError::Unavailable(why) => write!(f, "the anchor sink was not usable: {why}"),
            AnchorError::ReadBackDiffers => {
                f.write_str("the anchor sink read back something other than what was written")
            }
        }
    }
}

impl std::error::Error for AnchorError {}

/// Puts a checkpoint somewhere outside the node's own write authority, and reads the head back.
///
/// **The requirement this trait cannot enforce.** An anchor sink that the node can rewrite proves
/// nothing, and there is no way for an implementation to demonstrate to this crate that it is out
/// of reach. So the requirement is stated, the default is labelled self-attestation, and
/// [`AnchorState::self_attesting`] carries that label onward to whatever reports the node's health.
pub trait CheckpointAnchor {
    /// Put it there. An implementation should read back what it wrote and report a mismatch.
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<(), AnchorError>;

    /// The most recently anchored checkpoint's identity, if there is one.
    fn head(&self) -> Result<Option<AnchoredHead>, AnchorError>;

    /// Whether this sink is inside the node's own write authority. The default local file anchor
    /// answers `true`, and says so on the ledger endpoint rather than quietly.
    fn is_self_attesting(&self) -> bool;
}

/// What the anchor sink says the last anchored checkpoint was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredHead {
    /// Which checkpoint.
    pub checkpoint_seq: u64,
    /// The hash of its body.
    pub body_hash: [u8; 32],
}

/// How the anchoring is going.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorState {
    /// How many anchor attempts have failed in a row.
    pub consecutive_failures: u32,
    /// Whether the sink is inside the node's own write authority.
    pub self_attesting: bool,
    /// The last head the sink reported.
    pub head: Option<AnchoredHead>,
}

impl AnchorState {
    /// Whether the failure count has reached the alarm threshold.
    pub fn should_alarm(&self, threshold: u32) -> bool {
        self.consecutive_failures >= threshold
    }
}

/// One sealed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Which checkpoint in the deployment's sequence.
    pub checkpoint_seq: u64,
    /// Which node sealed it.
    pub node: u64,
    /// When, in whole seconds.
    pub wall: u64,
    /// Every node chain's head at the moment of sealing.
    pub heads: Vec<ChainHead>,
    /// The totals, per bucket, dimension, scope and window.
    pub totals: BTreeMap<(TotalsKey, WindowStart), Totals>,
    /// How far the backup has got. Retention may not discard past this.
    pub backup_watermark: u64,
    /// The store's sequence high-water at the moment of sealing.
    pub store_seq_high_water: u64,
    /// The digest of the sealed body.
    pub body_hash: [u8; 32],
    /// The signature over that body, if a signer was available.
    pub signature: Option<Signature>,
}

impl Checkpoint {
    /// Seal a set of totals into a checkpoint, digesting and signing the body.
    ///
    /// The heads are sorted before they are digested, because two nodes that collected the same
    /// heads in a different order must produce the same body — a signature that depended on
    /// iteration order would verify only on the machine that made it.
    #[allow(clippy::too_many_arguments)]
    // Eight arguments, and every one of them is a distinct fact the body digests. Bundling them
    // into a struct would only move the same eight names one line further away, and a caller that
    // could build the struct incrementally could seal a checkpoint with a field it forgot to set —
    // which is worse than a long signature.
    pub fn seal(
        checkpoint_seq: u64,
        node: u64,
        wall: u64,
        mut heads: Vec<ChainHead>,
        totals: BTreeMap<(TotalsKey, WindowStart), Totals>,
        backup_watermark: u64,
        store_seq_high_water: u64,
        secret: Option<&dyn CheckpointSecret>,
    ) -> Result<Self, SignError> {
        heads.sort();
        let body = encode_body(
            checkpoint_seq,
            node,
            wall,
            &heads,
            &totals,
            backup_watermark,
            store_seq_high_water,
        );
        let body_hash = crate::digest::sha256(&body);
        let signature = match secret {
            Some(secret) => Some(secret.sign(&body)?),
            None => None,
        };
        Ok(Checkpoint {
            checkpoint_seq,
            node,
            wall,
            heads,
            totals,
            backup_watermark,
            store_seq_high_water,
            body_hash,
            signature,
        })
    }

    /// The totals this checkpoint sealed for one balance, zeros if it sealed none.
    pub fn totals_for(&self, key: &TotalsKey, window: WindowStart) -> Totals {
        self.totals
            .get(&(key.clone(), window))
            .copied()
            .unwrap_or_default()
    }

    /// Recompute the body digest and compare it to the stored one. This is what catches a
    /// checkpoint whose figures were edited after it was sealed.
    pub fn body_hash_verifies(&self) -> bool {
        let body = encode_body(
            self.checkpoint_seq,
            self.node,
            self.wall,
            &self.heads,
            &self.totals,
            self.backup_watermark,
            self.store_seq_high_water,
        );
        crate::digest::sha256(&body) == self.body_hash
    }

    /// The exact bytes that were signed, so a verifier can hand them to the same secret plugin.
    pub fn signed_body(&self) -> Vec<u8> {
        encode_body(
            self.checkpoint_seq,
            self.node,
            self.wall,
            &self.heads,
            &self.totals,
            self.backup_watermark,
            self.store_seq_high_water,
        )
    }
}

/// Frame a checkpoint's body for digesting.
///
/// Length-prefixed throughout: a bucket name can contain any character, so a separator-joined body
/// would let a caller who controls one name forge the same byte stream under a different split.
/// Length prefixes make the boundary between fields unforgeable regardless of what any field holds.
fn encode_body(
    checkpoint_seq: u64,
    node: u64,
    wall: u64,
    heads: &[ChainHead],
    totals: &BTreeMap<(TotalsKey, WindowStart), Totals>,
    backup_watermark: u64,
    store_seq_high_water: u64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let num = |v: u64, body: &mut Vec<u8>| body.extend_from_slice(&v.to_be_bytes());
    num(checkpoint_seq, &mut body);
    num(node, &mut body);
    num(wall, &mut body);
    num(backup_watermark, &mut body);
    num(store_seq_high_water, &mut body);
    num(heads.len() as u64, &mut body);
    for head in heads {
        num(head.node, &mut body);
        num(head.node_seq, &mut body);
        body.extend_from_slice(&head.hash);
    }
    num(totals.len() as u64, &mut body);
    for ((key, window), figures) in totals {
        push_text(&mut body, key.bucket.as_str());
        push_text(&mut body, &key.dimension.to_string());
        push_text(&mut body, &key.scope.to_string());
        num(*window, &mut body);
        for figure in [
            figures.budget,
            figures.drawn,
            figures.released,
            figures.settled,
            figures.open_holds,
            figures.open_slice_remainders,
            figures.adjustments,
            figures.unreconciled,
            figures.overdraft_carried_in,
            figures.overdraft_carried_out,
            figures.cross_window_transfers,
            figures.disputed,
        ] {
            body.extend_from_slice(&figure.to_be_bytes());
        }
        num(figures.oldest_open_hold_age_secs, &mut body);
        num(figures.open_dispute_count, &mut body);
        num(figures.oldest_dispute_age_secs, &mut body);
    }
    body
}

fn push_text(body: &mut Vec<u8>, text: &str) {
    body.extend_from_slice(&(text.len() as u64).to_be_bytes());
    body.extend_from_slice(text.as_bytes());
}

/// A local-file anchor, and the honest label that goes with it.
///
/// It keeps the head in memory rather than naming a path, because this crate does not open files —
/// the point being made here is about TRUST, not about storage. Whatever the integrator binds
/// underneath, it answers `true` to [`CheckpointAnchor::is_self_attesting`] as long as the node can
/// write to it.
#[derive(Debug, Default)]
pub struct SelfAttestingAnchor {
    head: Option<AnchoredHead>,
}

impl SelfAttestingAnchor {
    /// A fresh one.
    pub fn new() -> Self {
        SelfAttestingAnchor::default()
    }
}

impl CheckpointAnchor for SelfAttestingAnchor {
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<(), AnchorError> {
        self.head = Some(AnchoredHead {
            checkpoint_seq: checkpoint.checkpoint_seq,
            body_hash: checkpoint.body_hash,
        });
        Ok(())
    }

    fn head(&self) -> Result<Option<AnchoredHead>, AnchorError> {
        Ok(self.head.clone())
    }

    fn is_self_attesting(&self) -> bool {
        true
    }
}
