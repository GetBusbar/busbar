// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESTART WALK (SEALING-FIX r20 §3.6.0): one definition, used by the own-node restart seal
//! (§3.6.1), the predecessor sealer (§3.6.2) and the covering-stamp rule.
//!
//! Given a node's records up to its tail T, oldest first, the walk finds the newest anchor that
//! verifies (a page stamp of this node, or a legacy line with a valid per-line signature), walks
//! the links from the anchor to T, and then asks whether the tail is a genuine crash leftover of
//! this host: anchored by a `live` or `after_restart` stamp, on this host, and no longer than any
//! crash leaves. Only then may a restart page be signed over it. Everything else is a break, which
//! is recorded and alerted, never sealed. The walk reads no clock and signs nothing; its caller
//! signs on the Bootstrap signer thread.

use crate::link::Fingerprint;
use crate::record::{AuditBreakKind, AuditChain, AuditRecord};
use crate::sign::{AuditVerifyingKey, SIGNATURE_ALGORITHM};
use crate::stamp::{BreakReason, Stamp, StampKind};

/// The shortest tail span the walk ever accepts, ms (§3.6.0 step 3).
pub const MIN_SPAN_MS: u64 = 1_000;

/// How many pages one tail may span: `SPAN` = max(100 × `every`, [`MIN_SPAN_MS`]).
pub const SPAN_PAGES: u64 = 100;

/// One record of the walked node, as the caller decoded it from the journal.
#[derive(Debug, Clone)]
pub enum TailItem {
    /// An audit line (any recipe).
    Line {
        /// The decoded line.
        record: AuditRecord,
        /// The WAL `node_seq` of the journal record that carries it.
        node_seq: u64,
    },
    /// A page stamp (`audit.stamp.v1`).
    Stamp {
        /// The decoded stamp.
        stamp: Stamp,
        /// Its WAL `node_seq`.
        node_seq: u64,
    },
    /// An audit-class body that does not decode (a line or a stamp).
    Undecodable {
        /// Its WAL `node_seq`.
        node_seq: u64,
    },
}

/// Whose chain is walked, by whom.
#[derive(Debug, Clone, Copy)]
pub struct WalkContext<'a> {
    /// The walked node X.
    pub node: u64,
    /// The sealer's own host identity.
    pub host: &'a str,
    /// The bound Bootstrap key: `key_cert = 0` stamps and legacy per-line signatures verify under it.
    pub key: &'a AuditVerifyingKey,
    /// Whether `items` start at the node's first journal record. A caller reading backwards passes
    /// `false` until it has reached the start, and reads more on [`WalkOutcome::NeedMore`].
    pub complete: bool,
}

/// Where a chain stops being vouched for (the body of an `audit.break.v1` notice, unsigned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakAt {
    /// The last line that is vouched for (0: none).
    pub last_good: u64,
    /// The first unsealed line (chain `seq`).
    pub unsealed_from: u64,
    /// The last unsealed line (chain `seq`), the tail T.
    pub unsealed_to: u64,
    /// The WAL `node_seq` of the first failing record.
    pub journal_from: u64,
    /// The WAL `node_seq` of line T.
    pub journal_to: u64,
    /// Why.
    pub reason: BreakReason,
}

/// What the walk found (§3.6.0 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkOutcome {
    /// Every line is already vouched for (M == T), or the chain holds only an unsigned legacy
    /// prefix: nothing to sign.
    Nothing {
        /// T (0 for a chain with no line).
        through: u64,
        /// Line T's WAL `node_seq` (0 for none).
        through_node_seq: u64,
    },
    /// A crash leftover M+1…T, anchored on this host: sign an `after_restart` page over it.
    Clean {
        /// M + 1.
        from: u64,
        /// T.
        to: u64,
        /// Line M+1's WAL `node_seq`.
        from_node_seq: u64,
        /// Line T's fingerprint.
        fingerprint: Fingerprint,
        /// Line T's WAL `node_seq`.
        to_node_seq: u64,
        /// The anchor stamp's `every`.
        every: u64,
        /// Line T's `linked_ms`: the last durable activity before the crash.
        down_from_ms: u64,
    },
    /// The anchor is a page of another host: this process writes nothing for the node.
    Foreign {
        /// The anchor's host.
        anchor_host: String,
    },
    /// The chain is not vouched for after `last_good`.
    Break(BreakAt),
    /// A recipe or signature algorithm this build cannot compute: nothing is stamped or recorded.
    Unsupported,
    /// The items do not reach back to an anchor yet (only with `complete = false`).
    NeedMore,
}

/// One anchor candidate, newest first.
enum Candidate<'a> {
    Stamp(&'a Stamp),
    Legacy(usize),
}

/// The anchor found in step 1.
struct Anchor<'a> {
    /// M.
    seq: u64,
    /// The index of line M in `lines`, if M > 0.
    line: Option<usize>,
    /// The stamp, if the anchor is one.
    stamp: Option<&'a Stamp>,
}

/// `SPAN` for an anchor stamp's `every`.
#[must_use]
pub fn span_ms(every: u64) -> u64 {
    let _ = every;
    0
}

/// THE WALK (§3.6.0): `items` are the node's records oldest first, through its tail.
#[must_use]
pub fn walk_tail(items: &[TailItem], cx: &WalkContext<'_>) -> WalkOutcome {
    let _ = (items, cx);
    WalkOutcome::NeedMore
}

/// Whether one stamp candidate passes step 1 against its line `to`.
fn stamp_passes(stamp: &Stamp, line: &AuditRecord, cx: &WalkContext<'_>) -> bool {
    // Only Bootstrap-keyed stamps (`key_cert = 0`) are resolvable: no build of this release
    // writes a `notary_key` certificate line, so a certified key can never be shown genuine here.
    if stamp.key_cert != 0 || stamp.node != cx.node || line.node != cx.node {
        return false;
    }
    if stamp.verify(cx.key).is_err() {
        return false;
    }
    AuditChain::digest_of(line) == line.hash
        && Fingerprint::from_hex(&line.hash) == Some(stamp.fingerprint)
}
