// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration: what the previous release's rows already hold, sealed once as the opening figures.
//!
//! ## What it is for
//!
//! A checkpoint is the point the identity is measured FROM, and on the first boot of a deployment
//! that has been serving for a year there is no such point. Without one, every figure the previous
//! release accumulated is either invisible to this release's books or — worse — looks like value
//! that appeared out of nowhere the first time anything is checked. So the first boot reads what the
//! previous release's rows hold, seals it as an OPENING checkpoint, and measures everything
//! afterwards from there.
//!
//! ## The three rules, and why each is a rule rather than an intention
//!
//! **It runs once.** The marker is written into the ledger's own records, not into the rows it read,
//! and a boot that finds one reads nothing and writes nothing. A migration that ran twice would seal
//! a second opening on top of the first and double every balance in it.
//!
//! **It never writes to what it read.** A deployment may perfectly well be booting against a
//! read-only replica or a grant-restricted database — that is the previous release's supported
//! shape, not an exotic one — so the source seam here has a `read` and nothing else. There is no
//! write-read-back probe, no watermark stamped back onto the legacy rows, and no "mark migrated"
//! column: a seam with no write method cannot grow one by accident.
//!
//! **The sealed figures are the legacy totals, exactly.** Not rounded, not re-priced, not summed
//! across dimensions. One legacy figure is one bucket, on one day, on one lane, from one provider,
//! in one dimension; it lands in one balance, and the balance holds the same integer that was read.
//!
//! ## What "an opening figure" means in the totals
//!
//! Value that the previous release consumed was taken out of the store and posted, so the opening
//! sets DRAWN and SETTLED to the same amount and everything else to zero. That is not a
//! presentational choice: it is what makes the opening checkpoint satisfy the identity by
//! construction — everything drawn is accounted for, in the settled column — so the very first
//! reconciliation after an upgrade measures this release's own postings and not the previous
//! release's history.
//!
//! ## Why the two row families stay apart
//!
//! The previous release keeps a bucket's consumption twice: once as the bucket's own token ledger
//! for a window, and once as per-lane, per-provider metering rows on a day. They are two VIEWS of
//! the same consumption, and folding them into one balance would open the books at double what was
//! actually consumed. So each family seals at its own scope — the window family at the bucket's
//! scope, the metering family in a pool named for the lane and the provider — and the two prefixes
//! are what makes a collision ACROSS THE FAMILIES impossible rather than unlikely.
//!
//! The prefix settles the families and nothing else. Inside the metering family the pool joins two
//! caller-controlled components, and a prefix says nothing about where one of them ends: joined on a
//! bare slash, `("lane/4", "vendor")` and `("lane", "4/vendor")` both spell `meter:lane/4/vendor`, so two
//! providers' opening figures land in one balance and add. That is the same error one level down —
//! two customers' money in one bucket — and it is closed the same way it is closed everywhere else
//! in this tree: each component is LENGTH-FRAMED, so the boundary is fixed by a count the rows
//! cannot write. See `meter_pool_scope`, which is the single source of truth for that key.
//!
//! ## An empty store is not a failure
//!
//! A deployment whose store keeps nothing across a restart, and an older store that cannot answer
//! at all, both read as nothing. Both seal an opening checkpoint at zero and the node serves. A
//! refusal here would mean a configuration that worked yesterday stops working on upgrade, which is
//! the one outcome a migration may not produce — and a boot that skipped the seal on an empty read
//! would leave the deployment with no point to measure from, which is the defect this module exists
//! to remove.

use std::collections::BTreeMap;

use crate::checkpoint::{ChainHead, Checkpoint, CheckpointSecret};
use crate::legacy::{opening_balances, LegacyHead, OpeningBalance};
use crate::totals::{BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart};

/// The sequence number of the opening checkpoint.
///
/// Zero, because it is the point everything else is measured from: the first checkpoint this
/// deployment seals under its own steam is the one after it. Named rather than spelled inline so
/// the marker, the checkpoint and anything reading either agree by construction.
pub const OPENING_CHECKPOINT_SEQ: u64 = 0;

/// The figures the migration reads, the seams it reads them through and the marker it seals: the
/// contract's, because the store adapter implements the seams on the other side of it.
pub use busbar_contract::migration::{
    LegacyCapDimension, LegacyFamily, LegacyFigure, LegacyFigures, LegacyLedgerRows,
    MigrationError, MigrationMarker, MigrationRecords,
};

impl From<LegacyCapDimension> for CapDimension {
    fn from(dimension: LegacyCapDimension) -> Self {
        match dimension {
            LegacyCapDimension::Requests => CapDimension::Requests,
            LegacyCapDimension::Class(class) => CapDimension::Class(class),
        }
    }
}

/// ONE COMPONENT OF A COMPOSITE POOL KEY, FRAMED SO ITS BOUNDARY CANNOT BE FORGED.
///
/// The component's byte length goes down first in decimal, then a colon, then exactly that many
/// bytes. A reader takes the digits up to the colon as a count and consumes precisely that count, so
/// every boundary is fixed by a number the caller does not write; a decimal length can itself contain
/// no colon, so there is nothing left for a caller's own bytes to move.
///
/// This is the SAME framing, for the same reason, as the admin crate's `verbs::rotate_replay_key`
/// (`crates/busbar-core-admin/src/verbs.rs:91`), which joins two caller-controlled halves of a
/// replay key. That helper could not be called from here for two independent reasons: it is
/// `pub(crate)` to `busbar-core-admin`, and `busbar-core-admin` depends on this crate
/// (`busbar-core-admin → busbar-kernel-ledger`), so an edge back would be a cycle Cargo
/// refuses outright. What is shared is the VOCABULARY, deliberately spelled the same way rather than
/// as a second length-framing dialect — a tree with two spellings of "length-prefixed" is a tree
/// where the next composite key picks the wrong one.
///
/// The lengths are BYTE lengths, not character counts: the key is compared as bytes, and a count of
/// characters would put the boundary somewhere other than where a reader would find it.
fn length_framed(component: &str) -> String {
    format!("{}:{component}", component.len())
}

/// THE POOL SCOPE A METERING ROW LANDS ON, given its lane and its provider.
///
/// The single source of truth for the metering pool key: [`figure_key`] builds its metering
/// scope through this, and any consumer that needs to look a migrated metering balance back up must
/// build the same scope here rather than re-spelling the framed key by hand — a hand-spelled copy is
/// how the producer and the reader come to disagree about which balance is which.
#[must_use]
pub fn meter_pool_scope(lane: &str, provider: &str) -> BucketScope {
    BucketScope::Pool(format!(
        "meter:{}{}",
        length_framed(lane),
        length_framed(provider)
    ))
}

/// The balance `figure` opens.
///
/// The two families take deliberately different pool prefixes. A metering row whose provider
/// happens to be empty would otherwise land on the same key as a window row for the same lane,
/// and the two would silently add — which is the one arithmetic error a migration cannot be
/// allowed to make, because there is nothing left to compare the result against.
///
/// The prefix settles the two FAMILIES, and nothing more. Inside the metering family the key
/// joins two caller-controlled components — the lane and the provider, both free text read off
/// the previous release's rows — and a bare delimiter between them is not a key: joined on a
/// slash, `("lane/4", "vendor")` and `("lane", "4/vendor")` both spell `meter:lane/4/vendor` and land
/// on ONE balance, silently adding two providers' opening figures together. That is two
/// customers' money in one bucket, and it is the one arithmetic error a migration cannot be
/// allowed to make. So each component is LENGTH-FRAMED (see [`length_framed`]), which no
/// arrangement of delimiters inside a component's own text can imitate.
pub fn figure_key(figure: &LegacyFigure) -> TotalsKey {
    let scope = match (figure.family, figure.lane.as_str()) {
        (LegacyFamily::Window, "") => BucketScope::All,
        (LegacyFamily::Window, lane) => BucketScope::Pool(format!("lane:{lane}")),
        (LegacyFamily::Meter, lane) => meter_pool_scope(lane, &figure.provider),
    };
    TotalsKey::new(
        BucketId::new(figure.bucket.clone()),
        figure.dimension.clone().into(),
        scope,
    )
}

/// What the migration sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    /// The opening checkpoint. Its totals ARE the legacy figures.
    pub checkpoint: Checkpoint,
    /// The marker for this opening, so the caller need not read the records back to report it.
    /// Written to the records only when [`Opening::marker_written`] is true.
    pub marker: MigrationMarker,
    /// Whether the marker was actually committed to the records.
    ///
    /// False exactly when the read was degraded — see [`Opening::unreadable`]. The marker is a
    /// run-once record, so committing it over a short read would make the short read permanent:
    /// every later boot would return [`Outcome::AlreadySealed`] and the buckets the store could not
    /// answer for would be missing from the opening forever, leaving the reconciliation identity
    /// quietly short by their whole history. Leaving it unwritten costs a re-read on the next boot
    /// and nothing else, because the seal is a pure function of what was read: once the store
    /// answers for everything, the same rows seal the same checkpoint and the marker goes down then.
    pub marker_written: bool,
    /// The opening entry per bucket, at the named card version.
    pub balances: Vec<OpeningBalance>,
    /// The rows that could not be read, named. Empty on a store that answered for everything.
    pub unreadable: Vec<String>,
}

/// What a boot's migration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This boot sealed the opening.
    Sealed(Box<Opening>),
    /// A marker was already there. Nothing was read and nothing was written.
    AlreadySealed(MigrationMarker),
}

impl Outcome {
    /// Whether this boot did the sealing.
    pub fn sealed_now(&self) -> bool {
        matches!(self, Outcome::Sealed(_))
    }

    /// The marker for what this boot found or sealed. On [`Outcome::Sealed`] it describes the
    /// opening whether or not it was committed — [`Opening::marker_written`] is the field that says
    /// which, because a degraded read seals an opening and deliberately leaves no record behind.
    pub fn marker(&self) -> &MigrationMarker {
        match self {
            Outcome::Sealed(opening) => &opening.marker,
            Outcome::AlreadySealed(marker) => marker,
        }
    }
}

/// Fold the legacy figures into the balances an opening checkpoint seals.
///
/// A pure function of the figures: no clock, no store, no records. That is what lets the claim "the
/// sealed figures equal the legacy totals" be checked by a test that never sealed anything, and by
/// an auditor holding a checkpoint and the rows it was made from.
///
/// Drawn and settled move together and everything else stays at zero — see this module's preamble
/// for why that is the shape that makes the opening satisfy the identity.
///
/// # Errors
///
/// Two figures for one balance sum past what a ledger figure can hold.
pub fn opening_totals(
    figures: &[LegacyFigure],
) -> Result<BTreeMap<(TotalsKey, WindowStart), Totals>, MigrationError> {
    let mut totals: BTreeMap<(TotalsKey, WindowStart), Totals> = BTreeMap::new();
    for figure in figures {
        let key = figure_key(figure);
        let entry = totals.entry((key.clone(), figure.window)).or_default();
        let overflow = || MigrationError::FigureOverflow {
            key: key.to_string(),
            window: figure.window,
        };
        entry.drawn = entry
            .drawn
            .checked_add(figure.amount)
            .ok_or_else(overflow)?;
        entry.settled = entry
            .settled
            .checked_add(figure.amount)
            .ok_or_else(overflow)?;
    }
    Ok(totals)
}

/// The previous release's chain head, as a checkpoint cross-links it.
///
/// The head's hash is text of a shape this crate never agreed to, so it is DIGESTED rather than
/// parsed: a fixed-width identity that is a pure function of what was read, and no parse that could
/// fail on a deployment whose previous release wrote something else. A head with neither a sequence
/// number nor a hash cross-links nothing, which is the honest answer for a store that had nothing to
/// say.
fn opening_heads(head: &LegacyHead, node: u64) -> Vec<ChainHead> {
    if head.seq.is_none() && head.hash.is_none() {
        return Vec::new();
    }
    vec![ChainHead {
        node,
        node_seq: head.seq.unwrap_or(0),
        hash: crate::digest::sha256(head.hash.as_deref().unwrap_or("").as_bytes()),
    }]
}

/// Run the migration: read what the previous release holds, seal it as the opening, and mark it
/// done IF the read was complete.
///
/// Idempotent by the marker AND by the figures. The marker is what makes a second boot cost
/// nothing; but a deployment whose records do not survive a restart re-reads the same read-only rows
/// and seals a checkpoint with the same body hash, so even there running again is indistinguishable
/// from not having run. That is the property to lean on, because it does not depend on where the
/// marker was kept.
///
/// It is also what makes withholding the marker after a degraded read safe, and withholding it
/// necessary: the marker is run-once, so writing it over a read that could not answer for some
/// buckets would seal those buckets out of the opening forever and leave the reconciliation
/// identity short by their whole history, with every later boot short-circuiting on the marker
/// before it could notice. So a degraded read seals the opening the node needs to boot and leaves
/// the marker for a boot that can read everything ([`Opening::marker_written`] says which happened).
///
/// # Errors
///
/// The ledger's own records could not be read or written, the opening could not be signed, or the
/// figures do not fit. A store that could not answer for some rows is NOT an error — those rows come
/// back named in [`Opening::unreadable`] and the node boots.
pub fn migrate(
    source: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    node: u64,
    wall: u64,
    rate_card_version: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Outcome, MigrationError> {
    // The marker first, and the read only if there is no marker. Reading anyway would be harmless
    // arithmetic and a pointless full scan of somebody else's rows on every restart.
    if let Some(marker) = records.read_marker()? {
        return Ok(Outcome::AlreadySealed(marker));
    }

    let head = source.read_head();
    let read = source.read_figures();
    let totals = opening_totals(&read.figures)?;
    let balances = opening_balances(&head, rate_card_version);

    let checkpoint = Checkpoint::seal(
        OPENING_CHECKPOINT_SEQ,
        node,
        wall,
        opening_heads(&head, node),
        totals,
        // Nothing has been backed up under this release yet, and claiming otherwise would let
        // retention discard a segment on the strength of a backup that was never taken.
        0,
        head.seq.unwrap_or(0),
        secret,
    )?;

    let marker = MigrationMarker {
        checkpoint_seq: checkpoint.checkpoint_seq,
        node,
        sealed_at: wall,
        body_hash: checkpoint.body_hash,
        balances: checkpoint.totals.len() as u64,
        cells_read: head.cells_read,
        rate_card_version,
    };
    // The marker goes down only over a COMPLETE read. It is the run-once record: written over a
    // degraded read it makes the degradation permanent, because every later boot then returns
    // `AlreadySealed` and never looks at the rows the store could not answer for. Withholding it
    // costs the next boot a re-read and nothing else — the seal is a pure function of what was read,
    // so a clean re-read seals the identical checkpoint and writes the marker then. The opening is
    // still returned either way: a node must boot over what could be read.
    let marker_written = read.unreadable.is_empty();
    if marker_written {
        records.write_marker(&marker)?;
    }

    Ok(Outcome::Sealed(Box::new(Opening {
        checkpoint,
        marker,
        marker_written,
        balances,
        unreadable: read.unreadable,
    })))
}

/// Records that keep the marker in this node's own memory.
///
/// The honest default, and labelled as one: on a deployment whose store predates the ledger's own
/// record wire there is nowhere durable for a marker to go, so it goes here and does not survive a
/// restart. That costs a re-read of the previous release's rows on the next boot and nothing else —
/// the seal is a pure function of what was read, so the same rows seal the same checkpoint.
#[derive(Debug, Default, Clone)]
pub struct NodeLocalRecords {
    marker: std::sync::Arc<std::sync::Mutex<Option<MigrationMarker>>>,
}

impl NodeLocalRecords {
    /// A fresh one.
    pub fn new() -> Self {
        NodeLocalRecords::default()
    }

    /// Whether this node has sealed a migration in this process.
    pub fn is_sealed(&self) -> bool {
        self.marker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

impl MigrationRecords for NodeLocalRecords {
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError> {
        Ok(self
            .marker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn write_marker(&mut self, marker: &MigrationMarker) -> Result<(), MigrationError> {
        *self.marker.lock().unwrap_or_else(|e| e.into_inner()) = Some(marker.clone());
        Ok(())
    }
}
