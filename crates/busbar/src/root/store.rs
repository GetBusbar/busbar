// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S ONE STORE HANDLE, bound once by the composition root.
//!
//! ## Why this file exists
//!
//! A plane may not hold a store and a unit may not know a schema, so the only kind entitled to bind
//! the two together is the composition. Until this file there was no production binding at all: the
//! adapter that carries the three unit-side store seams was constructed by tests and by nothing
//! else, so every plane's record legs had nothing to be bound TO and the one mounted leg was handed
//! a refusing stand-in instead. That is the gap this closes, and it closes it ONCE for every
//! plane rather than once per plane — a second binding would be a second answer to "which store did
//! this node write that record onto", and the two would agree right up until one of them did not.
//!
//! ## One handle, and how that is made a fact rather than a convention
//!
//! The node has exactly one store: whatever the configured `store.module` resolved to, which is the
//! in-tree RAM backend when a configuration names none and a loaded module when it names one. Both
//! arrive here as the same `busbar_api::Store`, and everything downstream — the plane record legs,
//! the mutation log's durable path, the per-call record's — is handed the handle THIS
//! function returns rather than taking its own read of the governance state. That is what makes
//! "the same handle" a property of the code and not of the reader's memory of it.
//!
//! ## What the RAM default and a durable module have in common, stated
//!
//! Nothing here branches on which backend is behind the face, and that is deliberate: the published
//! store protocol is the whole of what a record leg uses, the RAM backend implements it, and a
//! durable module implements it. A binding that asked which one it had would be a binding that
//! could answer differently for the two, and then "it works on memory" would stop meaning anything
//! about the deployment an operator actually runs.

use std::sync::Arc;

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, Store as AbiStore};
use busbar_contract::ids::RecordSchemaId;
use busbar_plugin_loader::store_adapter::StoreAdapter;

/// Bind the node's one store handle behind the published ABI.
///
/// **This is the composition root's only construction of a store adapter, and the only one in the
/// tree outside tests.** What it returns is cheap to clone and every clone is the same store, so a
/// caller that needs the handle in two places takes two clones rather than binding twice.
///
/// The payload schema is the CURRENT one. That is exact for the RAM default and for a module
/// published against this release, and it is the only reading available where the handle exists:
/// the signed manifest that would say otherwise is read by the plugin registry during preflight and
/// is not carried on the `Store` face. What the schema gates is the verbs unit's node-local shim
/// (`StoreAdapter::speaks_new_ops`) and nothing on the record path, which passes every operation
/// through to the store untouched — so a module at an older schema still writes and reads its
/// plane records exactly as it did. A deployment that needs the shim gated on a manifest value
/// binds through `StoreAdapter::new` with that value; this function does not guess one.
#[must_use]
pub fn node_adapter(store: Arc<dyn busbar_api::Store>) -> StoreAdapter {
    StoreAdapter::native(store)
}

/// THE SIX RECORD OPERATIONS, as the composition root names them.
///
/// The published store protocol offers six calls; a plane's route plan names one of them by word.
/// The JOIN between the two is this root's, because the root is the one kind entitled to name a
/// store and a plane together — a plane may not hold a store and the store may not know a plane.
///
/// The words are here rather than read off one plane's re-export of them, which is what the runner
/// below used to do: reading `busbar_plane_mcp::records::OP_GET` to decide which store call to make
/// meant the NEUTRAL runner named a plane, and a second plane's identical constant was a different
/// symbol with the same text. Each plane keeps its own spelling — that is its declaration, and it
/// is what its route plan is written in — and a cell in this module asserts the two sets are the
/// same six words, so a rename on either side goes red here rather than quietly routing a leg to a
/// store call nobody meant.
pub mod op {
    /// Read one record by key.
    pub const GET: &str = "get";
    /// Write one record, replacing whatever was under the key.
    pub const PUT: &str = "put";
    /// Every record the selector matches.
    pub const SCAN: &str = "scan";
    /// Add one record under a parent.
    pub const APPEND: &str = "append";
    /// Remove one record by key.
    pub const DELETE: &str = "delete";
    /// Spend a one-time grant, as a test-and-set on the store.
    pub const REDEEM: &str = "redeem";

    /// The six, in the order the runner maps them.
    pub const ALL: &[&str] = &[GET, PUT, SCAN, APPEND, DELETE, REDEEM];
}

/// What one record leg answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordAnswer {
    /// One record's body, or nothing under that key.
    One(Option<Vec<u8>>),
    /// Every record the scan matched, oldest first where the schema is ordered.
    Many(Vec<Vec<u8>>),
    /// The write landed.
    Written,
    /// The grant was spent, and whether this caller is the one who spent it.
    Redeemed(bool),
}

/// A record leg the root could not service.
#[derive(Debug)]
pub enum RecordRefusal {
    /// The plane does not declare this operation for this schema. The trust unit refuses such a leg
    /// before it is ever run; this arm is the second door, so a caller reaching the store by another
    /// route cannot get past it either.
    Undeclared {
        /// The schema the leg named.
        schema: RecordSchemaId,
        /// The operation it named.
        op: &'static str,
    },
    /// The store answered with a failure.
    Store(String),
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordRefusal::Undeclared { schema, op } => {
                write!(f, "this plane declares no {op} on {schema}")
            }
            RecordRefusal::Store(message) => {
                write!(f, "the store refused the record leg: {message}")
            }
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// ONE PLANE'S record legs, over the node's one store.
///
/// Two things and no third: the node's ONE store handle, and the DECLARATION TABLE of the plane
/// whose legs these are — which schemas carry which operations. The declaration is a function
/// pointer into the plane's own `records` module rather than a table restated here, because which
/// operations a schema has is the plane's data and a root that restated it would be a second answer
/// that drifts the first time a plane gains an operation.
///
/// That pair is the whole of what makes this KIND-NEUTRAL. There is nothing of any plane in the
/// body below: the six operations it maps onto are the published protocol's own, every plane's legs
/// are the same six, and the one question that could differ between planes — may this schema do
/// this? — is asked of the plane. So one runner serves every plane, and a plane's leg cannot reach
/// an operation its own declaration does not carry, whichever plane it is.
///
/// A store that predates the record operations answers from the adapter's node-local shim, which is
/// why a deployment on a released store boots and serves exactly as it did.
pub struct PlaneRecords {
    store: Arc<dyn AbiStore>,
    /// The plane's own declaration: which operations this schema carries. Held as the plane
    /// exported it, so a schema that gains or loses one changes what is refused here with nothing
    /// in the root edited.
    operations: fn(RecordSchemaId) -> &'static [&'static str],
}

impl PlaneRecords {
    /// Bind ONE plane's record legs to the node's one store, under that plane's declaration table.
    ///
    /// The adapter is the one store handle in the process — [`node_adapter`]'s — and it is the
    /// published protocol's own record operations that answer here, not a second shape invented for
    /// any plane. Keyed by the plane whose declaration is handed in: two planes bound through this
    /// get two values over ONE store, which is what it means for a node to have one store and
    /// several planes' records on it.
    #[must_use]
    pub fn of(
        adapter: &StoreAdapter,
        operations: fn(RecordSchemaId) -> &'static [&'static str],
    ) -> Self {
        PlaneRecords {
            store: adapter.store(),
            operations,
        }
    }

    /// Run one leg.
    ///
    /// The six operations the plane declares map one to one onto the six the published protocol
    /// offers. Five of them are the obvious mapping; the sixth is not, and it is the reason the
    /// mapping is written out rather than derived: a redemption is a test-and-set on the store, so a
    /// retry cannot spend a grant a first attempt already spent.
    ///
    /// # Errors
    ///
    /// The plane does not declare the operation for the schema, or the store refused.
    pub fn run(&self, leg: &RecordLeg<'_>) -> Result<RecordAnswer, RecordRefusal> {
        if !(self.operations)(leg.schema).contains(&leg.op) {
            return Err(RecordRefusal::Undeclared {
                schema: leg.schema,
                op: leg.op,
            });
        }
        let kind = leg.schema.as_str();
        let map = |e: busbar_api::StoreError| RecordRefusal::Store(e.0);
        match leg.op {
            op::GET => self
                .store
                .get_plane_record(kind, leg.key)
                .map(RecordAnswer::One)
                .map_err(map),
            op::SCAN => {
                let selector = match leg.parent {
                    Some(parent) => PlaneSelector::Parent(parent.to_string()),
                    None => PlaneSelector::All,
                };
                self.store
                    .list_plane_records(kind, &selector)
                    .map(RecordAnswer::Many)
                    .map_err(map)
            }
            op::PUT => self
                .store
                .upsert_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            op::APPEND => self
                .store
                .append_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            op::DELETE => self
                .store
                .delete_plane_record(kind, leg.key)
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            op::REDEEM => self
                .store
                .redeem_plane_token(kind, leg.key, leg.expires_at, leg.now)
                .map(RecordAnswer::Redeemed)
                .map_err(map),
            // Unreachable while the declaration check above runs first, and kept because the
            // declaration is data: a seventh operation added to the plane would land here rather
            // than in whichever arm it happened to look like.
            other => Err(RecordRefusal::Undeclared {
                schema: leg.schema,
                op: other,
            }),
        }
    }
}

/// Everything one record leg needs.
#[derive(Debug, Clone, Copy)]
pub struct RecordLeg<'a> {
    /// Which of the plane's six schemas.
    pub schema: RecordSchemaId,
    /// Which of the plane's six operations.
    pub op: &'static str,
    /// The record's own key within the schema.
    pub key: &'a str,
    /// The record this leg belongs under, where the schema is a child one.
    pub parent: Option<&'a str>,
    /// The position within the parent, for an append.
    pub seq: u64,
    /// The opaque body. The store keeps it verbatim and never looks inside.
    pub body: &'a [u8],
    /// Whether this record is finished, which is what retention reads to decide whether it may go.
    pub terminal: bool,
    /// The wall clock, in seconds.
    pub now: u64,
    /// When a one-time grant lapses.
    pub expires_at: u64,
}

impl RecordLeg<'_> {
    /// The durable envelope this leg writes.
    fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: self.schema.as_str().to_string(),
            id: self.key.to_string(),
            parent: self.parent.map(ToString::to_string),
            seq: self.seq,
            ts: self.now,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            body: self.body.to_vec(),
        }
    }
}

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
