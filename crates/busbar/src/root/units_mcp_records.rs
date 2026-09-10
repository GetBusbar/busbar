// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S RECORD LEGS: what a Route step's record leg answers, why it refuses, and the
//! one runner (`Records`) that walks a planned leg against the kernel-held store.
//!
//! ## Why this is its own file
//!
//! [`crate::root::units_mcp`] is the twelve steps and the unit assembled over them. The record legs
//! are the Route step's OTHER half: the durable state a plane reaches only through a leg (§2.3
//! `PlaneRecord`), sourced from the plane's own catalogue and written through the store adapter.
//! They are reached per arrival like everything in `units_mcp`, but they are a closed vocabulary of
//! their own — five operations, one envelope, one answer, one refusal — and the structural cap
//! (`structure-lint:oversized`) said the request half had grown past what one file may hold. This
//! is the seam it picked, for the same reason [`crate::root::units_mcp_seal`] was: a reader looking
//! for how a record is written should not have to read how a request is decoded to find it.
//!
//! Re-exported from `units_mcp`, so every caller and every cell reads the same names it always did.
//!
//! **The cells did not move with it, and that is deliberate.** Every record cell sits in
//! `tests/units_mcp.rs` beside the fixtures it shares with the step cells — one store double, one
//! registration set, one plane. They reach these names through the re-export, unchanged.

use std::sync::Arc;

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, Store as AbiStore, StoreError};
use busbar_contract::ids::RecordSchemaId;
use busbar_plane_mcp::records;
use busbar_plugin_loader::store_adapter::StoreAdapter;

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
                write!(f, "the mcp plane declares no {op} on {schema}")
            }
            RecordRefusal::Store(message) => {
                write!(f, "the store refused the record leg: {message}")
            }
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// This plane's record legs, over the store the loader opened — and over the catalogue SNAPSHOT.
///
/// The adapter is the one store handle in the process, and it is the published protocol's own record
/// operations that answer here — not a second shape invented for this plane. A store that predates
/// them answers from the adapter's node-local shim, which is why a deployment on a released store
/// boots and serves exactly as it did.
///
/// **The catalogue schema is answered from the snapshot and never from the store**, and that is a
/// fact about what the catalogue IS rather than a shortcut. The protocol's existing server builds its
/// catalogue from the operator's configuration on every apply and swaps it whole; nothing of it is
/// ever written to the store, and a store scan under that kind has answered no row on any
/// deployment. So the honest source for [`records::SCHEMA_CATALOGUE`] is the same snapshot, handed
/// in at assembly as rows in the plane's own grammar ([`busbar_plane_mcp::catalogue::Row`]) — a
/// `get` reads one row by its published name and a `scan` reads them all, in the order the existing
/// server lists them. The demotion, task, call and approval schemas are the store's, exactly as
/// before.
pub struct Records {
    store: Arc<dyn AbiStore>,
    /// The catalogue rows, encoded once in the plane's record grammar, keyed by published name.
    ///
    /// Encoded at assembly and decoded by the plane on every listing, rather than kept as `Row`s
    /// and handed across directly, so the leg the plane declares is the leg that runs: a listing
    /// composed from a `Vec<Row>` the root passed beside the plan would be a listing composed from
    /// state the unit never read through a record leg.
    catalogue: Arc<[(String, Vec<u8>)]>,
}

impl Records {
    /// Bind this plane's record legs to the loaded store.
    #[must_use]
    pub fn new(adapter: &StoreAdapter) -> Self {
        Records::over(adapter.store())
    }

    /// Bind them to the store handle itself, with an EMPTY catalogue.
    ///
    /// The adapter's whole contribution above is `adapter.store()`, and a leg assembled at boot
    /// holds the handle rather than the adapter that opened it — the same shape the sibling plane's
    /// `RecordLegs::new` has. Written as the one constructor the other calls, so there is one place
    /// this binding is made rather than two that could bind different stores.
    ///
    /// Empty is a real catalogue and not a missing one: it is what a deployment with no `tools:`
    /// block has, and every listing composed over it is the empty listing the existing server
    /// answers for that deployment.
    #[must_use]
    pub fn over(store: Arc<dyn AbiStore>) -> Self {
        Records {
            store,
            catalogue: Arc::from(Vec::new()),
        }
    }

    /// The same legs, over a catalogue snapshot.
    ///
    /// Rows are encoded here, once, in the plane's own record grammar. A row that does not encode
    /// is dropped rather than written as a truncated body — which cannot happen for a row built from
    /// a serialiser's own value, and is an arm rather than an unwrap because assembly is not a place
    /// to abort a boot over a catalogue entry.
    #[must_use]
    pub fn with_catalogue(self, rows: &[busbar_plane_mcp::catalogue::Row]) -> Self {
        let catalogue: Vec<(String, Vec<u8>)> = rows
            .iter()
            .filter_map(|row| row.encode().ok().map(|body| (row.name.clone(), body)))
            .collect();
        Records {
            store: self.store,
            catalogue: Arc::from(catalogue),
        }
    }

    /// How many catalogue rows this snapshot holds, for the boot line that reports it.
    #[must_use]
    pub fn catalogue_len(&self) -> usize {
        self.catalogue.len()
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
        if !records::operations_for(leg.schema).contains(&leg.op) {
            return Err(RecordRefusal::Undeclared {
                schema: leg.schema,
                op: leg.op,
            });
        }
        let kind = leg.schema.as_str();
        let map = |e: StoreError| RecordRefusal::Store(e.0);
        // THE CATALOGUE IS THE SNAPSHOT'S — see the type's own header. Answered before the store is
        // asked so a store that happens to hold rows under this kind is never a second catalogue.
        if leg.schema == records::SCHEMA_CATALOGUE {
            return match leg.op {
                records::OP_GET => Ok(RecordAnswer::One(
                    self.catalogue
                        .iter()
                        .find(|(name, _)| name == leg.key)
                        .map(|(_, body)| body.clone()),
                )),
                records::OP_SCAN => Ok(RecordAnswer::Many(
                    self.catalogue
                        .iter()
                        .map(|(_, body)| body.clone())
                        .collect(),
                )),
                // The plane declares a `put` on this schema — its own records table says the
                // catalogue is meant to survive a restart as records — and that write lands in the
                // store exactly as it did before the snapshot existed. Nothing reads it back yet:
                // the read half is the snapshot's, and moving the read onto the store-held rows is
                // the cut after this one, named in the deletion list.
                _ => self.store_leg(leg, kind, map),
            };
        }
        self.store_leg(leg, kind, map)
    }

    /// One leg over the store, for every schema and operation the plane declares.
    fn store_leg(
        &self,
        leg: &RecordLeg<'_>,
        kind: &str,
        map: impl Fn(StoreError) -> RecordRefusal,
    ) -> Result<RecordAnswer, RecordRefusal> {
        match leg.op {
            records::OP_GET => self
                .store
                .get_plane_record(kind, leg.key)
                .map(RecordAnswer::One)
                .map_err(map),
            records::OP_SCAN => {
                let selector = match leg.parent {
                    Some(parent) => PlaneSelector::Parent(parent.to_string()),
                    None => PlaneSelector::All,
                };
                self.store
                    .list_plane_records(kind, &selector)
                    .map(RecordAnswer::Many)
                    .map_err(map)
            }
            records::OP_PUT => self
                .store
                .upsert_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_APPEND => self
                .store
                .append_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_DELETE => self
                .store
                .delete_plane_record(kind, leg.key)
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_REDEEM => self
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
