// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL-HELD RECORD LEG, and the store reach that lands it.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! kernel-held record, reached only through a leg of the route plan — which is what each plane's
//! own record declaration has said since it was written. This module is the other half of that
//! sentence: the leg is validated by the kernel, the record's bytes are framed by the
//! audit unit, and the reach onto the published store protocol is the composition root's, because
//! the root is the one kind entitled to name a store, a unit and a plane in the same file.
//!
//! ## The three owners, and why none of them is this file
//!
//! | what | whose | where |
//! |---|---|---|
//! | may this plane name this schema, may this schema do this operation, is the body within the record ceiling | the kernel's | [`busbar_kernel::pump::run_record_leg`] |
//! | the prelude, the digest, the sequence authority, the verifier | the audit unit's | [`busbar_unit_audit::legacy`] |
//! | which store verb performs the operation | the composition root's | here |
//!
//! What is left here is the composition and nothing else: hold the position, ask the unit to seal,
//! ask the kernel to admit, ask the store to keep it. A record whose middle any of those three
//! could rewrite would not be evidence.
//!
//! ## The record is opaque, and that is the whole point
//!
//! A leg carries a pre-framed content SUFFIX — the plane's own fields, already canonicalised in the
//! record's declared framing — and this module never looks inside it. The digest input is the
//! unit's prelude byte-concatenated with that suffix, so a chain appended through a leg is
//! byte-identical to one appended by anything else that fed the same suffix. That is what lets a
//! store written by a previous release verify here without a migration, and it is why this file
//! names no plane, no schema and no field: it knows the KIND of thing it is carrying and nothing
//! about the instance.
//!
//! ## The one shape a record may still need per stream
//!
//! Some streams have bodies on disk that predate the neutral envelope. Rather than teach this file
//! which stream those are, the composition supplies a [`LegacyDecode`] beside the schema: a
//! function that recognises the older row and returns the same four parts. A stream with no such
//! history supplies `None` and the neutral envelope is the only shape it ever sees.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector};
use busbar_contract::ids::RecordSchemaId;
use busbar_kernel::pump::{RecordAnswer, RecordKey, RecordRefusal, RecordSchemas, RecordStore};
use busbar_unit_audit::legacy::{
    frame_prelude, verify_chain, Chain, ChainBreak, ChainLabels, ChainedRecord, Digest, Framing,
};

/// The neutral durable body one chained record persists as — `{seq, prev_hash, hash, content}`,
/// naming no plane type and no schema.
///
/// The field names are a wire fact, not a preference: they are what is on disk in every deployment
/// that has ever written one of these streams, and renaming one would make every persisted record
/// undecodable at the next boot.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordBody {
    /// The chain sequence this record was minted at.
    seq: u64,
    /// The link to the previous record (empty at genesis).
    prev_hash: String,
    /// This record's sealed digest.
    hash: String,
    /// The plane's OPAQUE pre-framed content suffix, carried verbatim.
    content: Vec<u8>,
}

/// Recognise a body a store held BEFORE the neutral envelope existed, and return the same four
/// parts a neutral body carries.
///
/// A function rather than a variant, because the set of streams with an older shape is a property
/// of what has been deployed and not of what a record leg is. `None` from a decode that does not
/// recognise the bytes; the leg then reports the row unreadable rather than guessing.
pub type LegacyDecode = fn(&[u8]) -> Option<(u64, String, String, Vec<u8>)>;

/// One record read back off the store, in the parts every reader of a chained stream needs.
///
/// The content is handed back opaque. Turning it into whatever typed row a reader wants is that
/// reader's business — this module framed it, it did not author it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredRecord {
    /// The chain this record belongs to.
    pub scope: String,
    /// Its position.
    pub seq: u64,
    /// The link to its predecessor.
    pub prev_hash: String,
    /// Its sealed digest.
    pub hash: String,
    /// Its opaque pre-framed content suffix.
    pub content: Vec<u8>,
}

/// What one append minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// The position the record took.
    pub seq: u64,
    /// The predecessor it linked to.
    pub prev_hash: String,
    /// The digest it was sealed under.
    pub hash: String,
}

/// What a boot restore actually found.
///
/// Every number is reported rather than summed: they mean different things to an operator, and a
/// single number hides the one that is bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// The chains the store held records for.
    pub scopes: usize,
    /// Records read back and seeded.
    pub records: usize,
    /// Chains the store enumerated but held no readable record for.
    pub empty_chains: usize,
    /// Rows the store returned that could NOT be decoded. COUNTED and SKIPPED per-record rather
    /// than aborting the restore: an unreadable row on an evidence stream may be tamper evidence,
    /// and aborting would leave every chain after it unseeded and fork it at sequence one.
    pub unreadable: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes from the broken tail — refusing would let anyone who can write to the store
    /// erase history by corrupting one record — but the break is reported.
    pub chain_breaks: Vec<ChainBreak>,
    /// The records themselves, in the order the store returned them, for a reader that seeds a
    /// read model from the durable tail.
    pub rows: Vec<RestoredRecord>,
}

/// Why a leg did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegError {
    /// The kernel refused the leg.
    Refused(RecordRefusal),
    /// A body could not be encoded into, or decoded out of, the neutral envelope.
    Body(String),
    /// The store refused or failed.
    Store(String),
}

impl std::fmt::Display for LegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegError::Refused(r) => write!(f, "the record leg was refused: {r:?}"),
            LegError::Body(why) => write!(f, "the record body could not be framed: {why}"),
            LegError::Store(why) => write!(f, "the record store refused: {why}"),
        }
    }
}

/// One appended record: the chain's own prelude fields, the stream's framing declaration, and the
/// plane's opaque suffix.
///
/// It implements the audit unit's [`ChainedRecord`] so that the ONE verifier walks it unchanged.
/// The framing travels on the RECORD rather than on the type, because one process serves several
/// streams and they do not agree on it — so [`ChainedRecord::FRAMING`] governs no byte here and
/// [`ChainedRecord::digest_fields`] frames the prelude in the record's own declaration before
/// appending the suffix raw.
#[derive(Clone)]
struct LeggedRecord {
    scope: String,
    seq: u64,
    prev_hash: String,
    hash: String,
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

/// The payload one append supplies. Carries NO sequence, previous hash or hash: those are the
/// chain's authority, and a call site that could supply one could choose where its record sits.
struct LeggedInput {
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

impl ChainedRecord for LeggedRecord {
    type Input = LeggedInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the kernel-held record chain",
        scope: "scope",
    };
    /// Governs no byte: [`Self::digest_fields`] frames the prelude in the record's per-instance
    /// framing and appends the suffix raw. It is here because the trait asks for it.
    const FRAMING: Framing = Framing::LengthPrefixed;

    fn scope_of(&self) -> &str {
        &self.scope
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }

    fn link(scope: &str, seq: u64, prev_hash: String, input: LeggedInput) -> Self {
        LeggedRecord {
            scope: scope.to_string(),
            seq,
            prev_hash,
            hash: String::new(),
            content: input.content,
            framing: input.framing,
            digests_scope: input.digests_scope,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    /// The prelude, framed in this record's declaration, then the plane's suffix RAW.
    ///
    /// A pure byte concatenation, which is what makes `prelude ⧺ suffix` equal to the single
    /// canonicalised buffer a record type that fed its own fields would have produced. The
    /// pipe-separated genesis vertical bar is preserved by the prelude, and the suffix carries the
    /// separator it owes.
    fn digest_fields(&self, d: &mut Digest) {
        let scope = self.digests_scope.then_some(self.scope.as_str());
        d.raw(&frame_prelude(
            self.framing,
            &self.prev_hash,
            scope,
            self.seq,
        ));
        d.raw(&self.content);
    }
}

/// A plane's declaration table, as the kernel reads it.
///
/// The two items are the plane crate's own and are not restated: a schema that gains or loses an
/// operation changes what the kernel refuses without anything in the root being edited. It is a
/// pair of pointers rather than a trait each plane implements, because the composition is what
/// knows which plane it is mounting and the kernel only ever asks these two questions.
pub struct DeclaredSchemas {
    schemas: &'static [RecordSchemaId],
    operations: fn(RecordSchemaId) -> &'static [&'static str],
}

impl DeclaredSchemas {
    /// Point the kernel at one plane's declaration.
    #[must_use]
    pub fn of(
        schemas: &'static [RecordSchemaId],
        operations: fn(RecordSchemaId) -> &'static [&'static str],
    ) -> Self {
        DeclaredSchemas {
            schemas,
            operations,
        }
    }
}

impl RecordSchemas for DeclaredSchemas {
    fn schemas(&self) -> &'static [RecordSchemaId] {
        self.schemas
    }

    fn operations_for(&self, schema: RecordSchemaId) -> &'static [&'static str] {
        (self.operations)(schema)
    }
}

/// ONE plane's kernel-held record, reached through a leg.
///
/// Bound to the schema the plane declared, the framing that record's bytes are already on disk in,
/// the plane's declaration table (which the kernel reads, not this file), and the store the loader
/// resolved. It holds the chain POSITION for each scope and nothing else: the records live in the
/// store, and holding every record of every scope in memory is the thing a durable log exists to
/// avoid.
pub struct RecordLeg {
    store: Arc<dyn busbar_api::Store>,
    schemas: Box<dyn RecordSchemas>,
    schema: RecordSchemaId,
    framing: Framing,
    digests_scope: bool,
    legacy: Option<LegacyDecode>,
    /// One chain position per scope. A `Mutex` and not a lock-free map because the position IS the
    /// serialisation point: two appends that read the same tail would seal two records at the same
    /// sequence and fork the chain.
    positions: Mutex<HashMap<String, Chain<LeggedRecord>>>,
}

impl std::fmt::Debug for RecordLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordLeg")
            .field("schema", &self.schema.as_str())
            .field("framing", &self.framing)
            .field("digests_scope", &self.digests_scope)
            .finish()
    }
}

impl RecordLeg {
    /// Bind a leg to a schema, its record's framing, the plane's declaration table and a store.
    ///
    /// The framing arrives from the composition rather than being chosen here, because it is a wire
    /// fact of the records already on disk: a stream whose framing moved would report every
    /// deployed chain as tampered at its next boot.
    #[must_use]
    pub fn new(
        store: Arc<dyn busbar_api::Store>,
        schemas: Box<dyn RecordSchemas>,
        schema: RecordSchemaId,
        framing: Framing,
        digests_scope: bool,
        legacy: Option<LegacyDecode>,
    ) -> Self {
        RecordLeg {
            store,
            schemas,
            schema,
            framing,
            digests_scope,
            legacy,
            positions: Mutex::new(HashMap::new()),
        }
    }

    /// The sequence the next record appended to `scope` will carry.
    #[must_use]
    pub fn next_seq(&self, scope: &str) -> u64 {
        self.lock()
            .get(scope)
            .map_or(1, busbar_unit_audit::legacy::Chain::next_seq)
    }

    /// APPEND one record: seal it at the chain's position, offer it to the kernel as a leg, and
    /// persist what the kernel admitted.
    ///
    /// The position is advanced ONLY on a store that took the record. A write that failed leaves
    /// the chain exactly where it was, so the next append reuses the sequence and the chain stays
    /// contiguous — what is missing is this record, not the ones after it.
    ///
    /// # Errors
    ///
    /// The kernel refused the leg (undeclared schema, undeclared operation, oversize body), the
    /// neutral envelope could not be encoded, or the store refused.
    pub fn append(
        &self,
        scope: &str,
        op: &'static str,
        ts: u64,
        suffix: &[u8],
    ) -> Result<Appended, LegError> {
        let mut positions = self.lock();
        // Sealed on a CLONE of the position. The chain advances on the clone; the clone is only
        // written back once the store has the record, which is what makes a failed write leave a
        // contiguous chain rather than a hole.
        let mut chain = positions.get(scope).cloned().unwrap_or_default();
        let record = chain.append(
            scope,
            LeggedInput {
                content: suffix.to_vec(),
                framing: self.framing,
                digests_scope: self.digests_scope,
            },
        );
        let body = serde_json::to_vec(&RecordBody {
            seq: record.seq,
            prev_hash: record.prev_hash.clone(),
            hash: record.hash.clone(),
            content: record.content.clone(),
        })
        .map_err(|e| LegError::Body(e.to_string()))?;
        let key = RecordKey {
            id: scope,
            parent: Some(scope),
            seq: record.seq,
            ts,
            expires_at: 0,
            terminal: false,
        };
        self.run(op, &key, &body)?;
        let appended = Appended {
            seq: record.seq,
            prev_hash: record.prev_hash,
            hash: record.hash,
        };
        positions.insert(scope.to_string(), chain);
        Ok(appended)
    }

    /// READ one chain back, oldest-first, exactly as it is on disk.
    ///
    /// # Errors
    ///
    /// The kernel refused the leg, or the store refused.
    pub fn scan(&self, scope: &str, op: &'static str) -> Result<Vec<RestoredRecord>, LegError> {
        let key = RecordKey {
            id: scope,
            parent: Some(scope),
            seq: 0,
            ts: 0,
            expires_at: 0,
            terminal: false,
        };
        let answer = self.run(op, &key, &[])?;
        Ok(answer
            .bodies
            .iter()
            .filter_map(|b| self.decode(scope, b))
            .collect())
    }

    /// BOOT RESTORE: seed every chain this store holds records for from its persisted tail, verify
    /// each, and REPORT what was found.
    ///
    /// The scope enumeration is the root's own store reach and not a leg: a leg is a step of one
    /// plane's route plan, and no plan asks "which chains exist" — boot does, once, before any plan
    /// runs. A break is reported and the chain still resumes from the broken tail, because refusing
    /// to restore a chain that does not verify would turn a DETECTION control into a DELETION
    /// primitive: anyone who could write to the store could erase a whole history by corrupting one
    /// byte of one record.
    ///
    /// # Errors
    ///
    /// The store refused the enumeration or a read.
    pub fn restore(&self) -> Result<Restored, LegError> {
        let kind = self.schema.as_str();
        let scopes = self
            .store
            .list_plane_record_parents(kind)
            .map_err(|e| LegError::Store(e.0))?;
        let mut out = Restored {
            scopes: scopes.len(),
            ..Restored::default()
        };
        let mut positions = self.lock();
        for scope in &scopes {
            let bodies = self
                .store
                .list_plane_records(kind, &PlaneSelector::Parent(scope.clone()))
                .map_err(|e| LegError::Store(e.0))?;
            let mut records: Vec<LeggedRecord> = Vec::with_capacity(bodies.len());
            for body in &bodies {
                match self.decode_record(scope, body) {
                    Some(record) => records.push(record),
                    None => out.unreadable += 1,
                }
            }
            if records.is_empty() {
                out.empty_chains += 1;
                continue;
            }
            out.records += records.len();
            if let Err(brk) = verify_chain(&records) {
                out.chain_breaks.push(brk);
            }
            out.rows.extend(records.iter().map(|r| RestoredRecord {
                scope: r.scope.clone(),
                seq: r.seq,
                prev_hash: r.prev_hash.clone(),
                hash: r.hash.clone(),
                content: r.content.clone(),
            }));
            positions.insert(scope.clone(), Chain::from_persisted_unverified(&records));
        }
        Ok(out)
    }

    /// Run one leg through the ONE runner. The three checks are the kernel's and are not repeated
    /// here: a leg is validated in the one place a leg is run.
    fn run(
        &self,
        op: &'static str,
        key: &RecordKey<'_>,
        body: &[u8],
    ) -> Result<RecordAnswer, LegError> {
        busbar_kernel::pump::run_record_leg(self, self.schemas.as_ref(), self.schema, op, key, body)
            .map_err(|refusal| match refusal {
                RecordRefusal::Sink(why) => LegError::Store(why),
                other => LegError::Refused(other),
            })
    }

    /// Turn one stored body back into the parts a reader wants, or `None` if nothing recognises it.
    fn decode(&self, scope: &str, body: &[u8]) -> Option<RestoredRecord> {
        self.decode_record(scope, body).map(|r| RestoredRecord {
            scope: r.scope,
            seq: r.seq,
            prev_hash: r.prev_hash,
            hash: r.hash,
            content: r.content,
        })
    }

    /// The neutral envelope first — the shape every append writes — and the stream's own older row
    /// only if the composition declared one.
    fn decode_record(&self, scope: &str, body: &[u8]) -> Option<LeggedRecord> {
        let parts = match serde_json::from_slice::<RecordBody>(body) {
            Ok(nb) => (nb.seq, nb.prev_hash, nb.hash, nb.content),
            Err(_) => self.legacy?(body)?,
        };
        Some(LeggedRecord {
            scope: scope.to_string(),
            seq: parts.0,
            prev_hash: parts.1,
            hash: parts.2,
            content: parts.3,
            framing: self.framing,
            digests_scope: self.digests_scope,
        })
    }

    /// Poison-recovering: the critical section holds a position and nothing that can be left half
    /// written, so a panic elsewhere must not take the whole stream's evidence with it.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Chain<LeggedRecord>>> {
        self.positions.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The published store protocol, presented to the kernel as the sink a record leg lands in.
///
/// This is the whole of what the composition root still owns on this path: the kernel validated the
/// leg, and this turns the operation the plane spelled into the store verb that performs it.
impl RecordStore for RecordLeg {
    fn perform(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &RecordKey<'_>,
        body: &[u8],
    ) -> Result<RecordAnswer, String> {
        let kind = schema.as_str();
        let fail = |e: busbar_api::StoreError| e.0;
        match op {
            "append" => {
                self.store
                    .append_plane_record(&PlaneRecord {
                        kind: kind.to_string(),
                        id: key.id.to_string(),
                        parent: key.parent.map(str::to_string),
                        seq: key.seq,
                        ts: key.ts,
                        disposition: PlaneDisposition::Active,
                        body: body.to_vec(),
                    })
                    .map_err(fail)?;
                Ok(RecordAnswer::default())
            }
            "scan" => {
                let selector = match key.parent {
                    Some(parent) => PlaneSelector::Parent(parent.to_string()),
                    None => PlaneSelector::All,
                };
                Ok(RecordAnswer {
                    bodies: self
                        .store
                        .list_plane_records(kind, &selector)
                        .map_err(fail)?,
                    ..RecordAnswer::default()
                })
            }
            // Unreachable through the kernel, which admits only operations the schema declared, and
            // a chained stream declares append and scan. Carried as a sink refusal rather than
            // unwrapped, because a panic on the request path is never the right answer to a case
            // that says the check above it stopped working.
            other => Err(format!(
                "the {kind} record leg does not perform {other} on a chained stream"
            )),
        }
    }
}

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
