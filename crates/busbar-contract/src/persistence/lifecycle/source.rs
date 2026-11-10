// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned historical interpretation over the retained native snapshot.
//! These declarations select a neutral codec, never a backend or executable path.

use super::{Digest, Error, Id};
use crate::{
    records::{
        AuditRecord, CredentialMeta, MeteringRow, PlaneDisposition, UsageLedger, VirtualKey,
    },
    redacted::Kernel,
    Secret,
};

/// Source-page family carrying version-one interpreted historical facts.
pub const INTERPRETED_SOURCE: Id = *b"busbar.source.v1";

/// Logical document semantics established by the native historical reader.
/// Physical versions do not establish a product release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentSemantics {
    /// Historical root grammar and its explicitly supported normalization rules.
    Historical,
    /// The source has current document semantics; no historical defaults inferred.
    Current,
}

/// A supported, typed logical source codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCodec {
    /// Bounded historical facts and their complete original-byte evidence.
    HistoricalV1,
}

/// Mandatory declaration for a native source that promises historical support.
/// Private fields prevent construction of an invalid or absent decoder identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceReader {
    codec: SourceCodec,
    documents: DocumentSemantics,
    decoder_digest: Digest,
}
impl SourceReader {
    /// Bind a compiled reader's exact semantics to the typed source codec.
    pub fn new(
        codec: SourceCodec,
        documents: DocumentSemantics,
        decoder_digest: Digest,
    ) -> Result<Self, Error> {
        if decoder_digest == [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            codec,
            documents,
            decoder_digest,
        })
    }
    /// Exact neutral codec accepted by this reader.
    pub fn codec(self) -> SourceCodec {
        self.codec
    }
    /// Document grammar established by the owner, without naming a product release.
    pub fn documents(self) -> DocumentSemantics {
        self.documents
    }
    /// Exact compiled reader semantics; changing it cannot resume an old route.
    pub fn decoder_digest(self) -> Digest {
        self.decoder_digest
    }
}

/// Separate explicit limits for streaming output and retained group/index work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterpretationBounds {
    /// Maximum owned working bytes while interpreting one complete logical group.
    pub semantic_bytes: u32,
    /// Maximum retained source/group index metadata bytes.
    pub index_bytes: u32,
    /// Maximum cumulative bytes in owner-private derived source storage.
    pub storage_bytes: u64,
}
impl InterpretationBounds {
    /// Both budgets must be explicit and nonzero.
    pub fn validate(self) -> Result<(), Error> {
        if self.semantic_bytes == 0 || self.index_bytes == 0 || self.storage_bytes == 0 {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }
}

/// Logical migration domains. Physical tables, keys and indexes never select these in core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalFamily {
    /// Keys, credentials, denials and the revision allocator.
    Identity,
    /// Usage and metering quantities and their verification observations.
    Accounting,
    /// Opaque records, history, tokens and original operation evidence.
    Archival,
    /// Original audit records.
    Audit,
    /// Recognized native bookkeeping retained without a target effect.
    Evidence,
}

/// How a physical accounting observation participates in a logical result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingRole {
    /// A contributing fragment, including sparse open-unit fragments.
    Fragment,
    /// The exact logical quantity; companion observations are only verification evidence.
    Exact,
    /// A saturated signed-integer projection of a companion exact quantity.
    Signed64Projection,
    /// An exact quantity requiring its complete signed-integer projection observations.
    ExactWithSigned64Projection,
}

/// The request-counter relationship declared by the source owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAggregation {
    /// A single dedicated counter cell; other model cells contain zero counters.
    Dedicated,
    /// Every model cell contributes to the request totals.
    Sum,
}

/// Historical meaning supplied by the native owner, without target-write authority.
/// Protected payloads remain in wiping ownership and have no Debug implementation.
#[allow(missing_docs)] // Variant fields retain the corresponding records DTO meanings.
pub enum HistoricalFact<O = Kernel> {
    Key {
        value: VirtualKey,
        updated_at: Option<u64>,
    },
    Credential {
        meta: CredentialMeta,
        envelope: Secret<Vec<u8>, O>,
    },
    Denial {
        subject: String,
        reason: String,
        created_at: u64,
    },
    Revision(u64),
    Usage {
        bucket: String,
        window: u64,
        model: String,
        requests: RequestAggregation,
        ledger: UsageLedger,
        role: AccountingRole,
    },
    UsageUnit {
        bucket: String,
        window: u64,
        model: String,
        unit: String,
        count: i128,
        role: AccountingRole,
    },
    Metering {
        bucket: u64,
        row: MeteringRow,
        role: AccountingRole,
    },
    MeteringUnit {
        bucket: u64,
        key_id: String,
        provider: String,
        model: String,
        priced_from_ms: u64,
        key_group_at_use: Option<String>,
        pricing_version: Option<String>,
        unit: String,
        count: i128,
        role: AccountingRole,
    },
    Audit(AuditRecord),
    Record {
        schema: String,
        key: Secret<Vec<u8>, O>,
        value: Secret<Vec<u8>, O>,
    },
    History {
        kind: String,
        id: String,
        parent: Option<String>,
        sequence: u64,
        timestamp: u64,
        disposition: PlaneDisposition,
        body: Secret<Vec<u8>, O>,
        append: Option<bool>,
    },
    Token {
        kind: String,
        token: Secret<Vec<u8>, O>,
        expires_at: u64,
    },
    Receipt {
        operation: Id,
        body: Secret<Vec<u8>, O>,
        answer: Secret<Vec<u8>, O>,
        recorded_at: Option<u64>,
        expires_at_ms: Option<i64>,
        historical_digest: Option<Digest>,
        completed_shape: bool,
    },
    /// Known native bookkeeping with no logical target effect; its original bytes remain evidence.
    EvidenceOnly,
}

/// One exact physical preimage referenced by an interpreted logical group.
pub struct SourceEvidence<O = Kernel> {
    /// Original physical catalogue ordinal.
    pub table: u32,
    /// Untouched original native key frame.
    pub native_key: Secret<Vec<u8>, O>,
    /// SHA256 of the complete untouched physical row bytes.
    pub value_digest: Digest,
}

/// One bounded chunk of a complete logical source group.
/// A group is publishable only after its final chunk and complete original-byte coverage.
pub struct SourceChunk<O = Kernel> {
    /// Exact reader declaration admitted before native enforcement.
    pub reader: SourceReader,
    /// Logical domain of every fact in this group.
    pub family: HistoricalFamily,
    /// Stable protected logical group identity.
    pub group: Secret<Vec<u8>, O>,
    /// Zero-based contiguous chunk ordinal within this group.
    pub sequence: u64,
    /// This is the final chunk of the group.
    pub complete: bool,
    /// Original rows consumed by this group, with no repetition across groups.
    pub evidence: Vec<SourceEvidence<O>>,
    /// Interpreted logical facts; no candidate or mutation authority.
    pub facts: Vec<HistoricalFact<O>>,
}

impl<O> HistoricalFact<O> {
    /// The logical domain of this fact, independent of any physical layout.
    pub fn family(&self) -> HistoricalFamily {
        match self {
            Self::Key { .. }
            | Self::Credential { .. }
            | Self::Denial { .. }
            | Self::Revision(_) => HistoricalFamily::Identity,
            Self::Usage { .. }
            | Self::UsageUnit { .. }
            | Self::Metering { .. }
            | Self::MeteringUnit { .. } => HistoricalFamily::Accounting,
            Self::Audit(_) => HistoricalFamily::Audit,
            Self::Record { .. }
            | Self::History { .. }
            | Self::Token { .. }
            | Self::Receipt { .. } => HistoricalFamily::Archival,
            Self::EvidenceOnly => HistoricalFamily::Evidence,
        }
    }
}
impl<O> std::fmt::Debug for HistoricalFact<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricalFact")
            .field("family", &self.family())
            .finish_non_exhaustive()
    }
}
impl<O> std::fmt::Debug for SourceEvidence<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceEvidence")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}
impl<O> std::fmt::Debug for SourceChunk<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceChunk")
            .field("family", &self.family)
            .field("sequence", &self.sequence)
            .field("complete", &self.complete)
            .field("facts", &self.facts.len())
            .field("evidence", &self.evidence.len())
            .finish_non_exhaustive()
    }
}
