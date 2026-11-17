// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 part B §B3.1, §B10.3: the exported audit tail a declaration carries, one chain per node.
//!
//! Canonical encoding: `"BSRT1\0\0\0" ‖ u32 BE node_count ‖` per node in strictly ascending `node`:
//! `node u64 BE ‖ u32 BE record_count ‖` per record in strictly ascending `node_seq`:
//! `u32 BE length ‖` the record's exact journal bytes. Any other order, a duplicate, an empty chain, a
//! record of another node, non-canonical record bytes or trailing bytes is `tail_encoding_invalid`.
//! The digest is `sha256("busbar.restore.tail.v1\0" ‖ canonical bytes)`, so it does not depend on how
//! an upload was chunked.

use std::collections::BTreeMap;

use busbar_kernel_audit::linked_record::{linked_record_from_journal_body, AuditLinkedRecord};
use busbar_kernel_audit::linked_walk::{
    self, Evidence, LinkedRange, Read, SealRow, TrustedHead, Verdict, WalkedLine,
};
use busbar_kernel_audit::{
    break_from_journal_body, notary_key_from_journal_body, stamp_from_journal_body, AuditChain,
    AuditVerifyingKey, BreakNotice, Fingerprint, NotaryKeyRecord, Stamp, NOTARY_KEY_RECORD_DOMAIN,
};
use busbar_kernel_wal::journal::{JournalRecord, RecordClass};

/// The encoding's magic.
pub const MAGIC: &[u8; 8] = b"BSRT1\0\0\0";
/// The largest tail one declaration takes (§B10.3); beyond it `restore_tail_too_large` (413).
pub const MAX_RESTORE_TAIL_BYTES: usize = 256 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"busbar.restore.tail.v1\0";

/// One node's exported chain, oldest record first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChain {
    /// The journal `NODE` every record carries.
    pub node: u64,
    /// The records, in strictly ascending `node_seq`.
    pub records: Vec<JournalRecord>,
}

/// The tail: one chain per node, in strictly ascending `node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tail {
    /// The per-node chains.
    pub chains: Vec<NodeChain>,
}

/// Why a tail does not decode (the `reason` of the refusal, §B10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailError {
    /// Over [`MAX_RESTORE_TAIL_BYTES`]: 413 `restore_tail_too_large`.
    TooLarge,
    /// Not the canonical encoding: 422 `tail_encoding_invalid`.
    Encoding,
}

impl TailError {
    /// The refusal's reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "restore_tail_too_large",
            Self::Encoding => "tail_encoding_invalid",
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TailError> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or(TailError::Encoding)?;
        self.bytes = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, TailError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| TailError::Encoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, TailError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| TailError::Encoding)?,
        ))
    }
}

/// Decode a canonical tail.
pub fn decode(bytes: &[u8]) -> Result<Tail, TailError> {
    if bytes.len() > MAX_RESTORE_TAIL_BYTES {
        return Err(TailError::TooLarge);
    }
    let mut reader = Reader { bytes };
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(TailError::Encoding);
    }
    let node_count = reader.u32()?;
    let mut chains: Vec<NodeChain> = Vec::new();
    for _ in 0..node_count {
        let node = reader.u64()?;
        if chains.last().is_some_and(|last| last.node >= node) {
            return Err(TailError::Encoding);
        }
        let record_count = reader.u32()?;
        if record_count == 0 {
            return Err(TailError::Encoding);
        }
        let mut records: Vec<JournalRecord> = Vec::new();
        for _ in 0..record_count {
            let length = usize::try_from(reader.u32()?).map_err(|_| TailError::Encoding)?;
            let raw = reader.take(length)?;
            let record = JournalRecord::decode(raw).map_err(|_| TailError::Encoding)?;
            if record.node != node
                || record.encode() != raw
                || records
                    .last()
                    .is_some_and(|last| last.node_seq >= record.node_seq)
            {
                return Err(TailError::Encoding);
            }
            records.push(record);
        }
        chains.push(NodeChain { node, records });
    }
    if !reader.bytes.is_empty() {
        return Err(TailError::Encoding);
    }
    Ok(Tail { chains })
}

/// The canonical encoding of `tail`.
#[must_use]
pub fn encode(tail: &Tail) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(tail.chains.len() as u32).to_be_bytes());
    for chain in &tail.chains {
        out.extend_from_slice(&chain.node.to_be_bytes());
        out.extend_from_slice(&(chain.records.len() as u32).to_be_bytes());
        for record in &chain.records {
            let raw = record.encode();
            out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            out.extend_from_slice(&raw);
        }
    }
    out
}

/// The tail digest over its canonical bytes.
#[must_use]
pub fn digest(canonical: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(DIGEST_DOMAIN.len() + canonical.len());
    data.extend_from_slice(DIGEST_DOMAIN);
    data.extend_from_slice(canonical);
    busbar_contract::abi::sdk::digest::sha256(&data)
}

/// Why a decoded tail does not verify (§B3.1, §B10.2): each a 422 reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// `tail_chain_broken`: the node's chain does not continue from its restored head (or, for a node born
    /// after the backup, from genesis), or does not link record to record.
    ChainBroken {
        /// The node whose chain breaks.
        node: u64,
    },
    /// `tail_seal_invalid`: an audit line, stamp, break notice or notary certificate of the node's
    /// chain does not decode or does not verify under the deployment Bootstrap key.
    SealInvalid {
        /// The node whose chain carries it.
        node: u64,
        /// The audit verifier's refusal.
        why: &'static str,
    },
    /// `tail_unsealed_end`: the node's audit chain in the tail does not end at a line a verified
    /// stamp covers.
    UnsealedEnd {
        /// The node whose chain ends unsealed.
        node: u64,
    },
    /// `tail_missing_chain`: a node of the witness has no chain in the tail, or its chain stops
    /// short of the witnessed position.
    MissingChain {
        /// The witnessed node.
        node: u64,
    },
}

impl VerifyError {
    /// The refusal's reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::ChainBroken { .. } => "tail_chain_broken",
            Self::SealInvalid { .. } => "tail_seal_invalid",
            Self::UnsealedEnd { .. } => "tail_unsealed_end",
            Self::MissingChain { .. } => "tail_missing_chain",
        }
    }

    /// The node the refusal names.
    #[must_use]
    pub fn node(self) -> u64 {
        match self {
            Self::ChainBroken { node }
            | Self::SealInvalid { node, .. }
            | Self::UnsealedEnd { node }
            | Self::MissingChain { node } => node,
        }
    }
}

/// Continuity (§B3.1): every chain continues from `heads[node]`, the node's head in the restored Store
/// as `(node_seq, hash)`, or from genesis (`node_seq` 1, a zero predecessor) for a node with no head
/// there (born after the backup), and links record to record by the journal's own rules (a
/// quarantine `ChainBreak`'s named hole included).
pub fn verify_continuity(
    tail: &Tail,
    heads: &std::collections::BTreeMap<u64, (u64, [u8; 32])>,
) -> Result<(), VerifyError> {
    for chain in &tail.chains {
        let broken = VerifyError::ChainBroken { node: chain.node };
        let first = chain.records.first().ok_or(broken)?;
        let (sequence, hash) = heads.get(&chain.node).copied().unwrap_or((0, [0u8; 32]));
        if sequence.checked_add(1) != Some(first.node_seq) || first.prev_hash != hash {
            return Err(broken);
        }
        busbar_kernel_wal::journal::verify(&chain.records).map_err(|_| broken)?;
    }
    Ok(())
}

/// The restored Store's head of each node in `nodes` (absent for a node with no records there), read
/// from each node's journal head row.
pub async fn restored_heads(
    core: &super::facade::CoreStore,
    nodes: impl IntoIterator<Item = u64>,
) -> Result<std::collections::BTreeMap<u64, (u64, [u8; 32])>, String> {
    let mut heads = std::collections::BTreeMap::new();
    for node in nodes {
        let journal = super::journal::StoreJournal::new(core, node)
            .map_err(|error| format!("node {node}: {error:?}"))?;
        if let Some(head) = journal
            .selected_head()
            .await
            .map_err(|error| format!("node {node}: {error:?}"))?
        {
            heads.insert(node, head);
        }
    }
    Ok(heads)
}

/// ONE AUDIT CHAIN LINE OF THE TAIL: a unit line or a notary certificate line, decoded from its
/// journal body by the existing decoder, with the WAL `node_seq` of the record that carries it.
#[derive(Debug, Clone)]
struct TailLine {
    at: u64,
    line: AuditLinkedRecord,
    prev: String,
    hash: String,
}

impl TailLine {
    fn new(at: u64, line: AuditLinkedRecord) -> Self {
        let (prev, hash) = match &line {
            AuditLinkedRecord::Unit(record) => (record.prev_hash.clone(), record.hash.clone()),
            // As the range read prints a certificate line: the genesis predecessor is empty.
            AuditLinkedRecord::NotaryKey(record) => (
                if record.prev_link == Fingerprint::ZERO {
                    String::new()
                } else {
                    record.prev_link.to_string()
                },
                record.fingerprint.to_string(),
            ),
        };
        Self {
            at,
            line,
            prev,
            hash,
        }
    }
}

impl WalkedLine for TailLine {
    fn seq(&self) -> Read<u64> {
        Ok(self.line.chain_seq())
    }
    fn node(&self) -> Read<u64> {
        Ok(self.line.node())
    }
    fn prev_hash(&self) -> Read<&str> {
        Ok(&self.prev)
    }
    fn hash(&self) -> Read<&str> {
        Ok(&self.hash)
    }
    fn recipe(&self) -> Read<&str> {
        Ok(match &self.line {
            AuditLinkedRecord::Unit(record) => record.recipe.name(),
            AuditLinkedRecord::NotaryKey(_) => NOTARY_KEY_RECORD_DOMAIN,
        })
    }
    fn certificate(&self) -> Read<(u64, NotaryKeyRecord)> {
        match &self.line {
            AuditLinkedRecord::NotaryKey(record) => Ok((self.at, (**record).clone())),
            AuditLinkedRecord::Unit(_) => Err("a certificate line names another recipe"),
        }
    }
    fn digest(&self) -> Read<String> {
        match &self.line {
            AuditLinkedRecord::Unit(record) => Ok(AuditChain::digest_of(record)),
            AuditLinkedRecord::NotaryKey(record) => Ok(record.recompute_fingerprint().to_string()),
        }
    }
    fn signature(&self) -> Read<&str> {
        match &self.line {
            AuditLinkedRecord::Unit(record) => record
                .signature
                .as_deref()
                .ok_or("a required text member is absent or is not a string"),
            AuditLinkedRecord::NotaryKey(_) => Err("a certificate line carries no line signature"),
        }
    }
    fn key_id(&self) -> Read<&str> {
        match &self.line {
            AuditLinkedRecord::Unit(record) => record
                .key_id
                .as_deref()
                .ok_or("a required text member is absent or is not a string"),
            AuditLinkedRecord::NotaryKey(_) => Err("a certificate line carries no line signature"),
        }
    }
}

/// A page stamp, with the WAL `node_seq` it was read at, or a break notice, from the tail.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TailEvidence {
    Page(u64, Stamp),
    Break(BreakNotice),
}

impl Evidence for TailEvidence {
    fn is_break(&self) -> Read<bool> {
        Ok(matches!(self, Self::Break(_)))
    }
    fn notice(&self) -> Read<BreakNotice> {
        match self {
            Self::Break(notice) => Ok(notice.clone()),
            Self::Page(..) => Err("invalid break reason"),
        }
    }
    fn node_seq(&self) -> Read<Option<u64>> {
        Ok(match self {
            Self::Page(at, _) => Some(*at),
            Self::Break(_) => None,
        })
    }
    fn stamp(&self) -> Read<Stamp> {
        match self {
            Self::Page(_, stamp) => Ok(stamp.clone()),
            Self::Break(_) => Err("invalid stamp kind"),
        }
    }
}

/// ONE NODE'S AUDIT WINDOW IN THE TAIL: its audit lines (non-empty, in chain order), its stamps and
/// breaks in journal order, and the node's certificates read from the restored Store, which a stamp
/// in the tail may name. The tail carries no cover, no seal row and no anchor.
struct NodeWindow {
    lines: Vec<TailLine>,
    evidence: Vec<TailEvidence>,
    certs: Vec<TailLine>,
}

impl LinkedRange for NodeWindow {
    type Line = TailLine;
    type Evidence = TailEvidence;

    fn from(&self) -> Read<u64> {
        self.lines
            .first()
            .map(|line| line.line.chain_seq())
            .ok_or("records are absent")
    }
    fn to(&self) -> Read<u64> {
        self.lines
            .last()
            .map(|line| line.line.chain_seq())
            .ok_or("records are absent")
    }
    fn records(&self) -> Read<Vec<TailLine>> {
        Ok(self.lines.clone())
    }
    fn cover(&self) -> Read<Vec<TailLine>> {
        Ok(Vec::new())
    }
    fn certs(&self) -> Read<Option<Vec<TailLine>>> {
        Ok(Some(self.certs.clone()))
    }
    fn stamps(&self) -> Read<Vec<TailEvidence>> {
        Ok(self.evidence.clone())
    }
    fn seal_row(&self) -> Read<Option<SealRow>> {
        Ok(None)
    }
    fn anchor(&self) -> Read<Option<TailEvidence>> {
        Ok(None)
    }
}

/// A restore tail has no independently retained head: completeness comes from the witness (§B6).
enum NoHead {}

impl TrustedHead for NoHead {
    fn recipe(&self) -> Read<&str> {
        match *self {}
    }
    fn head(&self) -> Read<Stamp> {
        match *self {}
    }
    fn next_seq(&self) -> Read<u64> {
        match *self {}
    }
}

/// Sort one chain's journal records into its audit lines and its stamps and breaks. Only
/// `Transaction` records carry them; a body that names an audit tag and does not decode refuses
/// the tail.
fn window(chain: &NodeChain, certs: Vec<TailLine>) -> Result<NodeWindow, VerifyError> {
    let invalid = |why| VerifyError::SealInvalid {
        node: chain.node,
        why,
    };
    let mut lines = Vec::new();
    let mut evidence = Vec::new();
    for record in &chain.records {
        if record.class != RecordClass::Transaction {
            continue;
        }
        let meter_class = crate::Registration::meter_class;
        if let Some(line) = linked_record_from_journal_body(&record.body, &meter_class)
            .map_err(|_| invalid("an audit line does not decode"))?
        {
            lines.push(TailLine::new(record.node_seq, line));
        } else if let Some(stamp) =
            stamp_from_journal_body(&record.body).map_err(|_| invalid("a stamp does not decode"))?
        {
            evidence.push(TailEvidence::Page(record.node_seq, stamp));
        } else if let Some(notice) = break_from_journal_body(&record.body)
            .map_err(|_| invalid("a break notice does not decode"))?
        {
            evidence.push(TailEvidence::Break(notice));
        }
    }
    Ok(NodeWindow {
        lines,
        evidence,
        certs,
    })
}

/// The node certificates the restored Store holds, by node, each with its WAL `node_seq`: a stamp
/// in the tail may name a certificate written before the backup.
pub type RestoredCerts = BTreeMap<u64, Vec<(u64, NotaryKeyRecord)>>;

/// THE SEALS (§B3.1): every node's audit lines in the tail pass the audit verifier's linked-window
/// rules ([`busbar_kernel_audit::linked_walk`]) under the one deployment Bootstrap key, notary
/// certificate v2 included, and end at a line a verified stamp covers. Returns each node's verdict
/// (nodes whose tail carries no audit line have none).
pub fn verify_seals(
    tail: &Tail,
    bootstrap: &AuditVerifyingKey,
    restored: &RestoredCerts,
) -> Result<BTreeMap<u64, Verdict>, VerifyError> {
    let keys = BTreeMap::from([(bootstrap.key_id().to_owned(), bootstrap.clone())]);
    let mut verdicts = BTreeMap::new();
    for chain in &tail.chains {
        let certs = restored
            .get(&chain.node)
            .into_iter()
            .flatten()
            .map(|(at, cert)| {
                TailLine::new(*at, AuditLinkedRecord::NotaryKey(Box::new(cert.clone())))
            })
            .collect();
        let window = window(chain, certs)?;
        if window.lines.is_empty() {
            continue;
        }
        let verdict = linked_walk::verify::<_, NoHead>(&keys, &window, None).map_err(|why| {
            VerifyError::SealInvalid {
                node: chain.node,
                why,
            }
        })?;
        if verdict.last_sealed < verdict.to {
            return Err(VerifyError::UnsealedEnd { node: chain.node });
        }
        verdicts.insert(chain.node, verdict);
    }
    Ok(verdicts)
}

/// One entry of the store-side witness's per-node vector (§B6, option S): the newest
/// `(node_seq, chain head hash)` the witness saw for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessEntry {
    /// The journal `NODE`.
    pub node: u64,
    /// The node's witnessed `node_seq`.
    pub node_seq: u64,
    /// The record hash at that position.
    pub hash: [u8; 32],
}

/// REACH (§B3.1): the tail reaches every entry of the witness. An entry the restored head already
/// covers needs nothing; otherwise the node's chain must be in the tail (`tail_missing_chain`) and
/// carry the witnessed position (`tail_missing_chain` when it stops short) with the witnessed hash
/// (`tail_chain_broken` when it differs: another history).
pub fn verify_reach(
    tail: &Tail,
    heads: &BTreeMap<u64, (u64, [u8; 32])>,
    witness: &[WitnessEntry],
) -> Result<(), VerifyError> {
    for entry in witness {
        if heads
            .get(&entry.node)
            .is_some_and(|(sequence, _)| *sequence >= entry.node_seq)
        {
            continue;
        }
        let missing = VerifyError::MissingChain { node: entry.node };
        let chain = tail
            .chains
            .iter()
            .find(|chain| chain.node == entry.node)
            .ok_or(missing)?;
        let record = chain
            .records
            .iter()
            .find(|record| record.node_seq == entry.node_seq)
            .ok_or(missing)?;
        if record.hash != entry.hash {
            return Err(VerifyError::ChainBroken { node: entry.node });
        }
    }
    Ok(())
}

/// One node's bridge (§B7): its restored head (`None` for a node born after the backup) and the
/// head its tail reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bridge {
    /// The journal `NODE`.
    pub node: u64,
    /// The restored head `(node_seq, hash)`.
    pub restored: Option<(u64, [u8; 32])>,
    /// The tail's last record `(node_seq, hash)`.
    pub pre_restore: (u64, [u8; 32]),
}

/// A verified tail (§B3.1, §B10.3): its digest, the nodes it covers and their bridges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTail {
    /// `tail_digest` over the canonical bytes.
    pub tail_digest: [u8; 32],
    /// Every node whose chain the tail contains, ascending.
    pub covered_nodes: Vec<u64>,
    /// One bridge per covered node.
    pub bridges: Vec<Bridge>,
    /// The decoded tail.
    pub tail: Tail,
}

/// Why a tail is refused: its encoding, or a §B3.1 check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes are not a canonical tail, or too large.
    Decode(TailError),
    /// A chain fails a check.
    Verify(VerifyError),
}

impl Refusal {
    /// The refusal's reason (§B10.2).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Decode(error) => error.reason(),
            Self::Verify(error) => error.reason(),
        }
    }
}

/// EVERY §B3.1 CHECK of a canonical tail against the restored Store's heads and certificates and
/// the witness, in order: the encoding, per-node continuity, the seals and the reach. The
/// declaration and its `verify` dry run both run exactly this; it commits nothing.
pub fn verify_tail(
    canonical: &[u8],
    heads: &BTreeMap<u64, (u64, [u8; 32])>,
    restored: &RestoredCerts,
    witness: &[WitnessEntry],
    bootstrap: &AuditVerifyingKey,
) -> Result<VerifiedTail, Refusal> {
    let tail = decode(canonical).map_err(Refusal::Decode)?;
    verify_continuity(&tail, heads).map_err(Refusal::Verify)?;
    verify_seals(&tail, bootstrap, restored).map_err(Refusal::Verify)?;
    verify_reach(&tail, heads, witness).map_err(Refusal::Verify)?;
    let mut bridges = Vec::new();
    for chain in &tail.chains {
        let last = chain
            .records
            .last()
            .ok_or(Refusal::Decode(TailError::Encoding))?;
        bridges.push(Bridge {
            node: chain.node,
            restored: heads.get(&chain.node).copied(),
            pre_restore: (last.node_seq, last.hash),
        });
    }
    Ok(VerifiedTail {
        tail_digest: digest(canonical),
        covered_nodes: tail.chains.iter().map(|chain| chain.node).collect(),
        bridges,
        tail,
    })
}

/// The notary certificates the restored Store holds for each of `nodes` (none for a node with no
/// records there), read by walking each node's verified journal.
pub async fn restored_certificates(
    core: &super::facade::CoreStore,
    nodes: impl IntoIterator<Item = u64>,
) -> Result<RestoredCerts, String> {
    let mut certs = BTreeMap::new();
    for node in nodes {
        let journal = super::journal::StoreJournal::new(core, node)
            .map_err(|error| format!("node {node}: {error:?}"))?;
        if journal
            .selected_head()
            .await
            .map_err(|error| format!("node {node}: {error:?}"))?
            .is_none()
        {
            continue;
        }
        let (found, _) = journal
            .walk(
                Vec::new,
                |found: &mut Vec<(u64, NotaryKeyRecord)>, row, _kept| {
                    let record = JournalRecord::decode(&row.body)
                        .map_err(|_| super::journal::Error::Corrupt)?;
                    if record.class == RecordClass::Transaction {
                        if let Some(cert) = notary_key_from_journal_body(&record.body)
                            .map_err(|_| super::journal::Error::Corrupt)?
                        {
                            found.push((record.node_seq, cert));
                        }
                    }
                    Ok(())
                },
            )
            .await
            .map_err(|error| format!("node {node}: {error:?}"))?;
        certs.insert(node, found);
    }
    Ok(certs)
}

/// The largest chunk one `PUT /store-restore/tail/{tail_digest}/{index}` takes (§B10.3).
pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Why a chunk or an assembled upload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadError {
    /// A chunk over [`MAX_CHUNK_BYTES`], or uploads over [`MAX_RESTORE_TAIL_BYTES`] in total: 413
    /// `restore_tail_too_large`.
    TooLarge,
    /// A chunk out of order (each upload starts at index 0 and goes up by one): 422
    /// `tail_encoding_invalid`.
    OutOfOrder,
    /// The assembled chunks do not hash to the named digest, or nothing was uploaded under it: 422
    /// `tail_digest_mismatch`.
    DigestMismatch,
}

impl UploadError {
    /// The refusal's reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "restore_tail_too_large",
            Self::OutOfOrder => "tail_encoding_invalid",
            Self::DigestMismatch => "tail_digest_mismatch",
        }
    }
}

struct Upload {
    next: u64,
    bytes: Vec<u8>,
}

/// THE CHUNKED TAIL UPLOADS (§B10.3), in this process's memory only (no Store write, no file),
/// keyed by the declared `tail_digest`, bounded in total by [`MAX_RESTORE_TAIL_BYTES`]. An upload
/// is dropped when it is taken (the declaration), on a digest mismatch, and with the process.
#[derive(Default)]
pub struct TailUploads {
    uploads: std::sync::Mutex<BTreeMap<[u8; 32], Upload>>,
}

impl TailUploads {
    /// Accept chunk `index` of the upload named `tail_digest`. Index 0 starts (or restarts) it.
    pub fn put(&self, tail_digest: [u8; 32], index: u64, chunk: &[u8]) -> Result<(), UploadError> {
        if chunk.len() > MAX_CHUNK_BYTES {
            return Err(UploadError::TooLarge);
        }
        let mut uploads = self
            .uploads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if index == 0 {
            uploads.remove(&tail_digest);
        }
        let held: usize = uploads.values().map(|upload| upload.bytes.len()).sum();
        if held.saturating_add(chunk.len()) > MAX_RESTORE_TAIL_BYTES {
            return Err(UploadError::TooLarge);
        }
        let upload = uploads.entry(tail_digest).or_insert(Upload {
            next: 0,
            bytes: Vec::new(),
        });
        if upload.next != index {
            return Err(UploadError::OutOfOrder);
        }
        upload.bytes.extend_from_slice(chunk);
        upload.next = index.saturating_add(1);
        Ok(())
    }

    /// The assembled canonical bytes of the upload named `tail_digest`, dropping it. Bytes that do
    /// not hash to `tail_digest` are refused (and dropped).
    pub fn take(&self, tail_digest: [u8; 32]) -> Result<Vec<u8>, UploadError> {
        let upload = self
            .uploads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&tail_digest)
            .ok_or(UploadError::DigestMismatch)?;
        if digest(&upload.bytes) != tail_digest {
            return Err(UploadError::DigestMismatch);
        }
        Ok(upload.bytes)
    }
}

#[cfg(test)]
#[path = "tests/restore_tail_tests.rs"]
mod tests;
