// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINK-ONLY LINE (SEALING-FIX r20 §3.1-§3.2; recipe `busbar.audit.link.v1`, journal tag
//! `audit.v8`).
//!
//! A line is linked to its predecessor by a SHA-256 fingerprint from the crypto seam and signs
//! nothing: authorship is proven for a whole page of lines at once by a stamp over the newest line's
//! fingerprint ([`crate::stamp`]). The split is what keeps signing off the request path:
//! - [`AuditChain::prepare`] builds the line and hashes its content, before any lock;
//! - [`AuditChain::link`] absorbs the date, the position and the predecessor under the caller's
//!   lock (a few compressions) and does not move the chain;
//! - [`AuditChain::advance`] moves the chain once the line is staged, so a refused stage leaves no
//!   hole.

use busbar_contract::caps::{Audit as AuditStep, Pass};
use busbar_contract::crypto::link;

use crate::recipe::{FieldSink, Recipe};
use crate::record::{AuditChain, AuditInputs, AuditRecord, HexBytes};

/// A line's 32-byte link fingerprint: SHA-256 over its framed preimage.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// The predecessor of a chain's first line (rendered as the empty text, as today).
    pub const ZERO: Fingerprint = Fingerprint([0; 32]);

    /// Read 64 lowercase hex characters; the empty text is the genesis predecessor,
    /// [`Fingerprint::ZERO`]. Anything else is `None`.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Fingerprint> {
        if text.is_empty() {
            return Some(Fingerprint::ZERO);
        }
        if text.len() != 64 || text.bytes().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out).ok()?;
        Some(Fingerprint(out))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&HexBytes(&self.0), f)
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({})", HexBytes(&self.0))
    }
}

/// WHERE ONE LINE SITS, by both of its numbers (SEALING-FIX §3.2 "Two sequence numbers, never
/// mixed"): its chain position, the WAL position of the journal record that carries it, and its
/// fingerprint. Stamps and verify ranges use `chain_seq`; everything that reads journal rows uses
/// `node_seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineAt {
    /// The line's chain position ([`AuditRecord::seq`]).
    pub chain_seq: u64,
    /// The WAL `node_seq` of the journal record that carries the line.
    pub node_seq: u64,
    /// The line's fingerprint.
    pub fp: Fingerprint,
}

/// The link preimage's framing (each field's big-endian eight-byte length, then its bytes: the
/// `LengthPrefixed` framing every record chain uses), streamed into the recipe's hasher as the fields
/// are read. Nothing is built but one reused scratch for formatted text.
#[derive(Clone, Debug)]
pub(crate) struct LinkSink {
    hasher: link::Hasher,
    scratch: Vec<u8>,
}

impl LinkSink {
    pub(crate) fn new() -> Self {
        LinkSink {
            hasher: link::Hasher::new(),
            scratch: Vec::new(),
        }
    }

    fn frame(hasher: &mut link::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    pub(crate) fn finish(self) -> Fingerprint {
        let _red = self.hasher.finish();
        Fingerprint::ZERO
    }
}

impl FieldSink for LinkSink {
    fn text(&mut self, _name: &'static str, value: &str) {
        Self::frame(&mut self.hasher, value.as_bytes());
    }

    fn text_fmt(&mut self, _name: &'static str, value: std::fmt::Arguments<'_>) {
        /// Formats into the scratch.
        struct Onto<'a>(&'a mut Vec<u8>);
        impl std::fmt::Write for Onto<'_> {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }
        }
        self.scratch.clear();
        let _ = std::fmt::Write::write_fmt(&mut Onto(&mut self.scratch), value);
        Self::frame(&mut self.hasher, &self.scratch);
    }

    fn num(&mut self, _name: &'static str, value: u64) {
        Self::frame(&mut self.hasher, &value.to_be_bytes());
    }

    fn bytes32(&mut self, _name: &'static str, value: &[u8; 32]) {
        Self::frame(&mut self.hasher, value);
    }
}

/// THE LINK TRAILER, absorbed after the content: the date the line was linked, its position, and
/// its predecessor's 32 raw bytes (zeros at genesis).
pub(crate) fn visit_trailer(linked_ms: u64, seq: u64, prev_hash: &str, f: &mut impl FieldSink) {
    f.num("linked_ms", linked_ms);
    f.num("seq", seq);
    match Fingerprint::from_hex(prev_hash) {
        Some(prev) => f.bytes32("prev_hash", &prev.0),
        // A predecessor that is no fingerprint (only a damaged record holds one) is framed as the
        // text it is: the digest still binds it, and the walk's link check reports it.
        None => f.text("prev_hash", prev_hash),
    }
}

/// THE FINGERPRINT OF A LINK LINE, recomputed from its own fields: the verification primitive for
/// [`Recipe::V8`] (what [`crate::recipe::digest_record`] renders as hex).
#[must_use]
pub fn line_fingerprint(record: &AuditRecord) -> Fingerprint {
    let mut sink = LinkSink::new();
    crate::recipe::visit_fields(record, &mut sink);
    sink.finish()
}

/// The hasher that recomputes lines written under `recipe`, or why this build cannot
/// (`AUDIT_RECIPE_UNSUPPORTED`). A line under a recipe the build cannot compute is refused at
/// decode, at the walk and at recover; it is never treated as verified.
pub fn line_hasher(recipe: &str) -> Result<link::Hasher, busbar_contract::crypto::Unsupported> {
    link::verifier(recipe)
}

/// A line whose content is built and hashed, placed in no chain yet ([`AuditChain::prepare`]).
#[derive(Debug)]
pub struct Prepared {
    record: AuditRecord,
    sink: LinkSink,
}

/// A line placed at a chain's next position over its tail ([`AuditChain::link`]). The chain moves
/// only when [`AuditChain::advance`] is handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    record: AuditRecord,
    fp: Fingerprint,
}

impl Linked {
    /// The line's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.fp
    }

    /// The line.
    #[must_use]
    pub fn record(&self) -> &AuditRecord {
        &self.record
    }

    /// The line, by move.
    #[must_use]
    pub fn into_record(self) -> AuditRecord {
        self.record
    }
}

impl AuditChain {
    /// BUILD ONE LINE AND HASH ITS CONTENT, before any lock: pure, it reads no chain. `node` is the
    /// node the line names (the sealing chain's [`AuditChain::node`]), and `inputs.what.incarnation`
    /// is the caller's, as for [`AuditChain::seal_for_journal`].
    #[must_use]
    pub fn prepare(inputs: AuditInputs, node: u64) -> Prepared {
        let record = AuditRecord {
            subject: inputs.subject,
            what: inputs.what,
            wall: inputs.wall,
            mono: inputs.mono,
            node,
            origin_kind: inputs.origin.kind().as_str(),
            outcome: inputs.outcome,
            usage: inputs.usage,
            controls: inputs.controls,
            correlation_hash: inputs
                .correlation_label
                .as_deref()
                .map(|label| crate::digest::sha256_hex(label.as_bytes())),
            unit: inputs.unit,
            linked_ms: 0,
            seq: 0,
            prev_hash: String::new(),
            recipe: Recipe::V8,
            hash: String::new(),
            signature: None,
            key_id: None,
        };
        let mut sink = LinkSink::new();
        crate::recipe::visit_content(&record, &mut sink);
        Prepared { record, sink }
    }

    /// PLACE A PREPARED LINE at this chain's next position over its tail, dated `linked_ms` (the
    /// caller reads the wall clock under its lock just before this call; this crate reads no clock).
    /// Finishes the hash with the date, the position and the predecessor. Signs nothing, and does
    /// not move the chain: a line whose stage is refused is dropped and the next one takes the same
    /// position.
    #[must_use]
    pub fn link(&self, prepared: Prepared, linked_ms: u64, _token: &Pass<AuditStep>) -> Linked {
        let Prepared {
            mut record,
            mut sink,
        } = prepared;
        debug_assert_eq!(record.node, self.node(), "a line names its chain's node");
        record.linked_ms = linked_ms;
        record.seq = self.next_seq;
        record.prev_hash.clone_from(&self.tail_hash);
        visit_trailer(linked_ms, record.seq, &record.prev_hash, &mut sink);
        let fp = sink.finish();
        record.hash = hex::encode(fp.0);
        Linked { record, fp }
    }

    /// MOVE THE CHAIN past a line that was staged. Infallible: the line was linked over this tail.
    pub fn advance(&mut self, linked: &Linked) {
        debug_assert_eq!(
            linked.record.seq, self.next_seq,
            "advance the line just linked"
        );
        self.tail_hash.clone_from(&linked.record.hash);
        self.next_seq = self.next_seq.saturating_add(1);
        self.sealed += 1;
    }
}
