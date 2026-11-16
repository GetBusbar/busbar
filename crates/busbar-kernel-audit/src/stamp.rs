// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PAGE STAMP AND THE BREAK NOTICE (SEALING-FIX r20 §3.1).
//!
//! A stamp is one signature over the newest line's fingerprint: with the digest-and-link walk from
//! a line up to the stamp's `to`, it vouches for every link line of the page (G5). A break notice
//! records where a chain could not be vouched for, and vouches for nothing. Neither is an
//! [`AuditRecord`]: each has its own journal tag and decoder, and [`crate::from_journal_body`]
//! passes over both. Both are built and signed off the request path (the notary and the Bootstrap
//! signer threads, [`crate::grant`]).

use crate::link::Fingerprint;
use crate::record::{AuditBreak, AuditChain, AuditRecord};
use crate::sign::{AuditVerifyingKey, SIGNATURE_ALGORITHM};

/// The domain a stamp signature is FOR: a stamp signature can never be replayed as a per-line
/// record signature (`busbar.audit.record.v1`), or the reverse.
pub const STAMP_DOMAIN: &str = "busbar.audit.stamp.v1";

/// The domain a break notice's signature is for.
pub const BREAK_DOMAIN: &str = "busbar.audit.break.v1";

/// The journal tag of a stamp body.
pub const STAMP_JOURNAL_TAG: &str = "audit.stamp.v1";

/// The journal tag of a break notice body.
pub const BREAK_JOURNAL_TAG: &str = "audit.break.v1";

/// Which page a stamp closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampKind {
    /// A page the running node's notary stamped.
    Live,
    /// The last page of a clean shutdown.
    Final,
    /// A crash leftover, sealed after a restart (by the node itself or its successor on the host).
    AfterRestart,
}

impl StampKind {
    /// Every kind, in tag order.
    pub const ALL: [StampKind; 3] = [StampKind::Live, StampKind::Final, StampKind::AfterRestart];

    /// The frozen text the preimage and the body carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StampKind::Live => "live",
            StampKind::Final => "final",
            StampKind::AfterRestart => "after_restart",
        }
    }

    /// The kind [`StampKind::as_str`] spells `tag`, if any.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        StampKind::ALL.into_iter().find(|k| k.as_str() == tag)
    }
}

/// ONE PAGE STAMP (`audit.stamp.v1`), in the field order its signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// Which node's chain.
    pub node: u64,
    /// The first line of the page (chain `seq`).
    pub from: u64,
    /// The last line of the page (chain `seq`).
    pub to: u64,
    /// Line `to`'s fingerprint.
    pub fingerprint: Fingerprint,
    /// Which page this is.
    pub kind: StampKind,
    /// The node that signed: `node` itself, or its successor for a predecessor seal.
    pub sealer: u64,
    /// The sealer's host identity.
    pub host: String,
    /// The signing node's `audit.seal_every`, in milliseconds.
    pub every: u64,
    /// The wall clock (ms) read when the page was built.
    pub stamped_ms: u64,
    /// `after_restart` only: the last durable activity before the crash (ms); 0 otherwise.
    pub down_from_ms: u64,
    /// `after_restart` only: the sealing time (ms); 0 otherwise.
    pub down_to_ms: u64,
    /// The crypto backend that built the stamp (`busbar_contract::crypto::BACKEND`).
    pub crypto: String,
    /// The signature algorithm (`ed25519` | `ecdsa-p256-sha256`).
    pub sig_alg: String,
    /// Which key signed.
    pub key_id: String,
    /// The WAL `node_seq` of the `notary_key` line that certifies `key_id`; 0 for the Bootstrap key
    /// and always 0 on `after_restart`.
    pub key_cert: u64,
    /// The signature over [`Stamp::preimage`]: 64 raw bytes for `ed25519`.
    pub signature: Vec<u8>,
}

/// Why a stamp or a break notice does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampError {
    /// It names a signature algorithm this verifier does not hold keys for.
    UnsupportedAlgorithm,
    /// The key handed to the check is not the key it names.
    WrongKey,
    /// The signature does not verify over its preimage under that key.
    BadSignature,
}

impl std::fmt::Display for StampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StampError::UnsupportedAlgorithm => "the stamp names a signature algorithm with no key",
            StampError::WrongKey => "the stamp names another key than the one checked",
            StampError::BadSignature => "the stamp signature does not verify over its fields",
        })
    }
}

impl std::error::Error for StampError {}

/// Why a stamp does not vouch for a run of lines (SEALING-FIX §3.5 "Covering stamp").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverError {
    /// There are no lines, or the first is outside the page, or the last is not the page's `to`.
    OutOfRange,
    /// A line belongs to another node's chain.
    WrongNode,
    /// A walked line is not a link line: a legacy line is vouched for only by its own signature.
    NotALinkLine,
    /// The walk from the line to the stamp's `to` breaks.
    Walk(AuditBreak),
    /// Line `to`'s hash is not the stamp's fingerprint.
    Fingerprint,
}

impl std::fmt::Display for CoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverError::OutOfRange => {
                f.write_str("the lines are not a walk to the stamp's last line")
            }
            CoverError::WrongNode => f.write_str("a line belongs to another node's chain"),
            CoverError::NotALinkLine => f.write_str("a legacy line is never covered by a stamp"),
            CoverError::Walk(broken) => write!(f, "the walk to the stamp breaks: {broken}"),
            CoverError::Fingerprint => {
                f.write_str("the stamp's fingerprint is not its last line's hash")
            }
        }
    }
}

impl std::error::Error for CoverError {}

/// The `LengthPrefixed` preimage builder: the domain and a NUL, then every field framed by its
/// big-endian eight-byte length.
struct Preimage(Vec<u8>);

impl Preimage {
    fn new(domain: &str) -> Self {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(domain.as_bytes());
        out.push(0);
        Preimage(out)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.0
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.0.extend_from_slice(bytes);
    }

    fn text(&mut self, text: &str) {
        self.bytes(text.as_bytes());
    }

    fn num(&mut self, n: u64) {
        self.bytes(&n.to_be_bytes());
    }
}

/// Check one raw signature over `preimage` under `key`, naming `key_id` and `sig_alg`.
fn verify_signed(
    key: &AuditVerifyingKey,
    sig_alg: &str,
    key_id: &str,
    preimage: &[u8],
    signature: &[u8],
) -> Result<(), StampError> {
    if sig_alg != SIGNATURE_ALGORITHM {
        return Err(StampError::UnsupportedAlgorithm);
    }
    if key_id != key.key_id() {
        return Err(StampError::WrongKey);
    }
    key.verify_raw(preimage, signature)
        .map_err(|_| StampError::BadSignature)
}

impl Stamp {
    /// THE EXACT BYTES THE SIGNATURE IS OVER: `"busbar.audit.stamp.v1\0"`, then every field above
    /// but the signature, length-prefixed, in table order. So a store writer without the key
    /// cannot relabel a page, move a boundary, re-attribute it, or point it at another certificate.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let mut p = Preimage::new(STAMP_DOMAIN);
        p.num(self.node);
        p.num(self.from);
        p.num(self.to);
        p.bytes(&self.fingerprint.0);
        p.text(self.kind.as_str());
        p.num(self.sealer);
        p.text(&self.host);
        p.num(self.every);
        p.num(self.stamped_ms);
        p.num(self.down_from_ms);
        p.num(self.down_to_ms);
        p.text(&self.crypto);
        p.text(&self.sig_alg);
        p.text(&self.key_id);
        p.num(self.key_cert);
        p.0
    }

    /// Check the signature under `key`, which must be the key the stamp names. Which keys a kind
    /// may be signed under is the walk's and verify's rule (§3.6.0, §3.7), not this check's.
    pub fn verify(&self, key: &AuditVerifyingKey) -> Result<(), StampError> {
        verify_signed(
            key,
            &self.sig_alg,
            &self.key_id,
            &self.preimage(),
            &self.signature,
        )
    }

    /// WHETHER THIS STAMP VOUCHES FOR `walk[0]` (§3.5 "Covering stamp", items 2 and 3): `walk` is
    /// the node's lines from that line through the stamp's `to`, oldest first. Every line is a link
    /// line of this stamp's node, the first lies in the page, the walk recomputes and links, and the
    /// last line is the stamp's `to` with the stamp's fingerprint. The signature is checked apart
    /// ([`Stamp::verify`]); a range check alone is never enough.
    pub fn covers(&self, walk: &[AuditRecord]) -> Result<(), CoverError> {
        let (Some(first), Some(last)) = (walk.first(), walk.last()) else {
            return Err(CoverError::OutOfRange);
        };
        if first.seq < self.from || first.seq > self.to || last.seq != self.to {
            return Err(CoverError::OutOfRange);
        }
        if walk.iter().any(|line| line.node != self.node) {
            return Err(CoverError::WrongNode);
        }
        if walk.iter().any(|line| !line.recipe.is_link()) {
            return Err(CoverError::NotALinkLine);
        }
        AuditChain::verify_window(walk).map_err(CoverError::Walk)?;
        if Fingerprint::from_hex(&last.hash) != Some(self.fingerprint) {
            return Err(CoverError::Fingerprint);
        }
        Ok(())
    }
}

/// Why a chain could not be vouched for (`audit.break.v1` `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakReason {
    /// A `prev_hash` does not match.
    Link,
    /// A line does not hash to its own fields.
    Digest,
    /// A position is missing or renumbered.
    Sequence,
    /// A record does not decode.
    Decode,
    /// A stamp failed its own check.
    Stamp,
    /// A legacy line after the anchor has no valid per-line signature.
    Unsigned,
    /// A predecessor walk reached its record budget before an anchor.
    Budget,
    /// The tail holds link lines but no genuine anchor of this node on this host.
    Unanchored,
    /// The tail is longer than any crash leftover.
    Span,
    /// Lines follow a clean-shutdown page.
    AfterFinal,
    /// A fenced node has no seal row and no open fence mark.
    UnsealedFenced,
}

impl BreakReason {
    /// Every reason, in tag order.
    pub const ALL: [BreakReason; 11] = [
        BreakReason::Link,
        BreakReason::Digest,
        BreakReason::Sequence,
        BreakReason::Decode,
        BreakReason::Stamp,
        BreakReason::Unsigned,
        BreakReason::Budget,
        BreakReason::Unanchored,
        BreakReason::Span,
        BreakReason::AfterFinal,
        BreakReason::UnsealedFenced,
    ];

    /// The frozen text the preimage and the body carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BreakReason::Link => "link",
            BreakReason::Digest => "digest",
            BreakReason::Sequence => "sequence",
            BreakReason::Decode => "decode",
            BreakReason::Stamp => "stamp",
            BreakReason::Unsigned => "unsigned",
            BreakReason::Budget => "budget",
            BreakReason::Unanchored => "unanchored",
            BreakReason::Span => "span",
            BreakReason::AfterFinal => "after_final",
            BreakReason::UnsealedFenced => "unsealed_fenced",
        }
    }

    /// The reason [`BreakReason::as_str`] spells `tag`, if any.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        BreakReason::ALL.into_iter().find(|r| r.as_str() == tag)
    }
}

/// ONE BREAK NOTICE (`audit.break.v1`): where a node's chain stops being vouched for. Always signed
/// by the Bootstrap key. It vouches for no line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakNotice {
    /// Which node's chain.
    pub node: u64,
    /// The node that recorded it.
    pub sealer: u64,
    /// The last line that is vouched for (0: unknown).
    pub last_good: u64,
    /// The first unsealed line (chain `seq`).
    pub unsealed_from: u64,
    /// The last unsealed line (chain `seq`).
    pub unsealed_to: u64,
    /// The WAL `node_seq` of the first failing record.
    pub journal_from: u64,
    /// The WAL `node_seq` of line `unsealed_to`.
    pub journal_to: u64,
    /// Why.
    pub reason: BreakReason,
    /// When it was detected (ms).
    pub detected_ms: u64,
    /// The sealer's host identity.
    pub host: String,
    /// The crypto backend that built it.
    pub crypto: String,
    /// The signature algorithm.
    pub sig_alg: String,
    /// Which key signed (the Bootstrap key).
    pub key_id: String,
    /// The signature over [`BreakNotice::preimage`].
    pub signature: Vec<u8>,
}

impl BreakNotice {
    /// The exact bytes the signature is over: `"busbar.audit.break.v1\0"`, then every field but the
    /// signature, length-prefixed, in order.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let mut p = Preimage::new(BREAK_DOMAIN);
        p.num(self.node);
        p.num(self.sealer);
        p.num(self.last_good);
        p.num(self.unsealed_from);
        p.num(self.unsealed_to);
        p.num(self.journal_from);
        p.num(self.journal_to);
        p.text(self.reason.as_str());
        p.num(self.detected_ms);
        p.text(&self.host);
        p.text(&self.crypto);
        p.text(&self.sig_alg);
        p.text(&self.key_id);
        p.0
    }

    /// Check the signature under `key`, which must be the key the notice names.
    pub fn verify(&self, key: &AuditVerifyingKey) -> Result<(), StampError> {
        verify_signed(
            key,
            &self.sig_alg,
            &self.key_id,
            &self.preimage(),
            &self.signature,
        )
    }
}

/// The journal body of one stamp.
pub fn stamp_body(stamp: &Stamp) -> Result<Vec<u8>, crate::journal::FieldTooLong> {
    let mut w = crate::journal::Writer::within(u32::MAX as usize);
    w.text(STAMP_JOURNAL_TAG);
    w.num(stamp.node);
    w.num(stamp.from);
    w.num(stamp.to);
    w.bytes(&stamp.fingerprint.0);
    w.text(stamp.kind.as_str());
    w.num(stamp.sealer);
    w.text(&stamp.host);
    w.num(stamp.every);
    w.num(stamp.stamped_ms);
    w.num(stamp.down_from_ms);
    w.num(stamp.down_to_ms);
    w.text(&stamp.crypto);
    w.text(&stamp.sig_alg);
    w.text(&stamp.key_id);
    w.num(stamp.key_cert);
    w.bytes(&stamp.signature);
    w.finish()
}

/// Read a journal body back into the stamp it keeps: `Ok(None)` for any other body.
pub fn stamp_from_journal_body(bytes: &[u8]) -> Result<Option<Stamp>, String> {
    let mut r = crate::off_path::journal::Reader::new(bytes);
    if r.text().as_deref() != Some(STAMP_JOURNAL_TAG) {
        return Ok(None);
    }
    let bad = || "an audit stamp body does not decode".to_string();
    let stamp = (|| {
        Some(Stamp {
            node: r.num()?,
            from: r.num()?,
            to: r.num()?,
            fingerprint: r.fingerprint()?,
            kind: StampKind::from_tag(&r.text()?)?,
            sealer: r.num()?,
            host: r.text()?,
            every: r.num()?,
            stamped_ms: r.num()?,
            down_from_ms: r.num()?,
            down_to_ms: r.num()?,
            crypto: r.text()?,
            sig_alg: r.text()?,
            key_id: r.text()?,
            key_cert: r.num()?,
            signature: r.bytes()?.to_vec(),
        })
    })()
    .ok_or_else(bad)?;
    if !r.done() {
        return Err(bad());
    }
    Ok(Some(stamp))
}

/// The journal body of one break notice.
pub fn break_body(notice: &BreakNotice) -> Result<Vec<u8>, crate::journal::FieldTooLong> {
    let mut w = crate::journal::Writer::within(u32::MAX as usize);
    w.text(BREAK_JOURNAL_TAG);
    w.num(notice.node);
    w.num(notice.sealer);
    w.num(notice.last_good);
    w.num(notice.unsealed_from);
    w.num(notice.unsealed_to);
    w.num(notice.journal_from);
    w.num(notice.journal_to);
    w.text(notice.reason.as_str());
    w.num(notice.detected_ms);
    w.text(&notice.host);
    w.text(&notice.crypto);
    w.text(&notice.sig_alg);
    w.text(&notice.key_id);
    w.bytes(&notice.signature);
    w.finish()
}

/// Read a journal body back into the break notice it keeps: `Ok(None)` for any other body.
pub fn break_from_journal_body(bytes: &[u8]) -> Result<Option<BreakNotice>, String> {
    let mut r = crate::off_path::journal::Reader::new(bytes);
    if r.text().as_deref() != Some(BREAK_JOURNAL_TAG) {
        return Ok(None);
    }
    let bad = || "an audit break notice body does not decode".to_string();
    let notice = (|| {
        Some(BreakNotice {
            node: r.num()?,
            sealer: r.num()?,
            last_good: r.num()?,
            unsealed_from: r.num()?,
            unsealed_to: r.num()?,
            journal_from: r.num()?,
            journal_to: r.num()?,
            reason: BreakReason::from_tag(&r.text()?)?,
            detected_ms: r.num()?,
            host: r.text()?,
            crypto: r.text()?,
            sig_alg: r.text()?,
            key_id: r.text()?,
            signature: r.bytes()?.to_vec(),
        })
    })()
    .ok_or_else(bad)?;
    if !r.done() {
        return Err(bad());
    }
    Ok(Some(notice))
}
