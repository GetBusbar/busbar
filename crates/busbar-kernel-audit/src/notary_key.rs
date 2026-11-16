// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bootstrap certificates for per-boot notary keys. V2 binds the node, chain sequence and
//! predecessor; a genesis certificate cannot be replayed into another node's zero predecessor.
//! A valid certificate proves delegation at its signed position, not continued authority after
//! that position. Full authority additionally requires a complete chronological chain walk.

use busbar_contract::crypto::{self, PublicKey, SigAlg};

use crate::journal::{FieldTooLong, Writer};
use crate::link::Fingerprint;
use crate::off_path::journal::Reader;

/// The journal discriminator of a linked certificate, distinct from unit records.
pub const NOTARY_KEY_JOURNAL_TAG: &str = "audit.notary_key.v2";
const NOTARY_KEY_JOURNAL_PREFIX: &str = "audit.notary_key.";
/// The signature domain approved for node-and-position-bound certificates.
pub const NOTARY_KEY_DOMAIN: &str = "busbar.audit.notary_key.v2";
/// The domain of the containing linked record's fingerprint.
pub const NOTARY_KEY_RECORD_DOMAIN: &str = "busbar.audit.notary_key.record.v2";

/// Public delegation, signed only by the node's bound Bootstrap key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotaryKeyCertificate {
    /// The delegated public key's derived identifier.
    pub key_id: String,
    /// The delegated key's algorithm, not the Bootstrap signature algorithm.
    pub sig_alg: String,
    /// Raw Ed25519 or uncompressed SEC1 P-256 public bytes.
    pub public_key: Vec<u8>,
    /// The bound Bootstrap key's identifier.
    pub signed_by: String,
    /// Raw fixed-width Bootstrap signature.
    pub signature: Vec<u8>,
}

fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

impl NotaryKeyCertificate {
    /// The fixed v2 signing preimage. Verifiers must take all three position arguments from
    /// the containing record, never from a separate caller-supplied assertion.
    #[must_use]
    pub fn preimage(&self, node: u64, seq: u64, prev_link: Fingerprint) -> Vec<u8> {
        let mut out = NOTARY_KEY_DOMAIN.as_bytes().to_vec();
        out.push(0);
        for field in [
            node.to_be_bytes().as_slice(),
            seq.to_be_bytes().as_slice(),
            prev_link.0.as_slice(),
            self.key_id.as_bytes(),
            self.sig_alg.as_bytes(),
            self.public_key.as_slice(),
        ] {
            frame(&mut out, field);
        }
        out
    }

    /// Decode and validate the delegated key's fixed representation and derived identifier.
    pub fn key(&self) -> Result<PublicKey, crypto::Error> {
        let alg = match self.sig_alg.as_str() {
            "ed25519" => {
                let raw: &[u8; 32] = self
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crypto::Error::Invalid("notary Ed25519 key length"))?;
                crypto::ed25519::validate_public_key(raw)?;
                SigAlg::Ed25519
            }
            "ecdsa-p256-sha256"
                if self.public_key.len() == 65 && self.public_key.first() == Some(&4) =>
            {
                SigAlg::EcdsaP256Sha256
            }
            _ => return Err(crypto::Error::Invalid("notary key algorithm or encoding")),
        };
        let key = PublicKey::new(alg, &self.public_key);
        if key.key_id.as_ref() != self.key_id {
            return Err(crypto::Error::Invalid("notary key identifier"));
        }
        Ok(key)
    }
}

/// One certificate in the audit chain. Its sequence shares the unit chain, while its journal
/// tag keeps certificate payloads out of unit facts and preserves existing unit encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotaryKeyRecord {
    /// The node owning the chain.
    pub node: u64,
    /// Chain sequence, distinct from the enclosing WAL row position.
    pub seq: u64,
    /// Time of linking in milliseconds.
    pub linked_ms: u64,
    /// The preceding linked record's fingerprint.
    pub prev_link: Fingerprint,
    /// This record's fingerprint, including its certificate signature.
    pub fingerprint: Fingerprint,
    /// The Bootstrap-certified public key.
    pub certificate: NotaryKeyCertificate,
}

/// A certificate signed for a snapshotted position, not staged into a journal yet.
#[derive(Debug)]
pub struct PreparedNotaryKey {
    node: u64,
    seq: u64,
    prev_link: Fingerprint,
    certificate: NotaryKeyCertificate,
}

/// A certificate linked over the current chain tail. Advance only after its journal stage
/// succeeds, while still holding the same durability lock.
#[derive(Debug)]
pub struct LinkedNotaryKey {
    record: NotaryKeyRecord,
}

impl LinkedNotaryKey {
    /// The linked certificate, including its computed fingerprint.
    #[must_use]
    pub fn record(&self) -> &NotaryKeyRecord {
        &self.record
    }

    /// Move the certificate out after staging and advancing.
    #[must_use]
    pub fn into_record(self) -> NotaryKeyRecord {
        self.record
    }
}

impl crate::AuditChain {
    /// Prepare a signed certificate before the durability lock. The signer must have signed
    /// exactly these position fields. Linking rechecks them against the live chain.
    #[must_use]
    pub fn prepare_notary_key(
        node: u64,
        seq: u64,
        prev_link: Fingerprint,
        certificate: NotaryKeyCertificate,
    ) -> PreparedNotaryKey {
        PreparedNotaryKey {
            node,
            seq,
            prev_link,
            certificate,
        }
    }

    /// Link a certificate without changing the chain. A changed tail or position requires a
    /// new Bootstrap signature; it is never repaired by relabelling the certificate.
    pub fn link_notary_key(
        &self,
        prepared: PreparedNotaryKey,
        linked_ms: u64,
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
    ) -> Result<LinkedNotaryKey, crypto::Error> {
        if prepared.node == 0
            || prepared.node != self.node()
            || prepared.seq != self.next_seq
            || self.next_seq == u64::MAX
            || Some(prepared.prev_link) != Fingerprint::from_hex(&self.tail_hash)
        {
            return Err(crypto::Error::Invalid("notary signing position changed"));
        }
        let mut record = NotaryKeyRecord {
            node: prepared.node,
            seq: prepared.seq,
            linked_ms,
            prev_link: prepared.prev_link,
            fingerprint: Fingerprint::ZERO,
            certificate: prepared.certificate,
        };
        record.fingerprint = record.recompute_fingerprint();
        Ok(LinkedNotaryKey { record })
    }

    /// Advance past a successfully staged certificate. Stale or repeated advancement refuses
    /// rather than creating a chain hole; it must share the staging lock with linking.
    pub fn advance_notary_key(&mut self, linked: &LinkedNotaryKey) -> Result<(), crypto::Error> {
        let record = linked.record();
        let next = self
            .next_seq
            .checked_add(1)
            .ok_or(crypto::Error::Invalid("notary chain sequence overflow"))?;
        if record.node != self.node()
            || record.seq != self.next_seq
            || Some(record.prev_link) != Fingerprint::from_hex(&self.tail_hash)
        {
            return Err(crypto::Error::Invalid("notary signing position changed"));
        }
        self.tail_hash = record.fingerprint.to_string();
        self.next_seq = next;
        self.sealed = self.sealed.saturating_add(1);
        self.heads.observe_notary_key(record);
        Ok(())
    }
}

impl NotaryKeyRecord {
    /// Recompute the record fingerprint with the independently versioned certificate payload.
    #[must_use]
    pub fn recompute_fingerprint(&self) -> Fingerprint {
        let mut out = Vec::new();
        for field in [
            NOTARY_KEY_RECORD_DOMAIN.as_bytes(),
            self.node.to_be_bytes().as_slice(),
            self.certificate.key_id.as_bytes(),
            self.certificate.sig_alg.as_bytes(),
            self.certificate.public_key.as_slice(),
            self.certificate.signed_by.as_bytes(),
            self.certificate.signature.as_slice(),
            self.linked_ms.to_be_bytes().as_slice(),
            self.seq.to_be_bytes().as_slice(),
            self.prev_link.0.as_slice(),
        ] {
            frame(&mut out, field);
        }
        Fingerprint(crypto::sha256(&out))
    }

    /// Verify the digest and certification under an independently bound Bootstrap key. This
    /// does not establish predecessor continuity, WAL identity or subsequent key authority.
    pub fn verify(&self, bootstrap: &PublicKey) -> Result<(), crypto::Error> {
        self.certificate.key()?;
        if self.node == 0 || self.seq == 0 || self.fingerprint != self.recompute_fingerprint() {
            return Err(crypto::Error::Invalid(
                "notary certificate position or digest",
            ));
        }
        if self.certificate.signed_by != bootstrap.key_id.as_ref() {
            return Err(crypto::Error::Invalid("notary certificate Bootstrap key"));
        }
        crypto::verify(
            bootstrap,
            &self
                .certificate
                .preimage(self.node, self.seq, self.prev_link),
            &self.certificate.signature,
        )
    }
}

/// Encode a certificate row with the existing journal's scalar framing.
pub fn notary_key_body(record: &NotaryKeyRecord) -> Result<Vec<u8>, FieldTooLong> {
    let mut w = Writer::within(u32::MAX as usize);
    w.text(NOTARY_KEY_JOURNAL_TAG);
    w.text(crate::recipe::LINK_RECIPE);
    w.num(record.seq);
    w.bytes(&record.prev_link.0);
    w.bytes(&record.fingerprint.0);
    w.num(record.linked_ms);
    w.num(record.node);
    w.text(&record.certificate.key_id);
    w.text(&record.certificate.sig_alg);
    w.bytes(&record.certificate.public_key);
    w.text(&record.certificate.signed_by);
    w.bytes(&record.certificate.signature);
    w.finish()
}

/// Decode a certificate row. A recognized but malformed row fails rather than disappearing
/// from the chain. Unrelated journal tags return None.
pub fn notary_key_from_journal_body(bytes: &[u8]) -> Result<Option<NotaryKeyRecord>, String> {
    let mut r = Reader::new(bytes);
    match r.text() {
        Some(tag) if tag == NOTARY_KEY_JOURNAL_TAG => {}
        Some(tag) if tag.starts_with(NOTARY_KEY_JOURNAL_PREFIX) => {
            return Err("an audit certificate uses an unsupported version".into());
        }
        _ => return Ok(None),
    }
    let bad = || "a notary_key.v2 record does not decode".to_string();
    if r.text().as_deref() != Some(crate::recipe::LINK_RECIPE) {
        return Err("a notary_key.v2 record names an unsupported recipe".into());
    }
    let seq = r.num().ok_or_else(bad)?;
    let prev_link = r.fingerprint().ok_or_else(bad)?;
    let fingerprint = r.fingerprint().ok_or_else(bad)?;
    let linked_ms = r.num().ok_or_else(bad)?;
    let node = r.num().ok_or_else(bad)?;
    let key_id = r.text().ok_or_else(bad)?;
    let sig_alg = r.text().ok_or_else(bad)?;
    let public_key = r
        .bytes()
        .filter(|key| matches!(key.len(), 32 | 65))
        .ok_or_else(bad)?
        .to_vec();
    let signed_by = r.text().ok_or_else(bad)?;
    let signature = r
        .bytes()
        .filter(|sig| sig.len() == 64)
        .ok_or_else(bad)?
        .to_vec();
    if !r.done()
        || node == 0
        || seq == 0
        || signed_by.len() != 16
        || !signed_by
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(bad());
    }
    let certificate = NotaryKeyCertificate {
        key_id,
        sig_alg,
        public_key,
        signed_by,
        signature,
    };
    certificate.key().map_err(|error| error.to_string())?;
    Ok(Some(NotaryKeyRecord {
        node,
        seq,
        linked_ms,
        prev_link,
        fingerprint,
        certificate,
    }))
}
