// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NOTARY KEY CERTIFICATE, READ SIDE (owner ruling 2026-11-16, certificate v2; SEALING-FIX
//! §3.5 "Reads" `certs`, §3.7 rule 3).
//!
//! A `notary_key` line is a linked line of the node's chain whose payload is the Bootstrap key's
//! certificate for a per-boot notary key. A `live` or `final` stamp whose `key_cert` is that line's
//! WAL `node_seq` is signed under the certified key. V2 binds the node, the chain sequence and the
//! predecessor, all taken from the containing record, so a certificate cannot be replayed into
//! another node's chain or another position. A valid certificate proves delegation at its signed
//! position, not continued authority after it: supersession (a later certificate, a `final` or an
//! `after_restart` stamp) is the verifier's chronological rule, not this check's.
//!
//! This module decodes and checks certificates; the writer is the delegated-signer lane's.

use busbar_contract::crypto::{self, PublicKey, SigAlg};

use crate::link::Fingerprint;
use crate::off_path::journal::Reader;

/// The journal discriminator of a certificate line, distinct from unit lines.
pub const NOTARY_KEY_JOURNAL_TAG: &str = "audit.notary_key.v2";
const NOTARY_KEY_JOURNAL_PREFIX: &str = "audit.notary_key.";
/// The certificate signature's domain.
pub const NOTARY_KEY_DOMAIN: &str = "busbar.audit.notary_key.v2";
/// The domain of the certificate line's own fingerprint (its link hash).
pub const NOTARY_KEY_RECORD_DOMAIN: &str = "busbar.audit.notary_key.record.v2";

/// A public delegation, signed only by the node's bound Bootstrap key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotaryKeyCertificate {
    /// The delegated public key's derived identifier.
    pub key_id: String,
    /// The delegated key's algorithm (not the Bootstrap signature's).
    pub sig_alg: String,
    /// Raw Ed25519 (32 bytes) or uncompressed SEC 1 P-256 (65 bytes) public key.
    pub public_key: Vec<u8>,
    /// The Bootstrap key's identifier.
    pub signed_by: String,
    /// The Bootstrap signature over [`NotaryKeyCertificate::preimage`], 64 raw bytes.
    pub signature: Vec<u8>,
}

fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

impl NotaryKeyCertificate {
    /// The v2 signing preimage: the domain and a NUL, then node, chain sequence, predecessor,
    /// key id, algorithm and public key, each framed by its big-endian eight-byte length. A
    /// verifier takes the three position arguments from the containing record, never from a
    /// separate caller assertion.
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

    /// The delegated key, after checking its fixed encoding and that its identifier is the one
    /// derived from it.
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

/// One certificate line of a node's chain: it takes a chain `seq` and links like a unit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotaryKeyRecord {
    /// The node owning the chain.
    pub node: u64,
    /// Chain sequence (not the WAL `node_seq` a stamp's `key_cert` names).
    pub seq: u64,
    /// When it was linked, in milliseconds since the epoch.
    pub linked_ms: u64,
    /// The preceding line's fingerprint (zeros at genesis).
    pub prev_link: Fingerprint,
    /// This line's fingerprint, [`NotaryKeyRecord::recompute_fingerprint`].
    pub fingerprint: Fingerprint,
    /// The certificate it carries.
    pub certificate: NotaryKeyCertificate,
}

impl NotaryKeyRecord {
    /// The line's fingerprint: SHA-256 over the record domain, node, key id, algorithm, public
    /// key, signer, signature, `linked_ms`, `seq` and the predecessor, each framed by its
    /// big-endian eight-byte length.
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

    /// Check the line's own digest and the Bootstrap certification under the independently
    /// bound Bootstrap key. This does not establish the line's place in a walked chain, its WAL
    /// identity, or that the key was still current at a later stamp.
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

/// Decode a certificate line. A recognised but malformed line, or one of an unsupported version,
/// is an error rather than disappearing from the chain; any other tag is `None`.
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
