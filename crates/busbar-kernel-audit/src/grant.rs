// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT SIGNING CAPABILITIES (SEALING-FIX r20 §5.3 layer 1, decision 159).
//!
//! The deployment key's signing power leaves [`AuditSigningKey`] only through
//! [`AuditSigningKey::into_grants`], which consumes the key into exactly two grants:
//! - [`NotaryGrant`] → [`Notary`]: `live` and `final` page stamps, on the notary signer thread;
//! - [`BootstrapGrant`] → [`BootstrapSigner`]: `after_restart` pages, break notices and unit
//!   checkpoint bodies, on the Bootstrap signer thread.
//!
//! No grant or capability is `Clone`, none has a public constructor but these, and none lends the
//! crypto seam [`Signer`] inside: possession is the capability. Every sign is blocking (a KMS may
//! answer in tens of milliseconds) and is never made on the request path.

use std::sync::Arc;

use busbar_contract::crypto::{approve_signer, LocalSigner, SignError, Signer, BACKEND};

use crate::sign::{checkpoint_preimage, AuditSigningKey};
use crate::stamp::{BreakNotice, Stamp, StampKind};

/// Who signs `live` and `final` pages.
pub enum LiveSigner {
    /// The Bootstrap key itself (the default: no KMS notary key, so both threads hold one signer).
    SameAsBootstrap,
    /// A per-boot notary key the Bootstrap key certifies (decision 159; CRYPTO-SEAM's
    /// `DelegatedSigner`).
    Delegated(Box<dyn Signer>),
}

/// The live notary's grant: built only by [`AuditSigningKey::into_grants`].
pub struct NotaryGrant {
    signer: Arc<dyn Signer>,
}

/// The Bootstrap signer's grant: built only by [`AuditSigningKey::into_grants`].
pub struct BootstrapGrant {
    signer: Arc<dyn Signer>,
}

/// Prints the key identifier and nothing else.
impl std::fmt::Debug for NotaryGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotaryGrant")
            .field("key_id", &self.signer.public_key().key_id)
            .finish_non_exhaustive()
    }
}

/// Prints the key identifier and nothing else.
impl std::fmt::Debug for BootstrapGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapGrant")
            .field("key_id", &self.signer.public_key().key_id)
            .finish_non_exhaustive()
    }
}

/// Why no grant was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// The linked crypto backend refused a signer (decision 168, F7: a FIPS backend refuses an
    /// unattested external module), or refused the key.
    Refused(busbar_contract::crypto::Error),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::Refused(e) => write!(f, "the audit signer was refused: {e}"),
        }
    }
}

impl std::error::Error for GrantError {}

impl AuditSigningKey {
    /// CONSUME THE KEY INTO ITS TWO GRANTS. The crypto backend approves the boundary of each
    /// distinct signer object first (the Bootstrap signer always; a delegated notary signer too),
    /// and a refusal of either builds no grant at all.
    pub fn into_grants(
        self,
        live: LiveSigner,
    ) -> Result<(NotaryGrant, BootstrapGrant), GrantError> {
        let local = LocalSigner::from_seed(self.seed_bytes()).map_err(GrantError::Refused)?;
        let bootstrap: Arc<dyn Signer> = Arc::new(local);
        approve_signer(bootstrap.as_ref()).map_err(GrantError::Refused)?;
        let notary: Arc<dyn Signer> = match live {
            LiveSigner::SameAsBootstrap => Arc::clone(&bootstrap),
            LiveSigner::Delegated(signer) => {
                approve_signer(signer.as_ref()).map_err(GrantError::Refused)?;
                Arc::from(signer)
            }
        };
        Ok((
            NotaryGrant { signer: notary },
            BootstrapGrant { signer: bootstrap },
        ))
    }
}

/// Why a page was not signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StampSignError {
    /// This capability does not sign this kind of page (CRYPTO-SEAM §2.5 key map: only the
    /// Bootstrap key signs `after_restart`; the Bootstrap signer signs no `live` or `final` page).
    WrongKind(StampKind),
    /// The signer failed.
    Signer(SignError),
}

impl From<SignError> for StampSignError {
    fn from(e: SignError) -> Self {
        StampSignError::Signer(e)
    }
}

impl std::fmt::Display for StampSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StampSignError::WrongKind(kind) => {
                write!(f, "this signer does not sign {} pages", kind.as_str())
            }
            StampSignError::Signer(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for StampSignError {}

/// Fill a stamp's signer fields from `signer`, then sign its preimage.
fn sign_stamp_with(signer: &dyn Signer, stamp: &mut Stamp) -> Result<(), SignError> {
    let public = signer.public_key();
    stamp.crypto.clear();
    stamp.crypto.push_str(BACKEND);
    stamp.sig_alg.clear();
    stamp.sig_alg.push_str(public.alg.as_str());
    stamp.key_id.clear();
    stamp.key_id.push_str(&public.key_id);
    stamp.signature.clear();
    let preimage = stamp.preimage();
    signer.sign(&preimage, &mut stamp.signature)
}

/// THE LIVE NOTARY'S CAPABILITY: signs `live` and `final` pages. Held by value by the notary signer
/// thread alone.
pub struct Notary {
    signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for Notary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notary")
            .field("key_id", &self.signer.public_key().key_id)
            .finish_non_exhaustive()
    }
}

impl Notary {
    /// The public live key, for building its Bootstrap certificate before live signing starts.
    #[must_use]
    pub fn public_key(&self) -> &busbar_contract::crypto::PublicKey {
        self.signer.public_key()
    }

    /// The capability its grant names.
    #[must_use]
    pub fn new(grant: NotaryGrant) -> Self {
        Notary {
            signer: grant.signer,
        }
    }

    /// The identifier live pages are signed under.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.signer.public_key().key_id
    }

    /// SIGN ONE `live` OR `final` PAGE: fills `crypto`, `sig_alg`, `key_id` and the signature (the
    /// caller sets `key_cert`). Refuses any other kind. Blocking.
    pub fn sign_stamp(&self, mut stamp: Stamp) -> Result<Stamp, StampSignError> {
        if !matches!(stamp.kind, StampKind::Live | StampKind::Final) {
            return Err(StampSignError::WrongKind(stamp.kind));
        }
        sign_stamp_with(self.signer.as_ref(), &mut stamp)?;
        Ok(stamp)
    }
}

/// THE BOOTSTRAP SIGNER'S CAPABILITY: restart pages, break notices and unit checkpoint bodies,
/// always under the deployment key. Held by value by the Bootstrap signer thread alone.
pub struct BootstrapSigner {
    signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for BootstrapSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapSigner")
            .field("key_id", &self.signer.public_key().key_id)
            .finish_non_exhaustive()
    }
}

impl BootstrapSigner {
    /// The bound public key; this lends no signing capability.
    #[must_use]
    pub fn public_key(&self) -> &busbar_contract::crypto::PublicKey {
        self.signer.public_key()
    }

    /// Certify a live key for exactly this node, chain position and predecessor. Blocking;
    /// only the Bootstrap signer thread holds this capability in production.
    pub fn sign_notary_key(
        &self,
        node: u64,
        seq: u64,
        prev_link: crate::Fingerprint,
        public: &busbar_contract::crypto::PublicKey,
    ) -> Result<crate::notary_key::NotaryKeyCertificate, SignError> {
        if node == 0 || seq == 0 {
            return Err(SignError::Crypto(busbar_contract::crypto::Error::Invalid(
                "notary certificate position",
            )));
        }
        let mut certificate = crate::notary_key::NotaryKeyCertificate {
            key_id: public.key_id.to_string(),
            sig_alg: public.alg.as_str().into(),
            public_key: public.bytes.to_vec(),
            signed_by: self.signer.public_key().key_id.to_string(),
            signature: Vec::new(),
        };
        certificate.key()?;
        self.signer.sign(
            &certificate.preimage(node, seq, prev_link),
            &mut certificate.signature,
        )?;
        Ok(certificate)
    }

    /// The capability its grant names.
    #[must_use]
    pub fn new(grant: BootstrapGrant) -> Self {
        BootstrapSigner {
            signer: grant.signer,
        }
    }

    /// The deployment key's identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.signer.public_key().key_id
    }

    /// SIGN ONE `after_restart` PAGE (`key_cert` is always 0 on it). Refuses any other kind.
    /// Blocking.
    pub fn sign_restart_page(&self, mut stamp: Stamp) -> Result<Stamp, StampSignError> {
        if stamp.kind != StampKind::AfterRestart {
            return Err(StampSignError::WrongKind(stamp.kind));
        }
        stamp.key_cert = 0;
        sign_stamp_with(self.signer.as_ref(), &mut stamp)?;
        Ok(stamp)
    }

    /// SIGN ONE BREAK NOTICE: fills `crypto`, `sig_alg`, `key_id` and the signature. Blocking.
    pub fn sign_break(&self, mut notice: BreakNotice) -> Result<BreakNotice, SignError> {
        let public = self.signer.public_key();
        notice.crypto.clear();
        notice.crypto.push_str(BACKEND);
        notice.sig_alg.clear();
        notice.sig_alg.push_str(public.alg.as_str());
        notice.key_id.clear();
        notice.key_id.push_str(&public.key_id);
        notice.signature.clear();
        let preimage = notice.preimage();
        self.signer.sign(&preimage, &mut notice.signature)?;
        Ok(notice)
    }

    /// SIGN A BATCH OF UNIT CHECKPOINT BODIES, one signature per body, in order: the same bytes as
    /// the deployment key's checkpoint signature ([`checkpoint_preimage`]), so a later boot verifies
    /// them under the key set as today. All or nothing: the first failure fails the batch.
    /// Blocking.
    pub fn sign_checkpoint(&self, bodies: &[&[u8]]) -> Result<Vec<Vec<u8>>, SignError> {
        let mut signatures = Vec::with_capacity(bodies.len());
        for body in bodies {
            let mut signature = Vec::with_capacity(64);
            self.signer
                .sign(&checkpoint_preimage(body), &mut signature)?;
            signatures.push(signature);
        }
        Ok(signatures)
    }
}
