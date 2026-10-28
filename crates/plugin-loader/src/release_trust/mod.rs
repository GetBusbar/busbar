// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELEASE TRUST CHAIN for first-party plugins: ROOT -> KEYS DOCUMENT -> RELEASE MANIFEST ->
//! ARTEFACT, modelled on TUF (`docs/design/release-trust.md`).
//!
//! * The ROOT keys are compiled in (`BUSBAR_RELEASE_PUBKEY`, [`crate::sign::embedded_release_keys`]).
//!   They sign nothing but keys documents, and [`ROOT_THRESHOLD`] of them must.
//! * A KEYS DOCUMENT ([`KeysDoc`], TUF's root/delegation metadata) names the release signer keys of
//!   each product role ([`PLUGINS_ROLE`] for first-party plugins) with a threshold, an `expires`
//!   and a `version` that only increases, and carries signed revocations of signer keys and of
//!   artefact digests. Replacing the release signer is a new keys document; the binary is unchanged.
//! * A RELEASE MANIFEST ([`TargetsDoc`], TUF's targets metadata) lists every artefact of one
//!   release, `(name, version, target, sha256)`, and is signed ONCE by the role's signers.
//! * The ARTEFACT is a plugin's canonical manifest bytes (`sign::canonical_manifest_bytes`, which
//!   pin the library by its own sha256): the plugin loads only if the release manifest lists it
//!   for this binary's target ([`PLUGIN_TARGET`]) under exactly that digest.
//!
//! Every refusal is a [`SealRefusal`]: a stable [`SealRefusal::code`] for the audit record and a
//! message that says what failed and what to do. Nothing here defaults open: a missing role, a zero
//! threshold or an unreadable document is a refusal.
//!
//! The byte encoding lives in [`wire`] alone, so the documents' format can move to ModernCI's v1
//! without touching the chain.

pub mod wire;

use std::collections::{BTreeMap, BTreeSet};

/// How many distinct root keys must sign a keys document.
pub const ROOT_THRESHOLD: usize = 1;

/// The keys-document role whose signers sign first-party plugin releases.
pub const PLUGINS_ROLE: &str = "busbar-plugins";

/// The plugin target this binary loads: its own Rust target triple, the `<target>` a release
/// manifest lists and a plugin release asset is named for.
pub const PLUGIN_TARGET: &str = env!("BUSBAR_PLUGIN_TARGET");

/// A public key a root or a release signer holds.
#[derive(Clone, PartialEq, Eq)]
pub enum ReleaseKey {
    /// An ed25519 public key.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// An ECDSA P-256 public key: its 65-byte uncompressed SEC1 point (`04 || x || y`).
    P256([u8; 65]),
}

impl ReleaseKey {
    /// The algorithm's key-list spelling (`ed25519` | `p256`).
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        match self {
            ReleaseKey::Ed25519(_) => "ed25519",
            ReleaseKey::P256(_) => "p256",
        }
    }

    /// The public key bytes, hex.
    #[must_use]
    pub fn public_hex(&self) -> String {
        match self {
            ReleaseKey::Ed25519(k) => hex::encode(k.as_bytes()),
            ReleaseKey::P256(p) => hex::encode(p),
        }
    }

    /// A P-256 public key from the hex of its 65-byte uncompressed SEC1 point. The point's place on
    /// the curve is checked by every verification (`ring` refuses an off-curve key there), so a
    /// malformed point verifies nothing: it fails closed.
    ///
    /// # Errors
    ///
    /// Not hex, not 65 bytes, or not an uncompressed point (`04` prefix).
    pub fn p256_from_hex(s: &str) -> Result<Self, String> {
        let bytes =
            hex::decode(s.trim()).map_err(|e| format!("p256 public key not valid hex: {e}"))?;
        let point: [u8; 65] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "p256 public key must be the 65-byte uncompressed SEC1 point, got {} bytes",
                bytes.len()
            )
        })?;
        if point[0] != 0x04 {
            return Err("p256 public key is not an uncompressed SEC1 point (04 || x || y)".into());
        }
        Ok(ReleaseKey::P256(point))
    }
}

impl std::fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm(), self.public_hex())
    }
}

impl PartialEq<ed25519_dalek::VerifyingKey> for ReleaseKey {
    fn eq(&self, other: &ed25519_dalek::VerifyingKey) -> bool {
        matches!(self, ReleaseKey::Ed25519(k) if k == other)
    }
}

/// A keys-document role: the signer key ids and how many must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub keyids: Vec<String>,
    pub threshold: u64,
}

/// A keys document, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeysDoc {
    /// Only ever increases; a verifier refuses one below the highest it has accepted.
    pub version: u64,
    /// Unix seconds; refused at or after.
    pub expires: u64,
    /// Every signer key, by key id ([`wire::key_id`]).
    pub keys: BTreeMap<String, ReleaseKey>,
    /// Each product role's signers and threshold.
    pub roles: BTreeMap<String, Role>,
    /// Signer key ids that no longer count toward any threshold.
    pub revoked_keyids: BTreeSet<String>,
    /// Artefact digests (canonical-manifest or library sha256) that never load, with why.
    pub revoked_digests: BTreeMap<String, String>,
}

/// One artefact a release manifest lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub version: String,
    pub target: String,
    /// sha256 of the plugin's canonical manifest bytes.
    pub sha256: String,
    /// Length of those bytes.
    pub length: u64,
}

/// A release manifest, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetsDoc {
    /// The keys-document role whose signers sign it.
    pub role: String,
    pub version: u64,
    /// Unix seconds; refused at or after.
    pub expires: u64,
    pub targets: Vec<Target>,
}

/// A decoded document with the exact bytes its signatures cover and its `(keyid, signature)`s.
#[derive(Debug, Clone)]
pub struct Signed<T> {
    pub doc: T,
    pub signed_bytes: Vec<u8>,
    pub signatures: Vec<(String, Vec<u8>)>,
}

/// The two documents a sealed plugin carries, as their encoded bytes.
#[derive(Debug, Clone, Copy)]
pub struct Seal<'a> {
    pub keys: &'a [u8],
    pub targets: &'a [u8],
}

/// The artefact being judged.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// The target the release must list it for ([`PLUGIN_TARGET`] in the loader).
    pub target: &'a str,
    /// sha256 of its canonical manifest bytes.
    pub sha256: &'a str,
    /// sha256 of its library bytes (a revocation may name either).
    pub lib_sha256: &'a str,
}

/// The facts a verification is judged against.
#[derive(Debug, Clone, Copy)]
pub struct Checks {
    /// Unix seconds now.
    pub now: u64,
    /// The highest keys-document version this deployment has accepted (0: none).
    pub keys_floor: u64,
}

/// A verified chain: which root vouched for the keys document, which signers signed the release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The id of the root key (from the compiled-in list) that signed the keys document.
    pub root: String,
    /// The key ids whose signatures met the role's threshold.
    pub signers: Vec<String>,
    pub keys_version: u64,
    pub targets_version: u64,
}

/// Why a sealed plugin was refused. [`SealRefusal::code`] is the audit record's stable token;
/// [`Display`](std::fmt::Display) says what failed and what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRefusal {
    /// A document is not one well-formed document of its kind.
    Malformed { doc: &'static str, why: String },
    /// No compiled-in root key's signature on the keys document verifies.
    KeysSignature { roots: Vec<String> },
    /// The keys document has expired.
    KeysExpired {
        version: u64,
        expires: u64,
        now: u64,
    },
    /// The keys document is older than one this deployment has accepted.
    KeysRollback { version: u64, floor: u64 },
    /// The keys document names no signers for the role, or a zero threshold.
    NoRole { role: String },
    /// Fewer than the role's threshold of its signers signed the release manifest.
    TargetsSignature {
        role: String,
        threshold: u64,
        valid: u64,
    },
    /// The release manifest's signatures came from revoked signers.
    SignerRevoked { keyids: Vec<String> },
    /// The release manifest has expired.
    TargetsExpired {
        version: u64,
        expires: u64,
        now: u64,
    },
    /// The keys document revokes this artefact's digest.
    DigestRevoked { digest: String, why: String },
    /// The release manifest does not list this name and version at all.
    Unlisted { name: String, version: String },
    /// It lists this name and version, but not for this binary's target.
    WrongTarget {
        name: String,
        version: String,
        target: String,
        listed: Vec<String>,
    },
    /// It lists this name, version and target with another digest.
    HashMismatch {
        name: String,
        version: String,
        target: String,
        listed: String,
        actual: String,
    },
}

impl SealRefusal {
    /// The stable token the audit record carries.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SealRefusal::Malformed { .. } => "release-seal-malformed",
            SealRefusal::KeysSignature { .. } => "keys-signature",
            SealRefusal::KeysExpired { .. } => "keys-expired",
            SealRefusal::KeysRollback { .. } => "keys-rollback",
            SealRefusal::NoRole { .. } => "keys-no-role",
            SealRefusal::TargetsSignature { .. } => "release-signature",
            SealRefusal::SignerRevoked { .. } => "signer-revoked",
            SealRefusal::TargetsExpired { .. } => "release-expired",
            SealRefusal::DigestRevoked { .. } => "digest-revoked",
            SealRefusal::Unlisted { .. } => "not-in-release",
            SealRefusal::WrongTarget { .. } => "wrong-target",
            SealRefusal::HashMismatch { .. } => "hash-mismatch",
        }
    }
}

impl std::fmt::Display for SealRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = wire::format_time;
        match self {
            SealRefusal::Malformed { doc, why } => write!(
                f,
                "the {doc} this plugin carries cannot be read ({why}); reinstall the plugin from \
                 its published release"
            ),
            SealRefusal::KeysSignature { roots } => write!(
                f,
                "the keys document is not signed by any root key this build trusts [{}]; the \
                 plugin was not released by busbar, or this binary predates its root",
                roots.join(", ")
            ),
            SealRefusal::KeysExpired {
                version,
                expires,
                now,
            } => write!(
                f,
                "the keys document (version {version}) expired at {} (now {}); install a release \
                 of the plugin sealed under a current keys document",
                t(*expires),
                t(*now)
            ),
            SealRefusal::KeysRollback { version, floor } => write!(
                f,
                "the keys document is version {version}, older than version {floor} this \
                 deployment has already accepted (rollback); install a release sealed under \
                 version {floor} or later"
            ),
            SealRefusal::NoRole { role } => write!(
                f,
                "the keys document names no signers (or a zero threshold) for the '{role}' role, \
                 so nothing it signs can be trusted"
            ),
            SealRefusal::TargetsSignature {
                role,
                threshold,
                valid,
            } => write!(
                f,
                "the release manifest carries {valid} valid signature(s) from the '{role}' \
                 signers, below the threshold of {threshold}; it was not signed by a current \
                 release signer"
            ),
            SealRefusal::SignerRevoked { keyids } => write!(
                f,
                "the release manifest is signed by revoked signer key(s) [{}]; a revoked signer's \
                 releases never load, install a release re-signed by a current signer",
                keyids.join(", ")
            ),
            SealRefusal::TargetsExpired {
                version,
                expires,
                now,
            } => write!(
                f,
                "the release manifest (version {version}) expired at {} (now {}); install a \
                 current release of the plugin",
                t(*expires),
                t(*now)
            ),
            SealRefusal::DigestRevoked { digest, why } => write!(
                f,
                "this artefact (sha256 {digest}) is REVOKED by the keys document: {why}; it never \
                 loads, install a release that is not revoked"
            ),
            SealRefusal::Unlisted { name, version } => write!(
                f,
                "the release manifest does not list '{name}' version {version}; the plugin was \
                 not part of the release its seal names"
            ),
            SealRefusal::WrongTarget {
                name,
                version,
                target,
                listed,
            } => write!(
                f,
                "the release manifest lists '{name}' version {version} for [{}], not for this \
                 binary's target {target}; install the {target} build of the plugin",
                listed.join(", ")
            ),
            SealRefusal::HashMismatch {
                name,
                version,
                target,
                listed,
                actual,
            } => write!(
                f,
                "the release manifest lists '{name}' version {version} for {target} as sha256 \
                 {listed}, but this plugin's canonical manifest is sha256 {actual}: it is not \
                 the released artefact (altered after release)"
            ),
        }
    }
}

/// VERIFY THE CHAIN for `subject`: the keys document against `roots`, the release manifest against
/// the keys document, the artefact against the release manifest.
///
/// # Errors
///
/// The first link that does not hold, as a [`SealRefusal`].
pub fn verify_release(
    roots: &[crate::sign::FirstPartyKey],
    seal: Seal<'_>,
    subject: Subject<'_>,
    checks: Checks,
) -> Result<Verified, SealRefusal> {
    let malformed = |doc: &'static str| move |why: String| SealRefusal::Malformed { doc, why };
    #[allow(unreachable_code)]
    if true {
        return Err(SealRefusal::Malformed {
            doc: "keys document",
            why: "RED: the release trust chain is not verified yet".into(),
        });
    }

    // ROOT -> KEYS DOCUMENT.
    let keys = wire::read_keys(seal.keys).map_err(malformed("keys document"))?;
    let mut vouching: Vec<&str> = Vec::new();
    for (keyid, sig) in &keys.signatures {
        if let Some(root) = roots.iter().find(|r| wire::key_id(&r.key) == *keyid) {
            if !vouching.contains(&root.id.as_str())
                && wire::verify(&root.key, &keys.signed_bytes, sig)
            {
                vouching.push(&root.id);
            }
        }
    }
    if vouching.len() < ROOT_THRESHOLD {
        return Err(SealRefusal::KeysSignature {
            roots: roots.iter().map(|r| r.id.clone()).collect(),
        });
    }
    let kd = &keys.doc;
    if kd.expires <= checks.now {
        return Err(SealRefusal::KeysExpired {
            version: kd.version,
            expires: kd.expires,
            now: checks.now,
        });
    }
    if kd.version < checks.keys_floor {
        return Err(SealRefusal::KeysRollback {
            version: kd.version,
            floor: checks.keys_floor,
        });
    }
    let role = match kd.roles.get(PLUGINS_ROLE) {
        Some(r) if r.threshold > 0 && !r.keyids.is_empty() => r,
        _ => {
            return Err(SealRefusal::NoRole {
                role: PLUGINS_ROLE.to_string(),
            })
        }
    };

    // KEYS DOCUMENT -> RELEASE MANIFEST.
    let targets = wire::read_targets(seal.targets).map_err(malformed("release manifest"))?;
    if targets.doc.role != PLUGINS_ROLE {
        return Err(SealRefusal::Malformed {
            doc: "release manifest",
            why: format!("it names role '{}', not '{PLUGINS_ROLE}'", targets.doc.role),
        });
    }
    let (mut signers, mut revoked): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for (keyid, sig) in &targets.signatures {
        if signers.contains(keyid) || revoked.contains(keyid) || !role.keyids.contains(keyid) {
            continue;
        }
        let Some(key) = kd.keys.get(keyid) else {
            continue;
        };
        if wire::verify(key, &targets.signed_bytes, sig) {
            if kd.revoked_keyids.contains(keyid) {
                revoked.push(keyid.clone());
            } else {
                signers.push(keyid.clone());
            }
        }
    }
    if (signers.len() as u64) < role.threshold {
        return Err(if revoked.is_empty() {
            SealRefusal::TargetsSignature {
                role: PLUGINS_ROLE.to_string(),
                threshold: role.threshold,
                valid: signers.len() as u64,
            }
        } else {
            SealRefusal::SignerRevoked { keyids: revoked }
        });
    }
    let td = &targets.doc;
    if td.expires <= checks.now {
        return Err(SealRefusal::TargetsExpired {
            version: td.version,
            expires: td.expires,
            now: checks.now,
        });
    }

    // RELEASE MANIFEST -> ARTEFACT.
    for digest in [subject.sha256, subject.lib_sha256] {
        if let Some(why) = kd.revoked_digests.get(&digest.to_ascii_lowercase()) {
            return Err(SealRefusal::DigestRevoked {
                digest: digest.to_ascii_lowercase(),
                why: why.clone(),
            });
        }
    }
    let same_release: Vec<&Target> = td
        .targets
        .iter()
        .filter(|t| t.name == subject.name && t.version == subject.version)
        .collect();
    if same_release.is_empty() {
        return Err(SealRefusal::Unlisted {
            name: subject.name.to_string(),
            version: subject.version.to_string(),
        });
    }
    let Some(entry) = same_release.iter().find(|t| t.target == subject.target) else {
        return Err(SealRefusal::WrongTarget {
            name: subject.name.to_string(),
            version: subject.version.to_string(),
            target: subject.target.to_string(),
            listed: same_release.iter().map(|t| t.target.clone()).collect(),
        });
    };
    if entry.sha256 != subject.sha256.to_ascii_lowercase() {
        return Err(SealRefusal::HashMismatch {
            name: subject.name.to_string(),
            version: subject.version.to_string(),
            target: subject.target.to_string(),
            listed: entry.sha256.clone(),
            actual: subject.sha256.to_ascii_lowercase(),
        });
    }
    Ok(Verified {
        root: vouching[0].to_string(),
        signers,
        keys_version: kd.version,
        targets_version: td.version,
    })
}

#[cfg(test)]
#[path = "../tests/release_trust_tests.rs"]
mod tests;
