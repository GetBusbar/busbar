// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector::dtls` — the DTLS engine: transport encryption over a DATAGRAM carrier,

mod ring;
pub mod stun;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::ring::rand::{SecureRandom as _, SystemRandom};
pub use stun::IceCredentials;
use zeroize::Zeroizing;

/// How many distinct heard paths (and, apart, admitted candidates) one association remembers.
const MAX_HEARD_PATHS: usize = 16;
/// How many probes may be in flight.
const MAX_PROBES: usize = 32;
/// How many DTLS datagrams from a heard-but-unbound path wait for the bind.
const MAX_EARLY: usize = 8;
/// The largest DTLS record the engine emits.
const RECORD_BUF: usize = 2048;
/// How often the bound path is re-probed for consent (RFC 7675 §5.1: 5 s, randomised; here fixed).
pub const CONSENT_INTERVAL: Duration = Duration::from_secs(5);
/// How long the bound path may go without proof before the association stops (RFC 7675 §5.1).
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a probe is awaited before a heard path is probed again.
const PROBE_RETRY: Duration = Duration::from_millis(500);

/// What one datagram on a media port is (RFC 7983 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// First byte 0–3: STUN.
    Stun,
    /// First byte 20–63: DTLS.
    Dtls,
    /// First byte 128–191: RTP or RTCP (SRTP/SRTCP here).
    Media,
    /// Anything else (ZRTP 16–19, TURN channel 64–79, the rest): dropped.
    Drop,
}

/// Classify a datagram by its first byte.
#[must_use]
pub fn classify(datagram: &[u8]) -> Class {
    match datagram.first() {
        Some(0..=3) => Class::Stun,
        Some(20..=63) => Class::Dtls,
        Some(128..=191) => Class::Media,
        _ => Class::Drop,
    }
}

/// What [`Association::ingest`] decided about a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Hand the datagram, as it is, to the framer's clear lane.
    Raw,
    /// Core took it (DTLS, the answer to a probe) or dropped it.
    Kept,
}

/// A per-session certificate the host mints and owns. Its key is a ring key pair parked behind a
pub struct SessionCert {
    der: Vec<u8>,
    handle: Vec<u8>,
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for SessionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCert")
            .field("fingerprint", &hex(&self.fingerprint))
            .finish_non_exhaustive()
    }
}

impl Drop for SessionCert {
    fn drop(&mut self) {
        ring::unregister_key(&self.handle);
    }
}

impl SessionCert {
    /// Mint a fresh self-signed ECDSA P-256 certificate: ring generates the key, rcgen (on ring)
    pub fn mint() -> Result<Self, Failure> {
        use ::ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let failed = |e: &dyn std::fmt::Display| Failure::Certificate(e.to_string());
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| failed(&e))?;
        let pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
            .map_err(|e| failed(&e))?;
        let signer = rcgen::KeyPair::try_from(pkcs8.as_slice()).map_err(|e| failed(&e))?;
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .and_then(|p| p.self_signed(&signer))
            .map_err(|e| failed(&e))?;
        let der = cert.der().to_vec();
        let handle = ring::register_key(Arc::new(pair)).map_err(|e| failed(&e))?;
        Ok(SessionCert {
            fingerprint: sha256(&der),
            der,
            handle,
        })
    }

    /// The certificate, DER — public; the framer's SDP answer carries its fingerprint.
    #[must_use]
    pub fn public_der(&self) -> &[u8] {
        &self.der
    }

    /// SHA-256 of [`Self::public_der`], the `a=fingerprint:sha-256` value.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn dimpl(&self) -> dimpl::DtlsCertificate {
        dimpl::DtlsCertificate {
            certificate: self.der.clone(),
            private_key: self.handle.clone(),
        }
    }
}

/// Which end of the DTLS handshake this association is (the SDP `a=setup` outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `a=setup:active` — sends the ClientHello.
    Client,
    /// `a=setup:passive` — answers it.
    Server,
}

/// An admitted SRTP protection profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// `SRTP_AEAD_AES_128_GCM` (RFC 7714).
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM` (RFC 7714).
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// The profile's registry code (RFC 7714 §14.2), as the keying-material item names it.
    #[must_use]
    pub fn code(self) -> u32 {
        match self {
            SrtpProfile::AeadAes128Gcm => 0x0007,
            SrtpProfile::AeadAes256Gcm => 0x0008,
        }
    }
}

/// The DTLS-SRTP exporter's output (RFC 5764 §4.2): the profile and the keying material, zeroed
pub struct SrtpKeying {
    /// The negotiated profile.
    pub profile: SrtpProfile,
    material: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SrtpKeying {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpKeying")
            .field("profile", &self.profile)
            .field("len", &self.material.len())
            .finish_non_exhaustive()
    }
}

impl SrtpKeying {
    /// The exported material: client key, server key, client salt, server salt.
    #[must_use]
    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

/// What the association hands the framer (clear-lane datagrams go by [`Verdict::Raw`] instead,
/// uncopied).
#[derive(Debug)]
pub enum Up {
    /// The handshake finished and the peer certificate matched the SDP fingerprint.
    Connected,
    /// The exported SRTP keying material.
    Keyed(SrtpKeying),
    /// Decrypted DTLS application data (SCTP, for the data channels).
    Plaintext(Vec<u8>),
    /// The peer closed the DTLS session.
    Closed,
}

/// Why an association failed. A failed association is torn down: it exports nothing further and
/// sends nothing further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The certificate could not be minted.
    Certificate(String),
    /// The peer's certificate does not hash to the fingerprint its SDP carried.
    Fingerprint,
    /// The handshake negotiated an SRTP profile this host refuses.
    Profile(String),
    /// The DTLS layer failed.
    Dtls(String),
    /// The bound path gave no proof of consent for [`CONSENT_TIMEOUT`].
    ConsentExpired,
}

/// Why a bind or rebind was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRefused {
    /// No verified connectivity check came from the path.
    Unchecked,
    /// A rebind named an old path that is not the bound one.
    NotBound,
    /// The association has failed.
    Failed,
}

/// How an accepted bind or rebind stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    /// The path is proven; the association runs on it now.
    Now,
    /// The path was heard; core's probe is out, and the bind applies when it is answered.
    WhenProven,
}

/// One media association's DTLS engine and demux.
pub struct Association {
    #[cfg(test)]
    ingest_calls: usize,
    cert: Arc<SessionCert>,
    role: Role,
    keys: stun::Keys,
    remote_fingerprint: [u8; 32],
    dtls: Option<dimpl::Dtls>,
    /// Paths a verified check came from, and when the last one did.
    heard: HashMap<SocketAddr, Instant>,
    /// Far-end candidates the host's destination guard admitted (the dialling side).
    candidates: HashSet<SocketAddr>,
    /// Core's probes say ICE-CONTROLLING (the dialling side) rather than ICE-CONTROLLED.
    controlling: bool,
    /// The dialling side: only admitted candidates may be heard or bound.
    dialling: bool,
    proven: HashMap<SocketAddr, Instant>,
    probes: HashMap<[u8; 12], (SocketAddr, Instant)>,
    tie_breaker: [u8; 8],
    bound: Option<SocketAddr>,
    wanted: Option<SocketAddr>,
    next_consent: Option<Instant>,
    early: Vec<(SocketAddr, Vec<u8>)>,
    up: VecDeque<Up>,
    wire: VecDeque<(SocketAddr, Vec<u8>)>,
    record: Vec<u8>,
    timeout: Option<Instant>,
    peer_verified: bool,
    failed: Option<Failure>,
}

impl std::fmt::Debug for Association {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Association")
            .field("role", &self.role)
            .field("bound", &self.bound)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Association {
    /// An association for one session: the host's `cert`, the DTLS `role` from the SDP, the local
    #[must_use]
    pub fn new(
        cert: Arc<SessionCert>,
        role: Role,
        local: &IceCredentials,
        remote: &IceCredentials,
        remote_fingerprint: [u8; 32],
    ) -> Self {
        let mut tie_breaker = [0_u8; 8];
        let _ = SystemRandom::new().fill(&mut tie_breaker);
        Association {
            #[cfg(test)]
            ingest_calls: 0,
            cert,
            role,
            keys: stun::Keys::new(local, remote),
            remote_fingerprint,
            dtls: None,
            heard: HashMap::new(),
            candidates: HashSet::new(),
            controlling: false,
            dialling: false,
            proven: HashMap::new(),
            probes: HashMap::new(),
            tie_breaker,
            bound: None,
            wanted: None,
            next_consent: None,
            early: Vec::new(),
            up: VecDeque::new(),
            wire: VecDeque::new(),
            record: vec![0_u8; RECORD_BUF],
            timeout: None,
            peer_verified: false,
            failed: None,
        }
    }

    /// One datagram in from `path` (RFC 7983 demux; module docs). [`Verdict::Raw`] tells the caller
    pub fn ingest(&mut self, path: SocketAddr, datagram: &[u8], now: Instant) -> Verdict {
        #[cfg(test)]
        {
            self.ingest_calls += 1;
        }
        if self.failed.is_some() {
            return Verdict::Kept;
        }
        match classify(datagram) {
            Class::Stun => {
                if let Some(txid) = stun::verified_probe_answer(datagram, &self.keys) {
                    if self.probes.get(&txid).is_some_and(|(to, _)| *to == path) {
                        self.probes.remove(&txid);
                        self.proven.insert(path, now);
                        self.on_proof(path, now);
                        return Verdict::Kept;
                    }
                }
                if stun::is_verified_check(datagram, &self.keys) {
                    if self.dialling && !self.candidates.contains(&path) {
                        return Verdict::Kept;
                    }
                    self.hear(path, now);
                    if !self.proven.contains_key(&path) {
                        self.probe(path, now);
                    }
                }
                Verdict::Raw
            }
            Class::Media if self.heard.contains_key(&path) || self.bound == Some(path) => {
                Verdict::Raw
            }
            Class::Dtls => {
                if self.bound == Some(path) {
                    if let Some(dtls) = self.dtls.as_mut() {
                        if let Err(e) = dtls.handle_packet(datagram) {
                            self.fail(Failure::Dtls(e.to_string()));
                            return Verdict::Kept;
                        }
                    }
                    self.drive();
                } else if (self.heard.contains_key(&path) || self.candidates.contains(&path))
                    && self.early.len() < MAX_EARLY
                {
                    self.early.push((path, datagram.to_vec()));
                }
                Verdict::Kept
            }
            Class::Media | Class::Drop => Verdict::Kept,
        }
    }

    #[cfg(test)]
    pub(crate) fn ingest_calls(&self) -> usize {
        self.ingest_calls
    }

    /// The framer's ICE agent chose `path`: run DTLS on it, now if core has proven the path, or
    pub fn bind_path(&mut self, path: SocketAddr, now: Instant) -> Result<Bind, BindRefused> {
        if self.failed.is_some() {
            return Err(BindRefused::Failed);
        }
        if !self.admitted(path) {
            return Err(BindRefused::Unchecked);
        }
        self.wanted = Some(path);
        if self.proven.contains_key(&path) {
            self.apply_bind(path, now);
            Ok(Bind::Now)
        } else {
            self.probe(path, now);
            Ok(Bind::WhenProven)
        }
    }

    /// The framer's ICE agent moved the session from `old` to `new` (a network change). DTLS
    pub fn rebind_path(
        &mut self,
        old: SocketAddr,
        new: SocketAddr,
        now: Instant,
    ) -> Result<Bind, BindRefused> {
        if self.failed.is_some() {
            return Err(BindRefused::Failed);
        }
        if self.bound != Some(old) {
            return Err(BindRefused::NotBound);
        }
        if !self.admitted(new) {
            return Err(BindRefused::Unchecked);
        }
        self.wanted = Some(new);
        if self.proven.contains_key(&new) {
            self.apply_bind(new, now);
            Ok(Bind::Now)
        } else {
            self.probe(new, now);
            Ok(Bind::WhenProven)
        }
    }

    /// May the framer send `datagram` (clear lane) to `path`? A STUN success response — the framer
    #[must_use]
    pub fn may_send_clear(&self, path: SocketAddr, datagram: &[u8]) -> bool {
        if self.failed.is_some() {
            return false;
        }
        if stun::is_binding_success(datagram) {
            return self.heard.contains_key(&path) || self.proven.contains_key(&path);
        }
        if stun::is_binding_request(datagram) && self.candidates.contains(&path) {
            return true;
        }
        self.bound == Some(path)
    }

    /// The host's destination guard admitted `path`, a far-end candidate the description advertised
    pub fn admit_candidate(&mut self, path: SocketAddr, now: Instant) -> bool {
        if self.failed.is_some() {
            return false;
        }
        if !self.candidates.contains(&path) && self.candidates.len() >= MAX_HEARD_PATHS {
            return false;
        }
        self.controlling = true;
        self.candidates.insert(path);
        self.probe(path, now);
        true
    }

    /// Make this the dialling side (module docs): core's probes say ICE-CONTROLLING, and only a
    pub fn set_dialling(&mut self) {
        self.dialling = true;
        self.controlling = true;
    }

    /// Whether `datagram` from `path` is a verified check this DIALLING association will not hear
    #[must_use]
    pub fn unadmitted_check(&self, path: SocketAddr, datagram: &[u8]) -> bool {
        self.dialling
            && self.failed.is_none()
            && !self.candidates.contains(&path)
            && stun::is_verified_check(datagram, &self.keys)
    }

    /// Whether a bind to `path` may be accepted: an admitted candidate, or (the accepting side
    fn admitted(&self, path: SocketAddr) -> bool {
        self.candidates.contains(&path) || (!self.dialling && self.heard.contains_key(&path))
    }

    /// Seal `plaintext` (SCTP, for the data channels) as DTLS application data toward the bound path.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(), Failure> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        let Some(dtls) = self.dtls.as_mut() else {
            return Err(Failure::Dtls("no handshake yet".into()));
        };
        if let Err(e) = dtls.send_application_data(plaintext) {
            return Err(Failure::Dtls(e.to_string()));
        }
        self.drive();
        Ok(())
    }

    /// Advance timers to `now`: DTLS retransmission and deadline, probe retries, consent.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.failed.is_some() {
            return;
        }

        let keep = [self.bound, self.wanted];
        let fresh = |t: &Instant| now.saturating_duration_since(*t) < CONSENT_TIMEOUT;
        self.heard
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.proven
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.probes.retain(|_, (_, sent)| fresh(sent));
        if let Some(bound) = self.bound {
            let last = self.proven.get(&bound).copied();
            if last.is_some_and(|t| now.saturating_duration_since(t) >= CONSENT_TIMEOUT) {
                self.fail(Failure::ConsentExpired);
                return;
            }
            if self.next_consent.is_some_and(|t| t <= now) {
                self.next_consent = Some(now + CONSENT_INTERVAL);
                self.send_probe(bound, now);
            }
        }
        if let Some(wanted) = self.wanted.filter(|w| Some(*w) != self.bound) {
            let stale = self
                .probes
                .values()
                .filter(|(to, _)| *to == wanted)
                .all(|(_, sent)| now.saturating_duration_since(*sent) >= PROBE_RETRY);
            if stale {
                self.send_probe(wanted, now);
            }
        }
        if self.timeout.is_some_and(|t| t <= now) {
            self.timeout = None;
            if let Some(dtls) = self.dtls.as_mut() {
                if let Err(e) = dtls.handle_timeout(now) {
                    self.fail(Failure::Dtls(e.to_string()));
                    return;
                }
            }
        }
        self.drive();
    }

    /// The next instant [`Self::handle_timeout`] is owed.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        let expiry = self
            .bound
            .and_then(|path| self.proven.get(&path))
            .map(|proved| *proved + CONSENT_TIMEOUT);
        [self.timeout, self.next_consent, expiry]
            .into_iter()
            .flatten()
            .min()
    }

    /// The next thing for the framer.
    pub(crate) fn has_host_output(&self) -> bool {
        !self.up.is_empty() || !self.wire.is_empty()
    }

    /// The next thing for the framer.
    pub fn poll_up(&mut self) -> Option<Up> {
        self.up.pop_front()
    }

    /// The next datagram core owes the wire (DTLS, probes), and the path it goes to.
    pub fn poll_wire(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.wire.pop_front()
    }

    /// Why the association failed, if it did.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }

    /// The bound path, if any.
    #[must_use]
    pub fn bound_path(&self) -> Option<SocketAddr> {
        self.bound
    }

    /// Whether a verified check came from `path` (or core's own probe proved it) and consent has
    #[must_use]
    pub fn knows(&self, path: SocketAddr) -> bool {
        self.heard.contains_key(&path)
            || self.proven.contains_key(&path)
            || self.candidates.contains(&path)
    }

    /// Whether the far end's certificate matched the fingerprint its description carried. Nothing
    #[must_use]
    pub fn peer_verified(&self) -> bool {
        self.peer_verified && self.failed.is_none()
    }

    /// Record a verified check from `path`. At the cap the oldest heard path that is neither bound
    fn hear(&mut self, path: SocketAddr, now: Instant) {
        if !self.heard.contains_key(&path) && self.heard.len() >= MAX_HEARD_PATHS {
            let keep = [self.bound, self.wanted];
            let oldest = self
                .heard
                .iter()
                .filter(|(p, _)| !keep.contains(&Some(**p)))
                .min_by_key(|(_, t)| **t)
                .map(|(p, _)| *p);
            match oldest {
                Some(p) => {
                    self.heard.remove(&p);
                    self.proven.remove(&p);
                }
                None => return,
            }
        }
        self.heard.insert(path, now);
    }

    /// Probe `path` unless a probe to it is already in flight.
    fn probe(&mut self, path: SocketAddr, now: Instant) {
        if !self.probes.values().any(|(to, _)| *to == path) {
            self.send_probe(path, now);
        }
    }

    fn send_probe(&mut self, path: SocketAddr, now: Instant) {
        if self.probes.len() >= MAX_PROBES {
            let keep = [self.bound, self.wanted];
            let oldest = |spare: bool| {
                self.probes
                    .iter()
                    .filter(|(_, (to, _))| !spare || !keep.contains(&Some(*to)))
                    .min_by_key(|(_, (_, sent))| *sent)
                    .map(|(id, _)| *id)
            };
            if let Some(id) = oldest(true).or_else(|| oldest(false)) {
                self.probes.remove(&id);
            }
        }
        let mut txid = [0_u8; 12];
        if SystemRandom::new().fill(&mut txid).is_err() {
            return;
        }
        self.probes.insert(txid, (path, now));
        self.wire.push_back((
            path,
            stun::probe(&self.keys, txid, self.tie_breaker, self.controlling),
        ));
    }

    /// A probe to `path` was answered: apply a bind waiting on it.
    fn on_proof(&mut self, path: SocketAddr, now: Instant) {
        if self.wanted == Some(path) && self.bound != Some(path) {
            self.apply_bind(path, now);
        }
    }

    fn apply_bind(&mut self, path: SocketAddr, now: Instant) {
        let proved = self.proven.get(&path).copied();
        if proved.is_some_and(|proved| now.saturating_duration_since(proved) >= CONSENT_TIMEOUT) {
            self.fail(Failure::ConsentExpired);
            return;
        }
        self.bound = Some(path);
        let mut due = proved.map_or(now + CONSENT_INTERVAL, |proved| proved + CONSENT_INTERVAL);
        if let Some(sent) = self
            .probes
            .values()
            .filter_map(|(to, sent)| (*to == path).then_some(*sent))
            .max()
        {
            due = due.max(sent + CONSENT_INTERVAL);
        }
        if due <= now {
            self.send_probe(path, now);
            due = now + CONSENT_INTERVAL;
        }
        self.next_consent = Some(due);
        if self.dtls.is_none() {
            let config = match dimpl::Config::builder()
                .with_crypto_provider(ring::provider())
                .build()
            {
                Ok(c) => c,
                Err(e) => return self.fail(Failure::Dtls(e.to_string())),
            };
            let mut dtls = dimpl::Dtls::new_12(Arc::new(config), self.cert.dimpl(), now);
            dtls.set_active(self.role == Role::Client);
            if let Err(e) = dtls.handle_timeout(now) {
                return self.fail(Failure::Dtls(e.to_string()));
            }
            self.dtls = Some(dtls);
        }
        for (from, datagram) in std::mem::take(&mut self.early) {
            if from == path {
                self.ingest(from, &datagram, now);
            }
        }
        self.drive();
    }

    fn fail(&mut self, failure: Failure) {
        self.failed = Some(failure);
        self.dtls = None;
        self.early.clear();
        self.wire.clear();
        self.up.clear();
    }

    /// Admit or refuse the exported material (module docs: policy).
    fn keyed(&mut self, material: &[u8], profile: dimpl::SrtpProfile) {
        let profile = match profile {
            dimpl::SrtpProfile::AEAD_AES_128_GCM => SrtpProfile::AeadAes128Gcm,
            dimpl::SrtpProfile::AEAD_AES_256_GCM => SrtpProfile::AeadAes256Gcm,
            other => {
                self.fail(Failure::Profile(other.to_string()));
                return;
            }
        };
        self.up.push_back(Up::Keyed(SrtpKeying {
            profile,
            material: Zeroizing::new(material.to_vec()),
        }));
    }

    fn drive(&mut self) {
        let mut record = std::mem::take(&mut self.record);
        while let Some(dtls) = self.dtls.as_mut() {
            match dtls.poll_output(&mut record) {
                dimpl::Output::Packet(p) => {
                    if let Some(path) = self.bound {
                        self.wire.push_back((path, p.to_vec()));
                    }
                }
                dimpl::Output::PeerCert(der) => {
                    if sha256(der) != self.remote_fingerprint {
                        self.fail(Failure::Fingerprint);
                        break;
                    }
                    self.peer_verified = true;
                }

                dimpl::Output::KeyingMaterial(km, profile) => {
                    let km = Zeroizing::new(km.to_vec());
                    if !self.peer_verified {
                        self.fail(Failure::Fingerprint);
                        break;
                    }
                    self.keyed(&km, profile);
                }
                dimpl::Output::Connected => {
                    if !self.peer_verified {
                        self.fail(Failure::Fingerprint);
                        break;
                    }
                    self.up.push_back(Up::Connected);
                }
                dimpl::Output::ApplicationData(d) => {
                    if !self.peer_verified {
                        self.fail(Failure::Fingerprint);
                        break;
                    }
                    self.up.push_back(Up::Plaintext(d.to_vec()));
                }
                dimpl::Output::Timeout(t) => {
                    self.timeout = Some(t);
                    break;
                }
                dimpl::Output::CloseNotify => {
                    self.up.push_back(Up::Closed);
                    break;
                }
                other => {
                    let reason = format!("{other:?}");
                    self.fail(Failure::Dtls(reason));
                    break;
                }
            }
        }
        self.record = record;
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(::ring::digest::digest(&::ring::digest::SHA256, bytes).as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests;
