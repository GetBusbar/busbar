// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector::dtls` — the DTLS engine: transport encryption over a DATAGRAM carrier,

mod carrier;
mod session;
pub mod stun;

pub use carrier::{DatagramCarrier, LogAudit, MediaListeners, MediaRoute};
pub use session::MediaAudit;

use foldhash::{HashMap, HashMapExt as _, HashSet, HashSetExt as _};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::crypto;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::kinds::transport::transport::{FP_SHA256, FP_SHA384, FP_SHA512};
pub use stun::{IceCredentials, IceTerms};

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

/// A per-session certificate the host mints and owns. Its key is a backend key pair parked behind a
pub struct SessionCert {
    cert: crypto::dtls::DtlsCert,
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for SessionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCert")
            .field("fingerprint", &Hex(&self.fingerprint))
            .finish_non_exhaustive()
    }
}

impl SessionCert {
    /// Mint a fresh self-signed ECDSA P-256 certificate: the crypto backend generates the key and
    /// keeps it (`busbar_contract::crypto::dtls::dtls_self_signed`); dropping the cert forgets it.
    pub fn mint() -> Result<Self, Failure> {
        let cert = crypto::dtls::dtls_self_signed()
            .map_err(|e| crate::cold::datagram::certificate_failed(&e))?;
        Ok(SessionCert {
            fingerprint: sha256(cert.der()),
            cert,
        })
    }

    /// The certificate, DER — public; the framer's SDP answer carries its fingerprint.
    #[must_use]
    pub fn public_der(&self) -> &[u8] {
        self.cert.der()
    }

    /// SHA-256 of [`Self::public_der`], the `a=fingerprint:sha-256` value.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn dimpl(&self) -> dimpl::DtlsCertificate {
        crate::off_path::dtls::certificate(&self.cert)
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
    material: SecureVec,
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
    /// The far end's certificate digest under its FP_* algorithm; `None` until a session learns it (SECURE).
    /// No handshake starts while it is `None`.
    remote_fingerprint: Option<(u32, PeerDigest)>,
    dtls: Option<dimpl::Dtls>,
    /// Paths a verified check came from, and when the last one did.
    pub(crate) heard: HashMap<SocketAddr, Instant>,
    /// Far-end candidates the host's destination guard admitted (the dialling side).
    candidates: HashSet<SocketAddr>,
    /// Core's probes say ICE-CONTROLLING (the dialling side) rather than ICE-CONTROLLED.
    controlling: bool,
    /// The dialling side: only admitted candidates may be heard or bound.
    dialling: bool,
    pub(crate) proven: HashMap<SocketAddr, Instant>,
    pub(crate) probes: HashMap<[u8; 12], (SocketAddr, Instant)>,
    /// The probes in flight indexed by path: when each one to the path was sent (kept with
    /// `probes`, so a path's probes are found by key, not by a sweep).
    pub(crate) probed: HashMap<SocketAddr, smallvec::SmallVec<[Instant; 2]>>,
    tie_breaker: [u8; 8],
    pub(crate) bound: Option<SocketAddr>,
    pub(crate) wanted: Option<SocketAddr>,
    next_consent: Option<Instant>,
    /// DTLS datagrams from a heard-but-unbound path: each one's path and its span of
    /// `early_bytes`, the one buffer they are all held in (cleared, never shrunk, on replay).
    early: Vec<(SocketAddr, std::ops::Range<usize>)>,
    early_bytes: Vec<u8>,
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
        let mut association = Self::pending(cert, local.terms());
        association.set_credentials(local.terms(), remote.terms());
        let _ = association.accept_peer(role, FP_SHA256, &remote_fingerprint);
        association
    }

    /// An association for a session that has only its own ICE credentials so far (a MIN-3 session: its
    /// ICE_TERMS come first, the far end's credentials and the SECURE fingerprint later). It hears and
    /// verifies checks at once; no handshake starts until [`Self::set_peer`].
    #[must_use]
    pub fn pending(cert: Arc<SessionCert>, local: IceTerms<'_>) -> Self {
        let remote = IceTerms { ufrag: "", pwd: "" };
        let role = Role::Server;
        let remote_fingerprint = None;
        let mut tie_breaker = [0_u8; 8];
        let _ = crypto::fill(&mut tie_breaker);
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
            probed: HashMap::new(),
            tie_breaker,
            bound: None,
            wanted: None,
            next_consent: None,
            early: Vec::new(),
            early_bytes: Vec::new(),
            up: VecDeque::new(),
            wire: VecDeque::new(),
            record: vec![0_u8; RECORD_BUF],
            timeout: None,
            peer_verified: false,
            failed: None,
        }
    }

    /// Replace both sides' ICE credentials (a later ICE_TERMS: the far end's credentials learned, or an
    /// ICE restart's new ones). Checks already heard stay heard; probes in flight keep their old key.
    pub fn set_credentials(&mut self, local: IceTerms<'_>, remote: IceTerms<'_>) {
        self.keys.set(local, remote);
    }

    /// The far end's DTLS role and certificate digest under `alg` (an FP_* code), from SECURE. Refused (`false`)
    /// for an algorithm or length this host does not check, or a different answer once a handshake began.
    /// A handshake starts here when a path is already bound.
    pub fn set_peer(&mut self, role: Role, alg: u32, digest: &[u8], now: Instant) -> bool {
        if !self.accept_peer(role, alg, digest) {
            return false;
        }
        if self.bound.is_some() && self.dtls.is_none() {
            self.start_dtls(now);
            self.drive();
        }
        true
    }

    /// [`Self::set_peer`]'s record of the far end's role and digest, without starting a handshake.
    fn accept_peer(&mut self, role: Role, alg: u32, digest: &[u8]) -> bool {
        let want = match alg {
            FP_SHA256 => 32,
            FP_SHA384 => 48,
            FP_SHA512 => 64,
            _ => return false,
        };
        if digest.len() != want {
            return false;
        }
        if self.dtls.is_some() {
            return self.role == role
                && self
                    .remote_fingerprint
                    .as_ref()
                    .is_some_and(|(a, d)| *a == alg && d.bytes() == digest);
        }
        self.role = role;
        self.remote_fingerprint = Some((alg, PeerDigest::of(digest)));
        true
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
                        self.probe_gone(&txid);
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
                if self.bound == Some(path) && self.dtls.is_some() {
                    if let Some(dtls) = self.dtls.as_mut() {
                        if let Err(e) = dtls.handle_packet(datagram) {
                            self.fail(dtls_failed(&e));
                            return Verdict::Kept;
                        }
                    }
                    self.drive();
                } else if (self.bound == Some(path)
                    || self.heard.contains_key(&path)
                    || self.candidates.contains(&path))
                    && self.early.len() < MAX_EARLY
                {
                    let at = self.early_bytes.len();
                    self.early_bytes.extend_from_slice(datagram);
                    self.early.push((path, at..self.early_bytes.len()));
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
            if self.failed.is_some() {
                Err(BindRefused::Failed)
            } else {
                Ok(Bind::Now)
            }
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
            if self.failed.is_some() {
                Err(BindRefused::Failed)
            } else {
                Ok(Bind::Now)
            }
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

    /// Say ICE-CONTROLLING (`true`) or ICE-CONTROLLED in core's probes (a session's ICE_TERMS flag).
    pub fn set_controlling(&mut self, controlling: bool) {
        self.controlling = controlling;
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
            return Err(dtls_failed(&e));
        }
        self.drive();
        Ok(())
    }

    /// Advance timers to `now`: DTLS retransmission and deadline, probe retries, consent.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.failed.is_some() {
            return;
        }

        self.expire(now);
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
            // Every probe to `wanted` is stale exactly when its latest one is.
            let stale = self
                .latest_probe(wanted)
                .is_none_or(|sent| now.saturating_duration_since(sent) >= PROBE_RETRY);
            if stale {
                self.send_probe(wanted, now);
            }
        }
        if self.timeout.is_some_and(|t| t <= now) {
            self.timeout = None;
            if let Some(dtls) = self.dtls.as_mut() {
                if let Err(e) = dtls.handle_timeout(now) {
                    self.fail(dtls_failed(&e));
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
        if !self.heard.contains_key(&path)
            && self.heard.len() >= MAX_HEARD_PATHS
            && !self.let_go_oldest_heard()
        {
            return;
        }
        self.heard.insert(path, now);
    }

    /// Probe `path` unless a probe to it is already in flight.
    fn probe(&mut self, path: SocketAddr, now: Instant) {
        if !self.probed.contains_key(&path) {
            self.send_probe(path, now);
        }
    }

    fn send_probe(&mut self, path: SocketAddr, now: Instant) {
        if self.probes.len() >= MAX_PROBES {
            if let Some(id) = self.oldest_probe() {
                self.probe_gone(&id);
            }
        }
        let mut txid = [0_u8; 12];
        if crypto::fill(&mut txid).is_err() {
            return;
        }
        let Some(probe) =
            crate::off_path::dtls::probe(&self.keys, txid, self.tie_breaker, self.controlling)
        else {
            return;
        };
        if let Some((to, sent)) = self.probes.insert(txid, (path, now)) {
            unindex_probe(&mut self.probed, to, sent);
        }
        self.probed.entry(path).or_default().push(now);
        self.wire.push_back((path, probe));
    }

    /// The probe `txid` is out of flight (answered or let go): removed with its path index entry.
    fn probe_gone(&mut self, txid: &[u8; 12]) {
        if let Some((to, sent)) = self.probes.remove(txid) {
            unindex_probe(&mut self.probed, to, sent);
        }
    }

    /// When the latest probe in flight to `path` was sent.
    fn latest_probe(&self, path: SocketAddr) -> Option<Instant> {
        self.probed
            .get(&path)
            .and_then(|sents| sents.iter().max().copied())
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
        if let Some(sent) = self.latest_probe(path) {
            due = due.max(sent + CONSENT_INTERVAL);
        }
        if due <= now {
            self.send_probe(path, now);
            due = now + CONSENT_INTERVAL;
        }
        self.next_consent = Some(due);
        if self.dtls.is_none() {
            // No handshake without the far end's digest: the early datagrams wait for `set_peer`.
            if self.remote_fingerprint.is_some() {
                self.start_dtls(now);
            }
            return;
        }
        self.replay_early(path, now);
        self.drive();
    }

    /// Begin the handshake on the bound path, now that the far end's digest is known, and replay what
    /// that path sent before it.
    fn start_dtls(&mut self, now: Instant) {
        let Some(path) = self.bound else {
            return;
        };
        let provider = match crypto::dtls::dtls_provider() {
            Ok(p) => p,
            Err(e) => return self.fail(dtls_failed(&e)),
        };
        let config = match dimpl::Config::builder()
            .with_crypto_provider(provider)
            .build()
        {
            Ok(c) => c,
            Err(e) => return self.fail(dtls_failed(&e)),
        };
        let mut dtls = dimpl::Dtls::new_12(Arc::new(config), self.cert.dimpl(), now);
        dtls.set_active(self.role == Role::Client);
        if let Err(e) = dtls.handle_timeout(now) {
            return self.fail(dtls_failed(&e));
        }
        self.dtls = Some(dtls);
        self.replay_early(path, now);
        self.drive();
    }

    /// Replay the DTLS datagrams `path` sent while it was heard but unbound (or the handshake unstarted).
    fn replay_early(&mut self, path: SocketAddr, now: Instant) {
        let mut early = std::mem::take(&mut self.early);
        let mut bytes = std::mem::take(&mut self.early_bytes);
        for (from, span) in early.drain(..) {
            if from == path {
                if let Some(datagram) = bytes.get(span) {
                    self.ingest(from, datagram, now);
                }
            }
        }
        bytes.clear();
        if self.early.is_empty() {
            self.early = early;
        }
        if self.early_bytes.is_empty() {
            self.early_bytes = bytes;
        }
        self.drive();
    }

    fn fail(&mut self, failure: Failure) {
        self.failed = Some(failure);
        self.dtls = None;
        self.early.clear();
        self.early_bytes.clear();
        self.wire.clear();
        self.up.clear();
    }

    /// Admit or refuse the exported material (module docs: policy).
    fn keyed(&mut self, material: &[u8], profile: dimpl::SrtpProfile) {
        let profile = match profile {
            dimpl::SrtpProfile::AEAD_AES_128_GCM => SrtpProfile::AeadAes128Gcm,
            dimpl::SrtpProfile::AEAD_AES_256_GCM => SrtpProfile::AeadAes256Gcm,
            other => {
                self.fail(crate::cold::datagram::profile_refused(&other));
                return;
            }
        };
        let material = SecureVec::from(material);
        self.up
            .push_back(Up::Keyed(SrtpKeying { profile, material }));
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
                    if !self.peer_matches(der) {
                        self.fail(Failure::Fingerprint);
                        break;
                    }
                    self.peer_verified = true;
                }

                dimpl::Output::KeyingMaterial(km, profile) => {
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
                    self.fail(crate::cold::datagram::output_unowed(&other));
                    break;
                }
            }
        }
        self.record = record;
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    crypto::sha256(bytes)
}

impl Association {
    /// Whether the far end's certificate `der` hashes, under the algorithm SECURE named, to the digest it
    /// gave. `false` with no digest known: a handshake never completes unchecked.
    fn peer_matches(&self, der: &[u8]) -> bool {
        let Some((alg, digest)) = self.remote_fingerprint.as_ref() else {
            return false;
        };
        match *alg {
            FP_SHA256 => crypto::ct_eq(&crypto::sha256(der), digest.bytes()),
            FP_SHA384 => crypto::ct_eq(&crypto::sha384(der), digest.bytes()),
            FP_SHA512 => crypto::ct_eq(&crypto::sha512(der), digest.bytes()),
            _ => false,
        }
    }
}

/// The far end's certificate digest SECURE gave (at most SHA-512's 64 bytes; `accept_peer` admits
/// only the lengths of the algorithms it checks), held in place.
#[derive(Clone, Copy)]
struct PeerDigest {
    bytes: [u8; 64],
    len: usize,
}

impl PeerDigest {
    /// `digest` (at most 64 bytes: the caller checked its length against its algorithm).
    fn of(digest: &[u8]) -> Self {
        let mut bytes = [0_u8; 64];
        let len = digest.len().min(bytes.len());
        bytes[..len].copy_from_slice(&digest[..len]);
        Self { bytes, len }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// `bytes` as colon-separated upper-case hex pairs, written straight into the formatter.
struct Hex<'a>(&'a [u8]);

impl std::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"")?;
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        f.write_str("\"")
    }
}

/// Drop one probe sent at `sent` from `path`'s entry in the probe index (the entry goes with its
/// last probe).
fn unindex_probe(
    probed: &mut HashMap<SocketAddr, smallvec::SmallVec<[Instant; 2]>>,
    path: SocketAddr,
    sent: Instant,
) {
    if let Some(sents) = probed.get_mut(&path) {
        if let Some(at) = sents.iter().position(|s| *s == sent) {
            sents.swap_remove(at);
        }
        if sents.is_empty() {
            probed.remove(&path);
        }
    }
}

use crate::cold::datagram::dtls_failed;

#[cfg(test)]
mod tests;
