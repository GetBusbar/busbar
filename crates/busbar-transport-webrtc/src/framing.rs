// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE ASSOCIATION'S FRAMING: the media stack (ICE, SRTP, SCTP) over the host's datagram port and
//! secure layer, with no ABI type in it ([`crate::door`] lowers it onto the transport kind's table).
//!
//! # What goes in
//!
//! * the far end's session description ([`Framing::rendezvous`]): the offer on the accepting side,
//!   the answer on the dialling side;
//! * the host's state on every call ([`Framing::host`]): the bound path, the verified bit, the
//!   keying-material item once;
//! * datagrams ([`Framing::datagram`]): clear (a connectivity check, protected media) or secured
//!   (plaintext the host's secure layer opened);
//! * messages to send ([`Framing::emit`]) and the clock ([`Framing::timeout`]).
//!
//! # What comes out
//!
//! * routes ([`Route`]): a check or its answer to the path it concerns; protected media and
//!   secured plaintext to the BOUND path only — the host's choice, never the media stack's;
//! * pieces ([`Piece`]): stream [`DESCRIPTION`] carries this end's own description; each data
//!   channel and each media line is a stream whose first frame is a field block naming it
//!   (`label` for a channel; `kind`, `codec` for media), then one frame per message;
//! * at most one path request: bind the path the far end nominated (or this end did, dialling),
//!   or move to it from the bound one;
//! * the rendezvous terms the host's secure layer runs under.
//!
//! # The guards (THE DESIGN l.756-765)
//!
//! * AEAD-AES-GCM only: a keying-material item under any other profile fails the framing.
//! * Application data waits for peer verification: until the host's verified bit, a secured
//!   datagram or protected media is dropped unread, and nothing is handed up.
//! * A path the host has not bound receives no media: a nomination the media stack's ICE agent
//!   accepted is only a REQUEST; media follows the host's bound path, which moves only after the
//!   host's own verified round trip.
//! * Keys are zeroised: the keying material this framing holds is cleared once handed on.

use std::collections::{HashMap, VecDeque};
use core::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::format::Codec;
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, IceCreds, Input, Output, Rtc};
use zeroize::{Zeroize as _, Zeroizing};

use crate::shim::{self, Shim};
use crate::stun::{self, Check};

/// The stream this end's own session description is yielded on.
pub const DESCRIPTION: u64 = 0;
/// The first media stream: media line `n` (in the order it appeared) is `MEDIA_BASE + n`.
pub const MEDIA_BASE: u64 = 1 << 32;

/// The registry codes of the protection profiles this framer admits (RFC 7714 §14.2).
pub const PROFILE_AEAD_AES_128_GCM: u32 = 0x0007;
/// `SRTP_AEAD_AES_256_GCM`.
pub const PROFILE_AEAD_AES_256_GCM: u32 = 0x0008;

/// The most messages held for a channel not yet open, and the most pieces or routes queued.
const MAX_HELD: usize = 256;
/// The most nominating checks awaiting their answer.
const MAX_NOMINATING: usize = 64;

/// Which end of the association this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Answers the far end's offer (ICE-lite).
    Accept,
    /// Offers (full ICE, controlling).
    Dial,
}

/// The lane a datagram travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// As the port carried it.
    Clear,
    /// Plaintext of the host's secure layer.
    Secured,
}

/// One datagram for the host to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// Its path.
    pub path: u32,
    /// Its lane.
    pub lane: Lane,
}

/// One piece for the layer above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The stream.
    pub stream: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// A field block (a stream's head).
    pub fields: bool,
    /// The message was text.
    pub text: bool,
}

/// A path request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Bind this path.
    Bind(u32),
    /// Move from the first (bound) path to the second.
    Rebind(u32, u32),
}

/// What the host's secure layer runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    /// This end opens the handshake.
    pub initiates: bool,
    /// The user name the far end's checks carry first (ours).
    pub local_user: String,
    /// Our secret.
    pub local_secret: Zeroizing<String>,
    /// The far end's user name.
    pub remote_user: String,
    /// The far end's secret.
    pub remote_secret: Zeroizing<String>,
    /// The far end's certificate fingerprint.
    pub peer_fingerprint: [u8; 32],
    /// The far end's datagram candidates, `ip:port` each.
    pub candidates: Vec<SocketAddr>,
}

/// What a dialling framing offers: its channels' labels and whether it carries audio.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opening {
    /// The data channels, by label, in stream order (stream `1 + i`).
    pub channels: Vec<String>,
    /// One audio line (Opus, sent and received).
    pub audio: bool,
}

/// Why a framing failed. Never secret material.
pub type Failed = String;

/// One association's framing.
pub struct Framing {
    side: Side,
    rtc: Rtc,
    shim: Shim,
    local: Option<SocketAddr>,
    local_creds: IceCreds,
    pending: Option<SdpPendingOffer>,
    described: bool,
    paths: HashMap<u32, SocketAddr>,
    addrs: HashMap<SocketAddr, u32>,
    bound: u32,
    verified: bool,
    keyed: bool,
    ice: IceConnectionState,
    /// Checks that nominate, by transaction id, and the path each travels.
    nominating: HashMap<[u8; 12], u32>,
    nominated: u32,
    asked: Option<Request>,
    request: Option<Request>,
    terms: Option<Terms>,
    routes: VecDeque<Route>,
    pieces: VecDeque<Piece>,
    channels: HashMap<ChannelId, u64>,
    channel_by_stream: HashMap<u64, ChannelId>,
    held: HashMap<u64, VecDeque<(bool, Vec<u8>)>>,
    next_channel: u64,
    medias: HashMap<Mid, u64>,
    media_by_stream: HashMap<u64, Mid>,
    media_clock: HashMap<u64, u64>,
    next_timeout: Option<Instant>,
    failed: Option<Failed>,
    ended: bool,
}

impl std::fmt::Debug for Framing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framing")
            .field("side", &self.side)
            .field("bound", &self.bound)
            .field("verified", &self.verified)
            .field("keyed", &self.keyed)
            .finish_non_exhaustive()
    }
}

impl Drop for Framing {
    /// This framing's own copy of its check secret is cleared with it (the keying material is the
    /// shim's, held zeroising).
    fn drop(&mut self) {
        self.local_creds.pass.zeroize();
    }
}

fn hex_pair(s: &str) -> Option<u8> {
    u8::from_str_radix(s, 16).ok()
}

/// A description's line values for `prefix` (`a=ice-ufrag:` and the like), in order.
fn values<'a>(description: &'a str, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    description
        .lines()
        .filter_map(move |l| l.trim_end_matches('\r').strip_prefix(prefix))
}

/// The terms a description pair settles, read from the far end's description text.
fn read_remote(
    description: &str,
) -> Result<(String, Zeroizing<String>, [u8; 32], Vec<SocketAddr>), Failed> {
    let user = values(description, "a=ice-ufrag:")
        .next()
        .ok_or("the far end's description has no check user")?
        .trim()
        .to_owned();
    let secret = Zeroizing::new(
        values(description, "a=ice-pwd:")
            .next()
            .ok_or("the far end's description has no check secret")?
            .trim()
            .to_owned(),
    );
    let print = values(description, "a=fingerprint:")
        .find_map(|v| {
            let (alg, hex) = v.trim().split_once(' ')?;
            alg.eq_ignore_ascii_case("sha-256").then_some(hex)
        })
        .ok_or("the far end's description has no sha-256 fingerprint")?;
    let bytes: Vec<u8> = print
        .split(':')
        .map(hex_pair)
        .collect::<Option<_>>()
        .ok_or("a malformed fingerprint")?;
    let fingerprint: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "a fingerprint that is not 32 bytes")?;
    let candidates = values(description, "a=candidate:")
        .filter_map(|v| {
            let f: Vec<&str> = v.split_whitespace().collect();
            let (proto, ip, port) = (f.get(2)?, f.get(4)?, f.get(5)?);
            if !proto.eq_ignore_ascii_case("udp") {
                return None;
            }
            format!("{ip}:{port}")
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| {
                    let ip: core::net::IpAddr = ip.parse().ok()?;
                    Some(SocketAddr::new(ip, port.parse().ok()?))
                })
        })
        .collect();
    Ok((user, secret, fingerprint, candidates))
}

/// A fresh check credential: `n` random bytes as lower-case hex (RFC 8445 §5.3: the user at least
/// 24 bits, the secret at least 128).
fn credential(n: usize) -> Result<String, Failed> {
    let bytes: [u8; 32] = crate::crypto::random().ok_or("the host has no randomness")?;
    Ok(bytes[..n].iter().map(|b| format!("{b:02x}")).collect())
}

/// How many 48 kHz samples an Opus packet spans, from its table-of-contents byte (RFC 6716 §3.1).
/// No codec runs: the frame is passed through, and this is only its length in time.
#[must_use]
pub fn opus_samples(packet: &[u8]) -> u64 {
    let Some(&toc) = packet.first() else {
        return 0;
    };
    let config = toc >> 3;
    // Frame length in units of 2.5 ms (120 samples).
    let unit = match config {
        0..=11 => [4, 8, 16, 24][usize::from(config % 4)],
        12..=15 => [4, 8][usize::from(config % 2)],
        _ => [1, 2, 4, 8][usize::from(config % 4)],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => packet.get(1).map_or(0, |b| u64::from(b & 0x3f)),
    };
    120 * unit * frames
}

impl Framing {
    /// Begin a framing on `side`. `certificate` is the host's public certificate (its fingerprint is
    /// what this end's description states); `opening` is what a dialling end offers.
    ///
    /// # Errors
    ///
    /// No randomness, or a dialling end with nothing to offer.
    pub fn begin(
        side: Side,
        certificate: &[u8],
        local: Option<SocketAddr>,
        opening: &Opening,
        now: Instant,
    ) -> Result<Self, Failed> {
        let local_creds = IceCreds {
            ufrag: credential(4)?,
            pass: credential(16)?,
        };
        let shim = Shim::default();
        shim::arm(shim.clone());
        let config = Rtc::builder().set_crypto_provider(Arc::new(crate::crypto::provider()));
        let mut config = shim::present(config, certificate)
            .set_local_ice_credentials(local_creds.clone())
            .set_ice_lite(side == Side::Accept)
            .clear_codecs()
            .enable_opus(true, false);
        config = config.set_stats_interval(None);
        let rtc = config.build(now);
        let _ = shim::take_pending();
        let mut f = Framing {
            side,
            rtc,
            shim,
            local: None,
            local_creds,
            pending: None,
            described: false,
            paths: HashMap::new(),
            addrs: HashMap::new(),
            bound: 0,
            verified: false,
            keyed: false,
            ice: IceConnectionState::New,
            nominating: HashMap::new(),
            nominated: 0,
            asked: None,
            request: None,
            terms: None,
            routes: VecDeque::new(),
            pieces: VecDeque::new(),
            channels: HashMap::new(),
            channel_by_stream: HashMap::new(),
            held: HashMap::new(),
            next_channel: 1,
            medias: HashMap::new(),
            media_by_stream: HashMap::new(),
            media_clock: HashMap::new(),
            next_timeout: None,
            failed: None,
            ended: false,
        };
        if let Some(addr) = local {
            f.local(addr);
        }
        if side == Side::Dial {
            if opening.channels.is_empty() && !opening.audio {
                return Err("a dialling framing offers nothing".into());
            }
            let mut api = f.rtc.sdp_api();
            let mut mids = Vec::new();
            if opening.audio {
                mids.push(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None));
            }
            let mut ids = Vec::new();
            for label in &opening.channels {
                ids.push(api.add_channel(label.clone()));
            }
            let (offer, pending) = api.apply().ok_or("the offer could not be built")?;
            f.pending = Some(pending);
            f.describe(offer.to_sdp_string());
            for (n, mid) in mids.into_iter().enumerate() {
                let s = f.media(mid, n as u64);
                f.head(s, &[("kind", "audio"), ("codec", "opus")]);
            }
            for id in ids {
                f.channel_stream(id);
            }
        }
        Ok(f)
    }

    fn describe(&mut self, description: String) {
        let description = self.with_candidate(description);
        self.described = true;
        self.pieces.push_back(Piece {
            stream: DESCRIPTION,
            bytes: description.into_bytes(),
            fields: false,
            text: true,
        });
    }

    /// A description with this end's one host candidate, when the host has told it its port.
    fn with_candidate(&self, description: String) -> String {
        let Some(local) = self.local else {
            return description;
        };
        if description.contains("a=candidate:") {
            return description;
        }
        let line = format!(
            "a=candidate:1 1 udp 2130706431 {} {} typ host\r\n",
            local.ip(),
            local.port()
        );
        let mut out = String::with_capacity(description.len() + line.len() * 2);
        for l in description.split_inclusive('\n') {
            out.push_str(l);
            if l.starts_with("a=ice-pwd:") {
                out.push_str(&line);
            }
        }
        out
    }

    /// The host port's own address: the one candidate this end advertises.
    pub fn local(&mut self, addr: SocketAddr) {
        if self.local.is_some() {
            return;
        }
        self.local = Some(addr);
        if let Ok(c) = Candidate::host(addr, "udp") {
            self.rtc.add_local_candidate(c);
        }
    }

    /// Paths the host knows.
    pub fn paths(&mut self, paths: impl IntoIterator<Item = (u32, SocketAddr)>) {
        for (path, addr) in paths {
            if path != 0 {
                self.paths.insert(path, addr);
                self.addrs.insert(addr, path);
            }
        }
    }

    /// The far end's session description.
    ///
    /// # Errors
    ///
    /// A description the media stack refuses, or one with no terms.
    pub fn rendezvous(&mut self, description: &[u8], now: Instant) -> Result<(), Failed> {
        let text =
            std::str::from_utf8(description).map_err(|_| "a description that is not text")?;
        let (remote_user, remote_secret, peer_fingerprint, candidates) = read_remote(text)?;
        match self.side {
            Side::Accept => {
                if self.described {
                    return Err("a second offer on one association".into());
                }
                let offer = SdpOffer::from_sdp_string(text)
                    .map_err(|e| format!("the offer did not parse: {e}"))?;
                let answer = self
                    .rtc
                    .sdp_api()
                    .accept_offer(offer)
                    .map_err(|e| format!("the offer was refused: {e}"))?;
                self.describe(answer.to_sdp_string());
            }
            Side::Dial => {
                let pending = self.pending.take().ok_or("an answer with no offer out")?;
                let answer = SdpAnswer::from_sdp_string(text)
                    .map_err(|e| format!("the answer did not parse: {e}"))?;
                self.rtc
                    .sdp_api()
                    .accept_answer(pending, answer)
                    .map_err(|e| format!("the answer was refused: {e}"))?;
            }
        }
        let initiates = self
            .shim
            .active()
            .ok_or("the description settled no handshake role")?;
        self.terms = Some(Terms {
            initiates,
            local_user: self.local_creds.ufrag.clone(),
            local_secret: Zeroizing::new(self.local_creds.pass.clone()),
            remote_user,
            remote_secret,
            peer_fingerprint,
            candidates,
        });
        self.drain(now);
        Ok(())
    }

    /// The host's state at this call: the bound path, the verified bit, and the keying-material item
    /// when it presents one (`(profile, material)`).
    ///
    /// # Errors
    ///
    /// Keying under a profile other than AEAD-AES-GCM, keying before verification, or a second
    /// keying.
    pub fn host(
        &mut self,
        bound: u32,
        verified: bool,
        keying: Option<(u32, &[u8])>,
        now: Instant,
    ) -> Result<(), Failed> {
        if bound != self.bound {
            self.bound = bound;
            if self.asked.is_some_and(|r| target(r) == bound) {
                self.asked = None;
            }
        }
        if verified && !self.verified {
            self.verified = true;
        }
        if let Some((profile, material)) = keying {
            let material = Zeroizing::new(material.to_vec());
            if !self.verified {
                return Err("keying material before the far end was verified".into());
            }
            if self.keyed {
                return Err("keying material twice".into());
            }
            self.shim.keyed(&material, profile)?;
            self.keyed = true;
        }
        if self.verified && self.keyed {
            self.shim.connected();
        }
        self.drain(now);
        Ok(())
    }

    /// One datagram from `path` on `lane`.
    pub fn datagram(
        &mut self,
        path: u32,
        from: SocketAddr,
        lane: Lane,
        bytes: &[u8],
        now: Instant,
    ) {
        if self.failed.is_some() || bytes.is_empty() {
            return;
        }
        if path != 0 {
            self.paths.insert(path, from);
            self.addrs.insert(from, path);
        }
        match lane {
            Lane::Secured => {
                // Application data waits for peer verification.
                if self.verified && self.keyed {
                    self.shim.opened(bytes);
                    self.drain(now);
                }
            }
            Lane::Clear if stun::is_stun(bytes) => {
                match stun::read(bytes) {
                    Some(Check::Request {
                        txid,
                        nominates: true,
                    }) if self.side == Side::Accept => {
                        self.track(txid, path);
                    }
                    Some(Check::Success { txid }) if self.side == Side::Dial => {
                        if self.nominating.get(&txid) == Some(&path) {
                            self.nominating.remove(&txid);
                            self.feed(from, bytes, now);
                            if matches!(
                                self.ice,
                                IceConnectionState::Connected | IceConnectionState::Completed
                            ) {
                                self.nominate(path);
                            }
                            return;
                        }
                    }
                    _ => {}
                }
                self.feed(from, bytes, now);
            }
            Lane::Clear => {
                // Protected media: read only once verified and keyed, and only from the bound path.
                if self.verified && self.keyed && path == self.bound && path != 0 {
                    self.feed(from, bytes, now);
                }
            }
        }
    }

    fn feed(&mut self, from: SocketAddr, bytes: &[u8], now: Instant) {
        let Some(local) = self.local else {
            return;
        };
        let Ok(receive) = Receive::new(Protocol::Udp, from, local, bytes) else {
            return;
        };
        if let Err(e) = self.rtc.handle_input(Input::Receive(now, receive)) {
            self.fail(format!("the media stack refused a datagram: {e}"));
            return;
        }
        self.drain(now);
    }

    /// Remember a nominating check, holding the set bounded (a flood of checks evicts the set,
    /// never grows it).
    fn track(&mut self, txid: [u8; 12], path: u32) {
        if self.nominating.len() >= MAX_NOMINATING {
            self.nominating.clear();
        }
        self.nominating.insert(txid, path);
    }

    fn nominate(&mut self, path: u32) {
        self.nominated = path;
        let want = if self.bound == 0 {
            Request::Bind(path)
        } else if self.bound != path {
            Request::Rebind(self.bound, path)
        } else {
            return;
        };
        if self.asked != Some(want) {
            self.asked = Some(want);
            self.request = Some(want);
        }
    }

    /// A message for the far end on `stream`.
    ///
    /// # Errors
    ///
    /// A stream this framing does not carry, or a media frame the stack refuses.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        text: bool,
        now: Instant,
    ) -> Result<(), Failed> {
        if let Some(mid) = self.media_by_stream.get(&stream).copied() {
            if !(self.verified && self.keyed) {
                return Ok(());
            }
            let clock = self.media_clock.entry(stream).or_insert(0);
            let at = *clock;
            *clock = clock.wrapping_add(opus_samples(bytes));
            let Some(writer) = self.rtc.writer(mid) else {
                return Ok(());
            };
            let pt: Option<Pt> = writer
                .payload_params()
                .find(|p| p.spec().codec == Codec::Opus)
                .map(|p| p.pt());
            let Some(pt) = pt else {
                return Err("the media line carries no Opus".into());
            };
            writer
                .write(
                    pt,
                    now,
                    MediaTime::new(at, Frequency::FORTY_EIGHT_KHZ),
                    bytes.to_vec(),
                )
                .map_err(|e| format!("the media frame was refused: {e}"))?;
            self.drain(now);
            return Ok(());
        }
        let Some(id) = self.channel_by_stream.get(&stream).copied() else {
            return Err(format!("no stream {stream} on this association"));
        };
        let sent = match self.rtc.channel(id) {
            Some(mut ch) => ch
                .write(!text, bytes)
                .map_err(|e| format!("the channel refused the message: {e}"))?,
            None => false,
        };
        if !sent {
            let held = self.held.entry(stream).or_default();
            if held.len() >= MAX_HELD {
                return Err("too many messages held for a channel not yet open".into());
            }
            held.push_back((text, bytes.to_vec()));
        }
        self.drain(now);
        Ok(())
    }

    /// The clock reached `now`.
    pub fn timeout(&mut self, now: Instant) {
        if self.failed.is_some() {
            return;
        }
        if let Err(e) = self.rtc.handle_input(Input::Timeout(now)) {
            self.fail(format!("the media stack failed: {e}"));
            return;
        }
        self.drain(now);
    }

    /// Close the association.
    pub fn finish(&mut self, now: Instant) {
        let _ = self.rtc.close();
        self.drain(now);
        self.ended = true;
    }

    fn fail(&mut self, why: Failed) {
        self.rtc.disconnect();
        self.failed = Some(why);
        self.routes.clear();
    }

    fn channel_stream(&mut self, id: ChannelId) -> u64 {
        if let Some(s) = self.channels.get(&id) {
            return *s;
        }
        let s = self.next_channel;
        self.next_channel += 1;
        self.channels.insert(id, s);
        self.channel_by_stream.insert(s, id);
        s
    }

    fn media(&mut self, mid: Mid, n: u64) -> u64 {
        let s = MEDIA_BASE + n;
        self.medias.insert(mid, s);
        self.media_by_stream.insert(s, mid);
        s
    }

    fn head(&mut self, stream: u64, fields: &[(&str, &str)]) {
        let mut block = Vec::new();
        for (n, v) in fields {
            block.extend_from_slice(n.as_bytes());
            block.extend_from_slice(b": ");
            block.extend_from_slice(v.as_bytes());
            block.extend_from_slice(b"\r\n");
        }
        self.pieces.push_back(Piece {
            stream,
            bytes: block,
            fields: true,
            text: false,
        });
    }

    /// Run the media stack until it waits, collecting what it owes.
    fn drain(&mut self, now: Instant) {
        // Messages held for channels that have since opened.
        let open: Vec<u64> = self.held.keys().copied().collect();
        for stream in open {
            let Some(id) = self.channel_by_stream.get(&stream).copied() else {
                continue;
            };
            while let Some((text, bytes)) = self.held.get_mut(&stream).and_then(VecDeque::pop_front)
            {
                let sent = self
                    .rtc
                    .channel(id)
                    .is_some_and(|mut ch| ch.write(!text, &bytes).unwrap_or(false));
                if !sent {
                    if let Some(q) = self.held.get_mut(&stream) {
                        q.push_front((text, bytes));
                    }
                    break;
                }
            }
        }
        for _ in 0..10_000 {
            let out = match self.rtc.poll_output() {
                Ok(o) => o,
                Err(e) => {
                    self.fail(format!("the media stack failed: {e}"));
                    return;
                }
            };
            // What the stack handed the shim to seal during this poll (an SCTP packet is queued
            // there, never transmitted), routed whatever the poll answered.
            let waits = match out {
                Output::Timeout(t) => {
                    self.next_timeout = Some(t.max(now));
                    true
                }
                Output::Transmit(t) => {
                    self.transmit(t.destination, &t.contents);
                    false
                }
                Output::Event(e) => {
                    self.event(e);
                    false
                }
            };
            while let Some(plain) = self.shim.take_to_seal() {
                if self.bound != 0 && self.routes.len() < MAX_HELD * 4 {
                    self.routes.push_back(Route {
                        bytes: plain,
                        path: self.bound,
                        lane: Lane::Secured,
                    });
                }
            }
            if waits {
                break;
            }
        }
        if !self.rtc.is_alive() && self.failed.is_none() {
            self.ended = true;
        }
    }

    fn transmit(&mut self, to: SocketAddr, bytes: &[u8]) {
        if self.routes.len() >= MAX_HELD * 4 {
            return;
        }
        if stun::is_stun(bytes) {
            let Some(path) = self.addrs.get(&to).copied() else {
                // An address the host never judged or heard: nothing goes there.
                return;
            };
            match stun::read(bytes) {
                Some(Check::Success { txid }) if self.side == Side::Accept => {
                    if self.nominating.remove(&txid) == Some(path) {
                        self.nominate(path);
                    }
                }
                Some(Check::Request {
                    txid,
                    nominates: true,
                }) if self.side == Side::Dial => {
                    self.track(txid, path);
                }
                _ => {}
            }
            self.routes.push_back(Route {
                bytes: bytes.to_vec(),
                path,
                lane: Lane::Clear,
            });
            return;
        }
        // Protected media goes to the host's bound path, whatever the stack chose.
        if self.bound != 0 && self.verified && self.keyed {
            self.routes.push_back(Route {
                bytes: bytes.to_vec(),
                path: self.bound,
                lane: Lane::Clear,
            });
        }
    }

    fn event(&mut self, e: Event) {
        match e {
            Event::IceConnectionStateChange(s) => {
                self.ice = s;
                if s == IceConnectionState::Disconnected {
                    self.ended = true;
                }
            }
            Event::ChannelOpen(id, label) => {
                let s = self.channel_stream(id);
                self.head(s, &[("label", &label)]);
            }
            Event::ChannelData(d) => {
                // Application data waits for peer verification (the shim hands none up before it,
                // so this is the second lock on the same door).
                if !(self.verified && self.keyed) || self.pieces.len() >= MAX_HELD * 4 {
                    return;
                }
                let s = self.channel_stream(d.id);
                self.pieces.push_back(Piece {
                    stream: s,
                    bytes: d.data,
                    fields: false,
                    text: !d.binary,
                });
            }
            Event::ChannelClose(id) => {
                if let Some(s) = self.channels.get(&id).copied() {
                    self.pieces.push_back(Piece {
                        stream: s,
                        bytes: Vec::new(),
                        fields: false,
                        text: false,
                    });
                }
            }
            Event::MediaAdded(m) => {
                if m.kind == MediaKind::Audio && !self.medias.contains_key(&m.mid) {
                    let n = self.medias.len() as u64;
                    let s = self.media(m.mid, n);
                    self.head(s, &[("kind", "audio"), ("codec", "opus")]);
                }
            }
            Event::MediaData(d) => {
                if !(self.verified && self.keyed) || self.pieces.len() >= MAX_HELD * 4 {
                    return;
                }
                if let Some(s) = self.medias.get(&d.mid).copied() {
                    self.pieces.push_back(Piece {
                        stream: s,
                        bytes: d.data.to_vec(),
                        fields: false,
                        text: false,
                    });
                }
            }
            Event::Closed => self.ended = true,
            _ => {}
        }
    }

    // ── what the framing owes ───────────────────────────────────────────────────────────────────

    /// The next route.
    pub fn next_route(&mut self) -> Option<Route> {
        self.routes.pop_front()
    }

    /// Put a route back at the front (the host's buffer was full).
    pub fn unroute(&mut self, r: Route) {
        self.routes.push_front(r);
    }

    /// The next piece.
    pub fn next_piece(&mut self) -> Option<Piece> {
        self.pieces.pop_front()
    }

    /// Put a piece back at the front.
    pub fn unpiece(&mut self, p: Piece) {
        self.pieces.push_front(p);
    }

    /// Whether anything is still owed.
    #[must_use]
    pub fn owes(&self) -> bool {
        !self.routes.is_empty() || !self.pieces.is_empty() || self.terms.is_some()
    }

    /// The path request, taken.
    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The rendezvous terms, taken.
    pub fn take_terms(&mut self) -> Option<Terms> {
        self.terms.take()
    }

    /// Put the terms back (the host's frame buffer could not hold them whole).
    pub fn restore_terms(&mut self, t: Terms) {
        self.terms = Some(t);
    }

    /// When [`Self::timeout`] is next owed.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        self.next_timeout
    }

    /// Why the framing failed.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Whether the association ended.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// The path the far end nominated last, as this framer's ICE agent accepted it.
    #[must_use]
    pub fn nominated(&self) -> u32 {
        self.nominated
    }

    /// Whether keying material is held un-handed (it is cleared once the stack took it).
    #[must_use]
    pub fn holds_keying(&self) -> bool {
        self.shim.holds_keying()
    }

    /// How long until `deadline`, from `now`.
    #[must_use]
    pub fn until(deadline: Instant, now: Instant) -> Duration {
        deadline.saturating_duration_since(now)
    }
}

fn target(r: Request) -> u32 {
    match r {
        Request::Bind(p) | Request::Rebind(_, p) => p,
    }
}

#[cfg(test)]
#[path = "tests/framing_tests.rs"]
mod tests;
