// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The STUN core speaks itself: recognising a connectivity check addressed to THIS session, and
//! the round trip that proves the far end OWNS the address a check came from.
//!
//! A verified inbound check (USERNAME names the local ufrag first, MESSAGE-INTEGRITY verifies under
//! the local password) proves only that the sender knows the local password — which the peer
//! learned from the SDP answer, and which a replayed or source-spoofed datagram also carries. It
//! does not prove the source address is the peer's. Ownership needs a round trip (RFC 8445 §7.2.5,
//! RFC 7675): core sends its own Binding request to the address, under the REMOTE credentials, and
//! only a success response from that same address, carrying the same transaction id and a
//! MESSAGE-INTEGRITY under the remote password, proves it. An ICE-lite agent sends no checks of its
//! own for ICE's sake; these are consent probes, answered by every full ICE agent.

use ring::hmac;

/// STUN's magic cookie (RFC 8489 §5).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
/// A Binding request (method 0x001, class request).
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
/// A Binding success response.
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
/// The USERNAME attribute.
const USERNAME: u16 = 0x0006;
/// The MESSAGE-INTEGRITY attribute (HMAC-SHA1, 20 bytes).
const MESSAGE_INTEGRITY: u16 = 0x0008;
/// PRIORITY.
const PRIORITY: u16 = 0x0024;
/// ICE-CONTROLLED.
const ICE_CONTROLLED: u16 = 0x8029;
/// FINGERPRINT.
const FINGERPRINT: u16 = 0x8028;
/// FINGERPRINT's XOR constant (RFC 8489 §14.7).
const FINGERPRINT_XOR: u32 = 0x5354_554e;
/// The header length.
const HEADER: usize = 20;
/// MESSAGE-INTEGRITY's value length.
const MI_LEN: usize = 20;
/// A host candidate's priority for the probe's PRIORITY (RFC 8445 §5.1.2.1, type preference 126).
const PROBE_PRIORITY: u32 = 0x7eff_ffff;

/// One side's ICE credentials.
#[derive(Clone)]
pub struct IceCredentials {
    /// The username fragment (`a=ice-ufrag`).
    pub ufrag: String,
    /// The password (`a=ice-pwd`), an HMAC key.
    pub pwd: String,
}

impl std::fmt::Debug for IceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag)
            .finish_non_exhaustive()
    }
}

/// The keys an association checks and signs with, built once.
pub(crate) struct Keys {
    local_ufrag_prefix: Vec<u8>,
    local: hmac::Key,
    remote: hmac::Key,
    probe_username: Vec<u8>,
}

impl Keys {
    pub(crate) fn new(local: &IceCredentials, remote: &IceCredentials) -> Self {
        let mut local_ufrag_prefix = local.ufrag.clone().into_bytes();
        local_ufrag_prefix.push(b':');
        Keys {
            local_ufrag_prefix,
            local: hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, local.pwd.as_bytes()),
            remote: hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, remote.pwd.as_bytes()),
            probe_username: format!("{}:{}", remote.ufrag, local.ufrag).into_bytes(),
        }
    }
}

/// The attributes of a STUN message, walked once.
struct Walk<'a> {
    d: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Walk<'a> {
    /// (attribute type, offset of the attribute header, value)
    type Item = (u16, usize, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let at = self.at;
        let head = self.d.get(at..at + 4)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let value = self.d.get(at + 4..at + 4 + len)?;
        self.at = at + 4 + len.div_ceil(4) * 4;
        Some((kind, at, value))
    }
}

/// `d`'s attributes, if `d` is a well-formed STUN message of class/method `kind`.
fn walk(d: &[u8], kind: [u8; 2]) -> Option<Walk<'_>> {
    if d.len() < HEADER || d[0..2] != kind || d[4..8] != MAGIC_COOKIE {
        return None;
    }
    let body = usize::from(u16::from_be_bytes([d[2], d[3]]));
    if HEADER + body != d.len() || body % 4 != 0 {
        return None;
    }
    Some(Walk { d, at: HEADER })
}

/// Does the MESSAGE-INTEGRITY at `mi_at` verify under `key` (RFC 8489 §14.5: over the message up to
/// the attribute, the header length rewritten to end just after it)?
fn integrity_ok(d: &[u8], mi_at: usize, mac: &[u8], key: &hmac::Key) -> bool {
    let Ok(covered_len) = u16::try_from(mi_at + 4 + MI_LEN - HEADER) else {
        return false;
    };
    // A check or answer longer than 512 bytes before its MESSAGE-INTEGRITY verifies as nothing.
    let mut covered = [0_u8; 512];
    let Some(dst) = covered.get_mut(..mi_at) else {
        return false;
    };
    dst.copy_from_slice(&d[..mi_at]);
    dst[2..4].copy_from_slice(&covered_len.to_be_bytes());
    hmac::verify(key, dst, mac).is_ok()
}

/// `true` when `d` is a Binding request whose USERNAME names the local ufrag first and whose
/// MESSAGE-INTEGRITY verifies under the local password. Anything else is `false`.
pub(crate) fn is_verified_check(d: &[u8], keys: &Keys) -> bool {
    let Some(attrs) = walk(d, BINDING_REQUEST) else {
        return false;
    };
    let mut username_ok = false;
    for (kind, at, value) in attrs {
        match kind {
            USERNAME => username_ok = value.starts_with(&keys.local_ufrag_prefix),
            MESSAGE_INTEGRITY => {
                return value.len() == MI_LEN
                    && username_ok
                    && integrity_ok(d, at, value, &keys.local)
            }
            _ => {}
        }
    }
    false
}

/// The transaction id of `d` if it is a Binding success response whose MESSAGE-INTEGRITY verifies
/// under the REMOTE password — the answer to one of core's probes.
pub(crate) fn verified_probe_answer(d: &[u8], keys: &Keys) -> Option<[u8; 12]> {
    let attrs = walk(d, BINDING_SUCCESS)?;
    for (kind, at, value) in attrs {
        if kind == MESSAGE_INTEGRITY {
            if value.len() == MI_LEN && integrity_ok(d, at, value, &keys.remote) {
                let mut txid = [0_u8; 12];
                txid.copy_from_slice(&d[8..20]);
                return Some(txid);
            }
            return None;
        }
    }
    None
}

/// Is `d` a Binding success response (whoever it answers)?
pub(crate) fn is_binding_success(d: &[u8]) -> bool {
    d.len() >= HEADER && d[0..2] == BINDING_SUCCESS && d[4..8] == MAGIC_COOKIE
}

fn attr(m: &mut Vec<u8>, kind: u16, value: &[u8]) {
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
    m.extend_from_slice(value);
    m.resize(m.len().div_ceil(4) * 4, 0);
}

fn set_len(m: &mut [u8], body: usize) {
    m[2..4].copy_from_slice(&u16::try_from(body).unwrap_or(0).to_be_bytes());
}

/// A consent probe: a Binding request to the peer under the REMOTE credentials (USERNAME
/// "remote:local", MESSAGE-INTEGRITY with the remote password), as the controlled agent, with
/// FINGERPRINT.
pub(crate) fn probe(keys: &Keys, txid: [u8; 12], tie_breaker: [u8; 8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(128);
    m.extend_from_slice(&BINDING_REQUEST);
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&MAGIC_COOKIE);
    m.extend_from_slice(&txid);
    attr(&mut m, USERNAME, &keys.probe_username);
    attr(&mut m, PRIORITY, &PROBE_PRIORITY.to_be_bytes());
    attr(&mut m, ICE_CONTROLLED, &tie_breaker);
    let body = m.len() - HEADER + 4 + MI_LEN;
    set_len(&mut m, body);
    let mac = hmac::sign(&keys.remote, &m);
    attr(&mut m, MESSAGE_INTEGRITY, mac.as_ref());
    let body = m.len() - HEADER + 8;
    set_len(&mut m, body);
    let crc = crc32fast::hash(&m) ^ FINGERPRINT_XOR;
    attr(&mut m, FINGERPRINT, &crc.to_be_bytes());
    m
}
