// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The STUN core speaks itself: recognising a connectivity check addressed to THIS session, and

use busbar_contract::crypto;
use busbar_contract::secure::SecureVec;

/// STUN's magic cookie (RFC 8489 §5).
pub(crate) const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
/// A Binding request (method 0x001, class request).
pub(crate) const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
/// A Binding success response.
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
/// The USERNAME attribute.
pub(crate) const USERNAME: u16 = 0x0006;
/// The MESSAGE-INTEGRITY attribute (HMAC-SHA1, 20 bytes).
pub(crate) const MESSAGE_INTEGRITY: u16 = 0x0008;
/// PRIORITY.
pub(crate) const PRIORITY: u16 = 0x0024;
/// ICE-CONTROLLED.
pub(crate) const ICE_CONTROLLED: u16 = 0x8029;
/// ICE-CONTROLLING.
pub(crate) const ICE_CONTROLLING: u16 = 0x802a;
/// FINGERPRINT.
pub(crate) const FINGERPRINT: u16 = 0x8028;
/// FINGERPRINT's XOR constant (RFC 8489 §14.7).
pub(crate) const FINGERPRINT_XOR: u32 = 0x5354_554e;
/// The header length.
pub(crate) const HEADER: usize = 20;
/// MESSAGE-INTEGRITY's value length.
pub(crate) const MI_LEN: usize = 20;
/// A probe states peer-reflexive priority (RFC 8445 §7.1.1), using the same UDP type preference
pub(crate) const PROBE_PRIORITY: u32 = 0x6eff_ffff;

/// One side's ICE credentials.
#[derive(Clone)]
pub struct IceCredentials {
    /// The username fragment (`a=ice-ufrag`): shared text, made once when the terms are read, so
    /// the association that is found by it shares it and copies nothing.
    pub ufrag: busbar_contract::kept::Text,
    /// The password (`a=ice-pwd`), an HMAC key.
    pub pwd: String,
}

impl std::fmt::Debug for IceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag.as_str())
            .finish_non_exhaustive()
    }
}

impl IceCredentials {
    /// The credentials, borrowed.
    #[must_use]
    pub fn terms(&self) -> IceTerms<'_> {
        IceTerms {
            ufrag: &self.ufrag,
            pwd: &self.pwd,
        }
    }
}

/// One side's ICE credentials, borrowed: what an ICE_TERMS names, read where it was kept (a
/// session's act buffer); the association copies only what its keys hold.
#[derive(Clone, Copy)]
pub struct IceTerms<'a> {
    /// The username fragment (`a=ice-ufrag`).
    pub ufrag: &'a str,
    /// The password (`a=ice-pwd`), an HMAC key.
    pub pwd: &'a str,
}

/// The keys an association checks and signs with: built when it is, replaced in place (their
/// buffers reused) by a later ICE_TERMS.
pub(crate) struct Keys {
    local_ufrag_prefix: Vec<u8>,
    /// The local ICE password: the MESSAGE-INTEGRITY (HMAC-SHA1) key of checks to us.
    local: SecureVec,
    /// The remote ICE password: the key of our probes and of their answers.
    pub(crate) remote: SecureVec,
    pub(crate) probe_username: Vec<u8>,
}

impl Keys {
    pub(crate) fn new(local: IceTerms<'_>, remote: IceTerms<'_>) -> Self {
        let mut keys = Keys {
            local_ufrag_prefix: Vec::new(),
            local: SecureVec::from(local.pwd.as_bytes()),
            remote: SecureVec::from(remote.pwd.as_bytes()),
            probe_username: Vec::new(),
        };
        keys.name(local, remote);
        keys
    }

    /// Both sides' credentials replaced: the passwords re-keyed, the user names rewritten into
    /// the buffers they already have.
    pub(crate) fn set(&mut self, local: IceTerms<'_>, remote: IceTerms<'_>) {
        self.local = SecureVec::from(local.pwd.as_bytes());
        self.remote = SecureVec::from(remote.pwd.as_bytes());
        self.name(local, remote);
    }

    /// The local USERNAME prefix a check to us names (`local:`), and the USERNAME our probes carry
    /// (`remote:local`).
    fn name(&mut self, local: IceTerms<'_>, remote: IceTerms<'_>) {
        self.local_ufrag_prefix.clear();
        self.local_ufrag_prefix
            .extend_from_slice(local.ufrag.as_bytes());
        self.local_ufrag_prefix.push(b':');
        self.probe_username.clear();
        self.probe_username
            .extend_from_slice(remote.ufrag.as_bytes());
        self.probe_username.push(b':');
        self.probe_username
            .extend_from_slice(local.ufrag.as_bytes());
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
fn integrity_ok(d: &[u8], mi_at: usize, mac: &[u8], key: &[u8]) -> bool {
    let Ok(covered_len) = u16::try_from(mi_at + 4 + MI_LEN - HEADER) else {
        return false;
    };

    let mut covered = [0_u8; 512];
    let Some(dst) = covered.get_mut(..mi_at) else {
        return false;
    };
    dst.copy_from_slice(&d[..mi_at]);
    dst[2..4].copy_from_slice(&covered_len.to_be_bytes());
    crypto::legacy::hmac_sha1(key, dst).is_ok_and(|tag| crypto::ct_eq(&tag, mac))
}

/// `true` when `d` is a Binding request whose USERNAME names the local ufrag first and whose
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
                    && integrity_ok(d, at, value, &keys.local);
            }
            _ => {}
        }
    }
    false
}

/// The local ufrag a Binding request's USERNAME names first (`<local>:<remote>`), the key a shared media
/// port routes the check by. `None` for anything that is not a well-formed Binding request with a USERNAME.
/// Nothing is verified here: the session the key finds verifies MESSAGE-INTEGRITY itself.
pub(crate) fn local_ufrag(d: &[u8]) -> Option<&[u8]> {
    let attrs = walk(d, BINDING_REQUEST)?;
    for (kind, _, value) in attrs {
        if kind == USERNAME {
            let end = value.iter().position(|b| *b == b':')?;
            return value.get(..end).filter(|u| !u.is_empty());
        }
    }
    None
}

/// The transaction id of `d` if it is a Binding success response whose MESSAGE-INTEGRITY verifies
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

/// Is `d` a Binding request (whoever it is for)?
pub(crate) fn is_binding_request(d: &[u8]) -> bool {
    d.len() >= HEADER && d[0..2] == BINDING_REQUEST && d[4..8] == MAGIC_COOKIE
}

/// Is `d` a Binding success response (whoever it answers)?
pub(crate) fn is_binding_success(d: &[u8]) -> bool {
    d.len() >= HEADER && d[0..2] == BINDING_SUCCESS && d[4..8] == MAGIC_COOKIE
}

pub(crate) fn attr(m: &mut Vec<u8>, kind: u16, value: &[u8]) {
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
    m.extend_from_slice(value);
    m.resize(m.len().div_ceil(4) * 4, 0);
}

pub(crate) fn set_len(m: &mut [u8], body: usize) {
    m[2..4].copy_from_slice(&u16::try_from(body).unwrap_or(0).to_be_bytes());
}
