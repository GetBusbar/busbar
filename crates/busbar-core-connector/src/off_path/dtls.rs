// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dtls` off-path code (see `crate::off_path`): what an association builds once (its
//! handshake certificate) and the consent probe its timers and path discovery
//! send (a probe per consent interval, or per newly heard path; no datagram's own handling).

use busbar_contract::crypto;

use crate::dtls::stun::{
    attr, set_len, Keys, BINDING_REQUEST, FINGERPRINT, FINGERPRINT_XOR, HEADER, ICE_CONTROLLED,
    ICE_CONTROLLING, MAGIC_COOKIE, MESSAGE_INTEGRITY, MI_LEN, PRIORITY, PROBE_PRIORITY, USERNAME,
};

/// The handshake certificate in the DTLS engine's form (DER and key): built once, when the
/// association's handshake begins.
pub(crate) fn certificate(cert: &crypto::dtls::DtlsCert) -> dimpl::DtlsCertificate {
    let certificate = cert.der().to_vec();
    dimpl::DtlsCertificate {
        certificate,
        private_key: cert.handle().to_vec(),
    }
}

/// A consent probe: a Binding request to the peer under the REMOTE credentials (USERNAME
/// …). `None` when the crypto backend does not provide HMAC-SHA1.
pub(crate) fn probe(
    keys: &Keys,
    txid: [u8; 12],
    tie_breaker: [u8; 8],
    controlling: bool,
) -> Option<Vec<u8>> {
    let mut m = Vec::with_capacity(128);
    m.extend_from_slice(&BINDING_REQUEST);
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&MAGIC_COOKIE);
    m.extend_from_slice(&txid);
    attr(&mut m, USERNAME, &keys.probe_username);
    attr(&mut m, PRIORITY, &PROBE_PRIORITY.to_be_bytes());
    let role = if controlling {
        ICE_CONTROLLING
    } else {
        ICE_CONTROLLED
    };
    attr(&mut m, role, &tie_breaker);
    let body = m.len() - HEADER + 4 + MI_LEN;
    set_len(&mut m, body);
    let mac = crypto::legacy::hmac_sha1(&keys.remote, &m).ok()?;
    attr(&mut m, MESSAGE_INTEGRITY, &mac);
    let body = m.len() - HEADER + 8;
    set_len(&mut m, body);
    let crc = crc32fast::hash(&m) ^ FINGERPRINT_XOR;
    attr(&mut m, FINGERPRINT, &crc.to_be_bytes());
    Some(m)
}
