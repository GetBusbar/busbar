// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! UNIX-DOMAIN DESTINATIONS of an OPEN (IF 12.1, round 24; TRANSPORT-SECURITY-POLICY 8 test 3).
//!
//! An OPEN whose dest starts `unix:` is admitted only if, in this order: (1) the grammar holds
//! (`socket::unix_path`, no NUL, at most 107 path bytes) else INVALID; (2) the Need is TLS_NONE
//! with no secret, trust, SNI or ALPN else INVALID; (3) the stated class is
//! OPERATOR_INFRASTRUCTURE else DENIED; and (5) on a pool miss the instance's own configured
//! `unix_paths` name it (`ConfigBinder::unix_path`) else DENIED. There is no rule (4): the caller's
//! kind is never consulted, and `accept: plaintext` is what admits a `unix:` dest at all (the
//! transport gate, `policy`). No DNS, no guard address check, no `not_the_node`: there is no
//! address.

use busbar_plugin_abi::host_side::needs::{NeedErr, TlsMode};
use busbar_plugin_abi::need::egress::OPERATOR_INFRASTRUCTURE;

use crate::socket::{unix_path, UNIX_TARGET};

/// `sun_path` holds 108 bytes including its NUL.
const MAX_PATH: usize = 107;

/// Whether `dest` names a unix-domain socket (the prefix, compared ASCII case-insensitively, as the
/// transport gate does).
#[must_use]
pub fn names_unix(dest: &str) -> bool {
    dest.get(..UNIX_TARGET.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(UNIX_TARGET))
}

/// Rules (1) to (3) for a dest that names a unix socket: the socket path, or the refusal.
///
/// # Errors
/// `Invalid` for rules (1) and (2), `Denied` for rule (3).
pub fn unix_rules<'d>(dest: &'d str, tls: &TlsMode<'_>, egress: u32) -> Result<&'d str, NeedErr> {
    let path = unix_path(dest).ok_or(NeedErr::Invalid)?;
    if path.contains('\0') || path.len() > MAX_PATH {
        return Err(NeedErr::Invalid);
    }
    if !matches!(tls, TlsMode::None) {
        return Err(NeedErr::Invalid);
    }
    if egress != OPERATOR_INFRASTRUCTURE {
        return Err(NeedErr::Denied);
    }
    Ok(path)
}

#[cfg(test)]
#[path = "../tests/need_unix_tests.rs"]
mod tests;
