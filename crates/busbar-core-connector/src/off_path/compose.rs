// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The composed connection's off-path text and lists (`crate::compose`): what a connection's
//! dial, accept, TLS upgrade or handshake settlement copies once, as the connection is built or
//! its handshake completes, never per byte or message it then carries.

/// An owned copy of `text`, kept by a connection's own record (its authority, offered name,
/// claim or sealed field name) as the connection is dialled, upgraded or sealed.
pub(crate) fn owned(text: &str) -> String {
    text.to_owned()
}

/// The destination text of a dial of the UNIX-domain socket at `path`.
pub(crate) fn unix_authority(path: &str) -> String {
    format!("{}{path}", crate::socket::UNIX_TARGET)
}

/// The protocol a finished TLS handshake agreed, if any.
pub(crate) fn agreed_alpn(tls: &rustls::Connection) -> Option<Vec<u8>> {
    tls.alpn_protocol().map(<[u8]>::to_vec)
}

/// The listener's protocol offer an accepted connection keeps, in order.
pub(crate) fn offer_of(alpn: &[Vec<u8>]) -> Vec<Vec<u8>> {
    alpn.to_vec()
}
