// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// Evidence supplied by the accepted connection, never by request headers.
#[derive(Clone)]
pub(crate) struct RequestContext {
    pub(crate) peer: Box<str>,
    pub(crate) tls_peer_cert: bytes::Bytes,
}
