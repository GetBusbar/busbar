// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The proxy dial's off-path bytes (`crate::proxy`): the CONNECT a dial through the operator's
//! proxy writes once, as the tunnel is opened, never per request on the tunnel.

use crate::proxy::ProxyHop;

/// `CONNECT host:port HTTP/1.1` (+ Host, + Proxy-Authorization when configured), the bytes the
/// connector writes to the proxy to open a tunnel to `target`.
#[must_use]
pub fn connect_request(target: &str, proxy: &ProxyHop) -> Vec<u8> {
    // The connection owns these bytes until the tunnel is written: one exactly sized buffer, the
    // hop's tail spelled once with the hop.
    const CONNECT: &[u8] = b"CONNECT ";
    const HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
    const EOL: &[u8] = b"\r\n";
    let tail = proxy.connect_tail().as_bytes();
    let mut req =
        Vec::with_capacity(CONNECT.len() + HOST.len() + EOL.len() + 2 * target.len() + tail.len());
    req.extend_from_slice(CONNECT);
    req.extend_from_slice(target.as_bytes());
    req.extend_from_slice(HOST);
    req.extend_from_slice(target.as_bytes());
    req.extend_from_slice(EOL);
    req.extend_from_slice(tail);
    req
}
