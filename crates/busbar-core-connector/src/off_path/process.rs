// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! process: stub.

/// A destination host in its ASCII (IDNA) form, owned: judged once per dial.
pub(crate) fn host_text(host: std::borrow::Cow<'_, str>) -> String {
    host.into_owned()
}

/// The other addresses a name resolved to (not the one the dial pinned, none the node itself):
/// collected once per judged dial, when its answer arrives.
pub(crate) fn also_reachable(
    at: std::net::SocketAddr,
    addrs: &[std::net::IpAddr],
    mut reachable: impl FnMut(std::net::SocketAddr) -> bool,
) -> Vec<std::net::SocketAddr> {
    addrs
        .iter()
        .map(|ip| std::net::SocketAddr::new(*ip, at.port()))
        .filter(|a| *a != at)
        .filter(|a| reachable(*a))
        .collect()
}
