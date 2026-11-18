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

/// THE PROCESS'S CONNECTOR over the framer entries `entries` yields, judging every dial through
/// `dest` (re-exported as `process::build_with_secrets`). Boot only: its one production caller is
/// the root's `connector::boot`, run once as the process starts; the others are test rigs. No
/// request path reaches it, so it lives off the request-path tree (the two pool epochs it reads,
/// the default connector's and the posture's, are boot readings).
pub fn build_with_secrets(
    entries: impl FnOnce() -> Result<Vec<crate::registry::Entry>, String>,
    dest: std::sync::Arc<dyn busbar_kernel::host_services::DestJudge>,
    own_ports: &[u16],
    wake: crate::WakeTicket,
    pool: crate::pool::PoolPosture,
    spawn_secrets: crate::spawn_env::SpawnSecretFn,
) -> Result<std::sync::Arc<crate::Connector>, String> {
    let proxy = crate::proxy::from_env()
        .map_err(|e| crate::cold::lines::prefixed("its proxy environment: ", &e))?;
    let view = crate::registry::Transports::new(entries()?)
        .map_err(|e| crate::cold::lines::display_text(&e))?;
    let connector = crate::Connector::serving_with_trust(
        view,
        crate::process::judge(dest, own_ports),
        busbar_contract::transport::trust::EgressTrust::default(),
        wake,
    )
    .map_err(|e| crate::cold::lines::prefixed("its connection security: ", &e))?;
    Ok(std::sync::Arc::new(
        connector
            .pooling(pool)
            .proxying(proxy)
            .resolving_spawn_secrets(spawn_secrets),
    ))
}
