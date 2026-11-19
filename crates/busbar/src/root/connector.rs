// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use busbar_contract::transport::TransportSettings;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::{process, Connector};
use busbar_kernel::config::{Destinations, RootCfg};
use busbar_kernel::host_services::DestJudge;

static ONE: OnceLock<Arc<Connector>> = OnceLock::new();

pub fn the() -> &'static Arc<Connector> {
    ONE.get_or_init(|| Arc::new(Connector::new()))
}

pub fn installed() -> Option<&'static Arc<Connector>> {
    ONE.get()
}

pub(crate) const ROOT_OWNER: busbar_contract::conn::InstanceId =
    busbar_contract::conn::InstanceId(0);

pub struct AuthServerConns;

impl busbar_core_oauth2::Connections for AuthServerConns {
    fn table() -> Option<busbar_core_oauth2::Table> {
        let one = the();
        Some(busbar_core_oauth2::Table {
            owner: ROOT_OWNER,
            declared: Arc::clone(one) as Arc<dyn busbar_contract::conn::DeclaredConns>,
            conns: Arc::clone(one) as Arc<dyn busbar_contract::conn::PollConns>,
        })
    }
}

pub fn install(connector: Arc<Connector>) -> Result<&'static Arc<Connector>, Arc<Connector>> {
    let mut given = Some(connector);
    let one = ONE.get_or_init(|| given.take().expect("the connector is given once"));
    match given {
        None => Ok(one),
        Some(refused) => Err(refused),
    }
}

pub fn dest_judge(cfg: &RootCfg) -> Arc<process::GuardJudge> {
    guard_for(&cfg.destinations()).unwrap_or_else(|refusal| {
        eprintln!(
            "[error] {}\n  - {refusal}",
            busbar_kernel::diagnostics::CLI_VALIDATE_CONFIG_INVALID.coded("config errors")
        );
        crate::root::exit::exit(2);
    })
}

/// THE OUTBOUND TLS TRUST STORE `cfg` states (`advanced.tls`), validated now. A refusal exits
/// the process with every coded reason, before anything is dialled.
fn trust_store(cfg: &RootCfg) -> Arc<busbar_core_connector::tls::store::TrustStore> {
    trust_store_of(&cfg.outbound_tls).unwrap_or_else(|errors| {
        eprintln!("busbar: config errors:\n  - {}", errors.join("\n  - "));
        crate::root::exit::exit(2);
    })
}

/// The trust store `tls` states, or every coded reason it is refused.
pub(crate) fn trust_store_of(
    tls: &busbar_kernel::config::tls::OutboundTlsCfg,
) -> Result<Arc<busbar_core_connector::tls::store::TrustStore>, Vec<String>> {
    busbar_core_connector::tls::store::TrustStore::build(
        tls,
        std::time::SystemTime::now(),
        &busbar_core_connector::tls::store::process_env,
    )
    .map(Arc::new)
}

/// INSTALL `cfg`'s trust store on the process connector and, once logging is up, report it
/// (BUSBAR-3138 per anchor, audited) and start its hourly sweep (expiry withdrawal, the daily
/// expiry warning, anchor-file drift). Restart to apply a change: the store is boot-time.
pub(crate) fn install_trust_store(cfg: &RootCfg, report: bool) {
    let Some(connector) = installed() else {
        return;
    };
    let store = trust_store(cfg);
    connector.install_trust_store(Arc::clone(&store));
    let by_address = cfg.proxy_resolution == busbar_kernel::config::tls::ProxyResolution::Local;
    connector.set_proxy_by_address(by_address);
    if !report {
        return;
    }
    process::note_proxy_posture(by_address);
    store.report_boot(std::time::SystemTime::now());
    if store.is_default() {
        return;
    }
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        let swept = Arc::clone(&store);
        rt.spawn(async move {
            let mut every = tokio::time::interval(busbar_core_connector::tls::store::SWEEP_EVERY);
            every.tick().await;
            loop {
                every.tick().await;
                swept.sweep(std::time::SystemTime::now());
            }
        });
    }
}

pub(crate) fn guard_for(d: &Destinations) -> Result<Arc<process::GuardJudge>, String> {
    process::dest_judge(d)
}

#[must_use]
pub(crate) fn pool_posture(settings: &TransportSettings) -> PoolPosture {
    PoolPosture {
        max_idle_per_host: settings.pool_max_idle_per_host,
        idle_timeout: std::time::Duration::from_secs(settings.pool_idle_timeout_secs),
    }
}

#[must_use]
pub(crate) fn spawn_secret_resolver() -> busbar_core_connector::spawn_env::SpawnSecretFn {
    busbar_core_connector::spawn_env::linked_spawn_secret
}

/// THE PROCESS'S ONE CONNECTOR, built once at boot: its reactor, the destination guard, the
/// engine's own listen addresses (never dialled), the pool posture and the spawn-secret resolver.
/// It frames no transport of its own: an outbound carrier is the admitted MIN-3 transport image the
/// build's carrier table assigns (`min3_boot`, `Connector::carry_natively`).
pub fn boot(
    reactor: tokio::runtime::Handle,
    settings: &TransportSettings,
    dest: Arc<dyn DestJudge>,
    listens: &[&str],
) -> &'static Arc<Connector> {
    busbar_core_connector::io::install_process_reactor(reactor);
    // No framer door is linked or dropped in, and no old-interface instance waits on a ticket: a
    // native caller polls its connection with its own task's waker, so the ticket wake has no one
    // to resume.
    let built = process::build_with_secrets(
        dest,
        &process::own_ports(listens),
        Arc::new(|_, _| {}),
        pool_posture(settings),
        spawn_secret_resolver(),
    );
    let connector = built.unwrap_or_else(|refusal| {
        eprintln!("busbar: the connector did not build: {refusal}");
        crate::root::exit::exit(2);
    });

    install(connector).unwrap_or_else(|_| {
        eprintln!("busbar: a second connector was built; the process has one");
        crate::root::exit::exit(2);
    })
}

/// The effective configuration's own listen addresses and pool posture, set once the boot's
/// configuration is recovered.
pub(crate) fn finalize_boot(settings: &TransportSettings, listens: &[&str]) -> Result<(), String> {
    let connector = installed().ok_or("the bootstrap connector is not installed")?;
    connector.finalize_boot_metadata(&process::own_ports(listens), pool_posture(settings));
    Ok(())
}

#[cfg(test)]
pub(crate) fn install_io_reactor() {
    busbar_core_connector::io::install_process_reactor(io_reactor());
}

#[cfg(test)]
fn io_reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let owner = crate::root::boot::process::ProcessIo::new().expect("test I/O executor");
        let handle = owner.handle();
        Box::leak(Box::new(owner));
        handle
    })
    .clone()
}

#[cfg(test)]
#[path = "tests/connector.rs"]
mod tests;
