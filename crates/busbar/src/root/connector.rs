// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{process, Connector};
use busbar_kernel::config::{Destinations, RootCfg};
use busbar_kernel::host_services::DestJudge;

use crate::root::loader::dispatch::{
    kinds::transport::Transport as TransportKind, load_linked, LinkedRow,
};

static ONE: OnceLock<Arc<Connector>> = OnceLock::new();

pub fn the() -> &'static Arc<Connector> {
    ONE.get_or_init(|| Arc::new(Connector::new()))
}

pub fn installed() -> Option<&'static Arc<Connector>> {
    ONE.get()
}

pub const ROOT_OWNER: busbar_contract::conn::InstanceId = busbar_contract::conn::InstanceId(0);

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

pub fn entries(
    doors: &[(&str, DoorFn)],
    settings: &TransportSettings,
) -> Result<Vec<Entry>, String> {
    doors
        .iter()
        .map(|(key, door)| {
            let plugin = LinkedRow::of(*door)
                .and_then(|row| load_linked::<TransportKind>(&row, crate::root::doors::bind()))
                .map_err(|e| format!("transport `{key}`: {e}"))?;
            let door: Arc<dyn FramerDoor> =
                Arc::new(crate::root::doors::Dispatched::open(plugin, settings)?);
            Ok(Entry {
                door,
                alpn: Vec::new(),
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn entries_on(
    on: &Arc<crate::root::loader::dispatch::Dispatcher>,
    doors: &[(&str, DoorFn)],
    settings: &TransportSettings,
) -> Result<Vec<Entry>, String> {
    doors
        .iter()
        .map(|(key, door)| {
            let plugin = LinkedRow::of(*door)
                .and_then(|row| load_linked::<TransportKind>(&row, crate::root::doors::bind_on(on)))
                .map_err(|e| format!("transport `{key}`: {e}"))?;
            let door: Arc<dyn FramerDoor> = Arc::new(crate::root::doors::Dispatched::open_on(
                plugin,
                settings,
                Arc::clone(on),
            )?);
            Ok(Entry {
                door,
                alpn: Vec::new(),
            })
        })
        .collect()
}

pub fn declared(
    mut linked: Vec<Entry>,
    dropped: &[crate::root::registry::DroppedDoor],
) -> Result<Vec<Entry>, String> {
    linked.extend(dropped.iter().map(|d| Entry {
        door: Arc::clone(&d.door),
        alpn: Vec::new(),
    }));
    Ok(linked)
}

#[must_use]
pub fn carrier_name(via: Option<&busbar_core_connector::compose::Via>) -> &'static str {
    via.and_then(|v| v.door.facts().claims.first().copied())
        .unwrap_or("host")
}

pub fn dest_judge(cfg: &RootCfg) -> Arc<process::GuardJudge> {
    guard_for(&cfg.destinations()).unwrap_or_else(|refusal| {
        eprintln!("busbar: config errors:\n  - {refusal}");
        std::process::exit(2);
    })
}

pub fn guard_for(d: &Destinations) -> Result<Arc<process::GuardJudge>, String> {
    process::dest_judge(d)
}

#[must_use]
pub fn pool_posture(settings: &TransportSettings) -> PoolPosture {
    PoolPosture {
        max_idle_per_host: settings.pool_max_idle_per_host,
        idle_timeout: std::time::Duration::from_secs(settings.pool_idle_timeout_secs),
    }
}

#[must_use]
pub fn spawn_secret_resolver() -> busbar_core_connector::spawn_env::SpawnSecretFn {
    busbar_core_connector::spawn_env::linked_spawn_secret
}

pub fn boot(
    doors: &[(&str, DoorFn)],
    settings: &TransportSettings,
    dest: Arc<dyn DestJudge>,
    listens: &[&str],
) -> &'static Arc<Connector> {
    install_io_reactor();

    crate::root::dispatch::dispatcher().install_runtime(io_reactor());
    let built = process::build_with_secrets(
        || {
            declared(
                entries(doors, settings)?,
                &crate::root::boot::dropped_transports(settings).doors,
            )
        },
        dest,
        &process::own_ports(listens),
        crate::root::dispatch::dispatcher().conn_waker(),
        pool_posture(settings),
        spawn_secret_resolver(),
    );
    let connector = built.unwrap_or_else(|refusal| {
        eprintln!("busbar: the connector did not build: {refusal}");
        std::process::exit(2);
    });

    install(connector).unwrap_or_else(|_| {
        eprintln!("busbar: a second connector was built; the process has one");
        std::process::exit(2);
    })
}

pub fn finalize_boot(settings: &TransportSettings, listens: &[&str]) -> Result<(), String> {
    let connector = installed().ok_or("the bootstrap connector is not installed")?;
    let dropped = crate::root::boot::open_dropped_transports(settings)?;
    let dropped = finalize_prepared(
        connector,
        crate::LINKED_TRANSPORT_DOORS,
        settings,
        listens,
        dropped,
    )?;
    crate::root::boot::publish_dropped_transports(dropped);
    Ok(())
}

fn finalize_prepared(
    connector: &Connector,
    doors: &[(&str, DoorFn)],
    settings: &TransportSettings,
    listens: &[&str],
    dropped: crate::root::registry::Dropped,
) -> Result<crate::root::registry::Dropped, String> {
    let view = prepare_effective(doors, settings, &dropped)?;
    connector.finalize_boot_metadata(view, &process::own_ports(listens), pool_posture(settings));
    Ok(dropped)
}

fn prepare_effective(
    doors: &[(&str, DoorFn)],
    settings: &TransportSettings,
    dropped: &crate::root::registry::Dropped,
) -> Result<Transports, String> {
    let entries = declared(entries(doors, settings)?, &dropped.doors)?;
    Transports::new(entries).map_err(|error| error.to_string())
}

pub(crate) fn install_io_reactor() {
    busbar_core_connector::io::install_process_reactor(io_reactor());
}

#[cfg(test)]
pub(crate) fn install_io(dispatcher: &crate::root::loader::dispatch::Dispatcher) {
    busbar_core_connector::io::install_process_reactor(io_reactor());
    let _ = dispatcher.install_runtime(io_reactor());
}

fn io_reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| {
                eprintln!("busbar: the connector's I/O runtime did not build: {e}");
                std::process::exit(2);
            });
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("busbar-conn-io".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .unwrap_or_else(|e| {
                eprintln!("busbar: the connector's I/O thread did not start: {e}");
                std::process::exit(2);
            });
        handle
    })
    .clone()
}

#[cfg(test)]
#[path = "tests/connector.rs"]
mod tests;

#[cfg(all(test, linked_every_transport))]
#[path = "tests/connector_h2.rs"]
mod h2_tests;
