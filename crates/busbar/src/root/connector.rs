// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR (`BUSBAR-1.6.0.md` THE DESIGN, section 5 "Connections"; ARCHITECT
//! ruling 2026-09-30: one Connector in the root, shared by inbound listening and outbound egress).
//! The root builds it once on the boot path, right after the transport registry is sealed, and
//! holds it for the process; every need of every plugin instance, inbound or outbound, goes through
//! this one instance ([`the`]). Nothing else builds a second.
//!
//! Its framer entries are every linked memory-ABI transport door, opened on the process's one
//! dispatcher; the connector builds the rest (`busbar_core_connector::process`): its dial judge is
//! the deployment's one destination guard ([`dest_judge`]), so every name a need dials is resolved,
//! judged and pinned by that guard at 1.5.5's refusal timing. The root hands it the deployment's
//! values only.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::registry::Entry;
use busbar_core_connector::{process, Connector};
use busbar_kernel::config::{Destinations, RootCfg};
use busbar_kernel::host_services::DestJudge;
use busbar_kernel::plane_host::egress_trust::{install_egress_trust_host, GuardedEgressTrust};

use crate::root::loader::dispatch::{
    kinds::transport::Transport as TransportKind, load_linked, LinkedRow,
};

static ONE: OnceLock<Arc<Connector>> = OnceLock::new();

/// THE CONNECTOR. Built and installed on the boot path ([`install`]); a read before that pins an
/// inert connector (every open refused) and the later install is refused, so a boot that reads it
/// early is caught rather than served by two connectors.
pub fn the() -> &'static Arc<Connector> {
    ONE.get_or_init(|| Arc::new(Connector::new()))
}

/// Install `connector` as the process's one.
///
/// # Errors
///
/// One is already installed (or was read, and so pinned): the argument comes back.
pub fn install(connector: Arc<Connector>) -> Result<&'static Arc<Connector>, Arc<Connector>> {
    let mut given = Some(connector);
    let one = ONE.get_or_init(|| given.take().expect("the connector is given once"));
    match given {
        None => Ok(one),
        Some(refused) => Err(refused),
    }
}

/// The framer entries of `doors` (key, door), each loaded and opened on the process's one
/// dispatcher. A door that will not load or open is named in the refusal.
///
/// # Errors
///
/// The first door that would not load or open.
pub fn entries(doors: &[(&str, DoorFn)]) -> Result<Vec<Entry>, String> {
    doors
        .iter()
        .map(|(key, door)| {
            let plugin = LinkedRow::of(*door)
                .and_then(|row| load_linked::<TransportKind>(&row, crate::root::doors::bind()))
                .map_err(|e| format!("transport `{key}`: {e}"))?;
            let door: Arc<dyn FramerDoor> = Arc::new(crate::root::doors::Dispatched::open(plugin)?);
            Ok(Entry {
                door,
                alpn: Vec::new(),
            })
        })
        .collect()
}

/// THE DEPLOYMENT'S ONE DESTINATION GUARD (OWNER ruling DESTINATION GUARD), built at boot from
/// `cfg`'s `advanced` keys and the 1.5.5 keys that still load. Once [`install_egress_trust`] puts
/// it behind the egress-trust capability it hears every config commit: its metadata lists
/// (`security.*`, `providers.<p>.allow_metadata_hosts`) are re-read at each one, as 1.5.5 re-read
/// them at every reload. An allowlist entry the guard cannot read refuses the boot, naming it.
pub fn dest_judge(cfg: &RootCfg) -> Arc<process::GuardJudge> {
    guard_for(&cfg.destinations()).unwrap_or_else(|refusal| {
        eprintln!("busbar: config errors:\n  - {refusal}");
        std::process::exit(2);
    })
}

/// The one guard `d` states, or the refusal naming its bad allowlist entry (`--validate`).
///
/// # Errors
///
/// An `advanced.allow_destinations` entry the guard cannot read.
pub fn guard_for(d: &Destinations) -> Result<Arc<process::GuardJudge>, String> {
    process::dest_judge(d)
}

/// Install the deployment's one destination guard behind the egress-trust capability (ARCHITECT
/// ruling (C), DEST-GUARD), once, at boot, before any kernel pooled client dials and before the boot
/// build commits: every config commit is raised to it there.
pub fn install_egress_trust(dest: Arc<dyn DestJudge>) {
    install_egress_trust_host(Arc::new(GuardedEgressTrust(dest)));
}

/// THE BOOT PATH'S STEP: build the one Connector over every linked transport door, its dials
/// judged by `dest` (the deployment's one guard) with the node's own ports read off its
/// `listens`, and install it. A connector that cannot be built refuses the boot, as an unsealed
/// composition does.
pub fn boot(
    doors: &[(&str, DoorFn)],
    dest: Arc<dyn DestJudge>,
    listens: &[&str],
) -> &'static Arc<Connector> {
    // The reactor a socket a plugin opens from a dispatcher worker registers on
    // (`busbar_core_connector::io`): the connector's own I/O thread, never a runtime a synchronous
    // caller may block. The control runtime's thread waits, synchronously, on governance-store ops
    // (the boot's store open, admin, the budget flusher: the bridge's TRANSITIONAL wait, ARCHITECT
    // ruling 2026-10-03 on Q-L16-1); a remote store's socket on that runtime's reactor would never
    // be driven while it waits.
    busbar_core_connector::io::install_process_reactor(io_reactor());
    let built = process::build(
        || entries(doors),
        dest,
        &process::own_ports(listens),
        // A plugin reading a connection through a ticket (an export sink's delivery parked on its
        // collector's reply; a remote store's pending reply, ARCHITECT ruling 2026-10-03 on
        // Q-L14-1) is woken on the process's one dispatcher, the one every kind's instances are
        // opened on.
        crate::root::dispatch::dispatcher().conn_waker(),
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

// TRANSITIONAL: the connector's own I/O thread exists because synchronous governance callers wait
// on the control runtime's thread (ARCHITECT ruling 2026-10-03 on Q-L16-3, the Q-L16-1 row); drains
// with that wait (D2/D3; 1.6.0-TODO.md).
/// THE CONNECTOR'S I/O THREAD: a single-threaded runtime of its own whose reactor drives every
/// socket a plugin opens from a dispatcher worker, and nothing else. Built once.
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
