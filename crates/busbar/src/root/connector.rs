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
//! the kernel's one destination judge, so every name a need dials is resolved and pinned inside the
//! kernel at 1.5.5's refusal timing. The root hands it the deployment's values only.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::registry::Entry;
use busbar_core_connector::{process, Connector};

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

/// THE BOOT PATH'S STEP: build the one Connector over every linked transport door, judged under
/// the deployment's metadata rules (`blocked`, `allowed`, `allow_all`) with the node's own ports
/// read off its `listens`, and install it. A connector that cannot be built refuses the boot, as an
/// unsealed composition does.
pub fn boot(
    doors: &[(&str, DoorFn)],
    blocked: &[String],
    allowed: &[String],
    allow_all: bool,
    listens: &[&str],
) -> &'static Arc<Connector> {
    let built = process::build(
        || entries(doors),
        blocked,
        allowed,
        allow_all,
        &process::own_ports(listens),
        // A plugin reading a connection through a ticket (an export sink's delivery parked on its
        // collector's reply) is woken through the process's one dispatcher.
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

#[cfg(test)]
#[path = "tests/connector.rs"]
mod tests;
