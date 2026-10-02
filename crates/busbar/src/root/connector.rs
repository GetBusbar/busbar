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
use std::net::IpAddr;

use busbar_kernel::egress::engine::ClientIdentity;
use busbar_kernel::host_services::{DestJudge, DestRefusal};
use busbar_kernel::plane_host::egress_trust::{
    install_egress_trust_host, CertificateDer, EgressTrustHost, PassThroughEgressTrust,
};
use busbar_kernel::plane_host::spki::SpkiError;

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

/// THE DEPLOYMENT'S ONE DESTINATION GUARD (OWNER ruling DESTINATION GUARD), built once from
/// `cfg`'s `advanced` keys and the 1.5.5 keys that still load. An allowlist entry the guard
/// cannot read refuses the boot, naming it.
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

/// THE EGRESS-TRUST CAPABILITY THE ROOT INSTALLS (ARCHITECT ruling (C), DEST-GUARD): the kernel's
/// pass-through trust primitives, and every answer a kernel pooled client resolved judged by the
/// deployment's one destination guard (`dest`). The connector decides; this only hands it on.
pub struct GuardedEgressTrust(pub Arc<dyn DestJudge>);

impl EgressTrustHost for GuardedEgressTrust {
    fn register_client_identity(&self, identity: ClientIdentity) -> u64 {
        PassThroughEgressTrust.register_client_identity(identity)
    }
    fn resolve_client_identity(&self, client_identity_ref: u64) -> Option<ClientIdentity> {
        PassThroughEgressTrust.resolve_client_identity(client_identity_ref)
    }
    fn register_trust_anchor(&self, roots: Vec<CertificateDer<'static>>) -> u64 {
        PassThroughEgressTrust.register_trust_anchor(roots)
    }
    fn resolve_trust_anchor(&self, trust_anchor_ref: u64) -> Vec<CertificateDer<'static>> {
        PassThroughEgressTrust.resolve_trust_anchor(trust_anchor_ref)
    }
    fn peer_leaf_pin(&self, cert_der: &[u8]) -> Result<String, SpkiError> {
        PassThroughEgressTrust.peer_leaf_pin(cert_der)
    }
    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal> {
        self.0.judge_answer(host, addrs, class)
    }
}

/// Install [`GuardedEgressTrust`] over `dest` as the process's egress-trust capability, once, at
/// boot, before any pooled client dials.
pub fn install_egress_trust(dest: Arc<dyn DestJudge>) {
    install_egress_trust_host(Box::leak(Box::new(GuardedEgressTrust(dest))));
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
    let built = process::build(
        || entries(doors),
        dest,
        &process::own_ports(listens),
        // No plugin reads a connection through a ticket yet; the kind that first does
        // (inbound listening) routes its wakes through the dispatcher here.
        Arc::new(|_| {}),
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
