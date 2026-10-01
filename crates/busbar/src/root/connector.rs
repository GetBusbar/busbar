// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR (`BUSBAR-1.6.0.md` THE DESIGN, section 5 "Connections"; ARCHITECT
//! ruling 2026-09-30: one Connector in the root, shared by inbound listening and outbound egress).
//! The root builds it once on the boot path, right after the transport registry is sealed, and
//! holds it for the process; every need of every plugin instance, inbound or outbound, goes through
//! this one instance ([`the`]). Nothing else builds a second.
//!
//! Its framer entries are every linked memory-ABI transport door, opened on the process's one
//! dispatcher; its dial judge is the kernel's one destination judge (`KernelServices::judge_dial`),
//! so every name a need dials is resolved and pinned inside the kernel at 1.5.5's refusal timing.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_core_connector::{
    framer::FramerDoor,
    registry::{Entry, Transports},
    tls::client::build_client_config,
    Connector, Judged, WakeTicket, DEFAULT_CLASS,
};
use busbar_kernel::host_services::KernelServices;

use crate::root::loader::dispatch::{kinds::transport::Transport as TransportKind, load_linked};

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
            let plugin = load_linked::<TransportKind>(*door, crate::root::doors::bind())
                .map_err(|e| format!("transport `{key}`: {e}"))?;
            let door: Arc<dyn FramerDoor> = Arc::new(crate::root::doors::Dispatched::open(plugin)?);
            Ok(Entry {
                door,
                alpn: Vec::new(),
            })
        })
        .collect()
}

/// THE CONNECTOR over `entries`, judging every dial through the kernel's `services`, securing a
/// connection with `tls` where its target asks for it, and waking a plugin's ticket through `wake`.
///
/// # Errors
///
/// Two entries claim one scheme, or an entry states no claim.
pub fn build(
    entries: Vec<Entry>,
    services: Arc<KernelServices>,
    tls: Option<Arc<rustls::ClientConfig>>,
    wake: WakeTicket,
) -> Result<Arc<Connector>, String> {
    let view = Transports::new(entries).map_err(|e| e.to_string())?;
    let judge = move |dest: &str, class: u32, done: Judged| services.judge_dial(dest, class, done);
    Ok(Arc::new(Connector::serving(
        view,
        Arc::new(judge),
        tls,
        wake,
    )))
}

/// The kernel's destination rules for the connector's dial class ([`DEFAULT_CLASS`]), 1.5.5's
/// posture for an operator-configured upstream: private and plaintext destinations dial (the
/// operator named them); cloud metadata hosts are refused unless the deployment carves them out
/// (`security.blocked_metadata_hosts`, `security.allow_metadata_hosts`,
/// `security.allow_all_metadata`).
#[must_use]
pub fn services(blocked: &[String], allowed: &[String], allow_all: bool) -> KernelServices {
    let rules = busbar_kernel::host_services::DestRules {
        policy: busbar_kernel::net_guard::GuardPolicy {
            allow_private: true,
            allow_plaintext: true,
            ..busbar_kernel::net_guard::GuardPolicy::default()
        },
        denylist: Arc::new(busbar_kernel::net_guard::Denylist::new(
            blocked, allowed, allow_all,
        )),
    };
    KernelServices::new(
        std::collections::HashMap::from([(DEFAULT_CLASS, rules)]),
        Arc::new(busbar_kernel::host_services::SystemResolver),
    )
}

/// THE BOOT PATH'S STEP: build the one Connector over every linked transport door and install it.
/// A connector that cannot be built refuses the boot, as an unsealed composition does.
pub fn boot(doors: &[(&str, DoorFn)], services: KernelServices) -> &'static Arc<Connector> {
    let built = build_client_config(&busbar_contract::transport::trust::EgressTrust::default())
        .map_err(|e| format!("its connection security: {e}"))
        .and_then(|tls| Ok((tls, entries(doors)?)))
        .and_then(|(tls, e)| {
            build(
                e,
                Arc::new(services),
                Some(Arc::new(tls)),
                // No plugin reads a connection through a ticket yet; the kind that first does
                // (inbound listening) routes its wakes through the dispatcher here.
                Arc::new(|_| {}),
            )
        });
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
