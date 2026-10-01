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

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::DEST_INTERNAL;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{Connector, DialJudge, Judged, Verdict, WakeTicket};
use busbar_kernel::host_services::KernelServices;

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

/// THE CONNECTOR over `entries`, judging every dial through the kernel's `services` ([`judge`],
/// the node's `own_ports` refused to a loopback-allowed need), securing a connection with `tls`
/// where its target asks for it, and waking a plugin's ticket through `wake`.
///
/// # Errors
///
/// Two entries claim one scheme, or an entry states no claim.
pub fn build(
    entries: Vec<Entry>,
    services: Arc<KernelServices>,
    own_ports: &[u16],
    tls: Option<Arc<rustls::ClientConfig>>,
    wake: WakeTicket,
) -> Result<Arc<Connector>, String> {
    let view = Transports::new(entries).map_err(|e| e.to_string())?;
    Ok(Arc::new(Connector::serving(
        view,
        judge(services, own_ports),
        tls,
        wake,
    )))
}

/// THE DIAL JUDGE the one Connector holds (spec section 5, "Dialing only what the kernel
/// judged"): the kernel's one judge (`KernelServices::judge_dial`), every dial under the need's
/// own egress class, the address it pinned dialled exactly. A loopback-allowed need is held off
/// the node itself: a pinned loopback (or unspecified) address on one of the node's `own_ports` is
/// refused as internal, whether the judgement answered at once or after resolving a name.
#[must_use]
pub fn judge(services: Arc<KernelServices>, own_ports: &[u16]) -> Arc<dyn DialJudge> {
    let own: Arc<[u16]> = own_ports.into();
    Arc::new(move |dest: &str, class: u32, done: Judged| {
        let later = Arc::clone(&own);
        let pended: Judged = Box::new(move |v| done(not_the_node(class, &later, v)));
        services
            .judge_dial(dest, class, pended)
            .map(|v| not_the_node(class, &own, v))
    })
}

/// A loopback-allowed pin on one of the node's own ports, refused (`DEST_INTERNAL`); any other
/// judgement as it was.
fn not_the_node(
    class: u32,
    own: &[u16],
    v: Result<SocketAddr, Verdict>,
) -> Result<SocketAddr, Verdict> {
    match v {
        Ok(at)
            if class == EGRESS_LOOPBACK_ALLOWED
                && (at.ip().is_loopback() || at.ip().is_unspecified())
                && own.contains(&at.port()) =>
        {
            Err(DEST_INTERNAL)
        }
        v => v,
    }
}

/// The ports the node listens on, read off its listen addresses (`listen`, `admin_listen`): an
/// address without a port names none.
#[must_use]
pub fn own_ports(listens: &[&str]) -> Vec<u16> {
    listens
        .iter()
        .filter_map(|l| l.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
        .collect()
}

/// THE KERNEL'S DESTINATION RULES, ONE PER EGRESS CLASS (spec section 5, "Egress classes"), so a
/// need is judged under its own class and never refused for naming one:
///
/// * the default class and `provider`: 1.5.5's posture for an operator-configured upstream:
///   private and plaintext destinations dial (the operator named them); cloud metadata hosts are
///   refused unless the deployment carves them out (`security.blocked_metadata_hosts`,
///   `security.allow_metadata_hosts`, `security.allow_all_metadata`);
/// * `operator-infrastructure`: private, loopback and plaintext dial; cloud metadata hosts are
///   refused whatever the carve-outs say (the accepted difference, owner 2026-09-27);
/// * `open-web`: public destinations only (the connector holds it to connection security);
/// * `loopback-allowed`: private and loopback destinations judge (the connector holds plaintext to
///   loopback, and [`judge`] holds it off the node's own ports); cloud metadata hosts refused.
///
/// An operator's `blocked` additions hold in every class.
#[must_use]
pub fn services(blocked: &[String], allowed: &[String], allow_all: bool) -> KernelServices {
    use busbar_kernel::host_services::DestRules;
    use busbar_kernel::net_guard::{Denylist, GuardPolicy};
    let carved = Arc::new(Denylist::new(blocked, allowed, allow_all));
    let strict = Arc::new(Denylist::new(blocked, &[], false));
    let operator = GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    };
    let rules = |policy: GuardPolicy, denylist: &Arc<Denylist>| DestRules {
        policy,
        denylist: Arc::clone(denylist),
    };
    KernelServices::new(
        std::collections::HashMap::from([
            (EGRESS_DEFAULT, rules(operator, &carved)),
            (EGRESS_PROVIDER, rules(operator, &carved)),
            (EGRESS_OPERATOR_INFRASTRUCTURE, rules(operator, &strict)),
            (EGRESS_OPEN_WEB, rules(GuardPolicy::default(), &strict)),
            (
                EGRESS_LOOPBACK_ALLOWED,
                rules(
                    GuardPolicy {
                        allow_private: true,
                        ..GuardPolicy::default()
                    },
                    &strict,
                ),
            ),
        ]),
        Arc::new(busbar_kernel::host_services::SystemResolver),
    )
}

/// THE BOOT PATH'S STEP: build the one Connector over every linked transport door and install it.
/// A connector that cannot be built refuses the boot, as an unsealed composition does.
pub fn boot(
    doors: &[(&str, DoorFn)],
    services: KernelServices,
    own_ports: &[u16],
) -> &'static Arc<Connector> {
    let built = busbar_core_connector::tls::client::build_client_config(
        &busbar_contract::transport::trust::EgressTrust::default(),
    )
    .map_err(|e| format!("its connection security: {e}"))
    .and_then(|tls| Ok((tls, entries(doors)?)))
    .and_then(|(tls, e)| {
        build(
            e,
            Arc::new(services),
            own_ports,
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
