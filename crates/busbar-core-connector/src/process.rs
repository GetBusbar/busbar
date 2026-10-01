// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR, AS THE BOOT PATH BUILDS IT (`BUSBAR-1.6.0.md` THE DESIGN, section 5
//! "Connections"; section 8: the connector is the sole holder of TLS trust roots; ARCHITECT ruling
//! 2026-10-01, the dial judge's one home). [`build`] is the root's one entry point: the kernel's
//! destination rules, one set per egress class ([`services`]), behind the one dial judge
//! ([`judge`]), the default outbound trust, the framer entries the root loaded and the wake a
//! caller's ticket goes through, joined into one [`Connector`]. The root hands in the deployment's
//! values (its metadata rules and its listen addresses) and holds and installs what it returns;
//! nothing here keeps a second.

use std::net::SocketAddr;
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::DEST_INTERNAL;
use busbar_contract::transport::trust::EgressTrust;
use busbar_kernel::host_services::KernelServices;

use crate::registry::{Entry, Transports};
use crate::{Connector, DialJudge, Judged, Verdict, WakeTicket};

/// THE PROCESS'S CONNECTOR over the framer entries `entries` yields, judging every dial through
/// the kernel's rules of `blocked`, `allowed` and `allow_all` ([`services`], [`judge`], the node's
/// `own_ports` refused to a loopback-allowed need), securing a connection with the default
/// outbound trust where its target asks for it, and waking a plugin's ticket through `wake`. The
/// trust is built before `entries` is asked for, so a boot that cannot secure a connection loads
/// no transport door.
///
/// # Errors
///
/// The default outbound trust will not build, `entries` refuses, two entries claim one scheme, or
/// an entry states no claim.
pub fn build(
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
    blocked: &[String],
    allowed: &[String],
    allow_all: bool,
    own_ports: &[u16],
    wake: WakeTicket,
) -> Result<Arc<Connector>, String> {
    let services = Arc::new(services(blocked, allowed, allow_all));
    let tls = crate::tls::client::build_client_config(&EgressTrust::default())
        .map_err(|e| format!("its connection security: {e}"))?;
    let view = Transports::new(entries()?).map_err(|e| e.to_string())?;
    Ok(Arc::new(Connector::serving(
        view,
        judge(services, own_ports),
        Some(Arc::new(tls)),
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

#[cfg(test)]
#[path = "tests/process_tests.rs"]
mod tests;
