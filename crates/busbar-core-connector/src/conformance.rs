// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED CONFORMANCE SUITE'S HOST CONNECTOR (ARCHITECT, Q-P4-4: "the suite's host side
//! mirrors production exactly: carrier -> [connsec TLS] -> framer", `BUSBAR-1.6.0.md` THE DESIGN
//! §5). [`host`] is THIS crate's [`Connector`], composed as the root composes the process's one
//! (`busbar/src/root/connector.rs`):
//!
//! * its framer entries are the linked `tcp` and `http` transport doors, each loaded through the
//!   loader's one load and opened by the ROOT'S OWN adapter (`root/doors.rs`, mounted here verbatim:
//!   the same `Dispatched` the process's connector drives);
//! * its connection security is this crate's ([`crate::tls`]): the default outbound trust, plus the
//!   test trust anchors the plugin's suite names (`conformance_suite! { …, tls: … }`), never handed
//!   to the plugin (TRANSPORT-STACK (1): no plugin holds a key, a certificate or a TLS type);
//! * its dial judge is the deployment's one destination guard ([`process::judge`] over
//!   [`process::dest_judge`]) with loopback allowlisted, as an operator allowlists a local backend
//!   (`advanced.allow_destinations`): a suite dials the REAL local endpoint its settings name;
//! * a parked read wakes the plugin's ticket through the leg dispatcher's conn waker.
//!
//! A plugin repo reaches this through a dev-dependency only (`busbar-core-connector`, feature
//! `conformance`) and hands it to the suite (`conformance_suite! { …, host: … }`); nothing here is
//! in a shipped closure.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::conn::DeclaredConns;
use busbar_contract::transport::{EgressTrust, TransportSettings};

use crate::registry::{Entry, Transports};
use crate::{process, Connector, WakeTicket};

/// The loader, as the mounted doors reach it (`super::loader`, the root's one naming module).
mod loader {
    pub use busbar_plugin_loader::*;
}

/// THE ROOT'S TRANSPORT DOORS, mounted verbatim: the same adapter the process's connector drives.
#[allow(dead_code, clippy::all, clippy::pedantic)]
#[path = "../../busbar/src/root/doors.rs"]
mod doors;

/// The framer doors the suite's connector serves: `tcp` (the carrier) and `http` over it, the
/// linked rows the root links.
const DOORS: &[(&str, DoorFn)] = &[
    (
        busbar_transport_tcp::linked::KEY,
        busbar_transport_tcp::linked::door,
    ),
    (
        busbar_transport_http::linked::KEY,
        busbar_transport_http::linked::door,
    ),
];

/// The destinations the suite may dial: loopback, by literal and by name.
const LOCAL: &[&str] = &["127.0.0.1", "::1", "localhost"];

/// The suite's host connector: a connector of its own per call (one per leg), its parked reads
/// woken through `wake` (the leg dispatcher's conn waker), securing a stream with the default
/// outbound trust plus `anchors` (CA certificates, PEM) where a need asks for TLS.
///
/// # Panics
/// The anchors do not parse, a transport door does not load or open, or the connector does not
/// build: the suite's own setup, which it reports rather than skips.
#[must_use]
pub fn host(wake: WakeTicket, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    crate::io::install_process_reactor(io_reactor());
    let trust = EgressTrust {
        extra_anchors: anchors.map(pem_certs).unwrap_or_default(),
        ..EgressTrust::default()
    };
    let tls = crate::tls::client::build_client_config(&trust)
        .unwrap_or_else(|e| panic!("the suite's connection security does not build: {e}"));
    let view = Transports::new(entries())
        .unwrap_or_else(|e| panic!("the suite's transport doors do not compose: {e}"));
    let guard = process::dest_judge(&busbar_kernel::config::Destinations {
        allow: LOCAL.iter().map(|s| (*s).to_owned()).collect(),
        ..busbar_kernel::config::Destinations::default()
    })
    .unwrap_or_else(|e| panic!("the suite's destination guard does not build: {e}"));
    Arc::new(Connector::serving(
        view,
        process::judge(guard, &[]),
        Some(Arc::new(tls)),
        wake,
    ))
}

/// Every certificate in `pem`, DER.
fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<Vec<u8>> = rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| {
            c.map(|c| c.to_vec())
                .unwrap_or_else(|e| panic!("the suite's trust anchors do not parse: {e}"))
        })
        .collect();
    assert!(
        !certs.is_empty(),
        "the suite's trust anchors hold no certificate"
    );
    certs
}

/// The framer entries, each door loaded through the one loader and opened by the root's adapter
/// with the default transport settings (`root::connector::entries`).
fn entries() -> Vec<Entry> {
    use loader::dispatch::kinds::transport::Transport;
    use loader::dispatch::{load_linked, LinkedRow};
    DOORS
        .iter()
        .map(|(key, door)| {
            let plugin = LinkedRow::of(*door)
                .and_then(|row| load_linked::<Transport>(&row, doors::bind()))
                .unwrap_or_else(|e| panic!("the suite's transport `{key}` does not load: {e}"));
            let door = doors::Dispatched::open(plugin, &TransportSettings::default())
                .unwrap_or_else(|e| panic!("the suite's transport `{key}` does not open: {e}"));
            Entry {
                door: Arc::new(door),
                alpn: Vec::new(),
            }
        })
        .collect()
}

/// The connector's I/O thread (`root::connector`'s): a single-threaded runtime of its own whose
/// reactor drives every socket a plugin opens from a dispatcher worker. Built once.
fn io_reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the suite connector's I/O runtime builds");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("busbar-conformance-io".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("the suite connector's I/O thread starts");
        handle
    })
    .clone()
}
