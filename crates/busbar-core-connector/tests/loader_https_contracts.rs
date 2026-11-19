// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Real transport/Connector refusal controls from the former loader HTTPS simulator, over core's
// in-tree kind-level TCP carrier and HTTP framer doubles (no plugin is built or loaded: owner
// ruling "core knows nothing about plugins just kinds, plugins test themselves and nothing else").
use busbar_contract::conn::codes::{DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED};
use busbar_contract::conn::{ConnError, DeclaredConns, InstanceId, NeedId, OpenDesc};
use busbar_contract::rendering::{ReadBlob, ReadNeed};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{Connector, Judged, Verdict};
#[path = "../src/tests/tcp_carrier_double.rs"]
mod tcp_carrier_double;

#[path = "../src/tests/http_framer_double.rs"]
mod http_framer_double;

use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, OnceLock,
};
const OWNER: InstanceId = InstanceId(1);
fn runtime() -> &'static tokio::runtime::Handle {
    static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the host I/O runtime");
        let handle = runtime.handle().clone();
        std::thread::spawn(move || runtime.block_on(std::future::pending::<()>()));
        handle
    })
}

fn dispatcher() -> &'static Arc<Dispatcher> {
    static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    DISPATCHER.get_or_init(|| {
        let dispatcher = Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        );
        dispatcher.install_runtime(runtime().clone());
        dispatcher.install_io(busbar_core_connector::hostio::process());
        Arc::new(dispatcher)
    })
}

fn actual_transport(name: &str, row: &LinkedRow) -> Entry {
    static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
    let dispatcher = dispatcher();
    let plugin = load_linked::<Transport>(
        row,
        Bind {
            accept: Default::default(),
            instance: Arc::from(format!(
                "{name}-{}",
                NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed)
            )),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual transport image loads");
    let door = Dispatched::open_on(
        plugin,
        &TransportSettings::default(),
        Arc::clone(dispatcher),
    )
    .expect("the actual transport opens");
    Entry {
        door: Arc::new(door),
        alpn: std::sync::Arc::default(),
    }
}

fn need(transport: &str, class: u32) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: transport.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

