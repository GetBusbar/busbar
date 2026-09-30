// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE TRANSPORT DOORS THE ROOT FOLDS (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.4). A transport entry
// on the memory ABI — compiled in (its row's `door`) or dropped in (a `kind: transport` image with
// the one door symbol) — is admitted through the ONE dispatcher's door validation, opened, and
// presented to the connector as the entry's framer table ([`Dispatched`]); the connector serves it
// over the host's sockets ([`HostWire`]). Compiled in and dropped in are the same table, the same
// crossing and the same wire.
//
// Written to be `include!`d: the root mounts it as `root::doors`, and the build's generated table of
// linked transports (`$OUT_DIR/linked_transports.rs`, which the integration tests include) mounts it
// under its own name. So it names nothing of the root's own, only crates the root links.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::slot;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::wire::HostWire;
use busbar_plugin_loader::dispatch::kinds::transport::{Transport as TransportKind, TransportFacts};
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, Frame, InFrame, NoSink, OutFrame, Plugin,
};

/// The one dispatcher every transport door is adopted by: its watchdog watches every crossing.
pub fn dispatcher() -> &'static Dispatcher {
    static ONE: OnceLock<Dispatcher> = OnceLock::new();
    ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()))
}

/// What a transport door is bound to.
pub fn bind() -> Bind {
    Bind {
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher().adopter(),
    }
}

/// One transport door, opened, as the connector reaches it.
pub struct Dispatched {
    plugin: Plugin<TransportKind>,
    facts: DoorFacts,
}

impl Dispatched {
    /// Open `plugin` (no settings: a door that reads one states it) and read what its tail states.
    ///
    /// # Errors
    ///
    /// The plugin would not open, or it is no transport.
    pub fn open(plugin: Plugin<TransportKind>) -> Result<Self, String> {
        let stated = plugin
            .context::<TransportFacts>()
            .cloned()
            .ok_or_else(|| format!("`{}` states no transport tail", plugin.name()))?;
        let mut i: OpenIn = blank_in();
        i.settings = Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        };
        let mut f = Frame::new(i, blank_out::<OpenOut>());
        let opened = plugin.call(life::OPEN, &mut f);
        if opened.outcome != busbar_contract::abi::mechanism::call::Outcome::Ready {
            return Err(format!(
                "transport `{}` would not open ({:?})",
                plugin.name(),
                opened.outcome
            ));
        }
        let facts = DoorFacts {
            name: plugin.name().to_owned(),
            claims: stated.claims,
            composes_over: stated.composes_over,
        };
        Ok(Self { plugin, facts })
    }
}

/// One crossing through the dispatcher: the host's `in`/`out` copied in, the answer copied back.
fn go<I: InFrame, O: OutFrame>(p: &Plugin<TransportKind>, s: u32, i: &mut I, o: &mut O) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.call(s, &mut f);
    *i = f.input;
    *o = f.out;
    Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

impl FramerDoor for Dispatched {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let p = &self.plugin;
        match call {
            Call::Locate(i, o) => go(p, slot::LOCATE, i, o),
            Call::Begin(i, o) => go(p, slot::BEGIN, i, o),
            Call::Ingest(i, o) => go(p, slot::INGEST, i, o),
            Call::Emit(i, o) => go(p, slot::EMIT, i, o),
            Call::Encode(i, o) => go(p, slot::ENCODE, i, o),
            Call::Refuse(i, o) => go(p, slot::REFUSE, i, o),
            Call::Finish(i, o) => go(p, slot::FINISH, i, o),
            Call::Detach(i, o) => go(p, slot::DETACH, i, o),
            Call::Adopt(i, o) => go(p, slot::ADOPT, i, o),
            Call::Timer(i, o) => go(p, slot::TIMER, i, o),
        }
    }
}

/// A door, opened and served over the host's sockets.
///
/// # Errors
///
/// The door would not open, or it composes over a layer (it does not frame the host's socket).
pub fn host_wire(plugin: Plugin<TransportKind>) -> Result<Arc<dyn busbar_contract::Transport>, String> {
    let door = Dispatched::open(plugin)?;
    Ok(Arc::new(HostWire::new(Arc::new(door))?))
}

/// A linked row's build: its door admitted through the one validation, served over the host's
/// sockets. A door row frames the host's socket, so it takes no lower layer and reads no setting.
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair.
pub fn build(
    door: DoorFn,
    _lower: Option<Arc<dyn busbar_contract::Transport>>,
    _settings: &busbar_contract::transport::TransportSettings,
) -> Arc<dyn busbar_contract::Transport> {
    load_linked::<TransportKind>(door, bind())
        .map_err(|e| e.to_string())
        .and_then(host_wire)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}
