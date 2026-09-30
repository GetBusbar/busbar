// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE TRANSPORT DOORS THE ROOT FOLDS (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.4). A transport entry
// on the memory ABI — compiled in (its row's `door`) or dropped in (a `kind: transport` image with
// the one door symbol) — is admitted through the ONE dispatcher's door validation, opened, and
// presented to the connector as the entry's framer table ([`Dispatched`]); the connector serves it
// over the host's sockets ([`HostWire`]), which the root presents at the kernel's legacy transport
// seam through [`RootWire`]. Compiled in and dropped in are the same table, the same crossing and
// the same wire.
//
// Written to be `include!`d: the root mounts it as `root::doors`, and the build's generated table of
// linked transports (`$OUT_DIR/linked_transports.rs`, which the integration tests include) mounts it
// under its own name. So it names nothing of the root's own, only crates the root links and
// `super::loader` (the root's one loader module, or the one-line re-export each other mount gives).

use std::sync::{Arc, OnceLock};

use super::loader::dispatch::{
    kinds::transport::{Transport as TransportKind, TransportFacts},
    load_linked, Bind, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink, OutFrame,
    Plugin,
};
use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::slot;
use busbar_core_connector::{
    framer::{Call, Crossed, DoorFacts, FramerDoor},
    wire::HostWire,
};

/// The dispatcher every transport door is adopted by (its watchdog watches every crossing).
static ONE: OnceLock<Arc<Dispatcher>> = OnceLock::new();

/// Hand the doors the process's one dispatcher (`root::dispatch`), before any door binds; the first
/// install stands. A mount of this file with no composition root (a test, the conformance
/// subject) builds its own on first use.
pub fn install_dispatcher(d: Arc<Dispatcher>) {
    let _ = ONE.set(d);
}

/// The dispatcher every transport door is adopted by.
pub fn dispatcher() -> &'static Dispatcher {
    ONE.get_or_init(|| Arc::new(Dispatcher::new(DispatchConfig::default())))
}

/// What a transport door is bound to. The instance label is the transport lane's own; every door
/// is relabelled as it opens: a linked row with its row name ([`row_bind`]), a dropped-in door
/// with its plugin's name (the registry), so the label is unique per instance.
pub fn bind() -> Bind {
    Bind {
        instance: Arc::from("transport"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher().adopter(),
        conns: None,
    }
}

/// What a LINKED row's door is bound to: [`bind`], labelled with the row's name (its registry
/// key), so two linked rows are two instances to the host services.
pub fn row_bind(row: &str) -> Bind {
    Bind {
        instance: Arc::from(row),
        ..bind()
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

/// THE ROOT'S ADAPTER FROM THE CONNECTOR'S HOST-SIDE SURFACE TO THE KERNEL'S LEGACY TRANSPORT SEAM.
/// The connector is core and presents no plugin face; the kernel's listeners, accept loop and
/// upgrades still speak `busbar_contract::Transport`, so the root wraps a [`HostWire`] in this and
/// every method ONLY delegates. Transitional: `RootWire` deletes with the legacy stack at TODO step 36.
#[derive(Debug)]
pub struct RootWire(pub HostWire);

impl busbar_contract::Plugin for RootWire {
    fn key(&self) -> &'static str {
        self.0.key()
    }
    fn kind(&self) -> busbar_contract::Kind {
        busbar_contract::Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl busbar_contract::Transport for RootWire {
    fn arrival(
        &self,
        conn: &busbar_contract::transport::wire::Conn,
    ) -> busbar_contract::transport::wire::ArrivalRecord {
        self.0.arrival(conn)
    }

    /// Nothing listens through this seam: every inbound socket is the connector's listener's (the
    /// one listener source, ARCHITECT ruling 2026-09-30 H5).
    fn listen<'a>(
        &'a self,
        _cfg: &'a dyn busbar_contract::TransportConfigView,
        _keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Listener> {
        Box::pin(async { Err(busbar_contract::transport::wire::TransportError::Refused) })
    }

    fn accept<'a>(
        &'a self,
        _l: &'a busbar_contract::transport::wire::Listener,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        Box::pin(async { Err(busbar_contract::transport::wire::TransportError::Closed) })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        self.0.dial(dest, keys)
    }

    fn frames(
        &self,
        conn: busbar_contract::transport::wire::Conn,
    ) -> busbar_contract::transport::FrameStream {
        self.0.frames(conn)
    }

    fn write<'a>(
        &'a self,
        conn: &'a busbar_contract::transport::wire::Conn,
        stream: busbar_contract::StreamId,
        bytes: busbar_contract::ScratchBytes<'a>,
    ) -> busbar_contract::Fut<'a, usize> {
        self.0.write(conn, stream, bytes)
    }

    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<busbar_contract::ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        self.0.encode_envelope(fields, body, arena)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn busbar_contract::Transport,
        conn: busbar_contract::transport::wire::Conn,
        keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        self.0.adopt(conn, keys)
    }

    fn detach(
        &self,
        conn: &busbar_contract::transport::wire::Conn,
    ) -> Option<busbar_contract::transport::wire::RawStream> {
        self.0.detach(conn)
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.0.composed_over()
    }

    fn close(
        &self,
        conn: busbar_contract::transport::wire::Conn,
        reason: busbar_contract::transport::wire::CloseReason,
    ) {
        self.0.close(conn, reason);
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: busbar_contract::transport::wire::Conn,
        stream: Option<busbar_contract::StreamId>,
        refusal: &'a busbar_contract::Refusal,
        bytes: busbar_contract::ScratchBytes<'a>,
    ) -> busbar_contract::Fut<'a, ()> {
        self.0.unit0_refusal(conn, stream, refusal, bytes)
    }
}

/// A door, opened and served over the host's sockets, presented at the legacy transport seam.
///
/// # Errors
///
/// The door would not open, or it composes over a layer (it does not frame the host's socket).
pub fn host_wire(
    plugin: Plugin<TransportKind>,
) -> Result<Arc<dyn busbar_contract::Transport>, String> {
    let door = Dispatched::open(plugin)?;
    Ok(Arc::new(RootWire(HostWire::new(Arc::new(door))?)))
}

/// A linked row's build: its door admitted through the one validation, bound under the row's name
/// `row` ([`row_bind`]), served over the host's sockets. A door row frames the host's socket, so it
/// takes no lower layer and reads no setting.
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair.
pub fn build(
    row: &str,
    door: DoorFn,
    _lower: Option<Arc<dyn busbar_contract::Transport>>,
    _settings: &busbar_contract::transport::TransportSettings,
) -> Arc<dyn busbar_contract::Transport> {
    LinkedRow::of(door)
        .and_then(|linked| load_linked::<TransportKind>(&linked, row_bind(row)))
        .map_err(|e| e.to_string())
        .and_then(host_wire)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}
