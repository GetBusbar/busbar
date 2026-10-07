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
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink,
    OutFrame, Plugin,
};
use busbar_contract::abi::mechanism::call::{Blob, BLOB_ABSENT, BLOB_JSON};
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
        // A transport door is a FRAMER the connector drives (a carrier dials over host io.* fds):
        // it declares no need, so it serves with no table, and one that declared a need would be
        // refused at bind.
        conns: ConnTable::NoNeeds,
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
    /// The customer settings its tail declares, by their 1.5.5 config paths.
    declared: Vec<&'static str>,
}

/// The deployment's value of the transport setting at config path `path`, as the door's settings
/// blob carries it (`TransportTail::settings`: "one customer setting the transport reads, at its
/// 1.5.5 path"), off the resolved transport settings; `None` = the deployment resolves no such
/// path, and the door keeps the default it declared.
fn dealt(
    path: &str,
    s: &busbar_contract::transport::TransportSettings,
) -> Option<serde_json::Value> {
    Some(match path {
        "advanced.upstream_h2_prior_knowledge" => s.upstream_h2_prior_knowledge.into(),
        "advanced.upstream_http1_only" => s.upstream_http1_only.into(),
        "limits.upstream_request_timeout_secs" => s.request_timeout_secs.into(),
        "limits.request_body_max_bytes" => s.request_body_max_bytes.into(),
        _ => return None,
    })
}

/// The settings blob a door that declares `declared` is opened with: each declared path the
/// deployment resolves, at its value (`{}` when it declares none the deployment resolves).
#[must_use]
pub fn settings_blob(
    declared: &[&str],
    s: &busbar_contract::transport::TransportSettings,
) -> Vec<u8> {
    let map: serde_json::Map<String, serde_json::Value> = declared
        .iter()
        .filter_map(|path| Some(((*path).to_owned(), dealt(path, s)?)))
        .collect();
    serde_json::Value::Object(map).to_string().into_bytes()
}

impl Dispatched {
    /// Open `plugin` with the deployment's value of every setting its tail declares
    /// ([`settings_blob`]; a door that declares none is opened with no settings) and read what its
    /// tail states.
    ///
    /// # Errors
    ///
    /// The plugin would not open, or it is no transport.
    pub fn open(
        plugin: Plugin<TransportKind>,
        settings: &busbar_contract::transport::TransportSettings,
    ) -> Result<Self, String> {
        let stated = plugin
            .context::<TransportFacts>()
            .cloned()
            .ok_or_else(|| format!("`{}` states no transport tail", plugin.name()))?;
        let blob = (!stated.settings_keys.is_empty())
            .then(|| settings_blob(&stated.settings_keys, settings));
        let mut i: OpenIn = blank_in();
        i.settings = match &blob {
            Some(b) => Blob {
                ptr: b.as_ptr(),
                len: b.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            None => Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: BLOB_ABSENT,
                flags: 0,
            },
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
        // DISCOVERY AT BOOT (ARCHITECT 2026-10-02): a door that states `ready` is awaited here,
        // after its `open` and before any listener binds; its refusal refuses the boot.
        plugin.ready(dispatcher(), super::loader::dispatch::ready::READY_DEADLINE)?;
        let facts = DoorFacts {
            name: plugin.name().to_owned(),
            claims: stated.claims,
            composes_over: stated.composes_over,
            status_rows: stated.status_rows,
        };
        Ok(Self {
            plugin,
            facts,
            declared: stated.settings_keys,
        })
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
///
/// A COMPOSING entry (SEAM-4f/4n: a message framer over an upgraded http connection) binds and
/// accepts through the layer it was built over, and adopts each connection that layer hands up; a
/// listener whose configuration names one of the settings the entry declares (the body cap, the
/// message ceiling) frames its connections with the entry opened under those settings.
pub struct RootWire {
    wire: HostWire,
    /// The layer a composing entry was built over: it binds and accepts for the entry.
    lower: Option<Arc<dyn busbar_contract::Transport>>,
    /// The entry opened anew under other settings (a linked row's; `None` = never re-opened).
    reopen: Option<Reopen>,
    /// The settings the entry declares, and the ones it was opened with.
    declared: Vec<&'static str>,
    settings: busbar_contract::transport::TransportSettings,
    /// The entry each listener's connections are framed by, where its configuration named its own
    /// settings, by listener id.
    listening: std::sync::Mutex<std::collections::HashMap<u64, Arc<dyn FramerDoor>>>,
}

/// The entry, opened anew under `settings`.
pub type Reopen = Box<
    dyn Fn(&busbar_contract::transport::TransportSettings) -> Result<Arc<dyn FramerDoor>, String>
        + Send
        + Sync,
>;

impl std::fmt::Debug for RootWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootWire")
            .field("wire", &self.wire)
            .finish_non_exhaustive()
    }
}

impl RootWire {
    /// `wire`, built over `lower`, its entry declaring `declared` and opened under `settings`.
    #[must_use]
    pub fn new(
        wire: HostWire,
        lower: Option<Arc<dyn busbar_contract::Transport>>,
        declared: Vec<&'static str>,
        settings: busbar_contract::transport::TransportSettings,
    ) -> Self {
        Self {
            wire,
            lower,
            reopen: None,
            declared,
            settings,
            listening: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The same wire, able to open its entry anew under a listener's own settings.
    #[must_use]
    pub fn reopening(mut self, reopen: Reopen) -> Self {
        self.reopen = Some(reopen);
        self
    }

    /// The settings a listener's configuration `view` names for the entry, where it names any of
    /// the ones the entry declares at another value than the entry was opened with.
    fn viewed(
        &self,
        view: &dyn busbar_contract::TransportConfigView,
    ) -> Option<busbar_contract::transport::TransportSettings> {
        let mut s = self.settings;
        for path in &self.declared {
            let int = || view.get_int(path);
            match *path {
                "limits.request_body_max_bytes" => {
                    if let Some(v) = int().and_then(|v| usize::try_from(v).ok()) {
                        s.request_body_max_bytes = v;
                    }
                }
                "limits.upstream_request_timeout_secs" => {
                    if let Some(v) = int().and_then(|v| u64::try_from(v).ok()) {
                        s.request_timeout_secs = v;
                    }
                }
                "advanced.upstream_h2_prior_knowledge" => {
                    if let Some(v) = view.get_bool(path) {
                        s.upstream_h2_prior_knowledge = v;
                    }
                }
                "advanced.upstream_http1_only" => {
                    if let Some(v) = view.get_bool(path) {
                        s.upstream_http1_only = v;
                    }
                }
                _ => {}
            }
        }
        let same = s.request_body_max_bytes == self.settings.request_body_max_bytes
            && s.request_timeout_secs == self.settings.request_timeout_secs
            && s.upstream_h2_prior_knowledge == self.settings.upstream_h2_prior_knowledge
            && s.upstream_http1_only == self.settings.upstream_http1_only;
        (!same).then_some(s)
    }
}

impl busbar_contract::Plugin for RootWire {
    fn key(&self) -> &'static str {
        self.wire.key()
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
        self.wire.arrival(conn)
    }

    /// An entry over the host's socket listens through nothing here: every inbound socket is the
    /// connector's listener's (the one listener source, ARCHITECT ruling 2026-09-30). A composing
    /// entry binds through the layer it was built over, its listener's own settings noted.
    fn listen<'a>(
        &'a self,
        cfg: &'a dyn busbar_contract::TransportConfigView,
        keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Listener> {
        use busbar_contract::transport::wire::TransportError;
        Box::pin(async move {
            let lower = self
                .lower
                .as_ref()
                .filter(|_| self.wire.composes())
                .ok_or(TransportError::Refused)?;
            let own = match (self.viewed(cfg), &self.reopen) {
                (Some(s), Some(reopen)) => Some(reopen(&s).map_err(|_| TransportError::Refused)?),
                _ => None,
            };
            let listener = lower.listen(cfg, keys).await?;
            if let Some(door) = own {
                self.listening
                    .lock()
                    .expect("listening")
                    .insert(listener.id(), door);
            }
            Ok(listener)
        })
    }

    /// A composing entry accepts what the layer under it accepted, adopting the stream it hands up
    /// (framed under its listener's own settings, where they were named).
    fn accept<'a>(
        &'a self,
        l: &'a busbar_contract::transport::wire::Listener,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        use busbar_contract::transport::wire::TransportError;
        Box::pin(async move {
            let lower = self
                .lower
                .as_ref()
                .filter(|_| self.wire.composes())
                .ok_or(TransportError::Closed)?;
            let conn = lower.accept(l).await?;
            let below = lower.arrival(&conn).transport_chain;
            let raw = lower.detach(&conn).ok_or(TransportError::HandoffMismatch)?;
            let door = self
                .listening
                .lock()
                .expect("listening")
                .get(&l.id())
                .cloned();
            self.wire.adopt_from(raw, below, door).await
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        self.wire.dial(dest, keys)
    }

    fn frames(
        &self,
        conn: busbar_contract::transport::wire::Conn,
    ) -> busbar_contract::transport::FrameStream {
        self.wire.frames(conn)
    }

    fn write<'a>(
        &'a self,
        conn: &'a busbar_contract::transport::wire::Conn,
        stream: busbar_contract::StreamId,
        bytes: busbar_contract::ScratchBytes<'a>,
    ) -> busbar_contract::Fut<'a, usize> {
        // The kernel's write carries no text bit yet: it takes FrameMeta::text from the plane's
        // PIECE_OUT_TEXT after SERVE-WIRE's P1; until then every write here is binary.
        self.wire.write(conn, stream, bytes, false)
    }

    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<busbar_contract::ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        self.wire.encode_envelope(fields, body, arena)
    }

    /// A composing entry ([`HostWire::composed`]) adopts the stream the layer under it hands up
    /// (`from`'s own detach); an entry over the host's socket adopts nothing.
    fn adopt<'a>(
        &'a self,
        from: &'a dyn busbar_contract::Transport,
        conn: busbar_contract::transport::wire::Conn,
        keys: &'a busbar_contract::TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract::transport::wire::Conn> {
        if !self.wire.composes() {
            return self.wire.adopt(conn, keys);
        }
        Box::pin(async move {
            let below = from.arrival(&conn).transport_chain;
            let raw = from
                .detach(&conn)
                .ok_or(busbar_contract::transport::wire::TransportError::HandoffMismatch)?;
            self.wire.adopt_from(raw, below, None).await
        })
    }

    fn detach(
        &self,
        conn: &busbar_contract::transport::wire::Conn,
    ) -> Option<busbar_contract::transport::wire::RawStream> {
        self.wire.detach(conn)
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.wire.composed_over()
    }

    fn close(
        &self,
        conn: busbar_contract::transport::wire::Conn,
        reason: busbar_contract::transport::wire::CloseReason,
    ) {
        self.wire.close(conn, reason);
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: busbar_contract::transport::wire::Conn,
        stream: Option<busbar_contract::StreamId>,
        refusal: &'a busbar_contract::Refusal,
        bytes: busbar_contract::ScratchBytes<'a>,
    ) -> busbar_contract::Fut<'a, ()> {
        self.wire.unit0_refusal(conn, stream, refusal, bytes)
    }
}

/// A door, opened with the deployment's `settings` and served over the host's sockets, presented
/// at the legacy transport seam.
///
/// # Errors
///
/// The door would not open, or it composes over a layer (it does not frame the host's socket).
pub fn host_wire(
    plugin: Plugin<TransportKind>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<Arc<dyn busbar_contract::Transport>, String> {
    let door = Dispatched::open(plugin, settings)?;
    let declared = door.declared.clone();
    Ok(Arc::new(RootWire::new(
        HostWire::new(Arc::new(door))?,
        None,
        declared,
        *settings,
    )))
}

/// A linked row's build: its door admitted through the one validation, bound under the row's name
/// `row` ([`row_bind`]), opened with the deployment's `settings`, served over the host's sockets. A
/// door that frames the host's socket takes no lower layer; one that COMPOSES OVER a layer (SEAM-4f:
/// a message framer over an upgraded http connection) is built over `lower`, the layer the registry
/// folded under it ([`HostWire::composed`]), so the row can be door-only: its entry's `door` is its
/// one face, on the registry and on the connector alike.
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair.
pub fn build(
    row: &str,
    door: DoorFn,
    lower: Option<Arc<dyn busbar_contract::Transport>>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Arc<dyn busbar_contract::Transport> {
    let label = row.to_owned();
    let open = move |s: &busbar_contract::transport::TransportSettings| {
        LinkedRow::of(door)
            .and_then(|linked| load_linked::<TransportKind>(&linked, row_bind(&label)))
            .map_err(|e| e.to_string())
            .and_then(|plugin| Dispatched::open(plugin, s))
    };
    open(settings)
        .and_then(|door| composed_wire_of(door, lower, settings))
        .map(|wire| {
            Arc::new(wire.reopening(Box::new(move |s| {
                open(s).map(|d| Arc::new(d) as Arc<dyn FramerDoor>)
            }))) as Arc<dyn busbar_contract::Transport>
        })
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// [`host_wire`], or, for a door that composes over a layer, the wire built over `lower` (`None`
/// where the composition carries none of its layers: the registry's boot check names it).
///
/// # Errors
///
/// The door would not open, or `lower` is not a layer it declares.
pub fn composed_wire(
    plugin: Plugin<TransportKind>,
    lower: Option<Arc<dyn busbar_contract::Transport>>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<Arc<dyn busbar_contract::Transport>, String> {
    let door = Dispatched::open(plugin, settings)?;
    Ok(Arc::new(composed_wire_of(door, lower, settings)?))
}

/// The wire over an opened entry: over the host's socket, or built over `lower`.
fn composed_wire_of(
    door: Dispatched,
    lower: Option<Arc<dyn busbar_contract::Transport>>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<RootWire, String> {
    let declared = door.declared.clone();
    if door.facts.composes_over.is_empty() {
        return Ok(RootWire::new(
            HostWire::new(Arc::new(door))?,
            None,
            declared,
            *settings,
        ));
    }
    let over = lower.as_ref().map(|l| busbar_contract::Plugin::key(&**l));
    Ok(RootWire::new(
        HostWire::composed(Arc::new(door), over)?,
        lower,
        declared,
        *settings,
    ))
}
