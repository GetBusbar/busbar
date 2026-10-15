// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE TRANSPORT DOORS THE ROOT FOLDS (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.4). A transport entry
// on the memory ABI — compiled in (its row's `door`) or dropped in (a `kind: transport` image with
// the one door symbol) — is admitted through the ONE dispatcher's door validation, opened, and
// presented to the connector as the entry's framer table ([`Dispatched`]); the connector serves it
// over the host's sockets ([`HostWire`]). Compiled in and dropped in are the same table, the same
// crossing and the same wire. A transport reaches the connector only as this framer door: there is
// no transport trait for the root to present it at (step 36).
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
    carrier::{Carry, Side},
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
            role: stated.role,
            composes_over: stated.composes_over,
            ported: stated.ported,
            status_rows: stated.status_rows,
            datagram: stated.datagram,
            duplex: stated
                .upgrades
                .iter()
                .chain(&stated.sessions)
                .copied()
                .collect(),
        };
        // A carrier moves bytes over the host's I/O (`io.*`): the process's one, the connector's.
        let _ = dispatcher().install_io(busbar_core_connector::hostio::process());
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

/// One side of a carried connection: an inline ticket of the process's one dispatcher, the one
/// every transport door is adopted by (its wakes route there).
struct InlineSide(super::loader::dispatch::InlineTicket);

impl Side for InlineSide {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.0.ticket()
    }

    fn register(&self, waker: &std::task::Waker) {
        self.0.register(waker);
    }
}

/// One INLINE crossing on `ticket` (a RESUME when `resume`): the host's `in`/`out` copied in, the
/// answer copied back.
fn go_inline<I: InFrame, O: OutFrame>(
    p: &Plugin<TransportKind>,
    ticket: busbar_contract::abi::mechanism::ticket::Ticket,
    resume: bool,
    s: u32,
    i: &mut I,
    o: &mut O,
) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.call_inline(ticket, resume, s, &mut f);
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

    fn side(&self) -> Option<Box<dyn Side>> {
        if self.facts.role != busbar_contract::abi::transport::ROLE_CARRIER {
            return None;
        }
        dispatcher()
            .inline_ticket()
            .map(|t| Box::new(InlineSide(t)) as Box<dyn Side>)
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        let (p, t) = (&self.plugin, side.ticket());
        match call {
            Carry::Listen(i, o) => go_inline(p, t, resume, slot::LISTEN, i, o),
            Carry::Accept(i, o) => go_inline(p, t, resume, slot::ACCEPT, i, o),
            Carry::Dial(i, o) => go_inline(p, t, resume, slot::DIAL, i, o),
            Carry::Read(i, o) => go_inline(p, t, resume, slot::READ, i, o),
            Carry::Write(i, o) => go_inline(p, t, resume, slot::WRITE, i, o),
            Carry::Flush(i, o) => go_inline(p, t, resume, slot::FLUSH, i, o),
            Carry::Shut(i, o) => go_inline(p, t, resume, slot::SHUT, i, o),
            Carry::Arrival(i, o) => go_inline(p, t, resume, slot::ARRIVAL, i, o),
            // `cancel` is made on no ticket: the ticket it cancels rides its `in`.
            Carry::Cancel(i, o) => go(p, life::CANCEL, i, o),
        }
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

/// Where a served wire's framed connections find their carrier: the root hands the process's
/// connector's address carrier (`crate::root::connector::address_carrier`); a mount with no root
/// hands none, and a framed dial on it is refused.
pub type Riding = Option<busbar_core_connector::carrier::AddressCarrier>;

/// `wire`, riding `riding` when one is handed.
fn ride(wire: HostWire, riding: Riding) -> HostWire {
    match riding {
        Some(carrier) => wire.riding(carrier),
        None => wire,
    }
}

/// An opened door and the wire the host serves it over.
pub type Served = (Arc<dyn FramerDoor>, Arc<HostWire>);

/// A door, opened with the deployment's `settings` and served over the host's sockets, its framed
/// connections riding `riding`; and the opened door itself, the one instance the connector serves
/// as an entry (a dropped-in door is opened once).
///
/// # Errors
///
/// The door would not open, or it composes over a layer (it does not frame the host's socket).
pub fn served(
    plugin: Plugin<TransportKind>,
    settings: &busbar_contract::transport::TransportSettings,
    riding: Riding,
) -> Result<Served, String> {
    let door: Arc<dyn FramerDoor> = Arc::new(Dispatched::open(plugin, settings)?);
    let wire = Arc::new(ride(HostWire::new(Arc::clone(&door))?, riding));
    Ok((door, wire))
}

/// A linked row's build: its door admitted through the one validation, bound under the row's name
/// `row` ([`row_bind`]), opened with the deployment's `settings`, served over the host's sockets. No
/// entry composes over another (ARCHITECT Q128 U7), so a build is handed no layer: the carrier is
/// the connector's choice from the target's scheme (`riding`, [`Riding`]).
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair.
pub fn build(
    row: &str,
    door: DoorFn,
    settings: &busbar_contract::transport::TransportSettings,
    riding: Riding,
) -> Arc<HostWire> {
    LinkedRow::of(door)
        .and_then(|linked| load_linked::<TransportKind>(&linked, row_bind(row)))
        .map_err(|e| e.to_string())
        .and_then(|plugin| Dispatched::open(plugin, settings))
        .and_then(|door| HostWire::new(Arc::new(door)))
        .map(|wire| Arc::new(ride(wire, riding)))
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// Every scheme a linked row's door claims, its own first, read off the door's Statement (ONE ENTRY
/// PER PLUGIN: the schemes are its claims). The seal registers each under its own key.
///
/// # Panics
///
/// The build's own door is refused, as [`build`] panics for it.
#[must_use]
pub fn claims_of(door: DoorFn) -> Vec<&'static str> {
    super::loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.claims)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The auth points a linked row's door offers, read off its Statement's `extensions`
/// (`abi::transport::EXT_OFFERED_POINTS`; THE DESIGN §6 step 3).
///
/// # Panics
///
/// The build's own door is refused, as [`build`] panics for it.
#[must_use]
pub fn offered_of(door: DoorFn) -> busbar_contract::abi::auth::AuthPoints {
    super::loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.offered)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The auth points a row that states no record offers (a row off the door axis states none).
#[must_use]
pub fn offers_unstated() -> busbar_contract::abi::auth::AuthPoints {
    busbar_contract::abi::transport::check::check_offered_points(&[]).unwrap_or_default()
}

/// The claims a linked row's door opens at an UPGRADE (their row's `unit0_trigger`), read off the
/// door's Statement: the data door's upgrade lines (ARCHITECT ruling Q128 U7).
///
/// # Panics
///
/// The build's own door is refused, as [`build`] panics for it.
#[must_use]
pub fn upgrades_of(door: DoorFn) -> Vec<&'static str> {
    super::loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.upgrades)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The claims a linked row's door opens on their FIRST LINE (their row's `unit0_trigger`), read off
/// the door's Statement: the carriers of whole lines, one of which the process's own stdin/stdout
/// serves (`crate::root::serve::lines::line_carrier`).
///
/// # Panics
///
/// The build's own door is refused, as [`build`] panics for it.
#[must_use]
pub fn lines_of(door: DoorFn) -> Vec<&'static str> {
    super::loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.lines)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}
