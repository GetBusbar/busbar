// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE TRANSPORT DOORS THE ROOT FOLDS (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.4). A transport entry
// on the memory ABI — compiled in (its row's `door`) or dropped in (a `kind: transport` image with
// the one door symbol) — is admitted through the ONE dispatcher's door validation, opened, and
// presented to the connector as the entry's framer table ([`Dispatched`]); the connector serves it
// over the host's sockets, the boot fold having admitted it ([`HostWire`]: a claim, no layer).
// Compiled in and dropped in are the same table, the same crossing and the same admission. A
// transport reaches the connector only as this framer door: there is no transport trait for the
// root to present it at (step 36).
//
// Written to be `include!`d: the root mounts it as `root::doors`, and the build's generated table of
// linked transports (`$OUT_DIR/linked_transports.rs`, which the integration tests include) mounts it
// under its own name. So it names nothing of the root's own, only crates the root links and
// `super::loader` (the root's one loader module, or the one-line re-export each other mount gives).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use super::loader::dispatch::{
    kinds::transport::{Transport as TransportKind, TransportFacts},
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink,
    OutFrame, Plugin, PluginLogConfig,
};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
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
    ONE.get_or_init(|| {
        let d = Dispatcher::new(DispatchConfig::default());
        let _ = d.lend_seal(busbar_kernel::seal::lend());
        Arc::new(d)
    })
}

/// Where a linked row's plugin log file is opened: the composition root's `plugins.logs`
/// ([`install_plugin_logs`]). A value, not a reader: the root's config follows an apply in place
/// (`root::boot::follow_plugin_logs`), so every sink opened from it takes the applied words.
static LOGS: OnceLock<&'static PluginLogConfig> = OnceLock::new();

/// Hand the doors the composition root's configured `plugins.logs` (`root::boot`), once it is read
/// and before any linked row binds; the first install stands. A mount of this file with no
/// composition root (a test, the conformance subject) logs under the defaults.
pub fn install_plugin_logs(logs: &'static PluginLogConfig) {
    let _ = LOGS.set(logs);
}

/// The `plugins.logs` a linked row's plugin log file is opened under.
fn plugin_logs() -> &'static PluginLogConfig {
    static DEFAULTS: OnceLock<PluginLogConfig> = OnceLock::new();
    match LOGS.get() {
        Some(logs) => logs,
        None => DEFAULTS.get_or_init(|| {
            PluginLogConfig::from_words(None, None, &std::collections::BTreeMap::new(), None, None)
                .expect("the plugins.logs defaults resolve")
        }),
    }
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
/// key), so two linked rows are two instances to the host services, and logging to that row's own
/// plugin log file under the configured `plugins.logs` (THE DESIGN §11.2, "Plugin logging": every
/// plugin, compiled in or dropped in; a dropped-in door's is opened by the registry).
///
/// # Errors
///
/// The row's plugin log file cannot be opened.
pub fn row_bind(row: &str) -> Result<Bind, String> {
    let bound = bind();
    let sink = plugin_logs().sink(
        row,
        busbar_contract::abi::mechanism::KindCode::Transport,
        bound.sink.clone(),
    )?;
    Ok(Bind {
        instance: Arc::from(row),
        sink: Arc::new(sink),
        ..bound
    })
}

/// One transport door, opened, as the connector reaches it.
pub struct Dispatched {
    live: Arc<Live>,
    facts: DoorFacts,
}

/// ONE OPENED TRANSPORT INSTANCE, as a config apply refreshes it: the instance, the setting paths
/// its tail declares, and the generation its last `open` or `refresh` opened.
struct Live {
    plugin: Plugin<TransportKind>,
    settings_keys: Vec<&'static str>,
    generation: AtomicU64,
}

/// EVERY TRANSPORT INSTANCE THIS PROCESS OPENED and still holds, linked and dropped in alike: what
/// [`refresh_live`] refreshes on a config apply. An instance whose last holder dropped it leaves
/// with its next pass.
static LIVE: Mutex<Vec<Weak<Live>>> = Mutex::new(Vec::new());

/// The settings blob a door that declares `blob` is handed (`None`: it declares none, and is handed
/// no settings).
fn settings_arg(blob: Option<&[u8]>) -> Blob {
    match blob {
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
    }
}

impl Live {
    /// REFRESH this instance onto the next generation with the deployment's value of every
    /// setting its tail declares ([`settings_blob`]), as its `open` was handed them. It moves
    /// settings only: no listener is bound or re-bound, and every connection stays open.
    fn refresh(
        &self,
        settings: &busbar_contract::transport::TransportSettings,
    ) -> Result<(), String> {
        let blob =
            (!self.settings_keys.is_empty()).then(|| settings_blob(&self.settings_keys, settings));
        let mut i: RefreshIn = blank_in();
        i.generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        i.settings = settings_arg(blob.as_deref());
        let mut f = Frame::new(i, blank_out::<OutHead>());
        let called = self.plugin.call(life::REFRESH, &mut f);
        if called.outcome == Outcome::Ready {
            return Ok(());
        }
        let why = called
            .error
            .as_deref()
            .map(|e| format!(": {}", String::from_utf8_lossy(e)))
            .unwrap_or_default();
        Err(format!(
            "transport `{}` did not refresh ({:?}){why}",
            self.plugin.name(),
            called.outcome
        ))
    }
}

/// A CONFIG APPLY, as every opened transport instance takes it (`BUSBAR-1.6.0.md` §11.4, "a plugin
/// is a plugin": every kind's `refresh` slot is called on an apply, as the planes' and the
/// credentials' are): each live instance is refreshed with the applied `settings`. An instance
/// that will not refresh keeps the settings it holds and keeps serving; each refusal is answered,
/// for the caller to log. A listener set change still applies on restart (THE DESIGN, the
/// generations rule): a refresh binds nothing.
pub fn refresh_live(settings: &busbar_contract::transport::TransportSettings) -> Vec<String> {
    refresh_named(settings, |_| true)
}

/// [`refresh_live`] over the live instances whose name `named` keeps.
pub fn refresh_named(
    settings: &busbar_contract::transport::TransportSettings,
    named: impl Fn(&str) -> bool,
) -> Vec<String> {
    let live: Vec<Arc<Live>> = {
        let mut book = LIVE.lock().unwrap_or_else(PoisonError::into_inner);
        book.retain(|w| w.strong_count() > 0);
        book.iter()
            .filter_map(Weak::upgrade)
            .filter(|l| named(l.plugin.name()))
            .collect()
    };
    live.iter()
        .filter_map(|l| l.refresh(settings).err())
        .collect()
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
        i.settings = settings_arg(blob.as_deref());
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
        let live = Arc::new(Live {
            plugin,
            settings_keys: stated.settings_keys,
            generation: AtomicU64::new(0),
        });
        LIVE.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::downgrade(&live));
        Ok(Self { live, facts })
    }

    /// REFRESH this instance with the deployment's applied `settings`: what [`refresh_live`] does
    /// for every opened instance on a config apply.
    ///
    /// # Errors
    ///
    /// The instance did not answer READY; it keeps the settings it holds.
    #[cfg(test)]
    pub fn refresh(
        &self,
        settings: &busbar_contract::transport::TransportSettings,
    ) -> Result<(), String> {
        self.live.refresh(settings)
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
        let (p, t) = (&self.live.plugin, side.ticket());
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
        let p = &self.live.plugin;
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

/// An opened door and the boot fold's admission of it ([`HostWire`]).
pub type Served = (Arc<dyn FramerDoor>, Arc<HostWire>);

/// A door, opened with the deployment's `settings` and admitted to be served over the host's
/// sockets; and the opened door itself, the one instance the connector serves as an entry (a
/// dropped-in door is opened once).
///
/// # Errors
///
/// The door would not open, or it composes over a layer (it does not frame the host's socket).
pub fn served(
    plugin: Plugin<TransportKind>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<Served, String> {
    let door: Arc<dyn FramerDoor> = Arc::new(Dispatched::open(plugin, settings)?);
    let wire = Arc::new(HostWire::new(door.as_ref())?);
    Ok((door, wire))
}

/// A linked row's build: its door admitted through the one validation, bound under the row's name
/// `row` ([`row_bind`]), opened with the deployment's `settings`, admitted to be served over the
/// host's sockets. No entry composes over another (ARCHITECT Q128 U7), so a build is handed no
/// layer: the carrier is the connector's choice from the target's scheme.
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair.
pub fn build(
    row: &str,
    door: DoorFn,
    settings: &busbar_contract::transport::TransportSettings,
) -> Arc<HostWire> {
    LinkedRow::of(door)
        .map_err(|e| e.to_string())
        .and_then(|linked| {
            load_linked::<TransportKind>(&linked, row_bind(row)?).map_err(|e| e.to_string())
        })
        .and_then(|plugin| Dispatched::open(plugin, settings))
        .and_then(|door| HostWire::new(&door))
        .map(Arc::new)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// A LINKED TRANSPORT ROW'S IDENTITY, read off its door's Statement and nothing else: the row's
/// entry is its bare `door` (`BUSBAR-1.6.0.md` A.1, l.3560: the logic crate's only public item), and
/// a linked row holds that door and reaches the same `'static` table a dropped-in copy does (l.3561),
/// so its key, its layers and whether it carries a session are what that table states (A.2,
/// l.3564-3577: the name, the claims and the kind tail), read by the one reader a load reads them by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowFacts {
    /// The row's registry key: the door's own claim (its first), which is its Statement's name.
    pub key: &'static str,
    /// The layers its transport tail states it composes over (`TransportTail::composes_over`).
    pub composes_over: Vec<&'static str>,
    /// Whether a claim it answers carries a session (a claim row whose `session` is set).
    pub session: bool,
}

/// [`RowFacts`] of a linked row's `door`, or the refusal: the door, its Statement or its tail is
/// refused by the loader's checks, it claims no scheme, or its own claim is not its Statement's name
/// (a row keyed by one and named by the other would register under a key no dropped-in copy of the
/// same door answers to).
///
/// # Errors
///
/// The refusal, in words naming both spellings where they differ.
pub fn stated_row(door: DoorFn) -> Result<RowFacts, String> {
    let facts = super::loader::dispatch::kinds::transport::linked_facts(door)?;
    let Some(&key) = facts.claims.first() else {
        return Err(format!(
            "the transport door `{}` claims no scheme: a linked row's key is its door's own claim",
            facts.name
        ));
    };
    if key != facts.name {
        return Err(format!(
            "the transport door's Statement is named `{}` but its own claim (its first) is `{key}`: \
             a linked row's key is its door's own claim, and the two must be one",
            facts.name
        ));
    }
    Ok(RowFacts {
        key,
        composes_over: facts.composes_over,
        session: !facts.sessions.is_empty(),
    })
}

/// [`RowFacts`] of a linked row's `door`, as the boot seal reads them.
///
/// # Panics
///
/// The build's own door is refused ([`stated_row`]), as [`build`] panics for it: the binary was
/// built with a broken plugin, which no configuration can repair, so the boot is refused.
#[must_use]
pub fn row_facts(door: DoorFn) -> RowFacts {
    stated_row(door).unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
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
