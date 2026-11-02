// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loaded transport doors presented to the connector's carrier and framer interfaces.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use crate::{
    carrier::{Carry, Side},
    framer::{Call, Crossed, DoorFacts, FramerDoor},
    wire::HostWire,
};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::slot;
use busbar_plugin_loader::dispatch::{
    kinds::transport::{Transport as TransportKind, TransportFacts},
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink,
    OutFrame, Plugin, PluginLogConfig,
};

/// The dispatcher every transport door is adopted by (its watchdog watches every crossing).
static ONE: OnceLock<Arc<Dispatcher>> = OnceLock::new();

/// Hand the doors the process's one dispatcher (`root::dispatch`), before any door binds; the first
pub fn install_dispatcher(d: Arc<Dispatcher>) {
    let _ = ONE.set(d);
}

/// The dispatcher every transport door is adopted by.
pub fn dispatcher() -> &'static Dispatcher {
    process_dispatcher()
}

/// [`dispatcher`], as the shared handle a door opened on it holds ([`Dispatched::open`]).
fn process_dispatcher() -> &'static Arc<Dispatcher> {
    ONE.get_or_init(|| {
        let d = Dispatcher::new(DispatchConfig::default());
        let _ = d.lend_seal(busbar_kernel::seal::lend());
        Arc::new(d)
    })
}

/// Where a linked row's plugin log file is opened: the composition root's `plugins.logs`
static LOGS: OnceLock<&'static PluginLogConfig> = OnceLock::new();

/// Hand the doors the composition root's configured `plugins.logs` (`root::boot`), once it is read
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
pub fn bind() -> Bind {
    bind_on(dispatcher())
}

/// [`bind`], adopted by `on`: a composition of its own (a root cell's rig) binds its doors on its
pub fn bind_on(on: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("transport"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: on.adopter(),

        conns: ConnTable::NoNeeds,
    }
}

/// What a LINKED row's door is bound to: [`bind`], labelled with the row's name (its registry
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

/// One transport door, opened, as the connector reaches it: on the dispatcher it was bound on,
pub struct Dispatched {
    live: Arc<Live>,
    facts: DoorFacts,
    /// Its tail states `FACT_ACCEPTS`.
    accepts: bool,
    /// Its Statement states it renders sealed values (TSEAL, `abi::transport::EXT_SEALED_VALUES`).
    seals: bool,
    /// Its Adopt consumes the host's admitted-session extension.
    adopts_session: bool,
    on: Arc<Dispatcher>,
}

/// ONE OPENED TRANSPORT INSTANCE, as a config apply refreshes it: the instance, the setting paths
struct Live {
    plugin: Plugin<TransportKind>,
    settings_keys: Vec<&'static str>,
    generation: AtomicU64,
}

/// EVERY TRANSPORT INSTANCE THIS PROCESS OPENED and still holds, linked and dropped in alike: what
static LIVE: Mutex<Vec<Weak<Live>>> = Mutex::new(Vec::new());

/// The settings blob a door that declares `blob` is handed (`None`: it declares none, and is handed
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
    pub fn open(
        plugin: Plugin<TransportKind>,
        settings: &busbar_contract::transport::TransportSettings,
    ) -> Result<Self, String> {
        Self::open_on(plugin, settings, Arc::clone(process_dispatcher()))
    }

    /// [`Dispatched::open`], for a `plugin` bound on `on` ([`bind_on`]): its `ready`, its host I/O
    pub fn open_on(
        plugin: Plugin<TransportKind>,
        settings: &busbar_contract::transport::TransportSettings,
        on: Arc<Dispatcher>,
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

        plugin.ready(&on, busbar_plugin_loader::dispatch::ready::READY_DEADLINE)?;
        let accepts = stated.accepts;
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

        let _ = on.install_io(crate::hostio::process());
        let live = Arc::new(Live {
            plugin,
            settings_keys: stated.settings_keys,
            generation: AtomicU64::new(0),
        });
        LIVE.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::downgrade(&live));
        Ok(Self {
            live,
            facts,
            accepts,
            seals: stated.seals,
            adopts_session: stated.adopts_session,
            on,
        })
    }

    /// REFRESH this instance with the deployment's applied `settings`: what [`refresh_live`] does
    #[cfg(any(test, feature = "test-support"))]
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

/// One side of a carried connection: an inline ticket of the dispatcher its door is adopted by (its
struct InlineSide(busbar_plugin_loader::dispatch::InlineTicket);

impl Side for InlineSide {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.0.ticket()
    }

    fn register(&self, waker: &std::task::Waker) {
        self.0.register(waker);
    }
}

/// One INLINE crossing on `ticket` (a RESUME when `resume`): the host's `in`/`out` copied in, the
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
    fn adopting_context(
        &self,
        source: Arc<dyn busbar_contract::framing_scope::FramingScope>,
    ) -> Result<Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>, crate::framer::Refused>
    {
        if source.listener() != 0 && !self.adopts_session {
            return Err(crate::framer::Refused {
                outcome: Outcome::Refused,
                error: "the transport does not consume inherited host sessions".into(),
            });
        }
        self.on
            .adopting_context(self.live.plugin.instance().0, source)
            .map(|c| Some(c as Arc<dyn busbar_contract::framing_scope::FramingScope>))
            .map_err(|error| crate::framer::Refused {
                outcome: Outcome::Refused,
                error: error.into(),
            })
    }

    fn framing_context(
        &self,
        listener: u64,
        connection: u64,
    ) -> Result<Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>, crate::framer::Refused>
    {
        self.on
            .framing_context(self.live.plugin.instance().0, listener, connection)
            .map(|c| Some(c as Arc<dyn busbar_contract::framing_scope::FramingScope>))
            .map_err(|e| crate::framer::Refused {
                outcome: Outcome::Refused,
                error: e.into(),
            })
    }

    fn cross_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: Option<&dyn Side>,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        busbar_plugin_loader::dispatch::framing_context::with_context(context.cloned(), || {
            match side {
                Some(side) => self.cross_on(side, resume, call),
                None => self.cross(call),
            }
        })
    }

    fn cancel_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: &dyn Side,
        call: Carry<'_>,
    ) -> Crossed {
        busbar_plugin_loader::dispatch::framing_context::with_context(context.cloned(), || {
            self.carry(side, false, call)
        })
    }

    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn accepts(&self) -> bool {
        self.accepts
    }

    fn instance(&self) -> Option<u64> {
        Some(self.live.plugin.instance().0)
    }

    fn io_owner(&self) -> Option<u64> {
        Some(self.live.plugin.inner.ctx().handle)
    }

    fn seals_values(&self) -> bool {
        self.seals
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        if self.facts.role != busbar_contract::abi::transport::ROLE_CARRIER {
            return None;
        }
        self.on
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

    /// A framer's framing runs its ticketed ops (`begin`, `ingest`, `emit`) on inline tickets of
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        if self.facts.role != busbar_contract::abi::transport::ROLE_FRAMER {
            return None;
        }
        self.on
            .inline_ticket()
            .map(|t| Box::new(InlineSide(t)) as Box<dyn Side>)
    }

    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        let (p, t) = (&self.live.plugin, side.ticket());
        match call {
            Call::Begin(i, o) => go_inline(p, t, resume, slot::BEGIN, i, o),
            Call::Ingest(i, o) => go_inline(p, t, resume, slot::INGEST, i, o),
            Call::Emit(i, o) => go_inline(p, t, resume, slot::EMIT, i, o),
            Call::Adopt(i, o) => go_inline(p, t, resume, slot::ADOPT, i, o),
            other => self.cross(other),
        }
    }
}

/// An opened door and the boot fold's admission of it ([`HostWire`]).
pub type Served = (Arc<dyn FramerDoor>, Arc<HostWire>);

/// A door, opened with the deployment's `settings` and admitted to be served over the host's
pub fn served(
    plugin: Plugin<TransportKind>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<Served, String> {
    let door: Arc<dyn FramerDoor> = Arc::new(Dispatched::open(plugin, settings)?);
    let wire = Arc::new(HostWire::new(door.as_ref())?);
    Ok((door, wire))
}

/// A linked row's build: its door admitted through the one validation, bound under the row's name
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
pub fn stated_row(door: DoorFn) -> Result<RowFacts, String> {
    let facts = busbar_plugin_loader::dispatch::kinds::transport::linked_facts(door)?;
    checked_row(facts)
}

fn checked_row(facts: TransportFacts) -> Result<RowFacts, String> {
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn actual_tcp_name_fault_is_refused() {
        use busbar_plugin_loader::dispatch::{load_dropped, rendering_of_library};

        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_TCP_CDYLIB")
                .expect("BUSBAR_TEST_TCP_CDYLIB must name the actual built TCP product"),
        );
        let statement = rendering_of_library(&path)
            .expect("the actual TCP image renders")
            .expect("the actual TCP image exports a door");
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let plugin = load_dropped::<TransportKind>(
            &path,
            &statement,
            Bind {
                instance: Arc::from("actual-tcp-root-identity"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the actual TCP product loads through its ABI");
        let actual = plugin
            .context::<TransportFacts>()
            .expect("the actual TCP product carries its validated facts")
            .clone();
        let positive = checked_row(actual.clone()).expect("the actual TCP identity is valid");
        assert_eq!(positive.key, "tcp");
        assert_eq!(positive.composes_over, actual.composes_over);
        assert_eq!(positive.session, !actual.sessions.is_empty());
        let mut faulted = actual.clone();
        faulted.name = "tcp-misnamed";
        let mut restored = faulted.clone();
        restored.name = actual.name;
        assert_eq!(
            restored, actual,
            "every other actual product fact is retained"
        );
        let refused = checked_row(faulted).expect_err("a name/own-claim mismatch is refused");
        assert!(
            refused.contains("`tcp-misnamed`") && refused.contains("`tcp`"),
            "the actual identity validator names both spellings: {refused}"
        );
    }
}

/// [`RowFacts`] of a linked row's `door`, as the boot seal reads them.
#[must_use]
pub fn row_facts(door: DoorFn) -> RowFacts {
    stated_row(door).unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// Every scheme a linked row's door claims, its own first, read off the door's Statement (ONE ENTRY
#[must_use]
pub fn claims_of(door: DoorFn) -> Vec<&'static str> {
    busbar_plugin_loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.claims)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The auth points a linked row's door offers, read off its Statement's `extensions`
#[must_use]
pub fn offered_of(door: DoorFn) -> busbar_contract::abi::auth::AuthPoints {
    busbar_plugin_loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.offered)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The auth points a row that states no record offers (a row off the door axis states none).
#[must_use]
pub fn offers_unstated() -> busbar_contract::abi::auth::AuthPoints {
    busbar_contract::abi::transport::check::check_offered_points(&[]).unwrap_or_default()
}

/// The claims a linked row's door opens at an UPGRADE (their row's `unit0_trigger`), read off the
#[must_use]
pub fn upgrades_of(door: DoorFn) -> Vec<&'static str> {
    busbar_plugin_loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.upgrades)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}

/// The claims a linked row's door opens on their FIRST LINE (their row's `unit0_trigger`), read off
#[must_use]
pub fn lines_of(door: DoorFn) -> Vec<&'static str> {
    busbar_plugin_loader::dispatch::kinds::transport::linked_facts(door)
        .map(|facts| facts.lines)
        .unwrap_or_else(|e| panic!("a linked transport door is refused: {e}"))
}
