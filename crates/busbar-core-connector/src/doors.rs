// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loaded transport doors presented to the connector's carrier and framer interfaces.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::off_path::egress::doors::checked_row;
use crate::{
    carrier::{Carry, Side},
    framer::{Call, Crossed, DoorFacts, FramerDoor},
    wire::unlayered,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::slot as life;
use busbar_contract::abi::transport::slot;
use busbar_plugin_loader::dispatch::{
    kinds::transport::Transport as TransportKind, DispatchConfig, Dispatcher, Frame, InFrame,
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
        let d = Dispatcher::new(
            DispatchConfig::default(),
            busbar_kernel::host_services::caller_binding(),
        );
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
pub(crate) fn plugin_logs() -> &'static PluginLogConfig {
    static DEFAULTS: OnceLock<PluginLogConfig> = OnceLock::new();
    match LOGS.get() {
        Some(logs) => logs,
        None => DEFAULTS.get_or_init(|| {
            PluginLogConfig::from_words(None, None, &std::collections::BTreeMap::new(), None, None)
                .expect("the plugins.logs defaults resolve")
        }),
    }
}

// A door is bound once, when it is bound, and a config apply refreshes the opened instances once: both off
// the request path, so they are built in `off_path` (callers: the root's boot, linked-row loads and config
// reload).
pub use crate::off_path::egress::doors::{bind, bind_on, refresh_live, refresh_named, row_bind};

/// One transport door, opened, as the connector reaches it: on the dispatcher it was bound on,
pub struct Dispatched {
    pub(crate) listener_bindings:
        Vec<busbar_contract::abi::transport::listener_bindings::ListenerBinding>,
    pub(crate) live: Arc<Live>,
    pub(crate) facts: DoorFacts,
    /// Its tail states `FACT_ACCEPTS`.
    pub(crate) accepts: bool,
    pub(crate) detaches: bool,
    pub(crate) adopts: bool,
    /// Its Statement states it renders sealed values (TSEAL, `abi::transport::EXT_SEALED_VALUES`).
    pub(crate) seals: bool,
    /// Its Adopt consumes the host's admitted-session extension.
    pub(crate) adopts_session: bool,
    pub(crate) on: Arc<Dispatcher>,
}

/// ONE OPENED TRANSPORT INSTANCE, as a config apply refreshes it: the instance, the setting paths
pub(crate) struct Live {
    pub(crate) plugin: Plugin<TransportKind>,
    pub(crate) settings_keys: Vec<&'static str>,
    pub(crate) generation: AtomicU64,
    /// How many REFRESH crossings have returned, whatever their outcome: the door's settings
    /// epoch ([`FramerDoor::settings_epoch`]). `generation` is bumped before the crossing, so it
    /// cannot say the settings were applied.
    pub(crate) applied: AtomicU64,
}

/// EVERY TRANSPORT INSTANCE THIS PROCESS OPENED and still holds, linked and dropped in alike: what
pub(crate) static LIVE: Mutex<Vec<Weak<Live>>> = Mutex::new(Vec::new());

/// The settings blob a door that declares `declared` is opened with: each declared path the
/// deployment deals, as one compact JSON object with its keys in byte order, written straight
/// into the blob.
#[must_use]
pub fn settings_blob(
    declared: &[&str],
    s: &busbar_contract::transport::TransportSettings,
) -> Vec<u8> {
    // A door is handed its settings blob owned, once per open or config apply: off the request path.
    crate::off_path::egress::doors::settings_blob(declared, s)
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
        // A door is opened once, when it is bound: off the request path.
        crate::off_path::egress::doors::open_on(plugin, settings, on)
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
pub(crate) fn go<I: InFrame, O: OutFrame>(
    p: &Plugin<TransportKind>,
    s: u32,
    i: &mut I,
    o: &mut O,
) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.answer(s, &mut f);
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
    let c = p.answer_inline(ticket, resume, s, &mut f);
    *i = f.input;
    *o = f.out;
    Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

impl FramerDoor for Dispatched {
    fn settings_epoch(&self) -> u64 {
        self.live.applied.load(Ordering::Acquire)
    }

    fn incomplete_retirement(&self, error: &crate::framer::Refused) {
        if error.outcome == Outcome::Fault {
            self.live.plugin.incomplete_retirement();
        }
    }

    fn listener_bindings(
        &self,
    ) -> &[busbar_contract::abi::transport::listener_bindings::ListenerBinding] {
        &self.listener_bindings
    }
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

    fn detaches(&self) -> bool {
        self.detaches
    }

    fn adopts(&self) -> bool {
        self.adopts
    }

    fn instance(&self) -> Option<u64> {
        Some(self.live.plugin.instance().0)
    }

    fn io_owner(&self) -> Option<u64> {
        Some(self.live.plugin.io_owner())
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
            Call::Locate(i, o) => {
                if i.head.deadline_ns != 0 {
                    let Some(provider) = self.on.host_services() else {
                        return crate::cold::egress::no_host_clock();
                    };
                    // Framer deadlines and CLOCK_NOW have distinct epochs. Cross the ABI using
                    // the same provider clock the plugin reads when preparing its signed head.
                    let remaining = i.head.deadline_ns.saturating_sub(crate::framer::now_ns());
                    i.head.deadline_ns = provider.now().mono_ns.saturating_add(remaining).max(1);
                }
                go(p, slot::LOCATE, i, o)
            }
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

/// A door, opened with the deployment's `settings` and admitted to be served over the host's
/// sockets: it names no layer ([`unlayered`]).
pub fn served(
    plugin: Plugin<TransportKind>,
    settings: &busbar_contract::transport::TransportSettings,
) -> Result<Arc<dyn FramerDoor>, String> {
    let door: Arc<dyn FramerDoor> = Arc::new(Dispatched::open(plugin, settings)?);
    unlayered(door.as_ref())?;
    Ok(door)
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

/// Locate an endpoint on an admitted, bound declaration without opening a transport instance.
/// The adapter exposes only LOCATE; neither OPEN, READY, DNS nor a carrier is reached.
pub fn locate_bound(
    plugin: &Plugin<TransportKind>,
    target: &str,
) -> Result<crate::framer::Located, String> {
    // A configuration locate stands its declaration's facts up once, at boot: off the request path.
    crate::off_path::egress::doors::locate_bound(plugin, target)
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use busbar_plugin_loader::dispatch::kinds::transport::TransportFacts;

    /// A TCP carrier's validated facts, as its Statement states them: its own claim `tcp`, a
    /// ported carrier with a session, composed over nothing.
    fn tcp_carrier_facts() -> TransportFacts {
        TransportFacts {
            listener_bindings: Vec::new(),
            name: "tcp",
            role: busbar_contract::abi::transport::ROLE_CARRIER,
            claims: vec!["tcp"],
            upgrades: Vec::new(),
            sessions: vec!["tcp"],
            lines: Vec::new(),
            composes_over: Vec::new(),
            settings_keys: Vec::new(),
            ported: true,
            status_rows: Vec::new(),
            status_namespaces: Vec::new(),
            handoff_status: Vec::new(),
            datagram: false,
            accepts: false,
            dials: false,
            detaches: false,
            adopts: false,
            offered: offers_unstated(),
            seals: false,
            adopts_session: false,
        }
    }

    #[test]
    fn a_tcp_name_fault_is_refused() {
        let actual = tcp_carrier_facts();
        let positive = checked_row(actual.clone()).expect("the TCP identity is valid");
        assert_eq!(positive.key, "tcp");
        assert_eq!(positive.composes_over, actual.composes_over);
        assert_eq!(positive.session, !actual.sessions.is_empty());
        let mut faulted = actual.clone();
        faulted.name = "tcp-misnamed";
        let mut restored = faulted.clone();
        restored.name = actual.name;
        assert_eq!(restored, actual, "every other stated fact is retained");
        let refused = checked_row(faulted).expect_err("a name/own-claim mismatch is refused");
        assert!(
            refused.contains("`tcp-misnamed`") && refused.contains("`tcp`"),
            "the identity validator names both spellings: {refused}"
        );
        let mut unclaimed = actual;
        unclaimed.claims.clear();
        let refused = checked_row(unclaimed).expect_err("a door with no claim has no key");
        assert!(
            refused.contains("the transport door `tcp` claims no scheme"),
            "{refused}"
        );
    }
}
