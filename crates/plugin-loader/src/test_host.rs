// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SAFE TEST HOST (SDK-SAFE-TEST-HOST §3.1-3.2): load any plugin and drive it from test code
//! with no `unsafe`. An [`Image`] is admitted through the loader's own entries (`load_linked`, and
//! `load_dropped_bytes` over the memfd stage path production uses); a [`Host`] binds it to a real
//! [`Dispatcher`]; an [`Opened`] instance crosses through the loader's real `Plugin::call`, its
//! `in` built by the SDK boundary's [`Loans`]. The `Plugin` stays private: a test never names a
//! raw frame or a raw crossing (R131 (b) bans them in test code).
//!
//! A wrong slot index, or another slot's `in`, does not compile:
//!
//! ```compile_fail,E0277
//! use busbar_plugin_loader::dispatch::kinds::transport::Transport;
//! use busbar_plugin_loader::test_host::Opened;
//! use busbar_contract::abi::sdk::test_support::loans::Loans;
//! use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn};
//! fn open_again(t: &mut Opened<Transport>) {
//!     let _ = t.call::<{ slot::OPEN }>(Loans::<OpenIn>::new()); // a lifecycle slot: no kind op
//! }
//! ```
//!
//! An opened instance stays on its thread:
//!
//! ```compile_fail,E0277
//! use busbar_plugin_loader::dispatch::kinds::transport::Transport;
//! fn send(t: busbar_plugin_loader::test_host::Opened<Transport>) {
//!     std::thread::spawn(move || drop(t));
//! }
//! ```
//!
//! A pending crossing is resumed once:
//!
//! ```compile_fail,E0382
//! use busbar_plugin_loader::dispatch::kinds::transport::Transport;
//! use busbar_plugin_loader::test_host::{Opened, Pending};
//! use busbar_contract::abi::transport::{WriteIn, IoOut};
//! fn twice(t: &mut Opened<Transport>, p: Pending<WriteIn, IoOut>) {
//!     drop(p.resume(t));
//!     drop(p.resume(t));
//! }
//! ```
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out, KindSlot, RawDoorFn};
use busbar_contract::abi::sdk::out::Scalar;
use busbar_contract::abi::sdk::test_support::loans::{Buf, Loans, Pairs};
use busbar_contract::abi::sdk::test_support::mutant::Mutant;
use busbar_contract::conn::InstanceId;
use busbar_contract::services::{CallerBinding, HostServices};

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, transport::Transport,
};
use crate::dispatch::plugin::str_bytes;
use crate::dispatch::Done as Settled;
use crate::dispatch::{
    in_head, lifecycle, load_dropped_bytes, load_linked, out_head, rendering_of, Bind, ConnTable,
    Diagnostic, DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, InFrame, Kind, LinkedRow,
    LoadError, Metric, NoSink, OutFrame, Plugin, Recall, Reply,
};

/// Why a host refused to load or open an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The loader refused the image.
    Load(LoadError),
    /// The plugin refused to open (its error text).
    Open(String),
    /// The plugin opened but its READY failed (the host's refusal text).
    Ready(String),
}

#[derive(Debug, Clone)]
enum Source {
    Linked(DoorFn),
    LinkedStated(DoorFn, Vec<u8>),
    Bytes {
        bytes: Vec<u8>,
        display: String,
        stated: Result<Vec<u8>, LoadError>,
    },
    Raw(RawDoorFn),
    RawStated(RawDoorFn, Result<Vec<u8>, LoadError>),
}

/// A linked door or a staged cdylib, plus the Statement it must state.
#[derive(Debug, Clone)]
pub struct Image<K> {
    source: Source,
    _k: PhantomData<fn() -> K>,
}

impl<K: Kind> Image<K> {
    fn of(source: Source) -> Self {
        Self {
            source,
            _k: PhantomData,
        }
    }

    /// A compiled-in door (`load_linked`).
    #[must_use]
    pub fn linked(door: DoorFn) -> Self {
        Self::of(Source::Linked(door))
    }

    /// The cdylib built from `lib_name`, stating what its linked twin states (so the load's
    /// `StatementMismatch` also proves the two state the same thing). Lookup, first hit wins:
    /// `BUSBAR_PLUGIN_CDYLIB_<LIB>`, then `BUSBAR_PLUGIN_CDYLIB` when it names this library's
    /// file, then `<profile>/<file>`, then `<profile>/examples/<file>`.
    ///
    /// # Panics
    /// When no such file exists; the panic names where it looked.
    #[must_use]
    pub fn cdylib(lib_name: &str, linked_twin: DoorFn) -> Self {
        let path = locate(lib_name);
        Self::read(&path, rendering_of(linked_twin))
    }

    /// A cdylib with no linked twin, stating `stated`.
    ///
    /// # Panics
    /// When `path` cannot be read.
    #[must_use]
    pub fn cdylib_stated(path: &Path, stated: &[u8]) -> Self {
        Self::read(path, Ok(stated.to_vec()))
    }

    fn read(path: &Path, stated: Result<Vec<u8>, LoadError>) -> Self {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("read the cdylib {}: {e}", path.display()));
        Self::of(Source::Bytes {
            bytes,
            display: path.display().to_string(),
            stated,
        })
    }

    /// A compiled-in door that must state `stated` (STH-ROWS D-9): a door whose Statement differs
    /// is refused `StatementMismatch`, as a restated plugin is. Take `stated` from `rendering_of`
    /// of another door.
    #[must_use]
    pub fn linked_stated(door: DoorFn, stated: &[u8]) -> Self {
        Self::of(Source::LinkedStated(door, stated.to_vec()))
    }

    /// A boundary-forged door (`Mutant`), admitted as a linked row.
    #[must_use]
    pub fn mutant(m: Mutant) -> Self {
        Self::of(Source::Raw(m.door_fn()))
    }

    /// A boundary-forged door stating what `twin` states, so a mutant whose Statement differs is
    /// refused `StatementMismatch`, as a restated plugin is.
    #[must_use]
    pub fn mutant_as(m: Mutant, twin: DoorFn) -> Self {
        Self::of(Source::RawStated(m.door_fn(), rendering_of(twin)))
    }

    fn load(&self, bind: Bind) -> Result<Plugin<K>, LoadError> {
        match &self.source {
            Source::Linked(door) => load_linked::<K>(&LinkedRow::of_kind::<K>(*door)?, bind),
            Source::LinkedStated(door, stated) => load_linked::<K>(
                &LinkedRow {
                    statement: stated.clone(),
                    door: LinkedRow::of_kind::<K>(*door)?.door,
                },
                bind,
            ),
            Source::Bytes {
                bytes,
                display,
                stated,
            } => load_dropped_bytes::<K>(
                bytes,
                display,
                stated.as_ref().map_err(Clone::clone)?,
                bind,
            ),
            Source::Raw(door) => load_linked::<K>(&LinkedRow::of_raw(*door)?, bind),
            Source::RawStated(door, stated) => load_linked::<K>(
                &LinkedRow {
                    statement: stated.clone()?,
                    door: *door,
                },
                bind,
            ),
        }
    }
}

/// The bytes of the cdylib example `lib_name` (a MIN-3 image for [`admit_bytes`]), found where
/// [`Image::cdylib`] looks.
///
/// # Panics
/// When no such library exists (the panic names where it looked) or it cannot be read.
#[must_use]
pub fn cdylib_bytes(lib_name: &str) -> Vec<u8> {
    let path = locate(lib_name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn locate(lib_name: &str) -> PathBuf {
    let file = crate::plugin_library_filename(lib_name);
    let var = format!(
        "BUSBAR_PLUGIN_CDYLIB_{}",
        lib_name.to_ascii_uppercase().replace('-', "_")
    );
    if let Some(p) = std::env::var_os(&var) {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .filter(|p| p.file_name().is_some_and(|n| *n == *file))
    {
        return p;
    }
    let profile = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()))
        .unwrap_or_default();
    let tried = [profile.join(&file), profile.join("examples").join(&file)];
    tried.iter().find(|p| p.is_file()).cloned().unwrap_or_else(|| {
        panic!(
            "no cdylib for `{lib_name}`: set {var} or BUSBAR_PLUGIN_CDYLIB, or build it to {} or {}",
            tried[0].display(),
            tried[1].display()
        )
    })
}

/// The Statement rendering a mutant states (STH-ROWS D-3): the bytes a dropped plugin's manifest
/// would carry, rendered by the loader's own linked-row path, which checks the Statement first.
/// It forges the mutant, so it takes one of the mutant bank's doors.
pub fn rendering(m: Mutant) -> Result<Vec<u8>, LoadError> {
    LinkedRow::of_raw(m.door_fn()).map(|row| row.statement)
}

/// Runs `case` on the linked door, then on the cdylib; the first argument names the image.
pub fn both<K: Kind>(lib_name: &str, door: DoorFn, case: impl Fn(&str, Image<K>)) {
    case("linked", Image::linked(door));
    case("cdylib", Image::cdylib(lib_name, door));
}

/// A real dispatcher a test binds images to. Its builders are order-free: [`Host::services`] and
/// [`Host::config`] each rebuild the dispatcher from everything stated so far, so neither erases
/// the other.
pub struct Host {
    dispatcher: Arc<Dispatcher>,
    callers: Arc<dyn CallerBinding>,
    conns: ConnTable,
    config: DispatchConfig,
    services: Option<Arc<dyn HostServices>>,
    sink: Arc<dyn EnvelopeSink>,
}

impl Host {
    /// A host whose dispatcher binds callers through `callers` (a test passes
    /// `busbar_contract::services::test_caller_binding()`, behind its dev-only `test-seal`).
    #[must_use]
    pub fn new(callers: Arc<dyn CallerBinding>) -> Self {
        let config = DispatchConfig::default();
        Self {
            dispatcher: Arc::new(Dispatcher::new(config, Arc::clone(&callers))),
            callers,
            conns: ConnTable::Probe,
            config,
            services: None,
            sink: Arc::new(NoSink),
        }
    }

    /// Host services the test states: a safe `impl HostServices` that overrides only what it
    /// serves.
    #[must_use]
    pub fn services(mut self, services: Arc<dyn HostServices>) -> Self {
        self.services = Some(services);
        self.rebuild();
        self
    }

    /// The dispatcher's shape (STH-ROWS D-5: a test's `workers`, budgets or quarantine count).
    #[must_use]
    pub fn config(mut self, config: DispatchConfig) -> Self {
        self.config = config;
        self.rebuild();
        self
    }

    /// Where every image this host binds sends its envelope (STH-ROWS D-5): what production's sink
    /// sees, nothing raw. A test passes a recording sink (the facade's `Envelopes`).
    #[must_use]
    pub fn sink(mut self, sink: Arc<dyn EnvelopeSink>) -> Self {
        self.sink = sink;
        self
    }

    /// The dispatcher, rebuilt from the stated config and services.
    fn rebuild(&mut self) {
        let callers = Arc::clone(&self.callers);
        self.dispatcher = Arc::new(match &self.services {
            Some(services) => Dispatcher::with_services(self.config, Arc::clone(services), callers),
            None => Dispatcher::new(self.config, callers),
        });
    }

    /// The connection table images are bound to (default: a probe, which declares no need).
    #[must_use]
    pub fn conns(mut self, conns: ConnTable) -> Self {
        self.conns = conns;
        self
    }

    /// The dispatcher, for the loader's typed adapters.
    #[must_use]
    pub fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    fn bind<K: Kind>(&self, img: &Image<K>, name: &str) -> Result<Plugin<K>, Refused> {
        self.bind_with(img, name, Arc::clone(&self.sink))
    }

    fn bind_with<K: Kind>(
        &self,
        img: &Image<K>,
        name: &str,
        sink: Arc<dyn EnvelopeSink>,
    ) -> Result<Plugin<K>, Refused> {
        img.load(Bind {
            accept: Default::default(),
            instance: Arc::from(name),
            max_inflight_cap: 64,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns: self.conns.clone(),
        })
        .map_err(Refused::Load)
    }

    /// Loads and binds `img` as instance `name`, and nothing more (STH-ROWS D-1a): no OPEN, no
    /// READY, so a test can VALIDATE before any OPEN and see what an instance does before READY.
    pub fn load<K: Openable>(&self, img: Image<K>, name: &str) -> Result<Loaded<K>, Refused> {
        Ok(Loaded {
            plugin: self.bind(&img, name)?,
            dispatcher: Arc::clone(&self.dispatcher),
        })
    }

    /// Loads `img` as instance `name`, opens it with `settings` (JSON) and readies it.
    pub fn open<K: Openable>(
        &self,
        img: Image<K>,
        name: &str,
        settings: &[u8],
    ) -> Result<Opened<K>, Refused> {
        self.open_lent(img, name, settings, &[])
    }

    /// As [`Host::open`], with `secrets` lent to OPEN (SDK-SAFE-TEST-HOST §12.1, Gaps 5): each a
    /// `BLOB_SECRET` octet blob, as production lends a resolved secret, held only for the call.
    /// A plane is lent none here: a non-empty `secrets` refuses its open.
    pub fn open_lent<K: Openable>(
        &self,
        img: Image<K>,
        name: &str,
        settings: &[u8],
        secrets: &[&[u8]],
    ) -> Result<Opened<K>, Refused> {
        let plugin = self.bind(&img, name)?;
        K::open(&plugin, settings, secrets).map_err(Refused::Open)?;
        plugin
            .ready(&self.dispatcher, crate::dispatch::ready::READY_DEADLINE)
            .map_err(Refused::Ready)?;
        Ok(Opened {
            plugin: Some(plugin),
            flight: Rc::new(Cell::new(0)),
            dispatcher: Arc::clone(&self.dispatcher),
        })
    }

    /// An export image opened as the loader's typed [`ExportInstance`](crate::export_door::ExportInstance).
    pub fn export(
        &self,
        img: Image<Export>,
        name: &str,
        settings: &[u8],
    ) -> Result<crate::export_door::ExportInstance, Refused> {
        let plugin = self.bind(&img, name)?;
        crate::export_door::ExportInstance::open(plugin, Arc::clone(&self.dispatcher), settings)
            .map_err(Refused::Open)
    }

    /// An auth image opened as the loader's typed [`AuthInstance`](crate::auth_door::AuthInstance)
    /// (its sink fresh, no secrets lent).
    pub fn auth(
        &self,
        img: Image<Auth>,
        name: &str,
        settings: &[u8],
    ) -> Result<crate::auth_door::AuthInstance, Refused> {
        let sink = crate::auth_door::AuthSink::new(name);
        let tee: Arc<dyn EnvelopeSink> = Arc::new(Tee(sink.bind(), Arc::clone(&self.sink)));
        let plugin = self.bind_with(&img, name, tee)?;
        crate::auth_door::AuthInstance::open(
            plugin,
            sink,
            Arc::clone(&self.dispatcher),
            name,
            settings,
            Vec::new(),
        )
        .map_err(Refused::Open)
    }
}

/// What one lifecycle crossing answered (STH-ROWS D-1a/D-1b), copied; its lease, if any, is
/// already released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Life {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text, copied, for a FAILED or REFUSED answer.
    pub error: Option<Vec<u8>>,
    /// A READY TICK's `next_tick_ns`; `None` for every other answer.
    pub next_tick_ns: Option<u64>,
}

impl Life {
    /// The answer of a lifecycle crossing on `plugin`, its lease handed back.
    fn crossed<K: Kind>(plugin: &Plugin<K>, called: crate::dispatch::Called) -> Self {
        lifecycle::release(plugin, called.lease);
        Self {
            outcome: called.outcome,
            error: called.error,
            next_tick_ns: None,
        }
    }
}

/// A bound image that is not opened yet (STH-ROWS D-1a). VALIDATE crosses it before any OPEN.
/// Dropped, it sends no CLOSE: nothing was opened.
pub struct Loaded<K: Kind> {
    plugin: Plugin<K>,
    dispatcher: Arc<Dispatcher>,
}

impl<K: Openable> Loaded<K> {
    /// VALIDATE `settings` (JSON) on the bound, unopened instance.
    pub fn validate(&mut self, settings: &[u8]) -> Life {
        let called =
            lifecycle::validate_call(&self.plugin, lifecycle::blob(settings, BLOB_JSON, 0));
        Life::crossed(&self.plugin, called)
    }

    /// OPEN only, with `settings` (JSON) and `secrets` lent as [`Host::open_lent`] lends them;
    /// READY is the [`Opening`]'s own step. A refused OPEN hands the image back with the host's
    /// refusal and sends no CLOSE: an OPEN that did not answer READY opened nothing.
    pub fn open(self, settings: &[u8], secrets: &[&[u8]]) -> Result<Opening<K>, (Refused, Self)> {
        match K::open(&self.plugin, settings, secrets) {
            Ok(()) => Ok(Opening {
                plugin: Some(self.plugin),
                dispatcher: self.dispatcher,
            }),
            Err(text) => Err((Refused::Open(text), self)),
        }
    }
}

/// An instance whose OPEN answered READY, before its own READY step (STH-ROWS D-1a). It holds no
/// kind op, so nothing can be in flight on it. Dropped, it CLOSEs once.
pub struct Opening<K: Kind> {
    plugin: Option<Plugin<K>>,
    dispatcher: Arc<Dispatcher>,
}

impl<K: Kind> Opening<K> {
    /// READY: the opened instance. A failed READY hands the opening back with the host's text.
    pub fn ready(mut self) -> Result<Opened<K>, (Refused, Self)> {
        let ready = self
            .plugin
            .as_ref()
            .expect("an opening holds its plugin until drop")
            .ready(&self.dispatcher, crate::dispatch::ready::READY_DEADLINE);
        match ready {
            Ok(()) => Ok(Opened {
                plugin: self.plugin.take(),
                flight: Rc::new(Cell::new(0)),
                dispatcher: Arc::clone(&self.dispatcher),
            }),
            Err(text) => Err((Refused::Ready(text), self)),
        }
    }
}

impl<K: Kind> Drop for Opening<K> {
    fn drop(&mut self) {
        if let Some(plugin) = self.plugin.take() {
            lifecycle::close(&plugin);
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A kind [`Host::open`] can open: OPEN with JSON settings (a plane through its own open).
pub trait Openable: Kind + Sized + sealed::Sealed {
    #[doc(hidden)]
    fn open(plugin: &Plugin<Self>, settings: &[u8], secrets: &[&[u8]]) -> Result<(), String> {
        let lent: Vec<Blob> = secrets
            .iter()
            .map(|s| lifecycle::blob(s, BLOB_OCTETS, BLOB_SECRET))
            .collect();
        let mut i: OpenIn = blank_in();
        i.settings = lifecycle::blob(settings, BLOB_JSON, 0);
        if !lent.is_empty() {
            i.secrets = lent.as_ptr();
            i.secrets_len = lent.len();
        }
        i.generation = 1;
        let mut f = Frame::new(i, blank_out::<OpenOut>());
        let opened = plugin.call(life::OPEN, &mut f);
        lifecycle::release(plugin, opened.lease);
        if opened.outcome == Outcome::Ready {
            Ok(())
        } else {
            Err(opened.open_failure(plugin.name()))
        }
    }
}

macro_rules! openable {
    ($($k:ty),+) => {$( impl sealed::Sealed for $k {} impl Openable for $k {} )+};
}
openable!(Transport, Auth, Hook, Export);
impl sealed::Sealed for Plane {}
impl Openable for Plane {
    fn open(plugin: &Plugin<Self>, settings: &[u8], secrets: &[&[u8]]) -> Result<(), String> {
        if !secrets.is_empty() {
            return Err(String::from(
                "the test host lends a plane's OPEN no secrets: open it with none",
            ));
        }
        crate::dispatch::kinds::plane::open_door(plugin, settings, b"", None).map(drop)
    }
}

/// The `in` of kind op `I` of kind `K`.
pub type InOf<K, const I: u32> = <<K as Kind>::Ops as KindSlot<I>>::In;
/// The `out` of kind op `I` of kind `K`.
pub type OutOf<K, const I: u32> = <<K as Kind>::Ops as KindSlot<I>>::Out;

/// One opened instance. CLOSE runs on drop, unless a pending crossing was forgotten: then the
/// instance is poisoned, CLOSE is skipped and it leaks, so no pointer the plugin holds dangles.
/// `!Send` and `!Sync`.
pub struct Opened<K: Kind> {
    plugin: Option<Plugin<K>>,
    flight: Rc<Cell<u32>>,
    /// The dispatcher a ticketed submission crosses (STH-ROWS D-6).
    dispatcher: Arc<Dispatcher>,
}

impl<K: Kind> Opened<K> {
    fn instance(&self) -> &Plugin<K> {
        self.plugin
            .as_ref()
            .expect("an open instance holds its plugin until drop")
    }

    /// Panics while a crossing on this instance is still in flight (the method panics, never a
    /// `Drop`).
    fn idle(&self) {
        assert_eq!(
            self.flight.get(),
            0,
            "a pending crossing is still in flight on this instance"
        );
    }

    /// The instance's id: the same across every REFRESH (STH-ROWS D-1b).
    #[must_use]
    pub fn instance_id(&self) -> InstanceId {
        self.instance().instance()
    }

    /// VALIDATE `settings` (JSON) on the open instance (STH-ROWS D-1b).
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked.
    pub fn validate(&mut self, settings: &[u8]) -> Life {
        self.idle();
        let plugin = self.instance();
        let called = lifecycle::validate_call(plugin, lifecycle::blob(settings, BLOB_JSON, 0));
        Life::crossed(plugin, called)
    }

    /// REFRESH to `generation` with `settings` (JSON) and `secrets`, each lent as a
    /// `BLOB_SECRET` octet blob for the call only, as OPEN lends them (STH-ROWS D-1b).
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked.
    pub fn refresh(&mut self, settings: &[u8], secrets: &[&[u8]], generation: u64) -> Life {
        self.idle();
        let lent: Vec<Blob> = secrets
            .iter()
            .map(|s| lifecycle::blob(s, BLOB_OCTETS, BLOB_SECRET))
            .collect();
        let mut i = RefreshIn {
            head: in_head(),
            generation,
            settings: lifecycle::blob(settings, BLOB_JSON, 0),
            secrets: std::ptr::null(),
            secrets_len: 0,
        };
        if !lent.is_empty() {
            i.secrets = lent.as_ptr();
            i.secrets_len = lent.len();
        }
        let mut f = Frame::new(i, out_head());
        let plugin = self.instance();
        let called = plugin.call(life::REFRESH, &mut f);
        Life::crossed(plugin, called)
    }

    /// TICK at `now_ns`; a READY answer carries the plugin's `next_tick_ns` (STH-ROWS D-1b).
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked.
    pub fn tick(&mut self, now_ns: u64) -> Life {
        self.idle();
        let mut f = Frame::new(
            TickIn {
                head: in_head(),
                now_ns,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let plugin = self.instance();
        let called = plugin.call(life::TICK, &mut f);
        let mut ticked = Life::crossed(plugin, called);
        if ticked.outcome == Outcome::Ready {
            ticked.next_tick_ns = Some(f.out.next_tick_ns);
        }
        ticked
    }

    /// RETIRE `generation`, after its drain (STH-ROWS D-1b).
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked.
    pub fn retire(&mut self, generation: u64) -> Life {
        self.idle();
        let mut f = Frame::new(
            GenIn {
                head: in_head(),
                generation,
            },
            out_head(),
        );
        let plugin = self.instance();
        let called = plugin.call(life::RETIRE, &mut f);
        Life::crossed(plugin, called)
    }

    /// CLOSE now, and its answer; the drop that follows sends no second CLOSE (STH-ROWS D-1b).
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked: the panic comes
    /// before any CLOSE, and the unwinding drop poisons the instance as a forgotten crossing does.
    pub fn close(mut self) -> Life {
        self.idle();
        let plugin = self
            .plugin
            .take()
            .expect("an open instance holds its plugin until drop");
        let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        let called = plugin.call(life::CLOSE, &mut f);
        Life {
            outcome: called.outcome,
            error: called.error,
            next_tick_ns: None,
        }
    }

    /// Kind op `I` with `loans` as its `in`, through the loader's real crossing.
    ///
    /// # Panics
    /// While a pending crossing on this instance is neither resumed nor leaked.
    pub fn call<const I: u32>(
        &mut self,
        loans: Loans<InOf<K, I>>,
    ) -> Called<'_, InOf<K, I>, OutOf<K, I>>
    where
        K::Ops: KindSlot<I>,
        InOf<K, I>: InFrame + Pairs,
        OutOf<K, I>: OutFrame,
    {
        assert_eq!(
            self.flight.get(),
            0,
            "a pending crossing is still in flight on this instance"
        );
        let mut loans = loans;
        let mut frame = Box::new(Frame::new(loans.seal(), blank_out::<OutOf<K, I>>()));
        let called = self.instance().call(I, &mut frame);
        self.answer(loans, frame, called, I)
    }

    /// Kind op `I` with `loans` as its `in`, submitted on a fresh ticket through the dispatcher's
    /// real ticketed path (STH-ROWS D-6): the op may PEND, be cancelled, or answer SHORT and be
    /// resubmitted once on the same ticket. A submission borrows the instance, so neither `call`
    /// nor a lifecycle method compiles while one lives; several may overlap, as production's
    /// ticketed submissions do. The loans stay on this thread: the dispatcher is handed only the
    /// frame, whose `in` is the sealed copy and names only storage the loans own.
    ///
    /// # Panics
    /// When the dispatcher mints no ticket on its first worker.
    pub fn submit<const I: u32>(
        &self,
        loans: Loans<InOf<K, I>>,
    ) -> Submitted<'_, InOf<K, I>, OutOf<K, I>>
    where
        K::Ops: KindSlot<I>,
        InOf<K, I>: InFrame + Pairs,
        OutOf<K, I>: OutFrame,
    {
        let plugin = self.instance();
        let dispatcher: &Dispatcher = &self.dispatcher;
        let ticket = dispatcher
            .mint(0)
            .expect("the test host's dispatcher mints a ticket on its first worker");
        let blank = blank_out::<OutOf<K, I>>();
        let mut loans = loans;
        let frame = Frame::new(loans.seal(), blank);
        let resend: Resend<'_, InOf<K, I>, OutOf<K, I>> =
            Box::new(move |frame: Frame<InOf<K, I>, OutOf<K, I>>| {
                dispatcher.submit(plugin, ticket, I, frame, DeadlineClass::Call, 0)
            });
        let reply = resend(frame);
        self.flight.set(self.flight.get() + 1);
        Submitted {
            lane: Some(Lane {
                dispatcher,
                resend,
                release: Box::new(move |lease: u64| lifecycle::release(plugin, lease)),
                flight: Rc::clone(&self.flight),
                ticket,
                blank,
                loans: Some(loans),
                resubmitted: false,
            }),
            reply: Some(reply),
        }
    }

    fn answer<In: Copy + 'static, Out: Copy>(
        &self,
        loans: Loans<In>,
        frame: Box<Frame<In, Out>>,
        called: crate::dispatch::Called,
        slot: u32,
    ) -> Called<'_, In, Out> {
        let plugin = self.instance();
        let lease = called.lease;
        match called.recall {
            Some(recall) => {
                lifecycle::release(plugin, lease);
                self.flight.set(self.flight.get() + 1);
                Called::Pending(Pending {
                    loans: Some(loans),
                    frame: Some(frame),
                    recall: Some(recall),
                    slot,
                    flight: Rc::clone(&self.flight),
                })
            }
            None => Called::Ready(Answer {
                out: frame.out,
                outcome: called.outcome,
                error: called.error,
                loans,
                release: Some(Box::new(move || lifecycle::release(plugin, lease))),
            }),
        }
    }
}

impl<K: Kind> Drop for Opened<K> {
    fn drop(&mut self) {
        let Some(plugin) = self.plugin.take() else {
            return;
        };
        if self.flight.get() == 0 {
            lifecycle::close(&plugin);
        } else {
            // POISONED: the plugin may still hold pointers into leaked loans, so CLOSE is skipped
            // and the instance leaks with them.
            std::mem::forget(plugin);
        }
    }
}

/// What one crossing answered.
pub enum Called<'o, In, Out> {
    /// It answered; the answer borrows the instance until dropped.
    Ready(Answer<'o, In, Out>),
    /// It answered SHORT: the one re-call it earned, holding the loans.
    Pending(Pending<In, Out>),
}

/// One answer, read while the instance's lease on it is held (released on drop).
pub struct Answer<'o, In, Out> {
    out: Out,
    outcome: Outcome,
    error: Option<Vec<u8>>,
    loans: Loans<In>,
    release: Option<Box<dyn FnOnce() + 'o>>,
}

impl<In, Out> Answer<'_, In, Out> {
    /// The authoritative outcome.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The error text, copied, for a FAILED or REFUSED answer.
    #[must_use]
    pub fn error(&self) -> Option<&[u8]> {
        self.error.as_deref()
    }

    /// A scalar of the `out`, copied: `answer.get(|o| o.len)`.
    #[must_use]
    pub fn get<T: Scalar>(&self, pick: impl FnOnce(&Out) -> T) -> T {
        pick(&self.out)
    }

    /// A plugin-owned string of the `out`, copied after the host's own bounds check (`None`: NULL
    /// with a length, or over-long). Trusted as far as the production host trusts it.
    #[must_use]
    pub fn text(&self, pick: impl FnOnce(&Out) -> AbiStr) -> Option<Vec<u8>> {
        str_bytes(pick(&self.out)).map(<[u8]>::to_vec)
    }

    /// A plugin-owned payload of the `out` (its head's `extensions` included), copied when it is
    /// within the host's hard cap; empty when absent.
    #[must_use]
    pub fn blob(&self, pick: impl FnOnce(&Out) -> Blob) -> Vec<u8> {
        let b = pick(&self.out);
        if b.len > HARD_MAX_BYTES as usize {
            return Vec::new();
        }
        lifecycle::copy_blob(b)
    }

    /// The values a host buffer the loans lent holds after the crossing.
    #[must_use]
    pub fn read<E: Scalar>(&self, key: &Buf<E>) -> &[E] {
        self.loans.read(key)
    }
}

impl<In, Out> Drop for Answer<'_, In, Out> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// A crossing that answered SHORT. It owns its loans and frame: [`Pending::resume`] spends the
/// re-call, [`Pending::leak_loans`] leaks them on purpose. Dropped otherwise (or forgotten), the
/// loans leak, the instance is poisoned, and a drop panics unless the thread already is.
pub struct Pending<In, Out> {
    loans: Option<Loans<In>>,
    frame: Option<Box<Frame<In, Out>>>,
    recall: Option<Recall>,
    slot: u32,
    flight: Rc<Cell<u32>>,
}

impl<In: InFrame + Pairs, Out: OutFrame> Pending<In, Out> {
    /// Grows the loans before the one re-call (STH-ROWS D-8): `grow` sets a bigger buffer (or any
    /// field) through the loans' own setters, and the `in` is sealed again into the pending frame.
    /// Storage `grow` replaces is retired, not freed, until the loans drop. Nothing of the first
    /// call's head is carried: the host stamps every head field again on the re-call.
    #[must_use]
    pub fn regrow(mut self, grow: impl FnOnce(&mut Loans<In>)) -> Self {
        let (Some(loans), Some(frame)) = (self.loans.as_mut(), self.frame.as_mut()) else {
            unreachable!("a pending crossing holds its loans until it is spent")
        };
        grow(&mut *loans);
        frame.input = loans.seal();
        self
    }
}

impl<In: InFrame, Out: OutFrame> Pending<In, Out> {
    /// The one re-call, through the loader's Recall path.
    ///
    /// # Panics
    /// When `t` is not the instance this crossing pended on.
    pub fn resume<K: Kind>(mut self, t: &mut Opened<K>) -> Called<'_, In, Out> {
        assert!(
            Rc::ptr_eq(&self.flight, &t.flight),
            "resumed on another instance"
        );
        self.flight.set(self.flight.get().saturating_sub(1));
        let (Some(loans), Some(mut frame), Some(recall)) =
            (self.loans.take(), self.frame.take(), self.recall.take())
        else {
            unreachable!("a pending crossing holds its loans until it is spent")
        };
        let called = t.instance().recall(recall, self.slot, &mut frame);
        t.answer(loans, frame, called, self.slot)
    }
}

impl<In, Out> Pending<In, Out> {
    /// Leaks the loans and the frame, so every pointer the plugin holds stays valid, and frees
    /// the instance for the next call.
    pub fn leak_loans(mut self) {
        std::mem::forget(self.loans.take());
        std::mem::forget(self.frame.take());
        self.recall = None;
        self.flight.set(self.flight.get().saturating_sub(1));
    }
}

impl<In, Out> Drop for Pending<In, Out> {
    fn drop(&mut self) {
        if self.loans.is_none() {
            return;
        }
        std::mem::forget(self.loans.take());
        std::mem::forget(self.frame.take());
        if !std::thread::panicking() {
            panic!("a pending crossing was dropped: resume it or leak_loans() it");
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// MIN-3 admission (IF §11.1; WBS rule 15; SDK-SAFE-TEST-HOST §5 "Load"). W1-L1: the door half above loads old-ABI
// doors through `dispatch::{load_linked, load_dropped_bytes}`, and an old door is not a MIN-3 header, so it cannot
// be admitted; it is a door-model type deleted with `dispatch/**` (STH §5 "Drive"). These entries admit MIN-3
// images through the loader's own `admit_linked` and `admit` (the dropped-in image staged and opened exactly as in
// production), signed by a fixed test key that only `test_trust` trusts. Nothing here names `dispatch`.
// ---------------------------------------------------------------------------------------------------------------

/// The publisher every test-signed MIN-3 manifest names; only [`test_trust`] trusts it.
pub const TEST_PUBLISHER: &str = "busbar-test";

/// The test signing key (a fixed seed: never a release key, trusted by nothing but [`test_trust`]).
#[must_use]
pub fn test_key() -> crate::sign::SigningKey {
    crate::sign::SigningKey::from_bytes(&[0x5a; 32])
}

/// A `plugins.trust` that trusts [`TEST_PUBLISHER`]'s [`test_key`] only for `expected_scope`
/// (no opt-in flag). The scope must come from the fixture's expectation, not the manifest under test.
#[must_use]
pub fn test_trust(expected_scope: &str) -> crate::admit::TrustConfig {
    let mut trust = crate::sign::TrustPolicy::default();
    trust.publishers.insert(
        TEST_PUBLISHER.to_string(),
        crate::sign::PublisherTrust {
            plugins: [expected_scope.to_string()].into_iter().collect(),
            keys: vec![crate::sign::PublisherKey {
                key: test_key().verifying_key(),
                revoked: false,
            }],
        },
    );
    trust
}

/// The manifest a pack would sign for `bytes`: name, version, kind and ABI read from the image's own stamp,
/// `former_names` as the header states them, signed by [`test_key`] under [`TEST_PUBLISHER`].
///
/// # Errors
/// The image's stamp scan refusal (no stamp, more than one, or a malformed one).
pub fn test_manifest(
    bytes: &[u8],
    former_names: &[&str],
) -> Result<crate::admit::SignedManifest, crate::refusal::Refusal> {
    let stamp = crate::scan::stamp(bytes).map_err(crate::scan::StampScanErr::refusal)?;
    let kind = busbar_plugin_abi::types::KindCode::from_raw(stamp.kind)
        .map_or("", crate::admit::kind_word);
    let name = crate::scan::text(&stamp.name).to_string();
    let manifest = crate::sign::Manifest {
        alias: name.clone(),
        name,
        kind: kind.to_string(),
        version: crate::scan::text(&stamp.version).to_string(),
        publisher: TEST_PUBLISHER.to_string(),
        abi_version: stamp.kind_abi,
        former_names: former_names.iter().map(|n| (*n).to_string()).collect(),
        ..crate::sign::Manifest::default()
    };
    Ok(test_sign(manifest, bytes))
}

/// `manifest` re-signed by [`test_key`] over `bytes` (its `sha256` set to theirs).
#[must_use]
pub fn test_sign(
    manifest: crate::admit::SignedManifest,
    bytes: &[u8],
) -> crate::admit::SignedManifest {
    crate::sign::sign(&test_key(), manifest, bytes)
}

/// A compiled-in MIN-3 image, through the loader's `admit_linked` (steps 3 to 7 on the static).
///
/// # Errors
/// The loader's refusal.
pub fn admit_linked(
    plugin: &'static busbar_ffi::LinkedPlugin,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    crate::admit::admit_linked(plugin)
}

/// A dropped-in MIN-3 image: `bytes` written to a private file, opened read-only, unlinked, and admitted from
/// that descriptor through the loader's `admit` under [`test_trust`] for the explicit expected plugin
/// scope (every step production runs).
///
/// # Errors
/// The loader's refusal.
///
/// # Panics
/// When the scratch file cannot be written or opened.
#[cfg(unix)]
pub fn admit_bytes(
    bytes: &[u8],
    manifest: &crate::admit::SignedManifest,
    expected_scope: &str,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    use std::io::Write as _;
    let path = std::env::temp_dir().join(format!(
        "busbar-test-admit-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("create the scratch image {}: {e}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|e| panic!("write the scratch image {}: {e}", path.display()));
    drop(file);
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("open the scratch image {}: {e}", path.display()));
    let _ = std::fs::remove_file(&path);
    crate::admit::admit(
        std::os::fd::OwnedFd::from(file),
        manifest,
        &test_trust(expected_scope),
    )
}

/// The cdylib built from `lib_name` (found as [`Image::cdylib`] finds it), admitted through `admit` under a
/// [`test_manifest`] stating `former_names`, trusted only for the explicit `expected_scope`.
///
/// # Errors
/// The loader's refusal.
///
/// # Panics
/// When no such file exists or it cannot be read.
#[cfg(unix)]
pub fn admit_cdylib(
    lib_name: &str,
    former_names: &[&str],
    expected_scope: &str,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    let path = locate(lib_name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read the cdylib {}: {e}", path.display()));
    let manifest = test_manifest(&bytes, former_names)?;
    admit_bytes(&bytes, &manifest, expected_scope)
}

/// How long a settled submission waits for its worker's retirement barrier before its loans are
/// leaked instead of freed.
const BARRIER: Duration = Duration::from_secs(5);

/// A submission's re-send on its own ticket.
type Resend<'o, In, Out> = Box<dyn Fn(Frame<In, Out>) -> Reply<In, Out> + 'o>;

/// What a ticketed submission holds until its loans are freed or leaked: its ticket, its loans
/// and the instance's shared flight counter (raised while it lives).
struct Lane<'o, In, Out> {
    dispatcher: &'o Dispatcher,
    resend: Resend<'o, In, Out>,
    release: Box<dyn Fn(u64) + 'o>,
    flight: Rc<Cell<u32>>,
    ticket: Ticket,
    /// A blank `out`, for a resubmission's fresh frame.
    blank: Out,
    loans: Option<Loans<In>>,
    /// Whether this is already the one resubmission a SHORT answer earned.
    resubmitted: bool,
}

impl<In, Out> Lane<'_, In, Out> {
    /// A settled op: its loans freed and its ticket recycled once the worker's retirement barrier
    /// passes; leaked, with the instance left poisoned, when it does not.
    fn settle(mut self) {
        if self.dispatcher.retirement_barrier(self.ticket, BARRIER) {
            drop(self.loans.take());
            self.dispatcher.recycle(self.ticket);
            self.flight.set(self.flight.get().saturating_sub(1));
        } else {
            std::mem::forget(self.loans.take());
        }
    }

    /// Leaks the loans on purpose, so every pointer the plugin may hold stays valid, and frees
    /// the instance for its next call.
    fn leak(mut self) {
        std::mem::forget(self.loans.take());
        self.flight.set(self.flight.get().saturating_sub(1));
    }

    /// Leaks the loans and leaves the instance poisoned: CLOSE is skipped when it drops.
    fn poison(mut self) {
        std::mem::forget(self.loans.take());
    }
}

/// The lane and the reply of a submission that is being spent.
fn spent<'o, In, Out>(
    lane: &mut Option<Lane<'o, In, Out>>,
    reply: &mut Option<Reply<In, Out>>,
) -> (Lane<'o, In, Out>, Reply<In, Out>) {
    match (lane.take(), reply.take()) {
        (Some(lane), Some(reply)) => (lane, reply),
        _ => unreachable!("a submission holds its loans until it is spent"),
    }
}

/// The reply waited for, up to `within`.
fn waited<'o, In: InFrame, Out: OutFrame>(
    lane: Lane<'o, In, Out>,
    reply: Reply<In, Out>,
    within: Duration,
) -> Result<Done<'o, In, Out>, TimedOut<'o, In, Out>> {
    match reply.wait(within) {
        Some(settled) => Ok(Done::of(lane, settled)),
        None => Err(TimedOut {
            lane: Some(lane),
            reply: Some(reply),
        }),
    }
}

/// A ticketed submission in flight (STH-ROWS D-6): it holds its loans, and gives no access to
/// them, until it is [`Done`]. Spend it with [`Submitted::wait`] or [`Submitted::cancel`].
/// Dropped unspent (or forgotten), its loans leak, the instance is poisoned (CLOSE skipped), and
/// the drop panics unless the thread already is.
pub struct Submitted<'o, In, Out> {
    lane: Option<Lane<'o, In, Out>>,
    reply: Option<Reply<In, Out>>,
}

impl<'o, In: InFrame, Out: OutFrame> Submitted<'o, In, Out> {
    /// The op's answer, waited for up to `within`.
    pub fn wait(mut self, within: Duration) -> Result<Done<'o, In, Out>, TimedOut<'o, In, Out>> {
        let (lane, reply) = spent(&mut self.lane, &mut self.reply);
        waited(lane, reply, within)
    }

    /// The client drops the op, as production's caller does at its deadline: the dispatcher
    /// CANCELs it on its ticket, and the answer, waited for up to `within`, carries the kind's
    /// disposition ([`Done::disposition`]).
    pub fn cancel(mut self, within: Duration) -> Result<Done<'o, In, Out>, TimedOut<'o, In, Out>> {
        let (lane, reply) = spent(&mut self.lane, &mut self.reply);
        lane.dispatcher.drop_client(lane.ticket);
        waited(lane, reply, within)
    }
}

impl<In, Out> Drop for Submitted<'_, In, Out> {
    fn drop(&mut self) {
        let Some(lane) = self.lane.take() else {
            return;
        };
        lane.poison();
        if !std::thread::panicking() {
            panic!("a submission was dropped unspent: wait() or cancel() it");
        }
    }
}

/// A submission whose answer did not come within the wait. Wait again, or leak its loans.
/// Dropped otherwise, it poisons the instance as an unspent [`Submitted`] does.
pub struct TimedOut<'o, In, Out> {
    lane: Option<Lane<'o, In, Out>>,
    reply: Option<Reply<In, Out>>,
}

impl<'o, In: InFrame, Out: OutFrame> TimedOut<'o, In, Out> {
    /// The op's answer, waited for up to `within` more.
    pub fn wait(mut self, within: Duration) -> Result<Done<'o, In, Out>, Self> {
        let (lane, reply) = spent(&mut self.lane, &mut self.reply);
        waited(lane, reply, within)
    }

    /// The client drops the op, as [`Submitted::cancel`] does, and its answer is waited for up to
    /// `within`.
    pub fn cancel(mut self, within: Duration) -> Result<Done<'o, In, Out>, Self> {
        let (lane, reply) = spent(&mut self.lane, &mut self.reply);
        lane.dispatcher.drop_client(lane.ticket);
        waited(lane, reply, within)
    }

    /// Leaks the loans on purpose and frees the instance for its next call; the client drops the
    /// op as the reply goes.
    pub fn leak_loans(mut self) {
        if let Some(lane) = self.lane.take() {
            lane.leak();
        }
    }
}

impl<In, Out> Drop for TimedOut<'_, In, Out> {
    fn drop(&mut self) {
        let Some(lane) = self.lane.take() else {
            return;
        };
        lane.poison();
        if !std::thread::panicking() {
            panic!("a timed-out submission was dropped: wait() again or leak_loans() it");
        }
    }
}

/// A settled submission (STH-ROWS D-6), read as an [`Answer`] is, while the instance's lease on
/// it is held. Dropped, the lease is released, then the loans are freed and the ticket recycled
/// once the worker's retirement barrier passes (leaked otherwise). It never panics in `Drop`.
pub struct Done<'o, In, Out> {
    lane: Option<Lane<'o, In, Out>>,
    out: Option<Out>,
    outcome: Outcome,
    error: Option<Vec<u8>>,
    lease: u64,
    short: bool,
    disposition: Option<u32>,
}

impl<'o, In, Out> Done<'o, In, Out> {
    fn of(lane: Lane<'o, In, Out>, settled: Settled<In, Out>) -> Self {
        Self {
            lane: Some(lane),
            out: settled.frame.map(|f| f.out),
            outcome: settled.outcome,
            error: settled.error,
            lease: settled.lease,
            short: settled.short,
            disposition: settled.disposition,
        }
    }

    /// The `out` the op answered.
    fn answered(&self) -> &Out {
        self.out
            .as_ref()
            .expect("the op was faulted mid-crossing or detached: no `out` came back")
    }

    /// The authoritative outcome.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The error text, copied, for a FAILED or REFUSED answer.
    #[must_use]
    pub fn error(&self) -> Option<&[u8]> {
        self.error.as_deref()
    }

    /// Whether the answer is one the kind calls SHORT: resubmit it once with grown loans.
    #[must_use]
    pub fn short(&self) -> bool {
        self.short
    }

    /// The kind's `CancelOut.disposition` when the op ended through CANCEL; `None` when it did
    /// not, or when the CANCEL faulted.
    #[must_use]
    pub fn disposition(&self) -> Option<u32> {
        self.disposition
    }

    /// A scalar of the `out`, copied.
    ///
    /// # Panics
    /// When no `out` came back (the op was faulted mid-crossing).
    #[must_use]
    pub fn get<T: Scalar>(&self, pick: impl FnOnce(&Out) -> T) -> T {
        pick(self.answered())
    }

    /// A plugin-owned string of the `out`, copied after the host's own bounds check.
    ///
    /// # Panics
    /// When no `out` came back (the op was faulted mid-crossing).
    #[must_use]
    pub fn text(&self, pick: impl FnOnce(&Out) -> AbiStr) -> Option<Vec<u8>> {
        str_bytes(pick(self.answered())).map(<[u8]>::to_vec)
    }

    /// A plugin-owned payload of the `out`, copied when it is within the host's hard cap.
    ///
    /// # Panics
    /// When no `out` came back (the op was faulted mid-crossing).
    #[must_use]
    pub fn blob(&self, pick: impl FnOnce(&Out) -> Blob) -> Vec<u8> {
        let b = pick(self.answered());
        if b.len > HARD_MAX_BYTES as usize {
            return Vec::new();
        }
        lifecycle::copy_blob(b)
    }

    /// The values a host buffer the loans lent holds after the op.
    #[must_use]
    pub fn read<E: Scalar>(&self, key: &Buf<E>) -> &[E] {
        match self.lane.as_ref().and_then(|l| l.loans.as_ref()) {
            Some(loans) => loans.read(key),
            None => &[],
        }
    }
}

impl<'o, In: InFrame + Pairs, Out: OutFrame> Done<'o, In, Out> {
    /// The one resubmission a SHORT answer earned, on the same ticket: `grow` grows the loans
    /// (storage it replaces is retired until the loans drop), the lease is handed back, and the
    /// loans are sealed into a fresh frame. A second SHORT is the dispatcher's FAULT.
    ///
    /// # Panics
    /// When the answer is not SHORT, or already answers a resubmission.
    pub fn resubmit(mut self, grow: impl FnOnce(&mut Loans<In>)) -> Submitted<'o, In, Out> {
        assert!(self.short, "only a SHORT answer is resubmitted");
        assert!(
            self.lane.as_ref().is_some_and(|l| !l.resubmitted),
            "a SHORT answer is resubmitted once"
        );
        let Some(mut lane) = self.lane.take() else {
            unreachable!("checked above")
        };
        (lane.release)(std::mem::take(&mut self.lease));
        let Some(loans) = lane.loans.as_mut() else {
            unreachable!("a lane holds its loans until it settles")
        };
        grow(&mut *loans);
        let frame = Frame::new(loans.seal(), lane.blank);
        let reply = (lane.resend)(frame);
        lane.resubmitted = true;
        Submitted {
            lane: Some(lane),
            reply: Some(reply),
        }
    }
}

impl<In, Out> Drop for Done<'_, In, Out> {
    fn drop(&mut self) {
        let Some(lane) = self.lane.take() else {
            return;
        };
        (lane.release)(std::mem::take(&mut self.lease));
        lane.settle();
    }
}

/// Forwards each envelope entry to two sinks: an auth instance binds production's own flush sink
/// and the host's, so the flushed count moves as it does in production.
struct Tee(Arc<dyn EnvelopeSink>, Arc<dyn EnvelopeSink>);

impl EnvelopeSink for Tee {
    fn metric(&self, m: Metric<'_>) {
        self.0.metric(m);
        self.1.metric(m);
    }

    fn diag(&self, d: Diagnostic<'_>) {
        self.0.diag(d);
        self.1.diag(d);
    }

    fn dropped(&self, why: Dropped) {
        self.0.dropped(why);
        self.1.dropped(why);
    }
}

/// Native stores for tests outside a booted root (the dist fixtures): one registry over one admitted store image,
/// opening each instance with no Needs and no reference sources. Enough for a store whose `open` makes no NEED and
/// binds no reference (a local file store such as store-sqlite: it calls only host services). The registry
/// outlives every handle it opened.
pub struct NativeStores {
    registry: crate::instance::Registry,
}

/// The test binary's one set of process plugin resources (a process installs its plugin sinks once).
///
/// # Errors
/// The resources could not start.
pub fn shared_process() -> Result<&'static crate::process::ProcessResources, &'static String> {
    static PROCESS: std::sync::OnceLock<Result<crate::process::ProcessResources, String>> =
        std::sync::OnceLock::new();
    PROCESS
        .get_or_init(crate::process::ProcessResources::new)
        .as_ref()
}

impl NativeStores {
    /// One registry over `admitted`, binding through `binder` (the kernel's `plugin_config::Binder`).
    ///
    /// # Errors
    /// The process resources or the image's admission refusal.
    pub fn new(
        admitted: crate::admit::Admitted,
        binder: Arc<dyn busbar_ports::binder::ConfigBinder>,
    ) -> Result<Self, crate::refusal::Refusal> {
        let process = shared_process().map_err(|error| {
            crate::refusal::Refusal::new(
                crate::refusal::RefusalCode::Integrity,
                "process",
                error.clone(),
                "process resources",
            )
        })?;
        let mut images = crate::instance::ImagesBuilder::new(
            &busbar_plugin_abi::host_side::host_vt::HOST,
            Arc::clone(process.slots()),
            crate::instance::Ceilings::DEFAULT,
        );
        images.admit(admitted)?;
        Ok(Self {
            registry: crate::instance::Registry::new(
                images.finish(),
                binder,
                Arc::clone(process.ids()),
            ),
        })
    }

    /// `Registry::open_store` for `spec` under `seal`, with every NEED denied and no reference source.
    ///
    /// # Errors
    /// The open's refusal.
    pub async fn open(
        &self,
        spec: &crate::instance::InstanceSpec<'_>,
        seal: crate::instance::StoreSeal,
    ) -> Result<busbar_ports::store::StoreHandle, crate::instance::OpenError> {
        let needs = Arc::new(crate::chains::DeniedNeeds);
        let refs: Arc<dyn busbar_ports::binder::RefSource> = Arc::new(crate::chains::DeniedRefs);
        self.registry.open_store(spec, &needs, &refs, seal).await
    }
}

/// A binder for a store that binds nothing: its config passes through unchanged and no secret, trust, dest or
/// reference position is bound (a local file store's `db_path`, the bench's in-memory store). A declared position
/// that holds a value is refused, so a store that needs custody is never opened over it.
struct PlainBinder;

impl busbar_ports::binder::ConfigBinder for PlainBinder {
    fn bind(
        &self,
        _instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        _ref_paths: &[&str],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        if let Some(pointer) = secret_paths
            .iter()
            .chain(trust_paths)
            .chain(dest_paths)
            .next()
        {
            return Err(busbar_ports::binder::BindError::NotAReference {
                pointer: (*pointer).into(),
            });
        }
        Ok(config.to_vec())
    }
    fn resolve_refs<'a>(
        &'a self,
        _instance: u64,
        _slot: u32,
        bound: Vec<u8>,
        _source: &'a dyn busbar_ports::binder::RefSource,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_contract::secure::SecureVec, busbar_ports::binder::BindError>,
    > {
        Box::pin(async move { Ok(busbar_contract::secure::SecureVec::from(bound)) })
    }
    fn unbind(&self, _instance: u64) {}
    fn bind_any(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        self.bind(
            instance,
            config,
            secret_paths,
            trust_paths,
            dest_paths,
            ref_paths,
        )
    }
    fn unbind_refs(
        &self,
        _instance: u64,
        bound: &[u8],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        Ok(bound.to_vec())
    }
    fn secret(
        &self,
        _instance: u64,
        _handle: u32,
    ) -> Option<busbar_contract::secret_ref::SecretRef> {
        None
    }
    fn trust(
        &self,
        _instance: u64,
        _handle: u32,
    ) -> Option<Arc<busbar_ports::binder::TrustAnchor>> {
        None
    }
    fn unix_path(&self, _instance: u64, _path: &str) -> bool {
        false
    }
    fn dest(&self, _instance: u64, _handle: u32) -> Option<Arc<busbar_ports::binder::DestDef>> {
        None
    }
}

impl NativeStores {
    /// [`NativeStores::new`] with a binder that binds nothing ([`PlainBinder`]): for a store whose config holds no
    /// secret, trust or dest position (plugin-bench's native store workload).
    ///
    /// # Errors
    /// As [`NativeStores::new`].
    pub fn plain(admitted: crate::admit::Admitted) -> Result<Self, crate::refusal::Refusal> {
        Self::new(admitted, Arc::new(PlainBinder))
    }
}
