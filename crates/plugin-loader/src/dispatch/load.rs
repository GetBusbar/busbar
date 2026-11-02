// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;
use std::mem::size_of;
use std::path::Path;
use std::ptr::addr_of;

use busbar_contract::abi::mechanism::call::{AbiStr, Op};
use busbar_contract::abi::mechanism::check::check_statement;
use busbar_contract::abi::mechanism::door::{
    Door, DoorFn, DoorParts, KindTailHead, MetricFamily, Statement, FAMILY_HISTOGRAM,
};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::mechanism::rendering::{read, render};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::transport::check::check_claim_rows;
use busbar_contract::abi::transport::{FramePiece, TransportTail};
use libloading::Library;

use super::plugin::{Bind, Plugin};
use super::{host_slots, host_table_size, Kind, FIRST_SLOT};

/// What a dropped plugin's signed manifest states about its door, checked before `dlopen`: the head
/// of the manifest's Statement rendering ([`ManifestFacts::read`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestFacts {
    /// The mechanism version the plugin was built against.
    pub mechanism_version: u32,
    /// Its kind.
    pub kind: KindCode,
    /// Its kind's ABI version.
    pub kind_abi: u32,
}

impl ManifestFacts {
    pub fn read(rendering: &[u8]) -> Result<Self, LoadError> {
        let facts = read(rendering)
            .map_err(|e| LoadError::Rendering(format!("byte {} is not {}", e.at, e.what)))?;
        let kind = facts.kind;
        Ok(Self {
            mechanism_version: facts.mechanism_version,
            kind: KindCode::from_raw(kind)
                .ok_or_else(|| LoadError::Rendering(format!("it names kind {kind}")))?,
            kind_abi: facts.kind_abi,
        })
    }
}

/// A COMPILED-IN ROW (the design's One row: `LinkedRow{statement, door}`): the Statement rendering
/// the row states and its door. Linked and dropped-in rows cross the same boundary: at load the
/// door's own Statement is rendered and must equal [`LinkedRow::statement`] byte for byte, as a
/// dropped plugin's must equal its signed manifest's.
#[derive(Debug, Clone)]
pub struct LinkedRow {
    /// The Statement rendering the row states.
    pub statement: Vec<u8>,
    /// The door.
    pub door: RawDoorFn,
}

impl LinkedRow {
    pub fn of(door: DoorFn) -> Result<Self, LoadError> {
        Ok(Self {
            statement: rendering_of(door)?,
            door: raw(door),
        })
    }

    pub fn of_macro(door: busbar_contract::abi::sdk::door::MacroDoor) -> Result<Self, LoadError> {
        Self::of(door.door_fn())
    }

    pub fn of_loaded(door: LoadedDoor) -> Result<Self, LoadError> {
        Self::of_raw(door.door)
    }

    /// [`LinkedRow::of`] over a door the loader already holds raw (a registry row's).
    #[doc(hidden)]
    pub fn of_raw(door: RawDoorFn) -> Result<Self, LoadError> {
        Ok(Self {
            statement: rendering_of_raw(door)?,
            door,
        })
    }
}

/// A door the loader may enter: either a [`MacroDoor`] built by the contract macro, or a door restated explicitly by a test or harness through unsafe [`LoadedDoor::from_raw`]. A hand-built door reaches a linked row through `LinkedRow::of_loaded(unsafe { LoadedDoor::from_raw(door) })`.
///
///
///
///
///
/// [`MacroDoor`]: busbar_contract::abi::sdk::door::MacroDoor
#[derive(Debug, Clone, Copy)]
pub struct LoadedDoor {
    #[doc(hidden)]
    pub door: RawDoorFn,
}

impl From<busbar_contract::abi::sdk::door::MacroDoor> for LoadedDoor {
    fn from(door: busbar_contract::abi::sdk::door::MacroDoor) -> Self {
        Self::from(door.door_fn())
    }
}

impl From<DoorFn> for LoadedDoor {
    fn from(door: DoorFn) -> Self {
        Self { door: raw(door) }
    }
}

/// A sealed door function as the raw one the loader enters ([`enter_door`]): the same `extern "C"`
/// function, typed as a `dlsym` answer is.
#[doc(hidden)]
pub const fn raw(door: DoorFn) -> RawDoorFn {
    // SAFETY: `&'static Door` and `*const Door` are ABI-compatible (one pointer; the reference is
    // never NULL), so calling the function through either type is the same call; the loader only
    // ever reads the raw answer through its checks.
    unsafe { std::mem::transmute::<DoorFn, RawDoorFn>(door) }
}

impl LoadedDoor {
    #[must_use]
    pub const fn door_fn(self) -> RawDoorFn {
        self.door
    }

    /// A door the loader read itself, or a test's or harness's restated door: the one way to a
    /// `LoadedDoor` other than a `MacroDoor`, and `unsafe`.
    ///
    /// # Safety
    ///
    /// `door` is a busbar door ([`RawDoorFn`]'s contract): read from the door symbol of a library
    /// held open for every use of the value, or a function answering NULL or a `'static`, fully
    /// initialised door whose Statement lists point at their stated counts of `'static` entries.
    #[must_use]
    pub const unsafe fn from_raw(door: RawDoorFn) -> Self {
        Self { door }
    }
}

/// The loader holds the linked door's unsafe entry
/// so the root can forbid unsafe code: a
/// compiled-in door-root crate's bare `door` (Part 4 A.1, l.3560: its only public item), admitted
/// exactly as a dropped-in library's door is once `dlsym` has resolved it (Part 2 #2 rule (1):
/// compiled in = dropped in, one path), and only then a [`LoadedDoor`]. The door function is called
/// on the loader's FFI worker ([`enter_door`]); its head is read and judged ([`read_door`]: the
/// magic, the mechanism version, its kind and that kind's ABI version); and the kind's own
/// [`validate_door`] runs, the one every origin runs: its table against the host's, its Statement
/// ([`statement`]: the lists, the kind tail, a transport's [`FramePiece`] stride and a plane's
/// [`ANSWER_LAYOUT`]). A refusal is the same [`LoadError`] the dropped-in door earns, word for word.
///
/// # Safety
///
/// `door` is the `door` a `plugin_door!` (or a kind's door macro) expanded in a crate this binary
/// links and the root manifest's `[package.metadata.busbar.door-root]` table names: `'static`
/// code answering NULL or a `'static` door, as the symbol `dlsym` resolves in a library held open
/// is. [`admit_linked`], over a sealed [`DoorFn`], is the one caller outside the loader's tests.
///
/// # Errors
///
/// The refusal the door, its table or its Statement earns.
pub(crate) unsafe fn open_linked(door: RawDoorFn) -> Result<LoadedDoor, LoadError> {
    validate_any(enter_door(door))?;
    // SAFETY: the caller's contract (a door-root crate's own door), and the host's own checks just
    // admitted its door, table and Statement, as `dlsym`'s door is admitted before a dropped plugin
    // is bound.
    Ok(unsafe { LoadedDoor::from_raw(door) })
}

/// The linked door's safe entry takes a sealed door. The composition root
/// generates the linked table and alone depends on plugin crates; the loader
/// names none. A compiled-in crate's `door`, a [`DoorFn`] answering a `&'static Door`
/// that only the contract's `unsafe` door constructor builds (its fields are private), admitted
/// through [`open_linked`] (the `dlopen` path's own checks, the one reviewed `unsafe` beside the
/// `dlopen` call), as a [`LoadedDoor`]. A refusal is the same [`LoadError`] the dropped-in door
/// earns.
///
/// A raw door function is refused at compile time:
///
/// ```compile_fail
/// extern "C" fn fake() -> *const busbar_contract::abi::mechanism::door::Door {
///     std::ptr::null()
/// }
/// let _ = busbar_plugin_loader::dispatch::admit_linked(fake);
/// ```
///
/// # Errors
///
/// The refusal the door, its table or its Statement earns.
pub fn admit_linked(door: DoorFn) -> Result<LoadedDoor, LoadError> {
    // SAFETY: a `DoorFn` answers a `&'static Door`, and a `Door` is built only through the
    // contract's `unsafe` `Door::__from_parts` (the door macro's expansion, or a caller's own
    // reviewed `unsafe`), whose contract is `open_linked`'s. `open_linked` checks what it answers
    // before any of it is used.
    unsafe { open_linked(raw(door)) }
}

pub(crate) fn validate_any(p: *const Door) -> Result<Validated, LoadError> {
    use super::kinds::{
        auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
        transport::Transport,
    };
    let (_, kind) = read_door(p, None)?;
    match kind {
        KindCode::Store => validate_door::<Store>(p),
        KindCode::Secret => validate_door::<Secret>(p),
        KindCode::Auth => validate_door::<Auth>(p),
        KindCode::Hook => validate_door::<Hook>(p),
        KindCode::Export => validate_door::<Export>(p),
        KindCode::Plane => validate_door::<Plane>(p),
        KindCode::Transport => validate_door::<Transport>(p),
    }
}

pub fn rendering_of_loaded(door: LoadedDoor) -> Result<Vec<u8>, LoadError> {
    rendering_of_raw(door.door)
}

pub fn rendering_of_macro(
    door: busbar_contract::abi::sdk::door::MacroDoor,
) -> Result<Vec<u8>, LoadError> {
    rendering_of(door.door_fn())
}

pub(crate) fn statement_of(door_fn: RawDoorFn) -> Result<Statement, LoadError> {
    let (door, _) = read_door(enter_door(door_fn), None)?;
    statement(&door)
}

pub fn rendering_of(door_fn: DoorFn) -> Result<Vec<u8>, LoadError> {
    rendering_of_raw(raw(door_fn))
}

/// [`rendering_of`] over a raw door function: a `dlsym` answer, or a door the loader already
/// holds.
#[doc(hidden)]
pub fn rendering_of_raw(door_fn: RawDoorFn) -> Result<Vec<u8>, LoadError> {
    let (door, _) = read_door(enter_door(door_fn), None)?;
    let st = statement(&door)?;
    // SAFETY: `statement` ran `check_statement`: every list is its stated count of `'static`
    // entries.
    unsafe { render(&st) }.map_err(|e| LoadError::Rendering(e.to_string()))
}

/// THE ENTRY: `door_fn` called on a permanent FFI worker ([`crate::ffi_thread`]), for every kind and
/// both origins. The door function is plugin code like any slot, so it runs where every other
/// per-load crossing runs; a call already on a worker stays there. A door function that panicked
/// answers NULL ([`LoadError::NullDoor`]).
#[doc(hidden)]
pub fn enter_door(door_fn: RawDoorFn) -> *const Door {
    let call = || {
        crate::ffi_thread::debug_assert_permanent("the door function");
        door_fn()
    };
    if crate::ffi_thread::on_permanent_worker() {
        return call();
    }
    crate::ffi_thread::on_plugin_thread(call).unwrap_or(std::ptr::null())
}

pub fn rendering_of_library(path: &Path) -> Result<Option<Vec<u8>>, LoadError> {
    crate::stage::allow_standalone_path_load().map_err(LoadError::Open)?;
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; `lib` outlives every use of it.
    let door = match unsafe { lib.get::<RawDoorFn>(DOOR_SYMBOL).map(|s| *s) } {
        Ok(door) => door,
        Err(_) => return Ok(None),
    };
    let rendering = rendering_of_raw(door);
    drop(Lib(Some(lib), None));
    rendering.map(Some)
}

pub fn door_addresses_of_library(path: &Path) -> Result<Option<(usize, usize)>, LoadError> {
    crate::stage::allow_standalone_path_load().map_err(LoadError::Open)?;
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; `lib` outlives every use of it.
    let door = match unsafe { lib.get::<RawDoorFn>(DOOR_SYMBOL).map(|s| *s) } {
        Ok(door) => door,
        Err(_) => return Ok(None),
    };
    let at = door();
    let ops = if at.is_null() {
        0
    } else {
        // SAFETY: a non-NULL door answer is a `'static` door of the library's at least its stated
        // size, read unaligned while the library is open.
        unsafe { Door::read_parts(at) }.ops as usize
    };
    drop(Lib(Some(lib), None));
    Ok(Some((at as usize, ops)))
}

/// Why a plugin was refused. Every refusal names the value it saw and the host's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// The manifest's mechanism version is not the host's (checked before `dlopen`).
    ManifestMechanism {
        /// The manifest's.
        stated: u32,
        /// The host's.
        host: u32,
    },
    /// The manifest names another kind than the one asked for.
    ManifestKind {
        /// The manifest's.
        stated: KindCode,
        /// The host's.
        want: KindCode,
    },
    /// The manifest's kind ABI version is not the host's.
    ManifestKindAbi {
        /// The manifest's.
        stated: u32,
        /// The host's.
        host: u32,
    },
    /// `dlopen` failed.
    Open(String),
    /// The library exports no door.
    NoDoor(String),
    /// The door function answered NULL.
    NullDoor,
    /// The door's magic is not `BUSBARPL`.
    Magic(u64),
    /// The door's mechanism version is older or newer than the host's.
    Mechanism {
        /// The door's.
        door: u32,
        /// The host's.
        host: u32,
    },
    /// The door does not reach its table (`host` is the least size: up to `ops`).
    DoorSize {
        /// The door's.
        door: u32,
        /// The host's.
        host: u32,
    },
    /// The door names no kind the host has.
    UnknownKind(u32),
    /// The door names another kind than the one asked for.
    WrongKind {
        /// The door's.
        door: KindCode,
        /// The host's.
        want: KindCode,
    },
    /// The door's kind ABI version is older or newer than the host's.
    KindAbi {
        /// The kind.
        kind: KindCode,
        /// The door's.
        door: u32,
        /// The host's.
        host: u32,
    },
    /// The door's table is NULL.
    NullOps,
    /// The table's `slots` is not the host's.
    TableSlots {
        /// The door's.
        door: u32,
        /// The host's.
        host: u32,
    },
    /// The table's `size` is not the host's.
    TableSize {
        /// The door's.
        door: u32,
        /// The host's.
        host: u32,
    },
    /// A slot is NULL (there is no "unsupported").
    NullSlot(u32),
    /// The door's Statement is NULL.
    NullStatement,
    /// The Statement is smaller than the host's.
    StatementSize {
        /// The Statement's.
        stated: u32,
        /// The host's.
        host: u32,
    },
    /// The Statement disagrees with the door on `field`.
    StatementDisagrees(&'static str),
    /// A Statement array is NULL with a non-zero length, or a family is malformed.
    BadStatement(String),
    /// The Statement's `kind_tail` is malformed.
    KindTail(String),
    /// A door was built against other shapes of its kind: it states another layout fingerprint
    /// ([`Door::layout`]) than this host's for its kind (`0`: a door that predates the word), so
    /// every struct crossing its table would be read and written at another layout. The same
    /// refusal for every kind, compiled in and dropped in.
    KindLayout {
        /// The plugin the Statement names.
        plugin: String,
        /// The kind.
        kind: KindCode,
        /// The door's.
        stated: u64,
        /// The host's.
        host: u64,
    },
    /// A transport's frame pieces are not the host's: its tail states another
    /// `size_of::<FramePiece>()` than this host's (`0`: a tail that predates the word), so every
    /// piece it writes would be read at the wrong stride.
    FramePieceSize {
        /// The plugin the Statement names.
        plugin: String,
        /// The tail's.
        stated: u32,
        /// The host's.
        host: u32,
    },
    /// A plane's answers are not laid out as the host's: its tail states another
    /// [`ANSWER_LAYOUT`] than this host's (`0`: a tail that predates the word), so every `out` it
    /// writes would be read at another layout.
    PlaneLayout {
        /// The plugin the Statement names.
        plugin: String,
        /// The tail's.
        stated: u32,
        /// The host's.
        host: u32,
    },
    /// A Statement rendering (a manifest's or a row's) is malformed.
    Rendering(String),
    /// The door's Statement is not the one the manifest (or the compiled-in row) states.
    StatementMismatch,
    /// A need, outbound or inbound, names a scheme no loaded transport serves (spec Part 2 #50:
    /// fail closed at boot, naming the plugin and the scheme).
    UnservedScheme {
        /// The plugin the Statement names.
        plugin: String,
        /// The need is inbound (it listens), not outbound.
        inbound: bool,
        /// The need's unserved scheme.
        scheme: String,
    },
    /// A need that names no config path (no `target_from`, no `trust_from`), declared on the
    /// host's connection table at bind, was refused by it (kind-secret K17: fail closed at the
    /// load, naming the plugin and the need, never bound with a need it can never open).
    NeedRefused {
        /// The plugin the Statement names.
        plugin: String,
        /// The need's index in the Statement.
        need: u32,
        /// The need's transport.
        transport: String,
        /// Why the table refused it ([`crate::observe::conn_reason`]).
        reason: &'static str,
    },
    /// A door whose Statement declares a need was bound to SERVE with no connection table
    /// ([`ConnTable::NoNeeds`](super::ConnTable::NoNeeds)): it could never dial or listen, so it is
    /// refused at bind (Q-P4-3), never at its first open.
    NoConnectionTable {
        /// The plugin the Statement names.
        plugin: String,
        /// How many needs it declares.
        needs: usize,
    },
    /// The host has minted every instance handle its handle can index (#74, `dispatch::handle`):
    /// a bind is refused rather than a handle reused.
    HandlesSpent,
    /// The OS random source could not answer the host's key draw (#74): the loader refuses to boot
    /// rather than mint handles under a weaker key.
    Entropy(String),
}

pub const REBUILD: &str = "rebuild the plugin against the 1.6.0 SDK";

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestMechanism { stated, host } => write!(
                f,
                "the manifest states mechanism version {stated}; this host speaks {host} — {REBUILD}"
            ),
            Self::ManifestKind { stated, want } => {
                write!(f, "the manifest states kind {stated:?}, not {want:?}")
            }
            Self::ManifestKindAbi { stated, host } => write!(
                f,
                "the manifest states kind ABI {stated}; this host speaks {host} — {REBUILD}"
            ),
            Self::Open(e) => write!(f, "the library did not load: {e}"),
            Self::NoDoor(e) => write!(
                f,
                "the library exports no busbar_plugin_door ({e}) — a plugin built against the 1.5.5 JSON contract; {REBUILD}"
            ),
            Self::NullDoor => f.write_str("the door function answered NULL"),
            Self::Magic(m) => write!(f, "the door's magic {m:#018x} is not BUSBARPL"),
            Self::Mechanism { door, host } => write!(
                f,
                "the door's mechanism version {door} is not this host's {host} — {REBUILD}"
            ),
            Self::DoorSize { door, host } => {
                write!(f, "the door is {door} bytes; this host reads at least {host}")
            }
            Self::UnknownKind(k) => write!(f, "the door names kind {k}, which no kind has"),
            Self::WrongKind { door, want } => {
                write!(f, "the door names kind {door:?}, not {want:?}")
            }
            Self::KindAbi { kind, door, host } => write!(
                f,
                "the door's {kind:?} ABI version {door} is not this host's {host} — {REBUILD}"
            ),
            Self::NullOps => f.write_str("the door's ops table is NULL"),
            Self::TableSlots { door, host } => {
                write!(f, "the ops table has {door} slots; this host's has {host}")
            }
            Self::TableSize { door, host } => {
                write!(f, "the ops table is {door} bytes; this host's is {host}")
            }
            Self::NullSlot(i) => write!(f, "ops slot {i} is NULL"),
            Self::NullStatement => f.write_str("the door's Statement is NULL"),
            Self::StatementSize { stated, host } => {
                write!(f, "the Statement is {stated} bytes; this host's is {host}")
            }
            Self::StatementDisagrees(field) => {
                write!(f, "the Statement's {field} disagrees with the door's")
            }
            Self::BadStatement(e) => write!(f, "the Statement is malformed: {e}"),
            Self::KindTail(e) => write!(f, "the Statement's kind tail is malformed: {e}"),
            Self::KindLayout {
                plugin,
                kind,
                stated,
                host,
            } => write!(
                f,
                "{kind:?} plugin '{plugin}' was built against {kind:?} layout {stated:#018x}; this \
                 host reads {kind:?} layout {host:#018x} — rebuild against this busbar-contract"
            ),
            Self::FramePieceSize {
                plugin,
                stated,
                host,
            } => write!(
                f,
                "transport plugin '{plugin}' writes {stated}-byte frame pieces; this host reads \
                 {host}-byte pieces — rebuild against this busbar-contract"
            ),
            Self::PlaneLayout {
                plugin,
                stated,
                host,
            } => write!(
                f,
                "plane plugin '{plugin}' writes its answers in plane layout {stated}; this host \
                 reads plane layout {host} — rebuild against this busbar-contract"
            ),
            Self::Rendering(e) => write!(f, "the stated Statement rendering is malformed: {e}"),
            Self::StatementMismatch => f.write_str(
                "the plugin's Statement is not the one its manifest states — repack the plugin",
            ),
            Self::UnservedScheme {
                plugin,
                inbound,
                scheme,
            } => write!(
                f,
                "plugin `{plugin}` declares an {} need over `{scheme}`, and no loaded transport serves `{scheme}`",
                if *inbound { "inbound" } else { "outbound" }
            ),
            Self::NeedRefused {
                plugin,
                need,
                transport,
                reason,
            } => write!(
                f,
                "plugin `{plugin}` declares need {need} over `{transport}`, and the host's \
                 connection table refused it ({reason}); the plugin is not loaded"
            ),
            Self::NoConnectionTable { plugin, needs } => write!(
                f,
                "plugin '{plugin}' declares {needs} connection need(s) and was bound with no connection table"
            ),
            Self::HandlesSpent => write!(
                f,
                "the host has minted every instance handle it can index; restart the process"
            ),
            Self::Entropy(why) => write!(
                f,
                "the OS random source could not answer the host's handle key ({why}); the loader \
                 refuses to boot"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

pub(crate) struct Validated {
    pub(crate) kind: KindCode,
    pub(crate) statement: Statement,
    pub(crate) slots: Box<[Op]>,

    pub(crate) ready: Option<Op>,
}

pub(crate) struct Lib(Option<Library>, Option<crate::stage::Staged>);

impl Drop for Lib {
    fn drop(&mut self) {
        let staged = self.1.take();
        if let Some(lib) = self.0.take() {
            reap(Box::new(move || {
                crate::dlclose_on_worker(lib);
                drop(staged);
            }));
        }
    }
}

pub(crate) type Unload = Box<dyn FnOnce() + Send>;

pub(crate) fn reap(unload: Unload) {
    reap_within(unload, super::Budgets::default().lifecycle);
}

pub(crate) fn reap_within(unload: Unload, bound: std::time::Duration) {
    use std::sync::atomic::Ordering::SeqCst;
    let handed = std::sync::Arc::new(std::sync::Mutex::new(Some(unload)));
    let taken = std::sync::Arc::clone(&handed);
    let (done, returned) = std::sync::mpsc::channel::<()>();
    LIVE_REAPERS.fetch_add(1, SeqCst);
    let spawned = std::thread::Builder::new()
        .name(REAPER_THREAD.into())
        .spawn(move || {
            let unload = taken.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(unload) = unload {
                unload();
                #[cfg(test)]
                UNLOADS.fetch_add(1, SeqCst);
            }
            LIVE_REAPERS.fetch_sub(1, SeqCst);
            let _ = done.send(());
        });
    if let Err(e) = spawned {
        LIVE_REAPERS.fetch_sub(1, SeqCst);
        tracing::warn!(error = %e, "no reaper thread: the plugin library stays loaded");
        let unload = handed.lock().unwrap_or_else(|e| e.into_inner()).take();
        std::mem::forget(unload);
        return;
    }

    let _ = std::thread::Builder::new()
        .name(REAPER_WATCH_THREAD.into())
        .spawn(move || {
            if returned.recv_timeout(bound) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
                tracing::warn!(
                    bound_secs = bound.as_secs_f64(),
                    live_reapers = live_reapers(),
                    "a plugin library's unload has not returned; its reaper stays, never forced"
                );
                #[cfg(test)]
                HUNG_WARNED.fetch_add(1, SeqCst);
            }
        });
}

pub(crate) fn live_reapers() -> u64 {
    LIVE_REAPERS.load(std::sync::atomic::Ordering::SeqCst)
}

static LIVE_REAPERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) const REAPER_THREAD: &str = "busbar-dispatch-reaper";

const REAPER_WATCH_THREAD: &str = "busbar-dispatch-reaper-watch";

#[cfg(test)]
pub(crate) static UNLOADS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) static HUNG_WARNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn load_dropped<K: Kind>(
    path: &Path,
    stated: &[u8],
    bind: Bind,
) -> Result<Plugin<K>, LoadError> {
    crate::stage::allow_standalone_path_load().map_err(LoadError::Open)?;
    check_facts::<K>(stated)?;
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    bind_library::<K>(Lib(Some(lib), None), stated, bind)
}

pub fn load_dropped_bytes<K: Kind>(
    bytes: &[u8],
    display: &str,
    stated: &[u8],
    bind: Bind,
) -> Result<Plugin<K>, LoadError> {
    check_facts::<K>(stated)?;
    let (lib, staged) =
        crate::stage::load_library_from_bytes(bytes, display).map_err(LoadError::Open)?;
    bind_library::<K>(Lib(Some(lib), Some(staged)), stated, bind)
}

fn bind_library<K: Kind>(lib: Lib, stated: &[u8], bind: Bind) -> Result<Plugin<K>, LoadError> {
    let door = {
        let l = lib.0.as_ref().expect("an opened library");
        // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; the symbol is copied out as a
        // plain fn pointer, kept valid by `Lib` for as long as any handle to the instance lives.
        unsafe { l.get::<RawDoorFn>(DOOR_SYMBOL).map(|s| *s) }
    };
    let door = door.map_err(|e| LoadError::NoDoor(e.to_string()))?;
    Plugin::bind(admitted::<K>(door, stated)?, Some(lib), bind)
}

fn check_facts<K: Kind>(stated: &[u8]) -> Result<(), LoadError> {
    let facts = ManifestFacts::read(stated)?;
    if facts.mechanism_version != MECHANISM_VERSION {
        return Err(LoadError::ManifestMechanism {
            stated: facts.mechanism_version,
            host: MECHANISM_VERSION,
        });
    }
    if facts.kind != K::CODE {
        return Err(LoadError::ManifestKind {
            stated: facts.kind,
            want: K::CODE,
        });
    }
    if facts.kind_abi != K::CODE.abi_version() {
        return Err(LoadError::ManifestKindAbi {
            stated: facts.kind_abi,
            host: K::CODE.abi_version(),
        });
    }
    Ok(())
}

pub(crate) enum Staging<K: Kind> {
    Door(Plugin<K>),

    NotADoor,
}

pub(crate) fn load_staged<K: Kind>(
    lib: Library,
    staged: crate::stage::Staged,
    stated: Option<&[u8]>,
    bind: Bind,
) -> Result<Staging<K>, LoadError> {
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; the symbol is copied out as a plain
    // fn pointer, kept valid by `Lib` for as long as any handle to the instance lives.
    let door = unsafe { lib.get::<RawDoorFn>(DOOR_SYMBOL).map(|s| *s) };
    let Ok(door) = door else {
        drop((lib, staged));
        return Ok(Staging::NotADoor);
    };
    let stated = stated.ok_or(LoadError::StatementMismatch)?;
    let lib = Lib(Some(lib), Some(staged));
    Ok(Staging::Door(Plugin::bind(
        admitted::<K>(door, stated)?,
        Some(lib),
        bind,
    )?))
}

pub fn load_linked<K: Kind>(row: &LinkedRow, bind: Bind) -> Result<Plugin<K>, LoadError> {
    Plugin::bind(admitted::<K>(row.door, &row.statement)?, None, bind)
}

fn admitted<K: Kind>(door: RawDoorFn, stated: &[u8]) -> Result<Validated, LoadError> {
    check_facts::<K>(stated)?;
    let v = validate::<K>(door)?;
    // SAFETY: `validate` ran `check_statement` on this Statement.
    let own = unsafe { render(&v.statement) }.map_err(|e| LoadError::Rendering(e.to_string()))?;
    if own != stated {
        return Err(LoadError::StatementMismatch);
    }
    Ok(v)
}

pub(crate) fn validate<K: Kind>(door_fn: RawDoorFn) -> Result<Validated, LoadError> {
    validate_door::<K>(enter_door(door_fn))
}

const READY_AT: usize = Door::ready_at();

pub(crate) fn read_door(
    p: *const Door,
    want: Option<KindCode>,
) -> Result<(DoorParts, KindCode), LoadError> {
    if p.is_null() {
        return Err(LoadError::NullDoor);
    }
    // SAFETY: a non-NULL door is `'static` plugin data; the leading fields are read one at a time,
    // and the whole door only after its stated size covers the host's.
    let (magic, mechanism, size) = unsafe { Door::read_head(p) };
    if magic != DOOR_MAGIC {
        return Err(LoadError::Magic(magic));
    }
    if mechanism != MECHANISM_VERSION {
        return Err(LoadError::Mechanism {
            door: mechanism,
            host: MECHANISM_VERSION,
        });
    }

    if (size as usize) < READY_AT {
        return Err(LoadError::DoorSize {
            door: size,
            host: READY_AT as u32,
        });
    }
    // SAFETY: as above; the door covers every field up to `ready`, and `ready` itself is read only
    // when `size` covers it (an absent tail reads as `None`).
    let door = unsafe { Door::read_parts(p) };
    let kind = KindCode::from_raw(door.kind).ok_or(LoadError::UnknownKind(door.kind))?;
    if let Some(want) = want.filter(|w| *w != kind) {
        return Err(LoadError::WrongKind { door: kind, want });
    }
    if door.kind_abi != kind.abi_version() {
        return Err(LoadError::KindAbi {
            kind,
            door: door.kind_abi,
            host: kind.abi_version(),
        });
    }
    Ok((door, kind))
}

pub(crate) fn validate_door<K: Kind>(p: *const Door) -> Result<Validated, LoadError> {
    let (door, kind) = read_door(p, Some(K::CODE))?;

    let stated = statement(&door);
    let by_statement = |i| {
        stated
            .as_ref()
            .is_ok_and(|st| K::optional_by_statement(i, st))
    };
    let slots = table::<K>(door.ops, by_statement)?;
    let statement = stated?;
    Ok(Validated {
        kind,
        statement,
        slots,
        ready: door.ready,
    })
}

extern "C" fn absent(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, RawOutcome};
    if !out.is_null() {
        // SAFETY: a non-NULL host `out` leads with an `OutHead` (the call convention), and the
        // host built it.
        unsafe {
            std::ptr::addr_of_mut!((*out.cast::<OutHead>()).outcome)
                .write_unaligned(RawOutcome::of(Outcome::Ready));
        }
    }
    RawOutcome::of(Outcome::Ready)
}

fn table<K: Kind>(
    ops: *const OpsHead,
    by_statement: impl Fn(u32) -> bool,
) -> Result<Box<[Op]>, LoadError> {
    if ops.is_null() {
        return Err(LoadError::NullOps);
    }
    // SAFETY: a non-NULL table is `'static` plugin data leading with `size` and `slots`.
    let (size, slots) = unsafe {
        (
            addr_of!((*ops).size).read_unaligned(),
            addr_of!((*ops).slots).read_unaligned(),
        )
    };
    let (host_slots, host_size) = (host_slots::<K>(), host_table_size::<K>());
    if slots != host_slots || slots < LIFECYCLE_SLOTS {
        return Err(LoadError::TableSlots {
            door: slots,
            host: host_slots,
        });
    }
    if size != host_size {
        return Err(LoadError::TableSize {
            door: size,
            host: host_size,
        });
    }
    let first = ops
        .cast::<u8>()
        .wrapping_add(FIRST_SLOT)
        .cast::<Option<Op>>();
    (0..slots)
        .map(|i| {
            // SAFETY: `size` equals the host's table, which holds `slots` contiguous slots here.
            match unsafe { first.add(i as usize).read_unaligned() } {
                Some(op) => Ok(op),

                None if K::optional_slot(i) || by_statement(i) => Ok(absent as Op),
                None => Err(LoadError::NullSlot(i)),
            }
        })
        .collect()
}

pub(crate) fn statement(door: &DoorParts) -> Result<Statement, LoadError> {
    let p = door.statement;
    if p.is_null() {
        return Err(LoadError::NullStatement);
    }
    // SAFETY: a non-NULL Statement is `'static` plugin data leading with `size`.
    let size = unsafe { addr_of!((*p).size).read_unaligned() };
    if (size as usize) < size_of::<Statement>() {
        return Err(LoadError::StatementSize {
            stated: size,
            host: size_of::<Statement>() as u32,
        });
    }
    // SAFETY: its stated size covers the host's.
    let st = unsafe { p.read_unaligned() };
    if st.kind != door.kind {
        return Err(LoadError::StatementDisagrees("kind"));
    }
    if st.kind_abi != door.kind_abi {
        return Err(LoadError::StatementDisagrees("kind_abi"));
    }
    if st.families_len > 0 && st.families.is_null() {
        return Err(LoadError::BadStatement("families is NULL".into()));
    }
    if st.secret_refs_len > 0 && st.secret_refs.is_null() {
        return Err(LoadError::BadStatement("secret_refs is NULL".into()));
    }
    if st.diag_ids_len > 0 && st.diag_ids.is_null() {
        return Err(LoadError::BadStatement("diag_ids is NULL".into()));
    }
    // THE LISTS' BOUNDS FIRST: `check_statement` refuses a NULL list with a count, a count above
    // `STATEMENT_LIST_MAX` and a misaligned list before any entry is read, so the walk below never
    // reads past the plugin's own data.
    // SAFETY: a door's Statement is `'static` plugin data; every list is checked before it is read.
    unsafe { check_statement(&st) }
        .map_err(|f| LoadError::BadStatement(format!("{} breaks {:?}", f.field, f.rule)))?;
    kind_layout(door, &st)?;
    reference_fields(&st)?;
    for i in 0..st.families_len {
        // SAFETY: `families` holds `families_len` `'static` entries, at most STATEMENT_LIST_MAX.
        let fam: MetricFamily = unsafe { st.families.add(i).read_unaligned() };
        if fam.kind > FAMILY_HISTOGRAM {
            return Err(LoadError::BadStatement(format!(
                "family {i} has kind {}",
                fam.kind
            )));
        }
        if fam.label_keys_len > 0 && fam.label_keys.is_null() {
            return Err(LoadError::BadStatement(format!(
                "family {i}'s label keys are NULL"
            )));
        }
        if str_is_bad(fam.name) {
            return Err(LoadError::BadStatement(format!("family {i} has no name")));
        }
    }
    kind_tail(&st)?;
    Ok(st)
}

pub(crate) fn reference_fields(st: &Statement) -> Result<Vec<String>, LoadError> {
    // SAFETY: a door's Statement is `'static` plugin data; its extensions blob holds its stated
    // length (a NULL one reads as none).
    let ext = unsafe { super::plugin::blob_bytes(st.extensions) };
    let reference = busbar_contract::abi::mechanism::extensions::reference_fields(ext)
        .map_err(LoadError::BadStatement)?;
    if reference.is_empty() {
        return Ok(reference);
    }
    let secret: Vec<String> = (0..st.secret_refs_len)
        .filter_map(|i| {
            // SAFETY: `check_statement` bounded the list; it holds `secret_refs_len` `'static`
            // strings.
            let key = unsafe { st.secret_refs.add(i).read_unaligned() };
            super::plugin::str_bytes(key).map(|k| String::from_utf8_lossy(k).into_owned())
        })
        .collect();
    match busbar_contract::secret_fields::contradiction(&secret, &reference) {
        Some(path) => Err(LoadError::BadStatement(format!(
            "extensions.reference_fields names '{path}', which secret_refs also names: a settings \
             field is secret or reference-capable, never both"
        ))),
        None => Ok(reference),
    }
}

fn kind_layout(door: &DoorParts, st: &Statement) -> Result<(), LoadError> {
    let Some(kind) = KindCode::from_raw(door.kind) else {
        return Err(LoadError::UnknownKind(door.kind));
    };
    let host = kind.layout_fingerprint();
    if door.layout == host {
        return Ok(());
    }
    Err(LoadError::KindLayout {
        plugin: super::plugin::str_bytes(st.name)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default(),
        kind,
        stated: door.layout,
        host,
    })
}

pub(crate) fn kind_tail(st: &Statement) -> Result<(), LoadError> {
    if st.kind_tail.is_null() {
        if st.kind == KindCode::Transport as u32 && st.claims_len != 0 {
            return Err(LoadError::KindTail(
                "a transport names claims but states no tail for their rows".into(),
            ));
        }
        return Ok(());
    }
    // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`.
    let tail = unsafe { st.kind_tail.read_unaligned() };
    if (tail.size as usize) < size_of::<KindTailHead>() {
        return Err(LoadError::KindTail(format!(
            "its head states {} bytes, less than the head itself",
            tail.size
        )));
    }
    if st.kind == KindCode::Plane as u32 {
        return plane_layout(st, tail.size);
    }
    if st.kind != KindCode::Transport as u32 {
        return Ok(());
    }

    let word = std::mem::offset_of!(TransportTail, frame_piece_size);
    let stated = if tail.size as usize >= word + size_of::<u32>() {
        // SAFETY: the tail states it covers the word; a kind tail is `'static` plugin data.
        unsafe {
            addr_of!((*st.kind_tail.cast::<TransportTail>()).frame_piece_size).read_unaligned()
        }
    } else {
        0
    };
    let host = size_of::<FramePiece>() as u32;
    if stated != host {
        let plugin = super::plugin::str_bytes(st.name)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        return Err(LoadError::FramePieceSize {
            plugin,
            stated,
            host,
        });
    }
    if (tail.size as usize) < size_of::<TransportTail>() {
        return Err(LoadError::KindTail(format!(
            "a transport tail states {} bytes, less than its claim rows",
            tail.size
        )));
    }
    // SAFETY: a transport's kind tail is a `'static` `TransportTail` of the size it states.
    let t = unsafe { st.kind_tail.cast::<TransportTail>().read_unaligned() };
    check_claim_rows(st.claims_len, &t)
        .map_err(|f| LoadError::KindTail(format!("{} breaks {:?}", f.field, f.rule)))
}

fn plane_layout(st: &Statement, size: u32) -> Result<(), LoadError> {
    let word = std::mem::offset_of!(PlaneTail, answer_layout);
    let stated = if size as usize >= word + size_of::<u32>() {
        // SAFETY: the tail states it covers the word; a kind tail is `'static` plugin data.
        unsafe { addr_of!((*st.kind_tail.cast::<PlaneTail>()).answer_layout).read_unaligned() }
    } else {
        0
    };
    if stated == ANSWER_LAYOUT {
        return Ok(());
    }
    Err(LoadError::PlaneLayout {
        plugin: super::plugin::str_bytes(st.name)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default(),
        stated,
        host: ANSWER_LAYOUT,
    })
}

fn str_is_bad(s: AbiStr) -> bool {
    s.ptr.is_null() || s.len == 0
}
