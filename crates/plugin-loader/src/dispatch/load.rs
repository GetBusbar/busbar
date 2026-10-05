// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADER PATH for both origins (`BUSBAR-1.6.0.md` THE DESIGN, §11.4: compiled in or dropped
//! in, the same table).
//!
//! [`load_dropped`] checks the manifest's mechanism version BEFORE `dlopen`, opens the library,
//! finds [`DOOR_SYMBOL`] and runs [`validate`]; [`load_linked`] runs the SAME [`validate`] on a
//! compiled-in row's door. Both answer the same [`Plugin`]. The door is refused — never guessed,
//! never a panic — for: a wrong magic, a mechanism or kind ABI version older OR newer than the
//! host's, an unknown kind or another kind than `K`, a door that does not reach its table, a NULL table,
//! a table whose `slots`/`size` differ from the host's table of `K`, any NULL slot, or a Statement
//! that is missing, short, disagrees with the door or points at NULL arrays.

use std::fmt;
use std::mem::size_of;
use std::path::Path;
use std::ptr::addr_of;

use busbar_contract::abi::mechanism::call::{AbiStr, Op};
use busbar_contract::abi::mechanism::check::check_statement;
use busbar_contract::abi::mechanism::door::{
    Door, DoorFn, KindTailHead, MetricFamily, Statement, FAMILY_HISTOGRAM,
};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::mechanism::rendering::{render, RENDERING_MAGIC};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use busbar_contract::abi::transport::check::check_claim_rows;
use busbar_contract::abi::transport::TransportTail;
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
    /// The facts at the head of a Statement rendering
    /// ([`rendering`](busbar_contract::abi::mechanism::rendering)): its magic, then the mechanism
    /// version, the kind and the kind's ABI version.
    ///
    /// # Errors
    ///
    /// [`LoadError::Rendering`] for a rendering too short or without the magic, or naming no kind.
    pub fn read(rendering: &[u8]) -> Result<Self, LoadError> {
        let magic = RENDERING_MAGIC.len();
        if rendering.len() < magic + 12 || &rendering[..magic] != RENDERING_MAGIC {
            return Err(LoadError::Rendering(
                "it does not start with a Statement rendering's head".into(),
            ));
        }
        let word = |at: usize| {
            u32::from_le_bytes([
                rendering[at],
                rendering[at + 1],
                rendering[at + 2],
                rendering[at + 3],
            ])
        };
        let kind = word(magic + 4);
        Ok(Self {
            mechanism_version: word(magic),
            kind: KindCode::from_raw(kind)
                .ok_or_else(|| LoadError::Rendering(format!("it names kind {kind}")))?,
            kind_abi: word(magic + 8),
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
    pub door: DoorFn,
}

impl LinkedRow {
    /// The row a compiled-in door states: its Statement, rendered once, without opening the plugin
    /// (no `validate` or `open` runs; the door function only answers its `'static` data).
    ///
    /// # Errors
    ///
    /// Whatever [`rendering_of`] refuses.
    pub fn of(door: DoorFn) -> Result<Self, LoadError> {
        Ok(Self {
            statement: rendering_of(door)?,
            door,
        })
    }
}

/// THE RENDERING a door's Statement makes, for any kind: the door's head checks (magic, mechanism,
/// size, a known kind at this host's ABI version for it) and the Statement's, then
/// [`render`]. The pack tool signs it into a dropped plugin's manifest; [`LinkedRow::of`] states it
/// for a compiled-in one.
///
/// # Errors
///
/// The refusal the door or its Statement earns.
pub fn rendering_of(door_fn: DoorFn) -> Result<Vec<u8>, LoadError> {
    let (door, _) = read_door(door_fn(), None)?;
    let st = statement(&door)?;
    // SAFETY: `statement` ran `check_statement`: every list is its stated count of `'static`
    // entries.
    unsafe { render(&st) }.map_err(|e| LoadError::Rendering(format!("{} is too long", e.0)))
}

/// THE PACK-TIME RENDERING: `path`'s door, if the library exports one, rendered
/// ([`rendering_of`]) for the pack tool to sign into the manifest. `None` for a library with no
/// door (a pre-1.6.0 artifact keeps today's handling). Runs on the publisher's machine, never in the
/// engine's boot: the engine reads the signed rendering and opens the library only at admit.
///
/// # Errors
///
/// [`LoadError::Open`] when the library does not load; the door's or Statement's refusal.
pub fn rendering_of_library(path: &Path) -> Result<Option<Vec<u8>>, LoadError> {
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; `lib` outlives every use of it.
    let door = match unsafe { lib.get::<DoorFn>(DOOR_SYMBOL).map(|s| *s) } {
        Ok(door) => door,
        Err(_) => return Ok(None),
    };
    let rendering = rendering_of(door);
    drop(Lib(Some(lib), None));
    rendering.map(Some)
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
}

/// What every refusal of a plugin built against an older contract tells the operator to do.
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
        }
    }
}

impl std::error::Error for LoadError {}

/// A door that passed [`validate`]: copies of its `'static` data and its slots.
pub(crate) struct Validated {
    pub(crate) kind: KindCode,
    pub(crate) statement: Statement,
    pub(crate) slots: Box<[Op]>,
    /// The door's optional `ready` (its append-only tail); `None` = it has none.
    pub(crate) ready: Option<Op>,
}

/// The loaded library, unloaded on the loader's worker when the last instance handle drops.
pub(crate) struct Lib(Option<Library>, Option<crate::stage::Staged>);

impl Drop for Lib {
    fn drop(&mut self) {
        let staged = self.1.take();
        if let Some(lib) = self.0.take() {
            // The staged backing (a verified-bytes load) is released only after the unload.
            reap(Box::new(move || {
                crate::dlclose_on_worker(lib);
                drop(staged);
            }));
        }
    }
}

/// An unload, as the reaper runs it.
pub(crate) type Unload = Box<dyn FnOnce() + Send>;

/// THE REAPER: every library unload (plugin `.fini_array` code) runs on a reaper thread of its own,
/// fire and forget. Never on a request worker, never on the watchdog, never under a worker's lock
/// and never inside another op's crossing record, so an unload that hangs wedges only its own
/// reaper: no innocent instance is faulted, no caller waits, and no LATER unload waits behind it (a
/// single shared reaper let one hanging `.fini_array` hold every later library — and its staged
/// image — loaded for the life of the process). A reaper the OS will not spawn leaks the library
/// rather than run its unload on the caller's thread.
///
/// A HUNG UNLOAD IS OBSERVABLE, NEVER FORCED: each reaper is counted live until its unload returns
/// ([`live_reapers`], reported in `DispatchStats::live_reapers`), and a watch beside it warns once
/// when the unload has not returned within the lifecycle budget. Nothing caps or cancels it — a
/// leaked library is safer than a forced unload.
pub(crate) fn reap(unload: Unload) {
    reap_within(unload, super::Budgets::default().lifecycle);
}

/// [`reap`], warning when the unload outlives `bound`.
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
    // The watch: it outlives nothing but its own wait, so a hung unload leaves one thread, its own.
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

/// Reapers whose unload has not returned, process-wide.
pub(crate) fn live_reapers() -> u64 {
    LIVE_REAPERS.load(std::sync::atomic::Ordering::SeqCst)
}

static LIVE_REAPERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The reaper thread's name.
pub(crate) const REAPER_THREAD: &str = "busbar-dispatch-reaper";

/// The reaper watch's thread name.
const REAPER_WATCH_THREAD: &str = "busbar-dispatch-reaper-watch";

/// TEST WITNESS: unloads the reapers finished.
#[cfg(test)]
pub(crate) static UNLOADS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// TEST WITNESS: hung unloads the watch warned of.
#[cfg(test)]
pub(crate) static HUNG_WARNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// THE DROPPED-IN DOOR: `path`'s signed manifest rendering `stated` — its head facts, checked before
/// `dlopen` — then `dlopen`, then [`DOOR_SYMBOL`], then [`validate`], then the door's own Statement
/// rendered and compared with `stated` byte for byte. A mechanism version the host does not speak is
/// refused before the library is opened.
pub fn load_dropped<K: Kind>(
    path: &Path,
    stated: &[u8],
    bind: Bind,
) -> Result<Plugin<K>, LoadError> {
    check_facts::<K>(stated)?;
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    bind_library::<K>(Lib(Some(lib), None), stated, bind)
}

/// [`load_dropped`] over a dropped plugin's VERIFIED library bytes (the bytes its signed manifest's
/// `sha256` names): staged by the loader's one staging path and opened from exactly those bytes.
/// `display` labels a refusal.
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

/// The door of an opened library, admitted against `stated`.
fn bind_library<K: Kind>(lib: Lib, stated: &[u8], bind: Bind) -> Result<Plugin<K>, LoadError> {
    let door = {
        let l = lib.0.as_ref().expect("an opened library");
        // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the symbol is copied out as a
        // plain fn pointer, kept valid by `Lib` for as long as any handle to the instance lives.
        unsafe { l.get::<DoorFn>(DOOR_SYMBOL).map(|s| *s) }
    };
    let door = door.map_err(|e| LoadError::NoDoor(e.to_string()))?;
    Plugin::bind(admitted::<K>(door, stated)?, Some(lib), bind)
}

/// The stated rendering's head facts against the host's, before anything is opened.
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

/// What a staged library turned out to be.
pub(crate) enum Staging<K: Kind> {
    /// A memory-ABI plugin, admitted through its door.
    Door(Plugin<K>),
    /// No door: not a memory-ABI plugin; the library and its backing come back for another lane.
    NotADoor(Library, crate::stage::Staged),
}

/// THE DROPPED-IN DOOR OF A STAGED LIBRARY: `lib` (already `dlopen`ed from its signed tarball's
/// verified bytes, `staged` its backing) through [`DOOR_SYMBOL`] and the same [`validate`], its
/// door's Statement compared with the `stated` rendering its signed manifest carries — a door whose
/// manifest states none is refused. The backing lives as long as the instance, image first.
pub(crate) fn load_staged<K: Kind>(
    lib: Library,
    staged: crate::stage::Staged,
    stated: Option<&[u8]>,
    bind: Bind,
) -> Result<Staging<K>, LoadError> {
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the symbol is copied out as a plain
    // fn pointer, kept valid by `Lib` for as long as any handle to the instance lives.
    let door = unsafe { lib.get::<DoorFn>(DOOR_SYMBOL).map(|s| *s) };
    let Ok(door) = door else {
        return Ok(Staging::NotADoor(lib, staged));
    };
    let stated = stated.ok_or(LoadError::StatementMismatch)?;
    let lib = Lib(Some(lib), Some(staged));
    Ok(Staging::Door(Plugin::bind(
        admitted::<K>(door, stated)?,
        Some(lib),
        bind,
    )?))
}

/// THE LINKED DOOR: a compiled-in row's [`DoorFn`], through the same [`validate`] and the same
/// comparison of the door's Statement with the one the row states.
pub fn load_linked<K: Kind>(row: &LinkedRow, bind: Bind) -> Result<Plugin<K>, LoadError> {
    Plugin::bind(admitted::<K>(row.door, &row.statement)?, None, bind)
}

/// [`validate`], then the door's Statement rendered and compared with the `stated` rendering.
fn admitted<K: Kind>(door: DoorFn, stated: &[u8]) -> Result<Validated, LoadError> {
    let v = validate::<K>(door)?;
    // SAFETY: `validate` ran `check_statement` on this Statement.
    let own = unsafe { render(&v.statement) }
        .map_err(|e| LoadError::Rendering(format!("{} is too long", e.0)))?;
    if own != stated {
        return Err(LoadError::StatementMismatch);
    }
    Ok(v)
}

/// The door checks, in the order the mechanism states them. Shared by both origins.
pub(crate) fn validate<K: Kind>(door_fn: DoorFn) -> Result<Validated, LoadError> {
    validate_door::<K>(door_fn())
}

/// Where the door's append-only `ready` tail starts: the least size a door states.
const READY_AT: usize = std::mem::offset_of!(Door, ready);

/// The door's head checks, in the mechanism's order: not NULL, the magic, the mechanism version, a
/// size that reaches `ops` (the append-only `ready` tail is optional), a kind the host has, the kind `want` asks for (any, for `None`), and
/// that kind's ABI version.
pub(crate) fn read_door(
    p: *const Door,
    want: Option<KindCode>,
) -> Result<(Door, KindCode), LoadError> {
    if p.is_null() {
        return Err(LoadError::NullDoor);
    }
    // SAFETY: a non-NULL door is `'static` plugin data; the leading fields are read one at a time,
    // and the whole door only after its stated size covers the host's.
    let (magic, mechanism, size) = unsafe {
        (
            addr_of!((*p).magic).read_unaligned(),
            addr_of!((*p).mechanism_version).read_unaligned(),
            addr_of!((*p).size).read_unaligned(),
        )
    };
    if magic != DOOR_MAGIC {
        return Err(LoadError::Magic(magic));
    }
    if mechanism != MECHANISM_VERSION {
        return Err(LoadError::Mechanism {
            door: mechanism,
            host: MECHANISM_VERSION,
        });
    }
    // APPEND-ONLY: a door must reach `ops`; the `ready` tail is read only when `size` covers it.
    if (size as usize) < READY_AT {
        return Err(LoadError::DoorSize {
            door: size,
            host: READY_AT as u32,
        });
    }
    let has_ready = size as usize >= READY_AT + size_of::<Option<Op>>();
    // SAFETY: as above; the door covers every field up to `ready`, and `ready` itself only when
    // `has_ready` (an absent tail reads as `None`).
    let door = unsafe {
        Door {
            magic,
            mechanism_version: mechanism,
            size,
            kind: addr_of!((*p).kind).read_unaligned(),
            kind_abi: addr_of!((*p).kind_abi).read_unaligned(),
            statement: addr_of!((*p).statement).read_unaligned(),
            ops: addr_of!((*p).ops).read_unaligned(),
            ready: if has_ready {
                addr_of!((*p).ready).read_unaligned()
            } else {
                None
            },
        }
    };
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

/// [`validate`] on the pointer a door function answered.
pub(crate) fn validate_door<K: Kind>(p: *const Door) -> Result<Validated, LoadError> {
    let (door, kind) = read_door(p, Some(K::CODE))?;
    let slots = table::<K>(door.ops)?;
    let statement = statement(&door)?;
    Ok(Validated {
        kind,
        statement,
        slots,
        ready: door.ready,
    })
}

/// The table: `slots` and `size` equal to the host's table of `K`, every slot non-NULL.
fn table<K: Kind>(ops: *const OpsHead) -> Result<Box<[Op]>, LoadError> {
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
            unsafe { first.add(i as usize).read_unaligned() }.ok_or(LoadError::NullSlot(i))
        })
        .collect()
}

pub(crate) fn statement(door: &Door) -> Result<Statement, LoadError> {
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
    for i in 0..st.families_len {
        // SAFETY: `families` holds `families_len` `'static` entries.
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
    // SAFETY: a door's Statement is `'static` plugin data; `check_statement` refuses a NULL list
    // with a count before it reads the list.
    unsafe { check_statement(&st) }
        .map_err(|f| LoadError::BadStatement(format!("{} breaks {:?}", f.field, f.rule)))?;
    kind_tail(&st)?;
    Ok(st)
}

/// A Statement's kind tail, at admit: its head states at least itself, and a transport's tail is a
/// whole [`TransportTail`] with exactly one claim row per scheme the Statement names (the names
/// are the Statement's alone).
pub(crate) fn kind_tail(st: &Statement) -> Result<(), LoadError> {
    if st.kind_tail.is_null() {
        // A transport that names claims has a row per name, so it has a tail.
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
    if st.kind != KindCode::Transport as u32 {
        return Ok(());
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

fn str_is_bad(s: AbiStr) -> bool {
    s.ptr.is_null() || s.len == 0
}
