// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADER PATH for both origins (§11.4: compiled in or dropped in, the same table).
//!
//! [`load_dropped`] checks the manifest's mechanism version BEFORE `dlopen`, opens the library,
//! finds [`DOOR_SYMBOL`] and runs [`validate`]; [`load_linked`] runs the SAME [`validate`] on a
//! compiled-in row's door. Both answer the same [`Plugin`]. The door is refused — never guessed,
//! never a panic — for: a wrong magic, a mechanism or kind ABI version older OR newer than the
//! host's, an unknown kind or another kind than `K`, a door smaller than the host's, a NULL table,
//! a table whose `slots`/`size` differ from the host's table of `K`, any NULL slot, or a Statement
//! that is missing, short, disagrees with the door or points at NULL arrays.

use std::fmt;
use std::mem::size_of;
use std::path::Path;
use std::ptr::addr_of;

use busbar_contract::abi::mechanism::call::{AbiStr, Op};
use busbar_contract::abi::mechanism::door::{
    Door, DoorFn, KindTailHead, MetricFamily, Statement, FAMILY_HISTOGRAM,
};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};
use libloading::Library;

use super::plugin::{Bind, Plugin};
use super::{host_slots, host_table_size, Kind, FIRST_SLOT};

/// What a dropped plugin's signed manifest states about its door, checked before `dlopen`.
///
/// M3-secret: the first kind table adds `mechanism_version`/`kind`/`kind_abi` to the signed
/// `sign::Manifest` and removes `ManifestFacts` (ARCHITECT ruling on M1 Q1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestFacts {
    /// The mechanism version the plugin was built against.
    pub mechanism_version: u32,
    /// Its kind.
    pub kind: KindCode,
    /// Its kind's ABI version.
    pub kind_abi: u32,
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
    /// The door is smaller than the host's.
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
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestMechanism { stated, host } => write!(
                f,
                "the manifest states mechanism version {stated}; this host speaks {host} — rebuild the plugin against the 1.6.0 SDK"
            ),
            Self::ManifestKind { stated, want } => {
                write!(f, "the manifest states kind {stated:?}, not {want:?}")
            }
            Self::ManifestKindAbi { stated, host } => write!(
                f,
                "the manifest states kind ABI {stated}; this host speaks {host} — rebuild the plugin against the 1.6.0 SDK"
            ),
            Self::Open(e) => write!(f, "the library did not load: {e}"),
            Self::NoDoor(e) => write!(f, "the library exports no busbar_plugin_door: {e}"),
            Self::NullDoor => f.write_str("the door function answered NULL"),
            Self::Magic(m) => write!(f, "the door's magic {m:#018x} is not BUSBARPL"),
            Self::Mechanism { door, host } => write!(
                f,
                "the door's mechanism version {door} is not this host's {host} — rebuild the plugin against the 1.6.0 SDK"
            ),
            Self::DoorSize { door, host } => {
                write!(f, "the door is {door} bytes; this host's is {host}")
            }
            Self::UnknownKind(k) => write!(f, "the door names kind {k}, which no kind has"),
            Self::WrongKind { door, want } => {
                write!(f, "the door names kind {door:?}, not {want:?}")
            }
            Self::KindAbi { kind, door, host } => write!(
                f,
                "the door's {kind:?} ABI version {door} is not this host's {host} — rebuild the plugin against the 1.6.0 SDK"
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
        }
    }
}

impl std::error::Error for LoadError {}

/// A door that passed [`validate`]: copies of its `'static` data and its slots.
pub(crate) struct Validated {
    pub(crate) kind: KindCode,
    pub(crate) statement: Statement,
    pub(crate) slots: Box<[Op]>,
}

/// The loaded library, unloaded on the loader's worker when the last instance handle drops.
pub(crate) struct Lib(Option<Library>);

impl Drop for Lib {
    fn drop(&mut self) {
        if let Some(lib) = self.0.take() {
            reap(Box::new(move || crate::dlclose_on_worker(lib)));
        }
    }
}

/// An unload, as the reaper runs it.
pub(crate) type Unload = Box<dyn FnOnce() + Send>;

/// THE REAPER: every library unload (plugin `.fini_array` code) runs on this one dedicated thread,
/// fire and forget. Never on a request worker, never on the watchdog, never under a worker's lock
/// and never inside another op's crossing record, so an unload that hangs wedges only the reaper:
/// no innocent instance is faulted and no caller waits.
pub(crate) fn reap(unload: Unload) {
    static REAPER: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Unload>>> =
        std::sync::OnceLock::new();
    let tx = REAPER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<Unload>();
        std::thread::Builder::new()
            .name(REAPER_THREAD.into())
            .spawn(move || {
                for unload in rx {
                    unload();
                    #[cfg(test)]
                    UNLOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .expect("spawn the unload reaper");
        std::sync::Mutex::new(tx)
    });
    let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send(unload);
}

/// The reaper thread's name.
pub(crate) const REAPER_THREAD: &str = "busbar-dispatch-reaper";

/// TEST WITNESS: unloads the reaper finished.
#[cfg(test)]
pub(crate) static UNLOADS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// THE DROPPED-IN DOOR: `path`'s manifest facts, then `dlopen`, then [`DOOR_SYMBOL`], then
/// [`validate`]. A mechanism version the host does not speak is refused before the library is
/// opened.
pub fn load_dropped<K: Kind>(
    path: &Path,
    facts: &ManifestFacts,
    bind: Bind,
) -> Result<Plugin<K>, LoadError> {
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
    let lib = crate::dlopen_on_worker(path.as_os_str()).map_err(LoadError::Open)?;
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the symbol is copied out as a plain
    // fn pointer, kept valid by `Lib` for as long as any handle to the instance lives.
    let door = unsafe { lib.get::<DoorFn>(DOOR_SYMBOL).map(|s| *s) };
    let lib = Lib(Some(lib));
    let door = door.map_err(|e| LoadError::NoDoor(e.to_string()))?;
    Plugin::bind(validate::<K>(door)?, Some(lib), bind)
}

/// THE LINKED DOOR: a compiled-in row's [`DoorFn`], through the same [`validate`].
pub fn load_linked<K: Kind>(door: DoorFn, bind: Bind) -> Result<Plugin<K>, LoadError> {
    Plugin::bind(validate::<K>(door)?, None, bind)
}

/// The door checks, in the order the mechanism states them. Shared by both origins.
pub(crate) fn validate<K: Kind>(door_fn: DoorFn) -> Result<Validated, LoadError> {
    validate_door::<K>(door_fn())
}

/// [`validate`] on the pointer a door function answered.
pub(crate) fn validate_door<K: Kind>(p: *const Door) -> Result<Validated, LoadError> {
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
    if (size as usize) < size_of::<Door>() {
        return Err(LoadError::DoorSize {
            door: size,
            host: size_of::<Door>() as u32,
        });
    }
    // SAFETY: as above; the door covers the host's size.
    let door = unsafe { p.read_unaligned() };
    let kind = KindCode::from_raw(door.kind).ok_or(LoadError::UnknownKind(door.kind))?;
    if kind != K::CODE {
        return Err(LoadError::WrongKind {
            door: kind,
            want: K::CODE,
        });
    }
    if door.kind_abi != kind.abi_version() {
        return Err(LoadError::KindAbi {
            kind,
            door: door.kind_abi,
            host: kind.abi_version(),
        });
    }
    let slots = table::<K>(door.ops)?;
    let statement = statement(&door)?;
    Ok(Validated {
        kind,
        statement,
        slots,
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

fn statement(door: &Door) -> Result<Statement, LoadError> {
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
    if !st.kind_tail.is_null() {
        // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`.
        let tail = unsafe { st.kind_tail.read_unaligned() };
        if (tail.size as usize) < size_of::<KindTailHead>() {
            return Err(LoadError::KindTail(format!(
                "its head states {} bytes, less than the head itself",
                tail.size
            )));
        }
    }
    Ok(st)
}

fn str_is_bad(s: AbiStr) -> bool {
    s.ptr.is_null() || s.len == 0
}
