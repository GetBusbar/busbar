// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUBLISHED GENERATION DATA, OWNED BY THE SDK (THE DESIGN §11.2: memory a plugin returns is
//! plugin-owned and valid until that plugin's next refresh generation; a plugin crate stays
//! `#![forbid(unsafe_code)]`). A plugin that publishes a value the host reads across calls — a
//! plane's generation snapshot and the claims and routes it points at — hands the SDK an OWNED
//! description of it (a [`Publish::Spec`]: `String`s and `Vec`s). The SDK copies every list and
//! string into an [`Arena`] it owns, lowers the description into the ABI value over that arena, and
//! keeps both until `retire` of that generation ([`Generations::retire`]) or the instance closes.
//!
//! So no safe code can hand the host a pointer into memory it later frees: the plugin never builds
//! the pointer-bearing ABI value itself (only the SDK implements [`Publish`]), and whatever the
//! plugin does with its description after publishing, the host reads the SDK's copy.
//!
//! ```
//! use busbar_contract::abi::plane::PlaneSnapshot;
//! use busbar_contract::abi::sdk::publish::{ClaimSpec, Generations, SnapshotSpec};
//! let gens: Generations<PlaneSnapshot> = Generations::new();
//! let mut target = String::from("/echo");
//! let spec = SnapshotSpec {
//!     claims: vec![ClaimSpec::new("POST", &target, "door", 0)],
//!     ..SnapshotSpec::default()
//! };
//! let _snapshot = gens.publish(1, &spec);
//! drop(spec);
//! target.clear(); // the host still reads "/echo": the SDK holds its own copy
//! assert_eq!(gens.live(), 1);
//! gens.retire(1);
//! assert_eq!(gens.live(), 0);
//! ```
//!
//! A plugin cannot publish an ABI value it built itself, pointers and all:
//!
//! ```compile_fail,E0308
//! use busbar_contract::abi::plane::PlaneSnapshot;
//! use busbar_contract::abi::sdk::publish::Generations;
//! let gens: Generations<PlaneSnapshot> = Generations::new();
//! let raw: PlaneSnapshot = unimplemented!();
//! let _ = gens.publish(1, &raw); // expects a `SnapshotSpec`
//! ```

use std::any::Any;
use std::sync::Mutex;

use crate::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT, BLOB_JSON};
use crate::abi::plane::{AdminRoute, Claim, PlaneSnapshot};

/// The storage one published generation points into. Only the SDK makes one and writes into it;
/// its contents never move (every piece is its own heap allocation) and are freed only when the
/// generation is retired.
pub struct Arena {
    bytes: Vec<Box<[u8]>>,
    lists: Vec<Box<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for Arena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arena")
            .field("bytes", &self.bytes.len())
            .field("lists", &self.lists.len())
            .finish()
    }
}

/// A list the arena holds: plain ABI values whose pointers point into the same arena.
struct List<T> {
    _items: Box<[T]>,
}

// SAFETY: `T` is one of the SDK's sealed `Publish` types: integers and raw pointers into the arena
// that owns this list, which nothing reads through on a safe path and nothing mutates.
unsafe impl<T> Send for List<T> {}
// SAFETY: as `Send`.
unsafe impl<T> Sync for List<T> {}

impl Arena {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            lists: Vec::new(),
        }
    }

    /// `bytes`, copied into the arena; the pointer to the copy (NULL when empty).
    fn copy(&mut self, bytes: &[u8]) -> *const u8 {
        if bytes.is_empty() {
            return std::ptr::null();
        }
        let held: Box<[u8]> = bytes.into();
        let p = held.as_ptr();
        self.bytes.push(held);
        p
    }

    /// `s`, copied, as a present string (an empty string is present, zero-length).
    fn str(&mut self, s: &str) -> AbiStr {
        let ptr = if s.is_empty() {
            // Present but empty: a non-NULL, never-read address.
            std::ptr::NonNull::<u8>::dangling().as_ptr().cast_const()
        } else {
            self.copy(s.as_bytes())
        };
        AbiStr { ptr, len: s.len() }
    }

    /// `s` copied, or absent (NULL) for `None`.
    fn opt_str(&mut self, s: Option<&str>) -> AbiStr {
        s.map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            |s| self.str(s),
        )
    }

    /// `b` copied as a JSON blob, or absent for `None`.
    fn json(&mut self, b: Option<&[u8]>) -> Blob {
        match b {
            Some(b) => Blob {
                ptr: self.copy(b),
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

    /// Each of `specs` lowered and held as one list; its pointer (NULL when empty) and length.
    fn list<T: Publish>(&mut self, specs: &[T::Spec]) -> (*const T, usize) {
        if specs.is_empty() {
            return (std::ptr::null(), 0);
        }
        let items: Box<[T]> = specs.iter().map(|s| T::lower(s, 0, self)).collect();
        let p = items.as_ptr();
        self.lists.push(Box::new(List { _items: items }));
        (p, specs.len())
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::abi::plane::PlaneSnapshot {}
    impl Sealed for crate::abi::plane::Claim {}
    impl Sealed for crate::abi::plane::AdminRoute {}
}

/// An ABI value a plugin publishes, and the owned description it publishes it from. Only the SDK
/// implements it: lowering is where pointers are made, and they are made into the SDK's arena only.
pub trait Publish: sealed::Sealed + Copy + 'static {
    /// The owned description a plugin hands the SDK.
    type Spec;
    /// Lower `spec` for `generation`, every list and string copied into `arena`.
    #[doc(hidden)]
    fn lower(spec: &Self::Spec, generation: u64, arena: &mut Arena) -> Self;
}

/// One claim, owned: see [`Claim`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimSpec {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// The transport claim it arrives over.
    pub carrier: String,
    /// `CLAIM_OPEN` | `CLAIM_EXACT`.
    pub flags: u32,
}

impl ClaimSpec {
    /// A claim of `verb` on `target` over `carrier`.
    #[must_use]
    pub fn new(verb: &str, target: &str, carrier: &str, flags: u32) -> Self {
        Self {
            verb: verb.to_string(),
            target: target.to_string(),
            carrier: carrier.to_string(),
            flags,
        }
    }
}

impl Publish for Claim {
    type Spec = ClaimSpec;
    fn lower(spec: &ClaimSpec, _: u64, arena: &mut Arena) -> Self {
        Self {
            verb: arena.str(&spec.verb),
            target: arena.str(&spec.target),
            carrier: arena.str(&spec.carrier),
            flags: spec.flags,
            _reserved: 0,
        }
    }
}

/// One admin route, owned: see [`AdminRoute`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminRouteSpec {
    /// The verb.
    pub verb: String,
    /// The target path.
    pub target: String,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
}

impl AdminRouteSpec {
    /// A route of `verb` on `target`.
    #[must_use]
    pub fn new(verb: &str, target: &str, flags: u32) -> Self {
        Self {
            verb: verb.to_string(),
            target: target.to_string(),
            flags,
        }
    }
}

impl Publish for AdminRoute {
    type Spec = AdminRouteSpec;
    fn lower(spec: &AdminRouteSpec, _: u64, arena: &mut Arena) -> Self {
        Self {
            verb: arena.str(&spec.verb),
            target: arena.str(&spec.target),
            flags: spec.flags,
            _reserved: 0,
        }
    }
}

/// A generation snapshot, owned: see [`PlaneSnapshot`]. Its generation is the one it is published
/// under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotSpec {
    /// The paths it answers on.
    pub claims: Vec<ClaimSpec>,
    /// Its admin routes.
    pub admin_routes: Vec<AdminRouteSpec>,
    /// Its OpenAPI contribution (JSON); `None` = none.
    pub openapi: Option<Vec<u8>>,
    /// The audience it binds; `None` = no receiving side.
    pub audience: Option<String>,
    /// Its resource metadata; `None` = none.
    pub resource_metadata: Option<String>,
}

impl Publish for PlaneSnapshot {
    type Spec = SnapshotSpec;
    fn lower(spec: &SnapshotSpec, generation: u64, arena: &mut Arena) -> Self {
        let (claims, claims_len) = arena.list::<Claim>(&spec.claims);
        let (admin_routes, admin_routes_len) = arena.list::<AdminRoute>(&spec.admin_routes);
        Self {
            size: std::mem::size_of::<Self>() as u32,
            _reserved: 0,
            generation,
            claims,
            claims_len,
            admin_routes,
            admin_routes_len,
            openapi: arena.json(spec.openapi.as_deref()),
            audience: arena.opt_str(spec.audience.as_deref()),
            resource_metadata: arena.opt_str(spec.resource_metadata.as_deref()),
        }
    }
}

/// One published generation: the value (boxed: its address is what the host holds) and the arena
/// it points into.
struct Generation<T> {
    generation: u64,
    _value: Box<T>,
    _arena: Arena,
}

// SAFETY: `T: Publish` is plain data whose pointers point into `_arena`, owned by the same value;
// nothing reads through them on a safe path, and nothing mutates either after publishing.
unsafe impl<T> Send for Generation<T> {}
// SAFETY: as `Send`.
unsafe impl<T> Sync for Generation<T> {}

/// THE PUBLISHED GENERATIONS of one instance: instance state (`Send + Sync`), holding each
/// published value and its storage until `retire` of its generation, or until it drops (`close`).
pub struct Generations<T: Publish> {
    live: Mutex<Vec<Generation<T>>>,
}

impl<T: Publish> std::fmt::Debug for Generations<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generations")
            .field("live", &self.live())
            .finish()
    }
}

impl<T: Publish> Default for Generations<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Publish> Generations<T> {
    /// None published.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: Mutex::new(Vec::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Generation<T>>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish `spec` as `generation`: the SDK's copy, lowered; the address the host reads, valid
    /// until [`Generations::retire`] of `generation` or until this drops.
    pub fn publish(&self, generation: u64, spec: &T::Spec) -> *const T {
        let mut arena = Arena::new();
        let value = Box::new(T::lower(spec, generation, &mut arena));
        let p = std::ptr::from_ref::<T>(&*value);
        self.lock().push(Generation {
            generation,
            _value: value,
            _arena: arena,
        });
        p
    }

    /// Drop every value published as `generation`, and its storage.
    pub fn retire(&self, generation: u64) {
        self.lock().retain(|g| g.generation != generation);
    }

    /// How many published values are held.
    #[must_use]
    pub fn live(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
#[path = "tests/publish_tests.rs"]
mod tests;
