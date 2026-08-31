// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL TEST-APP SEAM — the plane test-kits' one doorway onto the engine's test fixture,
//! so a plane crate builds/drives the test App WITHOUT naming `busbar_core::state::App` or
//! `busbar_core::test_support::TestApp`.
//!
//! Before this seam, `busbar-mcp`/`busbar-a2a`'s `testkit` reached BACKWARDS into
//! `busbar_core::test_support::TestApp` — a plane crate naming core implementation, the exact side
//! channel the neutral-purity lint forbids. The concrete fixture still lives in core (it builds a
//! `busbar_core::state::App`, which is core-central), but core now IMPLEMENTS this trait for it and
//! the plane test-kits consume only the trait — an opaque handle they drive through the same neutral
//! install seams (`install_plane_runtime`, `mount_plane`/`admit_plane`, the type-erased scratch, the
//! build-time finalizer) core's own `build()` reads. No `&App`, no `busbar_core::` name crosses.
//!
//! Object-safe by construction (so a finalizer is a `Box<dyn FnOnce(&mut dyn TestAppSeam)>` and a
//! plane can drive the handle as `&mut dyn TestAppSeam`): the generic scratch accessors live on the
//! blanket [`TestAppSeamExt`] rather than on the object-safe base.

use crate::plane::registry::CardIssuer;
use crate::plane::PlaneAdmission;
use std::any::Any;
use std::sync::Arc;

/// THE OBJECT-SAFE FIXTURE SEAM core implements for its `TestApp`. Every method is a neutral verb the
/// plane test-kits already drove on the concrete fixture; the signatures name only neutral ABI types
/// (`CardIssuer`, `PlaneAdmission`, opaque `Arc<dyn Any>` runtimes, `&str` keys), so a plane crate
/// consuming this trait spells no `busbar_core::` implementation item.
pub trait TestAppSeam {
    /// Get-or-create this plane's type-erased accumulator scratch under `key`, initialising with
    /// `init` on first touch. The plane downcasts the returned `&mut dyn Any` to its own scratch type
    /// (see [`TestAppSeamExt::plane_scratch`], the typed sugar). `key` must be used with ONE type.
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn Any>,
    ) -> &mut dyn Any;

    /// Remove and return this plane's accumulator scratch under `key` (or `None` if never touched),
    /// consumed by the finalizer at build time (see [`TestAppSeamExt::take_plane_scratch`]).
    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn Any>>;

    /// Register a finalizer to run at the top of `build()`. A plane registers exactly one; it reads
    /// the scratch back and drives the neutral install seams. Kept out of `build()` proper so core
    /// names no plane type.
    #[allow(clippy::type_complexity)]
    fn register_plane_finalizer(&mut self, f: Box<dyn FnOnce(&mut dyn TestAppSeam)>);

    /// The fixture's configured `public_url:`, which a plane's finalizer needs to lower its runtime
    /// (the A2A plane derives its card/discovery origins from it).
    fn configured_public_url(&self) -> Option<&str>;

    /// busbar's PUBLIC card-issuer key off the fixture's governance, as the neutral [`CardIssuer`] —
    /// computed exactly as production's boot fold. A KEYED capability (the requesting plane's decl
    /// `key`), mirroring the other keyed seams so the method names no plane; `None` when no governance
    /// / no card key. Only the card-issuing plane asks, under its own key.
    fn card_issuer(&self, plane_key: &'static str) -> Option<CardIssuer>;

    /// Install a pre-built, type-erased plane runtime under its plane decl `key` (or the per-generation
    /// runtime-slot companion). `build()` moves the accumulated map into the App's type-erased slots.
    fn install_plane_runtime(&mut self, key: &'static str, rt: Arc<dyn Any + Send + Sync>);

    /// Record that plane `key` is mounted at `path` speaking `wire` (a neutral wire const).
    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str);

    /// Record plane `key`'s RFC 8707 admission (the substrate `PlaneAdmission` the plane's own accessor
    /// returns), so `build()` wires the audience check naming no plane type.
    fn admit_plane(&mut self, key: &'static str, admission: PlaneAdmission);

    /// Hand `build()` plane `plane_key`'s per-container hook SPECS as plain strings (`(name, own-hooks)`
    /// pairs + the section hook list); `build()` resolves them through the SAME resolver production uses
    /// and files the resulting gate map under `plane_key`. KEYED by the plane's decl `key` — the neutral
    /// twin of the generic `plane_gates`/`plane_pools` keying — so one method serves every plane's
    /// container-gate section (`tools:` for MCP, `agents:` for A2A) naming no plane.
    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    );

    /// Set plane `plane_key`'s type-erased named-definition config the built App carries (the `agents:`
    /// defs the A2A plane erases); core names no plane config type. KEYED like [`Self::set_container_hooks`]
    /// so this one method serves any plane's section-defs handle.
    fn set_plane_defs_any(&mut self, plane_key: &'static str, defs: Arc<dyn Any + Send + Sync>);
}

/// TYPED SUGAR over the object-safe [`TestAppSeam`] scratch accessors — a blanket-implemented
/// extension so a plane writes `app.plane_scratch::<MyScratch>(KEY)` against a `&mut dyn TestAppSeam`
/// exactly as it did against the concrete fixture. Generic (hence off the object-safe base) but usable
/// on a trait object through the blanket impl below.
pub trait TestAppSeamExt: TestAppSeam {
    /// Get-or-create this plane's scratch under `key`, downcast to `T` (defaulting on first touch).
    fn plane_scratch<T: Any + Default>(&mut self, key: &'static str) -> &mut T {
        self.plane_scratch_any(key, &|| Box::<T>::default())
            .downcast_mut::<T>()
            .expect("plane_scratch key is used with one consistent type")
    }

    /// Remove and return this plane's scratch under `key`, downcast to `T` (or `T::default()`).
    fn take_plane_scratch<T: Any + Default>(&mut self, key: &'static str) -> T {
        self.take_plane_scratch_any(key)
            .map(|b| *b.downcast::<T>().expect("plane_scratch key type"))
            .unwrap_or_default()
    }
}

impl<A: TestAppSeam + ?Sized> TestAppSeamExt for A {}
