// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin images, the host-side `Instance` and the Need step driver (IF §10.4 generic part, §10.5). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

use core::marker::PhantomData;
use std::sync::Arc;

use crate::host_side::caller::{Caller, InstanceLimits};
use crate::host_side::needs::Needs;
use crate::host_side::scrub::Scrub;
use crate::types::KindCode;

/// One mapped plugin image. `Linked` = compiled into the binary (never unmapped). `Loaded` owns the dl handle,
/// the staged memfd/temp file and the mapped segments, and is **resident** (I13): it is never `dlclose`d. Its
/// last `Arc` is held by the loader's process-wide image table (`instance.rs`: a cold `Mutex<HashMap<[u8; 32],
/// Arc<Image>>>` touched only by admit, keyed by image SHA-256, so re-admitting identical bytes on a
/// reconfigure or an upgrade-and-back reuses the mapping instead of loading it again); when the last instance of
/// an image goes away the table keeps the handle, and stage.rs retains its memfd (origin/dev `retire_memfd`,
/// stage.rs:520), so its name is never recycled. Cost: one mapping per distinct image admitted during the
/// process's life (gauge `plugin_images_resident`, bytes in `plugin_images_resident_bytes`); a restart reclaims it.
pub enum Image {
    Linked,
    Loaded(LoadedImage),
}

// IF §11.1: the loaded-image payload of `Image::Loaded`.
// W1-L1 (loader admit) fills the fields the W0 stub assigned to it. UNSAFE-MIN r3.1 moved the dl handle and the
// H4 segment check into busbar-ffi (`image::Opened::open` checks the header against the image's segments,
// `Opened::admit` leaks the library, so it is never unloaded), so what the image keeps here is its SHA-256 and
// the loader's stage.rs `Staged` (the sealed memfd or the pinned temp file), held for the life of the process.
pub struct LoadedImage {
    sha256: [u8; 32],
    _staged: Box<dyn core::any::Any + Send + Sync>,
}
impl LoadedImage {
    /// A dropped-in image admit loaded: its SHA-256 and the staged handle its mapping came from.
    pub fn new(sha256: [u8; 32], staged: Box<dyn core::any::Any + Send + Sync>) -> Self {
        LoadedImage {
            sha256,
            _staged: staged,
        }
    }
    /// The SHA-256 of the image's bytes (the key of the loader's resident image table).
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

pub struct Instance {
    // W0-ABI: the private fields `image: Arc<Image>` (keeps the image mapped; dropped after `close` returns),
    // `plugin: NonNull<Plugin>` (points into `image`), `lease: SlotLease` (the slot record's lease, §11.2; a
    // plugin-loader type) and `inst: *const c_void` are one `_stub` here; they land with W1-H1 together with
    // the IF's `Send`/`Sync` impls for `Instance` (omitted: rule 2).
    _stub: PhantomData<Arc<Image>>,
    pub kind: KindCode,
    /// The verified stamp name.
    pub identity: Arc<str>,
    /// The configured instance name (§10.3 `Caller::name`).
    pub name: Arc<str>,
    pub id: u64,
    /// Watchdog slot (index into the registry's slot table, < 2^24).
    pub slot: u32,
    /// Round 8 (§12.22), copied into every `Caller`.
    pub limits: InstanceLimits,
    pub max_out: usize,
    pub methods: u64,
    pub facts: u64,
    /// This instance's scrub set (§12.16), filled by custody as it resolves secrets for it.
    pub scrub: Arc<Scrub>,
    // Round 14: `ceilings_us` and `state` moved into the slot's `SlotCell` (§11.2), reached through `lease`
    // (`SlotLease::cell()`, one pointer, cells never move), so the watchdog reads ceilings and quarantines through
    // the slot alone and Image-owned entries have the same row and target.
}
impl Instance {
    /// One Acquire load of the slot's state word (LIVE in this lease's epoch).
    pub fn is_live(&self) -> bool {
        todo!()
    }
    /// CAS (epoch, LIVE) → (epoch, QUARANTINED) on the slot's state word; the watchdog's `SlotTable::hung` and the
    /// entry guard's FAULT path both land here.
    pub fn quarantine(&self) {
        todo!()
    }
    /// The slot's ceiling row (µs; index = kind method bit 0..=55 or ENTRY_*, §10.6).
    pub fn ceilings_us(&self) -> &[core::sync::atomic::AtomicU32; 64] {
        todo!()
    }
    pub fn image(&self) -> &Arc<Image> {
        todo!()
    }
}
// W0-ABI: `impl Drop for Instance` (IF §10.4: `close` runs inline under `entry::guard` with the Image owner,
// then the lease is released, `Arc<Image>` last) lands with W1-H1.

/// Round 14: built by the adapter per async call (plain stores: `Caller<'a>` is Copy and borrows, §10.3) and
/// borrowed by the proxy future for its whole life (round 15: `drv: &'a mut Driver<'a, N>`, §10.4, exclusive, so
/// no second chain can borrow it); the `ChainGuard` reborrows `&drv.caller` shared, so no field is moved or
/// cloned out of it.
/// **Round 15: one Driver is one chain.** Fields are private and `Driver::new` is the only constructor, so every
/// Driver carries a fresh `caller.chain` (§10.3 `next_chain`), and the proxy methods take `&'a mut Driver`
/// (§10.4), so the borrow checker refuses two concurrent futures on one Driver (two live chains can never share
/// a chain id). The adapter builds one per async call, on its stack or in its port future.
pub struct Driver<'a, N: Needs> {
    needs: &'a N,
    caller: Caller<'a>,
    max_steps: u32,
}
impl<'a, N: Needs> Driver<'a, N> {
    /// Sets `caller.chain = next_chain()` (whatever the adapter wrote is overwritten); `max_steps` = 10,000.
    pub fn new(needs: &'a N, caller: Caller<'a>) -> Self {
        let _ = (needs, caller);
        todo!()
    }
    /// Override the step cap (tests, Image-owned chains); never touches `chain`.
    pub fn with_max_steps(self, max_steps: u32) -> Self {
        let _ = (&self.needs, &self.caller, &self.max_steps, max_steps);
        todo!()
    }
    pub fn caller(&self) -> &Caller<'a> {
        let _ = (&self.needs, &self.caller, &self.max_steps);
        todo!()
    }
}

// W0-ABI: `pub(crate) enum ChainOwner<'a> { Instance(&'a Instance), Image { image: Arc<Image>, plugin:
// NonNull<Plugin>, lease: SlotLease } }` with `inst_ptr`/`entry_owner` and its `Send`/`Sync` impls (IF §10.5),
// and `pub(crate) struct ChainGuard<'a, N: Needs> { owner, needs, caller, vt_resume: RawResume, vt_cancel:
// RawCancel, tok: Token, needed: bool, bufs: ChainBufs }` with its Drop rule (IF §10.5) land with W1-H1: they
// are crate-private with no caller in wave 0 (dead code), `SlotLease` is a plugin-loader type, the Send/Sync
// impls are rule-2 items, and `RawResume`/`RawCancel` are raw entry fn-pointer types.
