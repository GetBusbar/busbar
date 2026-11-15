// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 registry: admitted plugins, the instance and slot tables, error books, boot plan (IF §11.2, round 31
//! §47, round 34 §50). W0-ABI stub: frozen signatures, `todo!()` bodies; L2 fills it. The 1.5 `PluginRegistry`
//! stays in `registry.rs`.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use std::sync::Arc;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::types::KindCode;

use crate::admit::Admitted;
use crate::encode::plane;
use crate::ports::auth::{AuthPort, IssuedShape};
use crate::ports::export::ExportPort;
use crate::ports::hook::HookPort;
use crate::ports::plane::PlanePort;
use crate::ports::secret::{SecretPort, SugarDecl};
use crate::ports::store::StoreHandle;
use crate::ports::transport::TransportPort;
use crate::refusal::Refusal;

pub struct Registry<N: Needs> {
    // admitted plugins by identity, instance table (slots), Arc<N>, &'static Host, Arc<dyn ConfigBinder>
    _stub: PhantomData<Arc<N>>,
}

/// `config_json` is the operator's config for this instance as core holds it (secret references with their
/// `module`, PEM CAs inline). The registry never passes it to the plugin: the binder rewrites it first.
/// identity = which admitted plugin (verified stamp name); name = the operator's instance name (the config
/// key, e.g. `planes.mcp-main`, `auth.openai-outbound`), stable across restart, reconfigure and replicas, unique
/// per kind; every durable core state for the instance is keyed by (identity, name) (§10.3).
pub struct InstanceSpec<'a> {
    pub identity: &'a str,
    pub name: &'a str,
    pub config_json: &'a [u8],
    /// Round 8: parsed by the kernel from `limits` beside `module` (§12.22); `config_json` never contains it.
    pub limits: InstanceLimits,
    /// Round 14: core's top-level `public_url` (None = unset), the same value for every instance. The registry
    /// writes it only at a D_PUBLIC_URL_PATH a plane image declared (§12.7 core values); every other kind ignores it.
    pub public_url: Option<&'a str>,
    /// Round 22: the configured upstream names whose resolved binding is caller-mode (`UpstreamAuth.caller`,
    /// §12.1), sorted; the same slice for every instance. Written only at a D_CALLER_UPSTREAMS_PATH a plane image
    /// declared; every other kind ignores it.
    pub caller_upstreams: &'a [Box<str>],
}

pub struct Ceilings {
    pub max_out: usize,
    pub max_out_store: usize,
    pub sync_ceiling_us: u32,
    pub poll_ceiling_us: u32,
    pub cold_ceiling_us: u32,
    pub max_steps: u32,
}

impl<N: Needs> Registry<N> {
    // W0-ABI: `pub fn new(host: &'static Host, needs: Arc<N>, binder: Arc<dyn ConfigBinder>, ceilings: Ceilings)
    // -> Self` is omitted: `ConfigBinder` is a busbar-kernel trait (§12.7, `plugin_config`) and the kernel sits
    // above this crate, so the loader cannot name it. L2 lands `new` once the lead designer homes the trait.

    /// Round 6: also runs the plugin's describe once (cold, `EntryOwner::Image`, round 14: its own leased watchdog
    /// slot with the fixed describe row, refused `DescribeInvalid` "describe.ceiling" if the watchdog marked it; round 10:
    /// inline under `entry::guard` on the calling thread) and keeps the `Described`; a secret plugin's D_SUGAR items are decoded here
    /// (`secret::decode_sugars`) so `sugars()` is complete before any config is bound. Round 9: refuses
    /// `NameConflict` (§4.3) when the plugin's identity or a `former_names` word (§7.1) equals an already-admitted
    /// plugin's identity or word; the generic `module:` match resolves identity, then words.
    /// **Round 34 (PLUGIN-ERROR-CODES §2.2-§2.4):** in the same describe pass it decodes D_ERRORS and builds the
    /// image's `ErrorBook` (below), on both load paths. A bad declaration is exactly one of: more than one D_ERRORS
    /// item (`have` "2 D_ERRORS items"); body empty, odd or over 512 bytes ("body 3 bytes"); a number 0 or above 9999
    /// ("10000 at index 4"); not strictly ascending ("7071 after 7071 at index 2"); an identity that cannot form a
    /// code (`scan::error_identity`, L1: "bad character at byte 4", "length 70 > 64"). The check runs before any
    /// allocation. Every fault ends the same way: **the image is admitted with `ErrorBook::Refused`** (never a
    /// `Refusal`, never DescribeInvalid; a store or gate hook still serves, boot continues) and the fault is kept
    /// as `Described::error_codes_refused`; the kernel's admission path reads it once and writes one WARN (core
    /// diagnostic BUSBAR-6xxx "plugin error numbers refused", `field: "errors"`, `have`, `want`) and one audit row
    /// `plugin.error_codes_refused` (outcome `degraded`, severity `warning`, `data` = `ErrorCodesRefused {field,
    /// have, want}`, principal `node:<id>`, resource `plugin:<file>`, `kind`, `instance: null`, a core-written
    /// `message` naming the file and the library SHA-256) (K8D), and the admin API shows
    /// `image.admission.error_codes_refused` = that `data`, or `null` (K8C, ADMIN-API-1.6 §B.9). `have` is built only from
    /// the templates above (decimal counts, declared numbers, byte offsets and lengths), never a stamp or name byte;
    /// `want` is the constant "1..=256 numbers, each 1..=9999, strictly ascending; name ^[a-z][a-z0-9-]{0,63}$ not
    /// ending '-'". A malformed describe frame stays DescribeInvalid. An image without D_ERRORS gets
    /// `ErrorBook::None` and no identity check.
    pub fn add(&mut self, admitted: Admitted) -> Result<(), Refusal> {
        let _ = (&self._stub, admitted);
        todo!()
    }

    /// Round 6: every admitted secret plugin's declared shorthands, in admission order. The kernel feeds them to
    /// `busbar_contract::secret_ref::Sugars::declare` (which refuses core words, duplicate words and duplicate
    /// roles) and hands the resulting `Sugars` to the binder (§12.7) and to its own config-section parsing.
    pub fn sugars(&self) -> &[SugarDecl] {
        todo!()
    }

    /// Round 11: per admitted auth image, its identity and its D_OUTBOUND_STYLE words (decoded at `add`), in
    /// admission order. Read only to build the STYLES frame the helper's `config::resolve_styles` consumes
    /// (round 13, §12.10 item 3, §12.18).
    pub fn outbound_styles(&self) -> Vec<(&str, Vec<&str>)> {
        todo!()
    }

    /// Round 22: the D_STYLE_FLAGS mask (`auth::STYLE_*`) an admitted auth image declared for one of its styles
    /// (decoded at `add`; 0 when it declared none or the pair is unknown). Read only by K6 when it resolves a
    /// binding's credential mode and O_SCOPE (§12.18 "credential mode").
    pub fn style_flags(&self, identity: &str, style: &str) -> u64 {
        let _ = (identity, style);
        todo!()
    }

    /// Round 12: the identities of admitted **compiled-in** (`Image::Linked`) store images whose describe facts
    /// carry `store::FB_EPHEMERAL`, in admission order. Read only by K9's absent-store rule (§12.10 item 1;
    /// MIGRATE-ON-BOOT r15 §3 1d); drop-ins are never listed.
    pub fn ephemeral_stores(&self) -> Vec<&str> {
        todo!()
    }

    /// Round 12: per admitted hook image, its identity and its D_WORD words (§8.4), in admission order. Read
    /// only by the kernel's pool strategy resolution (§12.25).
    pub fn hook_words(&self) -> Vec<(&str, Vec<&str>)> {
        todo!()
    }

    /// Round 12: per issued-credential kind any admitted auth image declares (D_ISSUED_KIND), the shape its
    /// D_ISSUED_SHAPE item states (§8.3), decoded at `add`. Read only by issued credentials (§12.8).
    pub fn issued_shapes(&self) -> Vec<(&str /* issued kind */, IssuedShape)> {
        todo!()
    }

    /// Round 13: per admitted plane image, its identity and its D_PROVIDER_SCHEMA text (§8.6 provider keys),
    /// decoded at `add`. Read only by the kernel's provider-entry validation at config load.
    pub fn provider_schemas(&self) -> Vec<(&str, &str)> {
        todo!()
    }

    /// Round 14 (round 15: typed): per admitted plane image, its identity and its D_DIALECT_AUTH rows, decoded at
    /// `add` (`plane::decode_dialect_auth`, owned copies). Read only by K6's binding materialisation (§12.18).
    pub fn dialect_auth(&self) -> Vec<(&str, Vec<plane::DialectAuthOwned>)> {
        todo!()
    }

    /// Allocate the instance id and watchdog slot (the slot record carries (kind, configured name, a fresh
    /// `Arc<Scrub>`) from this moment, so log attribution and custody's scrub registration work in open chains.
    /// Round 8: the record stays in the registry's slot table for its whole life and is owned through a
    /// `SlotLease`; the lease moves Image chain → Instance and is released only after the last entry that can log
    /// under that slot has returned (round 10: after the inline close in `Drop for Instance`, or after the inline
    /// cancel in a dropped Image chain's guard, §10.4, §10.5), so a slot is never reused while a close or cancel
    /// of its previous owner is still running); describe; check against the kind (CapUnknown/DescribeInvalid);
    /// `binder.bind(id, config, D_SECRET_PATH*, D_TRUST_PATH*, D_DEST_PATH*, D_REF_PATH*)` then (round 13)
    /// `binder.resolve_refs(id, bound)` (§12.7); then (round 14) write `s.public_url` at each D_PUBLIC_URL_PATH
    /// and (round 22) `s.caller_upstreams` at each D_CALLER_UPSTREAMS_PATH (§12.7 core values; refuse CONFIG if the operator's bag already held that position); validate the *bound* config against
    /// D_SCHEMA; open (driving NEEDs); wrap the result in the kind's port. Any failure after bind calls
    /// `binder.unbind(id)`. Reconfigure = open new, swap, drop old (R6); dropping the old instance unbinds it.
    /// Round 10: describe, migrate and open (every step of their chains), check and close run inline under
    /// `entry::guard` on the thread that drives them, exactly like request ops (I10, §10.7). No dropped-in image
    /// is ever dlclosed (I13), so no entry needs TLS sampling or a permanent worker: origin/dev ffi_thread.rs's
    /// stated hazard (a thread that armed a plugin TLS key exiting after the unmap) is closed by residency, not
    /// by routing, for every entry alike. `ffi_thread` keeps only `dlopen` and `name_still_loaded` (§11.1).
    /// The store adapter is the kernel's existing `PersistenceBackend` (busbar-contract persistence.rs:534),
    /// implemented directly over the proxy. There is no other store port.
    pub fn open_store(&self, s: &InstanceSpec<'_>) -> BoxFut<'_, Result<StoreHandle, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_secret(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn SecretPort>, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_auth(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn AuthPort>, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_hook(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn HookPort>, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_export(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn ExportPort>, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_plane(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn PlanePort>, OpenError>> {
        let _ = s;
        todo!()
    }

    pub fn open_transport(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Arc<dyn TransportPort>, OpenError>> {
        let _ = s;
        todo!()
    }

    /// DRY_RUN open (`--validate`, admin config check). Async because it drives an open chain whose NEEDs await
    /// (round 10: its steps run inline, §10.5); `--validate` awaits it on its own runtime.
    pub fn check(&self, s: &InstanceSpec<'_>) -> BoxFut<'_, Result<(), OpenError>> {
        let _ = s;
        todo!()
    }

    /// Round 31 (owner ruling, §47): there is no `Registry::migrate`. The boot caller walks `BootPlan` (below) —
    /// 2a, 2b, 2c — calling `open_<kind>` for each step before the next step starts, identically for every plugin
    /// (257b: no plugin name, branch or table anywhere on this path), so every secret instance a store's open asks
    /// for through SECRET is already open. Every `open_<kind>` (boot, reload, admin install) binds the bag with
    /// `binder.bind_any` on an unstamped boot and `binder.bind` otherwise (§7.2, §12.7), decodes the optional
    /// CONFIG + CORE_CFG* after INSTANCE with `settled::decode_settled`, validates CONFIG against D_SCHEMA, maps it
    /// and every CORE_CFG value back through core's reference map with `binder.unbind_refs`, and keeps the owned
    /// `Settled` for its caller's write-back (§7.2: step 5, step 5W, the reload path or the admin config store).
    /// REFUSED => `OpenError::Refused` naming the instance index and its configured module, with the plugin's
    /// scrubbed text (or core's own `migrate_admit` text, §5); what that means at boot, reload and admin install
    /// is §7.2's "Refusal" rule, and a reload or admin install refused R_CONFLICT LIVE_WRITER is §7.2's "Live
    /// instances" rule.
    pub fn take_settled(&self, name: &str) -> Option<Settled> {
        let _ = name;
        todo!()
    }

    /// Round 6, boot only: the r6 §3 step 2 order, computed generically. `instances[i]` is configured instance i
    /// with its kind; `deps` = the kernel's existing edges, `appbuild::bootstrap_dependency_names` (appbuild.rs:770),
    /// fed with every SecretRef the binder finds in the store's bag at **any** position (`bind_any` semantics,
    /// because a 1.x bag's older positions are undeclared on an unstamped boot) and in core's own sections that the store
    /// boot needs (admin token, signing key, at-rest keys), each resolved to a configured secret instance through
    /// `Sugars`. 2a = those secret instances, then transitively the secret instances their own bags reference
    /// (depth ≤ 4; a cycle refuses CONFIG naming the instance indices), dependencies first; 2b = the store;
    /// 2c = every remaining instance kind by kind (secret, auth, hook, export, plane, transport), config order
    /// within a kind. Reads only kinds, configured names and SecretRefs: no plugin name (§15.8).
    pub fn boot_plan(
        &self,
        instances: &[(KindCode, InstanceSpec<'_>)],
        sugars: &busbar_contract::secret_ref::Sugars,
    ) -> Result<BootPlan, OpenError> {
        let _ = (instances, sugars);
        todo!()
    }

    /// A pushed desired state (today's hook/plane `configure`): merge `patch` (a JSON object) into the stored
    /// config of instance `name` (absent fields keep their values), `check` it (a refusal is the NACK and
    /// nothing changes), then open the new instance and return it for the caller to swap in (R6). `version`
    /// ordering: a push older than the last applied one is acknowledged and not applied. Core-owned; no plugin
    /// has a configure method.
    pub fn reconfigure(
        &self,
        kind: KindCode,
        name: &str,
        patch: &[u8],
        version: u64,
    ) -> BoxFut<'_, Result<Reconfigured, OpenError>> {
        let _ = (kind, name, patch, version);
        todo!()
    }

    /// Plugin describe facts for admin/health (never shown to another plugin).
    pub fn described(&self, identity: &str) -> Option<Described> {
        let _ = identity;
        todo!()
    }

    /// Start the watchdog thread (100 ms scan, §10.6; over-ceiling => quarantine + audit plugin_hung + alert).
    /// Round 14: the thread runs `watch::scan(|s, e| table.watch_view(s, e), |s, ep, e, ms| table.hung(s, ep, e, ms))`
    /// over the registry's `SlotTable`; it holds no Instance and no Image reference.
    pub fn start_watchdog(&self) {
        todo!()
    }
}

pub struct Described {
    pub kind: KindCode,
    pub methods: u64,
    pub facts: u64,
    pub items: Vec<(u16, Vec<u8>)>,
    pub schema: Option<Box<str>>,
    pub metrics: Vec<MetricInfo>,
    /// Round 34: Some when D_ERRORS was present and refused (`Registry::add`); the image runs without codes.
    pub error_codes_refused: Option<ErrorCodesRefused>,
}

/// Round 34: the one schema for the WARN, the audit `data` and `image.admission.error_codes_refused`.
/// `field` is always "errors"; `have` is template-built (never a plugin byte); `want` is the constant of `add`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCodesRefused {
    pub field: &'static str,
    pub have: Box<str>,
    pub want: &'static str,
}

/// Indices into the `instances` slice given to `boot_plan`, in execution order, with the r6 phase of each.
pub struct BootPlan {
    pub steps: Vec<(u32 /* instance index */, BootPhase)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootPhase {
    StoreSecrets, /* 2a */
    Store,        /* 2b */
    Rest,         /* 2c */
}

// Round 29, the deployment point between 2b and 2c (L2, `registry.rs` +2; §5 `deployment`, §16.187). After the
// last `Store` step and before the first `Rest` step, the boot walk calls `host_vt::set_deployment(id)` with the
// id the kernel read or wrote (K-side, boot_identity.rs keep-once), then `Registry::check` once for every
// `StoreSecrets` and `Store` instance, in plan order, with the same `InstanceSpec`. Any `Err` refuses the boot
// exactly as a step-2c `open` refusal does (`OpenError::Refused` naming the instance index and module, the plugin's
// scrubbed text). Those instances keep running; nothing is re-opened. A plugin that binds to the install identity
// therefore sees `deployment_id()` None in its 2a/2b `check`/`open` and Some in this re-check, always before 2c.

/// Round 31: one instance's settled settings from its `open`, in operator form (secret references restored).
/// `core_cfg` fragments are filed by `config::file_core_cfg` into core's own sections (§12.10); `config_json`
/// replaces the bag. Taken once by the write-back (`take_settled`); core stores no version with it.
pub struct Settled {
    pub config_json: Vec<u8>,
    pub core_cfg: Vec<CoreCfg>,
}

/// section = abi::core_cfg::*; value_json in that section's grammar.
pub struct CoreCfg {
    pub section: u32,
    pub name: Box<str>,
    pub value_json: Vec<u8>,
}

pub struct MetricInfo {
    pub id: u32,
    pub kind: u32,
    pub name: Box<str>,
    pub help: Box<str>,
    pub label_keys: Vec<Box<str>>,
}

/// Round 8: one watchdog slot's record. The log sink and the watchdog map a slot to its `SlotCell`, never to an
/// Instance. Written only by `SlotTable::alloc`, under the table's cold mutex, while the slot is free (no lease,
/// so no entry runs under it and no log line can map to it); read without a lock by the log sink only for the slot
/// of a running entry (whose lease is held, so the record cannot change), and by `hung` under the mutex.
/// Round 34: `errors` = the owning image's book (set at `alloc`, so migrate/open render codes as an instance does);
/// `undeclared_warned` = the per-slot latch of the undeclared WARN, touched only on that path (a Relaxed load and,
/// only when false, a Relaxed store; no RMW, I5; two racing threads may print the WARN twice, which is harmless).
pub struct SlotRecord {
    pub kind: KindCode,
    pub name: Arc<str>,
    pub scrub: Arc<Scrub>,
    pub errors: &'static ErrorBook,
    pub undeclared_warned: AtomicBool,
}

/// Round 34 (PLUGIN-ERROR-CODES §2.5). One per admitted image, built in `Registry::add`, leaked once (images are
/// never unloaded, I13, so `'static` is exact and the leak is bounded: ≤ 512 bytes of numbers + one ≤ 64-byte
/// identity copy per declaring image).
pub enum ErrorBook {
    /// D_ERRORS accepted. `identity` passed `scan::error_identity` (re-checked here with a `debug_assert` and the
    /// same function, so no unchecked identity reaches a rendered code); `numbers` strictly ascending.
    Declared {
        identity: &'static str,
        numbers: &'static [u16],
    },
    /// D_ERRORS present and bad (§11.2 `add`): text renders with no code and no undeclared WARN.
    Refused,
    /// No D_ERRORS.
    None,
}

/// The resolved code, `Copy` over `&'static`, so carrying it does no refcount RMW (B-SYNC REFUSED arm unchanged).
/// `Display` = `BUSBAR-{plugin}-{number:04}`; it always matches `^BUSBAR-[a-z][a-z0-9-]{0,63}-[0-9]{4}$` and can
/// never start like a core `BUSBAR-[0-9]{4}` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginCode {
    pub plugin: &'static str,
    pub number: u16,
}

impl core::fmt::Display for PluginCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BUSBAR-{}-{:04}", self.plugin, self.number)
    }
}

impl ErrorBook {
    /// The one rule for ERROR records and `log` numbers: 0 → None; n > 9999 (as `u32`) → not declared; `Declared`
    /// and `numbers.binary_search(&(n as u16))` hits → Some(code); `Declared` miss or `None` → not declared (None,
    /// and the first time per slot one WARN BUSBAR-6xxx "plugin error number not declared" `{number}`, attributed;
    /// no audit row, never FAULT); `Refused` → None, no WARN.
    pub fn resolve(&self, n: u32, latch: &AtomicBool) -> Option<PluginCode> {
        let _ = (n, latch);
        todo!()
    }
}

/// Round 14: one slot of the registry's slot table. The watchdog's whole view of an owner (§10.6): the ceiling row
/// and the quarantine target live here, beside the record, from `alloc` until the lease is released, and move
/// with the lease Image chain → Instance → close exactly as the record does (I10 (d)).
pub struct SlotCell {
    /// `(epoch << 32) | st`, st = LIVE 0 / QUARANTINED 1 / CLOSING 2. `alloc` bumps the epoch and stores LIVE
    /// (Release, under the mutex); quarantine is a CAS from (epoch, LIVE); `is_live` is one Acquire load.
    pub state: AtomicU64,
    /// The §10.6 row, written by `alloc` (Relaxed stores, before the lease exists), read by `watch::scan`.
    pub ceilings_us: [AtomicU32; 64],
    // W0-ABI: the IF's private `record: core::cell::UnsafeCell<SlotRecord>` (read through the lease) lands with
    // W1-L2.
    _stub: PhantomData<SlotRecord>,
}

/// Round 14: the registry's slot table. Cells live in pages of 64, allocated under the cold mutex when the free
/// list is empty, never moved or freed (so `&SlotCell` from a lease or from `watch_view` is always valid); slot
/// indices stay < 2^24 (the watch word's field).
pub struct SlotTable {
    // dir: [OnceLock<Box<[OnceLock<Box<[SlotCell; 64]>>; 512]>>; 512] (two-level, lock-free reads,
    // 2^24 cells max), cold: Mutex<Vec<u32> /* free list */>
    _stub: PhantomData<SlotCell>,
}

impl SlotTable {
    /// Cold: under the mutex, pops a free slot, writes its record and its ceiling row (`ceilings` = the §10.6 row
    /// for this image, kind and store fact; describe's slot gets the fixed describe row, every index 5 s), bumps
    /// the epoch and stores LIVE, and returns the lease. Every entry (describe included: round 14 withdraws the
    /// inert slot 0) runs under a leased slot.
    pub fn alloc(self: &Arc<Self>, rec: SlotRecord, ceilings: &[u32; 64]) -> SlotLease {
        let _ = (rec, ceilings);
        todo!()
    }

    /// `watch::scan`'s `ceiling` (§10.6): `ceilings_us[entry]` (Relaxed) and `epoch` (Acquire). No lock.
    pub fn watch_view(&self, slot: u32, entry: u8) -> (u32, u32) {
        let _ = (slot, entry);
        todo!()
    }

    /// `watch::scan`'s `report`, cold: takes the mutex (so the slot cannot be released or re-allocated meanwhile);
    /// if the cell's epoch is still `epoch` and its state is LIVE, CASes it to QUARANTINED and audits `plugin_hung`
    /// with the record's (kind, configured name), entry and busy_ms, plus the alert; otherwise (the owner already
    /// released the slot, or was already quarantined) does nothing. Never reaches an Instance: the owner observes
    /// the state word itself. Instance owner: `is_live()` turns false, so the ports answer
    /// `CallError::Quarantined` and the kernel's quarantine-and-reopen path runs (§10.7). Image owner: the registry
    /// checks `lease.is_live()` when the describe, migrate or open entry returns: describe → `Registry::add` refuses
    /// `Refusal { code: DescribeInvalid, field: "describe.ceiling" }`; migrate → `OpenError::Call(Quarantined)`
    /// (MIGRATION_REFUSED, nothing written); open → if INSTANCE was answered the Instance is built in that poll as
    /// always (so its Drop closes it) and dropped at once, and `open_<kind>` returns `OpenError::Call(Quarantined)`.
    pub fn hung(&self, slot: u32, epoch: u32, entry: u8, busy_ms: u64) {
        let _ = (slot, epoch, entry, busy_ms);
        todo!()
    }
}

/// Owns one slot of the registry's slot table; Drop frees the slot (cold: takes the table mutex, stores CLOSING,
/// pushes the slot on the free list). `take` leaves an inert lease whose Drop does nothing.
pub struct SlotLease {
    // slot: u32, epoch: u32, cell: NonNull<SlotCell>, table: Arc<SlotTable>
    // W0-ABI: the IF's `unsafe impl Send/Sync for SlotLease` (round 26) and `Drop` land with W1-L2.
    _stub: PhantomData<Arc<SlotTable>>,
}

impl SlotLease {
    pub fn slot(&self) -> u32 {
        todo!()
    }

    pub fn record(&self) -> &SlotRecord {
        todo!()
    }

    /// Round 14: the leased cell (ceiling row and state word).
    pub fn cell(&self) -> &SlotCell {
        todo!()
    }

    /// Round 14: state word is (this lease's epoch, LIVE).
    pub fn is_live(&self) -> bool {
        todo!()
    }

    pub fn take(&mut self) -> SlotLease {
        todo!()
    }
}

/// Round 10: the round-8 `cold_hop` adapter (`spawn_blocking` of `ffi_thread::on_plugin_thread`) is deleted with
/// `set_cold_hop` (§10.7, §16.92); `Registry::new` installs only the log sink.
/// The newly opened port (the kind's `Arc<dyn …Port>` or StoreHandle), or Stale when `version` was older.
pub enum Reconfigured {
    Opened(OpenedPort),
    Stale,
}

pub enum OpenedPort {
    Store(StoreHandle),
    Secret(Arc<dyn SecretPort>),
    Auth(Arc<dyn AuthPort>),
    Hook(Arc<dyn HookPort>),
    Export(Arc<dyn ExportPort>),
    Plane(Arc<dyn PlanePort>),
    Transport(Arc<dyn TransportPort>),
}

/// Round 34: the three plugin-answer variants carry the resolved ERROR number (`ErrorBook::resolve`; None for a
/// core-made refusal). Its `Display` writes core's own words and the code only; the plugin text is a separate
/// field, never interpolated into a message (§12.16).
#[derive(Debug)]
pub enum OpenError {
    Refused {
        refusal: Refusal,
        error: Option<PluginCode>,
    },
    Config {
        code: u32,
        text: String,
        error: Option<PluginCode>,
    },
    Failed {
        code: u32,
        text: String,
        error: Option<PluginCode>,
    },
    Call(CallError),
    Unknown(String),
}
