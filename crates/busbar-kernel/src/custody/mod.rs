// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Custody: SECRET Needs, kernel secrets and the outbound-credential cache (IF §12.2), and the scrub
//! registration that goes with every per-instance miss (IF §12.16). The verdict cache is `auth::verdicts`.

use core::future::Future;
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use busbar_contract::secret_ref::{SecretRef, SourceReference, TemplateRefused};
use busbar_contract::secure::{SecureString, SecureVec};
use busbar_contract::Secret;
use busbar_plugin_abi::fail::refused::R_NOT_FOUND;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller};
use busbar_plugin_abi::host_side::scrub::{Scrub, MIN_NEEDLE};
use busbar_plugin_loader::ports::secret::SecretPort;
use busbar_plugin_loader::ports::{CallCx, PortError};
use foldhash::HashMap;

mod cred;

pub use cred::{CredCache, CredEvent, CredGet, CredentialCache};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyDenied {
    ForeignHandle,
    NoSuchSecretSource,
    Cycle,
    NotFound,
    Unavailable,
    Denied,
}
/// SECRET Needs (by handle) and every secret the kernel itself needs (mTLS certs, upstream keys).
/// 1. Resolve `handle` in `bindings.secret(who.instance, handle)` (§12.7). None => ForeignHandle, audited
///    `secret_handle_foreign` with the instance's kind and configured name (§12.20 attribution rule) (C-SECRET-FOREIGN).
/// 2. SecretRef::None => NotFound. Source{module, settings} => the secret instance configured as `module`;
///    Template => fill each placeholder through step 3 and render the template text; **round 17: custody keeps
///    every fill value (Zeroizing) beside the rendered value until step 5 has registered them all**.
/// 3. Cycle refusal: `cx = CallCx { stack: who.stack.push(who.instance)?, .. }` (push fails at depth 4 =>
///    Cycle); if `cx.stack.contains(target.instance())` => Cycle. Then `target.resolve(cx, settings_json)`;
///    the target's adapter copies cx.stack into its Caller, so a nested SECRET from the target arrives here
///    with the whole chain (C-SECRET-CYCLE: A -> B -> A refused at the second hop, no recursion to deadline).
/// 4. Cache per policy and F_LEASE_S, zeroize, audit the resolve. Never names the secret source in any
///    error that reaches a plugin (every variant maps to NeedErr::Denied/Absent/Unavailable with no text).
///    **Round 7 (I14): the plugin-facing cache is keyed by `(who.instance, handle)`** — the runtime instance
///    id, so the new instance after `migrate`, reconfigure or reopen starts with an empty cache. Nothing in it
///    is shared with another instance or with `resolve_ref`. Fetches from the secret plugin *may* be
///    de-duplicated underneath by a source-level cache keyed by the canonical SecretRef (shared with
///    `resolve_ref` and between instances binding the same source), but a source-level hit is still a miss of
///    the per-instance cache and goes through step 5. `CustodyKey { instance: u64, handle: u32 }` is the
///    per-instance key; `generation(who, handle)` reads that entry; unbind/close drops the instance's entries.
/// 5. **On a per-instance cache miss only** (the instance's first resolve of the handle, a lease renewal or a
///    rotation, whether or not the source-level cache hit), register the value in `who`'s instance scrub set
///    under the binding handle: `scrub.register(handle, &[&value])` (§12.16), before returning it. **Round 17
///    (I14): a Template registers the rendered value and every fill in the same call,
///    `scrub.register(handle, &[&rendered, &fill_1, .., &fill_n])`** (same lock rule, same digest compare, one
///    rebuild), so a plugin line holding only a fill (`token <fill> rejected`, a scheme stripped off `Bearer
///    <fill>`) is masked; a fill shorter than `MIN_NEEDLE` is audited `secret_too_short_to_scrub` like any value.
///    The fills come from the same resolve (origin/dev secret_ref.rs:220-252 `resolve_template_typed` order), never
///    from a second one. **Round 19 (I14), normative: register, then publish.** A miss runs in exactly this
///    order: resolve (step 3); `scrub.register(..)` **returns** (its `ArcSwap::swap` is done); the value is
///    published in the per-instance cache entry (a `Release` store, read by the hit path with `Acquire`);
///    `generation` is bumped; the value is returned. So no consumer of the per-instance cache (a SECRET Need, the
///    connector's `CertDigests`, a kernel-slot user) can obtain a value before the instance's scrub snapshot
///    masks it, and a FAIL or log line built from it is scrubbed by a snapshot that holds it. Misses of one
///    `CustodyKey` are **single-flight**: the entry holds one in-flight resolve per value generation
///    (`tokio::sync::OnceCell::get_or_try_init` semantics; a lease renewal or rotation installs a fresh cell under
///    the shard lock, compare-and-replace on the expired cell only); every other caller that misses on that key
///    awaits it and returns the published value without registering; if the leading future is dropped (chain
///    cancel) or fails, one waiter becomes the leader, and a failure is never cached. An expired value is never
///    served while its renewal is in flight. Publishing first and registering after is forbidden (it opens a window
///    in which a hit returns a value no snapshot masks, §16.155). A per-instance cache hit does nothing but an
///    `Acquire` load and a clone of the published Arc: no lock, no allocation, no registration — and that
///    instance's scrub snapshot already masks that value, because its publish happened after the swap. The
///    kernel's own slots (`slot >= 0x1_0000`, §12.16) follow the same order. A value whose SHA-256 equals what that
///    handle already holds is a no-op in `register`; a new value **replaces** the handle's current value, and
///    **round 18 (I14): the value it replaces stays registered as that handle's previous generation**, masked until
///    the handle changes again or the instance closes (`Scrub::register` shifts, §12.16): a chain that resolved v1
///    before a renewal and fails after it, or v1 kept in instance state since `open` (connection credentials, an
///    outbound key), still has v1 masked. The generation before that is dropped (zeroized); never more than two. `resolve_ref` registers in no instance's set
///    (it has no instance; kernel-internal secrets for an instance use the kernel slots, §12.16).
///
/// Not dyn: `resolve` is RPITIT (I5: no SECRET step boxes); HostNeeds and every other consumer is generic over
/// `C: SecretCustody`. A cache hit returns a clone of the cached Arc (no allocation). `generation(who, handle)`
/// changes whenever step 5 stores a new value for that handle; the connector's `CertDigests` cache (§13) compares
/// it to know when to re-hash a client cert, so OPEN never resolves a cert just to build its PoolKey.
pub trait SecretCustody: Send + Sync + 'static {
    // The IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (clippy-crate-wide disallowed-types,
    // LR-094); custody uses its replacement `busbar_contract::secure::SecureVec` (W0-ABI).
    fn resolve(
        &self,
        who: &Caller<'_>,
        handle: u32,
    ) -> impl Future<Output = Result<Arc<SecureVec>, CustodyDenied>> + Send;
    /// One Relaxed load: the value generation of (who.instance, handle), 0 = never resolved.
    fn generation(&self, who: &Caller<'_>, handle: u32) -> u64;
    /// Kernel-internal callers (no plugin caller): by SecretRef directly, with an empty stack.
    fn resolve_ref<'a>(
        &'a self,
        cx: CallCx,
        r: &'a SecretRef,
    ) -> BoxFut<'a, Result<SecureVec, CustodyDenied>>;
}

/// Outbound credentials from auth plugins (F_CACHE_S > 0). Core-owned custody. The key separates every input
/// that changes the credential: a down-scoped token (RFC 8693, one per scope) never serves another scope, and a
/// caller-grant credential never serves another caller.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CredKey {
    pub auth_instance: u64,
    pub upstream: u64,
    pub scope: [u8; 32], /* SHA-256 of O_SCOPE, zero = none or a binding without STYLE_SCOPE */
    pub caller: [u8; 32], /* SHA-256 of ID_SUBJECT for a caller-mode binding (STYLE_CALLER), zero = none */
}
/// Round 23 (185, 235): the outbound-mint decisions auth-oauth made for itself (single-flight cells and parked
/// tickets, refresh skew, the mint-rate floor, the post-failure window, the scope-cell cap, the mint deadline)
/// are core's, here, and nowhere else. Config `auth.outbound.*`, core vocabulary, read once at load (K2 parses it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredPolicy {
    /// Refresh-ahead margin (`refresh_ahead_s`, default 300 = today's REFRESH_SKEW_SECS, 0..=3600). Sent to the
    /// plugin as FACT(F_MIN_VALID_S) on every outbound call (§8.3).
    pub refresh_ahead_s: u32,
    /// Least time between two mint starts for one key (`min_mint_interval_s`, default 5, 1..=60).
    pub min_mint_interval_s: u32,
    /// The mint call's own deadline (`mint_deadline_s`, default 30, 1..=120), independent of any one request.
    pub mint_deadline_s: u32,
    /// Most keys one auth instance holds (`max_keys_per_instance`, default 256 = today's MAX_SCOPE_CELLS).
    pub max_keys_per_instance: u32,
    /// Round 24: the longest core holds one minted value, whatever lifetime its issuer stated (`max_hold_s`,
    /// default 86,400 = today's MAX_REFRESH_SECS, auth-oauth mint/mod.rs:46-48, applied at :278; 60..=604,800),
    /// so a revoked token is not presented for the process's life.
    pub max_hold_s: u32,
}

impl CredPolicy {
    /// The defaults the IF states for every key.
    pub const DEFAULT: CredPolicy = CredPolicy {
        refresh_ahead_s: 300,
        min_mint_interval_s: 5,
        mint_deadline_s: 30,
        max_keys_per_instance: 256,
        max_hold_s: 86_400,
    };

    /// The config loader's range check for `auth.outbound.*` (K7 reads the keys and calls this); the refusal is
    /// core text naming the key.
    pub fn checked(self) -> Result<Self, &'static str> {
        if self.refresh_ahead_s > 3_600 {
            return Err("auth.outbound.refresh_ahead_s must be 0..=3600");
        }
        if !(1..=60).contains(&self.min_mint_interval_s) {
            return Err("auth.outbound.min_mint_interval_s must be 1..=60");
        }
        if !(1..=120).contains(&self.mint_deadline_s) {
            return Err("auth.outbound.mint_deadline_s must be 1..=120");
        }
        if self.max_keys_per_instance == 0 {
            return Err("auth.outbound.max_keys_per_instance must be at least 1");
        }
        if !(60..=604_800).contains(&self.max_hold_s) {
            return Err("auth.outbound.max_hold_s must be 60..=604800");
        }
        Ok(self)
    }
}

impl Default for CredPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The per-instance key of the plugin-facing cache (round 7, I14): the runtime instance id and the binding
/// handle. A new instance (reconfigure, reopen, an `open` that converted its data) starts with no entries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CustodyKey {
    pub instance: u64,
    pub handle: u32,
}

/// What custody reads from the registry and the config binder. The registry implements it over its slot table,
/// its secret instances and `ConfigBinder::secret`; tests implement it over fixed tables.
pub trait CustodyHost: Send + Sync + 'static {
    /// §12.7 `ConfigBinder::secret(key.instance, key.handle)`: None for an unknown instance or an unbound handle.
    fn binding(&self, key: CustodyKey) -> Option<SecretRef>;
    /// The scrub set of `who`'s instance (its watchdog slot record, §10.6). None: the instance has no live slot,
    /// and custody hands out nothing it could not mask.
    fn scrub(&self, who: &Caller<'_>) -> Option<Arc<Scrub>>;
    /// The secret instance configured as `module` (operator vocabulary), if one is open.
    fn source(&self, module: &str) -> Option<SecretSource>;
    /// One audit row, attributed to `who`'s kind and configured name (§12.20). Core text only: no value, no source.
    fn audit(&self, who: &Caller<'_>, handle: u32, event: CustodyEvent);
    /// The monotonic clock leases are measured on.
    fn now(&self) -> Instant;
}

/// One open secret instance: its runtime id (the cycle check compares it with the call stack) and its port.
#[derive(Clone)]
pub struct SecretSource {
    pub instance: u64,
    pub port: Arc<dyn SecretPort>,
}

/// The rows custody writes (§12.2 steps 1, 4, 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyEvent {
    /// `secret_handle_foreign`: the instance asked for a handle it was never bound (C-SECRET-FOREIGN).
    HandleForeign,
    /// `secret_too_short_to_scrub`: a value (or a template fill) shorter than `MIN_NEEDLE` is not masked.
    TooShortToScrub,
    /// `secret_resolve`: a per-instance miss resolved, registered and published a value.
    Resolved,
}

/// Test-only control of the miss path (C-SCRUB-HIT publish-order arm). Never in the shipped binary: the feature is
/// enabled only from a `[dev-dependencies]` table.
#[cfg(feature = "conformance")]
pub struct Probe {
    /// Awaited by every leading miss after its resolve and before `register` (so before its publish).
    pub park: Arc<dyn Fn(CustodyKey) -> BoxFut<'static, ()> + Send + Sync>,
    /// The negative control: publish first, then park, then register (the order §12.2 forbids).
    pub publish_first: bool,
}

/// The one custody: the plugin-facing cache keyed by `(instance, handle)`, single-flight per key, register then
/// publish, and a source-level cache of leased values underneath it.
pub struct Custody<H: CustodyHost> {
    host: H,
    /// instance id -> its handles. Copied on write: an insert happens once per (instance, handle) and on close.
    instances: ArcSwap<HashMap<u64, Arc<Handles>>>,
    grow: Mutex<()>,
    /// The source-level cache (§12.2 step 4): leased values only, keyed by SHA-256 over the canonical reference,
    /// shared between instances and `resolve_ref`. A hit here is still a per-instance miss (step 5 runs).
    sources: Mutex<HashMap<[u8; 32], Held>>,
    #[cfg(feature = "conformance")]
    probe: ArcSwapOption<Probe>,
}

struct Handles {
    map: ArcSwap<HashMap<u32, Arc<Entry>>>,
    grow: Mutex<()>,
}

/// One per-instance entry: the published value (read lock-free by the hit path), its generation, and the
/// single-flight cell of the generation being resolved.
#[derive(Default)]
struct Entry {
    published: ArcSwapOption<Held>,
    generation: AtomicU64,
    cell: Mutex<Arc<tokio::sync::OnceCell<Arc<Held>>>>,
}

#[derive(Clone)]
struct Held {
    value: Arc<SecureVec>,
    until: Option<Instant>,
}

impl Held {
    fn fresh(&self, now: Instant) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

/// One resolve: the value, every template fill (registered beside it, round 17) and the earliest lease end.
struct Resolved {
    value: Arc<SecureVec>,
    fills: Vec<Arc<SecureVec>>,
    until: Option<Instant>,
}

impl<H: CustodyHost> Custody<H> {
    pub fn new(host: H) -> Self {
        Custody {
            host,
            instances: ArcSwap::from_pointee(HashMap::default()),
            grow: Mutex::new(()),
            sources: Mutex::new(HashMap::default()),
            #[cfg(feature = "conformance")]
            probe: ArcSwapOption::empty(),
        }
    }

    /// Unbind or close: the instance's entries go (a value an in-flight leader publishes afterwards lands in an
    /// entry nothing can reach). Its scrub set closes with its slot.
    pub fn drop_instance(&self, instance: u64) {
        let _grow = lock(&self.grow);
        let current = self.instances.load_full();
        if current.contains_key(&instance) {
            let mut next = (*current).clone();
            next.remove(&instance);
            self.instances.store(Arc::new(next));
        }
    }

    #[cfg(feature = "conformance")]
    pub fn set_probe(&self, probe: Option<Probe>) {
        self.probe.store(probe.map(Arc::new));
    }

    /// The hit path: loads and a clone of the published Arc; no lock, no allocation, no registration.
    fn hit(&self, key: CustodyKey) -> Option<Arc<SecureVec>> {
        let instances = self.instances.load();
        let handles = instances.get(&key.instance)?.map.load();
        let published = handles.get(&key.handle)?.published.load();
        let held = Option::as_ref(&published)?;
        if held.until.is_some_and(|until| self.host.now() >= until) {
            return None;
        }
        Some(Arc::clone(&held.value))
    }

    fn handles(&self, instance: u64) -> Arc<Handles> {
        if let Some(handles) = self.instances.load().get(&instance) {
            return Arc::clone(handles);
        }
        let _grow = lock(&self.grow);
        let current = self.instances.load_full();
        if let Some(handles) = current.get(&instance) {
            return Arc::clone(handles);
        }
        let handles = Arc::new(Handles {
            map: ArcSwap::from_pointee(HashMap::default()),
            grow: Mutex::new(()),
        });
        let mut next = (*current).clone();
        next.insert(instance, Arc::clone(&handles));
        self.instances.store(Arc::new(next));
        handles
    }

    fn entry(&self, key: CustodyKey) -> Arc<Entry> {
        let handles = self.handles(key.instance);
        if let Some(entry) = handles.map.load().get(&key.handle) {
            return Arc::clone(entry);
        }
        let _grow = lock(&handles.grow);
        let current = handles.map.load_full();
        if let Some(entry) = current.get(&key.handle) {
            return Arc::clone(entry);
        }
        let entry = Arc::new(Entry::default());
        let mut next = (*current).clone();
        next.insert(key.handle, Arc::clone(&entry));
        handles.map.store(Arc::new(next));
        entry
    }

    /// A per-instance miss: join the key's in-flight resolve, or lead a new one. An expired cell is replaced under
    /// the entry's lock (compare-and-replace on that cell only); a failed or dropped leader leaves the cell empty,
    /// so one waiter leads next and no failure is cached.
    async fn miss(
        &self,
        who: &Caller<'_>,
        key: CustodyKey,
    ) -> Result<Arc<SecureVec>, CustodyDenied> {
        let entry = self.entry(key);
        let cell = {
            let mut cell = lock(&entry.cell);
            if cell.get().is_some_and(|held| !held.fresh(self.host.now())) {
                *cell = Arc::new(tokio::sync::OnceCell::new());
            }
            Arc::clone(&*cell)
        };
        let held = cell.get_or_try_init(|| self.lead(who, key, &entry)).await?;
        Ok(Arc::clone(&held.value))
    }

    /// The leader of one miss, in the normative order: resolve; `register` returns; publish; bump `generation`.
    async fn lead(
        &self,
        who: &Caller<'_>,
        key: CustodyKey,
        entry: &Entry,
    ) -> Result<Arc<Held>, CustodyDenied> {
        let Some(binding) = self.host.binding(key) else {
            self.host
                .audit(who, key.handle, CustodyEvent::HandleForeign);
            return Err(CustodyDenied::ForeignHandle);
        };
        let stack = pushed(who.stack, who.instance).ok_or(CustodyDenied::Cycle)?;
        let scrub = self.host.scrub(who).ok_or(CustodyDenied::Unavailable)?;
        let cx = CallCx {
            deadline: who.deadline,
            request_id: who.chain,
            stack,
        };
        let resolved = self.resolved(cx, &binding).await?;
        let mut values: Vec<&[u8]> = Vec::with_capacity(1 + resolved.fills.len());
        values.push(resolved.value.as_slice());
        values.extend(resolved.fills.iter().map(|fill| fill.as_slice()));
        if values.iter().any(|value| value.len() < MIN_NEEDLE) {
            self.host
                .audit(who, key.handle, CustodyEvent::TooShortToScrub);
        }
        let held = Arc::new(Held {
            value: Arc::clone(&resolved.value),
            until: resolved.until,
        });
        #[cfg(feature = "conformance")]
        if let Some(probe) = self.probe.load_full() {
            if probe.publish_first {
                publish(entry, &held);
                (probe.park)(key).await;
                scrub.register(key.handle, &values);
                self.host.audit(who, key.handle, CustodyEvent::Resolved);
                return Ok(held);
            }
            (probe.park)(key).await;
        }
        scrub.register(key.handle, &values);
        publish(entry, &held);
        self.host.audit(who, key.handle, CustodyEvent::Resolved);
        Ok(held)
    }

    async fn resolved(&self, cx: CallCx, binding: &SecretRef) -> Result<Resolved, CustodyDenied> {
        match binding {
            SecretRef::None => Err(CustodyDenied::NotFound),
            SecretRef::Source(source) => {
                let held = self.fetch(cx, source).await?;
                Ok(Resolved {
                    value: held.value,
                    fills: Vec::new(),
                    until: held.until,
                })
            }
            SecretRef::Template(_) => self.render(cx, binding).await,
        }
    }

    /// Step 3 for one source reference: the cycle check, then the source-level cache, then the secret instance.
    /// The plugin sees the reference's `settings` only, never its `module` (I2).
    async fn fetch(&self, cx: CallCx, source: &SourceReference) -> Result<Held, CustodyDenied> {
        let target = self
            .host
            .source(&source.module)
            .ok_or(CustodyDenied::NoSuchSecretSource)?;
        if holds(&cx.stack, target.instance) {
            return Err(CustodyDenied::Cycle);
        }
        let encoded = source
            .settings
            .encode()
            .map_err(|_| CustodyDenied::Denied)?;
        let reference = encoded.expose(&crate::seal::lend());
        let module_len = u32::try_from(source.module.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes();
        let id = busbar_contract::crypto::sha256_parts(&[
            &module_len,
            source.module.as_bytes(),
            reference,
        ]);
        let now = self.host.now();
        let cached = lock(&self.sources)
            .get(&id)
            .filter(|held| held.fresh(now))
            .cloned();
        if let Some(held) = cached {
            return Ok(held);
        }
        let answer = target.port.resolve(cx, reference).await.map_err(denied)?;
        let until = answer
            .lease_s
            .and_then(|lease| self.host.now().checked_add(Duration::from_secs(lease)));
        let held = Held {
            value: Arc::new(answer.value),
            until,
        };
        if held.until.is_some() {
            lock(&self.sources).insert(id, held.clone());
        }
        Ok(held)
    }

    /// A template: its fills from one resolve each, in `resolve_template_typed`'s order (origin/dev
    /// secret_ref.rs), then the rendered text. The fills stay beside the rendered value until step 5 registers
    /// them all (round 17).
    async fn render(&self, cx: CallCx, template: &SecretRef) -> Result<Resolved, CustodyDenied> {
        let wanted = {
            let wanted = RefCell::new(Vec::new());
            let asked = |fill: &SecretRef| -> Result<Secret<String>, CustodyDenied> {
                if let Some(source) = fill.source() {
                    wanted.borrow_mut().push(source.clone());
                }
                Ok(Secret::new(String::new()))
            };
            template
                .resolve_template_typed(&asked)
                .map_err(template_refused)?;
            wanted.into_inner()
        };
        let mut fills = Vec::with_capacity(wanted.len());
        let mut until = None;
        for source in &wanted {
            let held = self.fetch(cx, source).await?;
            until = earliest(until, held.until);
            fills.push(held.value);
        }
        let rendered = {
            let next = Cell::new(0_usize);
            let filled = |_: &SecretRef| -> Result<Secret<String>, CustodyDenied> {
                let at = next.get();
                next.set(at + 1);
                let fill = fills.get(at).ok_or(CustodyDenied::Denied)?;
                let text =
                    core::str::from_utf8(fill.as_slice()).map_err(|_| CustodyDenied::Denied)?;
                Ok(Secret::new(String::from(text)))
            };
            template
                .resolve_template_typed(&filled)
                .map_err(template_refused)?
        };
        let text = rendered.into_exposed(&crate::seal::lend());
        Ok(Resolved {
            value: Arc::new(SecureString::from(text).into_bytes()),
            fills,
            until,
        })
    }
}

impl<H: CustodyHost> SecretCustody for Custody<H> {
    fn resolve(
        &self,
        who: &Caller<'_>,
        handle: u32,
    ) -> impl Future<Output = Result<Arc<SecureVec>, CustodyDenied>> + Send {
        let who = *who;
        async move {
            let key = CustodyKey {
                instance: who.instance,
                handle,
            };
            match self.hit(key) {
                Some(value) => Ok(value),
                None => self.miss(&who, key).await,
            }
        }
    }

    fn generation(&self, who: &Caller<'_>, handle: u32) -> u64 {
        let instances = self.instances.load();
        let Some(handles) = instances.get(&who.instance) else {
            return 0;
        };
        handles
            .map
            .load()
            .get(&handle)
            .map_or(0, |entry| entry.generation.load(Ordering::Relaxed))
    }

    fn resolve_ref<'a>(
        &'a self,
        cx: CallCx,
        r: &'a SecretRef,
    ) -> BoxFut<'a, Result<SecureVec, CustodyDenied>> {
        Box::pin(async move {
            let resolved = self.resolved(cx, r).await?;
            Ok(SecureVec::from(resolved.value.as_slice()))
        })
    }
}

/// Publish (a Release store the hit path reads with Acquire), then bump the generation.
fn publish(entry: &Entry, held: &Arc<Held>) {
    entry.published.store(Some(Arc::clone(held)));
    entry.generation.fetch_add(1, Ordering::Release);
}

/// `CallStack::push`: None at depth 4 (custody refuses Cycle).
fn pushed(stack: CallStack, instance: u64) -> Option<CallStack> {
    let depth = usize::from(stack.depth);
    if depth >= stack.ids.len() {
        return None;
    }
    let mut next = stack;
    next.ids[depth] = instance;
    next.depth += 1;
    Some(next)
}

/// `CallStack::contains` over the live depth.
fn holds(stack: &CallStack, instance: u64) -> bool {
    stack
        .ids
        .iter()
        .take(usize::from(stack.depth))
        .any(|id| *id == instance)
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Every refusal maps to a variant with no text (step 4): nothing names the source.
fn denied(error: PortError) -> CustodyDenied {
    match error {
        PortError::Refused { code, .. } if code == R_NOT_FOUND => CustodyDenied::NotFound,
        PortError::Refused { .. } => CustodyDenied::Denied,
        PortError::Failed { .. } | PortError::Call(_) => CustodyDenied::Unavailable,
    }
}

fn template_refused(refused: TemplateRefused<CustodyDenied>) -> CustodyDenied {
    match refused {
        TemplateRefused::Source(denied) => denied,
        TemplateRefused::TooLarge => CustodyDenied::Denied,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cred_tests;
