// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound-credential cache (IF §12.2 `CredentialCache`, rules 1-7): core's single-flight minting, refresh
//! ahead, mint-rate floor, failure window, per-instance cap and per-request credentials. The plugin mints once per
//! call and keeps nothing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::failed::{F_BUSY, F_TIMEOUT};
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_loader::ports::auth::OutboundAnswer;
use busbar_plugin_loader::ports::PortError;
use foldhash::HashMap;
use tokio::sync::watch;

use super::{CredKey, CredPolicy};
use crate::retry::Retry;

/// What `get` answers. `Ready` costs no box, no copy and no lock beyond the shard read (the hit path); `Wait` is a miss,
/// an expired value or a join of the key's in-flight mint (round 24: never a refresh-ahead, rule 2). Round 26:
/// `Direct` is rule 5 only: `mint()`'s own future, returned unchanged (no second box, no `Arc`), because a
/// per-request answer is never shared; the caller awaits it and uses the owned `OutboundAnswer` once. So a
/// per-request upstream call allocates exactly what the port's `AuthPort::outbound` allocates (its one BoxFut,
/// ABI-DECISION r4's one plugin-future allocation) and nothing in `get`.
pub enum CredGet<'a> {
    Ready(Result<Arc<OutboundAnswer>, PortError>),
    Wait(BoxFut<'a, Result<Arc<OutboundAnswer>, PortError>>),
    Direct(BoxFut<'a, Result<OutboundAnswer, PortError>>),
}

/// The one outbound-credential path (K2; K6 calls it from the §12.18 binding for every upstream exchange).
/// Not dyn (generic `mint`); consumers are generic over `C: CredentialCache`, like custody. Per `CredKey` entry:
/// the published value (Arc, `expires` = now + min(cache_s, `UpstreamAuth` `cache_max_s`, `max_hold_s`) (round 24), `fresh_until` =
/// expires − margin, margin = min(refresh_ahead_s, cache_s / 2)), one in-flight mint cell
/// (`tokio::sync::OnceCell::get_or_try_init` semantics, as custody step 5), the last mint start (mono) and the
/// failure window (`failed_until`, `streak`, the last `PortError::Failed`). Rules, normative:
/// 1. **Hit**: a value with now < `fresh_until` → `Ready(Ok(arc clone))`; no plugin call, no allocation.
/// 2. **Refresh-ahead** (round 24: no request waits on it): `fresh_until` ≤ now < `expires` → every caller,
///    the trigger included, gets `Ready(Ok(old value))`. The first one whose call finds no mint in flight, no
///    open window and `min_mint_interval_s` passed since the last start installs the key's single-flight cell and
///    starts the mint **detached** on core's runtime (`tokio::spawn` of `detach()` under `mint_deadline_s`; the
///    cell keeps its `AbortHandle`; no request owns it, so dropping the trigger does not cancel it). Success
///    publishes (rule 7); failure keeps the old value served and opens the window (rule 4). A caller that
///    arrives after `expires` while that mint is in flight joins it under rule 3. `evict_instance` aborts the
///    instance's detached mints. This is today's auth-oauth background refresh (mint/mod.rs:40-42,
///    REFRESH_SKEW_SECS ahead), now core's, started on demand rather than by a per-key scheduler.
/// 3. **Miss or expired** (no value, or now ≥ `expires`; an expired value is never served; the only rule that
///    answers `Wait`; rule 5 answers `Direct`): every caller gets `Wait` on the one in-flight mint, started now (after waiting out what remains of `min_mint_interval_s`,
///    at most that long). The leader's mint is `mint()` under its own deadline `mint_deadline_s`; if the leading
///    future is dropped, one waiter becomes the leader; every waiter returns the leader's result.
/// 4. **Failure window**: a mint that ends `PortError::Failed` or `Call(Deadline)` opens the window: `streak`
///    += 1, `failed_until` = now + d where `RetryPolicy::next(RetrySite::AuthOutbound, streak, &err)` (K3) is
///    `After(d)` (its schedule, §12.3: 30 s × 2^(streak − 1), max 300 s, never shorter than the error's
///    `retry_after_s` clamped to 300 s; today's EXCHANGE_BACKOFF_SECS/MAX_BACKOFF_SECS) and `Stop` = 300 s. Inside
///    the window a still-valid value is served (rule 2, no mint) and a caller with none gets `Ready(Err(the
///    stored Failed, retry_after_s = the window's remaining seconds))` without calling the plugin; core audits
///    `outbound_credential_backoff` once per window (core text, attributed by §12.20). A successful mint
///    resets `streak`. `Refused` is a verdict: never windowed, never cached, returned to the leader and its
///    waiters only (R_CONNECT_REQUIRED then deletes the grant, §12.12).
/// 5. **Per-request credentials** (round 24: a declared style property, never inferred from one answer): for a
///    binding with `UpstreamAuth.per_request` (its style declared STYLE_PER_REQUEST, §8.3) every call is
///    `Direct(mint())` (round 26: the port's future itself, never re-boxed or `Arc`-wrapped), unshared, with no cell, no entry and no window, and the answer's `cache_s` is ignored (a
///    signed header is bound to its own request). For every other binding an answer with `cache_s == 0` (an
///    issuer that stated `expires_in: 0`) is an **already-expired value**: it is returned to the leader and its
///    waiters (single-flight kept) and never published; the key's last mint start stays, so the next caller is
///    a rule-3 miss that waits out `min_mint_interval_s` (the rate floor) and joins one mint; a failed mint opens
///    the window (rule 4). Core audits `outbound_credential_no_lifetime` (core text, §12.20) once per key per
///    process. So such an issuer costs at most one token-endpoint FETCH per `min_mint_interval_s` per key, and
///    a down endpoint at most one per window, never one per request (today's MIN_SLEEP_SECS/MIN_MINT_INTERVAL_SECS
///    behaviour, mint/mod.rs:67-71, :259-272, now core's).
/// 6. **Cap**: at `max_keys_per_instance` keys for the instance, inserting a key drops expired entries, then the
///    least recently used entry with no mint in flight; if every entry is minting, the call is `Ready(Err(
///    PortError::Failed { code: F_BUSY, text: core's "outbound credential cache full for this binding", .. }))`
///    (today's SCOPES_BUSY, now core's).
/// 7. A published value is replaced only by a successful mint (compare-and-replace under the shard lock, as
///    custody step 5); its `grant_update`, if any, is stored by K10 before the value is published (§12.12).
pub trait CredentialCache: Send + Sync + 'static {
    /// `now` is the caller's mono instant; `mint` makes exactly one `AuthPort::outbound` call (with
    /// FACT(F_MIN_VALID_S) = `policy.refresh_ahead_s`) and is called at most once per started mint.
    /// `per_request` = `UpstreamAuth.per_request` (rule 5). Round 25: `mint` borrows the caller's `UpstreamIn<'a>`
    /// (no copy) and serves rules 3 and 5 only. `detach` builds the owned future (an `Arc` of the port and an owned
    /// `UpstreamIn`) and is called only by rule 2, synchronously inside `get`, at most once per call, and only when
    /// this call starts the detached refresh-ahead mint; so rule 1, a rule-2 caller that starts nothing, rule 3 and
    /// rule 5 copy nothing and allocate nothing for it. Neither is called on a hit or inside an open window. Round 26:
    /// with `per_request` true, `get` touches no shard, cell or clock and returns `Direct(mint())`.
    fn get<'a, M>(
        &'a self,
        key: CredKey,
        per_request: bool,
        now: Instant,
        mint: M,
        detach: &dyn Fn() -> BoxFut<'static, Result<OutboundAnswer, PortError>>,
    ) -> CredGet<'a>
    where
        M: Fn() -> BoxFut<'a, Result<OutboundAnswer, PortError>> + Send + Sync + 'a;
    fn evict_instance(&self, auth_instance: u64);
    fn evict_caller(&self, caller: [u8; 32], upstream: u64);
}

/// The rows the cache writes (rules 4 and 5), attributed by the caller's audit sink (§12.20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredEvent {
    /// `outbound_credential_backoff`: a failed mint opened the key's window (once per window).
    Backoff,
    /// `outbound_credential_no_lifetime`: the issuer stated no lifetime (`cache_s` 0); once per key per process.
    NoLifetime,
}

const SHARDS: usize = 16;
/// Rule 4: a `Stop` from the retry policy is a 300 s window.
const STOP_WINDOW: Duration = Duration::from_secs(300);
const BUSY: &str = "outbound credential cache full for this binding";
const MINT_TIMED_OUT: &str = "outbound credential mint timed out";

type Shared = Result<Arc<OutboundAnswer>, PortError>;
type Window = dyn Fn(u32, &PortError) -> Retry + Send + Sync;
type Audit = dyn Fn(CredKey, CredEvent) + Send + Sync;

/// Core's credential cache: 16 shards by auth instance, each a `RwLock` (read lock on the hit path only).
pub struct CredCache {
    inner: Arc<Inner>,
}

struct Inner {
    policy: CredPolicy,
    /// The failure window per streak: the wiring passes `RetryPolicy::next(RetrySite::AuthOutbound, ..)` (K3).
    window: Box<Window>,
    audit: Box<Audit>,
    shards: [RwLock<HashMap<CredKey, Entry>>; SHARDS],
    /// The origin of `Entry::used` (LRU order, rule 6).
    base: Instant,
}

struct Entry {
    held: Option<Held>,
    flight: Option<Arc<Flight>>,
    last_start: Option<Instant>,
    failed_until: Option<Instant>,
    streak: u32,
    failure: Option<PortError>,
    /// Nanoseconds since `Inner::base` of the last use: a Relaxed store on the hit path, never an RMW.
    used: AtomicU64,
    told_no_lifetime: bool,
}

struct Held {
    answer: Arc<OutboundAnswer>,
    fresh_until: Instant,
    expires: Instant,
}

/// One in-flight mint. The leader holds a `Lead`; dropping it unfinished hands the mint to the next waiter.
struct Flight {
    state: watch::Sender<State>,
    abort: Mutex<Option<tokio::task::AbortHandle>>,
}

enum State {
    Running,
    Vacant,
    Done(Shared),
}

struct Lead {
    flight: Arc<Flight>,
    finished: bool,
}

enum Joined {
    Done(Shared),
    Lead(Lead),
}

enum Step {
    Hit(Arc<OutboundAnswer>),
    /// Rule 2: the old value, and whether this call starts the detached refresh.
    Stale(Arc<OutboundAnswer>, bool),
    Windowed(PortError),
    Miss,
}

impl CredCache {
    /// `window` is the failure window for a streak (`RetryPolicy::next(RetrySite::AuthOutbound, streak, err)`,
    /// K3); `audit` writes the rows of rules 4 and 5.
    pub fn new(
        policy: CredPolicy,
        window: impl Fn(u32, &PortError) -> Retry + Send + Sync + 'static,
        audit: impl Fn(CredKey, CredEvent) + Send + Sync + 'static,
    ) -> Self {
        CredCache {
            inner: Arc::new(Inner {
                policy,
                window: Box::new(window),
                audit: Box::new(audit),
                shards: std::array::from_fn(|_| RwLock::new(HashMap::default())),
                base: clock(),
            }),
        }
    }

    /// The policy (K6 and K8 copy `refresh_ahead_s` into `UpstreamIn.min_valid_s`, §11.3 round 35).
    pub fn policy(&self) -> CredPolicy {
        self.inner.policy
    }

    fn wait<'a, M>(
        &'a self,
        key: CredKey,
        flight: Arc<Flight>,
        lead: Option<Lead>,
        mint: M,
    ) -> BoxFut<'a, Shared>
    where
        M: Fn() -> BoxFut<'a, Result<OutboundAnswer, PortError>> + Send + Sync + 'a,
    {
        let inner = &*self.inner;
        Box::pin(async move {
            let mut lead = lead;
            loop {
                if let Some(lead) = lead.take() {
                    return inner.mint(key, lead, &mint).await;
                }
                match join(&flight).await {
                    Joined::Done(shared) => return shared,
                    Joined::Lead(next) => lead = Some(next),
                }
            }
        })
    }

    /// Rule 2: install the key's cell and start `detach()` on core's runtime. No runtime: nothing starts and the
    /// old value keeps being served until it expires.
    fn detached(
        &self,
        entry: &mut Entry,
        key: CredKey,
        now: Instant,
        detach: &dyn Fn() -> BoxFut<'static, Result<OutboundAnswer, PortError>>,
    ) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let flight = Flight::new();
        let lead = Lead::new(Arc::clone(&flight));
        entry.flight = Some(Arc::clone(&flight));
        entry.last_start = Some(now);
        let minting = detach();
        let inner = Arc::clone(&self.inner);
        let deadline = secs(inner.policy.mint_deadline_s);
        let task = runtime.spawn(async move {
            let answer = tokio::time::timeout(deadline, minting)
                .await
                .unwrap_or(Err(PortError::Call(CallError::Deadline)));
            let shared = inner.settle(key, &lead.flight, answer);
            lead.finish(&shared);
        });
        *lock(&flight.abort) = Some(task.abort_handle());
    }
}

impl CredentialCache for CredCache {
    fn get<'a, M>(
        &'a self,
        key: CredKey,
        per_request: bool,
        now: Instant,
        mint: M,
        detach: &dyn Fn() -> BoxFut<'static, Result<OutboundAnswer, PortError>>,
    ) -> CredGet<'a>
    where
        M: Fn() -> BoxFut<'a, Result<OutboundAnswer, PortError>> + Send + Sync + 'a,
    {
        let _ = (key, per_request, now, &mint, detach);
        todo!("W1-K2: credential cache")
    }

    fn evict_instance(&self, auth_instance: u64) {
        let mut map = self.inner.write(auth_instance);
        map.retain(|key, entry| {
            let keep = key.auth_instance != auth_instance;
            if !keep {
                entry.abort();
            }
            keep
        });
    }

    fn evict_caller(&self, caller: [u8; 32], upstream: u64) {
        for shard in &self.inner.shards {
            let mut map = shard.write().unwrap_or_else(PoisonError::into_inner);
            map.retain(|key, entry| {
                let keep = key.caller != caller || key.upstream != upstream;
                if !keep {
                    entry.abort();
                }
                keep
            });
        }
    }
}

impl Inner {
    fn shard(&self, auth_instance: u64) -> &RwLock<HashMap<CredKey, Entry>> {
        let at = usize::try_from(auth_instance % SHARDS as u64).unwrap_or(0);
        &self.shards[at]
    }

    fn read(&self, auth_instance: u64) -> RwLockReadGuard<'_, HashMap<CredKey, Entry>> {
        self.shard(auth_instance)
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, auth_instance: u64) -> RwLockWriteGuard<'_, HashMap<CredKey, Entry>> {
        self.shard(auth_instance)
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn nanos(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.base).as_nanos()).unwrap_or(u64::MAX)
    }

    /// The leader's mint (rule 3): wait out the rate floor, record the start, call `mint` once under its deadline,
    /// settle and hand the result to every waiter.
    async fn mint<'a, M>(&self, key: CredKey, lead: Lead, mint: &M) -> Shared
    where
        M: Fn() -> BoxFut<'a, Result<OutboundAnswer, PortError>> + Send + Sync + 'a,
    {
        let last_start = self
            .read(key.auth_instance)
            .get(&key)
            .and_then(|entry| entry.last_start);
        let floor = last_start.map_or(Duration::ZERO, |start| {
            (start + secs(self.policy.min_mint_interval_s)).saturating_duration_since(clock())
        });
        if !floor.is_zero() {
            tokio::time::sleep(floor).await;
        }
        {
            let mut map = self.write(key.auth_instance);
            if let Some(entry) = map
                .get_mut(&key)
                .filter(|entry| entry.minting(&lead.flight))
            {
                entry.last_start = Some(clock());
            }
        }
        let answer = tokio::time::timeout(secs(self.policy.mint_deadline_s), mint())
            .await
            .unwrap_or(Err(PortError::Call(CallError::Deadline)));
        let shared = self.settle(key, &lead.flight, answer);
        lead.finish(&shared);
        shared
    }

    /// Ends one mint: publish (rule 7: only a success with a lifetime, only into the entry whose cell this mint
    /// is), open the window (rule 4) or return a verdict unwindowed; then audit outside the lock.
    fn settle(
        &self,
        key: CredKey,
        flight: &Arc<Flight>,
        answer: Result<OutboundAnswer, PortError>,
    ) -> Shared {
        let now = clock();
        let shared = answer.map(Arc::new);
        let mut told = None;
        {
            let mut map = self.write(key.auth_instance);
            if let Some(entry) = map.get_mut(&key).filter(|entry| entry.minting(flight)) {
                entry.flight = None;
                match &shared {
                    Ok(answer) => {
                        entry.streak = 0;
                        entry.failed_until = None;
                        entry.failure = None;
                        if answer.cache_s > 0 {
                            let life = answer.cache_s.min(self.policy.max_hold_s);
                            let margin = self.policy.refresh_ahead_s.min(life / 2);
                            let expires = now + secs(life);
                            entry.held = Some(Held {
                                answer: Arc::clone(answer),
                                fresh_until: expires - secs(margin),
                                expires,
                            });
                        } else if !entry.told_no_lifetime {
                            entry.told_no_lifetime = true;
                            told = Some(CredEvent::NoLifetime);
                        }
                    }
                    Err(
                        error @ (PortError::Failed { .. } | PortError::Call(CallError::Deadline)),
                    ) => {
                        entry.streak = entry.streak.saturating_add(1);
                        let window = match (self.window)(entry.streak, error) {
                            Retry::After(window) => window,
                            Retry::Stop => STOP_WINDOW,
                        };
                        entry.failed_until = Some(now + window);
                        entry.failure = Some(error.clone());
                        told = Some(CredEvent::Backoff);
                    }
                    Err(_) => {}
                }
            }
        }
        if let Some(event) = told {
            (self.audit)(key, event);
        }
        shared
    }
}

impl Entry {
    fn new(used: u64) -> Self {
        Entry {
            held: None,
            flight: None,
            last_start: None,
            failed_until: None,
            streak: 0,
            failure: None,
            used: AtomicU64::new(used),
            told_no_lifetime: false,
        }
    }

    fn minting(&self, flight: &Arc<Flight>) -> bool {
        self.flight
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, flight))
    }

    fn abort(&self) {
        if let Some(flight) = &self.flight {
            if let Some(task) = lock(&flight.abort).as_ref() {
                task.abort();
            }
        }
    }

    fn valid(&self, now: Instant) -> bool {
        self.held.as_ref().is_some_and(|held| now < held.expires)
    }
}

impl Flight {
    fn new() -> Arc<Self> {
        Arc::new(Flight {
            state: watch::Sender::new(State::Running),
            abort: Mutex::new(None),
        })
    }
}

impl Lead {
    fn new(flight: Arc<Flight>) -> Self {
        Lead {
            flight,
            finished: false,
        }
    }

    fn finish(mut self, shared: &Shared) {
        self.finished = true;
        self.flight.state.send_replace(State::Done(shared.clone()));
    }
}

impl Drop for Lead {
    /// A leader dropped mid-mint (its request cancelled, or its detached task aborted): the next waiter leads.
    fn drop(&mut self) {
        if !self.finished {
            self.flight.state.send_replace(State::Vacant);
        }
    }
}

/// Wait on a flight: its result, or the lead when the leader was dropped.
async fn join(flight: &Arc<Flight>) -> Joined {
    let mut state = flight.state.subscribe();
    loop {
        let vacant = match &*state.borrow_and_update() {
            State::Done(shared) => return Joined::Done(shared.clone()),
            State::Running => false,
            State::Vacant => true,
        };
        if vacant
            && flight.state.send_if_modified(|state| {
                let take = matches!(state, State::Vacant);
                if take {
                    *state = State::Running;
                }
                take
            })
        {
            return Joined::Lead(Lead::new(Arc::clone(flight)));
        }
        if state.changed().await.is_err() {
            return Joined::Done(Err(PortError::Call(CallError::Cancelled)));
        }
    }
}

fn step(entry: &Entry, now: Instant, policy: &CredPolicy) -> Step {
    let open = entry.failed_until.is_some_and(|until| now < until);
    if let Some(held) = &entry.held {
        if now < held.fresh_until {
            return Step::Hit(Arc::clone(&held.answer));
        }
        if now < held.expires {
            let floor = entry
                .last_start
                .is_some_and(|start| now < start + secs(policy.min_mint_interval_s));
            let start = entry.flight.is_none() && !open && !floor;
            return Step::Stale(Arc::clone(&held.answer), start);
        }
    }
    match entry.failed_until.filter(|_| open) {
        Some(until) => Step::Windowed(windowed(entry.failure.as_ref(), until - now)),
        None => Step::Miss,
    }
}

/// Rule 4: the stored failure, with the window's remaining whole seconds (rounded up) as its Retry-After.
fn windowed(failure: Option<&PortError>, left: Duration) -> PortError {
    let left_s = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    match failure {
        Some(PortError::Failed {
            code,
            text,
            backend_status,
            error,
            ..
        }) => PortError::Failed {
            code: *code,
            text: text.clone(),
            retry_after_s: Some(left_s),
            backend_status: *backend_status,
            error: *error,
        },
        _ => PortError::Failed {
            code: F_TIMEOUT,
            text: Box::from(MINT_TIMED_OUT),
            retry_after_s: Some(left_s),
            backend_status: None,
            error: None,
        },
    }
}

/// Rule 6: room for one more key of `auth_instance`. Drops that instance's expired idle entries first, then its
/// least recently used entry with no mint in flight; false when every entry is minting.
fn room(
    map: &mut HashMap<CredKey, Entry>,
    auth_instance: u64,
    now: Instant,
    policy: &CredPolicy,
) -> bool {
    let cap = usize::try_from(policy.max_keys_per_instance).unwrap_or(usize::MAX);
    let held = |map: &HashMap<CredKey, Entry>| {
        map.keys()
            .filter(|key| key.auth_instance == auth_instance)
            .count()
    };
    if held(map) < cap {
        return true;
    }
    map.retain(|key, entry| {
        key.auth_instance != auth_instance
            || entry.flight.is_some()
            || entry.valid(now)
            || entry.failed_until.is_some_and(|until| now < until)
    });
    if held(map) < cap {
        return true;
    }
    let lru = map
        .iter()
        .filter(|(key, entry)| key.auth_instance == auth_instance && entry.flight.is_none())
        .min_by_key(|(_, entry)| entry.used.load(Ordering::Relaxed))
        .map(|(key, _)| *key);
    match lru {
        Some(key) => {
            map.remove(&key);
            true
        }
        None => false,
    }
}

fn busy() -> PortError {
    PortError::Failed {
        code: F_BUSY,
        text: Box::from(BUSY),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

fn secs(s: u32) -> Duration {
    Duration::from_secs(u64::from(s))
}

/// The cache's own clock reads (the leader's start and settle). Tokio's, so a paused test runtime drives it.
fn clock() -> Instant {
    tokio::time::Instant::now().into_std()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
