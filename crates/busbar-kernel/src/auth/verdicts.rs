// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verdict cache: core's one per-instance verify cache with single-flight leads (IF §12.28). Built from
//! `host_verify.rs`'s `VerifyBook` (its `room`, `Slot`, `fresh`, `idle`, `lead_until`/`LEAD_MS`, `MAX_FOLLOWERS`
//! and `expire`), re-keyed by auth instance id and credential hash, holding the adapter's `Identity`, sharded 16
//! ways by instance (a read lock on the hit path), with `oneshot` followers and per-instance flush epochs.
//! Standing leads live in their own bounded table, sharded by credential hash, so a lookup in flight never takes
//! room from a cached identity (#359 SEC-L12, DES-359 r3).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::chain_run::Verdict;
use busbar_plugin_abi::auth::{FB_NEEDS_BODY, FB_NEEDS_BODY_HASH};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::Identity;
use busbar_ports::PortError;
use foldhash::HashMap;
use tokio::sync::oneshot;

/// How long one lead stands before the `expire` sweep passes it on (VerifyBook's, kept).
pub const LEAD_MS: u64 = 30_000;
/// The most callers that wait on one lead; one more verifies unshared (`Bypass`, never refused).
pub const MAX_FOLLOWERS: usize = 1024;
pub(crate) const LEAD_S: u64 = LEAD_MS / 1_000;
const SHARDS: usize = 16;
/// The most slots one eviction looks at (rule 5): with every one recently referenced, the fill is declined.
pub const SWEEP_STEPS: usize = 16;
/// The most standing leads, every instance's, across the lead table's shards; a full shard answers `Bypass`.
pub const MAX_LEADS: usize = 4_096;
const LEADS_PER_SHARD: usize = MAX_LEADS / SHARDS;

/// The credential a verify read, by hash only (the credential itself is never stored). `credential` = SHA-256
/// (through the facade) over, for each of the instance's D_CRED_HEADER names in declared order, the u32 LE name
/// length, the name, the u32 LE count of that header's values on the request and each value with its u32 LE length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerdictKey {
    pub auth_instance: u64,
    pub policy_epoch: u64,
    pub credential: CredentialHash,
}

/// The SHA-256 a `VerdictKey` carries (IF `[u8; 32]`). Its own type so no `Debug` of a key prints it: the hash of
/// a low-entropy credential (a password behind basic auth) is guessable offline, so it is handled as secret
/// material everywhere but the map that compares it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialHash(pub [u8; 32]);

impl core::fmt::Debug for CredentialHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CredentialHash(..)")
    }
}

/// Config `auth.verdict_cache.*`, core vocabulary: `default_ttl_s` (300 = auth-oidc's DEFAULT_TTL_SECS; replaces
/// VerifyBook's DEFAULT_TTL_MS), `max_ttl_s` (3600 = MAX_TTL_SECS, 1..=86_400), `max_entries` per auth instance
/// (4096 = VerifyBook's MAX_KEYS and auth-oidc's MAX_ENTRIES, 0 = off), `max_identity_bytes` (8192 =
/// MAX_PRINCIPAL_BYTES; a bigger identity is verified afresh every time; replaces VerifyBook's MAX_ENTRY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerdictPolicy {
    pub default_ttl_s: u32,
    pub max_ttl_s: u32,
    pub max_entries: u32,
    pub max_identity_bytes: u32,
}

impl VerdictPolicy {
    /// The defaults the IF states.
    pub const DEFAULT: VerdictPolicy = VerdictPolicy {
        default_ttl_s: 300,
        max_ttl_s: 3_600,
        max_entries: 4_096,
        max_identity_bytes: 8_192,
    };

    /// The config loader's range check for `auth.verdict_cache.*` (K7 reads the keys and calls this).
    pub fn checked(self) -> Result<Self, &'static str> {
        if !(1..=86_400).contains(&self.max_ttl_s) {
            return Err("auth.verdict_cache.max_ttl_s must be 1..=86400");
        }
        Ok(self)
    }
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a lead settles with and what its followers receive: the auth port's verify outcome (§11.3).
pub type Outcome = Result<Verdict, PortError>;

/// A fill rule: the value to cache and its lifetime in seconds, when an outcome may fill (rules 2, 3). The cache
/// holds one; production's is [`fill`], and the tests drive the same machinery with their own.
pub type Fill<V, O> = fn(&O, u64, &VerdictPolicy) -> Option<(V, u64)>;

/// Rules 2 and 3 on the value itself: only `Verdict::Identity`; a REPLAY answer and an identity over
/// `max_identity_bytes` never fill. An ISSUED_WANTED identity reaches here with `cache_s` = Some(0) (the adapter's
/// mark, §12.8), so rule 3 drops it.
pub fn fill(outcome: &Outcome, now_s: u64, policy: &VerdictPolicy) -> Option<(Identity, u64)> {
    let Ok(Verdict::Identity(identity)) = outcome else {
        return None;
    };
    let size = usize::try_from(policy.max_identity_bytes).unwrap_or(usize::MAX);
    if identity.replay().is_some() || identity.identity_records().len() > size {
        return None;
    }
    let ttl = ttl(identity.cache_s(), identity.expires_at_s(), now_s, policy)?;
    Some((identity.clone(), ttl))
}

/// Rule 3: min(F_CACHE_S if stated else `default_ttl_s`, F_EXPIRES_AT_S − now_s if stated, `max_ttl_s`); None
/// (never cached) for a stated or default 0 and for an expiry at or before now.
pub fn ttl(
    cache_s: Option<u32>,
    expires_at_s: Option<u64>,
    now_s: u64,
    policy: &VerdictPolicy,
) -> Option<u64> {
    let stated = u64::from(cache_s.unwrap_or(policy.default_ttl_s));
    if stated == 0 {
        return None;
    }
    let mut ttl = stated.min(u64::from(policy.max_ttl_s));
    if let Some(at) = expires_at_s {
        let left = at.checked_sub(now_s).filter(|left| *left > 0)?;
        ttl = ttl.min(left);
    }
    Some(ttl)
}

/// Rule 1: an instance whose image declares at least one D_CRED_HEADER and neither FB_NEEDS_BODY nor
/// FB_NEEDS_BODY_HASH. The auth chain asks this once per instance from the port (`cred_headers().len()`,
/// `facts()`) and treats every other instance as `Bypass` without calling `begin` (so without a lock).
pub fn eligible(cred_headers: usize, facts: u64) -> bool {
    cred_headers > 0 && facts & (FB_NEEDS_BODY | FB_NEEDS_BODY_HASH) == 0
}

/// What `begin` answers (VerifyBook's VERIFY_HIT / VERIFY_LEAD / VERIFY_FOLLOW, plus the bypass that replaces its
/// CACHE_FULL and TOO_MANY_FOLLOWERS refusals: a full cache is never the client's fault, so it never refuses).
pub enum VerdictGet<'a, V = Identity, O = Outcome> {
    /// A fresh entry: answer this identity without calling the plugin (one Arc clone, no allocation).
    Hit(V),
    /// This caller verifies and must end the lead with `VerdictLead::settle`.
    Lead(VerdictLead<'a, V, O>),
    /// A lead stands for this key: await it. `Ok` = the leader's outcome (shared, never re-verified); `Err` = the
    /// lead passed to this caller (the leader was dropped unsettled, or `LEAD_MS` lapsed), which now verifies.
    Follow(BoxFut<'a, Result<O, VerdictLead<'a, V, O>>>),
    /// Ineligible instance (rule 1), cache off, a full lead-table shard, or `MAX_FOLLOWERS` reached: verify
    /// unshared and do not fill.
    Bypass,
}

/// One standing lead held by its caller. Holds the cache, the key and the instance's flush epoch read in `begin`
/// (rule 6).
pub struct VerdictLead<'a, V = Identity, O = Outcome> {
    cache: &'a Verdicts<V, O>,
    key: VerdictKey,
    epoch: u64,
    settled: bool,
}

impl<V: Clone + Send + Sync + 'static, O: Clone + Send + Sync + 'static> VerdictLead<'_, V, O> {
    /// Ends the lead with the leader's outcome: fills only for an eligible answer (rules 2, 3; discarded if the
    /// epoch moved) and hands `outcome` (cloned) to every follower, whatever it is (an identity, NotMine, Rejected
    /// or a `PortError`): followers carry the same credential bytes to the same instance at the same moment.
    pub fn settle(mut self, outcome: &O, now_s: u64) {
        self.settled = true;
        let followers = self
            .cache
            .leads(&self.key)
            .remove(&self.key)
            .map(|lead| lead.followers)
            .unwrap_or_default();
        if let Some((value, ttl)) = (self.cache.fill)(outcome, now_s, &self.cache.policy) {
            self.cache.store(
                self.key,
                self.epoch,
                value,
                now_s,
                now_s.saturating_add(ttl),
            );
        }
        for follower in followers {
            // A follower that gave up has dropped its receiver; nothing to tell it.
            let _ = follower.send(Handoff::Outcome(outcome.clone()));
        }
    }
}

/// Dropped unsettled (the leading request was cancelled): the lead passes at once to the first follower, which
/// gets `Err(lead)` (VerifyBook's `expire` hand-off, done on drop instead of after LEAD_MS).
impl<V, O> Drop for VerdictLead<'_, V, O> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let mut leads = self.cache.leads(&self.key);
        if leads.get_mut(&self.key).map(hand) == Some(false) {
            leads.remove(&self.key);
        }
    }
}

/// Rules, normative:
/// 1. **Eligible instances**: an instance whose image declares ≥ 1 D_CRED_HEADER and neither FB_NEEDS_BODY nor
///    FB_NEEDS_BODY_HASH (a body-bound or per-request signature is never a reusable credential). Others get
///    `Bypass` with no lock taken.
/// 2. **Eligible answers**: only `Verdict::Identity` from `verify`/`verify_io` with no REPLAY, not reached through
///    ISSUED_WANTED (an issued credential's revocation is immediate, §12.8), with `F_CACHE_S` ≠ 0 (0 = never) and
///    `identity_records().len()` ≤ `max_identity_bytes`. NotMine, Rejected, KEYS_STALE and every `PortError`
///    are never cached (they are shared with the lead's followers only, rule 4).
/// 3. **TTL** = min(F_CACHE_S if stated else `default_ttl_s`, F_EXPIRES_AT_S − now_s if stated (≤ 0: not
///    cached), `max_ttl_s`). The plugin states facts (its token's expiry, a suggested lifetime); core picks the TTL.
/// 4. **Lookup and single-flight** (K8, before `AuthPort::verify` for each eligible instance in the route's
///    effective chain, in chain order): `begin` answers `Hit` for a fresh entry (the instance's read lock only;
///    the hit marks the entry referenced with one atomic store). Otherwise, under the lead table's shard lock
///    (sharded by credential hash, keyed by auth instance, policy epoch and credential), `Follow` if a lead stands
///    for the key (now < its lapse), else `Lead` lapsing at now + `LEAD_MS`, or `Bypass` when the shard holds
///    `MAX_LEADS` / 16 leads. So a burst of N requests carrying the same cold credential makes one plugin verify
///    and, for `verify_io`, one set of upstream Needs, not N; the other N − 1 return the leader's outcome. A lead
///    that lapses (`LEAD_MS`, a hung leader past its own deadline) passes to the first follower by the kept
///    `expire` sweep, which K2 runs on the watchdog tick.
/// 5. **Capacity** (amended by DES-359 r3, #359 SEC-L12): leads take no room from cached identities; only a
///    positive fill stores, and only a positive fill evicts. At `max_entries` keys for an instance, the fill takes
///    the first slot, from where the last sweep stopped, that is stale or not referenced since the sweep last
///    passed it, clearing the reference of each referenced slot it passes. It looks at no more than
///    `SWEEP_STEPS` slots; with every one referenced it does not fill. The former soonest-expiry rule is replaced.
/// 6. **Flush**: every entry of an instance is dropped when its `refresh` completes OK (scheduled or after
///    KEYS_STALE), when a verify answers KEYS_STALE, on reconfigure (a new instance id starts empty) and on close.
///    Each instance has a flush epoch (one Relaxed counter); a lead carries the epoch read in `begin`, and its
///    fill is discarded if the epoch moved, so a verdict reached before a flush never outlives it (its followers
///    still get the outcome: they asked before the flush, like the leader). A flush keeps standing leads.
pub trait VerdictCache: Send + Sync + 'static {
    fn begin<'a>(&'a self, key: VerdictKey, now_s: u64) -> VerdictGet<'a>;
    fn epoch(&self, auth_instance: u64) -> u64;
    fn flush_instance(&self, auth_instance: u64);
}

/// One cached identity of one instance (rule 5's ring slot).
pub(crate) struct Cached<V> {
    /// The (policy epoch, credential hash) it answers for.
    pub(crate) key: (u64, [u8; 32]),
    pub(crate) value: V,
    /// When it goes stale (seconds, the caller's `now_s` clock).
    pub(crate) until: u64,
    /// Set by a hit (read lock, one atomic store); cleared by an eviction sweep passing it.
    pub(crate) referenced: AtomicBool,
}

/// One standing lead in the lead table (VerifyBook's `lead_until` and followers).
pub(crate) struct Lead<O> {
    /// When the lead lapses.
    pub(crate) until: u64,
    /// The callers waiting on the lead, in arrival order.
    pub(crate) followers: VecDeque<oneshot::Sender<Handoff<O>>>,
}

pub(crate) enum Handoff<O> {
    Outcome(O),
    Lead,
}

/// One instance's cached identities and its flush epoch (rules 5, 6): a ring the sweep walks, an index into it,
/// and the position where the last sweep stopped.
pub(crate) struct Keys<V> {
    pub(crate) epoch: AtomicU64,
    pub(crate) index: HashMap<(u64, [u8; 32]), usize>,
    pub(crate) ring: Vec<Cached<V>>,
    pub(crate) hand: usize,
}

impl<V> Default for Keys<V> {
    fn default() -> Self {
        Keys {
            epoch: AtomicU64::new(0),
            index: HashMap::default(),
            ring: Vec::new(),
            hand: 0,
        }
    }
}

impl<V> Keys<V> {
    /// Rebuild the index after the ring changed shape (the off-path sweeps).
    pub(crate) fn reindex(&mut self) {
        self.index = self
            .ring
            .iter()
            .enumerate()
            .map(|(at, cached)| (cached.key, at))
            .collect();
        if self.hand >= self.ring.len() {
            self.hand = 0;
        }
    }
}

type LeadShard<O> = Mutex<HashMap<VerdictKey, Lead<O>>>;

/// The verdict cache, every auth instance's: 16 shards by instance id, each a `RwLock`, and the lead table, 16
/// shards by credential hash, each a `Mutex`. Lock order: a lead shard may be held while an instance shard is
/// read; never the reverse.
pub struct Verdicts<V = Identity, O = Outcome> {
    policy: VerdictPolicy,
    fill: Fill<V, O>,
    pub(crate) shards: [RwLock<HashMap<u64, Keys<V>>>; SHARDS],
    pub(crate) lead_shards: [LeadShard<O>; SHARDS],
}

impl Verdicts {
    pub fn new(policy: VerdictPolicy) -> Self {
        Self::with_fill(policy, fill)
    }
}

impl<V, O> Verdicts<V, O> {
    /// The same cache over another fill rule (the tests' stand-in values).
    pub fn with_fill(policy: VerdictPolicy, fill: Fill<V, O>) -> Self {
        Verdicts {
            policy,
            fill,
            shards: std::array::from_fn(|_| RwLock::new(HashMap::default())),
            lead_shards: std::array::from_fn(|_| Mutex::new(HashMap::default())),
        }
    }

    fn shard(&self, auth_instance: u64) -> &RwLock<HashMap<u64, Keys<V>>> {
        let at = usize::try_from(auth_instance % SHARDS as u64).unwrap_or(0);
        &self.shards[at]
    }

    fn read(&self, auth_instance: u64) -> RwLockReadGuard<'_, HashMap<u64, Keys<V>>> {
        self.shard(auth_instance)
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn write(&self, auth_instance: u64) -> RwLockWriteGuard<'_, HashMap<u64, Keys<V>>> {
        self.shard(auth_instance)
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The lead-table shard of `key`: by credential hash (SHA-256, so its first byte is uniform).
    pub(crate) fn leads(&self, key: &VerdictKey) -> MutexGuard<'_, HashMap<VerdictKey, Lead<O>>> {
        self.lead_shards[usize::from(key.credential.0[0]) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn max_entries(&self) -> usize {
        usize::try_from(self.policy.max_entries).unwrap_or(usize::MAX)
    }
}

impl<V: Clone + Send + Sync + 'static, O: Clone + Send + Sync + 'static> Verdicts<V, O> {
    /// Rule 4 (`VerdictCache::begin`): `Hit` under the instance's read lock; otherwise, under the lead shard's
    /// lock, `Follow` a standing lead or take a new one. A lead never takes room from a cached identity (rule 5).
    pub fn start(&self, key: VerdictKey, now_s: u64) -> VerdictGet<'_, V, O> {
        if self.max_entries() == 0 {
            return VerdictGet::Bypass;
        }
        if let Some(value) = self.cached(&key, now_s) {
            return VerdictGet::Hit(value);
        }
        let epoch = self.instance_epoch(key.auth_instance);
        let mut leads = self.leads(&key);
        let full = leads.len() >= LEADS_PER_SHARD;
        // A lead may have settled and filled between the miss and this lock.
        if let Some(value) = self.cached(&key, now_s) {
            return VerdictGet::Hit(value);
        }
        match leads.get_mut(&key) {
            Some(lead) if now_s < lead.until => {
                if lead.followers.len() >= MAX_FOLLOWERS {
                    return VerdictGet::Bypass;
                }
                let (tell, told) = oneshot::channel();
                lead.followers.push_back(tell);
                drop(leads);
                VerdictGet::Follow(Box::pin(async move {
                    match told.await {
                        Ok(Handoff::Outcome(outcome)) => Ok(outcome),
                        Ok(Handoff::Lead) | Err(_) => Err(self.lead(key, epoch)),
                    }
                }))
            }
            Some(lead) => {
                lead.until = now_s.saturating_add(LEAD_S);
                VerdictGet::Lead(self.lead(key, epoch))
            }
            None if full => VerdictGet::Bypass,
            None => {
                leads.insert(
                    key,
                    Lead {
                        until: now_s.saturating_add(LEAD_S),
                        followers: VecDeque::new(),
                    },
                );
                VerdictGet::Lead(self.lead(key, epoch))
            }
        }
    }

    /// A fresh cached identity for `key`, marked referenced (the instance's read lock only).
    fn cached(&self, key: &VerdictKey, now_s: u64) -> Option<V> {
        let book = self.read(key.auth_instance);
        let keys = book.get(&key.auth_instance)?;
        let at = *keys.index.get(&(key.policy_epoch, key.credential.0))?;
        let cached = keys.ring.get(at).filter(|cached| now_s < cached.until)?;
        cached.referenced.store(true, Ordering::Relaxed);
        Some(cached.value.clone())
    }

    /// The instance's flush epoch, its record made on first use so a later flush always moves it.
    fn instance_epoch(&self, auth_instance: u64) -> u64 {
        let known = self
            .read(auth_instance)
            .get(&auth_instance)
            .map(|keys| keys.epoch.load(Ordering::Relaxed));
        match known {
            Some(epoch) => epoch,
            None => self
                .write(auth_instance)
                .entry(auth_instance)
                .or_default()
                .epoch
                .load(Ordering::Relaxed),
        }
    }

    /// Rule 5: a positive fill. Replaces the key's own slot, takes a free slot, or evicts the sweep's victim;
    /// with none found within `SWEEP_STEPS`, it does not fill. Discarded if the instance's epoch moved (rule 6).
    fn store(&self, key: VerdictKey, epoch: u64, value: V, now_s: u64, until: u64) {
        let max = self.max_entries();
        let mut book = self.write(key.auth_instance);
        let Some(keys) = book.get_mut(&key.auth_instance) else {
            return;
        };
        if keys.epoch.load(Ordering::Relaxed) != epoch {
            return;
        }
        let id = (key.policy_epoch, key.credential.0);
        let cached = Cached {
            key: id,
            value,
            until,
            referenced: AtomicBool::new(false),
        };
        if let Some(&at) = keys.index.get(&id) {
            keys.ring[at] = cached;
            return;
        }
        if keys.ring.len() < max {
            keys.index.insert(id, keys.ring.len());
            keys.ring.push(cached);
            return;
        }
        let Some(at) = victim(keys, now_s) else {
            return;
        };
        let evicted = keys.ring[at].key;
        keys.index.remove(&evicted);
        keys.index.insert(id, at);
        keys.ring[at] = cached;
    }

    fn lead(&self, key: VerdictKey, epoch: u64) -> VerdictLead<'_, V, O> {
        VerdictLead {
            cache: self,
            key,
            epoch,
            settled: false,
        }
    }

    /// Rule 6: the instance's flush epoch (one Relaxed load).
    pub(crate) fn epoch_of(&self, auth_instance: u64) -> u64 {
        self.read(auth_instance)
            .get(&auth_instance)
            .map_or(0, |keys| keys.epoch.load(Ordering::Relaxed))
    }

    /// How many identities the instance holds cached (VerifyBook's `keys`; standing leads are not counted).
    pub fn keys(&self, auth_instance: u64) -> usize {
        self.read(auth_instance)
            .get(&auth_instance)
            .map_or(0, |keys| keys.ring.len())
    }
}

impl VerdictCache for Verdicts {
    fn begin<'a>(&'a self, key: VerdictKey, now_s: u64) -> VerdictGet<'a> {
        self.start(key, now_s)
    }

    fn epoch(&self, auth_instance: u64) -> u64 {
        self.epoch_of(auth_instance)
    }

    fn flush_instance(&self, auth_instance: u64) {
        self.flush(auth_instance);
    }
}

/// Pass a lead to its first follower still waiting; false when none is left (the caller ends the lead).
pub(crate) fn hand<O>(lead: &mut Lead<O>) -> bool {
    while let Some(next) = lead.followers.pop_front() {
        if next.send(Handoff::Lead).is_ok() {
            return true;
        }
    }
    false
}

/// Rule 5's sweep: from where the last sweep stopped, the first slot that is stale or unreferenced, clearing the
/// reference of each referenced slot passed. At most `SWEEP_STEPS` slots; None when all of them were referenced.
fn victim<V>(keys: &mut Keys<V>, now_s: u64) -> Option<usize> {
    let len = keys.ring.len();
    if len == 0 {
        return None;
    }
    for _ in 0..SWEEP_STEPS {
        let at = keys.hand % len;
        keys.hand = (at + 1) % len;
        let cached = &keys.ring[at];
        if now_s >= cached.until || !cached.referenced.swap(false, Ordering::Relaxed) {
            return Some(at);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;

    /// A stand-in value: `Ok((who, cache_s))` is an eligible identity, `Err` a verdict that never fills.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Who(u32);

    type Answer = Result<(Who, Option<u32>), &'static str>;

    fn who_fill(outcome: &Answer, now_s: u64, policy: &VerdictPolicy) -> Option<(Who, u64)> {
        let Ok((who, cache_s)) = outcome else {
            return None;
        };
        ttl(*cache_s, None, now_s, policy).map(|ttl| (who.clone(), ttl))
    }

    fn key(instance: u64, byte: u8) -> VerdictKey {
        VerdictKey {
            auth_instance: instance,
            policy_epoch: 0,
            credential: CredentialHash([byte; 32]),
        }
    }

    fn book(max_entries: u32) -> Verdicts<Who, Answer> {
        Verdicts::with_fill(
            VerdictPolicy {
                max_entries,
                ..VerdictPolicy::DEFAULT
            },
            who_fill,
        )
    }

    fn lead(get: VerdictGet<'_, Who, Answer>) -> VerdictLead<'_, Who, Answer> {
        match get {
            VerdictGet::Lead(lead) => lead,
            VerdictGet::Hit(_) => panic!("a hit, not a lead"),
            VerdictGet::Follow(_) => panic!("a follow, not a lead"),
            VerdictGet::Bypass => panic!("a bypass, not a lead"),
        }
    }

    type Following<'a> = BoxFut<'a, Result<Answer, VerdictLead<'a, Who, Answer>>>;

    fn follow(get: VerdictGet<'_, Who, Answer>) -> Following<'_> {
        match get {
            VerdictGet::Follow(waiting) => waiting,
            VerdictGet::Hit(_) => panic!("a hit, not a follow"),
            VerdictGet::Lead(_) => panic!("a lead, not a follow"),
            VerdictGet::Bypass => panic!("a bypass, not a follow"),
        }
    }

    fn hit(get: VerdictGet<'_, Who, Answer>) -> Option<Who> {
        match get {
            VerdictGet::Hit(who) => Some(who),
            _ => None,
        }
    }

    #[test]
    fn a_settled_lead_fills_and_the_same_credential_then_hits_until_its_ttl() {
        let cache = book(4_096);
        lead(cache.start(key(1, 7), 100)).settle(&Ok((Who(9), Some(60))), 100);
        assert_eq!(hit(cache.start(key(1, 7), 159)), Some(Who(9)));
        assert!(
            hit(cache.start(key(1, 7), 160)).is_none(),
            "stale at its TTL"
        );
    }

    #[test]
    fn the_ttl_is_the_least_of_the_stated_lifetime_the_expiry_and_the_cap() {
        let p = VerdictPolicy::DEFAULT;
        assert_eq!(ttl(Some(60), Some(130), 100, &p), Some(30));
        assert_eq!(ttl(None, None, 100, &p), Some(300));
        assert_eq!(ttl(Some(99_999), None, 100, &p), Some(3_600));
        assert_eq!(ttl(Some(0), None, 100, &p), None);
        assert_eq!(ttl(Some(60), Some(100), 100, &p), None);
        assert_eq!(ttl(Some(60), Some(90), 100, &p), None);
    }

    #[test]
    fn a_verdict_that_never_fills_reaches_the_followers_and_nothing_else() {
        let cache = book(4_096);
        let leading = lead(cache.start(key(1, 1), 10));
        let waiting = follow(cache.start(key(1, 1), 10));
        leading.settle(&Err("rejected"), 10);
        match waiting.now_or_never() {
            Some(Ok(Err(text))) => assert_eq!(text, "rejected"),
            _ => panic!("the follower gets the leader's outcome"),
        }
        let _again = lead(cache.start(key(1, 1), 11));
    }

    #[test]
    fn a_burst_on_one_cold_credential_has_one_leader_and_every_follower_gets_its_identity() {
        let cache = book(4_096);
        let leading = lead(cache.start(key(2, 3), 50));
        let waiting: Vec<_> = (0..63)
            .map(|_| follow(cache.start(key(2, 3), 50)))
            .collect();
        leading.settle(&Ok((Who(4), Some(60))), 50);
        for follower in waiting {
            match follower.now_or_never() {
                Some(Ok(Ok((who, _)))) => assert_eq!(who, Who(4)),
                _ => panic!("every follower gets the leader's identity"),
            }
        }
    }

    #[test]
    fn a_dropped_lead_passes_at_once_to_the_first_follower() {
        let cache = book(4_096);
        let leading = lead(cache.start(key(3, 1), 0));
        let first = follow(cache.start(key(3, 1), 0));
        let second = follow(cache.start(key(3, 1), 0));
        drop(leading);
        let next = match first.now_or_never() {
            Some(Err(next)) => next,
            _ => panic!("the first follower leads at once"),
        };
        next.settle(&Ok((Who(5), Some(60))), 1);
        match second.now_or_never() {
            Some(Ok(Ok((who, _)))) => assert_eq!(who, Who(5)),
            _ => panic!("the second follower gets the new leader's outcome"),
        }
        assert_eq!(hit(cache.start(key(3, 1), 2)), Some(Who(5)));
    }

    #[test]
    fn room_drops_idle_stale_keys_then_the_soonest_expiry_and_bypasses_when_all_lead() {
        let cache = book(2);
        lead(cache.start(key(1, 1), 0)).settle(&Ok((Who(1), Some(10))), 0);
        lead(cache.start(key(1, 2), 0)).settle(&Ok((Who(2), Some(20))), 0);
        let third = lead(cache.start(key(1, 3), 5));
        assert_eq!(
            hit(cache.start(key(1, 2), 5)),
            Some(Who(2)),
            "the later expiry stays"
        );
        assert_eq!(cache.keys(1), 2, "the soonest expiry went");
        drop(third);

        // DES-359 r3 rule 5: standing leads take no cache room, so a third key still leads.
        let busy = book(2);
        let _a = lead(busy.start(key(1, 1), 0));
        let _b = lead(busy.start(key(1, 2), 0));
        assert!(matches!(busy.start(key(1, 3), 0), VerdictGet::Lead(_)));
        assert_eq!(busy.keys(1), 0, "leads are not cached identities");
    }

    #[test]
    fn a_flush_drops_entries_and_a_lead_begun_before_it_does_not_fill() {
        let cache = book(4_096);
        lead(cache.start(key(1, 1), 0)).settle(&Ok((Who(1), Some(60))), 0);
        let before = lead(cache.start(key(1, 2), 0));
        assert_eq!(cache.epoch_of(1), 0);
        cache.flush(1);
        assert_eq!(cache.epoch_of(1), 1);
        assert!(hit(cache.start(key(1, 1), 1)).is_none(), "flushed");
        before.settle(&Ok((Who(2), Some(60))), 1);
        assert!(
            hit(cache.start(key(1, 2), 2)).is_none(),
            "a pre-flush verdict never fills"
        );
    }

    #[test]
    fn two_instances_never_share_an_entry() {
        let cache = book(4_096);
        lead(cache.start(key(1, 9), 0)).settle(&Ok((Who(1), Some(60))), 0);
        let _other = lead(cache.start(key(2, 9), 0));
        assert_eq!(cache.keys(1), 1);
    }

    #[test]
    fn policy_epochs_never_share_a_cached_identity() {
        let cache = book(4_096);
        let old = key(1, 9);
        lead(cache.start(old, 0)).settle(&Ok((Who(1), Some(60))), 0);
        let current = VerdictKey {
            policy_epoch: 1,
            ..old
        };
        assert!(matches!(cache.start(current, 1), VerdictGet::Lead(_)));
        assert_eq!(hit(cache.start(old, 1)), Some(Who(1)));
    }

    #[test]
    fn the_tick_hands_a_lapsed_lead_to_a_follower() {
        let cache = book(4_096);
        let _hung = lead(cache.start(key(1, 1), 0));
        let waiting = follow(cache.start(key(1, 1), 1));
        assert_eq!(cache.expire(LEAD_S - 1), 0);
        assert_eq!(cache.expire(LEAD_S), 1);
        assert!(matches!(waiting.now_or_never(), Some(Err(_))));
    }

    #[test]
    fn past_max_followers_and_with_the_cache_off_the_caller_verifies_unshared() {
        let cache = book(4_096);
        let _leading = lead(cache.start(key(1, 1), 0));
        let _waiting: Vec<_> = (0..MAX_FOLLOWERS)
            .map(|_| follow(cache.start(key(1, 1), 0)))
            .collect();
        assert!(matches!(cache.start(key(1, 1), 0), VerdictGet::Bypass));
        assert!(matches!(book(0).start(key(1, 1), 0), VerdictGet::Bypass));
    }

    #[test]
    fn only_a_header_credential_with_no_body_binding_is_eligible() {
        assert!(eligible(1, 0));
        assert!(!eligible(0, 0));
        assert!(!eligible(1, FB_NEEDS_BODY));
        assert!(!eligible(2, FB_NEEDS_BODY_HASH));
    }

    #[test]
    fn a_key_never_prints_its_credential_hash() {
        let shown = format!("{:?}", key(1, 0xab));
        assert!(!shown.contains("171") && !shown.contains("ab,"), "{shown}");
        assert_eq!(VerdictPolicy::DEFAULT.checked(), Ok(VerdictPolicy::DEFAULT));
        assert!(VerdictPolicy {
            max_ttl_s: 0,
            ..VerdictPolicy::DEFAULT
        }
        .checked()
        .is_err());
    }

    /// #359 SEC-L12 (DES-359 r3): a lookup still in flight never takes room from a cached identity. A
    /// flood of unknown credentials leaves every cached identity answering from the cache.
    #[test]
    fn unknown_credential_leads_never_evict_a_cached_identity() {
        let cache = book(2);
        lead(cache.start(key(1, 1), 0)).settle(&Ok((Who(1), Some(600))), 0);
        lead(cache.start(key(1, 2), 0)).settle(&Ok((Who(2), Some(600))), 0);
        let flood: Vec<_> = (10..110u8)
            .map(|byte| cache.start(key(1, byte), 1))
            .collect();
        assert!(flood.iter().all(|get| !matches!(get, VerdictGet::Hit(_))));
        assert_eq!(hit(cache.start(key(1, 1), 2)), Some(Who(1)), "still cached");
        assert_eq!(hit(cache.start(key(1, 2), 2)), Some(Who(2)), "still cached");
        drop(flood);
    }

    /// #359 SEC-L12: the lead table is bounded per shard; a full shard verifies unshared, never refuses.
    #[test]
    fn a_full_lead_shard_verifies_unshared() {
        let cache = book(4_096);
        let held: Vec<_> = (0..LEADS_PER_SHARD as u64)
            .map(|instance| lead(cache.start(key(instance, 0), 0)))
            .collect();
        assert!(matches!(
            cache.start(key(LEADS_PER_SHARD as u64, 0), 0),
            VerdictGet::Bypass
        ));
        assert!(
            matches!(cache.start(key(0, 1), 0), VerdictGet::Lead(_)),
            "another shard still leads"
        );
        drop(held);
        assert!(matches!(
            cache.start(key(LEADS_PER_SHARD as u64, 0), 1),
            VerdictGet::Lead(_)
        ));
    }

    /// #359 SEC-L12 B-R1: a lead is keyed by (auth instance, policy epoch, credential): the same credential
    /// on two instances leads twice, never follows the other instance.
    #[test]
    fn the_same_credential_on_two_instances_leads_on_each() {
        let cache = book(4_096);
        let _first = lead(cache.start(key(1, 5), 0));
        let _second = lead(cache.start(key(2, 5), 0));
        let _other_epoch = lead(cache.start(
            VerdictKey {
                policy_epoch: 1,
                ..key(1, 5)
            },
            0,
        ));
    }

    /// #359 SEC-L12: at capacity a positive fill evicts the least recently referenced identity, not the
    /// one with the soonest expiry: a referenced identity survives.
    #[test]
    fn a_positive_fill_at_capacity_evicts_the_least_recently_referenced() {
        let cache = book(2);
        lead(cache.start(key(1, 1), 0)).settle(&Ok((Who(1), Some(50))), 0);
        lead(cache.start(key(1, 2), 0)).settle(&Ok((Who(2), Some(100))), 0);
        assert_eq!(hit(cache.start(key(1, 1), 1)), Some(Who(1)));
        lead(cache.start(key(1, 3), 2)).settle(&Ok((Who(3), Some(100))), 2);
        assert_eq!(
            hit(cache.start(key(1, 1), 3)),
            Some(Who(1)),
            "referenced: kept"
        );
        assert_eq!(hit(cache.start(key(1, 3), 3)), Some(Who(3)), "filled");
        assert!(
            hit(cache.start(key(1, 2), 3)).is_none(),
            "unreferenced: evicted"
        );
        assert_eq!(cache.keys(1), 2);
    }

    /// #359 SEC-L12: the eviction sweep is bounded. With every identity recently referenced, a fill looks
    /// at no more than 16 slots and then does not fill; the sweep resumes where it stopped.
    #[test]
    fn the_eviction_sweep_stops_after_sixteen_steps_and_resumes_where_it_stopped() {
        let cache = book(32);
        for byte in 0..32u8 {
            lead(cache.start(key(1, byte), 0)).settle(&Ok((Who(u32::from(byte)), Some(600))), 0);
        }
        for byte in 0..32u8 {
            assert!(hit(cache.start(key(1, byte), 1)).is_some());
        }
        lead(cache.start(key(1, 100), 2)).settle(&Ok((Who(100), Some(600))), 2);
        assert!(
            hit(cache.start(key(1, 100), 3)).is_none(),
            "16 referenced slots: no fill"
        );
        assert_eq!(cache.keys(1), 32);
        lead(cache.start(key(1, 101), 3)).settle(&Ok((Who(101), Some(600))), 3);
        assert!(
            hit(cache.start(key(1, 101), 4)).is_none(),
            "the next 16: no fill"
        );
        lead(cache.start(key(1, 102), 4)).settle(&Ok((Who(102), Some(600))), 4);
        assert_eq!(
            hit(cache.start(key(1, 102), 5)),
            Some(Who(102)),
            "the sweep wrapped to a cleared slot"
        );
        assert!(
            hit(cache.start(key(1, 0), 5)).is_none(),
            "slot 0 was the victim"
        );
    }
}
