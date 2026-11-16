// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verdict cache: core's one per-instance verify cache with single-flight leads (IF §12.28). Built from
//! `host_verify.rs`'s `VerifyBook` (its `room`, `Slot`, `fresh`, `idle`, `lead_until`/`LEAD_MS`, `MAX_FOLLOWERS`
//! and `expire`), re-keyed by auth instance id and credential hash, holding the adapter's `Identity`, sharded 16
//! ways by instance (a read lock on the hit path), with `oneshot` followers and per-instance flush epochs.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use busbar_plugin_abi::auth::{FB_NEEDS_BODY, FB_NEEDS_BODY_HASH};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::{Identity, Verdict};
use busbar_ports::PortError;
use foldhash::HashMap;
use tokio::sync::oneshot;

/// How long one lead stands before the `expire` sweep passes it on (VerifyBook's, kept).
pub const LEAD_MS: u64 = 30_000;
/// The most callers that wait on one lead; one more verifies unshared (`Bypass`, never refused).
pub const MAX_FOLLOWERS: usize = 1024;
pub(crate) const LEAD_S: u64 = LEAD_MS / 1_000;
const SHARDS: usize = 16;

/// The credential a verify read, by hash only (the credential itself is never stored). `credential` = SHA-256
/// (through the facade) over, for each of the instance's D_CRED_HEADER names in declared order, the u32 LE name
/// length, the name, the u32 LE count of that header's values on the request and each value with its u32 LE length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerdictKey {
    pub auth_instance: u64,
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
    /// Ineligible instance (rule 1), cache off, no room with every entry leading, or `MAX_FOLLOWERS` reached:
    /// verify unshared and do not fill.
    Bypass,
}

/// One standing lead (VerifyBook's `lead_until`). Holds the cache, the key and the instance's flush epoch read in
/// `begin` (rule 6).
pub struct VerdictLead<'a, V = Identity, O = Outcome> {
    cache: &'a Verdicts<V, O>,
    key: VerdictKey,
    epoch: u64,
    settled: bool,
}

impl<V, O: Clone> VerdictLead<'_, V, O> {
    /// Ends the lead with the leader's outcome: fills only for an eligible answer (rules 2, 3; discarded if the
    /// epoch moved) and hands `outcome` (cloned) to every follower, whatever it is (an identity, NotMine, Rejected
    /// or a `PortError`): followers carry the same credential bytes to the same instance at the same moment.
    pub fn settle(mut self, outcome: &O, now_s: u64) {
        self.settled = true;
        let fill = (self.cache.fill)(outcome, now_s, &self.cache.policy);
        let followers = {
            let mut book = self.cache.write(self.key.auth_instance);
            let Some(keys) = book.get_mut(&self.key.auth_instance) else {
                return;
            };
            let current = keys.epoch.load(Ordering::Relaxed) == self.epoch;
            let Some(slot) = keys.keys.get_mut(&self.key.credential.0) else {
                return;
            };
            if let Some((value, ttl)) = fill.filter(|_| current) {
                slot.entry = Some((value, now_s.saturating_add(ttl)));
            }
            slot.lead_until = None;
            std::mem::take(&mut slot.followers)
        };
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
        let mut book = self.cache.write(self.key.auth_instance);
        if let Some(slot) = book
            .get_mut(&self.key.auth_instance)
            .and_then(|keys| keys.keys.get_mut(&self.key.credential.0))
        {
            hand(slot);
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
///    effective chain, in chain order): `begin` answers `Hit` for a fresh entry (read lock only); otherwise, under
///    the shard's write lock, `Follow` if a lead stands for the key (now < `lead_until`), else `Lead` with
///    `lead_until` = now + `LEAD_MS`. So a burst of N requests carrying the same cold credential makes one plugin
///    verify and, for `verify_io`, one set of upstream Needs (JWKS, LDAP bind, GitHub user lookup), not N; the
///    other N − 1 return the leader's outcome. Round 23's "no single-flight" is withdrawn: under I1 a plugin has
///    no I/O of its own, so a duplicate miss is a duplicate core-run upstream call, and VerifyBook already
///    collapses them. A lead that lapses (`LEAD_MS`, a hung leader past its own deadline) passes to the first
///    follower by the kept `expire` sweep, which K2 runs on the watchdog tick.
/// 5. **Capacity** (VerifyBook's `room`, kept): at `max_entries` keys for an instance, a new key first drops that
///    instance's idle expired entries, then its idle entry with the soonest expiry; if every entry is leading or
///    followed, `begin` answers `Bypass`. Round 23's oldest-inserted rule (auth-oidc's) is replaced by core's.
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

/// One key of one instance's cache (VerifyBook's `Slot`).
pub(crate) struct Slot<V, O> {
    /// The stored value and when it goes stale (seconds, the caller's `now_s` clock).
    pub(crate) entry: Option<(V, u64)>,
    /// When the standing lead lapses; `None` = no lead.
    pub(crate) lead_until: Option<u64>,
    /// The callers waiting on the lead, in arrival order.
    pub(crate) followers: VecDeque<oneshot::Sender<Handoff<O>>>,
}

pub(crate) enum Handoff<O> {
    Outcome(O),
    Lead,
}

impl<V, O> Default for Slot<V, O> {
    fn default() -> Self {
        Slot {
            entry: None,
            lead_until: None,
            followers: VecDeque::new(),
        }
    }
}

impl<V, O> Slot<V, O> {
    pub(crate) fn fresh(&self, now_s: u64) -> Option<&V> {
        self.entry
            .as_ref()
            .filter(|(_, until)| now_s < *until)
            .map(|(value, _)| value)
    }

    pub(crate) fn idle(&self) -> bool {
        self.lead_until.is_none() && self.followers.is_empty()
    }
}

/// One instance's keys and its flush epoch (rule 6).
pub(crate) struct Keys<V, O> {
    pub(crate) epoch: AtomicU64,
    pub(crate) keys: HashMap<[u8; 32], Slot<V, O>>,
}

impl<V, O> Default for Keys<V, O> {
    fn default() -> Self {
        Keys {
            epoch: AtomicU64::new(0),
            keys: HashMap::default(),
        }
    }
}

/// The verdict cache, every auth instance's: 16 shards by instance id, each a `RwLock`.
pub struct Verdicts<V = Identity, O = Outcome> {
    policy: VerdictPolicy,
    fill: Fill<V, O>,
    pub(crate) shards: [RwLock<HashMap<u64, Keys<V, O>>>; SHARDS],
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
        }
    }

    fn shard(&self, auth_instance: u64) -> &RwLock<HashMap<u64, Keys<V, O>>> {
        let at = usize::try_from(auth_instance % SHARDS as u64).unwrap_or(0);
        &self.shards[at]
    }

    fn read(&self, auth_instance: u64) -> RwLockReadGuard<'_, HashMap<u64, Keys<V, O>>> {
        self.shard(auth_instance)
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn write(
        &self,
        auth_instance: u64,
    ) -> RwLockWriteGuard<'_, HashMap<u64, Keys<V, O>>> {
        self.shard(auth_instance)
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl<V: Clone + Send + Sync + 'static, O: Clone + Send + Sync + 'static> Verdicts<V, O> {
    /// Rule 4 (`VerdictCache::begin`): `Hit` under the read lock; otherwise, under the write lock, `Follow` a
    /// standing lead or take a new one. Rule 5's `room` decides whether a new key fits.
    pub fn start(&self, key: VerdictKey, now_s: u64) -> VerdictGet<'_, V, O> {
        let max = usize::try_from(self.policy.max_entries).unwrap_or(usize::MAX);
        if max == 0 {
            return VerdictGet::Bypass;
        }
        {
            let book = self.read(key.auth_instance);
            let hit = book
                .get(&key.auth_instance)
                .and_then(|keys| keys.keys.get(&key.credential.0))
                .and_then(|slot| slot.fresh(now_s));
            if let Some(value) = hit {
                return VerdictGet::Hit(value.clone());
            }
        }
        let mut book = self.write(key.auth_instance);
        let keys = book.entry(key.auth_instance).or_default();
        if !keys.keys.contains_key(&key.credential.0) && !room(&mut keys.keys, now_s, max) {
            return VerdictGet::Bypass;
        }
        let epoch = keys.epoch.load(Ordering::Relaxed);
        let slot = keys.keys.entry(key.credential.0).or_default();
        if let Some(value) = slot.fresh(now_s) {
            return VerdictGet::Hit(value.clone());
        }
        match slot.lead_until {
            Some(until) if now_s < until => {
                if slot.followers.len() >= MAX_FOLLOWERS {
                    return VerdictGet::Bypass;
                }
                let (tell, told) = oneshot::channel();
                slot.followers.push_back(tell);
                drop(book);
                VerdictGet::Follow(Box::pin(async move {
                    match told.await {
                        Ok(Handoff::Outcome(outcome)) => Ok(outcome),
                        Ok(Handoff::Lead) | Err(_) => Err(self.lead(key, epoch)),
                    }
                }))
            }
            _ => {
                slot.lead_until = Some(now_s.saturating_add(LEAD_S));
                VerdictGet::Lead(self.lead(key, epoch))
            }
        }
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

    /// How many keys the instance holds (VerifyBook's `keys`).
    pub fn keys(&self, auth_instance: u64) -> usize {
        self.read(auth_instance)
            .get(&auth_instance)
            .map_or(0, |keys| keys.keys.len())
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

/// Pass a slot's lead to its first follower still waiting; with none left, the lead ends.
pub(crate) fn hand<V, O>(slot: &mut Slot<V, O>) -> bool {
    while let Some(next) = slot.followers.pop_front() {
        if next.send(Handoff::Lead).is_ok() {
            return true;
        }
    }
    slot.lead_until = None;
    false
}

/// Rule 5 (VerifyBook's `room`, kept): at `max` keys, drop the idle stale keys, then the idle key with the soonest
/// expiry; false when every key is leading or followed.
fn room<V, O>(keys: &mut HashMap<[u8; 32], Slot<V, O>>, now_s: u64, max: usize) -> bool {
    if keys.len() < max {
        return true;
    }
    keys.retain(|_, slot| !(slot.idle() && slot.fresh(now_s).is_none()));
    if keys.len() < max {
        return true;
    }
    let soonest = keys
        .iter()
        .filter(|(_, slot)| slot.idle())
        .min_by_key(|(_, slot)| slot.entry.as_ref().map_or(0, |(_, until)| *until))
        .map(|(key, _)| *key);
    match soonest {
        Some(key) => {
            keys.remove(&key);
            true
        }
        None => false,
    }
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

        let busy = book(2);
        let _a = lead(busy.start(key(1, 1), 0));
        let _b = lead(busy.start(key(1, 2), 0));
        assert!(matches!(busy.start(key(1, 3), 0), VerdictGet::Bypass));
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
}
