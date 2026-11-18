// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `FakeNeeds` and `ConnScript` (ABI-MIN3-INTERFACE §14): a scriptable `Needs` for plugin CI. Canned conns
//! (byte scripts), fetch answers, secrets and records; the kernel answers a plane suite scripts (grants,
//! rendezvous, issued credentials, channels, trust verdicts, observation statuses) are held for the suite.
//!
//! Ordinary scripts answer immediately. An explicit [`FakeNeeds::park_fetch`] script suspends until the
//! owning operation is dropped, with no State lock held while inspecting or pending. Conns are keyed by
//! `(instance, chain, conn id)` as the connector keys them (§13), so `release` closes only its own chain's conns;
//! conn ids and pooled-conn ids are minted per instance from 1 and never repeat (C-POOL-STATE (a), round 19).
//! Every OPEN and FETCH is recorded, so a suite can hold them against the ENDPOINTs a plugin's `check` declared
//! (TRANSPORT-SECURITY-POLICY §2, [`FakeNeeds::undeclared`]).
//! RECORD COMMIT evaluates predicates and publishes mutations under that same lock, scoped by plugin and
//! instance. It supports TTL=0 only; timed COMMIT writes fail Invalid. This in-memory fixture proves host
//! interactions, not native Store durability or crash recovery. Existing Put/Claim TTL behavior is unchanged.

use core::future::{ready, Future};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, NeedErr, NeedOut, Needs, OpenNeed, RecordNeed, TlsMode,
};
use busbar_plugin_abi::secure::SecureVec;

mod parked_fetch;
mod records;
pub use busbar_plugin_abi::host_side::needs::FetchNeed;
pub use parked_fetch::ParkedFetch;

/// Host-side record errors, exposed for fixture scripts without an internal loader dependency.
pub use busbar_plugin_abi::host_side::needs::NeedErr as RecordError;

/// One scripted RECORD call. Unscripted calls use the in-memory state normally.
#[derive(Clone, Debug)]
pub enum RecordStep {
    /// Use normal state for this call (useful before a later scripted failure).
    Pass,
    /// Fail before any access or mutation.
    Error(RecordError),
    /// Simulate another writer in this caller's namespace immediately before the next COMMIT.
    /// Its write remains even when the submitted CAS conflicts. Non-COMMIT calls are Invalid.
    BeforeCommit { key: Vec<u8>, value: Vec<u8> },
    /// Apply a successful COMMIT, then lose its acknowledgement. A conflicting commit still
    /// returns Conflict; a non-COMMIT call is Invalid. The next read observes committed state.
    CommitThenError(RecordError),
}

/// Every RECORD invocation, including failed calls, in execution order. Values stay in `records()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordCall {
    pub plugin: String,
    pub instance: String,
    /// `get`, `put`, `claim`, `del`, `list`, or `commit`.
    pub op: &'static str,
}
use busbar_plugin_abi::host_side::scrub::Scrub;

/// One step of a scripted conn.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// The plugin must write exactly these bytes next (over one or several WRITEs).
    Expect(Vec<u8>),
    /// The next READs return these bytes (over one or several READs, each at most its `max`).
    Reply(Vec<u8>),
    /// The far end closed: READ answers EOF from here on.
    Eof,
    /// The far end reset: every later WRITE or READ answers `Closed`.
    Reset,
}

/// What one READ answers.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Read {
    Bytes(Vec<u8>),
    Eof,
}

/// A conn's byte script: `expect` / `reply` / `eof` / `reset` steps, played in order.
#[derive(Clone, Debug, Default)]
pub struct ConnScript {
    steps: VecDeque<Step>,
}

impl ConnScript {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expect(mut self, b: &[u8]) -> Self {
        self.steps.push_back(Step::Expect(b.to_vec()));
        self
    }

    pub fn reply(mut self, b: &[u8]) -> Self {
        self.steps.push_back(Step::Reply(b.to_vec()));
        self
    }

    pub fn eof(mut self) -> Self {
        self.steps.push_back(Step::Eof);
        self
    }

    pub fn reset(mut self) -> Self {
        self.steps.push_back(Step::Reset);
        self
    }

    /// The plugin wrote `bytes`: they must be the bytes the script expects next. One `expect` may be met over
    /// several writes and one write may meet several `expect`s; a write past the expected bytes, or bytes that
    /// differ, is `Invalid`; a write after a `reset` is `Closed`.
    fn wrote(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        let mut rest = bytes;
        while !rest.is_empty() {
            match self.steps.front_mut() {
                Some(Step::Expect(want)) => {
                    let n = want.len().min(rest.len());
                    if want[..n] != rest[..n] {
                        return Err(NeedErr::Invalid);
                    }
                    want.drain(..n);
                    rest = &rest[n..];
                    if want.is_empty() {
                        self.steps.pop_front();
                    }
                }
                Some(Step::Reset) => return Err(NeedErr::Closed),
                _ => return Err(NeedErr::Invalid),
            }
        }
        Ok(())
    }

    /// The plugin reads at most `max` bytes. A READ while the script still expects bytes from the plugin would
    /// wait forever on a real conn: it answers `Timeout`. A spent script reads as EOF.
    fn read(&mut self, max: usize) -> Result<Read, NeedErr> {
        if max == 0 {
            return Err(NeedErr::Invalid);
        }
        match self.steps.front_mut() {
            Some(Step::Reply(have)) => {
                let n = have.len().min(max);
                let out: Vec<u8> = have.drain(..n).collect();
                if have.is_empty() {
                    self.steps.pop_front();
                }
                Ok(Read::Bytes(out))
            }
            Some(Step::Eof) | None => Ok(Read::Eof),
            Some(Step::Reset) => Err(NeedErr::Closed),
            Some(Step::Expect(_)) => Err(NeedErr::Timeout),
        }
    }
}

/// One OPEN or FETCH a plugin made: the destination, whether it asked for TLS, and the egress class it stated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// `"open"` or `"fetch"`.
    pub op: &'static str,
    /// The OPEN `dest`, or the FETCH URL.
    pub dest: String,
    pub tls: bool,
    pub egress: u32,
}

/// The kernel answers a plane suite scripts (FROM_CORE results of ENTITLE, MINT/SIGN, CONNECT, rendezvous and
/// trust intents, the shared channels and the observation custody's statuses), in the order they were added.
#[derive(Clone, Debug, Default)]
pub struct Kernel {
    pub grants: Vec<(String, String)>,
    pub rendezvous: Vec<(String, String)>,
    pub issued: Vec<(String, String, Vec<u8>)>,
    pub channels: Vec<(String, String, ConnScript)>,
    pub trust: Vec<(String, String, u32)>,
    pub observe: VecDeque<u32>,
}

struct Fetch {
    method: String,
    url: String,
    reply: FetchReply,
}

enum FetchReply {
    Ready {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    },
    Park(parked_fetch::Script),
}

#[derive(Default)]
struct State {
    #[cfg(feature = "target-sockets")]
    socket_routes: std::collections::BTreeSet<(u64, u64, u64)>,
    conns: BTreeMap<String, VecDeque<ConnScript>>,
    fetches: Vec<Fetch>,
    secrets: Vec<(String, SecureVec)>,
    denied: Vec<String>,
    kernel: Kernel,
    live: BTreeMap<(u64, u64, u64), ConnScript>,
    next_conn: BTreeMap<u64, u64>,
    next_pooled: BTreeMap<u64, u64>,
    records: BTreeMap<(String, String, Vec<u8>), Vec<u8>>,
    record_steps: VecDeque<RecordStep>,
    record_calls: Vec<RecordCall>,
    seen: Vec<Seen>,
    #[cfg(test)]
    open_limits: Vec<(String, busbar_plugin_abi::host_side::caller::InstanceLimits)>,
    released: u64,
}

/// The scrub set of the instance that owns a watchdog slot: `Registry::scrub_of`, as the kernel attaches it to
/// custody (`SecretCustody::attach`, busbar root `min3_boot.rs`).
pub type ScrubOf = Arc<dyn Fn(u32) -> Option<Arc<Scrub>> + Send + Sync>;

/// A scriptable `Needs` for plugin CI (IF §14). Suites run `Registry<FakeNeeds>`.
#[derive(Default)]
pub struct FakeNeeds {
    #[cfg(feature = "target-sockets")]
    sockets: Option<crate::sockets::SocketTargets>,
    state: Mutex<State>,
    scrubs: Mutex<Option<ScrubOf>>,
}

/// The next id in `ids` for `instance`: 1, 2, 3, ... per instance, never repeated.
fn mint(ids: &mut BTreeMap<u64, u64>, instance: u64) -> Result<u64, NeedErr> {
    let next = ids.entry(instance).or_insert(0);
    *next = next.checked_add(1).ok_or(NeedErr::Limit)?;
    Ok(*next)
}

/// The host of a FETCH URL or an OPEN `host:port` dest, for `deny` matching; a `unix:<path>` dest is its own host.
fn host_of(dest: &str) -> &str {
    if dest.starts_with("unix:") {
        return dest;
    }
    let rest = dest.split_once("://").map_or(dest, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    }
}

impl FakeNeeds {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed opaque bytes in exactly one plugin/instance namespace. Use `records()` from a
    /// previous harness to restore a snapshot into a fresh fixture; nothing is persisted to disk.
    /// This is test setup, so it does not count as a plugin RECORD call.
    pub fn seed_record(&self, plugin: &str, instance: &str, key: &[u8], value: &[u8]) {
        self.lock().records.insert(
            (plugin.to_owned(), instance.to_owned(), key.to_vec()),
            value.to_vec(),
        );
    }

    /// Queue the next RECORD call's behavior, including after a harness has opened.
    pub fn script_record(&self, step: RecordStep) {
        self.lock().record_steps.push_back(step);
    }

    pub fn record_calls(&self) -> Vec<RecordCall> {
        self.lock().record_calls.clone()
    }

    #[cfg(test)]
    pub(crate) fn open_limits(
        &self,
    ) -> Vec<(String, busbar_plugin_abi::host_side::caller::InstanceLimits)> {
        self.lock().open_limits.clone()
    }

    fn state(&mut self) -> &mut State {
        self.state.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One more conn for OPENs to `dest` (`host:port` or `unix:<path>`): each OPEN takes the next script queued
    /// for its dest; an OPEN with none left answers `Unavailable`.
    pub fn conn(&mut self, dest: &str, script: ConnScript) -> &mut Self {
        #[cfg(feature = "target-sockets")]
        if let Some(host) = &self.sockets {
            if host.contains_dest(dest) {
                host.failure("overlap");
            }
        }
        self.state()
            .conns
            .entry(dest.to_owned())
            .or_default()
            .push_back(script);
        self
    }

    /// One FETCH answer for (`method`, `url`), used once, in the order added.
    pub fn fetch(
        &mut self,
        method: &str,
        url: &str,
        status: u16,
        headers: &[(&str, &[u8])],
        body: &[u8],
    ) -> &mut Self {
        let fetch = Fetch {
            method: method.to_owned(),
            url: url.to_owned(),
            reply: FetchReply::Ready {
                status,
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
                    .collect(),
                body: body.to_vec(),
            },
        };
        self.state().fetches.push(fetch);
        self
    }

    /// Queue one FETCH that inspects borrowed request bytes and then remains pending until cancellation.
    /// Shares ordinary FETCH matching/FIFO order. The inspector runs outside the State lock; it must not
    /// copy credentials into unguarded owners or format request bytes in assertion messages.
    pub fn park_fetch(
        &mut self,
        method: &str,
        url: &str,
        inspect: impl for<'a> Fn(FetchNeed<'a>) + Send + Sync + 'static,
    ) -> ParkedFetch {
        let (script, parked) = parked_fetch::Script::new(inspect);
        self.state().fetches.push(Fetch {
            method: method.to_owned(),
            url: url.to_owned(),
            reply: FetchReply::Park(script),
        });
        parked
    }

    /// The value custody returns for the secret the operator config holds at `pointer` (the suite binds the
    /// config, so the plugin only ever sees the handle). Handles are numbered from 1 in the order of these calls,
    /// the order the suite binds the pointers in. For a D_REF_PATH reference, `pointer` is its concrete pointer:
    /// the suite binder writes this value there, as a JSON string, before `check` and `open` (a reference with no
    /// value scripted is refused, as custody's failed resolve is).
    pub fn secret(&mut self, pointer: &str, value: &[u8]) -> &mut Self {
        self.state()
            .secrets
            .push((pointer.to_owned(), SecureVec::from(value)));
        self
    }

    /// The secret a CORE_CFG(LIFT) moved out of the settings: core writes the literal to its own secret file and
    /// leaves a reference at `pointer` (busbar-migrate `settle`), so custody answers that literal for it from then
    /// on. Used by the migrate suite after a converting open, the way [`Self::secret`] scripts one up front.
    pub(crate) fn lifted(&self, pointer: &str, value: &[u8]) {
        self.lock()
            .secrets
            .push((pointer.to_owned(), SecureVec::from(value)));
    }

    /// Custody's scrub registration (§12.2 step 5, I14): from here on every SECRET this double answers is first
    /// registered, under its handle, in the scrub set `scrub_of` names for the asking chain's slot, and only then
    /// handed to the plugin (register, then publish), as the kernel's custody does once the boot attaches
    /// `Registry::scrub_of` to it. A suite attaches its registry's after the harness is built:
    /// `h.needs().attach_scrubs(Arc::new(move |slot| weak.upgrade()?.registry().scrub_of(slot)))`. Without it no
    /// value is registered (a plugin's FAIL text and log lines are then scrubbed of nothing it resolved).
    pub fn attach_scrubs(&self, scrub_of: ScrubOf) {
        *self.scrubs.lock().unwrap_or_else(PoisonError::into_inner) = Some(scrub_of);
    }

    /// The first value `secret` scripted for `pointer`.
    pub(crate) fn secret_at(&self, pointer: &str) -> Option<Vec<u8>> {
        self.lock()
            .secrets
            .iter()
            .find(|(at, _)| at == pointer)
            .map(|(_, value)| value.as_slice().to_vec())
    }

    /// Scripted kernel answers for plane intents (ENTITLE grants, MINT/SIGN outputs, CONNECT states, rendezvous).
    pub fn grant(&mut self, subject: &str, grant: &str) -> &mut Self {
        self.state()
            .kernel
            .grants
            .push((subject.to_owned(), grant.to_owned()));
        self
    }

    pub fn rendezvous(&mut self, offer: &str, answer: &str) -> &mut Self {
        self.state()
            .kernel
            .rendezvous
            .push((offer.to_owned(), answer.to_owned()));
        self
    }

    pub fn issued(&mut self, kind: &str, id: &str, value: &[u8]) -> &mut Self {
        self.state()
            .kernel
            .issued
            .push((kind.to_owned(), id.to_owned(), value.to_vec()));
        self
    }

    /// Every OPEN and FETCH whose host is `dest` answers `Denied` (the guard's verdict).
    pub fn deny(&mut self, dest: &str) -> &mut Self {
        self.state().denied.push(host_of(dest).to_owned());
        self
    }

    /// A scripted shared channel for (upstream, key): inbound messages the core side emits, in order.
    pub fn channel(&mut self, upstream: &str, key: &str, script: ConnScript) -> &mut Self {
        self.state()
            .kernel
            .channels
            .push((upstream.to_owned(), key.to_owned(), script));
        self
    }

    /// The trust book's verdict for (party, item).
    pub fn trust(&mut self, party: &str, item: &str, verdict: u32) -> &mut Self {
        self.state()
            .kernel
            .trust
            .push((party.to_owned(), item.to_owned(), verdict));
        self
    }

    /// The observation custody's next answers (OBS_* status) for OBS_SCOPE / OBSERVE, in order.
    pub fn observe(&mut self, status: u32) -> &mut Self {
        self.state().kernel.observe.push_back(status);
        self
    }

    /// The kernel answers scripted so far (the plane suite drives them).
    pub fn kernel(&self) -> Kernel {
        self.lock().kernel.clone()
    }

    /// Every OPEN and FETCH the plugin made, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.lock().seen.clone()
    }

    /// The generic ENDPOINT match (TRANSPORT-SECURITY-POLICY §2): every OPEN/FETCH whose (host, TLS) is not
    /// among `declared` (host, TLS) pairs, i.e. a Need the plugin's `check` did not declare.
    pub fn undeclared(&self, declared: &[(&str, bool)]) -> Vec<Seen> {
        self.lock()
            .seen
            .iter()
            .filter(|seen| {
                !declared
                    .iter()
                    .any(|(dest, tls)| host_of(dest) == host_of(&seen.dest) && *tls == seen.tls)
            })
            .cloned()
            .collect()
    }

    /// Every record the plugin holds through RECORD, as (plugin identity, configured instance name, key, value), in
    /// key order.
    pub fn records(&self) -> Vec<(String, String, Vec<u8>, Vec<u8>)> {
        self.lock()
            .records
            .iter()
            .map(|((plugin, name, key), value)| {
                (plugin.clone(), name.clone(), key.clone(), value.clone())
            })
            .collect()
    }

    /// How many chains ended with a `release` (§10.5: exactly one per chain that made a NEED).
    pub fn released(&self) -> u64 {
        self.lock().released
    }
}

impl State {
    fn denies(&self, dest: &str) -> bool {
        let host = host_of(dest);
        self.denied.iter().any(|denied| denied == host)
    }

    fn conn(&mut self, cx: &Caller<'_>, c: ConnId) -> Result<&mut ConnScript, NeedErr> {
        self.live
            .get_mut(&(cx.instance, cx.chain, c.0))
            .ok_or(NeedErr::Invalid)
    }

    fn open_script(&mut self, cx: &Caller<'_>, n: OpenNeed<'_>) -> Result<OpenAnswer, NeedErr> {
        let script = self
            .conns
            .get_mut(n.dest)
            .and_then(VecDeque::pop_front)
            .ok_or(NeedErr::Unavailable)?;
        let id = mint(&mut self.next_conn, cx.instance)?;
        let pooled = mint(&mut self.next_pooled, cx.instance)?;
        self.live.insert((cx.instance, cx.chain, id), script);
        Ok(OpenAnswer {
            id,
            pooled,
            flags: 0,
            alpn: Vec::new(),
        })
    }

    fn fetch(&mut self, cx: &Caller<'_>, n: FetchNeed<'_>) -> Result<FetchReply, NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        self.seen.push(Seen {
            op: "fetch",
            dest: n.url.to_owned(),
            tls: n.url.starts_with("https://"),
            egress: n.egress,
        });
        if self.denies(n.url) {
            return Err(NeedErr::Denied);
        }
        let at = self
            .fetches
            .iter()
            .position(|f| f.method == n.method && f.url == n.url)
            .ok_or(NeedErr::Unavailable)?;
        Ok(self.fetches.remove(at).reply)
    }

    fn record(
        &mut self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let at = |key: &[u8]| (cx.plugin.to_owned(), cx.name.to_owned(), key.to_vec());
        self.record_calls.push(RecordCall {
            plugin: cx.plugin.to_owned(),
            instance: cx.name.to_owned(),
            op: match &n {
                RecordNeed::Get(_) => "get",
                RecordNeed::Put(..) => "put",
                RecordNeed::Claim(..) => "claim",
                RecordNeed::Del(_) => "del",
                RecordNeed::List(..) => "list",
                RecordNeed::Commit(_) => "commit",
            },
        });
        let mut after_commit = None;
        match self.record_steps.pop_front().unwrap_or(RecordStep::Pass) {
            RecordStep::Pass => {}
            RecordStep::Error(error) => return Err(error),
            RecordStep::BeforeCommit { key, value } => {
                if !matches!(&n, RecordNeed::Commit(_)) {
                    return Err(NeedErr::Invalid);
                }
                self.records.insert(at(&key), value);
            }
            RecordStep::CommitThenError(error) => {
                if !matches!(&n, RecordNeed::Commit(_)) {
                    return Err(NeedErr::Invalid);
                }
                after_commit = Some(error);
            }
        }
        match n {
            RecordNeed::Get(key) => match self.records.get(&at(key)) {
                Some(value) => {
                    res.set(1, 0);
                    res.put0(value)?;
                }
                None => res.set(0, 0),
            },
            RecordNeed::Put(key, value, _ttl) => {
                self.records.insert(at(key), value.to_vec());
                res.set(1, 0);
            }
            RecordNeed::Claim(key, value, _ttl) => {
                let won = !self.records.contains_key(&at(key));
                if won {
                    self.records.insert(at(key), value.to_vec());
                }
                res.set(u64::from(won), 0);
            }
            RecordNeed::Del(key) => {
                let had = self.records.remove(&at(key)).is_some();
                res.set(u64::from(had), 0);
            }
            RecordNeed::List(prefix, limit) => {
                let mut listed = 0u64;
                for ((plugin, name, key), value) in &self.records {
                    if listed >= u64::from(limit) {
                        break;
                    }
                    if plugin == cx.plugin && name == cx.name && key.starts_with(prefix) {
                        res.pair0(key, value)?;
                        listed += 1;
                    }
                }
                res.set(listed, 0);
            }
            RecordNeed::Commit(records) => {
                let outcome = self.commit_records(cx, records)?;
                if outcome.0 == u64::from(busbar_plugin_abi::records::commit::APPLIED) {
                    if let Some(error) = after_commit {
                        return Err(error);
                    }
                }
                res.set(outcome.0, outcome.1);
            }
        }
        Ok(())
    }
}

impl Needs for FakeNeeds {
    async fn open(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let a = self.open_answer(cx, n).await?;
        res.set(a.id, a.flags);
        if let Err(error) = res
            .put0(&a.alpn)
            .and_then(|()| res.put1(&a.pooled.to_le_bytes()))
        {
            self.close(cx, ConnId(a.id), false).await;
            return Err(error);
        }
        Ok(())
    }
    async fn starttls(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        tls: TlsMode<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        #[cfg(feature = "target-sockets")]
        if self.socket_route(cx, c) {
            let host = self.sockets.as_ref().ok_or(NeedErr::Invalid)?;
            let (flags, alpn) = host.starttls(cx, c.0, tls).await?;
            res.set(0, flags);
            if let Err(error) = res.put0(&alpn) {
                self.close(cx, c, false).await;
                return Err(error);
            }
            return Ok(());
        }
        let _ = tls;
        self.lock().conn(cx, c).map(|_| res.set(0, 0))
    }
    async fn write(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        bytes: &[u8],
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let n = self.write_answer(cx, c, bytes).await?;
        res.set(n, 0);
        Ok(())
    }
    async fn read(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        max: u32,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let read = self.read_answer(cx, c, max).await?;
        if let Err(error) = res.put0(read.bytes.as_slice()) {
            self.close(cx, c, false).await;
            return Err(error);
        }
        res.set(
            u64::try_from(read.bytes.len()).map_err(|_| NeedErr::Limit)?,
            u64::from(read.eof),
        );
        Ok(())
    }
    async fn close(&self, cx: &Caller<'_>, c: ConnId, reusable: bool) {
        let _ = reusable;
        let mut state = self.lock();
        #[cfg(feature = "target-sockets")]
        if state.socket_routes.remove(&(cx.instance, cx.chain, c.0)) {
            if let Some(host) = &self.sockets {
                host.close(cx, c.0, reusable);
            }
            return;
        }
        state.live.remove(&(cx.instance, cx.chain, c.0));
    }

    async fn fetch(
        &self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let answer = self.lock().fetch(cx, n)?;
        match answer {
            FetchReply::Ready {
                status,
                headers,
                body,
            } => {
                res.set(u64::from(status), 0);
                res.put0(&body)?;
                for (name, value) in &headers {
                    res.pair1(name, value)?;
                }
                Ok(())
            }
            FetchReply::Park(script) => script.run(n).await,
        }
    }

    fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let value = usize::try_from(handle)
            .ok()
            .and_then(|handle| handle.checked_sub(1))
            .and_then(|at| self.lock().secrets.get(at).map(|(_, value)| value.clone()));
        let answer = match value {
            Some(value) => {
                // Register, then publish (custody's order, §12.2 step 5): the scrub set masks the value before
                // the plugin holds it.
                let scrub_of = self
                    .scrubs
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                if let Some(scrub) = scrub_of.and_then(|scrub_of| scrub_of(cx.slot)) {
                    scrub.register(handle, &[value.as_slice()]);
                }
                res.put0(&value)
            }
            None => Err(NeedErr::Denied),
        };
        ready(answer)
    }

    fn record(
        &self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let answer = self.lock().record(cx, n, res);
        ready(answer)
    }

    /// No `provisioning:` block exists for a fixture instance, so DIRECTORY is denied (§12.29).
    fn directory(
        &self,
        cx: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let _ = (cx, n, res);
        ready(Err(NeedErr::Denied))
    }

    fn release(&self, cx: &Caller<'_>) {
        let mut state = self.lock();
        state
            .live
            .retain(|(instance, chain, _), _| !(*instance == cx.instance && *chain == cx.chain));
        #[cfg(feature = "target-sockets")]
        {
            state
                .socket_routes
                .retain(|(i, c, _)| !(*i == cx.instance && *c == cx.chain));
            if let Some(host) = &self.sockets {
                host.release(cx);
            }
        }
        state.released += 1;
    }
}

pub(crate) struct OpenAnswer {
    pub id: u64,
    pub pooled: u64,
    pub flags: u64,
    pub alpn: Vec<u8>,
}
pub(crate) struct ReadAnswer {
    pub bytes: busbar_contract::secure::SecureVec,
    pub eof: bool,
}

impl FakeNeeds {
    #[cfg(feature = "target-sockets")]
    pub fn with_sockets(
        mut self,
        targets: crate::sockets::SocketTargets,
    ) -> Result<Self, crate::sockets::ConfigError> {
        if self.sockets.is_some()
            || self
                .lock()
                .conns
                .keys()
                .any(|dest| targets.contains_dest(dest))
        {
            return Err(crate::sockets::ConfigError::Overlap);
        }
        self.sockets = Some(targets);
        Ok(self)
    }
    #[cfg(feature = "target-sockets")]
    pub fn socket_report(&self) -> Option<&crate::sockets::SocketTargets> {
        self.sockets.as_ref()
    }
    #[cfg(feature = "target-sockets")]
    fn socket_route(&self, cx: &Caller<'_>, id: ConnId) -> bool {
        self.lock()
            .socket_routes
            .contains(&(cx.instance, cx.chain, id.0))
    }
    #[cfg(feature = "target-sockets")]
    pub(crate) fn bind_sockets(
        &self,
        instance: u64,
        bindings: crate::sockets::Bindings,
    ) -> Result<(), crate::sockets::ConfigError> {
        if let Some(host) = &self.sockets {
            host.bind(instance, bindings)?;
        }
        Ok(())
    }
    #[cfg(feature = "target-sockets")]
    pub(crate) fn unbind_sockets(&self, instance: u64) {
        if let Some(host) = &self.sockets {
            host.unbind(instance);
        }
    }
    pub(crate) async fn open_answer(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
    ) -> Result<OpenAnswer, NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        if std::time::Instant::now() >= cx.deadline {
            return Err(NeedErr::Timeout);
        }
        {
            let mut state = self.lock();
            #[cfg(test)]
            state.open_limits.push((cx.name.to_owned(), cx.limits));
            state.seen.push(Seen {
                op: "open",
                dest: n.dest.to_owned(),
                tls: !matches!(n.tls, TlsMode::None),
                egress: n.egress,
            });
            if state.denies(n.dest) {
                return Err(NeedErr::Denied);
            }
        }
        #[cfg(feature = "target-sockets")]
        if let Some(host) = &self.sockets {
            if host.contains_dest(n.dest) {
                let (id, opening) = {
                    let mut state = self.lock();
                    if state.conns.contains_key(n.dest) || !host.configured(cx.name, n.dest) {
                        return Err(NeedErr::Denied);
                    }
                    let id = mint(&mut state.next_conn, cx.instance)?;
                    let pooled = mint(&mut state.next_pooled, cx.instance)?;
                    let opening = host.prepare(cx, n, id, pooled)?;
                    state.socket_routes.insert((cx.instance, cx.chain, id));
                    (id, opening)
                };
                let mut pending = SocketRoute {
                    host: self,
                    key: (cx.instance, cx.chain, id),
                    keep: false,
                };
                let answer = opening.run().await?;
                let state = self.lock();
                if !state.socket_routes.contains(&pending.key) {
                    host.close(cx, id, false);
                    return Err(NeedErr::Closed);
                }
                pending.keep = true;
                return Ok(answer);
            }
        }
        self.lock().open_script(cx, n)
    }
    pub(crate) async fn write_answer(
        &self,
        cx: &Caller<'_>,
        id: ConnId,
        bytes: &[u8],
    ) -> Result<u64, NeedErr> {
        #[cfg(feature = "target-sockets")]
        if self.socket_route(cx, id) {
            return self
                .sockets
                .as_ref()
                .ok_or(NeedErr::Invalid)?
                .write(cx, id.0, bytes)
                .await;
        }
        self.lock().conn(cx, id)?.wrote(bytes)?;
        u64::try_from(bytes.len()).map_err(|_| NeedErr::Limit)
    }
    pub(crate) async fn read_answer(
        &self,
        cx: &Caller<'_>,
        id: ConnId,
        max: u32,
    ) -> Result<ReadAnswer, NeedErr> {
        #[cfg(feature = "target-sockets")]
        if self.socket_route(cx, id) {
            return self
                .sockets
                .as_ref()
                .ok_or(NeedErr::Invalid)?
                .read(cx, id.0, max)
                .await;
        }
        let read = self
            .lock()
            .conn(cx, id)?
            .read(usize::try_from(max).map_err(|_| NeedErr::Limit)?)?;
        Ok(match read {
            Read::Bytes(bytes) => ReadAnswer {
                bytes: bytes.into(),
                eof: false,
            },
            Read::Eof => ReadAnswer {
                bytes: busbar_contract::secure::SecureVec::new(),
                eof: true,
            },
        })
    }
}
#[cfg(feature = "target-sockets")]
struct SocketRoute<'a> {
    host: &'a FakeNeeds,
    key: (u64, u64, u64),
    keep: bool,
}
#[cfg(feature = "target-sockets")]
impl Drop for SocketRoute<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.host.lock().socket_routes.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_replays_expect_and_reply_in_order() {
        let mut script = ConnScript::new()
            .expect(b"PING\r\n")
            .reply(b"+PONG\r\n")
            .eof();
        assert_eq!(script.read(64), Err(NeedErr::Timeout));
        assert_eq!(script.wrote(b"PI"), Ok(()));
        assert_eq!(script.wrote(b"NG\r\n"), Ok(()));
        assert_eq!(script.read(3), Ok(Read::Bytes(b"+PO".to_vec())));
        assert_eq!(script.read(64), Ok(Read::Bytes(b"NG\r\n".to_vec())));
        assert_eq!(script.read(64), Ok(Read::Eof));
        assert_eq!(script.read(64), Ok(Read::Eof));
    }

    #[test]
    fn a_wrong_or_extra_write_is_invalid_and_a_reset_closes() {
        let mut script = ConnScript::new().expect(b"AB").reset();
        assert_eq!(script.wrote(b"AC"), Err(NeedErr::Invalid));
        let mut script = ConnScript::new().expect(b"AB").expect(b"CD").reset();
        assert_eq!(script.wrote(b"ABC"), Ok(()));
        assert_eq!(script.wrote(b"DE"), Err(NeedErr::Closed));
        assert_eq!(script.read(1), Err(NeedErr::Closed));
        let mut spent = ConnScript::new();
        assert_eq!(spent.wrote(b"x"), Err(NeedErr::Invalid));
        assert_eq!(spent.read(0), Err(NeedErr::Invalid));
    }

    /// C-POOL-STATE (a), the FakeNeeds side (round 19): ids per instance start at 1 and never repeat.
    #[test]
    fn ids_are_minted_per_instance_from_one_and_never_repeat() {
        let mut ids = BTreeMap::new();
        assert_eq!(mint(&mut ids, 7), Ok(1));
        assert_eq!(mint(&mut ids, 9), Ok(1));
        let mut last = 1;
        for _ in 0..10_000 {
            let id = mint(&mut ids, 7).unwrap();
            assert!(id > last);
            last = id;
        }
    }

    #[test]
    fn deny_and_the_endpoint_match_compare_hosts() {
        assert_eq!(host_of("db.test:5432"), "db.test");
        assert_eq!(host_of("https://user:pw@api.test:8443/v1?x=1"), "api.test");
        assert_eq!(host_of("[::1]:6379"), "::1");
        assert_eq!(host_of("unix:/run/x.sock"), "unix:/run/x.sock");
        let mut needs = FakeNeeds::new();
        needs.deny("https://169.254.169.254/latest");
        let state = needs.state();
        assert!(state.denies("169.254.169.254:80"));
        assert!(!state.denies("api.test:443"));
        state.seen.push(Seen {
            op: "open",
            dest: "db.test:5432".to_owned(),
            tls: true,
            egress: 0,
        });
        state.seen.push(Seen {
            op: "fetch",
            dest: "http://api.test/x".to_owned(),
            tls: false,
            egress: 0,
        });
        let undeclared = needs.undeclared(&[("db.test:5432", true), ("api.test:443", true)]);
        assert_eq!(undeclared.len(), 1);
        assert_eq!(undeclared[0].dest, "http://api.test/x");
    }
}
