// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `FakeNeeds` and `ConnScript` (ABI-MIN3-INTERFACE §14): a scriptable `Needs` for plugin CI. Canned conns
//! (byte scripts), fetch answers, secrets and records; the kernel answers a plane suite scripts (grants,
//! rendezvous, issued credentials, channels, trust verdicts, observation statuses) are held for the suite.
//!
//! Every Need is answered synchronously from the script under one lock and handed back as a ready future, so a
//! chain never parks here and the future is `Send` whatever the arguments are. Conns are keyed by
//! `(instance, chain, conn id)` as the connector keys them (§13), so `release` closes only its own chain's conns;
//! conn ids and pooled-conn ids are minted per instance from 1 and never repeat (C-POOL-STATE (a), round 19).
//! Every OPEN and FETCH is recorded, so a suite can hold them against the ENDPOINTs a plugin's `check` declared
//! (TRANSPORT-SECURITY-POLICY §2, [`FakeNeeds::undeclared`]).

use core::future::{ready, Future};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, Needs, OpenNeed, RecordNeed, TlsMode,
};

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
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

#[derive(Default)]
struct State {
    conns: BTreeMap<String, VecDeque<ConnScript>>,
    fetches: Vec<Fetch>,
    secrets: Vec<(String, Vec<u8>)>,
    denied: Vec<String>,
    kernel: Kernel,
    live: BTreeMap<(u64, u64, u64), ConnScript>,
    next_conn: BTreeMap<u64, u64>,
    next_pooled: BTreeMap<u64, u64>,
    records: BTreeMap<(String, String, Vec<u8>), Vec<u8>>,
    seen: Vec<Seen>,
    released: u64,
}

/// A scriptable `Needs` for plugin CI (IF §14). Suites run `Registry<FakeNeeds>`.
#[derive(Default)]
pub struct FakeNeeds {
    state: Mutex<State>,
}

/// The next id in `ids` for `instance`: 1, 2, 3, ... per instance, never repeated.
fn mint(ids: &mut BTreeMap<u64, u64>, instance: u64) -> u64 {
    let next = ids.entry(instance).or_insert(0);
    *next += 1;
    *next
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

    fn state(&mut self) -> &mut State {
        self.state.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One more conn for OPENs to `dest` (`host:port` or `unix:<path>`): each OPEN takes the next script queued
    /// for its dest; an OPEN with none left answers `Unavailable`.
    pub fn conn(&mut self, dest: &str, script: ConnScript) -> &mut Self {
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
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
                .collect(),
            body: body.to_vec(),
        };
        self.state().fetches.push(fetch);
        self
    }

    /// The value custody returns for the secret the operator config holds at `pointer` (the suite binds the
    /// config, so the plugin only ever sees the handle). Handles are numbered from 1 in the order of these calls,
    /// the order the suite binds the pointers in.
    pub fn secret(&mut self, pointer: &str, value: &[u8]) -> &mut Self {
        self.state()
            .secrets
            .push((pointer.to_owned(), value.to_vec()));
        self
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

    fn open(
        &mut self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        self.seen.push(Seen {
            op: "open",
            dest: n.dest.to_owned(),
            tls: !matches!(n.tls, TlsMode::None),
            egress: n.egress,
        });
        if self.denies(n.dest) {
            return Err(NeedErr::Denied);
        }
        let script = self
            .conns
            .get_mut(n.dest)
            .and_then(VecDeque::pop_front)
            .ok_or(NeedErr::Unavailable)?;
        let id = mint(&mut self.next_conn, cx.instance);
        let pooled = mint(&mut self.next_pooled, cx.instance);
        self.live.insert((cx.instance, cx.chain, id), script);
        res.set(id, 0);
        res.put1(&pooled.to_le_bytes())
    }

    fn fetch(
        &mut self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
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
        let answer = self.fetches.remove(at);
        res.set(u64::from(answer.status), 0);
        res.put0(&answer.body)?;
        for (name, value) in &answer.headers {
            res.pair1(name, value)?;
        }
        Ok(())
    }

    fn record(
        &mut self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let at = |key: &[u8]| (cx.plugin.to_owned(), cx.name.to_owned(), key.to_vec());
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
            // C-COMMIT runs over the kernel's own plugin records (§12.5, W1-K5), not over this double.
            RecordNeed::Commit(_) => return Err(NeedErr::Invalid),
        }
        Ok(())
    }
}

impl Needs for FakeNeeds {
    fn open(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let answer = self.lock().open(cx, n, res);
        ready(answer)
    }

    fn starttls(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        tls: TlsMode<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let _ = tls;
        let answer = self.lock().conn(cx, c).map(|_| res.set(0, 0));
        ready(answer)
    }

    fn write(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        bytes: &[u8],
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let mut state = self.lock();
        let wrote = state.conn(cx, c).and_then(|script| script.wrote(bytes));
        drop(state);
        let answer = wrote.map(|()| res.set(u64::try_from(bytes.len()).unwrap_or(u64::MAX), 0));
        ready(answer)
    }

    fn read(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        max: u32,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let mut state = self.lock();
        let step = state
            .conn(cx, c)
            .and_then(|script| script.read(usize::try_from(max).unwrap_or(usize::MAX)));
        drop(state);
        let answer = step.and_then(|read| match read {
            Read::Bytes(bytes) => {
                res.put0(&bytes)?;
                res.set(u64::try_from(bytes.len()).unwrap_or(u64::MAX), 0);
                Ok(())
            }
            Read::Eof => {
                res.set(0, 1);
                Ok(())
            }
        });
        ready(answer)
    }

    fn close(&self, cx: &Caller<'_>, c: ConnId, reusable: bool) -> impl Future<Output = ()> + Send {
        let _ = reusable;
        self.lock().live.remove(&(cx.instance, cx.chain, c.0));
        ready(())
    }

    fn fetch(
        &self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let answer = self.lock().fetch(cx, n, res);
        ready(answer)
    }

    fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        let _ = cx;
        let value = usize::try_from(handle)
            .ok()
            .and_then(|handle| handle.checked_sub(1))
            .and_then(|at| self.lock().secrets.get(at).map(|(_, value)| value.clone()));
        let answer = match value {
            Some(value) => res.put0(&value),
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
        state.released += 1;
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
        assert_eq!(mint(&mut ids, 7), 1);
        assert_eq!(mint(&mut ids, 9), 1);
        let mut last = 1;
        for _ in 0..10_000 {
            let id = mint(&mut ids, 7);
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
