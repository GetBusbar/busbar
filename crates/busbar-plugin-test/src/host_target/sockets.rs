// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit loopback I/O for the safe SDK host. This is not the production connector.
use std::collections::HashMap;
use std::future::Future;
use std::net::{Shutdown, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::crypto::tls;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{NeedErr, OpenNeed, TlsMode};
use busbar_plugin_abi::need::open_flag;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;

use crate::fake_needs::{OpenAnswer, ReadAnswer};

/// Explicit per-target budgets; no production defaults are inferred.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub connect: Duration,
    pub io: Duration,
    pub live: usize,
    pub idle: usize,
    pub idle_lifetime: Duration,
    pub read: usize,
}
#[derive(Clone, Debug)]
pub enum TrustSource {
    Bound { pointer: String },
    Explicit { roots_pem: String },
}
#[derive(Clone, Debug)]
pub struct ClientSource {
    pub pointer: String,
}
#[derive(Clone, Debug)]
pub struct TlsProfile {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub trust: TrustSource,
    pub client: Option<ClientSource>,
}
#[derive(Clone, Debug)]
pub enum Security {
    Plaintext,
    Tls(TlsProfile),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Limits,
    Address,
    Duplicate,
    Tls,
    Overlap,
    Finished,
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socket target configuration: {self:?}")
    }
}
impl std::error::Error for ConfigError {}

/// A network lifecycle observation, never credentials or protocol bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketEvent {
    pub instance: u64,
    pub chain: u64,
    pub connection: u64,
    pub pooled: u64,
    pub destination: SocketAddr,
    pub outcome: SocketOutcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOutcome {
    Fresh,
    Reused,
    Closed,
    Released,
    Cancelled,
    Unbound,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    instance: u64,
    generation: u64,
    addr: SocketAddr,
    mode: u8,
    sni: String,
    alpn: String,
    trust: u32,
    cert: Option<u32>,
    egress: u32,
}
type Owner = (u64, u64, u64);
struct Binding {
    generation: u64,
    trusts: HashMap<String, (u32, String)>,
    clients: HashMap<String, (u32, SecureVec)>,
}
/// Concrete declared paths and their instance-scoped handles, supplied by MemBinder.
pub(crate) struct Bindings {
    pub trusts: Vec<(String, u32, String)>,
    pub clients: Vec<(String, u32, SecureVec)>,
}
struct Entry {
    revoked: AtomicBool,
    notify: Notify,
    shutdown: Mutex<Option<std::net::TcpStream>>,
    count: Arc<AtomicUsize>,
}
impl Entry {
    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        if let Some(socket) = lock(&self.shutdown).as_ref() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.notify.notify_waiters();
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}
enum Wire {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
struct Connection {
    wire: Wire,
    key: PoolKey,
    pooled: u64,
    alpn: Vec<u8>,
    flags: u64,
}
struct Slot {
    destination: SocketAddr,
    pooled: u64,
    entry: Arc<Entry>,
    conn: Option<Connection>,
}
struct Idle {
    entry: Arc<Entry>,
    conn: Connection,
    since: Instant,
}
#[derive(Default)]
struct State {
    events: Vec<SocketEvent>,
    slots: HashMap<Owner, Slot>,
    idle: Vec<Idle>,
    bindings: HashMap<u64, Binding>,
    generation: u64,
    failures: HashMap<&'static str, usize>,
    expected: HashMap<&'static str, usize>,
    finished: bool,
}
/// A finite, explicitly authorized set of loopback database endpoints.
pub struct SocketTargets {
    limits: Limits,
    targets: HashMap<(String, SocketAddr), Security>,
    state: Mutex<State>,
    count: Arc<AtomicUsize>,
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
impl SocketTargets {
    pub fn new(limits: Limits) -> Result<Self, ConfigError> {
        if limits.live == 0
            || limits.idle == 0
            || limits.read == 0
            || limits.connect.is_zero()
            || limits.io.is_zero()
            || limits.idle_lifetime.is_zero()
            || [limits.connect, limits.io, limits.idle_lifetime]
                .iter()
                .any(|d| Instant::now().checked_add(*d).is_none())
        {
            return Err(ConfigError::Limits);
        }
        Ok(Self {
            limits,
            targets: HashMap::new(),
            state: Mutex::new(State::default()),
            count: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub fn allow(
        &mut self,
        instance: &str,
        addr: SocketAddr,
        security: Security,
    ) -> Result<&mut Self, ConfigError> {
        if instance.is_empty() || !addr.ip().to_canonical().is_loopback() || addr.port() == 0 {
            return Err(ConfigError::Address);
        }
        if let Security::Tls(profile) = &security {
            ServerName::try_from(profile.server_name.clone()).map_err(|_| ConfigError::Tls)?;
            if profile
                .alpn
                .iter()
                .any(|p| p.is_empty() || p.len() > usize::from(u8::MAX) || p.contains(','))
            {
                return Err(ConfigError::Tls);
            }
            if let TrustSource::Explicit { roots_pem } = &profile.trust {
                roots(roots_pem).map_err(|_| ConfigError::Tls)?;
            }
        }
        let key = (instance.to_owned(), addr);
        if self.targets.contains_key(&key) {
            return Err(ConfigError::Duplicate);
        }
        self.targets.insert(key, security);
        Ok(self)
    }
    pub(crate) fn wants_trust(&self, pointer: &str) -> bool {
        self.targets.values().any(|security|matches!(security,Security::Tls(TlsProfile{trust:TrustSource::Bound{pointer:p},..}) if p==pointer))
    }
    pub(crate) fn wants_client(&self, pointer: &str) -> bool {
        self.targets.values().any(|security|matches!(security,Security::Tls(TlsProfile{client:Some(ClientSource{pointer:p}),..}) if p==pointer))
    }
    pub(crate) fn contains_dest(&self, dest: &str) -> bool {
        dest.parse::<SocketAddr>()
            .ok()
            .is_some_and(|addr| self.targets.keys().any(|(_, a)| *a == addr))
    }
    pub(crate) fn configured(&self, name: &str, dest: &str) -> bool {
        dest.parse::<SocketAddr>()
            .ok()
            .is_some_and(|addr| self.targets.contains_key(&(name.to_owned(), addr)))
    }
    pub(crate) fn failure(&self, category: &'static str) {
        *lock(&self.state).failures.entry(category).or_default() += 1;
    }
    /// Snapshot the socket lifecycle; this target never reports kernel coverage.
    pub fn events(&self) -> Vec<SocketEvent> {
        lock(&self.state).events.clone()
    }
    pub fn subject(&self) -> &'static str {
        "host target; kernel not present"
    }
    pub fn expect_failure(&self, category: &'static str, count: usize) {
        *lock(&self.state).expected.entry(category).or_default() += count;
    }
    pub fn finish(&self) -> Result<(), ConfigError> {
        let mut s = lock(&self.state);
        if !s.slots.is_empty()
            || self.count.load(Ordering::Acquire) != s.idle.len()
            || s.failures != s.expected
        {
            return Err(ConfigError::Finished);
        }
        s.idle.clear();
        s.finished = true;
        Ok(())
    }
    pub(crate) fn bind(&self, instance: u64, values: Bindings) -> Result<(), ConfigError> {
        for (_, _, pem) in &values.trusts {
            roots(pem).map_err(|_| ConfigError::Tls)?;
        }
        for (_, _, pem) in &values.clients {
            let chain = CertificateDer::pem_slice_iter(pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ConfigError::Tls)?;
            if chain.is_empty() {
                return Err(ConfigError::Tls);
            }
            let _ = PrivateKeyDer::from_pem_slice(pem.as_slice()).map_err(|_| ConfigError::Tls)?;
        }
        let mut s = lock(&self.state);
        Self::revoke_instance(&mut s, instance);
        s.generation = s.generation.checked_add(1).ok_or(ConfigError::Limits)?;
        let generation = s.generation;
        s.bindings.insert(
            instance,
            Binding {
                generation,
                trusts: values
                    .trusts
                    .into_iter()
                    .map(|(p, h, v)| (p, (h, v)))
                    .collect(),
                clients: values
                    .clients
                    .into_iter()
                    .map(|(p, h, v)| (p, (h, v)))
                    .collect(),
            },
        );
        Ok(())
    }
    fn revoke_instance(s: &mut State, instance: u64) {
        let owners: Vec<_> = s
            .slots
            .keys()
            .filter(|(i, _, _)| *i == instance)
            .copied()
            .collect();
        for owner in owners {
            if let Some(slot) = s.slots.remove(&owner) {
                event(s, owner, &slot, SocketOutcome::Unbound);
                slot.entry.revoke();
            }
        }
        s.idle.retain(|idle| idle.conn.key.instance != instance);
    }
    pub(crate) fn unbind(&self, instance: u64) {
        let mut s = lock(&self.state);
        Self::revoke_instance(&mut s, instance);
        s.bindings.remove(&instance);
    }
    pub(crate) fn release(&self, cx: &Caller<'_>) {
        let mut s = lock(&self.state);
        let owners: Vec<_> = s
            .slots
            .keys()
            .filter(|(i, c, _)| *i == cx.instance && *c == cx.chain)
            .copied()
            .collect();
        for owner in owners {
            if let Some(slot) = s.slots.remove(&owner) {
                event(&mut s, owner, &slot, SocketOutcome::Released);
                slot.entry.revoke();
            }
        }
    }
    fn deadline(&self, cx: &Caller<'_>, phase: Duration) -> Result<Instant, NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        let now = Instant::now();
        if now >= cx.deadline {
            return Err(NeedErr::Timeout);
        }
        Ok(cx
            .deadline
            .min(now.checked_add(phase).ok_or(NeedErr::Invalid)?))
    }
    fn plan(
        &self,
        cx: &Caller<'_>,
        n: &OpenNeed<'_>,
    ) -> Result<(PoolKey, Option<Arc<rustls::ClientConfig>>), NeedErr> {
        let addr = n.dest.parse::<SocketAddr>().map_err(|_| NeedErr::Denied)?;
        let security = self
            .targets
            .get(&(cx.name.to_owned(), addr))
            .ok_or(NeedErr::Denied)?;
        let (mode, sni, alpn, trust, cert) = tls_parts(n.tls);
        let s = lock(&self.state);
        if s.finished {
            return Err(NeedErr::Closed);
        }
        let binding = s.bindings.get(&cx.instance);
        let generation = binding.map_or(0, |b| b.generation);
        let key = PoolKey {
            instance: cx.instance,
            generation,
            addr,
            mode,
            sni: sni.into(),
            alpn: alpn.into(),
            trust,
            cert,
            egress: n.egress,
        };
        match security {
            Security::Plaintext if mode == 0 => Ok((key, None)),
            Security::Tls(profile) if mode != 0 => {
                if sni != profile.server_name || alpn != profile.alpn.join(",") {
                    return Err(NeedErr::Denied);
                }
                let pem = match &profile.trust {
                    TrustSource::Explicit { roots_pem } if trust == 0 => roots_pem,
                    TrustSource::Bound { pointer } => {
                        let (h, pem) = binding
                            .and_then(|b| b.trusts.get(pointer))
                            .ok_or(NeedErr::Denied)?;
                        if *h != trust || trust == 0 {
                            return Err(NeedErr::Denied);
                        }
                        pem
                    }
                    _ => return Err(NeedErr::Denied),
                };
                let roots = roots(pem)?;
                let identity = match (&profile.client, cert) {
                    (None, None) => None,
                    (Some(source), Some(handle)) if handle != 0 => {
                        let (h, pem) = binding
                            .and_then(|b| b.clients.get(&source.pointer))
                            .ok_or(NeedErr::Denied)?;
                        if *h != handle {
                            return Err(NeedErr::Denied);
                        }
                        let chain = CertificateDer::pem_slice_iter(pem.as_slice())
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| NeedErr::Tls)?;
                        let key = PrivateKeyDer::from_pem_slice(pem.as_slice())
                            .map_err(|_| NeedErr::Tls)?;
                        Some((chain, key))
                    }
                    _ => return Err(NeedErr::Denied),
                };
                let protocols: Vec<Vec<u8>> =
                    profile.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
                let config = tls::client_config(move |builder| {
                    let builder = builder.with_root_certificates(roots);
                    let mut config = match identity {
                        Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
                        None => builder.with_no_client_auth(),
                    };
                    config.alpn_protocols = protocols;
                    Ok(config)
                })
                .map_err(|_| NeedErr::Tls)?;
                Ok((key, Some(config)))
            }
            _ => Err(NeedErr::Denied),
        }
    }
    pub(crate) fn prepare(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        id: u64,
        pooled: u64,
    ) -> Result<Opening<'_>, NeedErr> {
        let deadline = self.deadline(cx, self.limits.connect)?;
        let (key, config) = self.plan(cx, &n)?;
        let owner = (cx.instance, cx.chain, id);
        let (entry, conn, reused) = {
            let mut s = lock(&self.state);
            s.idle
                .retain(|i| i.since.elapsed() < self.limits.idle_lifetime);
            if let Some(at) = s.idle.iter().position(|i| i.conn.key == key) {
                let idle = s.idle.swap_remove(at);
                (idle.entry, Some(idle.conn), true)
            } else {
                if self.count.load(Ordering::Acquire) >= self.limits.live {
                    return Err(NeedErr::Limit);
                }
                self.count.fetch_add(1, Ordering::AcqRel);
                (
                    Arc::new(Entry {
                        revoked: AtomicBool::new(false),
                        notify: Notify::new(),
                        shutdown: Mutex::new(None),
                        count: Arc::clone(&self.count),
                    }),
                    None,
                    false,
                )
            }
        };
        let lease = Lease {
            host: self,
            owner,
            entry: Arc::clone(&entry),
            conn,
            committed: false,
        };
        {
            let mut s = lock(&self.state);
            // A binding change between planning and reservation invalidates the plan.
            if s.bindings.get(&cx.instance).map_or(0, |b| b.generation) != key.generation {
                return Err(NeedErr::Closed);
            }
            if s.slots.contains_key(&owner) {
                return Err(NeedErr::Invalid);
            }
            s.slots.insert(
                owner,
                Slot {
                    destination: key.addr,
                    pooled: lease.conn.as_ref().map_or(pooled, |c| c.pooled),
                    entry: Arc::clone(&entry),
                    conn: None,
                },
            );
        }
        Ok(Opening {
            lease,
            key,
            config,
            deadline,
            reused,
            id,
            pooled,
        })
    }
    fn take(&self, cx: &Caller<'_>, id: u64) -> Result<Lease<'_>, NeedErr> {
        let owner = (cx.instance, cx.chain, id);
        let mut s = lock(&self.state);
        let slot = s.slots.get_mut(&owner).ok_or(NeedErr::Invalid)?;
        let conn = slot.conn.take().ok_or(NeedErr::Invalid)?;
        Ok(Lease {
            host: self,
            owner,
            entry: Arc::clone(&slot.entry),
            conn: Some(conn),
            committed: false,
        })
    }
    pub(crate) async fn write(
        &self,
        cx: &Caller<'_>,
        id: u64,
        bytes: &[u8],
    ) -> Result<u64, NeedErr> {
        let deadline = self.deadline(cx, self.limits.io)?;
        let mut lease = self.take(cx, id)?;
        let entry = Arc::clone(&lease.entry);
        let conn = lease.conn.as_mut().ok_or(NeedErr::Closed)?;
        let result = match &mut conn.wire {
            Wire::Plain(stream) => wait(&entry, deadline, stream.write_all(bytes)).await?,
            Wire::Tls(stream) => wait(&entry, deadline, stream.write_all(bytes)).await?,
        };
        result.map_err(|_| NeedErr::Closed)?;
        lease.commit()?;
        u64::try_from(bytes.len()).map_err(|_| NeedErr::Limit)
    }
    pub(crate) async fn read(
        &self,
        cx: &Caller<'_>,
        id: u64,
        max: u32,
    ) -> Result<ReadAnswer, NeedErr> {
        let deadline = self.deadline(cx, self.limits.io)?;
        let max = usize::try_from(max).map_err(|_| NeedErr::Limit)?;
        if max == 0 || max > self.limits.read {
            return Err(NeedErr::Limit);
        }
        let mut lease = self.take(cx, id)?;
        let entry = Arc::clone(&lease.entry);
        let conn = lease.conn.as_mut().ok_or(NeedErr::Closed)?;
        let mut bytes = SecureVec::zeroed(max);
        let n = match &mut conn.wire {
            Wire::Plain(stream) => wait(&entry, deadline, stream.read(&mut bytes[..])).await?,
            Wire::Tls(stream) => wait(&entry, deadline, stream.read(&mut bytes[..])).await?,
        }
        .map_err(|_| NeedErr::Closed)?;
        bytes.truncate(n);
        if n != 0 {
            lease.commit()?;
        }
        Ok(ReadAnswer { bytes, eof: n == 0 })
    }
    pub(crate) async fn starttls(
        &self,
        cx: &Caller<'_>,
        id: u64,
        tls: TlsMode<'_>,
    ) -> Result<(u64, Vec<u8>), NeedErr> {
        let deadline = self.deadline(cx, self.limits.connect)?;
        let mut lease = self.take(cx, id)?;
        let conn = lease.conn.take().ok_or(NeedErr::Closed)?;
        let (mode, sni, alpn, trust, cert) = tls_parts(tls);
        if conn.key.mode != 3
            || !(mode == 1 || mode == 2)
            || sni != conn.key.sni
            || alpn != conn.key.alpn
            || trust != conn.key.trust
            || cert != conn.key.cert
        {
            return Err(NeedErr::Invalid);
        }
        let Wire::Plain(stream) = conn.wire else {
            return Err(NeedErr::Invalid);
        };
        let dest = conn.key.addr.to_string();
        let (_, config) = self.plan(
            cx,
            &OpenNeed {
                dest: &dest,
                tls,
                egress: conn.key.egress,
            },
        )?;
        let (wire, alpn, flags) = handshake(
            &lease.entry,
            deadline,
            stream,
            &conn.key,
            config.ok_or(NeedErr::Tls)?,
        )
        .await?;
        lease.conn = Some(Connection {
            wire,
            key: conn.key,
            pooled: conn.pooled,
            alpn: alpn.clone(),
            flags,
        });
        lease.commit()?;
        Ok((flags, alpn))
    }
    pub(crate) fn close(&self, cx: &Caller<'_>, id: u64, reusable: bool) {
        let mut s = lock(&self.state);
        let Some(slot) = s.slots.remove(&(cx.instance, cx.chain, id)) else {
            return;
        };
        if reusable
            && !slot.entry.revoked.load(Ordering::Acquire)
            && s.idle.len() < self.limits.idle
        {
            if let Some(conn) = slot.conn {
                if conn.key.mode != 3 || matches!(conn.wire, Wire::Tls(_)) {
                    s.idle.push(Idle {
                        entry: slot.entry,
                        conn,
                        since: Instant::now(),
                    });
                    return;
                }
            }
        }
        slot.entry.revoke();
    }
}
impl Drop for SocketTargets {
    fn drop(&mut self) {
        let s = lock(&self.state);
        for slot in s.slots.values() {
            slot.entry.revoke();
        }
        let fail = !s.finished
            && (!s.slots.is_empty()
                || s.failures != s.expected
                || self.count.load(Ordering::Acquire) > s.idle.len());
        drop(s);
        if fail && !std::thread::panicking() {
            panic!("socket host target unfinished or unserved");
        }
    }
}
struct Lease<'a> {
    host: &'a SocketTargets,
    owner: Owner,
    entry: Arc<Entry>,
    conn: Option<Connection>,
    committed: bool,
}
impl Lease<'_> {
    fn commit(&mut self) -> Result<(), NeedErr> {
        let mut s = lock(&self.host.state);
        let slot = s
            .slots
            .get_mut(&self.owner)
            .filter(|slot| Arc::ptr_eq(&slot.entry, &self.entry))
            .ok_or(NeedErr::Closed)?;
        if self.entry.revoked.load(Ordering::Acquire) {
            return Err(NeedErr::Closed);
        }
        slot.conn = self.conn.take();
        self.committed = true;
        Ok(())
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let mut s = lock(&self.host.state);
            if s.slots
                .get(&self.owner)
                .is_some_and(|slot| Arc::ptr_eq(&slot.entry, &self.entry))
            {
                if let Some(slot) = s.slots.remove(&self.owner) {
                    event(&mut s, self.owner, &slot, SocketOutcome::Cancelled);
                }
            }
            self.entry.revoke();
            drop(self.conn.take());
        }
    }
}
async fn wait<T>(
    entry: &Entry,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, NeedErr> {
    let notified = entry.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if entry.revoked.load(Ordering::Acquire) {
        return Err(NeedErr::Closed);
    }
    tokio::select! { biased;
        _=&mut notified=>Err(NeedErr::Closed),
        result=tokio::time::timeout_at(deadline.into(),future)=>result.map_err(|_|NeedErr::Timeout),
    }
}
fn tls_parts(tls: TlsMode<'_>) -> (u8, &str, &str, u32, Option<u32>) {
    match tls {
        TlsMode::None => (0, "", "", 0, None),
        TlsMode::Required { sni, alpn, trust } => (1, sni, alpn, trust, None),
        TlsMode::Mutual {
            sni,
            alpn,
            trust,
            cert,
        } => (2, sni, alpn, trust, Some(cert)),
        TlsMode::Inband {
            sni,
            alpn,
            trust,
            cert,
        } => (3, sni, alpn, trust, cert),
    }
}
fn roots(pem: &str) -> Result<rustls::RootCertStore, NeedErr> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots
            .add(cert.map_err(|_| NeedErr::Tls)?)
            .map_err(|_| NeedErr::Tls)?;
    }
    if roots.is_empty() {
        return Err(NeedErr::Tls);
    }
    Ok(roots)
}
async fn handshake(
    entry: &Entry,
    deadline: Instant,
    stream: TcpStream,
    key: &PoolKey,
    config: Arc<rustls::ClientConfig>,
) -> Result<(Wire, Vec<u8>, u64), NeedErr> {
    let name = ServerName::try_from(key.sni.clone()).map_err(|_| NeedErr::Tls)?;
    let stream = wait(
        entry,
        deadline,
        TlsConnector::from(config).connect(name, stream),
    )
    .await?
    .map_err(|_| NeedErr::Tls)?;
    let (_, session) = stream.get_ref();
    let alpn = session.alpn_protocol().unwrap_or_default().to_vec();
    if !key.alpn.is_empty() && !key.alpn.split(',').any(|p| p.as_bytes() == alpn) {
        return Err(NeedErr::Tls);
    }
    let flags = if session.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
        open_flag::TLS_RESUMED
    } else {
        0
    };
    Ok((Wire::Tls(Box::new(stream)), alpn, flags))
}

pub(crate) struct Opening<'a> {
    lease: Lease<'a>,
    key: PoolKey,
    config: Option<Arc<rustls::ClientConfig>>,
    deadline: Instant,
    reused: bool,
    id: u64,
    pooled: u64,
}
impl Opening<'_> {
    pub(crate) async fn run(self) -> Result<OpenAnswer, NeedErr> {
        let Opening {
            mut lease,
            key,
            config,
            deadline,
            reused,
            id,
            pooled,
        } = self;
        let entry = Arc::clone(&lease.entry);
        if !reused {
            let stream = wait(&entry, deadline, TcpStream::connect(key.addr))
                .await?
                .map_err(|_| NeedErr::Unavailable)?;
            let native = stream.into_std().map_err(|_| NeedErr::Unavailable)?;
            *lock(&entry.shutdown) = Some(native.try_clone().map_err(|_| NeedErr::Unavailable)?);
            if entry.revoked.load(Ordering::Acquire) {
                entry.revoke();
                return Err(NeedErr::Closed);
            }
            let stream = TcpStream::from_std(native).map_err(|_| NeedErr::Unavailable)?;
            let (wire, alpn, flags) = if key.mode == 1 || key.mode == 2 {
                handshake(&entry, deadline, stream, &key, config.ok_or(NeedErr::Tls)?).await?
            } else {
                (Wire::Plain(stream), Vec::new(), 0)
            };
            lease.conn = Some(Connection {
                wire,
                key,
                pooled,
                alpn,
                flags,
            });
        }
        let c = lease.conn.as_ref().ok_or(NeedErr::Closed)?;
        let mut flags = c.flags;
        if reused {
            flags |= open_flag::REUSED;
            if c.key.mode == 3 {
                flags |= open_flag::TLS_DONE;
            }
        }
        let answer = OpenAnswer {
            id,
            pooled: c.pooled,
            flags,
            alpn: c.alpn.clone(),
        };
        lease.commit()?;
        {
            let mut s = lock(&lease.host.state);
            if let Some(slot) = s.slots.get(&lease.owner) {
                let e = SocketEvent {
                    instance: lease.owner.0,
                    chain: lease.owner.1,
                    connection: lease.owner.2,
                    pooled: slot.pooled,
                    destination: slot.destination,
                    outcome: if reused {
                        SocketOutcome::Reused
                    } else {
                        SocketOutcome::Fresh
                    },
                };
                s.events.push(e);
            }
        }
        Ok(answer)
    }
}

fn event(s: &mut State, owner: Owner, slot: &Slot, outcome: SocketOutcome) {
    s.events.push(SocketEvent {
        instance: owner.0,
        chain: owner.1,
        connection: owner.2,
        pooled: slot.pooled,
        destination: slot.destination,
        outcome,
    });
}
