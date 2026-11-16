// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEED HANDLERS (IF 13): `HostNeeds` implements `busbar_plugin_abi::host_side::needs::Needs`
//! over the connector's guard, the transport-security gate, the pool and the conn table.
//!
//! Every OPEN, STARTTLS and FETCH runs, in this order: the unix rules (1) to (3) when the dest is a
//! `unix:` path; the transport gate (`policy`, with the caller's core-held `Accept`) before the pool
//! lookup and before any DNS; the instance's unix-path binding check; the pool probe on a
//! [`key::NeedKey`] built from the owning instance, normalised dest,
//! `guard::judged_class(stated, configured)`, the effective SNI, the ALPN, the trust and
//! certificate digests and the `verify` bit; and only on a miss the judge (`judge`: name, DNS,
//! answer, the node's own ports), then the dial. Every refusal is `NeedErr::Denied` with no text
//! (I2), audited here with the full reason.
//!
//! The sockets, TLS and HTTP client are behind one seam, [`NeedIo`], so the policy above is the one
//! place a decision is made, whatever carries the bytes. The handlers never read
//! `destinations[].plaintext`, `plaintext_admitted`, `limits.plaintext` or `kind_default`, and
//! never take a plugin-requested unverified path: a TLS conn is verified unless the caller's
//! `Accept` waives it.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::SecretCustody;
use busbar_kernel::directory::PluginDirectory;
use busbar_kernel::plugin_config::{ConfigBinder, TrustAnchor};
use busbar_kernel::plugin_records::{CommitOutcome, PluginRecords, RecordsDenied, Scope};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, Needs, OpenNeed, RecordNeed, TlsMode,
};
use busbar_plugin_abi::need::need_flag::{TLS_INBAND, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED};
use busbar_plugin_abi::need::open_flag;
use busbar_plugin_abi::records::commit as commit_code;

use crate::guard::{judged_class, Resolve, SystemResolver};

pub mod certs;
pub mod commit;
pub mod exchange;
pub mod judge;
pub mod key;
pub mod net;
pub mod policy;
pub mod table;
pub mod tlsconf;
pub mod unix;

use certs::{custody_err, CertDigests};
use judge::{split_dest, split_url, Judge};
use key::{NeedKey, NeedPool, Pooled, Tls};
pub use net::ConnectorIo;
use policy::{admit_fetch, admit_open, Admit, Reported};
use table::{ConnTable, Held, PooledIds};
use unix::{names_unix, unix_rules};

/// The sizes a Need is held to (IF 13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedLimits {
    /// Conns one chain may hold at once.
    pub max_conns_per_chain: u32,
    /// The most one READ returns.
    pub max_read: u32,
    /// The most one FETCH body returns.
    pub max_fetch_body: u64,
    /// The most FETCH header bytes returned.
    pub max_fetch_headers: u32,
    /// The longest record value a RECORD Need carries either way.
    pub max_record_value: u32,
    /// The most hits a RECORD LIST returns.
    pub max_list: u32,
}

impl Default for NeedLimits {
    fn default() -> Self {
        NeedLimits {
            max_conns_per_chain: 8,
            max_read: 1 << 20,
            max_fetch_body: 16 << 20,
            max_fetch_headers: 64 << 10,
            max_record_value: 64 << 10,
            max_list: 1_000,
        }
    }
}

/// What one egress class allows a dial: how long to connect, how long one read or write may take,
/// and whether the instance's own trust anchor may be added to the class's roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialPolicy {
    /// The longest a connect may take (capped by `limits.connect_timeout_ms`).
    pub connect_timeout: Duration,
    /// The longest one read or write may take (capped by the chain's deadline).
    pub io_timeout: Duration,
    /// Whether `binder.trust(..)` may be added to the class's roots. The open-web class trusts the
    /// public roots only, so a non-zero `trust` there is `Denied`.
    pub extra_roots_allowed: bool,
}

/// The dial policy of an egress class (the judged one).
#[must_use]
fn dial_policy(class: u32) -> DialPolicy {
    DialPolicy {
        connect_timeout: Duration::from_secs(10),
        io_timeout: Duration::from_secs(30),
        extra_roots_allowed: class != busbar_plugin_abi::need::egress::OPEN_WEB,
    }
}

/// How a dialled conn is secured, as the handler decided it.
pub struct TlsPlan<'a> {
    /// The effective SNI.
    pub sni: &'a str,
    /// The ALPN to offer (empty = none).
    pub alpn: &'a str,
    /// The instance's own trust anchor, added to the class's roots.
    pub trust: Option<Arc<TrustAnchor>>,
    /// The client certificate chain and key, as custody resolved them.
    pub cert: Option<Arc<SecureVec>>,
    /// The caller's `accept: unverified_tls` applies: use the unverified client config.
    pub waive: bool,
}

/// One dial.
pub struct Dial<'a> {
    /// The addresses the judge admitted, in answer order (empty for a unix socket).
    pub addrs: &'a [SocketAddr],
    /// The unix socket path (rules (1) to (3) and (5) held), when the dest is one.
    pub unix: Option<&'a str>,
    /// TLS from the first byte; `None` for plaintext and for TLS_INBAND's plaintext phase.
    pub tls: Option<TlsPlan<'a>>,
    /// The connect budget.
    pub timeout: Duration,
}

/// A conn and what it negotiated.
#[derive(Debug)]
pub struct Dialled<C> {
    /// The conn.
    pub conn: C,
    /// The negotiated ALPN (empty when none).
    pub alpn: Box<str>,
    /// The TLS session was resumed.
    pub resumed: bool,
}

/// A FETCH, decided and judged by the handler; the transport only carries it.
pub struct FetchReq<'a> {
    /// The request.
    pub need: FetchNeed<'a>,
    /// The judged class.
    pub class: u32,
    /// The caller's `accept: unverified_tls` applies.
    pub waive: bool,
    /// The instance's own trust anchor.
    pub trust: Option<Arc<TrustAnchor>>,
    /// The client certificate chain and key.
    pub cert: Option<Arc<SecureVec>>,
    /// The body cap (the lesser of the Need's and the limit).
    pub max_body: u64,
    /// The header cap.
    pub max_headers: u32,
    /// The time left for the whole exchange.
    pub timeout: Duration,
}

/// The judge as the transport sees it: asked once per NEW connection (a pooled connection is never
/// judged again), so a client that pools its own connections still judges every dial it makes.
pub trait Admission: Send + Sync {
    /// Judge a dial of `host:port` and return the addresses to connect to.
    fn dial<'a>(&'a self, host: &'a str, port: u16)
        -> BoxFut<'a, Result<Vec<SocketAddr>, NeedErr>>;
}

/// The seam under the handlers: sockets, TLS and the HTTP client. Everything a Need decides is
/// decided before one of these methods is called; none retries (IF 12.3).
pub trait NeedIo: Send + Sync + 'static {
    /// A live conn.
    type Conn: Send + 'static;
    /// Connect (and, for `Dial::tls`, handshake), within `timeout`.
    fn dial(
        &self,
        d: Dial<'_>,
    ) -> impl Future<Output = Result<Dialled<Self::Conn>, NeedErr>> + Send;
    /// TLS_INBAND's STARTTLS: handshake over the plaintext conn. The conn is consumed.
    fn upgrade(
        &self,
        conn: Self::Conn,
        tls: TlsPlan<'_>,
        timeout: Duration,
    ) -> impl Future<Output = Result<Dialled<Self::Conn>, NeedErr>> + Send;
    /// Write, returning the bytes written.
    fn write(
        &self,
        conn: &mut Self::Conn,
        bytes: &[u8],
        timeout: Duration,
    ) -> impl Future<Output = Result<usize, NeedErr>> + Send;
    /// Read at least one byte into `buf`, or return 0 at EOF.
    fn read(
        &self,
        conn: &mut Self::Conn,
        buf: &mut [u8],
        timeout: Duration,
    ) -> impl Future<Output = Result<usize, NeedErr>> + Send;
    /// Whether a pooled conn is still good (open, no unread bytes, no error).
    fn healthy(&self, conn: &Self::Conn) -> bool;
    /// One FETCH: no redirects, no ambient credentials, no retries; the status, headers and body
    /// go into `res`. `admission` judges each new connection the client makes.
    fn fetch(
        &self,
        req: FetchReq<'_>,
        admission: &dyn Admission,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send;
}

/// The one-judge-per-dial adapter handed to [`NeedIo::fetch`].
struct Dialer<'a, R: Resolve> {
    judge: &'a Judge<R>,
    class: u32,
    owner: (u64, u32),
}

impl<R: Resolve> Admission for Dialer<'_, R> {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFut<'a, Result<Vec<SocketAddr>, NeedErr>> {
        Box::pin(self.judge.dial(host, port, self.class, self.owner))
    }
}

/// A destination as the pool keys it: the host lower-cased without a trailing dot, the port, and an
/// IPv6 literal bracketed. A unix path is left as written.
fn normalise(dest: &str) -> Result<Box<str>, NeedErr> {
    if names_unix(dest) {
        return Ok(dest.into());
    }
    let (host, port) = split_dest(dest)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.contains(':') {
        Ok(format!("[{host}]:{port}").into())
    } else {
        Ok(format!("{host}:{port}").into())
    }
}

/// The effective SNI: the one the plugin gave, else the dial host unless that is an address.
fn effective_sni(sni: &str, dest: &str) -> Box<str> {
    if !sni.is_empty() {
        return sni.to_ascii_lowercase().into();
    }
    match split_dest(dest) {
        Ok((host, _)) if host.parse::<std::net::IpAddr>().is_err() => host.into(),
        _ => "".into(),
    }
}

fn record_err(e: RecordsDenied) -> NeedErr {
    match e {
        RecordsDenied::Quota | RecordsDenied::TooLarge => NeedErr::Limit,
        RecordsDenied::Unavailable => NeedErr::Unavailable,
        RecordsDenied::Invalid => NeedErr::Invalid,
    }
}

/// The TLS part of an OPEN or STARTTLS as the key and the plan read it.
struct Parts<'a> {
    bits: u32,
    sni: &'a str,
    alpn: &'a str,
    trust: u32,
    cert: Option<u32>,
}

fn parts<'a>(tls: &TlsMode<'a>) -> Parts<'a> {
    let (bits, sni, alpn, trust, cert) = match *tls {
        TlsMode::None => (TLS_NONE, "", "", 0, None),
        TlsMode::Required { sni, alpn, trust } => (TLS_REQUIRED, sni, alpn, trust, None),
        TlsMode::Mutual {
            sni,
            alpn,
            trust,
            cert,
        } => (TLS_MUTUAL, sni, alpn, trust, Some(cert)),
        TlsMode::Inband {
            sni,
            alpn,
            trust,
            cert,
        } => (TLS_INBAND, sni, alpn, trust, cert),
    };
    Parts {
        bits,
        sni,
        alpn,
        trust,
        cert: cert.filter(|c| *c != 0),
    }
}

/// The Need handlers. `C` custody, `R` records, `D` the kernel directory, `I` the I/O seam (the
/// connector's own sockets, TLS and HTTP in production), `Z` the resolver (the system's).
pub struct HostNeeds<C, R, D, I = ConnectorIo, Z = SystemResolver>
where
    C: SecretCustody,
    R: PluginRecords,
    D: PluginDirectory,
    I: NeedIo,
    Z: Resolve,
{
    custody: C,
    records: R,
    directory: D,
    binder: Arc<dyn ConfigBinder>,
    io: I,
    judge: Judge<Z>,
    limits: NeedLimits,
    pool: NeedPool<I::Conn>,
    table: ConnTable<I::Conn>,
    ids: PooledIds,
    certs: CertDigests,
    reported: Reported,
    configured: Option<ConfiguredFn>,
}

/// A test of whether a destination is one the operator configured.
type ConfiguredFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Idle conns kept per key.
const POOL_PER_KEY: usize = 8;

impl<C, R, D> HostNeeds<C, R, D>
where
    C: SecretCustody,
    R: PluginRecords,
    D: PluginDirectory,
{
    /// The production handlers, as the kernel boot builds them: the connector's own sockets, rustls
    /// and hyper ([`ConnectorIo`]) under `guard` (the node's own ports published into it, IF 12.1)
    /// and the system resolver.
    pub fn production(
        guard: crate::guard::Guard,
        custody: C,
        records: R,
        directory: D,
        binder: Arc<dyn ConfigBinder>,
        limits: NeedLimits,
    ) -> Self {
        Self::new(
            ConnectorIo::new(),
            Judge::new(guard, SystemResolver),
            custody,
            records,
            directory,
            binder,
            limits,
        )
    }
}

impl<C, R, D, I, Z> HostNeeds<C, R, D, I, Z>
where
    C: SecretCustody,
    R: PluginRecords,
    D: PluginDirectory,
    I: NeedIo,
    Z: Resolve,
{
    /// The handlers over `io`, judged by `judge`.
    pub fn new(
        io: I,
        judge: Judge<Z>,
        custody: C,
        records: R,
        directory: D,
        binder: Arc<dyn ConfigBinder>,
        limits: NeedLimits,
    ) -> Self {
        HostNeeds {
            custody,
            records,
            directory,
            binder,
            io,
            judge,
            limits,
            pool: NeedPool::new(POOL_PER_KEY),
            table: ConnTable::new(limits.max_conns_per_chain as usize),
            ids: PooledIds::default(),
            certs: CertDigests::default(),
            reported: Reported::default(),
            configured: None,
        }
    }

    /// The instance is unbound: drop what core keeps for it.
    pub fn unbind(&self, instance: u64) {
        self.ids.forget(instance);
        self.certs.forget(instance);
        self.reported.forget(instance);
    }

    fn is_configured(&self, dest: &str) -> bool {
        self.configured.as_ref().is_some_and(|f| f(dest))
    }

    /// The time one step may take: `cap`, the instance's own limit when set, and what is left of
    /// the chain's deadline. None left is `Timeout`.
    fn budget(&self, cx: &Caller<'_>, cap: Duration, limit_ms: u32) -> Result<Duration, NeedErr> {
        let mut t = cap;
        if limit_ms != 0 {
            t = t.min(Duration::from_millis(u64::from(limit_ms)));
        }
        t = t.min(cx.deadline.saturating_duration_since(Instant::now()));
        if t.is_zero() {
            return Err(NeedErr::Timeout);
        }
        Ok(t)
    }

    /// The trust anchor a Need binds (`trust` handle 0 = none), and its digest.
    fn trust(
        &self,
        cx: &Caller<'_>,
        class: u32,
        handle: u32,
    ) -> Result<(Option<Arc<TrustAnchor>>, [u8; 32]), NeedErr> {
        if handle == 0 {
            return Ok((None, [0; 32]));
        }
        if !dial_policy(class).extra_roots_allowed {
            return Err(NeedErr::Denied);
        }
        let anchor = self
            .binder
            .trust(cx.instance, handle)
            .ok_or(NeedErr::Invalid)?;
        let digest = anchor.sha256;
        Ok((Some(anchor), digest))
    }

    /// The client certificate a Need binds, its digest (no resolve on a cache hit), and, when the
    /// caller needs the value to dial, the value.
    async fn cert(
        &self,
        cx: &Caller<'_>,
        handle: Option<u32>,
        want_value: bool,
    ) -> Result<(Option<Arc<SecureVec>>, [u8; 32]), NeedErr> {
        let Some(handle) = handle else {
            return Ok((None, [0; 32]));
        };
        let digest = self.certs.digest(&self.custody, cx, handle).await?;
        let value = if want_value {
            Some(
                self.custody
                    .resolve(cx, handle)
                    .await
                    .map_err(custody_err)?,
            )
        } else {
            None
        };
        Ok((value, digest))
    }

    fn audit_refused(&self, cx: &Caller<'_>, dest: &str, class: u32, why: &str) {
        crate::egress_audit::dial_refused(dest, Some(class), why, Some((cx.instance, 0)));
    }

    /// Answer a conn the chain now holds: a = conn id, b = flags, data0 = ALPN, data1 = the
    /// pooled-conn id.
    fn answer(
        &self,
        res: &mut NeedOut<'_>,
        id: ConnId,
        flags: u64,
        alpn: &str,
        pooled: u64,
    ) -> Result<(), NeedErr> {
        res.set(id.0, flags);
        res.put0(alpn.as_bytes())?;
        res.put1(&pooled.to_le_bytes())
    }

    /// Register `held` for the chain; the conn is dropped (closed) when the chain may not hold it.
    fn hold(&self, cx: &Caller<'_>, held: Held<I::Conn>) -> Result<ConnId, NeedErr> {
        self.table
            .insert(cx.instance, cx.chain, held)
            .map_err(|(e, _closed)| e)
    }
}

impl<C, R, D, I, Z> Needs for HostNeeds<C, R, D, I, Z>
where
    C: SecretCustody,
    R: PluginRecords,
    D: PluginDirectory,
    I: NeedIo,
    Z: Resolve + 'static,
{
    async fn open(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        let p = parts(&n.tls);
        // Unix rules (1) to (3), before anything is looked up.
        let unix = if names_unix(n.dest) {
            let path = unix_rules(n.dest, &n.tls, n.egress);
            if path == Err(NeedErr::Denied) {
                self.audit_refused(cx, n.dest, n.egress, "unix-class");
            }
            Some(path?)
        } else {
            None
        };
        // The transport gate, before the pool lookup and before any DNS.
        let admit = match admit_open(cx.limits.accept, p.bits, n.dest) {
            Ok(a) => a,
            Err(e) => {
                policy::refused(cx, &self.reported, n.dest);
                return Err(e);
            }
        };
        let dest = normalise(n.dest)?;
        let class = judged_class(n.egress, self.is_configured(&dest));
        if let Some(path) = unix {
            if !self.binder.unix_path(cx.instance, path) {
                self.audit_refused(cx, n.dest, class, "unix-path");
                return Err(NeedErr::Denied);
            }
        }
        let inband = p.bits == TLS_INBAND;
        let (trust, trust_digest) = self.trust(cx, class, p.trust)?;
        let (_, cert_digest) = self.cert(cx, p.cert, false).await?;
        let sni = if p.bits == TLS_NONE {
            "".into()
        } else {
            effective_sni(p.sni, &dest)
        };
        let waived = admit.waived();
        // The pool is probed first. TLS_INBAND probes the post-STARTTLS key; its dial key is the
        // plaintext one and is never pooled.
        let pooled_tls = match p.bits {
            TLS_NONE => Tls::None,
            TLS_INBAND => Tls::Upgraded,
            _ => Tls::Direct,
        };
        let key = NeedKey {
            instance: cx.instance,
            dest: dest.clone(),
            sni: sni.clone(),
            alpn: p.alpn.into(),
            class,
            tls: pooled_tls,
            trust: trust_digest,
            cert: cert_digest,
            waived,
        };
        while let Some(hit) = self.pool.take(&key) {
            if !self.io.healthy(&hit.conn) {
                continue;
            }
            let mut flags = open_flag::REUSED;
            if inband {
                flags |= open_flag::TLS_DONE;
            }
            let held = Held {
                conn: hit.conn,
                key: key.clone(),
                pooled: hit.id,
                alpn: hit.alpn.clone(),
                inband_pending: false,
            };
            let id = self.hold(cx, held)?;
            return self.answer(res, id, flags, &hit.alpn, hit.id);
        }
        // A miss: judge, then dial.
        let (addrs, path) = match unix {
            Some(path) => (Vec::new(), Some(path)),
            None => {
                let (host, port) = split_dest(&dest)?;
                (
                    self.judge.dial(host, port, class, (cx.instance, 0)).await?,
                    None,
                )
            }
        };
        let policy = dial_policy(class);
        let timeout = self.budget(cx, policy.connect_timeout, cx.limits.connect_timeout_ms)?;
        let (cert, _) = self.cert(cx, p.cert, true).await?;
        let plan = (p.bits != TLS_NONE && !inband).then(|| TlsPlan {
            sni: &sni,
            alpn: p.alpn,
            trust: trust.clone(),
            cert: cert.clone(),
            waive: waived,
        });
        let dialled = self
            .io
            .dial(Dial {
                addrs: &addrs,
                unix: path,
                tls: plan,
                timeout,
            })
            .await?;
        let pooled = self.ids.mint(cx.instance);
        let mut dial_key = key;
        dial_key.tls = match p.bits {
            TLS_NONE | TLS_INBAND => Tls::None,
            _ => Tls::Direct,
        };
        let held = Held {
            conn: dialled.conn,
            key: dial_key,
            pooled,
            alpn: dialled.alpn.clone(),
            inband_pending: inband,
        };
        let id = self.hold(cx, held)?;
        let flags = if dialled.resumed {
            open_flag::TLS_RESUMED
        } else {
            0
        };
        self.answer(res, id, flags, &dialled.alpn, pooled)
    }

    async fn starttls(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        tls: TlsMode<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let mut held = self.table.take(cx.instance, cx.chain, c)?;
        // A unix conn, a conn that is not waiting for its upgrade and a non-TLS mode are Invalid.
        if names_unix(&held.key.dest) || !held.inband_pending {
            return self.keep_invalid(cx, c, held);
        }
        let p = parts(&tls);
        if p.bits == TLS_NONE {
            return self.keep_invalid(cx, c, held);
        }
        let admit = match admit_open(cx.limits.accept, TLS_INBAND, &held.key.dest) {
            Ok(a) => a,
            Err(e) => {
                policy::refused(cx, &self.reported, &held.key.dest);
                drop(held);
                return Err(e);
            }
        };
        let (trust, trust_digest) = self.trust(cx, held.key.class, p.trust)?;
        let (cert, cert_digest) = self.cert(cx, p.cert, true).await?;
        let sni = effective_sni(p.sni, &held.key.dest);
        // The parameters must equal the TLS_INBAND OPEN's.
        let same = *held.key.sni == *sni
            && *held.key.alpn == *p.alpn
            && held.key.trust == trust_digest
            && held.key.cert == cert_digest
            && held.key.waived == admit.waived();
        if !same {
            return self.keep_invalid(cx, c, held);
        }
        let timeout = self.budget(
            cx,
            dial_policy(held.key.class).connect_timeout,
            cx.limits.connect_timeout_ms,
        )?;
        let plan = TlsPlan {
            sni: &sni,
            alpn: p.alpn,
            trust,
            cert,
            waive: admit.waived(),
        };
        let up = self.io.upgrade(held.conn, plan, timeout).await?;
        held.conn = up.conn;
        held.key.tls = Tls::Upgraded;
        held.alpn = up.alpn.clone();
        held.inband_pending = false;
        if let Err(conn) = self.table.restore(cx.instance, cx.chain, c, held) {
            drop(conn);
            return Err(NeedErr::Closed);
        }
        res.set(
            0,
            if up.resumed {
                open_flag::TLS_RESUMED
            } else {
                0
            },
        );
        res.put0(up.alpn.as_bytes())
    }

    async fn write(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        bytes: &[u8],
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let mut held = self.table.take(cx.instance, cx.chain, c)?;
        let t = self.budget(
            cx,
            dial_policy(held.key.class).io_timeout,
            cx.limits.timeout_ms,
        )?;
        // Any failure drops the conn: its protocol state is unknown.
        let n = self.io.write(&mut held.conn, bytes, t).await?;
        self.put_back(cx, c, held)?;
        res.set(n as u64, 0);
        Ok(())
    }

    async fn read(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        max: u32,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let mut held = self.table.take(cx.instance, cx.chain, c)?;
        let t = self.budget(
            cx,
            dial_policy(held.key.class).io_timeout,
            cx.limits.timeout_ms,
        )?;
        let max = max.min(self.limits.max_read) as usize;
        let n = {
            let buf = res.spare0(max);
            self.io.read(&mut held.conn, buf, t).await?
        };
        self.put_back(cx, c, held)?;
        if n == 0 {
            res.set(0, 1);
        } else {
            res.commit0(n);
            res.set(n as u64, 0);
        }
        Ok(())
    }

    async fn close(&self, cx: &Caller<'_>, c: ConnId, reusable: bool) {
        let Ok(held) = self.table.take(cx.instance, cx.chain, c) else {
            return;
        };
        // Reuse only if REUSABLE, healthy, upgraded when it was to be, and under the cap, under the
        // conn's current key. An un-upgraded TLS_INBAND conn is dropped, with no exception.
        if reusable && !held.inband_pending && self.io.healthy(&held.conn) {
            let _ = self.pool.put(
                held.key,
                Pooled {
                    id: held.pooled,
                    conn: held.conn,
                    alpn: held.alpn,
                },
            );
        }
    }

    async fn fetch(
        &self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        if cx.chain == 0 {
            return Err(NeedErr::Invalid);
        }
        let admit = match admit_fetch(cx.limits.accept, n.url) {
            Ok(a) => a,
            Err(e) => {
                policy::refused(cx, &self.reported, n.url);
                return Err(e);
            }
        };
        let (host, port) = split_url(n.url)?;
        let dest = normalise(&format!("{host}:{port}"))?;
        let class = judged_class(n.egress, self.is_configured(&dest));
        let (trust, _) = self.trust(cx, class, n.trust)?;
        let cert_handle = n.cert.filter(|c| *c != 0);
        let (cert, _) = self.cert(cx, cert_handle, true).await?;
        let timeout = self.budget(cx, dial_policy(class).io_timeout, cx.limits.timeout_ms)?;
        let req = FetchReq {
            need: n,
            class,
            waive: admit == Admit::Waived,
            trust,
            cert,
            // 0 states no cap of its own: the core default.
            max_body: if n.max_body == 0 {
                self.limits.max_fetch_body
            } else {
                n.max_body.min(self.limits.max_fetch_body)
            },
            max_headers: self.limits.max_fetch_headers,
            timeout,
        };
        let dialer = Dialer {
            judge: &self.judge,
            class,
            owner: (cx.instance, 0),
        };
        self.io.fetch(req, &dialer, res).await
    }

    async fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let value = self
            .custody
            .resolve(cx, handle)
            .await
            .map_err(custody_err)?;
        res.put0(&value)
    }

    async fn record(
        &self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        let scope = Scope::default();
        let max_value = self.limits.max_record_value as usize;
        let sized = |v: &[u8]| {
            if v.len() > max_value {
                Err(NeedErr::Limit)
            } else {
                Ok(())
            }
        };
        match n {
            RecordNeed::Get(key) => {
                let mut put = Ok(());
                let found = self
                    .records
                    .get(cx, scope, key, &mut |v: &[u8]| {
                        put = sized(v).and_then(|()| res.put0(v));
                    })
                    .await
                    .map_err(record_err)?;
                put?;
                res.set(u64::from(found), 0);
            }
            RecordNeed::Put(key, value, ttl) => {
                sized(value)?;
                self.records
                    .put(cx, scope, key, value, ttl)
                    .await
                    .map_err(record_err)?;
            }
            RecordNeed::Claim(key, value, ttl) => {
                sized(value)?;
                let won = self
                    .records
                    .claim(cx, scope, key, value, ttl)
                    .await
                    .map_err(record_err)?;
                res.set(u64::from(won), 0);
            }
            RecordNeed::Del(key) => {
                self.records.del(cx, scope, key).await.map_err(record_err)?;
            }
            RecordNeed::List(prefix, limit) => {
                let limit = limit.min(self.limits.max_list);
                let mut put = Ok(());
                let hits = self
                    .records
                    .list(cx, scope, prefix, limit, &mut |k: &[u8], v: &[u8]| {
                        if put.is_ok() {
                            put = sized(v).and_then(|()| res.pair0(k, v));
                        }
                    })
                    .await
                    .map_err(record_err)?;
                put?;
                res.set(u64::from(hits), 0);
            }
            RecordNeed::Commit(recs) => {
                let mut ops = [commit::EMPTY; commit::MAX_OPS];
                let len = commit::decode(recs, &mut ops)?;
                match self
                    .records
                    .commit(cx, scope, &ops[..len])
                    .await
                    .map_err(record_err)?
                {
                    CommitOutcome::Applied => res.set(u64::from(commit_code::APPLIED), 0),
                    CommitOutcome::Conflict { failed } => {
                        res.set(u64::from(commit_code::CONFLICT), u64::from(failed));
                    }
                }
            }
        }
        Ok(())
    }

    async fn directory(
        &self,
        cx: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        self.directory.apply(cx, n, res).await
    }

    fn release(&self, cx: &Caller<'_>) {
        // Close (non-reusably) every conn this chain still holds, and only those.
        drop(self.table.release(cx.instance, cx.chain));
    }
}

impl<C, R, D, I, Z> HostNeeds<C, R, D, I, Z>
where
    C: SecretCustody,
    R: PluginRecords,
    D: PluginDirectory,
    I: NeedIo,
    Z: Resolve,
{
    /// Put a conn back after an operation; the conn is closed when its chain was released while it
    /// was out.
    fn put_back(&self, cx: &Caller<'_>, c: ConnId, held: Held<I::Conn>) -> Result<(), NeedErr> {
        self.table
            .restore(cx.instance, cx.chain, c, held)
            .map_err(|_closed| NeedErr::Closed)
    }

    /// A STARTTLS that cannot proceed leaves the conn where it was and answers Invalid.
    fn keep_invalid(&self, cx: &Caller<'_>, c: ConnId, held: Held<I::Conn>) -> Result<(), NeedErr> {
        self.put_back(cx, c, held)?;
        Err(NeedErr::Invalid)
    }
}
