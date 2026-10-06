// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REMOTE STORE'S CONNECTIONS OVER THE HOST'S CONNECTOR (store SDK `wire`; ARCHITECT rulings
//! 2026-10-03 STORE-KEEP, VALKEY-UNIX, VALKEY-TIMEOUT, VALKEY-RETRY, TLS), over the test connection
//! table (`tcp_conns`) and real backends:
//!
//! * the store's connections are KEPT across ops in a bounded set: one handshake, then reuse;
//!   concurrent ops beyond the bound wait for a connection and complete;
//! * a kept connection the far end dropped fails its op and is not kept; a store that retries on a
//!   fresh connection ([`Wire::reconnect`]) answers;
//! * a store's dial timeout reaches the table; a `unix:` target is a unix-domain stream; a stream
//!   secured through the table's TLS carries the op (the TLS a test double of the connector's: TLS
//!   stays in the connector, whose own suite proves the real `upgrade_secure`).

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Pool, Wire};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::records::{RecordStore, RecordStoreError, RecordStoreResult};

use super::pend_tests::{mint, TCP};
use crate::both_ways::store_fixture::MemoryStore;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::wrap::Hooks;
use crate::store_v3::LoadedStore;
use crate::tcp_conns::{SecureDial, SecuredSock, TcpConns};

// ── the table's TLS: a double of the connector's ─────────────────────────────────────────────

/// A TEST DOUBLE of the TLS a table secures with (TLS itself is the connector's, which this crate
/// cannot name; the real wrap's `upgrade_secure`, verify-off included, is proven in
/// the connector's own suite). It hands the stream back as it is, counting the handshakes
/// and recording what each asked for; told its backend is self-signed, it refuses a VERIFYING
/// handshake, as a verifying handshake refuses a self-signed certificate.
#[derive(Default)]
struct TlsDouble {
    self_signed: bool,
    asked: Mutex<Vec<(String, bool)>>,
}

impl TlsDouble {
    fn asked(&self) -> Vec<(String, bool)> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SecureDial for TlsDouble {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        tcp: std::net::TcpStream,
    ) -> std::io::Result<Box<dyn SecuredSock>> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((server.to_owned(), verify_off));
        if self.self_signed && !verify_off {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid peer certificate: the backend's certificate is self-signed",
            ));
        }
        Ok(Box::new(Secured(tcp)))
    }
}

/// The stream the double secured: the socket as it is.
struct Secured(std::net::TcpStream);

impl std::io::Read for Secured {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}

impl Write for Secured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl SecuredSock for Secured {
    fn tcp(&self) -> &std::net::TcpStream {
        &self.0
    }
    fn close(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

// ── backends ───────────────────────────────────────────────────────────────────────────────────

/// What a line backend does.
#[derive(Clone, Copy, Default)]
struct Behaviour {
    /// Wait this long before each reply.
    delay: Duration,
    /// Close the connection after each reply that is not the handshake's.
    close_after_reply: bool,
}

/// Serve one connection: `HELLO` answers `WELCOME`, any other line `echo <line>`.
fn serve_lines(r: impl std::io::Read, mut w: impl Write, b: Behaviour) {
    let mut r = std::io::BufReader::new(r);
    let mut line = String::new();
    while r.read_line(&mut line).is_ok_and(|n| n > 0) {
        std::thread::sleep(b.delay);
        let got = line.trim_end().to_owned();
        line.clear();
        let reply = if got == "HELLO" {
            "WELCOME".to_owned()
        } else {
            format!("echo {got}")
        };
        if w.write_all(format!("{reply}\n").as_bytes()).is_err() || w.flush().is_err() {
            return;
        }
        if b.close_after_reply && got != "HELLO" {
            return;
        }
    }
}

/// A TCP line backend: its address and how many connections it accepted.
fn tcp_backend(b: Behaviour) -> (String, Arc<AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr").to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let r = s.try_clone().expect("clone");
            std::thread::spawn(move || serve_lines(r, s, b));
        }
    });
    (addr, accepted)
}

// ── the store's body ───────────────────────────────────────────────────────────────────────────

fn failed(e: &ConnFailure) -> RecordStoreError {
    RecordStoreError(format!("wire-store: {e}"))
}

async fn line(w: &Wire, send: &str) -> RecordStoreResult<String> {
    w.write_all(format!("{send}\n").as_bytes())
        .await
        .map_err(|e| failed(&e))?;
    loop {
        if let Some(l) = w.input(|i| {
            let at = i.iter().position(|b| *b == b'\n')?;
            let l: Vec<u8> = i.drain(..=at).collect();
            Some(String::from_utf8_lossy(&l[..at]).into_owned())
        }) {
            return Ok(l);
        }
        if w.fill().await.map_err(|e| failed(&e))? == 0 {
            return Err(RecordStoreError("wire-store: the backend closed".into()));
        }
    }
}

/// The handshake a NEW connection makes (a kept one skips it): optional TLS, then `HELLO`.
/// How a new connection is secured.
#[derive(Clone, Copy)]
enum Tls {
    Off,
    Verified,
    /// The operator's opt-in to an unverified handshake (`#insecure`).
    Unverified,
}

async fn handshake(w: &Wire, tls: Tls) -> RecordStoreResult<()> {
    match tls {
        Tls::Off => {}
        Tls::Verified => w.upgrade_secure(None).await.map_err(|e| failed(&e))?,
        Tls::Unverified => w
            .upgrade_secure_unverified(None)
            .await
            .map_err(|e| failed(&e))?,
    }
    let greeting = line(w, "HELLO").await?;
    if greeting != "WELCOME" {
        return Err(RecordStoreError(format!("wire-store: greeted {greeting}")));
    }
    w.set_session(greeting);
    Ok(())
}

/// One op: connect (kept or new), handshake when new, `ping`; with `retry`, a failure on a KEPT
/// connection is retried once on a fresh one (a store's idempotent read).
async fn ping(
    w: Wire,
    target: String,
    timeout_ms: u32,
    tls: Tls,
    retry: bool,
) -> RecordStoreResult<Vec<String>> {
    w.connect_timed(0, Some(&target), timeout_ms)
        .await
        .map_err(|e| failed(&e))?;
    if !w.reused() {
        handshake(&w, tls).await?;
    }
    match line(&w, "ping").await {
        Ok(l) => Ok(vec![l]),
        Err(_) if retry && w.reused() => {
            w.reconnect().await.map_err(|e| failed(&e))?;
            handshake(&w, tls).await?;
            line(&w, "ping").await.map(|l| vec![l])
        }
        Err(e) => Err(e),
    }
}

/// A store whose `list_denylist` is [`ping`] on its kept set.
macro_rules! wire_store {
    ($name:ident, $door:ident, max: $max:expr, timeout: $t:expr, tls: $tls:expr, retry: $retry:expr) => {
        wire_store!($name, $door, max: $max, timeout: $t, tls: $tls, retry: $retry, needs: TCP);
    };
    ($name:ident, $door:ident, max: $max:expr, timeout: $t:expr, tls: $tls:expr, retry: $retry:expr, needs: $needs:ident) => {
        struct $name;
        impl $name {
            fn pool() -> &'static Arc<Pool> {
                static POOL: LazyLock<Arc<Pool>> = LazyLock::new(|| Pool::new($max));
                &POOL
            }
            fn target() -> &'static Mutex<String> {
                static TARGET: Mutex<String> = Mutex::new(String::new());
                &TARGET
            }
        }
        impl Hooks for $name {
            fn list_denylist(_: &MemoryStore, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
                let target = Self::target()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                drive_kept(cx, Self::pool(), move |w| {
                    Box::pin(ping(w, target, $t, $tls, $retry))
                })
            }
        }
        mod $door {
            busbar_contract::store_door!(
                crate::store_v3::wrap::Wrapped<super::$name>,
                "wire-store",
                "0",
                64,
                needs: super::$needs
            );
        }
    };
}

/// `door` loaded and opened over `conns`, with `workers` dispatcher workers.
fn open_over(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    conns: impl FnOnce(&Dispatcher) -> Arc<dyn busbar_contract::conn::DeclaredConns>,
) -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 4,
        ..DispatchConfig::default()
    }));
    let conns = conns(&d);
    let p = load_linked::<Store>(
        &LinkedRow::of(door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    LoadedStore::open(p, d, b"{}", mint).expect("it opens")
}

fn plain(d: &Dispatcher) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    Arc::new(TcpConns::new(d.conn_waker()))
}

fn ping_of(s: &LoadedStore) -> RecordStoreResult<Vec<String>> {
    RecordStore::list_denylist(s)
}

// ── STORE-KEEP ─────────────────────────────────────────────────────────────────────────────────

wire_store!(KeptOne, kept_one, max: 1, timeout: 0, tls: Tls::Off, retry: false);

/// RED (STORE-KEEP): three ops are ONE connection, one handshake: the connection is kept.
#[test]
fn a_stores_connection_is_kept_across_ops() {
    let (addr, accepted) = tcp_backend(Behaviour::default());
    *KeptOne::target().lock().expect("target") = addr;
    let s = open_over(kept_one::door, plain);
    for _ in 0..3 {
        assert_eq!(
            ping_of(&s).expect("the op answers"),
            vec!["echo ping".to_string()]
        );
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "one connection for every op"
    );
    assert_eq!((KeptOne::pool().live(), KeptOne::pool().idle()), (1, 1));
}

wire_store!(KeptBounded, kept_bounded, max: 2, timeout: 0, tls: Tls::Off, retry: false);

/// Concurrent ops beyond the bound WAIT for a kept connection and all complete; never more than
/// the bound are established.
#[test]
fn concurrent_ops_beyond_the_bound_wait_for_a_kept_connection() {
    let (addr, accepted) = tcp_backend(Behaviour {
        delay: Duration::from_millis(20),
        ..Behaviour::default()
    });
    *KeptBounded::target().lock().expect("target") = addr;
    let s = Arc::new(open_over(kept_bounded::door, plain));
    let ops: Vec<_> = (0..6)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || ping_of(&s))
        })
        .collect();
    for op in ops {
        assert_eq!(
            op.join().expect("the op's thread").expect("the op answers"),
            vec!["echo ping".to_string()]
        );
    }
    assert!(accepted.load(Ordering::SeqCst) <= 2, "at most the bound");
    assert!(KeptBounded::pool().live() <= 2);
}

// ── a kept connection the far end dropped; VALKEY-RETRY ─────────────────────────────────────────

wire_store!(NoRetry, no_retry, max: 1, timeout: 0, tls: Tls::Off, retry: false);

/// A kept connection the far end closed fails its op and is not kept: the next op dials fresh.
#[test]
fn a_dropped_kept_connection_fails_its_op_and_the_next_dials_fresh() {
    let (addr, accepted) = tcp_backend(Behaviour {
        close_after_reply: true,
        ..Behaviour::default()
    });
    *NoRetry::target().lock().expect("target") = addr;
    let s = open_over(no_retry::door, plain);
    assert_eq!(ping_of(&s).expect("first"), vec!["echo ping".to_string()]);
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        ping_of(&s).is_err(),
        "the kept connection was closed by the far end"
    );
    assert_eq!(
        ping_of(&s).expect("a fresh connection"),
        vec!["echo ping".to_string()]
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

wire_store!(Retries, retries, max: 1, timeout: 0, tls: Tls::Off, retry: true);

/// RED (VALKEY-RETRY): a read whose kept connection failed is retried ONCE on a fresh connection.
#[test]
fn a_read_on_a_dropped_kept_connection_is_retried_on_a_fresh_one() {
    let (addr, accepted) = tcp_backend(Behaviour {
        close_after_reply: true,
        ..Behaviour::default()
    });
    *Retries::target().lock().expect("target") = addr;
    let s = open_over(retries::door, plain);
    for _ in 0..3 {
        assert_eq!(ping_of(&s).expect("answers"), vec!["echo ping".to_string()]);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        3,
        "one fresh connection per retry"
    );
}

// ── VALKEY-TIMEOUT ──────────────────────────────────────────────────────────────────────────────

wire_store!(Timed, timed, max: 1, timeout: 300, tls: Tls::Off, retry: false);

/// RED (VALKEY-TIMEOUT): the store's dial timeout reaches the host's table as the open's timeout.
#[test]
fn the_stores_dial_timeout_reaches_the_hosts_table() {
    let (addr, _) = tcp_backend(Behaviour::default());
    *Timed::target().lock().expect("target") = addr;
    let table = Arc::new(Mutex::new(None::<Arc<TcpConns>>));
    let keep = table.clone();
    let s = open_over(timed::door, move |d| {
        let t = Arc::new(TcpConns::new(d.conn_waker()));
        *keep.lock().expect("table") = Some(t.clone());
        t
    });
    assert_eq!(ping_of(&s).expect("answers"), vec!["echo ping".to_string()]);
    let t = table.lock().expect("table").clone().expect("the table");
    assert_eq!(t.dial_timeouts(), vec![300]);
}

// ── VALKEY-UNIX ─────────────────────────────────────────────────────────────────────────────────

wire_store!(OverUnix, over_unix, max: 1, timeout: 0, tls: Tls::Off, retry: false);

/// RED (VALKEY-UNIX): a `unix:/path` target is a unix-domain stream through the host's table.
#[test]
fn a_unix_target_is_a_unix_domain_stream() {
    let dir = std::env::temp_dir().join(format!("busbar-wire-unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("s.sock");
    let l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let r = s.try_clone().expect("clone");
            std::thread::spawn(move || serve_lines(r, s, Behaviour::default()));
        }
    });
    *OverUnix::target().lock().expect("target") = format!("unix:{}", path.display());
    let s = open_over(over_unix::door, plain);
    assert_eq!(ping_of(&s).expect("answers"), vec!["echo ping".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── TLS ─────────────────────────────────────────────────────────────────────────────────────────

wire_store!(OverTls, over_tls, max: 1, timeout: 0, tls: Tls::Verified, retry: false);

/// RED (TLS): the store's stream secured with TLS (`upgrade_secure`) through the table's TLS carries
/// the handshake and the ops; the kept connection stays secure (one TLS handshake, for the target's
/// host name).
#[test]
fn a_tls_secured_stream_carries_the_stores_ops() {
    let (addr, accepted) = tcp_backend(Behaviour::default());
    let port = addr.rsplit_once(':').expect("host:port").1.to_owned();
    *OverTls::target().lock().expect("target") = format!("localhost:{port}");
    let tls = Arc::new(TlsDouble::default());
    let table_tls = Arc::clone(&tls);
    let s = open_over(over_tls::door, move |d| {
        Arc::new(TcpConns::with_tls(d.conn_waker(), table_tls))
    });
    for _ in 0..2 {
        assert_eq!(
            ping_of(&s).expect("answers over TLS"),
            vec!["echo ping".to_string()]
        );
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "one TLS connection, kept"
    );
    assert_eq!(
        tls.asked(),
        vec![("localhost".to_string(), false)],
        "one verifying handshake, for the target's host"
    );
}

wire_store!(Untrusted, untrusted, max: 1, timeout: 0, tls: Tls::Verified, retry: false);

/// Without the CA the handshake is refused: the op fails, in the store's words.
#[test]
fn a_tls_upgrade_without_trust_is_refused() {
    let (addr, _) = tcp_backend(Behaviour::default());
    // The plain table refuses every upgrade.
    *Untrusted::target().lock().expect("target") = addr;
    let s = open_over(untrusted::door, plain);
    let e = ping_of(&s).expect_err("no TLS without trust");
    assert!(e.0.contains("wire-store: "), "{e:?}");
}

// ── a bound over the dial AND the handshake (VALKEY-TIMEOUT: 1.5.5 bounded both) ───────────────

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest.
struct ClockOnly;

impl busbar_contract::services::HostServices for ClockOnly {
    fn now(&self) -> busbar_contract::services::Reading {
        busbar_contract::services::Reading {
            wall_ns: 0,
            mono_ns: crate::dispatch::now_ns(),
        }
    }
    fn dest_judge(
        &self,
        _: &str,
        _: u32,
        _: bool,
        _: Option<busbar_contract::services::Later>,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_get(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_list(
        &self,
        _: &busbar_contract::services::Caller,
        _: busbar_contract::services::RecordsList,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_claim(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: u64,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn sign(
        &self,
        _: &busbar_contract::services::Caller,
        _: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn trust_sight(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &str,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn trust_due(
        &self,
        _: &busbar_contract::services::Caller,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn trust_verify(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn entitlement_check(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &str,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn random_fill(&self, _: u64) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn records_secret(
        &self,
        _: &str,
        _: &str,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn unit_nest(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: busbar_contract::services::NestAsk,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_open(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &str,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_find(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_settle(
        &self,
        _: &busbar_contract::services::Caller,
        _: u64,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_resume(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: u64,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }

    fn disk_append(
        &self,
        _: &busbar_contract::services::DiskDest,
        _: Vec<u8>,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
}

/// A store whose connect is bounded by 200 ms over the dial and the handshake.
struct BoundedHandshake;

static SILENT_TARGET: Mutex<String> = Mutex::new(String::new());

impl Hooks for BoundedHandshake {
    fn list_denylist(_: &MemoryStore, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        static POOL: LazyLock<Arc<Pool>> = LazyLock::new(|| Pool::new(1));
        let target = SILENT_TARGET
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        drive_kept(cx, &POOL, move |w| {
            Box::pin(async move {
                w.bound(200);
                w.connect_timed(0, Some(&target), 200)
                    .await
                    .map_err(|e| failed(&e))?;
                handshake(&w, Tls::Off).await?;
                w.unbound();
                line(&w, "ping").await.map(|l| vec![l])
            })
        })
    }
}

mod bounded_handshake {
    busbar_contract::store_door!(
        crate::store_v3::wrap::Wrapped<super::BoundedHandshake>,
        "wire-store",
        "0",
        64,
        needs: super::TCP
    );
}

/// RED (VALKEY-TIMEOUT): a backend that accepts and never answers the handshake fails the op at
/// the store's connect bound, as a timeout, not at the op's deadline.
#[test]
fn a_bound_covers_the_handshake_after_the_dial() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    *SILENT_TARGET.lock().expect("target") = l.local_addr().expect("addr").to_string();
    // Accept and hold, saying nothing.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            held.push(s);
        }
    });
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(ClockOnly),
    ));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
        Arc::new(TcpConns::new(d.conn_waker()));
    let p = load_linked::<Store>(
        &LinkedRow::of(bounded_handshake::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    let s = LoadedStore::open(p, d, b"{}", mint).expect("it opens");
    let t = std::time::Instant::now();
    let e = ping_of(&s).expect_err("the handshake never answers");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(e.0.contains("deadline passed"), "{e:?}");
}

// ── verify-off (ARCHITECT ruling 2026-10-03 on Q-L16-4: 1.5.5's `#insecure`) ──────────────────

/// One outbound `tcp` need of class operator-infrastructure (a database).
const TCP_OPERATOR: &[busbar_contract::abi::host::conn::connector::Need] =
    &[busbar_contract::abi::host::conn::connector::Need {
        egress_class: busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE,
        ..TCP[0]
    }];

/// A line backend whose certificate the table's TLS double is told is SELF-SIGNED: its port.
fn self_signed_tls_backend() -> u16 {
    let (addr, _) = tcp_backend(Behaviour::default());
    addr.rsplit_once(':')
        .expect("host:port")
        .1
        .parse()
        .expect("a port")
}

/// The table's TLS for the self-signed backend.
fn self_signed_tls() -> Arc<dyn SecureDial> {
    Arc::new(TlsDouble {
        self_signed: true,
        ..TlsDouble::default()
    })
}

wire_store!(SelfSignedVerified, self_signed_verified, max: 1, timeout: 0, tls: Tls::Verified, retry: false, needs: TCP_OPERATOR);
wire_store!(SelfSignedInsecure, self_signed_insecure, max: 1, timeout: 0, tls: Tls::Unverified, retry: false, needs: TCP_OPERATOR);
wire_store!(InsecureOtherClass, insecure_other_class, max: 1, timeout: 0, tls: Tls::Unverified, retry: false, needs: TCP);

/// RED (Q-L16-4): a self-signed backend is REFUSED by a verifying handshake; with the operator's
/// verify-off opt-in on an operator-infrastructure need it is ACCEPTED; the opt-in on a need of
/// another class is REFUSED.
#[test]
fn a_self_signed_backend_is_accepted_only_with_verify_off_on_an_operator_need() {
    let port = self_signed_tls_backend();
    let target = format!("localhost:{port}");

    *SelfSignedVerified::target().lock().expect("target") = target.clone();
    let s = open_over(self_signed_verified::door, move |d| {
        Arc::new(TcpConns::with_tls(d.conn_waker(), self_signed_tls()))
    });
    assert!(
        ping_of(&s).is_err(),
        "a self-signed certificate fails verification"
    );

    *SelfSignedInsecure::target().lock().expect("target") = target.clone();
    let s = open_over(self_signed_insecure::door, move |d| {
        Arc::new(TcpConns::with_tls(d.conn_waker(), self_signed_tls()))
    });
    assert_eq!(
        ping_of(&s).expect("accepted with the opt-in"),
        vec!["echo ping".to_string()]
    );

    *InsecureOtherClass::target().lock().expect("target") = target;
    let s = open_over(insecure_other_class::door, plain);
    let e = ping_of(&s).expect_err("verify-off is an operator-infrastructure need's only");
    assert!(e.0.contains("wire-store: "), "{e:?}");
}
