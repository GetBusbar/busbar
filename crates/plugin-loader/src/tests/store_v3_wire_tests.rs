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
//!   secured with TLS trusting the test CA carries the op.

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
use crate::tcp_conns::TcpConns;

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
async fn handshake(w: &Wire, tls: bool) -> RecordStoreResult<()> {
    if tls {
        w.upgrade_secure(None).await.map_err(|e| failed(&e))?;
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
    tls: bool,
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
                needs: super::TCP
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
            conns: Some(conns),
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

wire_store!(KeptOne, kept_one, max: 1, timeout: 0, tls: false, retry: false);

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

wire_store!(KeptBounded, kept_bounded, max: 2, timeout: 0, tls: false, retry: false);

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

wire_store!(NoRetry, no_retry, max: 1, timeout: 0, tls: false, retry: false);

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

wire_store!(Retries, retries, max: 1, timeout: 0, tls: false, retry: true);

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

wire_store!(Timed, timed, max: 1, timeout: 300, tls: false, retry: false);

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

wire_store!(OverUnix, over_unix, max: 1, timeout: 0, tls: false, retry: false);

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

wire_store!(OverTls, over_tls, max: 1, timeout: 0, tls: true, retry: false);

/// RED (TLS): the store's stream secured with TLS (`upgrade_secure`) trusting the test CA carries
/// the handshake and the ops; the kept connection stays secure (one TLS handshake).
#[test]
fn a_tls_secured_stream_carries_the_stores_ops() {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let key = rcgen::KeyPair::generate().expect("key");
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("leaf");
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("server config");
    let server = Arc::new(server);
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let conn = rustls::ServerConnection::new(server.clone()).expect("tls conn");
            std::thread::spawn(move || {
                let tls = rustls::StreamOwned::new(conn, s);
                let shared = Arc::new(Mutex::new(tls));
                struct Half(
                    Arc<Mutex<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>>>,
                );
                impl std::io::Read for Half {
                    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                        self.0
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .read(b)
                    }
                }
                impl Write for Half {
                    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                        self.0
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .write(b)
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        self.0
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .flush()
                    }
                }
                serve_lines(Half(shared.clone()), Half(shared), Behaviour::default());
            });
        }
    });
    *OverTls::target().lock().expect("target") = format!("localhost:{port}");
    let ca_der = ca.der().to_vec();
    let s = open_over(over_tls::door, move |d| {
        Arc::new(TcpConns::with_roots(d.conn_waker(), &ca_der))
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
}

wire_store!(Untrusted, untrusted, max: 1, timeout: 0, tls: true, retry: false);

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
