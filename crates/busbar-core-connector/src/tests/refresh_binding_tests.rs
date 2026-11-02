// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A refused actual Vault REFRESH must leave the committed production connector binding intact.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    self as life, OpenIn, OpenOut, RefreshIn, ReleaseIn,
};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_contract::conn::{DeclaredConns, NeedId};
use busbar_contract::transport::{EgressTrust, TransportSettings};
use busbar_kernel::config::Destinations;
use busbar_kernel::host_services::KernelServices;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, now_ns, out_head, rendering_of_library, Bind, ConnTable, DispatchConfig,
    Dispatcher, Frame, NoSink, Plugin, NO_BLOB,
};

use crate::doors::Dispatched;
use crate::registry::{Entry, Transports};
use crate::Connector;

const TOKEN: &[u8] = b"s.x";
const REFERENCE: &[u8] = br#"{"path":"kv/data/x#k"}"#;
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn token() -> Blob {
    Blob {
        ptr: TOKEN.as_ptr(),
        len: TOKEN.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

fn artifact(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).expect(variable));
    assert!(
        path.is_absolute() && path.is_file(),
        "required actual image: {}",
        path.display()
    );
    path
}

fn bind(dispatcher: &Dispatcher, instance: &str, conns: ConnTable) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns,
    }
}

fn actual_transport(dispatcher: &Arc<Dispatcher>, variable: &str) -> Entry {
    let path = artifact(variable);
    let statement = rendering_of_library(&path)
        .expect("read actual transport Statement")
        .expect("actual transport door");
    let plugin = load_dropped::<Transport>(
        &path,
        &statement,
        bind(dispatcher, variable, ConnTable::NoNeeds),
    )
    .expect("admit actual transport");
    let door = Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher.clone())
        .expect("open actual transport");
    Entry {
        door: Arc::new(door),
        alpn: Vec::new(),
    }
}

// Only a bounded loopback wire peer; all transport, secret and connector code is the real product.
struct VaultPeer {
    addr: String,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl VaultPeer {
    fn new(material: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Vault loopback listener");
        listener.set_nonblocking(true).unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = requests.clone();
        let stopped = stop.clone();
        let task = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(90);
            while !stopped.load(Ordering::SeqCst) {
                assert!(Instant::now() < until, "Vault peer lifetime bound");
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("Vault peer accept: {error}"),
                };
                request(&mut stream);
                let body = serde_json::json!({"data":{"data":{"k":material}}}).to_string();
                observed.fetch_add(1, Ordering::SeqCst);
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("Vault response write");
                stream.flush().expect("Vault response flush");
            }
        });
        Self {
            addr,
            requests,
            stop,
            task: Some(task),
        }
    }
}

fn request(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(
            head.len() < 8192 && Instant::now() < until,
            "bounded Vault request head"
        );
        stream.read_exact(&mut byte).expect("Vault request head");
        head.push(byte[0]);
    }
    let head = std::str::from_utf8(&head).expect("HTTP request text");
    assert!(head.starts_with("GET /v1/kv/data/x HTTP/1.1\r\n"));
    assert!(head.lines().any(|line| line
        .split_once(':')
        .is_some_and(|(name, value)| name.eq_ignore_ascii_case("x-vault-token")
            && value.trim().as_bytes() == TOKEN)));
}

impl Drop for VaultPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            if let Err(error) = task.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}

struct OpenVault {
    plugin: Plugin<Secret>,
    closed: bool,
}

impl OpenVault {
    fn close(&mut self) {
        let mut close: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        let called = self.plugin.call(life::slot::CLOSE, &mut close);
        release(&self.plugin, called.lease);
        assert_eq!(called.outcome, Outcome::Ready, "actual Vault closes");
        self.closed = true;
    }
}

impl Drop for OpenVault {
    fn drop(&mut self) {
        if !self.closed {
            let mut close: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
            let _ = self.plugin.call(life::slot::CLOSE, &mut close);
        }
    }
}

// Caller-owned settings and mutable output stay lent until the actual dispatcher retires the call.
struct ResolveLoan {
    settings: Vec<u8>,
    material: Mutex<Vec<u8>>,
}

fn release(plugin: &Plugin<Secret>, lease: u64) {
    if lease != 0 {
        let mut frame: Frame<ReleaseIn, OutHead> = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        let called = plugin.call(life::slot::RELEASE, &mut frame);
        assert_eq!(
            called.outcome,
            Outcome::Ready,
            "release the actual answer's lease"
        );
    }
}

fn resolve(plugin: &Plugin<Secret>, dispatcher: &Dispatcher) -> Vec<u8> {
    let loan = Arc::new(ResolveLoan {
        settings: REFERENCE.to_vec(),
        material: Mutex::new(vec![0; 128]),
    });
    let mut frame = Frame::new(
        ResolveIn {
            head: in_head(),
            settings: json(&loan.settings),
            secret_buf: std::ptr::null_mut(),
            secret_cap: 0,
        },
        ResolveOut {
            head: out_head(),
            secret: NO_BLOB,
            error_kind: 0,
            _reserved: 0,
            needed: 0,
        },
    );
    {
        let mut material = loan.material.lock().unwrap();
        frame.input.secret_buf = material.as_mut_ptr();
        frame.input.secret_cap = material.len();
    }
    let ticket = dispatcher.mint(0).expect("actual resolve ticket");
    let reply = dispatcher.submit_lent(
        plugin,
        ticket,
        secret::slot::RESOLVE,
        frame,
        DeadlineClass::Call,
        now_ns() + CALL_TIMEOUT.as_nanos() as u64,
        loan.clone() as busbar_plugin_loader::dispatch::Lent,
    );
    let done = reply.wait(CALL_TIMEOUT + Duration::from_secs(5));
    if done.is_none() {
        dispatcher.drop_client(ticket);
    }
    dispatcher.recycle(ticket);
    let done = done.expect("actual Vault resolve finishes within its deadline");
    // Retire an error lease before any assertion can unwind the case. The copied
    // caller buffer below is never guest-leased.
    release(plugin, done.lease);
    assert_eq!(
        done.outcome,
        Outcome::Ready,
        "the committed Vault binding must remain usable: {:?}",
        done.error
    );
    let frame = done.frame.as_ref().expect("actual resolve frame");
    let len = frame.out.secret.len;
    let material = loan.material.lock().unwrap();
    assert_eq!(
        frame.out.secret.ptr,
        material.as_ptr(),
        "actual Vault returns its caller-owned output buffer"
    );
    assert!(
        len <= material.len(),
        "actual Vault output stays inside its loan"
    );
    let bytes = material[..len].to_vec();
    drop(material);
    bytes
}

fn refresh(plugin: &Plugin<Secret>, settings: &[u8], generation: u64) -> Outcome {
    let token = token();
    let mut frame: Frame<RefreshIn, OutHead> = Frame::new(
        RefreshIn {
            head: in_head(),
            generation,
            settings: json(settings),
            secrets: &token,
            secrets_len: 1,
        },
        out_head(),
    );
    let called = plugin.call(life::slot::REFRESH, &mut frame);
    release(plugin, called.lease);
    called.outcome
}

#[test]
fn refused_vault_refresh_preserves_the_committed_connector_binding() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("case-owned production I/O runtime");
    let _entered = runtime.enter();
    let first = VaultPeer::new("known");
    let second = VaultPeer::new("moved");
    // A real deployment policy explicitly allowing this loopback infrastructure fixture.
    let destinations = Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    };
    let guard = crate::process::dest_judge(&destinations).expect("production destination judge");
    let services = KernelServices::new()
        .with_dest_judge(guard.clone())
        .with_mono_clock(Arc::new(now_ns));
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(services),
    ));
    assert!(dispatcher.install_runtime(runtime.handle().clone()));
    assert!(dispatcher.install_io(crate::hostio::process()));
    let entries = vec![
        actual_transport(&dispatcher, "BUSBAR_TEST_TCP_CDYLIB"),
        actual_transport(&dispatcher, "BUSBAR_TEST_HTTP_CDYLIB"),
    ];
    let transports = Transports::new(entries).expect("actual TCP and HTTP compose");
    let tls = crate::tls::client::build_client_config(&EgressTrust::default()).unwrap();
    let table = Arc::new(Connector::serving(
        transports,
        crate::process::judge(guard, &[]),
        Some(Arc::new(tls)),
        dispatcher.conn_waker(),
    ));
    let path = artifact("BUSBAR_TEST_VAULT_CDYLIB");
    let statement = rendering_of_library(&path)
        .expect("actual Vault Statement")
        .expect("actual Vault door");
    let stated = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    assert_eq!(stated.name, "busbar-secret-vault");
    assert_eq!(stated.needs[0].transport, "http");
    assert_eq!(stated.needs[0].target_from, "settings.addr");
    let plugin = load_dropped::<Secret>(
        &path,
        &statement,
        bind(
            &dispatcher,
            "refresh-transaction-vault",
            ConnTable::Host(table.clone()),
        ),
    )
    .expect("actual Vault admitted with production DeclaredConns");
    let owner = plugin.instance();
    let settings =
        serde_json::to_vec(&serde_json::json!({"addr":first.addr,"timeout_secs":5})).unwrap();
    let token = token();
    let mut open = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: json(&settings),
            secrets: &token,
            secrets_len: 1,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    let opened = plugin.call(life::slot::OPEN, &mut open);
    release(&plugin, opened.lease);
    assert_eq!(opened.outcome, Outcome::Ready, "actual Vault opens");
    let mut vault = OpenVault {
        plugin,
        closed: false,
    };
    vault
        .plugin
        .ready(&dispatcher, CALL_TIMEOUT)
        .expect("actual Vault READY");
    assert_eq!(table.declared(owner, NeedId(0)), Some(Ok(())));
    for expected in 1..=5 {
        assert!(resolve(&vault.plugin, &dispatcher) == b"known");
        assert_eq!(first.requests.load(Ordering::SeqCst), expected);
    }
    assert_eq!(
        refresh(&vault.plugin, br#"{"addr":""}"#, 2),
        Outcome::Failed
    );
    assert_eq!(
        first.requests.load(Ordering::SeqCst),
        5,
        "refused refresh performs no backend request"
    );
    assert_eq!(
        vault.plugin.instance(),
        owner,
        "the public instance identity remains stable"
    );
    assert_eq!(
        table.declared(owner, NeedId(0)),
        Some(Ok(())),
        "a refused refresh cannot poison the committed declaration"
    );
    assert!(resolve(&vault.plugin, &dispatcher) == b"known");
    assert_eq!(first.requests.load(Ordering::SeqCst), 6);
    assert_eq!(second.requests.load(Ordering::SeqCst), 0);

    let moved =
        serde_json::to_vec(&serde_json::json!({"addr":second.addr,"timeout_secs":5})).unwrap();
    assert_eq!(refresh(&vault.plugin, &moved, 3), Outcome::Ready);
    assert!(
        resolve(&vault.plugin, &dispatcher) == b"moved",
        "a valid refresh publishes its new target"
    );
    assert_eq!(first.requests.load(Ordering::SeqCst), 6);
    assert_eq!(second.requests.load(Ordering::SeqCst), 1);
    vault.close();
}
