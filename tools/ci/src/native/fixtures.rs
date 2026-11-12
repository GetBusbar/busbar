//! Native CI fixture lifecycle (former `native_fixtures.Services`, confined
//! branch) and controller-only fixture capabilities (former
//! `native_fixture_proxy.Fixtures`): each Unix socket relays to one fixed
//! loopback peer; no protocol accepts a destination address.
use super::peers::Peers;
use super::sp::{self, R, runtime, value_error};
use super::{Q, native_settings};
use crate::json::{self, Value, object};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// One relay leg: copy until EOF or error, then half-close the peer.
pub trait Leg: Read + Write + Send {
    fn half_close(&self);
    fn nodelay(&self) {}
}
impl Leg for UnixStream {
    fn half_close(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}
impl Leg for TcpStream {
    fn half_close(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
    fn nodelay(&self) {
        // Preserve prompt small writes across the Unix capability instead of
        // adding Nagle/delayed-ACK stalls to every database protocol exchange.
        let _ = self.set_nodelay(true);
    }
}

/// `confinement_entry.relay(left, right)`.
pub fn relay(left: &mut dyn Leg, right: &mut dyn Leg) {
    right.nodelay();
    let mut buffer = vec![0u8; 65536];
    loop {
        match left.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if right.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
    right.half_close();
}

/// Relay both directions; the reverse leg runs on its own thread, joined for
/// at most five seconds like the former daemon thread.
fn bidirectional(
    mut downstream: UnixStream,
    upstream: Box<dyn Leg>,
    mut upstream_reader: Box<dyn Leg>,
) {
    let mut down_writer = match downstream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let (done, finished) = std::sync::mpsc::channel();
    let mut forward = upstream;
    std::thread::spawn(move || {
        relay(&mut downstream, forward.as_mut());
        let _ = done.send(());
    });
    relay(upstream_reader.as_mut(), &mut down_writer);
    let _ = finished.recv_timeout(Duration::from_secs(5));
}

struct Server {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    active: Arc<Mutex<Vec<(u64, UnixStream)>>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

#[derive(Clone, Copy)]
struct Target {
    port: u16,
    namespace: Option<(i32, u16, u64, u64)>,
}

pub struct Fixtures {
    directory: PathBuf,
    map: PathBuf,
    collector: (u64, u64),
    servers: Vec<Server>,
    pub ports: Vec<i128>,
    slots: Arc<AtomicUsize>,
}

const SLOTS: usize = 64;

impl Fixtures {
    pub fn new(directory: &Path, map: &Path, collector: (u64, u64)) -> Fixtures {
        Fixtures {
            directory: directory.to_owned(),
            map: map.to_owned(),
            collector,
            servers: Vec::new(),
            ports: Vec::new(),
            slots: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// `add(port, namespace=None, peer_port=None)`.
    pub fn add(&mut self, port: i128, namespace: Option<(i32, i128)>) -> R<()> {
        if !(1024..=65535).contains(&port) {
            return Err(value_error("invalid fixed fixture port"));
        }
        if self.ports.contains(&port) {
            return Ok(());
        }
        if self.ports.len() >= 32 {
            return Err(value_error("too many fixed fixture capabilities"));
        }
        if let Some((_, peer)) = namespace
            && !(1..=65535).contains(&peer)
        {
            return Err(value_error("invalid pinned namespace endpoint"));
        }
        let path = self.directory.join(format!("{port}.sock"));
        if sp::text(&path).len() > 100 {
            return Err(value_error(
                "fixture socket path exceeds portable Unix path limit",
            ));
        }
        let listener = UnixListener::bind(&path).map_err(|e| sp::os_error(&e, None))?;
        let started = (|| -> R<Server> {
            sp::chmod(&path, 0o666)?;
            listener
                .set_nonblocking(true)
                .map_err(|e| sp::os_error(&e, None))?;
            let target = Target {
                port: port as u16,
                namespace: namespace
                    .map(|(fd, peer)| (fd, peer as u16, self.collector.0, self.collector.1)),
            };
            let stop = Arc::new(AtomicBool::new(false));
            let active: Arc<Mutex<Vec<(u64, UnixStream)>>> = Arc::new(Mutex::new(Vec::new()));
            let handlers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
            let accept = {
                let (stop, active, handlers, slots) = (
                    stop.clone(),
                    active.clone(),
                    handlers.clone(),
                    self.slots.clone(),
                );
                std::thread::spawn(move || serve(listener, target, stop, active, handlers, slots))
            };
            Ok(Server {
                path: path.clone(),
                stop,
                accept: Some(accept),
                active,
                handlers,
            })
        })();
        let server = match started {
            Ok(server) => server,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        self.servers.push(server);
        self.ports.push(port);
        self.write_map()
    }

    fn write_map(&self) -> R<()> {
        let mut ports = self.ports.clone();
        ports.sort();
        let rows = Value::Array(
            ports
                .iter()
                .map(|p| {
                    object([
                        ("port", Value::int(*p)),
                        ("socket", format!("{p}.sock").into()),
                    ])
                })
                .collect(),
        );
        sp::write(&self.map, json::dumps(&rows, false) + "\n")
    }

    pub fn close(&mut self) -> R<()> {
        for mut server in self.servers.drain(..) {
            server.stop.store(true, Ordering::SeqCst);
            if let Some(accept) = server.accept.take() {
                let _ = accept.join();
            }
            for (_, stream) in server.active.lock().unwrap().iter() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            let handlers: Vec<JoinHandle<()>> = server.handlers.lock().unwrap().drain(..).collect();
            for handler in handlers {
                let _ = handler.join();
            }
            let _ = std::fs::remove_file(&server.path);
        }
        self.ports.clear();
        sp::write(&self.map, b"[]\n")
    }
}

fn serve(
    listener: UnixListener,
    target: Target,
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Vec<(u64, UnixStream)>>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    slots: Arc<AtomicUsize>,
) {
    let mut next = 0u64;
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        if slots.fetch_add(1, Ordering::SeqCst) >= SLOTS {
            slots.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        let _ = stream.set_nonblocking(false);
        next += 1;
        let id = next;
        if let Ok(clone) = stream.try_clone() {
            active.lock().unwrap().push((id, clone));
        }
        let (active, slots) = (active.clone(), slots.clone());
        let handler = std::thread::spawn(move || {
            handle(stream, target);
            active.lock().unwrap().retain(|(i, _)| *i != id);
            slots.fetch_sub(1, Ordering::SeqCst);
        });
        handlers.lock().unwrap().push(handler);
    }
}

fn handle(request: UnixStream, target: Target) {
    let _ = request.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = request.set_write_timeout(Some(Duration::from_secs(60)));
    match target.namespace {
        None => {
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], target.port));
            let Ok(upstream) = TcpStream::connect_timeout(&address, Duration::from_secs(10)) else {
                return;
            };
            let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(60)));
            let Ok(reader) = upstream.try_clone() else {
                return;
            };
            bidirectional(request, Box::new(upstream), Box::new(reader));
        }
        Some((namespace, peer, uid, gid)) => {
            let Ok((upstream, child)) = UnixStream::pair() else {
                return;
            };
            let mut helper = match spawn_relay(namespace, &child, peer, uid, gid) {
                Ok(helper) => helper,
                Err(_) => return,
            };
            drop(child);
            let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
            let _ = upstream.set_write_timeout(Some(Duration::from_secs(60)));
            if let Ok(reader) = upstream.try_clone() {
                bidirectional(request, Box::new(upstream), Box::new(reader));
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if !matches!(helper.try_wait(), Ok(None)) {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = helper.kill();
                    let _ = helper.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// The identity-dropping namespace relay (former `native_namespace_relay.py`),
/// run as this controller binary's `native-relay` command with inherited fds.
fn spawn_relay(
    namespace: i32,
    child: &UnixStream,
    port: u16,
    uid: u64,
    gid: u64,
) -> std::io::Result<std::process::Child> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let stream = child.as_raw_fd();
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args([
            "native-relay".to_owned(),
            namespace.to_string(),
            stream.to_string(),
            port.to_string(),
            uid.to_string(),
            gid.to_string(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            relay_ffi::inherit(namespace)?;
            relay_ffi::inherit(stream)
        });
    }
    command.spawn()
}

mod relay_ffi {
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;

    /// Clear close-on-exec for one descriptor (`pass_fds`).
    pub fn inherit(fd: i32) -> std::io::Result<()> {
        unsafe {
            let flags = fcntl(fd, F_GETFD);
            if flags < 0 || fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        pub fn setns(fd: i32, kind: i32) -> i32;
        pub fn setgroups(size: usize, list: *const u32) -> i32;
        pub fn setresgid(r: u32, e: u32, s: u32) -> i32;
        pub fn setresuid(r: u32, e: u32, s: u32) -> i32;
        pub fn prctl(option: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
        pub fn close(fd: i32) -> i32;
    }
}

/// `busbar-ci native-relay NAMESPACE_FD STREAM_FD PORT UID GID`: enter only
/// the pinned fixture network namespace, drop the host identity, and copy
/// opaque bytes to one fixed loopback port.
pub fn relay_main(args: &[String]) -> i32 {
    match relay_run(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("busbar-ci native-relay: {error}");
            1
        }
    }
}

#[cfg(target_os = "linux")]
fn relay_run(args: &[String]) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    let numbers: Vec<i64> = args
        .iter()
        .map(|a| {
            a.parse::<i64>()
                .map_err(|_| format!("invalid literal for int() with base 10: '{a}'"))
        })
        .collect::<Result<_, _>>()?;
    let [namespace, stream, port, uid, gid] = numbers.as_slice() else {
        return Err("expected five relay arguments".into());
    };
    if !(0 < *port && *port < 65536 && *uid >= 65536 && *gid >= 65536) {
        return Err("invalid protected relay endpoint".into());
    }
    let os = || std::io::Error::last_os_error().to_string();
    unsafe {
        if relay_ffi::setns(*namespace as i32, 0x4000_0000) != 0 {
            return Err(format!(
                "cannot enter pinned fixture network namespace: {}",
                os()
            ));
        }
        relay_ffi::close(*namespace as i32);
        if relay_ffi::setgroups(0, std::ptr::null()) != 0
            || relay_ffi::setresgid(*gid as u32, *gid as u32, *gid as u32) != 0
            || relay_ffi::setresuid(*uid as u32, *uid as u32, *uid as u32) != 0
        {
            return Err(format!("cannot drop relay identity: {}", os()));
        }
        if relay_ffi::prctl(38, 1, 0, 0, 0) != 0 {
            return Err(format!("cannot restrict relay privileges: {}", os()));
        }
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    for key in ["CapEff", "CapPrm", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}:")))
            .ok_or_else(|| format!("'{key}'"))?;
        if u64::from_str_radix(value.trim(), 16).map_err(|e| e.to_string())? != 0 {
            return Err("relay retained host capabilities after identity drop".into());
        }
    }
    let downstream = unsafe { UnixStream::from_raw_fd(*stream as i32) };
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], *port as u16));
    let upstream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|e| e.to_string())?;
    let timeout = Some(Duration::from_secs(60));
    let _ = downstream.set_read_timeout(timeout);
    let _ = downstream.set_write_timeout(timeout);
    let _ = upstream.set_read_timeout(timeout);
    let _ = upstream.set_write_timeout(timeout);
    let reader = upstream.try_clone().map_err(|e| e.to_string())?;
    bidirectional(downstream, Box::new(upstream), Box::new(reader));
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn relay_run(_: &[String]) -> Result<(), String> {
    Err("network namespace relay requires Linux".into())
}

/// `urlparse(value)` hostname and port for fixture capability URLs.
pub fn loopback_port(value: &str) -> R<Option<(String, Option<i128>)>> {
    let Some((_, rest)) = value.split_once("://") else {
        return Ok(None);
    };
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let (host, port) = if let Some(after) = host_port.strip_prefix('[') {
        match after.split_once(']') {
            Some((h, rest)) => (h.to_owned(), rest.strip_prefix(':')),
            None => return Err(value_error("Invalid IPv6 URL")),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (host_port.to_owned(), None),
        }
    };
    let port = match port {
        None | Some("") => None,
        Some(text) => {
            let number = text
                .parse::<i128>()
                .ok()
                .filter(|_| text.bytes().all(|c| c.is_ascii_digit()))
                .ok_or_else(|| {
                    value_error(format!(
                        "Port could not be cast to integer value as {}",
                        crate::py::repr_str(text)
                    ))
                })?;
            if !(0..=65535).contains(&number) {
                return Err(value_error("Port out of range 0-65535"));
            }
            Some(number)
        }
    };
    Ok(Some((host.to_ascii_lowercase(), port)))
}

pub struct Services {
    pub proxy: Fixtures,
    peers: Option<Peers>,
    pub tag: String,
    pub required: Value,
    pub requested: Vec<String>,
    pub images: Vec<(String, String)>,
}

impl Services {
    /// `with Services(q, host):` — initialization, then provisioning; a
    /// provisioning failure disposes everything before it is raised.
    pub fn open(q: &mut Q, host: &Path) -> R<Services> {
        let mut services = Self::new(q, host)?;
        match services.enter(q) {
            Ok(()) => Ok(services),
            Err(error) => match services.dispose(q) {
                Err(closed) => Err(closed),
                Ok(()) => Err(error),
            },
        }
    }

    fn new(q: &mut Q, _host: &Path) -> R<Services> {
        let execution = q.execution.as_ref().unwrap();
        let collector = execution.config.at("collector");
        let proxy = Fixtures::new(
            &execution.fixture_directory,
            &execution.fixture_map,
            (
                collector.at("uid").as_u64().unwrap_or(0),
                collector.at("gid").as_u64().unwrap_or(0),
            ),
        );
        let tag = format!("boundary-{}", q.job_id());
        let required = native_settings(&q.repository, &q.policy)?;
        let requested: Vec<String> = required
            .at("services")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let mut images = Vec::new();
        let source = q.trusted.join("testing/fleet-fixtures/service-images.tsv");
        let mut rows: Vec<String> = Vec::new();
        for line in super::staged::splitlines(&sp::read_text(&source)?) {
            if line.is_empty() || line.starts_with('#') {
                rows.push(line.to_owned());
                continue;
            }
            let mut cells: Vec<String> = line.split('\t').map(str::to_owned).collect();
            let cell = |i: usize| {
                cells
                    .get(i)
                    .cloned()
                    .ok_or_else(|| value_error("list index out of range"))
            };
            let image = format!("{}@{}", cell(1)?, cell(2)?);
            let name = cell(0)?;
            images.retain(|(n, _): &(String, String)| *n != name);
            images.push((name.clone(), image));
            if ["postgres", "mysql", "valkey"].contains(&name.as_str()) {
                let listener = std::net::TcpListener::bind("127.0.0.1:0")
                    .map_err(|e| sp::os_error(&e, None))?;
                let port = listener
                    .local_addr()
                    .map_err(|e| sp::os_error(&e, None))?
                    .port();
                if cells.len() <= 5 {
                    return Err(value_error("list assignment index out of range"));
                }
                cells[5] = port.to_string();
            }
            rows.push(cells.join("\t"));
        }
        let table = q.control.join("service-images.tsv");
        sp::write(&table, rows.join("\n") + "\n")?;
        q.env.set("BUSBAR_STORE_QA_TAG", tag.as_str());
        q.env.set("SERVICE_IMAGES_TSV", sp::text(&table));
        let endpoint = collector
            .at("docker_host")
            .as_str()
            .unwrap_or("")
            .to_owned();
        q.env.set("DOCKER_HOST", endpoint);
        let docker_dir = Path::new(execution.config.at("docker").as_str().unwrap_or(""))
            .parent()
            .map(sp::text)
            .unwrap_or_default();
        let path = format!(
            "{docker_dir}:{}",
            q.env.get("PATH").unwrap_or("/usr/bin:/bin")
        );
        q.env.set("PATH", path);
        Ok(Services {
            proxy,
            peers: None,
            tag,
            required,
            requested,
            images,
        })
    }

    pub fn image(&self, service: &str) -> R<String> {
        self.images
            .iter()
            .find(|(n, _)| n == service)
            .map(|(_, i)| i.clone())
            .ok_or_else(|| sp::key_error(service))
    }

    fn enter(&mut self, q: &mut Q) -> R<()> {
        let migration = self
            .required
            .get("migration_fixture")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(migration) = &migration
            && !q.staged_fixtures.iter().any(|(n, _)| n == migration)
        {
            return Err(runtime(
                "confined migration witness requires its typed, pinned 1.5.5 fixture input",
            ));
        }
        if !self.requested.is_empty() {
            let mut peers = Peers::new(q)?;
            let requested = self.requested.clone();
            let provisioned = peers.provision(q, self, &requested);
            self.peers = Some(peers);
            provisioned?;
        }
        // The supported migration witness is produced by the real published
        // 1.5.5 artifact, using the repository's digest-checked recorder.
        if let Some(migration) = &migration {
            let fixture = q
                .staged_fixtures
                .iter()
                .find(|(n, _)| n == migration)
                .map(|(_, p)| p.clone())
                .unwrap();
            let script = sp::text(&q.trusted.join("scripts/store-migration-fixture.sh"));
            q.run_controller_in(
                "migration-fixture-check",
                vec!["bash".into(), script, "check".into(), sp::text(&fixture)],
                &q.root.clone(),
                120,
            )?;
            q.env
                .set("BUSBAR_TEST_SQLITE_155_FIXTURE", sp::text(&fixture));
        }
        for (key, value) in q.env.0.clone() {
            if key.starts_with("BUSBAR_TEST_") && (key.ends_with("_URL") || key.ends_with("_ADDR"))
            {
                let parsed = loopback_port(&value)?;
                let Some((host, Some(port))) = parsed.filter(|(h, _)| h == "127.0.0.1") else {
                    return Err(runtime("fixture is not an explicit loopback capability"));
                };
                debug_assert_eq!(host, "127.0.0.1");
                self.proxy.add(port, None)?;
            }
        }
        let mut images = Vec::new();
        for name in &self.requested {
            images.push((name.clone(), Value::from(self.image(name)?)));
        }
        q.receipt.set("fixture_images", Value::Object(images));
        q.save()
    }

    fn dispose(&mut self, q: &mut Q) -> R<()> {
        self.proxy.close()?;
        if let Some(peers) = self.peers.as_mut() {
            peers.close(q)?;
        }
        q.receipt.set(
            "fixture_cleanup",
            object([
                ("removed", true.into()),
                ("remaining", Value::Array(Vec::new())),
            ]),
        );
        q.save()
    }

    pub fn close(mut self, q: &mut Q) -> R<()> {
        self.dispose(q)
    }

    pub fn proxy(&mut self) -> &mut Fixtures {
        &mut self.proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_urls_must_name_explicit_loopback_ports() {
        assert_eq!(
            loopback_port("postgres://busbar:busbar@127.0.0.1:27000/busbar_store_qa").unwrap(),
            Some(("127.0.0.1".into(), Some(27000)))
        );
        assert_eq!(
            loopback_port("http://127.0.0.1/x").unwrap(),
            Some(("127.0.0.1".into(), None))
        );
        assert_eq!(
            loopback_port("ldap://LOCALHOST:389").unwrap(),
            Some(("localhost".into(), Some(389)))
        );
        assert_eq!(loopback_port("not-a-url").unwrap(), None);
        assert!(loopback_port("http://127.0.0.1:99999/").is_err());
    }

    #[test]
    fn fixture_capability_relays_only_to_its_fixed_loopback_peer() {
        let base =
            sp::resolve(&std::env::temp_dir()).join(format!("bc-fx-{}", &sp::uuid_hex()[..8]));
        std::fs::create_dir_all(&base).unwrap();
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = i128::from(peer.local_addr().unwrap().port());
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = peer.accept().unwrap();
            let mut buffer = [0u8; 5];
            stream.read_exact(&mut buffer).unwrap();
            stream.write_all(&buffer).unwrap();
        });
        let map = base.join("map.json");
        let mut fixtures = Fixtures::new(&base, &map, (525288, 525288));
        if port < 1024 {
            return;
        }
        fixtures.add(port, None).unwrap();
        fixtures.add(port, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&map).unwrap(),
            format!("[{{\"port\": {port}, \"socket\": \"{port}.sock\"}}]\n")
        );
        let mut client = UnixStream::connect(base.join(format!("{port}.sock"))).unwrap();
        client.write_all(b"hello").unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"hello");
        drop(client);
        echo.join().unwrap();
        assert_eq!(
            fixtures.add(80, None).unwrap_err().message,
            "invalid fixed fixture port"
        );
        fixtures.close().unwrap();
        assert_eq!(std::fs::read_to_string(&map).unwrap(), "[]\n");
        assert!(!base.join(format!("{port}.sock")).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
