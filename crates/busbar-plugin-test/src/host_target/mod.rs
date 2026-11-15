// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST TARGET (SDK-SAFE-TEST-HOST §10): a plugin repository's conformance subject. A small
//! `[[example]]` binary or in-process driver in that repository loads **this plugin's own door**,
//! linked and as its cdylib, through the loader's real admission and dispatcher, and exposes the
//! network surface its upstream suite needs on loopback. It never loads a second plugin image,
//! never boots `BUSBAR_BIN` and is never built for release.
//!
//! This module is what every target shares (§10.3): the images ([`Images`]), the command line and
//! the ready file ([`Target::main`]), the in-process handle ([`Served`]), the plugin thread per
//! image ([`PluginThread`]), the callers whose tokens flow in and never out ([`Caller`]), and the
//! run report with its fail-closed judgement ([`Report`], [`Unserved`]). What a target serves on
//! its listeners is its [`Subject`]: the carrier's routes (feature `target-http`,
//! [`carrier::Routes`]), a stream framer on loopback TCP ([`stream::Framer`]), and the datagram
//! and plane targets as they join it.
//!
//! **Fail closed.** Anything the target was asked and does not serve is recorded; the run then
//! fails with no allow-list: [`Served::finish`] answers [`Unserved`], `main` exits non-zero, and a
//! [`Served`] dropped unfinished with a non-empty list panics.

#[cfg(feature = "target-http")]
pub mod carrier;
pub mod stream;

use std::cell::Cell;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::redacted::constant_time_eq;
use busbar_contract::secure::SecureVec;
use busbar_plugin_loader::dispatch::Kind;
use busbar_plugin_loader::test_host::{Host, Image, Openable, Opened, Refused as HostRefused};
use sonic_rs::{JsonContainerTrait, JsonValueTrait};

/// What the verdict and every report name as the subject: never a product-level pass.
pub const SUBJECT: &str = "host target; kernel not present";

/// Which images a run serves. Default [`Images::Both`]: one listener set per image, served
/// concurrently, and the suite passes only if both do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Images {
    /// The linked door and the cdylib.
    #[default]
    Both,
    /// The cdylib only (the library core admits).
    Cdylib,
    /// The linked door only.
    Linked,
}

impl Images {
    /// The image names this choice serves, in serving order.
    #[must_use]
    pub fn names(self) -> &'static [&'static str] {
        match self {
            Self::Both => &["linked", "cdylib"],
            Self::Cdylib => &["cdylib"],
            Self::Linked => &["linked"],
        }
    }

    fn parse(text: &str) -> Result<Self, Refused> {
        match text {
            "both" => Ok(Self::Both),
            "cdylib" => Ok(Self::Cdylib),
            "linked" => Ok(Self::Linked),
            _ => Err(Refused::Args(format!(
                "--images {text}: expected both, cdylib or linked"
            ))),
        }
    }
}

/// `image` of this plugin: its linked door for `"linked"`, else the cdylib built from `lib_name`
/// stating what the linked door states.
///
/// # Panics
/// When `image` is `"cdylib"` and no such library exists (the panic names where it looked).
#[must_use]
pub fn image<K: Kind>(image: &str, lib_name: &str, door: DoorFn) -> Image<K> {
    if image == "linked" {
        Image::linked(door)
    } else {
        Image::cdylib(lib_name, door)
    }
}

/// Why a target refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// An image did not load, open or ready: the image and the host's refusal.
    Image(&'static str, HostRefused),
    /// `--listen` or an upstream is not a loopback IP address. A hostname is refused unresolved.
    NotLoopback(String),
    /// A listener or a thread could not start.
    Bind(String),
    /// The command line or a file it names is wrong.
    Args(String),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(image, why) => write!(f, "{image}: {why:?}"),
            Self::NotLoopback(why) => write!(f, "not loopback: {why}"),
            Self::Bind(why) => write!(f, "bind: {why}"),
            Self::Args(why) => write!(f, "arguments: {why}"),
        }
    }
}

/// A caller the driver supplies. Its token flows **in** only: no getter returns it, its `Debug`
/// leaves it out, and neither the ready file nor stdout carries it (§10.3, SEC-1).
pub struct Caller {
    name: String,
    token: SecureVec,
    entries: Vec<String>,
}

impl Caller {
    /// A caller named `name`, with no token and no entries yet.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            token: SecureVec::new(),
            entries: Vec::new(),
        }
    }

    /// The bearer token this caller presents.
    #[must_use]
    pub fn token(mut self, bytes: &[u8]) -> Self {
        self.token = SecureVec::from(bytes);
        self
    }

    /// The entries this caller is granted; `"*"` grants every entry.
    #[must_use]
    pub fn entries(mut self, entries: &[&str]) -> Self {
        self.entries = entries.iter().map(|e| (*e).to_owned()).collect();
        self
    }

    /// The caller's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this caller is granted `entry`.
    #[must_use]
    pub fn grants(&self, entry: &str) -> bool {
        self.entries.iter().any(|e| e == "*" || e == entry)
    }
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller")
            .field("name", &self.name)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

/// The driver's callers, matched by bearer token in constant time.
#[derive(Debug, Default)]
pub struct Callers(Vec<Arc<Caller>>);

impl Callers {
    /// The caller presenting `token`, if any.
    #[must_use]
    pub fn find(&self, token: &[u8]) -> Option<Arc<Caller>> {
        self.0
            .iter()
            .find(|c| !c.token.is_empty() && constant_time_eq(c.token.as_slice(), token))
            .cloned()
    }
}

/// Reads `--callers PATH`: a JSON array of `{"name", "token", "entries"}` the driver wrote with
/// mode 0600. A file others can read is refused, so a token never sits world-readable.
fn read_callers(path: &Path) -> Result<Vec<Caller>, Refused> {
    let bad = |why: String| Refused::Args(format!("--callers {}: {why}", path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| bad(e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(bad(format!(
                "mode {:o} lets others read it; write it 0600",
                mode & 0o777
            )));
        }
    }
    let bytes = std::fs::read(path).map_err(|e| bad(e.to_string()))?;
    let value: sonic_rs::Value = sonic_rs::from_slice(&bytes).map_err(|e| bad(e.to_string()))?;
    let rows = value
        .as_array()
        .ok_or_else(|| bad("not a JSON array".to_owned()))?;
    let mut callers = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let field = |key: &str| row.get(key).and_then(|v| v.as_str());
        let name = field("name").ok_or_else(|| bad("a caller has no \"name\"".to_owned()))?;
        let token = field("token").ok_or_else(|| bad(format!("caller {name} has no \"token\"")))?;
        let mut caller = Caller::new(name).token(token.as_bytes());
        if let Some(entries) = row.get("entries").and_then(|v| v.as_array()) {
            for entry in entries.iter() {
                let entry = entry
                    .as_str()
                    .ok_or_else(|| bad(format!("caller {name}: an entry is not a string")))?;
                caller.entries.push(entry.to_owned());
            }
        }
        callers.push(caller);
    }
    Ok(callers)
}

/// The run report: what the run was asked and could not serve. Shared by every listener of
/// every image; cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct Report(Arc<Mutex<Ledger>>);

#[derive(Debug, Default)]
struct Ledger {
    images: Vec<&'static str>,
    scripted: Vec<String>,
    unserved: Vec<String>,
    /// `$CONFORMANCE_OUT/host-target.json`, rewritten on every change so a target that is killed
    /// instead of finished still leaves its verdict.
    verdict: Option<PathBuf>,
}

impl Report {
    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Everything the run was asked and did not serve, in order. Non-empty fails the run.
    #[must_use]
    pub fn unserved(&self) -> Vec<String> {
        self.ledger().unserved.clone()
    }

    /// Records `what` as asked and not served: the run fails.
    pub(crate) fn record_unserved(&self, what: String) {
        let mut ledger = self.ledger();
        ledger.unserved.push(what);
        write_verdict(&ledger);
    }
}

/// The verdict beside the suite's own (§10.3), through sonic-rs.
fn verdict_json(ledger: &Ledger) -> String {
    let mut v = sonic_rs::Object::new();
    v.insert("subject", SUBJECT);
    v.insert("images", ledger.images.clone());
    v.insert(
        "scripted_by_repo",
        ledger.scripted.iter().collect::<Vec<_>>(),
    );
    v.insert("unserved", ledger.unserved.iter().collect::<Vec<_>>());
    sonic_rs::Value::from(v).to_string()
}

fn write_verdict(ledger: &Ledger) {
    if let Some(path) = &ledger.verdict {
        if let Err(e) = write_atomic(path, verdict_json(ledger).as_bytes()) {
            eprintln!("host target: write the verdict {}: {e}", path.display());
        }
    }
}

/// Writes `bytes` to a sibling temporary file, then renames it over `path`, so a reader never
/// sees a partial file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// The run failed: what it was asked and did not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unserved(pub Vec<String>);

impl fmt::Display for Unserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not served by the host target:")?;
        for what in &self.0 {
            write!(f, "\n  {what}")?;
        }
        Ok(())
    }
}

/// What a target serves on its listeners, one image at a time: the facade's own targets, a closed
/// set: the carrier's route table ([`carrier::Routes`], feature `target-http`) and a stream framer
/// ([`stream::Framer`]); the datagram and plane targets join as variants. A concrete enum, not a
/// trait: every subject is the facade's, so there is no boundary for a trait to stand on (§3.1).
#[non_exhaustive]
pub enum Subject {
    /// The carrier's route table, served over hyper on every image's listener.
    #[cfg(feature = "target-http")]
    Routes(carrier::Routes),
    /// A stream framer, each image on its own loopback TCP listener.
    Stream(stream::Framer),
}

impl Subject {
    /// Binds `image`'s listeners at the addresses [`Binding::addr`] hands out and starts serving
    /// them. Called once per image, in [`Images::names`] order.
    fn bind(&mut self, image: &'static str, at: &Binding<'_>) -> Result<Listening, Refused> {
        match *self {
            #[cfg(feature = "target-http")]
            Self::Routes(ref routes) => routes.bind(image, at),
            Self::Stream(ref framer) => framer.bind(image, at),
        }
    }

    /// A command-line flag `main` does not know, with its value: the subject's to read or refuse.
    fn flag(&mut self, flag: &str, value: &str) -> Result<(), Refused> {
        match *self {
            #[cfg(feature = "target-http")]
            Self::Routes(ref mut routes) => routes.flag(flag, value),
            Self::Stream(ref mut framer) => framer.flag(flag, value),
        }
    }

    /// A command-line flag `main` does not know that takes no value: whether it is the
    /// subject's (and taken).
    fn switch(&mut self, flag: &str) -> bool {
        match *self {
            #[cfg(feature = "target-http")]
            Self::Routes(_) => false,
            Self::Stream(ref mut framer) => framer.switch(flag),
        }
    }

    /// The host services the repository answered with its own script, named in the verdict.
    fn scripted(&self) -> Vec<String> {
        match *self {
            #[cfg(feature = "target-http")]
            Self::Routes(_) => Vec::new(),
            Self::Stream(_) => Vec::new(),
        }
    }
}

/// What a [`Subject`] binds with: the addresses, the callers, the upstreams and the report.
pub struct Binding<'a> {
    at: SocketAddr,
    next: Cell<u16>,
    callers: &'a Arc<Callers>,
    upstreams: &'a [(String, SocketAddr)],
    report: &'a Report,
    seed: u64,
}

impl Binding<'_> {
    /// The address for the next listener: `--listen`'s IP, on port 0 (any) unless `--listen`
    /// named a port, in which case listeners take consecutive ports from it.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        let port = self.next.get();
        if port != 0 {
            self.next.set(port.saturating_add(1));
        }
        SocketAddr::new(self.at.ip(), port)
    }

    /// The driver's callers.
    #[must_use]
    pub fn callers(&self) -> &Arc<Callers> {
        self.callers
    }

    /// The loopback address the driver mapped `entry` to, if any.
    #[must_use]
    pub fn upstream(&self, entry: &str) -> Option<SocketAddr> {
        self.upstreams
            .iter()
            .find(|(e, _)| e == entry)
            .map(|(_, addr)| *addr)
    }

    /// The run report.
    #[must_use]
    pub fn report(&self) -> &Report {
        self.report
    }

    /// `--seed`: the run's one seed for anything a target draws.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }
}

/// One image's listeners, bound and serving.
pub struct Listening {
    /// The data listener.
    pub addr: SocketAddr,
    /// The admin listener, where the subject has one.
    pub admin: Option<SocketAddr>,
    /// Stops the listeners and everything they started, and waits for them.
    pub stop: Box<dyn FnOnce() + Send>,
}

/// A host target over `subject`: its images, its address, its callers and upstreams.
pub struct Target {
    subject: Subject,
    images: Images,
    listen: String,
    ready_file: Option<PathBuf>,
    seed: u64,
    callers: Vec<Arc<Caller>>,
    upstreams: Vec<(String, String)>,
}

impl Target {
    /// A target serving `subject` on `127.0.0.1`, both images, seed 0.
    #[must_use]
    pub fn new(subject: impl Into<Subject>) -> Self {
        Self {
            subject: subject.into(),
            images: Images::Both,
            listen: Ipv4Addr::LOCALHOST.to_string(),
            ready_file: None,
            seed: 0,
            callers: Vec::new(),
            upstreams: Vec::new(),
        }
    }

    /// Which images to serve.
    #[must_use]
    pub fn images(mut self, images: Images) -> Self {
        self.images = images;
        self
    }

    /// Where to listen: a loopback IP, or IP and port. A hostname is refused at start.
    #[must_use]
    pub fn listen(mut self, addr: &str) -> Self {
        addr.clone_into(&mut self.listen);
        self
    }

    /// The run's seed.
    #[must_use]
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// A caller the driver supplies (its token flows in only).
    #[must_use]
    pub fn caller(mut self, caller: Caller) -> Self {
        self.callers.push(Arc::new(caller));
        self
    }

    /// Maps `entry` to a loopback address. Any other address is refused at start.
    #[must_use]
    pub fn upstream(mut self, entry: &str, addr: SocketAddr) -> Self {
        self.upstreams.push((entry.to_owned(), addr.to_string()));
        self
    }

    /// Binds every image's listeners and serves them in-process.
    ///
    /// # Errors
    /// When an address is not loopback, a listener cannot bind, or an image is refused.
    pub fn serve(mut self) -> Result<Served, Refused> {
        let at = loopback(&self.listen)?;
        let mut upstreams = Vec::with_capacity(self.upstreams.len());
        for (entry, addr) in &self.upstreams {
            upstreams.push((entry.clone(), loopback(addr)?));
        }
        let verdict = std::env::var_os("CONFORMANCE_OUT")
            .map(|dir| PathBuf::from(dir).join("host-target.json"));
        let report = Report::default();
        {
            let mut ledger = report.ledger();
            ledger.images = self.images.names().to_vec();
            ledger.scripted = self.subject.scripted();
            ledger.verdict = verdict;
        }
        let callers = Arc::new(Callers(std::mem::take(&mut self.callers)));
        let binding = Binding {
            at,
            next: Cell::new(at.port()),
            callers: &callers,
            upstreams: &upstreams,
            report: &report,
            seed: self.seed,
        };
        let mut served = Served {
            bound: Vec::new(),
            report: report.clone(),
            seed: self.seed,
            done: false,
        };
        for &image in self.images.names() {
            match self.subject.bind(image, &binding) {
                Ok(listening) => served.bound.push((image, listening)),
                Err(refused) => {
                    served.stop();
                    served.done = true;
                    // The verdict says the run failed, never a stale pass.
                    report.record_unserved(format!("refused at start: {refused}"));
                    return Err(refused);
                }
            }
        }
        write_verdict(&report.ledger());
        Ok(served)
    }

    /// The target as its own process (§10.3). Reads `--listen ADDR`, `--images
    /// both|cdylib|linked`, `--ready-file PATH`, `--seed N`, `--callers PATH` and `--upstream
    /// ENTRY=ADDR` (any other flag is the subject's, with a value or, like `--mutant`, without);
    /// binds every listener; atomically writes the ready file and prints one `BUSBAR_TARGET
    /// {json}` line, both naming addresses, the seed and the images only; serves until stdin
    /// closes; then judges the run. Exit 0: served; 1: something was not served; 2: refused
    /// at start (the ready file holds `{"error": ..}`).
    #[must_use]
    pub fn main(mut self) -> ExitCode {
        let started = self.args(std::env::args().skip(1));
        let ready = self.ready_file.clone();
        let served = match started.and_then(|()| self.serve()) {
            Ok(served) => served,
            Err(refused) => {
                eprintln!("host target refused: {refused}");
                if let Some(path) = &ready {
                    let mut v = sonic_rs::Object::new();
                    v.insert("error", refused.to_string().as_str());
                    let text = sonic_rs::Value::from(v).to_string();
                    if let Err(e) = write_atomic(path, text.as_bytes()) {
                        eprintln!("host target: write {}: {e}", path.display());
                    }
                }
                return ExitCode::from(2);
            }
        };
        let line = served.ready_json();
        if let Some(path) = &ready {
            if let Err(e) = write_atomic(path, line.as_bytes()) {
                eprintln!("host target: write {}: {e}", path.display());
                drop(served.finish());
                return ExitCode::from(2);
            }
        }
        println!("BUSBAR_TARGET {line}");
        let mut stdin = std::io::stdin().lock();
        let mut sink = [0u8; 512];
        while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
        match served.finish() {
            Ok(_) => ExitCode::SUCCESS,
            Err(unserved) => {
                eprintln!("{unserved}");
                ExitCode::FAILURE
            }
        }
    }

    fn args(&mut self, mut args: impl Iterator<Item = String>) -> Result<(), Refused> {
        while let Some(flag) = args.next() {
            if self.subject.switch(&flag) {
                continue;
            }
            let value = args
                .next()
                .ok_or_else(|| Refused::Args(format!("{flag} needs a value")))?;
            match flag.as_str() {
                "--listen" => self.listen = value,
                "--images" => self.images = Images::parse(&value)?,
                "--ready-file" => self.ready_file = Some(PathBuf::from(value)),
                "--seed" => {
                    self.seed = value
                        .parse()
                        .map_err(|_| Refused::Args(format!("--seed {value}: not a number")))?;
                }
                "--callers" => self
                    .callers
                    .extend(read_callers(Path::new(&value))?.into_iter().map(Arc::new)),
                "--upstream" => {
                    let (entry, addr) = value.split_once('=').ok_or_else(|| {
                        Refused::Args(format!("--upstream {value}: expected ENTRY=ADDR"))
                    })?;
                    self.upstreams.push((entry.to_owned(), addr.to_owned()));
                }
                _ => self.subject.flag(&flag, &value)?,
            }
        }
        Ok(())
    }
}

/// `text` as a loopback socket address (port 0 when only an IP is given). The IP is parsed, never
/// resolved, and must be loopback once canonical (`::1` and `::ffff:127.0.0.1` pass).
fn loopback(text: &str) -> Result<SocketAddr, Refused> {
    let addr = text
        .parse::<SocketAddr>()
        .or_else(|_| text.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 0)))
        .map_err(|_| {
            Refused::NotLoopback(format!(
                "{text}: not an IP address (a hostname is never resolved)"
            ))
        })?;
    if addr.ip().to_canonical().is_loopback() {
        Ok(addr)
    } else {
        Err(Refused::NotLoopback(format!(
            "{text}: not a loopback address"
        )))
    }
}

/// A target serving in-process. [`Served::finish`] judges the run; dropping it unfinished with
/// anything unserved panics (unless the thread is already panicking), so a driver that never
/// calls `finish` still fails.
pub struct Served {
    bound: Vec<(&'static str, Listening)>,
    report: Report,
    seed: u64,
    done: bool,
}

impl Served {
    fn listening(&self, image: &str) -> &Listening {
        self.bound
            .iter()
            .find(|(name, _)| *name == image)
            .map(|(_, l)| l)
            .unwrap_or_else(|| {
                let names: Vec<&str> = self.bound.iter().map(|(n, _)| *n).collect();
                panic!("no image `{image}` in this run (served: {names:?})")
            })
    }

    /// `image`'s data listener (`"linked"` or `"cdylib"`).
    ///
    /// # Panics
    /// When the run does not serve `image`.
    #[must_use]
    pub fn addr(&self, image: &str) -> SocketAddr {
        self.listening(image).addr
    }

    /// `image`'s admin listener, where its subject has one.
    ///
    /// # Panics
    /// When the run does not serve `image`.
    #[must_use]
    pub fn admin_addr(&self, image: &str) -> Option<SocketAddr> {
        self.listening(image).admin
    }

    /// What the run has been asked and could not serve, so far.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Stops every listener and image, writes the verdict, and judges the run.
    ///
    /// # Errors
    /// [`Unserved`] when anything the run was asked was not served.
    pub fn finish(mut self) -> Result<Report, Unserved> {
        self.stop();
        self.done = true;
        write_verdict(&self.report.ledger());
        let unserved = self.report.unserved();
        if unserved.is_empty() {
            Ok(self.report.clone())
        } else {
            Err(Unserved(unserved))
        }
    }

    fn stop(&mut self) {
        for (_, listening) in &mut self.bound {
            let stop = std::mem::replace(&mut listening.stop, Box::new(|| {}));
            stop();
        }
    }

    /// The ready file and the `BUSBAR_TARGET` line: addresses, the seed and the images only.
    fn ready_json(&self) -> String {
        let mut images = sonic_rs::Object::new();
        for (name, l) in &self.bound {
            let mut entry = sonic_rs::Object::new();
            entry.insert("addr", l.addr.to_string().as_str());
            let admin = l.admin.map(|a| a.to_string());
            entry.insert("admin", admin.as_deref());
            images.insert(name, entry);
        }
        let mut v = sonic_rs::Object::new();
        v.insert("images", images);
        v.insert("seed", self.seed);
        sonic_rs::Value::from(v).to_string()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.stop();
        let unserved = self.report.unserved();
        if !unserved.is_empty() && !std::thread::panicking() {
            panic!(
                "the host target was dropped unfinished: {}",
                Unserved(unserved)
            );
        }
    }
}

type Job<K> = Box<dyn FnOnce(&mut Opened<K>) + Send>;

/// One image, opened and owned by its own thread (an [`Opened`] stays on its thread); other
/// threads hand it work. Dropping it closes the job queue, CLOSEs the instance on its thread and
/// waits for the thread.
pub struct PluginThread<K: Openable> {
    jobs: Option<mpsc::Sender<Job<K>>>,
    thread: Option<JoinHandle<()>>,
}

impl<K: Openable> PluginThread<K> {
    /// Opens `img` as instance `name` with `settings` on a new thread, on the host `make_host`
    /// builds there: `Host::new(test_caller_binding())`, the binding behind the contract's
    /// dev-only `test-seal`, which the repository enables in its own `[dev-dependencies]`.
    ///
    /// # Errors
    /// The host's refusal when the image does not load, open or ready.
    pub fn open(
        make_host: impl FnOnce() -> Host + Send + 'static,
        img: Image<K>,
        name: &str,
        settings: &[u8],
    ) -> Result<Self, HostRefused> {
        let (opened_tx, opened_rx) = mpsc::sync_channel::<Result<(), HostRefused>>(1);
        let (jobs, queue) = mpsc::channel::<Job<K>>();
        let instance = name.to_owned();
        let settings = settings.to_vec();
        let thread = std::thread::Builder::new()
            .name(format!("plugin-{name}"))
            .spawn(move || {
                let host = make_host();
                match host.open(img, &instance, &settings) {
                    Err(refused) => drop(opened_tx.send(Err(refused))),
                    Ok(mut opened) => {
                        drop(opened_tx.send(Ok(())));
                        while let Ok(job) = queue.recv() {
                            job(&mut opened);
                        }
                    }
                }
            })
            .map_err(|e| HostRefused::Open(format!("start the plugin thread for {name}: {e}")))?;
        match opened_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                jobs: Some(jobs),
                thread: Some(thread),
            }),
            Ok(Err(refused)) => {
                drop(thread.join());
                Err(refused)
            }
            Err(_) => {
                drop(thread.join());
                Err(HostRefused::Open(format!(
                    "the plugin thread for {name} ended while opening"
                )))
            }
        }
    }

    /// Runs `f` on the image's thread and waits for its answer. `None` when the thread is gone
    /// (an earlier job panicked).
    pub fn run<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Opened<K>) -> R + Send + 'static,
    ) -> Option<R> {
        let (tx, rx) = mpsc::sync_channel(1);
        let job: Job<K> = Box::new(move |opened: &mut Opened<K>| drop(tx.send(f(opened))));
        self.jobs.as_ref()?.send(job).ok()?;
        rx.recv().ok()
    }
}

impl<K: Openable> Drop for PluginThread<K> {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}
