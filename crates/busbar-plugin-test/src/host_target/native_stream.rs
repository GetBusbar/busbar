// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native message-stream conformance (WS-NATIVE-SUBJECT r2).
//! This is a bounded host target, not the production listener or a WebSocket implementation.
//! Signed packages use the production parser and admission boundary, with explicit trust and build identity.

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use busbar_plugin_abi::host::HostExt;
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::plugin::__rt::LinkedPlugin;
use busbar_plugin_abi::records::{tag, Reply, U32Rec, Writer};
use busbar_plugin_abi::transport::{
    CONN_UPGRADED, CR_DRAIN, E_BODY, E_CLOSE, MSG_BINARY, MSG_FIN, MSG_TEXT, ROLE_SERVER,
};
use busbar_plugin_loader::admit::{self, Admitted};
use busbar_ports::transport::{ConnIn, TransportOut, TransportPort, TransportSession};

// Plain producer vocabulary: callers supply their authenticated trust facts. No test key is inferred.
pub use busbar_plugin_loader::admit::TrustConfig;
pub use busbar_plugin_loader::sign::{public_key_from_hex, FirstPartyKey, TrustInput};

use crate::fake_needs::FakeNeeds;
use crate::suites::harness::Harness;

const READ_BYTES: usize = 64 * 1024;
const TIMER_TURN: usize = 64;
const SHUTDOWN_TICK: Duration = Duration::from_millis(100);

#[cfg(target_os = "linux")]
fn unpack_package(
    archive: &[u8],
) -> Result<busbar_plugin_loader::tarball::UnpackedPlugin, Failure> {
    use busbar_plugin_loader::{sign, supported_abi, tarball};

    let package = tarball::unpack(archive).map_err(|_| Failure::Admission)?;
    // Match Registry's package boundary before invoking native admission. Its lower-level
    // stamp/signature checks do not authorize manifest host, alias or operational metadata.
    sign::validate_structure(
        &package.manifest,
        &package.lib_bytes,
        &supported_abi,
        sign::HOST_IDENTITY,
    )
    .map_err(|_| Failure::Admission)?;
    Ok(package)
}

#[cfg(any(target_os = "linux", test))]
fn build_digest(expected: &str) -> Result<[u8; 32], Failure> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Failure::Admission);
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16)
            .map_err(|_| Failure::Admission)?;
    }
    Ok(digest)
}

/// Failure categories never include client payload or credential text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    UnsupportedBodyMode,
    Framing,
    Limit,
    Shape,
    TimerNoProgress,
    Deadline,
    Admission,
    Port,
    Io,
    Thread,
    MutationMissing,
}

/// Explicit host-target limits; no production configuration is inferred.
#[derive(Clone, Debug)]
pub struct StreamLimits {
    pub header_bytes: usize,
    pub header_fields: usize,
    pub streams: usize,
    pub messages: usize,
    pub message_bytes: usize,
    pub assembly_bytes: usize,
    pub queued_bytes: usize,
    pub output_records: usize,
    pub output_bytes: usize,
    pub wire_records: usize,
    pub wire_bytes: usize,
    pub connections: usize,
    pub io_timeout: Duration,
    pub run_timeout: Duration,
}

impl StreamLimits {
    fn validate(&self) -> Result<(), Failure> {
        let counts = [
            self.header_bytes,
            self.header_fields,
            self.streams,
            self.messages,
            self.message_bytes,
            self.assembly_bytes,
            self.queued_bytes,
            self.output_records,
            self.output_bytes,
            self.wire_records,
            self.wire_bytes,
            self.connections,
        ];
        if counts.contains(&0) || self.io_timeout.is_zero() || self.run_timeout.is_zero() {
            return Err(Failure::Limit);
        }
        // Allocation sizes and the aggregate per-image bound must be representable.
        counts
            .iter()
            .try_fold(0usize, |sum, &n| sum.checked_add(n))
            .and_then(|sum| sum.checked_mul(self.connections))
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or(Failure::Limit)?;
        for (count, width) in [
            (
                self.header_fields,
                std::mem::size_of::<httparse::Header<'_>>(),
            ),
            (self.streams, std::mem::size_of::<(u64, Stream)>()),
            (self.messages, std::mem::size_of::<Message>()),
            (self.output_records, std::mem::size_of::<Output>()),
            (self.wire_records, std::mem::size_of::<Wire>()),
            (self.connections, std::mem::size_of::<JoinHandle<()>>()),
        ] {
            count
                .checked_mul(width)
                .filter(|&bytes| bytes <= isize::MAX as usize)
                .ok_or(Failure::Limit)?;
        }
        Instant::now()
            .checked_add(self.run_timeout)
            .ok_or(Failure::Limit)?;
        Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(Failure::Limit)?;
        Ok(())
    }
}

/// A bounded report, deliberately identifying the limited coverage of this arm.
#[derive(Clone, Debug)]
pub struct Report {
    pub subject: &'static str,
    pub image: &'static str,
    pub canonical_name: String,
    /// Exact library digest bound to the independently supplied build digest; absent for linked code.
    pub library_sha256: Option<String>,
    pub package_sha256: Option<String>,
    pub connections: u64,
    pub mutations: u64,
    pub first_failure: Option<Failure>,
}

struct Shared {
    stop: AtomicBool,
    report: Mutex<Report>,
}
impl Shared {
    fn fail(&self, failure: Failure) {
        let mut report = self
            .report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        report.first_failure.get_or_insert(failure);
        self.stop.store(true, Ordering::Release);
    }
    fn snapshot(&self) -> Report {
        self.report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    fn count(&self, mutation: bool) {
        let mut report = self
            .report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = if mutation {
            &mut report.mutations
        } else {
            &mut report.connections
        };
        if let Some(n) = count.checked_add(1) {
            *count = n;
        } else {
            report.first_failure.get_or_insert(Failure::Limit);
            self.stop.store(true, Ordering::Release);
        }
    }
}

/// Message echo through a native transport's adopted HTTP upgrade.
/// Byte-stream bodies (flags zero) are explicitly unsupported.
pub struct MessageStreamSubject {
    plugin: &'static LinkedPlugin,
    config: Vec<u8>,
    limits: StreamLimits,
    mutant: bool,
}
impl MessageStreamSubject {
    pub fn http_upgrade(
        plugin: &'static LinkedPlugin,
        config: &[u8],
        limits: StreamLimits,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        if config.len() > limits.header_bytes {
            return Err(Failure::Limit);
        }
        Ok(Self {
            plugin,
            config: config.to_vec(),
            limits,
            mutant: false,
        })
    }
    /// Corrupt the first nonempty complete echo on each connection, after the real plugin decoded it.
    pub fn mutant(mut self) -> Self {
        self.mutant = true;
        self
    }

    /// Serve only the linked image on a numeric loopback listener. This cannot stand in for drop-in proof.
    pub fn serve_linked(self) -> Result<Served, Failure> {
        let image = admit::admit_linked(self.plugin).map_err(|_| Failure::Admission)?;
        self.start(image, None, None)
    }

    /// Serve the exact signed package produced by the native self-pack route. The expected digest must
    /// come from the separate unseeded build artifact, never from hashing this package as its own expectation.
    /// No listener is opened before signature, trust, image digest and canonical linked identity agree.
    #[cfg(target_os = "linux")]
    pub fn serve_signed_package(
        self,
        archive: &[u8],
        expected_sha256: &str,
        trust: &TrustConfig,
    ) -> Result<Served, Failure> {
        use busbar_plugin_loader::{sign, tarball};

        let expected = build_digest(expected_sha256)?;
        if trust.allow_untrusted || archive.len() as u64 > tarball::MAX_TARBALL_FILE_BYTES {
            return Err(Failure::Admission);
        }
        let package = unpack_package(archive)?;
        if package.manifest.sha256 != expected_sha256
            || sign::sha256_hex(&package.lib_bytes) != expected_sha256
        {
            return Err(Failure::Admission);
        }
        let linked = admit::admit_linked(self.plugin).map_err(|_| Failure::Admission)?;
        let image = admit::admit_bytes(&package.lib_bytes, &package.manifest, trust)
            .map_err(|_| Failure::Admission)?;
        if image.sha256() != Some(&expected)
            || image.identity() != linked.identity()
            || image.kind() != linked.kind()
        {
            return Err(Failure::Admission);
        }
        self.start(
            image,
            Some(expected_sha256.to_owned()),
            Some(sign::sha256_hex(archive)),
        )
    }

    fn start(
        self,
        image: Admitted,
        library_sha256: Option<String>,
        package_sha256: Option<String>,
    ) -> Result<Served, Failure> {
        let image_label = if library_sha256.is_some() {
            "signed-drop-in"
        } else {
            "linked"
        };
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            report: Mutex::new(Report {
                subject: "host target; kernel not present",
                image: image_label,
                canonical_name: image.identity().to_owned(),
                library_sha256,
                package_sha256,
                connections: 0,
                mutations: 0,
                first_failure: None,
            }),
        });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let owner_shared = Arc::clone(&shared);
        let require_mutation = self.mutant;
        let owner = std::thread::Builder::new()
            .name(format!("native-stream-{image_label}"))
            .spawn(move || {
                if let Err(failure) = self.serve(image, &owner_shared, &ready_tx) {
                    owner_shared.fail(failure);
                    let _ = ready_tx.try_send(Err(failure));
                }
            })
            .map_err(|_| Failure::Thread)?;
        match ready_rx.recv() {
            Ok(Ok(addr)) => Ok(Served {
                addr,
                shared,
                owner: Some(owner),
                require_mutation,
            }),
            result => {
                shared.stop.store(true, Ordering::Release);
                let _ = owner.join();
                Err(result.ok().and_then(Result::err).unwrap_or(Failure::Thread))
            }
        }
    }

    fn serve(
        self,
        image: Admitted,
        shared: &Arc<Shared>,
        ready: &mpsc::SyncSender<Result<SocketAddr, Failure>>,
    ) -> Result<(), Failure> {
        let end = Instant::now()
            .checked_add(self.limits.run_timeout)
            .ok_or(Failure::Limit)?;
        // Harness's subscriber guard and runtime are created and dropped on this owner thread.
        let harness =
            Harness::admit_admitted(image, FakeNeeds::new()).map_err(|_| Failure::Admission)?;
        let port = harness
            .open_transport("native-stream", &self.config)
            .map_err(|_| Failure::Admission)?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| Failure::Io)?;
        listener.set_nonblocking(true).map_err(|_| Failure::Io)?;
        ready
            .send(Ok(listener.local_addr().map_err(|_| Failure::Io)?))
            .map_err(|_| Failure::Thread)?;
        let mut live: Vec<JoinHandle<()>> = Vec::new();
        while !shared.stop.load(Ordering::Acquire) {
            if Instant::now() >= end {
                shared.fail(Failure::Deadline);
                break;
            }
            let mut index = 0;
            while index < live.len() {
                if live[index].is_finished() {
                    if live.swap_remove(index).join().is_err() {
                        shared.fail(Failure::Thread);
                    }
                } else {
                    index += 1;
                }
            }
            if shared.stop.load(Ordering::Acquire) {
                break;
            }
            if live.len() < self.limits.connections {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let serving = Arc::clone(shared);
                        let connection_port = Arc::clone(&port);
                        let limits = self.limits.clone();
                        let mutant = self.mutant;
                        // A slot is reserved by the owner before spawning. Finished handles also occupy slots.
                        match std::thread::Builder::new()
                            .name("native-stream-conn".into())
                            .spawn(move || {
                                serving.count(false);
                                if let Err(failure) = serve_connection(
                                    socket,
                                    &*connection_port,
                                    &limits,
                                    end,
                                    &serving,
                                    mutant,
                                ) {
                                    serving.fail(failure);
                                }
                            }) {
                            Ok(thread) => live.push(thread),
                            Err(_) => shared.fail(Failure::Thread),
                        }
                        continue;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => {
                        shared.fail(Failure::Io);
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(listener);
        shared.stop.store(true, Ordering::Release);
        for thread in live {
            if thread.join().is_err() {
                shared.fail(Failure::Thread);
            }
        }
        drop(port);
        drop(harness);
        Ok(())
    }
}

/// A live linked target. Finish joins all connections before judging the report.
pub struct Served {
    addr: SocketAddr,
    shared: Arc<Shared>,
    owner: Option<JoinHandle<()>>,
    require_mutation: bool,
}
impl Served {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn report(&self) -> Report {
        self.shared.snapshot()
    }
    pub fn finish(mut self) -> Result<Report, Report> {
        self.join();
        let report = self.report();
        if report.first_failure.is_some() {
            Err(report)
        } else {
            Ok(report)
        }
    }
    fn join(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(owner) = self.owner.take() {
            if owner.join().is_err() {
                self.shared.fail(Failure::Thread);
            }
            if self.require_mutation && self.shared.snapshot().mutations == 0 {
                self.shared.fail(Failure::MutationMissing);
            }
        }
    }
}
impl Drop for Served {
    fn drop(&mut self) {
        if self.owner.is_none() {
            return;
        }
        self.join();
        assert!(
            self.report().first_failure.is_none() || std::thread::panicking(),
            "unfinished native stream target failed: {:?}",
            self.report()
        );
    }
}

fn upgrade_head(bytes: &[u8], max_fields: usize) -> Result<Option<(Reply, usize)>, Failure> {
    let mut fields = vec![httparse::EMPTY_HEADER; max_fields];
    let mut request = httparse::Request::new(&mut fields);
    let used = match request.parse(bytes).map_err(|_| Failure::Framing)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(used) => used,
    };
    if request.version != Some(1) {
        return Err(Failure::Framing);
    }
    let mut host = None;
    let mut length = false;
    for field in request.headers.iter() {
        if field.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Failure::Framing);
        }
        if field.name.eq_ignore_ascii_case("content-length") {
            let value = field.value;
            let start = value
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t'))
                .unwrap_or(value.len());
            let end = value
                .iter()
                .rposition(|b| !matches!(b, b' ' | b'\t'))
                .map_or(start, |i| i + 1);
            let value = &value[start..end];
            if length || value.is_empty() || value.iter().any(|&b| b != b'0') {
                return Err(Failure::Framing);
            }
            length = true;
        }
        if field.name.eq_ignore_ascii_case("host") {
            if host.is_some() || field.value.is_empty() {
                return Err(Failure::Framing);
            }
            host = Some(std::str::from_utf8(field.value).map_err(|_| Failure::Framing)?);
        }
    }
    let mut head = Reply::new();
    let write = |_: busbar_plugin_abi::records::Full| Failure::Limit;
    head.put_text(tag::H_METHOD, request.method.ok_or(Failure::Framing)?)
        .map_err(write)?;
    head.put_text(tag::H_PATH, request.path.ok_or(Failure::Framing)?)
        .map_err(write)?;
    head.put_text(tag::H_AUTHORITY, host.ok_or(Failure::Framing)?)
        .map_err(write)?;
    head.put_text(tag::H_SCHEME, "http").map_err(write)?;
    for field in request.headers.iter() {
        head.put_pair(tag::PAIR, &field.name.to_ascii_lowercase(), field.value)
            .map_err(write)?;
    }
    head.put_pod(tag::H_STATUS, &U32Rec { value: 101, _r: 0 })
        .map_err(write)?;
    Ok(Some((head, used)))
}

#[derive(Debug, PartialEq, Eq)]
struct Message {
    stream: u64,
    flags: u32,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Stream {
    kind: Option<u32>,
    bytes: Vec<u8>,
    held: bool,
}
struct EchoState {
    streams: HashMap<u64, Stream>,
    queue: VecDeque<Message>,
    max_streams: usize,
    max_messages: usize,
    max_message: usize,
    max_assembly: usize,
    max_queued: usize,
    assembly: usize,
    queued: usize,
}
impl EchoState {
    fn new(streams: usize, messages: usize, bytes: usize) -> Self {
        Self {
            streams: HashMap::new(),
            queue: VecDeque::new(),
            max_streams: streams,
            max_messages: messages,
            max_message: bytes,
            max_assembly: bytes,
            max_queued: bytes,
            assembly: 0,
            queued: 0,
        }
    }
    fn stream(&mut self, id: u64) -> Result<&mut Stream, Failure> {
        if id == 0 {
            return Err(Failure::Shape);
        }
        if !self.streams.contains_key(&id) && self.streams.len() >= self.max_streams {
            return Err(Failure::Limit);
        }
        Ok(self.streams.entry(id).or_default())
    }
    fn body(&mut self, stream: u64, flags: u32, bytes: &[u8]) -> Result<(), Failure> {
        if flags == 0 {
            return Err(Failure::UnsupportedBodyMode);
        }
        let kind = flags & (MSG_TEXT | MSG_BINARY);
        if !matches!(kind, MSG_TEXT | MSG_BINARY) || flags & !(MSG_TEXT | MSG_BINARY | MSG_FIN) != 0
        {
            return Err(Failure::Shape);
        }
        let existing = self.streams.get(&stream).map_or(0, |s| s.bytes.len());
        let total = existing.checked_add(bytes.len()).ok_or(Failure::Limit)?;
        let assembly = self
            .assembly
            .checked_add(bytes.len())
            .ok_or(Failure::Limit)?;
        if total > self.max_message || assembly > self.max_assembly {
            return Err(Failure::Limit);
        }
        let complete = flags & MSG_FIN != 0;
        let queued = if complete {
            self.queued.checked_add(total).ok_or(Failure::Limit)?
        } else {
            self.queued
        };
        if complete && (self.queue.len() >= self.max_messages || queued > self.max_queued) {
            return Err(Failure::Limit);
        }
        let s = self.stream(stream)?;
        if s.kind.is_some_and(|prior| prior != kind) {
            return Err(Failure::Shape);
        }
        s.kind = Some(kind);
        s.bytes.extend_from_slice(bytes);
        if complete {
            let bytes = std::mem::take(&mut s.bytes);
            s.kind = None;
            self.queue.push_back(Message {
                stream,
                flags: kind | MSG_FIN,
                bytes,
            });
            self.assembly = assembly - total;
            self.queued = queued;
        } else {
            self.assembly = assembly;
        }
        Ok(())
    }
    fn full(&mut self, stream: u64) -> Result<(), Failure> {
        self.stream(stream)?.held = true;
        Ok(())
    }
    fn writable(&mut self, stream: u64) {
        if let Some(s) = self.streams.get_mut(&stream) {
            s.held = false;
        }
    }
    fn next(&mut self) -> Option<Message> {
        let i = self
            .queue
            .iter()
            .position(|m| self.streams.get(&m.stream).is_some_and(|s| !s.held))?;
        let m = self.queue.remove(i)?;
        self.queued -= m.bytes.len();
        Some(m)
    }
    fn end(&mut self, stream: u64) {
        if let Some(s) = self.streams.remove(&stream) {
            self.assembly -= s.bytes.len();
        }
        self.queue.retain(|m| {
            if m.stream == stream {
                self.queued -= m.bytes.len();
                false
            } else {
                true
            }
        });
    }
}

enum Output {
    Write(Vec<u8>),
    Wake(u64),
    Close,
    Head(u64, bool),
    Body(u64, u32, Vec<u8>),
    End(u64),
    Pause,
    Resume,
    Full(u64),
    Writable(u64),
}
#[derive(Default)]
struct Batch {
    records: Vec<Output>,
    bytes: usize,
    failure: Option<Failure>,
}
impl Batch {
    fn capture(&mut self, out: TransportOut<'_>, records: usize, bytes: usize) {
        if self.failure.is_some() {
            return;
        }
        let size = match &out {
            TransportOut::Write(b) | TransportOut::StreamBody { bytes: b, .. } => b.len(),
            TransportOut::StreamHead { head, .. } => head.rest().len(),
            _ => 0,
        };
        let Some(total) = self.bytes.checked_add(size) else {
            self.failure = Some(Failure::Limit);
            return;
        };
        if self.records.len() >= records || total > bytes {
            self.failure = Some(Failure::Limit);
            return;
        }
        let owned = match out {
            TransportOut::Write(b) => Output::Write(b.to_vec()),
            TransportOut::Close { .. } => Output::Close,
            TransportOut::WakeAt(t) => Output::Wake(t),
            TransportOut::StreamHead {
                stream, end_stream, ..
            } => Output::Head(stream, end_stream),
            TransportOut::StreamBody {
                stream,
                flags,
                bytes,
            } => Output::Body(stream, flags, bytes.to_vec()),
            TransportOut::StreamEnd(s) | TransportOut::StreamReset { stream: s, .. } => {
                Output::End(s)
            }
            TransportOut::Pause => Output::Pause,
            TransportOut::Resume => Output::Resume,
            TransportOut::StreamFull(s) => Output::Full(s),
            TransportOut::StreamWritable(s) => Output::Writable(s),
            _ => {
                self.failure = Some(Failure::Shape);
                return;
            }
        };
        self.bytes = total;
        self.records.push(owned);
    }
}

#[derive(Clone, Copy)]
enum Call {
    Begin,
    Ingest,
    Timer,
    Emit(u64),
    Close,
}
struct Wire {
    bytes: Vec<u8>,
    offset: usize,
    deadline: Instant,
}
struct Driver {
    echoes: EchoState,
    wire: VecDeque<Wire>,
    wire_bytes: usize,
    wake: Option<u64>,
    paused: bool,
    closed: bool,
    progress: u64,
}
impl Driver {
    fn new(limits: &StreamLimits) -> Self {
        let mut echoes = EchoState::new(limits.streams, limits.messages, limits.message_bytes);
        echoes.max_assembly = limits.assembly_bytes;
        echoes.max_queued = limits.queued_bytes;
        Self {
            echoes,
            wire: VecDeque::new(),
            wire_bytes: 0,
            wake: None,
            paused: false,
            closed: false,
            progress: 0,
        }
    }
    fn batch(
        &mut self,
        batch: Batch,
        call: Call,
        limits: &StreamLimits,
        end: Instant,
    ) -> Result<(), Failure> {
        if let Some(failure) = batch.failure {
            return Err(failure);
        }
        for out in batch.records {
            if self.closed {
                return Err(Failure::Shape);
            }
            if matches!(call, Call::Close) && !matches!(out, Output::Write(_) | Output::Close) {
                return Err(Failure::Shape);
            }
            match out {
                Output::Write(bytes) => {
                    let total = self
                        .wire_bytes
                        .checked_add(bytes.len())
                        .ok_or(Failure::Limit)?;
                    if self.wire.len() >= limits.wire_records || total > limits.wire_bytes {
                        return Err(Failure::Limit);
                    }
                    self.wire_bytes = total;
                    self.progress = self.progress.saturating_add(bytes.len() as u64);
                    self.wire.push_back(Wire {
                        bytes,
                        offset: 0,
                        deadline: operation_end(limits.io_timeout, end),
                    });
                }
                Output::Wake(at) => self.wake = Some(self.wake.map_or(at, |prior| prior.min(at))),
                Output::Close => {
                    self.closed = true;
                    self.progress = self.progress.saturating_add(1);
                }
                Output::Head(s, ended) => {
                    self.echoes.stream(s)?;
                    if ended {
                        self.echoes.end(s);
                    }
                }
                Output::Body(s, flags, bytes) => {
                    self.echoes.body(s, flags, &bytes)?;
                    self.progress = self.progress.saturating_add(bytes.len() as u64);
                }
                Output::End(s) => {
                    if self.echoes.streams.contains_key(&s) {
                        self.progress = self.progress.saturating_add(1);
                    }
                    self.echoes.end(s);
                }
                Output::Pause => self.paused = true,
                Output::Resume => self.paused = false,
                Output::Full(s) => {
                    if !matches!(call, Call::Emit(id) if id == s) {
                        return Err(Failure::Shape);
                    }
                    self.echoes.full(s)?;
                }
                Output::Writable(s) => {
                    if !matches!(call, Call::Ingest | Call::Timer) {
                        return Err(Failure::Shape);
                    }
                    self.echoes.writable(s);
                }
            }
        }
        Ok(())
    }
}

fn operation_end(budget: Duration, end: Instant) -> Instant {
    Instant::now().checked_add(budget).unwrap_or(end).min(end)
}

fn due(deadline: Instant) -> Result<(), Failure> {
    if Instant::now() >= deadline {
        Err(Failure::Deadline)
    } else {
        Ok(())
    }
}
fn wait_for(operation: Instant, end: Instant, wake: Option<u64>) -> Result<Duration, Failure> {
    let now = Instant::now();
    let mut duration = operation
        .min(end)
        .checked_duration_since(now)
        .ok_or(Failure::Deadline)?
        .min(SHUTDOWN_TICK);
    if let Some(wake) = wake {
        duration = duration.min(Duration::from_nanos(wake.saturating_sub(HOST.mono_ns())));
    }
    Ok(duration.max(Duration::from_micros(1)))
}
fn transient(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
    )
}

fn collect_head(
    socket: &mut TcpStream,
    limits: &StreamLimits,
    end: Instant,
    shared: &Shared,
) -> Result<Option<(Reply, Vec<u8>)>, Failure> {
    let deadline = operation_end(limits.io_timeout, end);
    let mut input = Vec::new();
    let mut read = vec![0u8; READ_BYTES];
    loop {
        due(end)?;
        if shared.stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        if let Some((head, used)) = upgrade_head(&input, limits.header_fields)? {
            if used > limits.header_bytes {
                return Err(Failure::Limit);
            }
            return Ok(Some((head, input[used..].to_vec())));
        }
        if input.len() >= limits.header_bytes {
            return Err(Failure::Limit);
        }
        socket
            .set_read_timeout(Some(wait_for(deadline, end, None)?))
            .map_err(|_| Failure::Io)?;
        match socket.read(&mut read) {
            Ok(0) => return Ok(None),
            Ok(n) => {
                due(deadline)?;
                input.extend_from_slice(&read[..n]);
            }
            Err(e) if transient(&e) => {}
            Err(_) => return Ok(None),
        }
    }
}

fn invoke(
    port: &dyn TransportPort,
    session: &mut TransportSession,
    call: Call,
    bytes: &[u8],
    flags: u32,
    limits: &StreamLimits,
) -> Result<Batch, Failure> {
    let mut batch = Batch::default();
    let mut sink = |out: TransportOut<'_>| {
        batch.capture(out, limits.output_records, limits.output_bytes);
    };
    let result = match call {
        Call::Ingest => port.ingest(session, bytes, &mut sink),
        Call::Timer => port.timer(session, &mut sink),
        Call::Emit(stream) => port.emit(session, stream, E_BODY, flags, bytes, &mut sink),
        Call::Close => port.emit(session, 0, E_CLOSE, CR_DRAIN, &[], &mut sink),
        Call::Begin => return Err(Failure::Shape),
    };
    result.map_err(|_| Failure::Port)?;
    Ok(batch)
}

// Returns false on an ordinary peer/socket termination: no later call (including E_CLOSE) is legal.
fn write_step(
    socket: &mut TcpStream,
    driver: &mut Driver,
    end: Instant,
    timers: bool,
) -> Result<bool, Failure> {
    let Some(front) = driver.wire.front_mut() else {
        return Ok(true);
    };
    due(front.deadline)?;
    if front.offset < front.bytes.len() {
        socket
            .set_write_timeout(Some(wait_for(
                front.deadline,
                end,
                if timers { driver.wake } else { None },
            )?))
            .map_err(|_| Failure::Io)?;
        match socket.write(&front.bytes[front.offset..]) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                front.offset += n;
                due(front.deadline)?;
            }
            Err(error) if transient(&error) => return Ok(true),
            Err(_) => return Ok(false),
        }
    }
    if front.offset == front.bytes.len() {
        driver.wire_bytes -= front.bytes.len();
        driver.wire.pop_front();
    }
    Ok(true)
}

fn serve_connection(
    mut socket: TcpStream,
    port: &dyn TransportPort,
    limits: &StreamLimits,
    end: Instant,
    shared: &Shared,
    mutant: bool,
) -> Result<(), Failure> {
    let result = connection(&mut socket, port, limits, end, shared, mutant);
    let _ = socket.shutdown(Shutdown::Both);
    result
}

fn connection(
    socket: &mut TcpStream,
    port: &dyn TransportPort,
    limits: &StreamLimits,
    end: Instant,
    shared: &Shared,
    mutant: bool,
) -> Result<(), Failure> {
    let Some((head, leftover)) = collect_head(socket, limits, end, shared)? else {
        return Ok(());
    };
    let peer = socket.peer_addr().map_err(|_| Failure::Io)?.to_string();
    let local = socket.local_addr().map_err(|_| Failure::Io)?.to_string();
    let conn = ConnIn {
        role: ROLE_SERVER,
        flags: CONN_UPGRADED,
        alpn: "http/1.1",
        sni: "",
        peer: &peer,
        local: &local,
        tls_peer_cert: &[],
        leftover: &leftover,
        head: head.as_bytes(),
        local_fingerprint: "",
        mono_ns: HOST.mono_ns(),
    };
    let mut batch = Batch::default();
    due(end)?;
    let mut session = port
        .begin(&conn, &mut |o| {
            batch.capture(o, limits.output_records, limits.output_bytes)
        })
        .map_err(|_| Failure::Port)?;
    due(end)?;
    let mut driver = Driver::new(limits);
    driver.batch(batch, Call::Begin, limits, end)?;
    let mut read = vec![0u8; READ_BYTES];
    let mut read_deadline = operation_end(limits.io_timeout, end);
    let mut mutated = false;
    let mut no_progress = 0;
    loop {
        due(end)?;
        if driver.closed {
            while !driver.wire.is_empty() {
                if !write_step(socket, &mut driver, end, false)? {
                    break;
                }
            }
            return Ok(());
        }
        if shared.stop.load(Ordering::Acquire) {
            // A sibling host fault quarantines the run; do not invoke any further plugin operation.
            if shared.snapshot().first_failure.is_some() {
                return Ok(());
            }
            let goodbye = invoke(port, &mut session, Call::Close, &[], 0, limits)?;
            due(end)?;
            driver.batch(goodbye, Call::Close, limits, end)?;
            while !driver.wire.is_empty() {
                if !write_step(socket, &mut driver, end, false)? {
                    break;
                }
            }
            return Ok(());
        }
        if !write_step(socket, &mut driver, end, true)? {
            return Ok(());
        }
        if !driver.wake.is_some_and(|at| at <= HOST.mono_ns()) {
            no_progress = 0;
        }
        // Bound each turn even when a plugin makes immediate progress indefinitely.
        for _ in 0..TIMER_TURN {
            if shared.stop.load(Ordering::Acquire)
                || !driver.wake.is_some_and(|at| at <= HOST.mono_ns())
            {
                break;
            }
            due(end)?;
            let before = driver.progress;
            driver.wake = None;
            let batch = invoke(port, &mut session, Call::Timer, &[], 0, limits)?;
            due(end)?;
            driver.batch(batch, Call::Timer, limits, end)?;
            if driver.progress == before {
                no_progress += 1;
            } else {
                no_progress = 0;
            }
            if no_progress >= TIMER_TURN {
                return Err(Failure::TimerNoProgress);
            }
            if driver.closed {
                break;
            }
            if !write_step(socket, &mut driver, end, true)? {
                return Ok(());
            }
        }
        if driver.closed || shared.stop.load(Ordering::Acquire) {
            continue;
        }
        // One message per turn; STREAM_FULL consumes it whole, and only subsequent messages remain queued.
        if driver.wire.is_empty() {
            if let Some(mut message) = driver.echoes.next() {
                if mutant && !mutated && !message.bytes.is_empty() {
                    message.bytes[0] ^= 1;
                    mutated = true;
                    shared.count(true);
                }
                let call = Call::Emit(message.stream);
                let batch = invoke(
                    port,
                    &mut session,
                    call,
                    &message.bytes,
                    message.flags,
                    limits,
                )?;
                due(end)?;
                driver.batch(batch, call, limits, end)?;
                continue;
            }
        }
        if driver.paused && driver.wire.is_empty() {
            std::thread::sleep(wait_for(end, end, driver.wake)?);
            continue;
        }
        if !driver.wire.is_empty() {
            // write_step performs the bounded socket wait; keep its pending offset in order.
            continue;
        }
        socket
            .set_read_timeout(Some(wait_for(read_deadline, end, driver.wake)?))
            .map_err(|_| Failure::Io)?;
        match socket.read(&mut read) {
            Ok(n) => {
                due(read_deadline)?;
                let batch = invoke(port, &mut session, Call::Ingest, &read[..n], 0, limits)?;
                due(end)?;
                driver.batch(batch, Call::Ingest, limits, end)?;
                if n == 0 {
                    // EOF is delivered once. Ignore timer/echo intentions afterward; only its wire is drained.
                    while !driver.wire.is_empty() {
                        if !write_step(socket, &mut driver, end, false)? {
                            break;
                        }
                    }
                    return Ok(());
                }
                read_deadline = operation_end(limits.io_timeout, end);
            }
            Err(error) if transient(&error) => {}
            Err(_) => return Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "native_stream_tests.rs"]
mod tests;
