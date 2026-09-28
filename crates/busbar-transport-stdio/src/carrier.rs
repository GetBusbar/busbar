// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER (TRANSPORT-STACK; #3, #30): `stdio` as the contract's [`Carrier`] — the one
//! implementation both doors drive. A build that links this crate holds a [`StdioCarrier`] as its
//! `Arc<dyn Carrier>` (`crate::linked::carrier`); the `cdylib` built with the `dropped-in` feature
//! lowers the same type to the HOT decl through the contract's `export_carrier!` ([`exports`]).
//!
//! A carrier moves BYTES. What a line means on this wire belongs to whichever plane rides it, so the
//! carrier reads and writes the byte stream as it comes: one read is whatever the pipe handed over.
//!
//! Two kinds of connection:
//!
//! * the process's OWN standard input and output, handed out once by the one listener
//!   ([`Carrier::listen`] binds nothing; [`Carrier::poll_accept`] answers the process's own standard input and output
//!   the first time and `Closed` after, because a process has exactly one of them);
//! * a spawned CHILD, dialled as [`Dest::Program`]: an absolute path only, no shell, and the
//!   environment CLEARED and then set to exactly what the destination declared, so a child inherits
//!   nothing the deployment did not write down. Closing the connection kills the child.
//!
//! No method blocks. The pipes' readiness is driven by this carrier's own I/O reactor (one thread
//! per built instance), which wakes the waker the caller registered.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierFacts, CarrierPoll, Dest};
use busbar_contract::{AbiVersion, Kind, Plugin};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The far end the process's own standard input and output report.
pub(crate) const OWN_PROCESS: &str = "stdio:own-process";

/// The one listener: the process's own standard input and output.
const OWN_LISTENER: u64 = 1;

/// One connection: its reading and writing halves (each polled by one task at a time), the child it
/// owns where it was dialled, and the wakers parked on it — so a close wakes both directions.
pub(crate) struct Pipe {
    peer: String,
    read: Mutex<Box<dyn AsyncRead + Send + Unpin>>,
    write: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    child: Mutex<Option<tokio::process::Child>>,
    reading: Mutex<Option<Waker>>,
    writing: Mutex<Option<Waker>>,
}

/// The `stdio` carrier: its connections, whether the process's own standard input and output were handed out, and the
/// I/O reactor its pipes are registered with (declared last, so it stops after every pipe).
pub struct StdioCarrier {
    pub(crate) conns: Mutex<HashMap<u64, Arc<Pipe>>>,
    next: AtomicU64,
    own_taken: AtomicBool,
    reactor: Reactor,
}

impl std::fmt::Debug for StdioCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioCarrier").finish_non_exhaustive()
    }
}

/// This carrier's I/O reactor: a single-threaded runtime on a thread of its own, driving the
/// readiness of every pipe this carrier opens. It runs no task of the caller's: it only delivers
/// readiness, by waking the caller's waker.
struct Reactor {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reactor {
    fn start() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("busbar-pipe-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Default for StdioCarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// A pipe's I/O error, in the transport kind's vocabulary.
fn map_io(e: &std::io::Error) -> TransportError {
    match e.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted => TransportError::Reset,
        std::io::ErrorKind::TimedOut => TransportError::Timeout,
        _ => TransportError::Closed,
    }
}

/// Remember `cx`'s waker in `slot`.
fn park(slot: &Mutex<Option<Waker>>, cx: &Context<'_>) {
    let mut held = slot.lock().expect("waker slot poisoned");
    match &*held {
        Some(w) if w.will_wake(cx.waker()) => {}
        _ => *held = Some(cx.waker().clone()),
    }
}

impl StdioCarrier {
    /// A carrier with no connections and its own reactor.
    ///
    /// # Panics
    ///
    /// The reactor thread cannot be started (the process is out of threads).
    #[must_use]
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            own_taken: AtomicBool::new(false),
            reactor: Reactor::start().expect("the stdio carrier's reactor thread starts"),
        }
    }

    fn pipe(&self, conn: u64) -> Option<Arc<Pipe>> {
        self.conns
            .lock()
            .expect("connection registry poisoned")
            .get(&conn)
            .cloned()
    }

    fn hold(&self, pipe: Pipe) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.conns
            .lock()
            .expect("connection registry poisoned")
            .insert(id, Arc::new(pipe));
        id
    }

    /// Spawn `program` with exactly `args` and `env`, and hold its pipes as a connection.
    fn spawn(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<u64, TransportError> {
        // An absolute path only: a bare name would be resolved through a search path the
        // deployment did not write down.
        if !program.starts_with('/') {
            return Err(TransportError::AddressRefused);
        }
        let _in = self.reactor.handle.enter();
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args);
        cmd.env_clear();
        for (name, value) in env {
            cmd.env(name, value);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|_| TransportError::Refused)?;
        let stdin = child.stdin.take().ok_or(TransportError::Refused)?;
        let stdout = child.stdout.take().ok_or(TransportError::Refused)?;
        Ok(self.hold(Pipe {
            peer: program.to_string(),
            read: Mutex::new(Box::new(stdout)),
            write: Mutex::new(Box::new(stdin)),
            child: Mutex::new(Some(child)),
            reading: Mutex::new(None),
            writing: Mutex::new(None),
        }))
    }

    /// Poll the writing half of `conn`, parking `cx`'s waker on it.
    fn poll_writer<T>(
        &self,
        conn: u64,
        cx: &mut Context<'_>,
        op: impl FnOnce(
            std::pin::Pin<&mut (dyn AsyncWrite + Send + Unpin)>,
            &mut Context<'_>,
        ) -> Poll<std::io::Result<T>>,
    ) -> CarrierPoll<T> {
        let Some(pipe) = self.pipe(conn) else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        park(&pipe.writing, cx);
        let _in = self.reactor.handle.enter();
        // One writer at a time: a second poller waits its turn.
        let Ok(mut half) = pipe.write.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        op(std::pin::Pin::new(&mut **half), cx).map_err(|e| map_io(&e))
    }
}

impl Plugin for StdioCarrier {
    fn key(&self) -> &'static str {
        crate::linked::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl Carrier for StdioCarrier {
    /// The one listener is the process's own standard input and output; `bind` names nothing here.
    fn listen(&self, _bind: &str) -> Result<(u64, String), TransportError> {
        Ok((OWN_LISTENER, OWN_PROCESS.to_string()))
    }

    fn poll_accept(&self, listener: u64, _cx: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        if listener != OWN_LISTENER || self.own_taken.swap(true, Ordering::AcqRel) {
            // A process has exactly one stdin and one stdout: once handed out, nothing is left.
            return Poll::Ready(Err(TransportError::Closed));
        }
        let _in = self.reactor.handle.enter();
        let id = self.hold(Pipe {
            peer: OWN_PROCESS.to_string(),
            read: Mutex::new(Box::new(tokio::io::stdin())),
            write: Mutex::new(Box::new(tokio::io::stdout())),
            child: Mutex::new(None),
            reading: Mutex::new(None),
            writing: Mutex::new(None),
        });
        Poll::Ready(Ok((id, OWN_PROCESS.to_string())))
    }

    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        match dest {
            Dest::Program { program, args, env } => self.spawn(program, args, env),
            // A pipe reaches a program, never an address.
            Dest::Authority(_) => Err(TransportError::AddressRefused),
        }
    }

    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<usize> {
        let Some(pipe) = self.pipe(conn) else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        park(&pipe.reading, cx);
        let _in = self.reactor.handle.enter();
        // One reader at a time: a second poller waits its turn.
        let Ok(mut half) = pipe.read.try_lock() else {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        let mut filled = ReadBuf::new(buf);
        match std::pin::Pin::new(&mut **half).poll_read(cx, &mut filled) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(filled.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_io(&e))),
        }
    }

    fn poll_write(&self, conn: u64, cx: &mut Context<'_>, bytes: &[u8]) -> CarrierPoll<usize> {
        self.poll_writer(conn, cx, |half, cx| half.poll_write(cx, bytes))
    }

    fn poll_flush(&self, conn: u64, cx: &mut Context<'_>) -> CarrierPoll<()> {
        self.poll_writer(conn, cx, |half, cx| half.poll_flush(cx))
    }

    /// Forget the connection, kill its child where it owns one, and wake whatever was parked on it.
    /// Idempotent.
    fn poll_close(
        &self,
        conn: u64,
        _cx: &mut Context<'_>,
        _reason: CloseReason,
    ) -> CarrierPoll<()> {
        let pipe = self
            .conns
            .lock()
            .expect("connection registry poisoned")
            .remove(&conn);
        if let Some(pipe) = pipe {
            let _in = self.reactor.handle.enter();
            if let Some(mut child) = pipe.child.lock().expect("child slot poisoned").take() {
                let _ = child.start_kill();
            }
            for slot in [&pipe.reading, &pipe.writing] {
                if let Some(w) = slot.lock().expect("waker slot poisoned").take() {
                    w.wake();
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        Some(CarrierFacts {
            peer: self.pipe(conn)?.peer.clone(),
            local_port: 0,
        })
    }
}

/// The dropped-in door, compiled only into the dropped-in build (feature `dropped-in`):
/// [`StdioCarrier`] lowered to the HOT decl and registered as this image's ONE door through the
/// contract's `export_carrier!`. The one module this crate's `#![deny(unsafe_code)]` allows: every
/// line of it is the macro's.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
pub mod exports {
    busbar_contract::export_carrier!(super::StdioCarrier, super::build);
}

/// The linked row's constructor, as the lowering calls it: this wire reads no setting.
#[cfg(feature = "dropped-in")]
fn build(_: &busbar_contract::transport::TransportSettings) -> StdioCarrier {
    StdioCarrier::new()
}
