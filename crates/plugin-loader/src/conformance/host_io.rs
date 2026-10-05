// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUITE'S HOST I/O: the `io.*` a carrier is served in the conformance suite, over the OS's own
//! sockets and processes, so a carrier's both legs move REAL bytes (`BUSBAR-1.6.0.md` THE DESIGN
//! §11.4: the same table, compiled in and dropped in). It is the host's side: it admits what the
//! script admits for a dial, a bind or a spawn and nothing else, and wakes a pending op's ticket when
//! its handle may make progress — a socket's readiness found by the script's own [`SuiteIo::pump`],
//! a program's output by the thread that reads it. A test host: it never ships (the connector is
//! the process's host).

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::io::{DIR_READ, DIR_WRITE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::io_host::{IoHost, IoRefusal, IoResult, Spawn};

/// The refusal of what the script did not admit.
pub const NOT_ADMITTED: &str = "the host did not admit this for the dial that asked";

/// What the script admitted for an op's ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit {
    /// `io.open` of this address.
    Addr(String),
    /// `io.listen` on this bind.
    Bind(String),
    /// `io.spawn` of this program.
    Program(String),
}

/// A program's output, as its reading thread fills it.
#[derive(Default)]
struct Output {
    bytes: VecDeque<u8>,
    eof: bool,
    waker: Option<Waker>,
}

type Shared = Arc<(Mutex<Output>, Condvar)>;

enum Handle {
    Stream(TcpStream),
    Listener(TcpListener),
    Program {
        child: Child,
        input: Option<ChildStdin>,
        output: Shared,
    },
}

#[derive(Default)]
struct Inner {
    next: u64,
    handles: HashMap<u64, (u64, Handle)>,
    admitted: HashMap<Ticket, Admit>,
    made: HashMap<Ticket, u64>,
    waiting: Vec<(u64, Waker)>,
}

/// THE SUITE'S HOST I/O (module docs).
#[derive(Default)]
pub struct SuiteIo {
    inner: Mutex<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn failed(e: &std::io::Error) -> IoRefusal {
    IoRefusal::Failed(e.to_string())
}

impl SuiteIo {
    /// Admit `what` for the op on `ticket`.
    pub fn admit(&self, ticket: Ticket, what: Admit) {
        lock(&self.inner).admitted.insert(ticket, what);
    }

    /// The handle the last op on `ticket` made (`open`, `listen`, `accept`, `spawn`).
    #[must_use]
    pub fn made(&self, ticket: Ticket) -> Option<u64> {
        lock(&self.inner).made.get(&ticket).copied()
    }

    /// How many handles are held.
    #[must_use]
    pub fn held(&self) -> usize {
        lock(&self.inner).handles.len()
    }

    fn admitted(&self, ticket: Ticket, want: &Admit) -> IoResult<()> {
        if lock(&self.inner).admitted.get(&ticket) == Some(want) {
            Ok(())
        } else {
            Err(IoRefusal::Refused(NOT_ADMITTED.into()))
        }
    }

    fn hold(&self, owner: u64, ticket: Option<Ticket>, h: Handle) -> u64 {
        let mut inner = lock(&self.inner);
        inner.next += 1;
        let id = inner.next;
        inner.handles.insert(id, (owner, h));
        if let Some(t) = ticket {
            inner.made.insert(t, id);
        }
        id
    }

    /// Run `f` on `owner`'s handle `id`.
    fn on<R>(&self, owner: u64, id: u64, f: impl FnOnce(&mut Handle) -> IoResult<R>) -> IoResult<R> {
        let mut inner = lock(&self.inner);
        match inner.handles.get_mut(&id) {
            Some((o, h)) if *o == owner => f(h),
            _ => Err(IoRefusal::unknown()),
        }
    }

    fn park(&self, id: u64, waker: &Waker) {
        lock(&self.inner).waiting.push((id, waker.clone()));
    }

    /// Wake every op waiting on a socket that is now readable (or at its end).
    pub fn pump(&self) {
        let mut inner = lock(&self.inner);
        let waiting = std::mem::take(&mut inner.waiting);
        for (id, waker) in waiting {
            let ready = match inner.handles.get(&id).map(|(_, h)| h) {
                Some(Handle::Stream(s)) => {
                    let mut one = [0_u8; 1];
                    !matches!(s.peek(&mut one), Err(e) if e.kind() == ErrorKind::WouldBlock)
                }
                Some(Handle::Listener(_)) | None => true,
                // A program's output wakes its reader from the thread that reads it.
                Some(Handle::Program { .. }) => continue,
            };
            if ready {
                waker.wake();
            } else {
                inner.waiting.push((id, waker));
            }
        }
    }

    /// Wait (up to five seconds) until handle `id` has bytes to read, or its end.
    pub fn wait_readable(&self, id: u64) {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            let ready = {
                let inner = lock(&self.inner);
                match inner.handles.get(&id).map(|(_, h)| h) {
                    Some(Handle::Stream(s)) => {
                        let mut one = [0_u8; 1];
                        !matches!(s.peek(&mut one), Err(e) if e.kind() == ErrorKind::WouldBlock)
                    }
                    Some(Handle::Program { output, .. }) => {
                        let o = lock(&output.0);
                        !o.bytes.is_empty() || o.eof
                    }
                    _ => true,
                }
            };
            if ready {
                // Let the rest of a short write land with it.
                std::thread::sleep(Duration::from_millis(20));
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl IoHost for SuiteIo {
    fn open(&self, owner: u64, ticket: Ticket, addr: &str) -> IoResult<u64> {
        self.admitted(ticket, &Admit::Addr(addr.to_owned()))?;
        let s = TcpStream::connect(addr).map_err(|e| failed(&e))?;
        s.set_nonblocking(true).map_err(|e| failed(&e))?;
        let _ = s.set_nodelay(true);
        Ok(self.hold(owner, Some(ticket), Handle::Stream(s)))
    }

    fn listen(&self, owner: u64, ticket: Ticket, bind: &str) -> IoResult<(u64, String)> {
        self.admitted(ticket, &Admit::Bind(bind.to_owned()))?;
        let l = TcpListener::bind(bind).map_err(|e| failed(&e))?;
        l.set_nonblocking(true).map_err(|e| failed(&e))?;
        let at = l.local_addr().map_err(|e| failed(&e))?.to_string();
        Ok((self.hold(owner, Some(ticket), Handle::Listener(l)), at))
    }

    fn accept(
        &self,
        owner: u64,
        ticket: Ticket,
        listener: u64,
        waker: &Waker,
    ) -> Poll<IoResult<(u64, String)>> {
        let got = self.on(owner, listener, |h| match h {
            Handle::Listener(l) => match l.accept() {
                Ok((s, peer)) => Ok(Some((s, peer.to_string()))),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(failed(&e)),
            },
            _ => Err(IoRefusal::unknown()),
        });
        match got {
            Ok(Some((s, peer))) => {
                let _ = s.set_nonblocking(true);
                Poll::Ready(Ok((self.hold(owner, Some(ticket), Handle::Stream(s)), peer)))
            }
            Ok(None) => {
                self.park(listener, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn read(&self, owner: u64, id: u64, buf: &mut [u8], waker: &Waker) -> Poll<IoResult<usize>> {
        let got = self.on(owner, id, |h| match h {
            Handle::Stream(s) => match s.read(buf) {
                Ok(n) => Ok(Some(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(failed(&e)),
            },
            Handle::Program { output, .. } => {
                let mut o = lock(&output.0);
                if o.bytes.is_empty() && !o.eof {
                    o.waker = Some(waker.clone());
                    return Ok(None);
                }
                let n = buf.len().min(o.bytes.len());
                for (to, from) in buf.iter_mut().zip(o.bytes.drain(..n)) {
                    *to = from;
                }
                Ok(Some(n))
            }
            Handle::Listener(_) => Err(IoRefusal::unknown()),
        });
        match got {
            Ok(Some(n)) => Poll::Ready(Ok(n)),
            Ok(None) => {
                self.park(id, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn write(&self, owner: u64, id: u64, bytes: &[u8], waker: &Waker) -> Poll<IoResult<usize>> {
        let got = self.on(owner, id, |h| match h {
            Handle::Stream(s) => match s.write(bytes) {
                Ok(n) => Ok(Some(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(failed(&e)),
            },
            Handle::Program { input, .. } => {
                let w = input
                    .as_mut()
                    .ok_or_else(|| IoRefusal::Failed("the program's input is shut".into()))?;
                w.write_all(bytes).map_err(|e| failed(&e))?;
                w.flush().map_err(|e| failed(&e))?;
                Ok(Some(bytes.len()))
            }
            Handle::Listener(_) => Err(IoRefusal::unknown()),
        });
        match got {
            Ok(Some(n)) => Poll::Ready(Ok(n)),
            Ok(None) => {
                self.park(id, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn ready(&self, owner: u64, id: u64, dir: u32, _waker: &Waker) -> Poll<IoResult<()>> {
        // A connect here completes inside `open`; a program's pipes are open from the spawn.
        let _ = dir == DIR_READ || dir == DIR_WRITE;
        Poll::Ready(self.on(owner, id, |_| Ok(())))
    }

    fn shut(&self, owner: u64, id: u64, how: u32) -> IoResult<()> {
        self.on(owner, id, |h| match h {
            Handle::Stream(s) => {
                let how = match how {
                    DIR_READ => Shutdown::Read,
                    DIR_WRITE => Shutdown::Write,
                    _ => Shutdown::Both,
                };
                s.shutdown(how).map_err(|e| failed(&e))
            }
            Handle::Program { input, .. } => {
                if how & DIR_WRITE != 0 {
                    input.take();
                }
                Ok(())
            }
            Handle::Listener(_) => Ok(()),
        })
    }

    fn close(&self, owner: u64, id: u64) -> IoResult<()> {
        let taken = {
            let mut inner = lock(&self.inner);
            match inner.handles.get(&id) {
                Some((o, _)) if *o == owner => inner.handles.remove(&id),
                _ => return Err(IoRefusal::unknown()),
            }
        };
        if let Some((_, Handle::Program { mut child, .. })) = taken {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    fn spawn(&self, owner: u64, ticket: Ticket, spawn: &Spawn<'_>) -> IoResult<u64> {
        self.admitted(ticket, &Admit::Program(spawn.program.to_owned()))?;
        let mut child = Command::new(spawn.program)
            .args(spawn.args)
            .env_clear()
            .envs(spawn.env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| failed(&e))?;
        let input = child.stdin.take();
        let mut out = child
            .stdout
            .take()
            .ok_or_else(|| IoRefusal::Failed("the program has no output".into()))?;
        let output: Shared = Arc::default();
        let feed = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                let n = out.read(&mut buf).unwrap_or(0);
                let mut o = lock(&feed.0);
                if n == 0 {
                    o.eof = true;
                } else {
                    o.bytes.extend(&buf[..n]);
                }
                if let Some(w) = o.waker.take() {
                    w.wake();
                }
                feed.1.notify_all();
                if n == 0 {
                    return;
                }
            }
        });
        Ok(self.hold(
            owner,
            Some(ticket),
            Handle::Program {
                child,
                input,
                output,
            },
        ))
    }

    fn ends(&self, owner: u64, id: u64) -> IoResult<(u16, String)> {
        self.on(owner, id, |h| match h {
            Handle::Stream(s) => {
                let local = s.local_addr().map_err(|e| failed(&e))?.port();
                let peer = s.peer_addr().map_err(|e| failed(&e))?.to_string();
                Ok((local, peer))
            }
            _ => Ok((0, String::new())),
        })
    }
}
