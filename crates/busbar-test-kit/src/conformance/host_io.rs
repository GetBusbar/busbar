// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::io::{DIR_READ, DIR_WRITE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::io_host::{Ends, IoHost, IoRefusal, IoResult, Spawn};

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
    error: Option<String>,
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
    waiting: Vec<(u64, u32, Waker)>,
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

fn program_exit(status: ExitStatus) -> u32 {
    if let Some(code) = status.code() {
        return code as u32;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .map_or(128, |signal| 128_u32.saturating_add(signal as u32))
    }
    #[cfg(not(unix))]
    {
        128
    }
}

#[cfg(unix)]
fn socket_ready(stream: &TcpStream, direction: u32) -> bool {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: if direction == DIR_WRITE {
            libc::POLLOUT
        } else {
            libc::POLLIN
        },
        revents: 0,
    };
    // SAFETY: one live pollfd, a socket borrowed for this nonblocking call, and no callbacks.
    let ready = unsafe { libc::poll(&mut fd, 1, 0) };

    ready < 0 || (ready > 0 && fd.revents != 0)
}

#[cfg(windows)]
fn socket_ready(stream: &TcpStream, direction: u32) -> bool {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAPoll, POLLRDNORM, POLLWRNORM, WSAPOLLFD};
    let mut fd = WSAPOLLFD {
        fd: stream.as_raw_socket() as _,
        events: if direction == DIR_WRITE {
            POLLWRNORM
        } else {
            POLLRDNORM
        },
        revents: 0,
    };
    // SAFETY: one initialized WSAPOLLFD borrows a live socket for this nonblocking call.
    let ready = unsafe { WSAPoll(&mut fd, 1, 0) };

    ready < 0 || (ready > 0 && fd.revents != 0)
}

impl SuiteIo {
    pub fn admit(&self, ticket: Ticket, what: Admit) {
        lock(&self.inner).admitted.insert(ticket, what);
    }

    #[must_use]
    pub fn made(&self, ticket: Ticket) -> Option<u64> {
        lock(&self.inner).made.get(&ticket).copied()
    }

    #[must_use]
    pub fn held(&self) -> usize {
        lock(&self.inner).handles.len()
    }

    pub(super) fn holds_only(&self, listener: Option<u64>) -> bool {
        lock(&self.inner)
            .handles
            .keys()
            .all(|handle| Some(*handle) == listener)
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

    fn on<R>(
        &self,
        owner: u64,
        id: u64,
        f: impl FnOnce(&mut Handle) -> IoResult<R>,
    ) -> IoResult<R> {
        let mut inner = lock(&self.inner);
        match inner.handles.get_mut(&id) {
            Some((o, h)) if *o == owner => f(h),
            _ => Err(IoRefusal::unknown()),
        }
    }

    fn park(&self, id: u64, direction: u32, waker: &Waker) {
        let waker = waker.clone();
        lock(&self.inner).waiting.push((id, direction, waker));
    }

    pub fn pump(&self) {
        let mut inner = lock(&self.inner);
        let waiting = std::mem::take(&mut inner.waiting);
        let mut ready_wakes = Vec::new();
        let mut retired_wakes = Vec::new();
        for (id, direction, waker) in waiting {
            let ready = match inner.handles.get(&id).map(|(_, h)| h) {
                Some(Handle::Stream(s)) => socket_ready(s, direction),
                Some(Handle::Listener(_)) | None => true,

                Some(Handle::Program { .. }) => {
                    retired_wakes.push(waker);
                    continue;
                }
            };
            if ready {
                ready_wakes.push(waker);
            } else {
                inner.waiting.push((id, direction, waker));
            }
        }
        drop(inner);
        drop(retired_wakes);
        for waker in ready_wakes {
            waker.wake();
        }
    }

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
                        !o.bytes.is_empty() || o.eof || o.error.is_some()
                    }
                    _ => true,
                }
            };
            if ready {
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
                if let Err(error) = s.set_nonblocking(true) {
                    return Poll::Ready(Err(failed(&error)));
                }
                Poll::Ready(Ok((
                    self.hold(owner, Some(ticket), Handle::Stream(s)),
                    peer,
                )))
            }
            Ok(None) => {
                self.park(listener, DIR_READ, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn read(&self, owner: u64, id: u64, buf: &mut [u8], waker: &Waker) -> Poll<IoResult<usize>> {
        let mut next_wake = Some(waker.clone());
        let mut retired_wake = None;
        let got = self.on(owner, id, |h| match h {
            Handle::Stream(s) => match s.read(buf) {
                Ok(n) => Ok(Some(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(failed(&e)),
            },
            Handle::Program { output, .. } => {
                let mut o = lock(&output.0);
                if o.bytes.is_empty() {
                    if let Some(error) = &o.error {
                        return Err(IoRefusal::Failed(error.clone()));
                    }
                }
                if o.bytes.is_empty() && !o.eof {
                    retired_wake = o
                        .waker
                        .replace(next_wake.take().expect("one program reader"));
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
        drop(retired_wake);
        drop(next_wake);
        match got {
            Ok(Some(n)) => Poll::Ready(Ok(n)),
            Ok(None) => {
                self.park(id, DIR_READ, waker);
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
                self.park(id, DIR_WRITE, waker);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn ready(&self, owner: u64, id: u64, dir: u32, _waker: &Waker) -> Poll<IoResult<()>> {
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
                let result = out.read(&mut buf);
                if matches!(&result, Err(e) if e.kind() == ErrorKind::Interrupted) {
                    continue;
                }
                let mut o = lock(&feed.0);
                let ended = match result {
                    Ok(0) => {
                        o.eof = true;
                        true
                    }
                    Ok(n) => {
                        o.bytes.extend(&buf[..n]);
                        false
                    }
                    Err(error) => {
                        o.error = Some(error.to_string());
                        true
                    }
                };
                let wake = o.waker.take();
                drop(o);
                feed.1.notify_all();
                if let Some(wake) = wake {
                    wake.wake();
                }
                if ended {
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

    fn ends(&self, owner: u64, id: u64) -> IoResult<Ends> {
        self.on(owner, id, |h| match h {
            Handle::Stream(s) => Ok(Ends {
                port: s.local_addr().map_err(|e| failed(&e))?.port(),
                peer: s.peer_addr().map_err(|e| failed(&e))?.to_string(),
                exit: None,
            }),

            Handle::Program { child, .. } => Ok(Ends {
                exit: child.try_wait().map_err(|e| failed(&e))?.map(program_exit),
                ..Ends::default()
            }),
            Handle::Listener(_) => Ok(Ends::default()),
        })
    }
}

#[cfg(all(test, loader_self_tests))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[test]
    fn finished_program_status_preserves_exit_codes_and_platform_termination() {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(program_exit(ExitStatus::from_raw(0)), 0);
            assert_eq!(program_exit(ExitStatus::from_raw(7 << 8)), 7);
            assert_eq!(program_exit(ExitStatus::from_raw(9)), 128 + 9);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            assert_eq!(program_exit(ExitStatus::from_raw(0)), 0);
            assert_eq!(program_exit(ExitStatus::from_raw(7)), 7);
            assert_eq!(program_exit(ExitStatus::from_raw(0xc000_013a)), 0xc000_013a);
        }
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_pending_writer_wakes_when_peer_drains_without_sending_input() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let io = SuiteIo::default();
        let id = io.hold(7, None, Handle::Stream(stream));
        let writes = Arc::new(Wakes::default());
        let reads = Arc::new(Wakes::default());
        let writer = Waker::from(Arc::clone(&writes));
        let reader = Waker::from(Arc::clone(&reads));
        let bytes = [7; 65536];
        let mut sent = 0;
        loop {
            match io.write(7, id, &bytes, &writer) {
                Poll::Ready(Ok(n)) if n > 0 => sent += n,
                Poll::Pending => break,
                other => panic!("write: {other:?}"),
            }
            assert!(
                sent < 64 * 1024 * 1024,
                "the peer must eventually apply backpressure"
            );
        }
        assert!(io.read(7, id, &mut [0; 1], &reader).is_pending());
        let until = Instant::now() + Duration::from_secs(5);
        let mut scratch = [0; 65536];
        while writes.0.load(Ordering::SeqCst) == 0 {
            loop {
                match peer.read(&mut scratch) {
                    Ok(n) if n > 0 => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    other => panic!("peer read: {other:?}"),
                }
            }
            io.pump();
            assert!(
                Instant::now() < until,
                "a writable socket never woke its writer"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(reads.0.load(Ordering::SeqCst), 0, "the peer sent no input");
        assert!(matches!(io.write(7, id, b"next", &writer), Poll::Ready(Ok(n)) if n > 0));
        io.close(7, id).unwrap();
    }
}
