// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST STAND-IN FOR THE HOST'S CONNECTION TABLE, over plain TCP: [`TcpConns`] serves the `tcp`
//! transport to a plugin's declared needs, so a store (or any kind) that reaches a real backend
//! over the host's connector can be opened on a [`Dispatcher`](crate::dispatch::Dispatcher) in a
//! test without the process's connector. A read with nothing ready answers PENDING and wakes the
//! ticket when bytes arrive, so a plugin's pending path is exercised as in production. Plaintext
//! only (`upgrade_secure` is refused). A test double: it never ships (`test-support`).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

/// How often a parked read looks for bytes.
const POLL: Duration = Duration::from_millis(1);

/// THE TEST CONNECTION TABLE over plain TCP.
pub struct TcpConns {
    slab: ConnSlab<Mutex<TcpStream>>,
    wake: Arc<dyn Fn(u64) + Send + Sync>,
}

impl std::fmt::Debug for TcpConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConns").finish_non_exhaustive()
    }
}

impl TcpConns {
    /// A table waking a parked read's ticket through `wake` (the dispatcher's
    /// [`conn_waker`](crate::dispatch::Dispatcher::conn_waker)).
    #[must_use]
    pub fn new(wake: Arc<dyn Fn(u64) + Send + Sync>) -> Self {
        Self {
            slab: ConnSlab::default(),
            wake,
        }
    }
}

fn io(e: &std::io::Error) -> ConnError {
    match e.kind() {
        ErrorKind::TimedOut => ConnError::Timeout,
        _ => ConnError::Closed,
    }
}

impl Conns for TcpConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        let stream = TcpStream::connect(desc.target).map_err(|_| ConnError::Refused)?;
        stream.set_nodelay(true).map_err(|e| io(&e))?;
        stream.set_nonblocking(true).map_err(|e| io(&e))?;
        self.slab.insert(caller, need, Mutex::new(stream))
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        let (_, s) = self.slab.get(caller, conn)?;
        let mut s = s.lock().unwrap_or_else(PoisonError::into_inner);
        let mut done = 0;
        while done < bytes.len() {
            match s.write(&bytes[done..]) {
                Ok(0) => return Err(ConnError::Closed),
                Ok(n) => done += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(io(&e)),
            }
        }
        Ok(done)
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, s) = self.slab.get(caller, conn)?;
        let mut s = s.lock().unwrap_or_else(PoisonError::into_inner);
        match s.read(buf) {
            Ok(0) => Err(ConnError::Closed),
            Ok(n) => Ok(Piece {
                kind: PieceKind::Body,
                stream: StreamId(0),
                len: n,
                end: false,
                status: None,
                status_code: None,
                status_namespace: None,
                retry_after_secs: None,
                reason: None,
            }),
            Err(e) if e.kind() == ErrorKind::WouldBlock && ticket != 0 => {
                // Wake the ticket once bytes (or the end) are there.
                let watch = s.try_clone().map_err(|e| io(&e))?;
                let wake = self.wake.clone();
                std::thread::spawn(move || {
                    let mut one = [0_u8; 1];
                    loop {
                        match watch.peek(&mut one) {
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(POLL);
                            }
                            _ => break,
                        }
                    }
                    wake(ticket);
                });
                Err(ConnError::Pending)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Err(ConnError::Pending),
            Err(e) => Err(io(&e)),
        }
    }

    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        Ok(ConnFacts::default())
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let s = self.slab.remove(caller, conn)?;
        let s = s.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = s.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

impl DeclaredConns for TcpConns {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        if spec.transport != "tcp" {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "tcp"
    }
}
