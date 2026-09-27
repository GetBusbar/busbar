// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAR END of the transport conformance tests: a peer that speaks through busbar's OWN linked
//! carrier — the both-ways fixture's `linked::carrier`, a separate instance from the one under test —
//! driven to completion on the calling thread. The tests reach a real connection through the carrier
//! kind they prove, rather than through a hand-rolled socket of their own, and name no wire.
//!
//! The peer has no half-close (a carrier closes a connection whole), so a leg that needs the far
//! end to see "no more bytes" closes the connection after its last write, and a leg that reads a
//! known length reads exactly that length.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierPoll, Dest, TransportSettings};

use crate::both_ways::transport_fixture;

/// Wakes the thread that parked on a poll.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive one future on this thread, parking between polls.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// Poll one carrier method to its answer on this thread.
pub(crate) fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    block_on(std::future::poll_fn(|cx| method(cx)))
}

/// One connection of the peer's own carrier.
pub(crate) struct Peer {
    carrier: Arc<dyn Carrier>,
    conn: u64,
}

/// A listener of the peer's own carrier, and the address it bound.
pub(crate) struct PeerListener {
    carrier: Arc<dyn Carrier>,
    listener: u64,
    /// The bound address.
    pub(crate) addr: String,
}

/// The peer's carrier: a fresh instance of the fixture's linked carrier.
fn peer_carrier() -> Arc<dyn Carrier> {
    transport_fixture::linked::carrier(&TransportSettings::default())
}

/// Listen on an ephemeral loopback address.
pub(crate) fn listen() -> PeerListener {
    let carrier = peer_carrier();
    let (listener, addr) = carrier.listen("127.0.0.1:0").expect("the peer listens");
    PeerListener {
        carrier,
        listener,
        addr,
    }
}

impl PeerListener {
    /// The next connection, and the far end it came from.
    pub(crate) fn accept(&self) -> (Peer, String) {
        let (conn, from) =
            wait(|cx| self.carrier.poll_accept(self.listener, cx)).expect("the peer accepts");
        (
            Peer {
                carrier: Arc::clone(&self.carrier),
                conn,
            },
            from,
        )
    }
}

/// Dial `addr` and wait for the connection to open.
pub(crate) fn dial(addr: &str) -> Peer {
    let carrier = peer_carrier();
    let conn = carrier
        .dial(&Dest::Authority(addr))
        .expect("the peer dials");
    wait(|cx| carrier.poll_flush(conn, cx)).expect("the peer's dial opens");
    Peer { carrier, conn }
}

/// An address nothing answers on: a listener the peer's carrier bound, whose connection attempts it
/// refuses by closing each at once — or, simpler and exact, a reserved port nobody may bind unprivileged.
pub(crate) const NOBODY: &str = "127.0.0.1:1";

impl Peer {
    /// Put every one of `bytes` on the connection, then flush.
    pub(crate) fn write_all(&self, bytes: &[u8]) {
        let mut at = 0;
        while at < bytes.len() {
            at += wait(|cx| self.carrier.poll_write(self.conn, cx, &bytes[at..]))
                .expect("the peer writes");
        }
        wait(|cx| self.carrier.poll_flush(self.conn, cx)).expect("the peer flushes");
    }

    /// Read exactly `n` bytes.
    pub(crate) fn read_exact(&self, n: usize) -> Vec<u8> {
        let mut all = Vec::with_capacity(n);
        let mut buf = vec![0_u8; 4096];
        while all.len() < n {
            let want = (n - all.len()).min(buf.len());
            let got = wait(|cx| self.carrier.poll_read(self.conn, cx, &mut buf[..want]))
                .expect("the peer reads");
            assert!(
                got > 0,
                "the far end closed after {} of {n} bytes",
                all.len()
            );
            all.extend_from_slice(&buf[..got]);
        }
        all
    }

    /// One read of at most `max` bytes; empty at the connection's end.
    pub(crate) fn read_some(&self, max: usize) -> Vec<u8> {
        let mut buf = vec![0_u8; max];
        match wait(|cx| self.carrier.poll_read(self.conn, cx, &mut buf)) {
            Ok(n) => buf[..n].to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Read to the connection's clean end.
    pub(crate) fn read_to_end(&self) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = vec![0_u8; 4096];
        loop {
            match wait(|cx| self.carrier.poll_read(self.conn, cx, &mut buf)) {
                Ok(0) | Err(_) => return all,
                Ok(n) => all.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Close the connection whole: the far end reads its clean end.
    pub(crate) fn close(&self) {
        let _ = wait(|cx| self.carrier.poll_close(self.conn, cx, CloseReason::Normal));
    }
}
