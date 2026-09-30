// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection table ACROSS ITS LOWERING: a plugin holding only the `#[repr(C)]` table and the
//! context its host minted ([`HostConns`]) reaches a host's [`Conns`] exactly as a linked caller
//! does, and is refused exactly as one is — a connection another instance owns, a closed one, and
//! a need it never declared.

use super::*;
use crate::conn::ConnSlab;
use crate::transport::wire::WireStatusClass;

/// A host whose connections echo what was written, one body piece per write, ownership kept by the
/// shared [`ConnSlab`].
#[derive(Default)]
struct Echo(ConnSlab<Mutex<Vec<Vec<u8>>>>, Mutex<Vec<u64>>);

impl Conns for Echo {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        if desc.target == "refused.test" {
            self.0.check_need(caller, need)?;
            return Err(ConnError::Refused);
        }
        let mut first = desc.body.to_vec();
        for (name, value) in desc.fields {
            first.extend_from_slice(name.as_bytes());
            first.extend_from_slice(value);
        }
        self.0.insert(caller, need, Mutex::new(vec![first]))
    }
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
    ) -> Result<usize, ConnError> {
        let (_, q) = self.0.get(caller, conn)?;
        q.lock().unwrap().push(bytes.to_vec());
        Ok(bytes.len())
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, q) = self.0.get(caller, conn)?;
        let mut q = q.lock().unwrap();
        if q.is_empty() {
            // Interest registered under the caller's ticket; the host would wake it later.
            self.1.lock().unwrap().push(ticket);
            return Err(ConnError::Pending);
        }
        let next = q.remove(0);
        buf[..next.len()].copy_from_slice(&next);
        // The first answer carries a reason phrase after its bytes, as a head's last piece does.
        let reason = (next == b"hellokv").then(|| {
            buf[next.len()..next.len() + 2].copy_from_slice(b"OK");
            next.len()..next.len() + 2
        });
        Ok(Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: next.len(),
            end: true,
            status: Some(WireStatusClass::Success),
            status_code: Some(200),
            status_namespace: Some("numbering".into()),
            retry_after_secs: None,
            reason,
        })
    }
    fn wait(&self, caller: InstanceId, set: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        for (i, c) in set.iter().enumerate() {
            let (_, q) = self.0.get(caller, *c)?;
            if !q.lock().unwrap().is_empty() {
                return Ok(i);
            }
        }
        Err(ConnError::Pending)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.0.get(caller, conn)?;
        Ok(ConnFacts {
            alpn: Some("h2".into()),
            ..ConnFacts::default()
        })
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.0.remove(caller, conn).map(|_| ())
    }
}

const NEED: NeedId = NeedId(0);

/// Two instances of one host, each with the table and the context its host minted for it.
fn two() -> (Box<ConnHost>, Box<ConnHost>, HostConns, HostConns) {
    let echo = Echo::default();
    echo.0.declare(InstanceId(1), NEED);
    echo.0.declare(InstanceId(2), NEED);
    let conns: Arc<dyn Conns> = Arc::new(echo);
    let (a, b) = (
        Box::new(ConnHost::new(Arc::clone(&conns), InstanceId(1))),
        Box::new(ConnHost::new(conns, InstanceId(2))),
    );
    // SAFETY: the host's own table, over contexts the boxes keep alive for the test.
    let (pa, pb) = unsafe {
        (
            HostConns::new(host_slots(), a.ctx()),
            HostConns::new(host_slots(), b.ctx()),
        )
    };
    (a, b, pa, pb)
}

/// Every operation crosses and comes back as itself: the open's fields and body, a write, the piece
/// with its status and numbering, the wait, the facts, the close.
#[test]
fn every_operation_crosses_the_lowering() {
    let (_a, _b, pa, _) = two();
    let conn = pa
        .open(
            NEED,
            &OpenDesc {
                target: "echo.test",
                fields: &[("k", b"v")],
                body: b"hello",
                timeout_ms: 5,
            },
        )
        .unwrap();
    assert_eq!(pa.wait(&[conn], 0), Ok(0));
    let mut buf = [0_u8; 64];
    let piece = pa.read(conn, 0, &mut buf).unwrap();
    assert_eq!(&buf[..piece.len], b"hellokv");
    // The reason crosses the lowering as a range of the caller's buffer, and reads back.
    assert_eq!(piece.reason, Some(7..9));
    assert_eq!(&buf[7..9], b"OK");
    assert_eq!(
        (
            piece.kind,
            piece.status,
            piece.status_code,
            piece.status_namespace.as_deref()
        ),
        (
            PieceKind::Body,
            Some(WireStatusClass::Success),
            Some(200),
            Some("numbering")
        )
    );
    assert_eq!(pa.write(conn, b"again", true), Ok(5));
    let again = pa.read(conn, 0, &mut buf).unwrap();
    assert_eq!(&buf[..again.len], b"again");
    assert_eq!(again.reason, None);
    assert_eq!(
        pa.read(conn, 0, &mut buf),
        Err(ConnError::Pending),
        "nothing ready is pending, never a block"
    );
    assert_eq!(pa.facts(conn).unwrap().alpn.as_deref(), Some("h2"));
    assert_eq!(pa.close(conn), Ok(()));
    assert_eq!(
        pa.open(
            NEED,
            &OpenDesc {
                target: "refused.test",
                ..OpenDesc::default()
            }
        ),
        Err(ConnError::Refused)
    );
}

/// RED ARM — CROSS-INSTANCE: a connection one instance opened is refused to another on every
/// operation, across the lowering, and stays its owner's.
#[test]
fn another_instances_connection_is_refused_across_the_lowering() {
    let (_a, _b, pa, pb) = two();
    let conn = pa
        .open(
            NEED,
            &OpenDesc {
                target: "echo.test",
                ..OpenDesc::default()
            },
        )
        .unwrap();
    let mut buf = [0_u8; 8];
    assert_eq!(pb.write(conn, b"x", true), Err(ConnError::NotOwner));
    assert_eq!(pb.read(conn, 0, &mut buf), Err(ConnError::NotOwner));
    assert_eq!(pb.wait(&[conn], 0), Err(ConnError::NotOwner));
    assert_eq!(pb.facts(conn), Err(ConnError::NotOwner));
    assert_eq!(pb.close(conn), Err(ConnError::NotOwner));
    assert_eq!(pa.close(conn), Ok(()), "the owner's connection stood");
}

/// RED ARM — CLOSED: a closed id is refused on every operation across the lowering.
#[test]
fn a_closed_connection_is_refused_across_the_lowering() {
    let (_a, _b, pa, _) = two();
    let conn = pa
        .open(
            NEED,
            &OpenDesc {
                target: "echo.test",
                ..OpenDesc::default()
            },
        )
        .unwrap();
    pa.close(conn).unwrap();
    let mut buf = [0_u8; 8];
    assert_eq!(pa.write(conn, b"x", true), Err(ConnError::Closed));
    assert_eq!(pa.read(conn, 0, &mut buf), Err(ConnError::Closed));
    assert_eq!(pa.facts(conn), Err(ConnError::Closed));
    assert_eq!(pa.close(conn), Err(ConnError::Closed));
}

/// RED ARM — UNDECLARED NEED: a need the instance never declared opens nothing across the lowering.
#[test]
fn an_undeclared_need_opens_nothing_across_the_lowering() {
    let (_a, _b, pa, _) = two();
    assert_eq!(
        pa.open(
            NeedId(9),
            &OpenDesc {
                target: "echo.test",
                ..OpenDesc::default()
            }
        ),
        Err(ConnError::UndeclaredNeed)
    );
}

/// Every outcome byte decodes, and only the nine stated ones decode to themselves: an unknown byte
/// is a fault, never a refusal it is not.
#[test]
fn every_outcome_byte_decodes_and_the_unknown_ones_are_faults() {
    for e in [
        ConnError::Pending,
        ConnError::Timeout,
        ConnError::Closed,
        ConnError::NotOwner,
        ConnError::UndeclaredNeed,
        ConnError::Refused,
        ConnError::Fault,
        ConnError::Unarmed,
    ] {
        assert_eq!(RawConnOutcome::of(Err(e)).result(), Err(e));
    }
    assert_eq!(RawConnOutcome::of(Ok(())).result(), Ok(()));
    for b in 9..=u8::MAX {
        assert_eq!(RawConnOutcome(b).result(), Err(ConnError::Fault));
    }
}

/// A null context is a fault, never a dereference.
#[test]
fn a_null_context_is_a_fault() {
    // SAFETY: the table is the host's; the null context is what is under test.
    let p = unsafe {
        HostConns::new(
            host_slots(),
            ConnCtx {
                ptr: core::ptr::null_mut(),
            },
        )
    };
    assert_eq!(p.close(ConnId(1)), Err(ConnError::Fault));
}

/// An instance its host handed no table answers [`ConnError::Unarmed`], by its own refusal text and
/// its own outcome byte, both ways across the ABI.
#[test]
fn an_unarmed_instance_is_refused_by_name() {
    assert_eq!(RawConnOutcome::of(Err(ConnError::Unarmed)).0, 8);
    assert_eq!(RawConnOutcome(8).result(), Err(ConnError::Unarmed));
    assert_eq!(
        ConnError::Unarmed.to_string(),
        "this plugin was handed no connection table"
    );
}

/// NOTHING BLOCKS: a read with nothing ready answers pending at once, and the caller's wake ticket
/// crosses the lowering to the host, which registers interest under it.
#[test]
fn a_read_with_nothing_ready_is_pending_and_hands_the_host_its_ticket() {
    let echo = Arc::new(Echo::default());
    echo.0.declare(InstanceId(1), NEED);
    let conns: Arc<dyn Conns> = echo.clone();
    let host = Box::new(ConnHost::new(conns, InstanceId(1)));
    // SAFETY: the host's own table, over a context the box keeps alive for the test.
    let p = unsafe { HostConns::new(host_slots(), host.ctx()) };
    let conn = p
        .open(
            NEED,
            &OpenDesc {
                target: "echo.test",
                ..OpenDesc::default()
            },
        )
        .unwrap();
    let mut buf = [0_u8; 64];
    p.read(conn, 7, &mut buf).unwrap();
    assert_eq!(p.read(conn, 42, &mut buf), Err(ConnError::Pending));
    assert_eq!(*echo.1.lock().unwrap(), [42], "the ticket reached the host");
    assert_eq!(
        ConnError::Pending.to_string(),
        "nothing is ready on the connection yet"
    );
}

/// A host minted with its state behind it, then MOVED (returned by value, pushed into a vector)
/// after the context was taken: the context points at the heap-stable state, not the moved value.
fn minted() -> (ConnHost, ConnCtx) {
    let echo = Arc::new(Echo::default());
    echo.0.declare(InstanceId(1), NEED);
    let host = ConnHost::new(echo, InstanceId(1));
    let ctx = host.ctx();
    (host, ctx)
}

/// RED: moving a `ConnHost` after minting its context leaves every call through that context
/// sound. The host is returned from a helper and then moved into a vector before any call; the
/// plugin's table still opens, writes and reads back its bytes. With the context pointing at the
/// `ConnHost` value itself this reads freed stack memory.
#[test]
fn a_host_moved_after_minting_its_context_still_serves_the_table() {
    let (host, ctx) = minted();
    let mut hosts = vec![host];
    hosts.push(ConnHost::new(Arc::new(Echo::default()), InstanceId(2)));
    // SAFETY: the host's own table over the context it minted; `hosts` keeps the host alive.
    let p = unsafe { HostConns::new(host_slots(), ctx) };
    let conn = p
        .open(
            NEED,
            &OpenDesc {
                target: "echo.test",
                ..OpenDesc::default()
            },
        )
        .expect("the moved host serves the open");
    assert_eq!(p.write(conn, b"moved", true), Ok(5));
    let mut buf = [0_u8; 64];
    let opening = p.read(conn, 7, &mut buf).expect("the (empty) opening");
    assert_eq!(opening.len, 0);
    let piece = p.read(conn, 7, &mut buf).expect("the echo");
    assert_eq!(&buf[..piece.len], b"moved");
    drop(hosts);
}
