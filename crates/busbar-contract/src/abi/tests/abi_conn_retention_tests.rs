// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RANGES THE CONNECTION TABLE EXPOSES OUTLIVE LATER ANSWERS: a raw plugin that keeps the

use super::*;
use crate::conn::ConnSlab;
use crate::transport::wire::CertFacts;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const NEED: NeedId = NeedId(0);

/// A host whose connections answer what the test scripts: each `read` an empty piece stating the
/// scripted numbering, each `facts` the scripted facts; or, cycling, eight different values by call
/// count (for the threaded test). The close can be made to fail.
#[derive(Default)]
struct Scripted {
    slab: ConnSlab<()>,
    namespace: Mutex<Option<String>>,
    facts: Mutex<ConnFacts>,
    cycle: AtomicBool,
    reads: AtomicUsize,
    answers: AtomicUsize,
    fail_close: AtomicBool,
}

impl Conns for Scripted {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        _: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.insert(caller, need, ())
    }
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(caller, conn)?;
        Ok(bytes.len())
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: Ticket,
        _: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.slab.get(caller, conn)?;
        let status_namespace = if self.cycle.load(Ordering::SeqCst) {
            Some(format!(
                "ns-{}",
                self.reads.fetch_add(1, Ordering::SeqCst) % 8
            ))
        } else {
            self.namespace.lock().unwrap().clone()
        };
        Ok(Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: 0,
            end: true,
            status: None,
            status_code: None,
            status_namespace,
            retry_after_secs: None,
            declared_len: None,
            fault: None,
            reason: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        if self.cycle.load(Ordering::SeqCst) {
            let n = self.answers.fetch_add(1, Ordering::SeqCst) % 8;
            return Ok(ConnFacts {
                sni: Some(format!("sni-{n}")),
                ..ConnFacts::default()
            });
        }
        Ok(self.facts.lock().unwrap().clone())
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        if self.fail_close.load(Ordering::SeqCst) {
            return Err(ConnError::Fault);
        }
        self.slab.remove(caller, conn).map(|_| ())
    }
}

/// A scripted host for instances 1 and 2, and a boxed `ConnHost` for each.
fn rig() -> (Arc<Scripted>, Box<ConnHost>, Box<ConnHost>) {
    let script = Arc::new(Scripted::default());
    script.slab.declare(InstanceId(1), NEED);
    script.slab.declare(InstanceId(2), NEED);
    let conns: Arc<dyn Conns> = script.clone();
    (
        script,
        Box::new(ConnHost::new(Arc::clone(&conns), InstanceId(1))),
        Box::new(ConnHost::new(conns, InstanceId(2))),
    )
}

/// A connection the instance behind `host` opened (through the SDK's view, which is all it is used
fn open(host: &ConnHost) -> ConnId {
    // SAFETY: the host's own table over the context `host` keeps alive for the test.
    let plugin = unsafe { HostConns::new(host_slots(), host.ctx()) };
    plugin
        .open(
            NEED,
            &OpenDesc {
                target: "scripted.test",
                ..OpenDesc::default()
            },
        )
        .expect("the scripted host opens")
}

/// The `read` slot itself: the numbering range the piece states.
fn raw_read(ctx: ConnCtx, conn: ConnId) -> DeclStr {
    let mut buf = [0_u8; 1];
    // SAFETY: an all-zero `WirePiece` is a valid out-slot (integers, NULL ranges).
    let mut piece: WirePiece = unsafe { core::mem::zeroed() };
    let read = host_slots().read.unwrap();
    assert_eq!(
        // SAFETY: callers keep ctx's host live; buf and piece are exclusive initialized outputs.
        unsafe { read(ctx, conn.0, 0, buf.as_mut_ptr(), buf.len(), &mut piece) }.result(),
        Ok(())
    );
    piece.ns
}

/// The `facts` slot itself: the six string ranges, in field order (sni, alpn, subject, issuer,
fn raw_facts(ctx: ConnCtx, conn: ConnId) -> [DeclStr; 6] {
    // SAFETY: an all-zero `WireConnFacts` is a valid out-slot (integers, NULL ranges).
    let mut w: WireConnFacts = unsafe { core::mem::zeroed() };
    let facts = host_slots().facts.unwrap();
    // SAFETY: callers keep ctx's host live and w is our initialized exclusive output.
    assert_eq!(unsafe { facts(ctx, conn.0, &mut w) }.result(), Ok(()));
    [
        w.sni,
        w.alpn,
        w.cert_subject,
        w.cert_issuer,
        w.cert_fingerprint,
        w.claim,
    ]
}

/// The `close` slot itself.
fn raw_close(ctx: ConnCtx, conn: ConnId) -> Result<(), ConnError> {
    // SAFETY: callers keep ctx's host live; the host checks the numeric connection handle.
    unsafe { (host_slots().close.unwrap())(ctx, conn.0) }.result()
}

/// A copy of the string the connection's retention CURRENTLY owns at exactly the saved address and
fn live(host: &ConnHost, conn: ConnId, d: DeclStr) -> Option<String> {
    host.state.held().get(&conn).and_then(|held| {
        held.retention
            .iter()
            .find(|s| s.as_ptr() == d.ptr && s.len() == d.len)
            .cloned()
    })
}

/// Whether the retention currently owns a string at exactly the saved address and length.
fn owns(host: &ConnHost, conn: ConnId, d: DeclStr) -> bool {
    live(host, conn, d).is_some()
}

/// How many distinct strings the connection's retention owns.
fn kept(host: &ConnHost, conn: ConnId) -> usize {
    host.state
        .held()
        .get(&conn)
        .map_or(0, |held| held.retention.len())
}

/// Whether the connection's retention owns a string equal to `text`.
fn holds(host: &ConnHost, conn: ConnId, text: &str) -> bool {
    host.state
        .held()
        .get(&conn)
        .is_some_and(|held| held.retention.contains(text))
}

/// Whether the host's table holds nothing at all for the connection (its close retired it).
fn retired(host: &ConnHost, conn: ConnId) -> bool {
    host.state.held().get(&conn).is_none()
}

/// The text of a range the slots handed out: the CURRENT live owner's copy at the saved address and
fn copy(host: &ConnHost, conn: ConnId, d: DeclStr) -> String {
    live(host, conn, d).unwrap_or_else(|| {
        panic!(
            "the exposed range {:?}+{} is no longer owned by the connection's retention",
            d.ptr, d.len
        )
    })
}

fn facts_of(
    sni: Option<&str>,
    alpn: Option<&str>,
    cert: Option<(&str, &str, &str)>,
    claim: Option<&str>,
) -> ConnFacts {
    ConnFacts {
        sni: sni.map(Into::into),
        alpn: alpn.map(Into::into),
        peer_cert: cert.map(|(subject, issuer, fingerprint)| CertFacts {
            subject: subject.into(),
            issuer: issuer.into(),
            fingerprint: fingerprint.into(),
        }),
        claim: claim.map(Into::into),
        ..ConnFacts::default()
    }
}

/// RED: `host_read` overwrote the connection's one numbering string, freeing the heap bytes an
#[test]
fn an_earlier_numbering_range_outlives_a_different_and_an_absent_one_until_close() {
    let (script, a, _b) = rig();
    let (ctx, conn) = (a.ctx(), open(&a));

    *script.namespace.lock().unwrap() = Some("alpha-numbering".into());
    let first = raw_read(ctx, conn);
    assert!(
        owns(&a, conn, first),
        "the numbering is held for the plugin"
    );
    assert_eq!(copy(&a, conn, first), "alpha-numbering");

    *script.namespace.lock().unwrap() = Some("beta-numbering-is-longer".into());
    let second = raw_read(ctx, conn);
    assert!(
        owns(&a, conn, first),
        "the first numbering's storage was freed by a later answer"
    );
    assert!(owns(&a, conn, second));
    assert_ne!(first.ptr, second.ptr);
    assert_eq!(copy(&a, conn, first), "alpha-numbering");
    assert_eq!(copy(&a, conn, second), "beta-numbering-is-longer");

    *script.namespace.lock().unwrap() = None;
    let none = raw_read(ctx, conn);
    assert!(
        none.ptr.is_null() && none.len == 0,
        "absent is the NULL range"
    );
    assert!(
        owns(&a, conn, first),
        "an absent answer took the first back"
    );
    assert!(
        owns(&a, conn, second),
        "an absent answer took the second back"
    );
    assert_eq!(copy(&a, conn, first), "alpha-numbering");
    assert_eq!(copy(&a, conn, second), "beta-numbering-is-longer");

    *script.namespace.lock().unwrap() = Some("alpha-numbering".into());
    let again = raw_read(ctx, conn);
    assert_eq!(
        (again.ptr, again.len),
        (first.ptr, first.len),
        "an equal numbering is the same range"
    );
    for _ in 0..100 {
        assert_eq!(raw_read(ctx, conn).ptr, first.ptr);
    }
    assert_eq!(kept(&a, conn), 2, "two distinct numberings, held once each");

    assert_eq!(raw_close(ctx, conn), Ok(()));
    assert!(retired(&a, conn), "the close retired what was held");
}

/// An absent numbering allocates nothing and files no entry for the connection: a read with none
#[test]
fn an_absent_numbering_files_nothing() {
    let (_script, a, _b) = rig();
    let (ctx, conn) = (a.ctx(), open(&a));
    let none = raw_read(ctx, conn);
    assert!(none.ptr.is_null() && none.len == 0);
    assert!(
        retired(&a, conn),
        "nothing was held for an absent numbering"
    );
    assert_eq!(raw_close(ctx, conn), Ok(()));
}

/// RED: `host_facts` replaced the connection's one `ConnFacts` (`Option::insert`), freeing the six
#[test]
fn every_facts_string_range_outlives_later_versions_and_an_absent_certificate_until_close() {
    let (script, a, _b) = rig();
    let (ctx, conn) = (a.ctx(), open(&a));
    let mut saved: Vec<(DeclStr, &str)> = Vec::new();

    *script.facts.lock().unwrap() = facts_of(
        Some("one.sni.test"),
        Some("h2"),
        Some(("CN=one subject", "CN=one issuer", "sha256:one-fingerprint")),
        Some("claim-one"),
    );
    let v1 = raw_facts(ctx, conn);
    let expect1 = [
        "one.sni.test",
        "h2",
        "CN=one subject",
        "CN=one issuer",
        "sha256:one-fingerprint",
        "claim-one",
    ];
    saved.extend(v1.into_iter().zip(expect1));
    assert_eq!(kept(&a, conn), 6);

    let mut two = facts_of(
        Some("two.sni.example"),
        Some("http/1.1"),
        Some(("CN=two subject", "CN=two issuer", "sha256:two-fingerprint")),
        Some("claim-two"),
    );
    two.peer_key_pin = Some("never-exposed-key-pin".into());
    two.client_identity = true;
    *script.facts.lock().unwrap() = two;
    let v2 = raw_facts(ctx, conn);
    let expect2 = [
        "two.sni.example",
        "http/1.1",
        "CN=two subject",
        "CN=two issuer",
        "sha256:two-fingerprint",
        "claim-two",
    ];
    saved.extend(v2.into_iter().zip(expect2));
    assert_eq!(kept(&a, conn), 12);
    assert!(
        !holds(&a, conn, "never-exposed-key-pin"),
        "a fact the plugin is never shown was kept"
    );

    *script.facts.lock().unwrap() = ConnFacts::default();
    let v3 = raw_facts(ctx, conn);
    assert!(
        v3.iter().all(|d| d.ptr.is_null() && d.len == 0),
        "an absent field is the NULL range, the certificate's three with it"
    );
    assert_eq!(kept(&a, conn), 12, "absent facts took nothing back");

    *script.facts.lock().unwrap() = facts_of(
        Some("one.sni.test"),
        Some("h2"),
        Some(("CN=one subject", "CN=one issuer", "sha256:one-fingerprint")),
        Some("claim-one"),
    );
    let v4 = raw_facts(ctx, conn);
    for (again, first) in v4.iter().zip(&v1) {
        assert_eq!((again.ptr, again.len), (first.ptr, first.len));
    }
    assert_eq!(kept(&a, conn), 12);

    *script.facts.lock().unwrap() = facts_of(Some("shared"), Some("shared"), None, Some("shared"));
    let v5 = raw_facts(ctx, conn);
    assert_eq!((v5[0].ptr, v5[0].len), (v5[1].ptr, v5[1].len));
    assert_eq!((v5[0].ptr, v5[0].len), (v5[5].ptr, v5[5].len));
    assert!(v5[2].ptr.is_null() && v5[3].ptr.is_null() && v5[4].ptr.is_null());
    saved.push((v5[0], "shared"));
    assert_eq!(kept(&a, conn), 13);

    for (range, _) in &saved {
        assert!(
            owns(&a, conn, *range),
            "an earlier facts range's storage was freed by a later answer"
        );
    }
    for (range, expected) in &saved {
        assert_eq!(copy(&a, conn, *range), *expected);
    }

    assert_eq!(raw_close(ctx, conn), Ok(()));
    assert!(retired(&a, conn));
}

/// Many distinct numberings and facts grow the retention through many rehashes; no range handed out
#[test]
fn many_growth_calls_keep_every_earlier_range_where_it_was_handed_out() {
    let (script, a, _b) = rig();
    let (ctx, conn) = (a.ctx(), open(&a));
    let mut numberings = Vec::new();
    let mut snis = Vec::new();
    for i in 0..200 {
        *script.namespace.lock().unwrap() = Some(format!("numbering-{i}"));
        numberings.push(raw_read(ctx, conn));
        *script.facts.lock().unwrap() =
            facts_of(Some(&format!("host-{i}.growth.test")), None, None, None);
        snis.push(raw_facts(ctx, conn)[0]);
    }
    assert_eq!(kept(&a, conn), 400);
    for (i, (numbering, sni)) in numberings.iter().zip(&snis).enumerate() {
        assert!(
            owns(&a, conn, *numbering),
            "numbering {i} moved or was freed"
        );
        assert!(owns(&a, conn, *sni), "sni {i} moved or was freed");
    }
    for (i, (numbering, sni)) in numberings.iter().zip(&snis).enumerate() {
        assert_eq!(copy(&a, conn, *numbering), format!("numbering-{i}"));
        assert_eq!(copy(&a, conn, *sni), format!("host-{i}.growth.test"));
    }

    *script.namespace.lock().unwrap() = Some("numbering-7".into());
    assert_eq!(raw_read(ctx, conn).ptr, numberings[7].ptr);
    assert_eq!(kept(&a, conn), 400);
    assert_eq!(raw_close(ctx, conn), Ok(()));
    assert!(retired(&a, conn));
}

/// Raw `read` and `facts` calls from several threads on one connection, each call a different one
#[test]
fn concurrent_raw_reads_and_facts_on_one_connection_keep_every_handed_range() {
    let (script, a, _b) = rig();
    let conn = open(&a);
    script.cycle.store(true, Ordering::SeqCst);
    let addr = a.ctx().ptr as usize;
    let raw = |range: DeclStr| (range.ptr as usize, range.len);

    let (numberings, snis) = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(move || {
                    let ctx = ConnCtx {
                        ptr: addr as *mut c_void,
                    };
                    (0..50)
                        .map(|_| raw(raw_read(ctx, conn)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let answerers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(move || {
                    let ctx = ConnCtx {
                        ptr: addr as *mut c_void,
                    };
                    (0..50)
                        .map(|_| raw(raw_facts(ctx, conn)[0]))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let join = |threads: Vec<std::thread::ScopedJoinHandle<'_, Vec<(usize, usize)>>>| {
            threads
                .into_iter()
                .flat_map(|t| t.join().expect("a raw slot call panicked"))
                .collect::<Vec<_>>()
        };
        (join(readers), join(answerers))
    });
    assert_eq!((numberings.len(), snis.len()), (200, 200));
    assert_eq!(kept(&a, conn), 16);

    let mut by_text: HashMap<String, (usize, usize)> = HashMap::new();
    for (ptr, len) in numberings.iter().chain(&snis) {
        let range = DeclStr {
            ptr: *ptr as *const u8,
            len: *len,
        };
        assert!(
            owns(&a, conn, range),
            "a range handed to a thread is no longer owned"
        );
    }
    for (ptr, len) in numberings.iter().chain(&snis) {
        let range = DeclStr {
            ptr: *ptr as *const u8,
            len: *len,
        };
        let text = copy(&a, conn, range);
        assert!(
            text.starts_with("ns-") || text.starts_with("sni-"),
            "{text}"
        );
        let same = by_text.entry(text.clone()).or_insert((*ptr, *len));
        assert_eq!(
            *same,
            (*ptr, *len),
            "{text} was handed out at two addresses"
        );
    }
    for n in 0..8 {
        assert!(by_text.contains_key(&format!("ns-{n}")));
        assert!(by_text.contains_key(&format!("sni-{n}")));
    }
    assert_eq!(raw_close(a.ctx(), conn), Ok(()));
    assert!(retired(&a, conn));
}

/// Only a SUCCESSFUL close by the owner ends the borrows: a close another instance attempts (not its
#[test]
fn only_a_successful_owner_close_retires_the_exposed_ranges() {
    let (script, a, b) = rig();
    let (actx, bctx) = (a.ctx(), b.ctx());
    let (conn, sibling) = (open(&a), open(&a));
    *script.namespace.lock().unwrap() = Some("kept-numbering".into());
    *script.facts.lock().unwrap() = facts_of(Some("kept.sni.test"), Some("h2"), None, None);
    let numbering = raw_read(actx, conn);
    let sni = raw_facts(actx, conn)[0];
    let other = raw_read(actx, sibling);
    assert_eq!(copy(&a, conn, numbering), "kept-numbering");
    assert_eq!(copy(&a, conn, sni), "kept.sni.test");

    assert_eq!(raw_close(bctx, conn), Err(ConnError::NotOwner));
    assert!(retired(&b, conn));
    assert_eq!(copy(&a, conn, numbering), "kept-numbering");
    assert_eq!(copy(&a, conn, sni), "kept.sni.test");

    script.fail_close.store(true, Ordering::SeqCst);
    assert_eq!(raw_close(actx, conn), Err(ConnError::Fault));
    assert!(owns(&a, conn, numbering) && owns(&a, conn, sni));
    assert_eq!(copy(&a, conn, numbering), "kept-numbering");
    assert_eq!(copy(&a, conn, sni), "kept.sni.test");
    script.fail_close.store(false, Ordering::SeqCst);

    assert_eq!(raw_close(actx, conn), Ok(()));
    assert!(
        retired(&a, conn),
        "the close left the retention in the table"
    );
    assert!(owns(&a, sibling, other), "a sibling's range ended with it");
    assert_eq!(copy(&a, sibling, other), "kept-numbering");
    assert_eq!(raw_close(actx, conn), Err(ConnError::Closed));
    assert!(retired(&a, conn));
    assert_eq!(raw_close(actx, sibling), Ok(()));
    assert!(retired(&a, sibling));
}
