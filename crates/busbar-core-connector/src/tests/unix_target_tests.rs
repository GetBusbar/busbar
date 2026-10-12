// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! UNIX-DOMAIN TARGETS (ARCHITECT ruling 2026-10-03 12:10Z, VALKEY-UNIX: "unix-socket URLs keep
//! working — the connector serves unix-domain targets for operator-infrastructure needs; no socket
//! in the plugin"). A `tcp` need names `unix:/absolute/path` as its target:
//!
//! * in the operator-infrastructure (or loopback-allowed) class it opens a raw stream to a real
//!   unix-domain far end, writes reach it, and a read with nothing ready pends and is woken through
//!   the connector's ticket wake;
//! * in every other class it is refused before any dial;
//! * a need whose config names its target dials that path and no other;
//! * no socket at the path is refused.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER,
};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

const OWNER: InstanceId = InstanceId(1);

/// A connector serving a raw `tcp` entry, counting its ticket wakes.
fn connector(wakes: Arc<AtomicU64>) -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("tcp")),
        alpn: Vec::new(),
    }])
    .unwrap();
    Connector::serving(
        view,
        crate::tests::loopback_literals(),
        None,
        Arc::new(move |_| {
            wakes.fetch_add(1, Ordering::SeqCst);
        }),
    )
}

/// A fresh socket path (short: a unix path is bounded) and its `unix:` target.
fn socket_path(tag: &str) -> (std::path::PathBuf, String) {
    static N: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "bbu-{tag}-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let target = format!("unix:{}", path.display());
    (path, target)
}

/// A unix-domain far end at `path`: per connection it reads five bytes, pauses, then answers
/// `answer`.
fn far_end(path: &std::path::Path) {
    let l = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0_u8; 5];
                if s.read_exact(&mut buf).await.is_ok() && &buf == b"hello" {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = s.write_all(b"answer").await;
                }
            });
        }
    });
}

fn open(c: &Connector, target: &str) -> Result<ConnId, ConnError> {
    c.open(
        OWNER,
        NeedId(0),
        &OpenDesc {
            target,
            ..OpenDesc::default()
        },
    )
}

/// Write all of `bytes`, driving the connection while it is still connecting or its buffer is full.
async fn send(c: &Connector, id: ConnId, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        match c.write(OWNER, id, &bytes[at..], false, false) {
            Ok(n) => at += n,
            Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
            Err(e) => panic!("the write was refused: {e:?}"),
        }
    }
}

/// RED: an operator-infrastructure `tcp` need reaches a real unix-domain far end at `unix:<path>`:
/// the write reaches it, a read with nothing ready is PENDING with the ticket registered, the far
/// end's answer wakes the ticket, and the next read answers it.
#[test]
fn an_operator_infrastructure_need_reaches_a_unix_domain_far_end() {
    worker().block_on(async {
        let (path, target) = socket_path("op");
        far_end(&path);
        let wakes = Arc::new(AtomicU64::new(0));
        let c = connector(wakes.clone());
        c.declare_need(OWNER, NeedId(0), "tcp", EGRESS_OPERATOR_INFRASTRUCTURE)
            .expect("a served scheme declares");
        let id = open(&c, &target).expect("the unix target opens");
        send(&c, id, b"hello").await;
        let mut buf = [0_u8; 64];
        let mut pended = false;
        let piece = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match c.read(OWNER, id, 7, &mut buf) {
                    Err(ConnError::Pending) => {
                        pended = true;
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    other => break other,
                }
            }
        })
        .await
        .expect("the answer arrives")
        .expect("the read answers");
        assert_eq!(&buf[..piece.len], b"answer");
        assert!(pended, "the read pended before the far end answered");
        assert!(wakes.load(Ordering::SeqCst) >= 1, "the ticket was woken");
        assert_eq!(c.facts(OWNER, id).unwrap().claim.as_deref(), Some("tcp"));
        c.close(OWNER, id).unwrap();
        let _ = std::fs::remove_file(&path);
    });
}

/// A loopback-allowed need is admitted to a unix target too.
#[test]
fn a_loopback_allowed_need_reaches_a_unix_domain_far_end() {
    worker().block_on(async {
        let (path, target) = socket_path("lb");
        far_end(&path);
        let c = connector(Arc::new(AtomicU64::new(0)));
        c.declare_need(OWNER, NeedId(0), "tcp", EGRESS_LOOPBACK_ALLOWED)
            .expect("declares");
        let id = open(&c, &target).expect("the unix target opens");
        c.close(OWNER, id).unwrap();
        let _ = std::fs::remove_file(&path);
    });
}

/// RED: a unix target is refused, before any dial, to every class but operator-infrastructure and
/// loopback-allowed.
#[test]
fn a_unix_target_is_refused_to_every_other_class() {
    worker().block_on(async {
        let (path, target) = socket_path("cls");
        far_end(&path);
        for class in [crate::DEFAULT_CLASS, EGRESS_PROVIDER, EGRESS_OPEN_WEB] {
            let c = connector(Arc::new(AtomicU64::new(0)));
            c.declare_need(OWNER, NeedId(0), "tcp", class)
                .expect("declares");
            assert_eq!(open(&c, &target), Err(ConnError::Refused), "class {class}");
        }
        let _ = std::fs::remove_file(&path);
    });
}

/// RED: a need whose config names its unix path dials that path and no other: another path is
/// refused, the declared one opens (named, or by naming no target).
#[test]
fn a_config_targeted_need_is_pinned_to_its_unix_path() {
    worker().block_on(async {
        let (path, declared) = socket_path("pin");
        let (other_path, other) = socket_path("other");
        far_end(&path);
        far_end(&other_path);
        let c = connector(Arc::new(AtomicU64::new(0)));
        c.declare_need_to(
            OWNER,
            NeedId(0),
            "tcp",
            EGRESS_OPERATOR_INFRASTRUCTURE,
            &declared,
        )
        .expect("declares");
        assert_eq!(open(&c, &other), Err(ConnError::Refused), "another path");
        let named = open(&c, &declared).expect("the declared path opens");
        c.close(OWNER, named).unwrap();
        let unnamed = open(&c, "").expect("no target: the declared path");
        c.close(OWNER, unnamed).unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&other_path);
    });
}

/// No socket listening at the path is refused at the open.
#[test]
fn no_socket_at_the_path_is_refused() {
    worker().block_on(async {
        let (_, target) = socket_path("none");
        let c = connector(Arc::new(AtomicU64::new(0)));
        c.declare_need(OWNER, NeedId(0), "tcp", EGRESS_OPERATOR_INFRASTRUCTURE)
            .expect("declares");
        assert_eq!(open(&c, &target), Err(ConnError::Refused));
    });
}

/// Only `unix:` with one leading `/` is a unix target; the URL spelling `unix:///…` is not, and is
/// refused as before (it names no host).
#[test]
fn only_the_unix_colon_path_form_is_a_unix_target() {
    assert_eq!(socket::unix_path("unix:/run/v.sock"), Some("/run/v.sock"));
    assert_eq!(socket::unix_path("unix:///run/v.sock"), None);
    assert_eq!(socket::unix_path("unix:run/v.sock"), None);
    assert_eq!(socket::unix_path("unix:/"), None);
    assert_eq!(socket::unix_path("127.0.0.1:6379"), None);
    worker().block_on(async {
        let c = connector(Arc::new(AtomicU64::new(0)));
        c.declare_need(OWNER, NeedId(0), "tcp", EGRESS_OPERATOR_INFRASTRUCTURE)
            .expect("declares");
        assert_eq!(open(&c, "unix:///run/v.sock"), Err(ConnError::Refused));
    });
}
