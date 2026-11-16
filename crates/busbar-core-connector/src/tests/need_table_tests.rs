// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CONN-SCOPE and C-POOL-STATE's id half.

use super::*;
use crate::need::key::Tls;

fn held(conn: u8) -> Held<u8> {
    Held {
        conn,
        key: NeedKey {
            dest: "db:5432".into(),
            sni: "".into(),
            alpn: "".into(),
            class: 2,
            tls: Tls::None,
            trust: [0; 32],
            cert: [0; 32],
            waived: false,
        },
        pooled: 1,
        alpn: "".into(),
        inband_pending: false,
    }
}

/// A conn id presented under another chain or another instance is a miss, and chain 0 is Invalid
/// for every operation.
#[test]
fn a_conn_is_reachable_only_under_its_own_instance_and_chain() {
    let t = ConnTable::new(8);
    let id = t.insert(1, 10, held(1)).unwrap();
    assert_eq!(
        t.take(1, 11, id).unwrap_err(),
        NeedErr::Invalid,
        "another chain"
    );
    assert_eq!(
        t.take(2, 10, id).unwrap_err(),
        NeedErr::Invalid,
        "another instance"
    );
    assert_eq!(t.take(1, 0, id).unwrap_err(), NeedErr::Invalid, "chain 0");
    let (err, conn) = t.insert(1, 0, held(7)).unwrap_err();
    assert_eq!((err, conn), (NeedErr::Invalid, 7));
    assert_eq!(t.take(1, 10, id).unwrap().conn, 1);
    assert_eq!(
        t.take(1, 10, id).unwrap_err(),
        NeedErr::Invalid,
        "taken once"
    );
}

/// The per-chain cap is Limit, and each chain has its own.
#[test]
fn the_per_chain_cap_is_limit() {
    let t = ConnTable::new(2);
    t.insert(1, 10, held(1)).unwrap();
    t.insert(1, 10, held(2)).unwrap();
    assert_eq!(t.insert(1, 10, held(3)).unwrap_err().0, NeedErr::Limit);
    t.insert(1, 11, held(4)).unwrap();
}

/// Release closes the ended chain's conns and only those, and leaves no row behind.
#[test]
fn release_returns_exactly_the_chains_conns_and_leaves_no_row() {
    let t = ConnTable::new(8);
    t.insert(1, 10, held(1)).unwrap();
    t.insert(1, 10, held(2)).unwrap();
    let other = t.insert(1, 11, held(3)).unwrap();
    assert!(t.release(1, 99).is_empty(), "a chain with no rows");
    let mut got: Vec<u8> = t.release(1, 10).into_iter().map(|h| h.conn).collect();
    got.sort_unstable();
    assert_eq!(got, [1, 2]);
    assert_eq!(t.chains(), 1);
    assert_eq!(t.take(1, 11, other).unwrap().conn, 3);
    assert_eq!(t.chains(), 0);
}

/// A taken conn restores under its own id.
#[test]
fn a_taken_conn_restores_under_its_id() {
    let t = ConnTable::new(8);
    let id = t.insert(1, 10, held(1)).unwrap();
    let h = t.take(1, 10, id).unwrap();
    t.restore(1, 10, id, h).unwrap();
    assert_eq!(t.take(1, 10, id).unwrap().conn, 1);
}

/// Pooled ids start at 1 per instance, never repeat, and restart only after the instance is
/// forgotten.
#[test]
fn pooled_ids_are_per_instance_and_never_repeat() {
    let ids = PooledIds::default();
    assert_eq!(
        [ids.mint(1), ids.mint(1), ids.mint(2), ids.mint(1)],
        [1, 2, 1, 3]
    );
    ids.forget(1);
    assert_eq!(ids.mint(1), 1);
    assert_eq!(ids.mint(2), 2);
}
