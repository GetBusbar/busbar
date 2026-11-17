// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-KEY, C-TLS-KEY's key half and the `verify` bit (TRANSPORT-SECURITY-POLICY 8 test 6).

use std::hash::{BuildHasher, Hasher};

use super::*;

fn key(dest: &str) -> NeedKey {
    NeedKey {
        instance: busbar_contract::conn::InstanceId(1),
        registration: 1,
        lease: busbar_ports::binder::NetworkLease::new(1),
        dest: dest.into(),
        sni: dest.into(),
        alpn: "".into(),
        class: 2,
        tls: Tls::Direct,
        trust: [0; 32],
        cert: [0; 32],
        waived: false,
    }
}

/// A hasher that gives every key one hash: a hit can then rest on `Eq` alone.
#[derive(Clone, Default)]
struct One;
struct OneHasher;
impl BuildHasher for One {
    type Hasher = OneHasher;
    fn build_hasher(&self) -> OneHasher {
        OneHasher
    }
}
impl Hasher for OneHasher {
    fn finish(&self) -> u64 {
        7
    }
    fn write(&mut self, _: &[u8]) {}
}

fn pooled(id: u64) -> Pooled<u32> {
    Pooled {
        id,
        conn: 0,
        alpn: "".into(),
    }
}

/// Two OPENs to one host:port differing only in SNI, ALPN, client cert, trust, class or TLS state
/// never share a conn, even when every key hashes alike.
#[test]
fn keys_differing_in_one_part_never_share_a_conn() {
    let pool = NeedPool::with_hasher(4, One);
    let base = key("db:5432");
    pool.put(base.clone(), pooled(1)).unwrap();
    let variants = [
        NeedKey {
            sni: "other".into(),
            ..base.clone()
        },
        NeedKey {
            alpn: "h2".into(),
            ..base.clone()
        },
        NeedKey {
            cert: [1; 32],
            ..base.clone()
        },
        NeedKey {
            trust: [1; 32],
            ..base.clone()
        },
        NeedKey {
            class: 0,
            ..base.clone()
        },
        NeedKey {
            tls: Tls::Upgraded,
            ..base.clone()
        },
        NeedKey {
            tls: Tls::None,
            ..base.clone()
        },
        NeedKey {
            dest: "db:5433".into(),
            ..base.clone()
        },
    ];
    for v in variants {
        assert!(pool.take(&v).is_none(), "{v:?}");
    }
    assert_eq!(pool.take(&base).map(|p| p.id), Some(1));
    assert!(
        pool.take(&base).is_none(),
        "a conn serves one OPEN at a time"
    );
}

/// A conn dialled under the unverified acceptance never serves an instance without it, and the
/// reverse.
#[test]
fn a_waived_conn_never_serves_a_verified_open() {
    let pool = NeedPool::new(4);
    let verified = key("db:5432");
    let waived = NeedKey {
        waived: true,
        ..verified.clone()
    };
    pool.put(waived.clone(), pooled(9)).unwrap();
    assert!(pool.take(&verified).is_none());
    assert_eq!(pool.take(&waived).map(|p| p.id), Some(9));
    pool.put(verified.clone(), pooled(10)).unwrap();
    assert!(pool.take(&waived).is_none());
}

#[test]
fn final_network_retirement_evicts_idle_and_refuses_late_returns() {
    let pool = NeedPool::new(2);
    let owner = key("db.internal:443");
    pool.put(
        owner.clone(),
        Pooled {
            id: 1,
            conn: 7_u8,
            alpn: "".into(),
        },
    )
    .unwrap();
    let in_flight = owner.clone();
    owner.lease.retire();
    pool.retire(owner.instance);
    assert_eq!(pool.idle(), 0);
    assert!(pool.take(&owner).is_none());
    assert!(pool
        .put(
            in_flight,
            Pooled {
                id: 2,
                conn: 8,
                alpn: "".into()
            }
        )
        .is_err());
    assert_eq!(
        pool.idle(),
        0,
        "no late return recreates a retired pool entry"
    );
}

/// The pooled-conn id travels with the conn, and the per-key cap hands the extra one back.
#[test]
fn the_cap_returns_the_extra_conn_and_ids_ride_along() {
    let pool = NeedPool::new(2);
    let k = key("db:5432");
    pool.put(k.clone(), pooled(1)).unwrap();
    pool.put(k.clone(), pooled(2)).unwrap();
    let back = pool.put(k.clone(), pooled(3)).unwrap_err();
    assert_eq!(back.id, 3);
    assert_eq!(pool.idle(), 2);
    assert_eq!(pool.take(&k).map(|p| p.id), Some(2));
    assert_eq!(pool.take(&k).map(|p| p.id), Some(1));
    assert_eq!(pool.idle(), 0);
}

/// SEC-M5: authenticated sessions belong to an instance, even at identical endpoints.
#[test]
fn pooled_sessions_never_cross_instance_boundaries() {
    for dest in ["db:5432", "unix:/run/database.sock"] {
        for tls in [Tls::None, Tls::Direct, Tls::Upgraded] {
            let pool = NeedPool::with_hasher(4, One);
            let owner = NeedKey {
                instance: busbar_contract::conn::InstanceId(1),
                tls,
                ..key(dest)
            };
            let stranger = NeedKey {
                instance: busbar_contract::conn::InstanceId(2),
                ..owner.clone()
            };
            pool.put(owner.clone(), pooled(41)).unwrap();
            assert!(pool.take(&stranger).is_none(), "another instance at {dest}");
            assert_eq!(pool.take(&owner).unwrap().id, 41, "owner retains reuse");
        }
    }
}

/// C-POOL-KEY round 11, the source check (moved here from busbar-plugin-test `c_pool_key`, whose case index
/// points at this test): the MIN-3 pool key, [`NeedKey`] (the IF's `PoolKey`), holds `dest`, `sni` and `alpn`
/// by value with no `u64` hash field, and the production pool, `HostNeeds::pool`, is `NeedPool` over std's
/// `RandomState`. The pattern below names every field and its type, so a field added to the key stops it
/// compiling; the text scan backs it on the declaration itself. (`pool::PoolKey`, which carries a `u64` by
/// design, is the pre-MIN-3 framer pool and leaves with W3-D-CONNECTOR; no Need is pooled through it.)
#[test]
fn pool_key_has_no_u64_hash_and_production_uses_random_state() {
    let NeedKey {
        instance,
        registration,
        lease,
        dest,
        sni,
        alpn,
        class,
        tls,
        trust,
        cert,
        waived,
    } = key("a.test:443");
    let _: (
        busbar_contract::conn::InstanceId,
        u32,
        busbar_ports::binder::NetworkLease,
        Box<str>,
        Box<str>,
        Box<str>,
        u32,
        Tls,
        [u8; 32],
        [u8; 32],
        bool,
    ) = (
        instance,
        registration,
        lease,
        dest,
        sni,
        alpn,
        class,
        tls,
        trust,
        cert,
        waived,
    );

    let key_rs = include_str!("../need/key.rs");
    let start = key_rs
        .find("pub struct NeedKey {")
        .expect("NeedKey is declared in need/key.rs");
    let body = &key_rs[start..];
    let body = &body[..body.find("\n}").expect("NeedKey's declaration ends")];
    assert!(
        !body.contains("u64"),
        "NeedKey carries no u64 (no precomputed hash):\n{body}"
    );

    assert!(
        key_rs.contains("use std::hash::{BuildHasher, RandomState};"),
        "the pool's RandomState is std's"
    );
    assert!(
        key_rs.contains("pub struct NeedPool<V, S = RandomState> {"),
        "NeedPool defaults to RandomState"
    );
    assert!(
        key_rs.contains("impl<V> NeedPool<V, RandomState> {")
            && key_rs.contains("Self::with_hasher(per_key, RandomState::new())"),
        "NeedPool::new builds over RandomState"
    );
    let need_rs = include_str!("../need.rs");
    assert!(
        need_rs.contains("    pool: NeedPool<I::Conn>,"),
        "HostNeeds' pool takes NeedPool's default hasher, never another"
    );
    assert!(
        need_rs.contains("pool: NeedPool::new(POOL_PER_KEY),"),
        "HostNeeds builds its pool with NeedPool::new"
    );
    assert!(
        !need_rs.contains("NeedPool::with_hasher"),
        "production never pins a hasher of its own"
    );
}
