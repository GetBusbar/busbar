// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-KEY, C-TLS-KEY's key half and the `verify` bit (TRANSPORT-SECURITY-POLICY 8 test 6).

use std::hash::{BuildHasher, Hasher};

use super::*;

fn key(dest: &str) -> NeedKey {
    NeedKey {
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
                instance: 1,
                tls,
                ..key(dest)
            };
            let stranger = NeedKey {
                instance: 2,
                ..owner.clone()
            };
            pool.put(owner.clone(), pooled(41)).unwrap();
            assert!(pool.take(&stranger).is_none(), "another instance at {dest}");
            assert_eq!(pool.take(&owner).unwrap().id, 41, "owner retains reuse");
        }
    }
}
