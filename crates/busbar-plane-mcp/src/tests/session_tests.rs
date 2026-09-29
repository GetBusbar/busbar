// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn owner(p: &str) -> Owner {
    Owner {
        principal: p.to_string(),
        tenant: "t1".to_string(),
    }
}

fn entropy(n: u64) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[..8].copy_from_slice(&n.to_be_bytes());
    e[8] = 0xa5;
    e
}

fn open(t: &mut SessionTable, n: u64, who: &str, now: u64) -> String {
    t.open(
        entropy(n),
        owner(who),
        Revision::R2025_11_25,
        Carriage::Endpoint,
        now,
    )
    .unwrap()
    .as_str()
    .to_string()
}

fn small(max_sessions: usize, per: usize, total: usize) -> SessionTable {
    SessionTable::new(Bounds {
        max_sessions,
        max_session_bytes: per,
        max_total_bytes: total,
        idle_ms: 1_000,
        max_streams: 2,
    })
}

#[test]
fn an_id_is_128_bits_of_the_callers_entropy_in_hex() {
    let mut t = SessionTable::new(Bounds::default());
    let id = open(&mut t, 7, "alice", 0);
    assert_eq!(id.len(), 32);
    assert!(id
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(&id[..16], "0000000000000007");
}

#[test]
fn zero_entropy_is_refused_and_a_live_id_is_not_minted_twice() {
    let mut t = SessionTable::new(Bounds::default());
    let r = t.open(
        [0; 16],
        owner("a"),
        Revision::R2025_06_18,
        Carriage::Endpoint,
        0,
    );
    assert_eq!(r, Err(OpenRefused::NoEntropy));
    open(&mut t, 1, "a", 0);
    let again = t.open(
        entropy(1),
        owner("b"),
        Revision::R2025_06_18,
        Carriage::Endpoint,
        0,
    );
    assert_eq!(again, Err(OpenRefused::Collision));
}

#[test]
fn red_a_session_is_unknown_to_every_other_principal_and_tenant() {
    let mut t = SessionTable::new(Bounds::default());
    let id = open(&mut t, 1, "alice", 0);
    assert_eq!(
        t.revision(&id, &owner("alice"), 1),
        Some(Revision::R2025_11_25)
    );
    assert_eq!(t.revision(&id, &owner("mallory"), 1), None);
    let other_tenant = Owner {
        principal: "alice".into(),
        tenant: "t2".into(),
    };
    assert_eq!(t.revision(&id, &other_tenant, 1), None);
    assert!(
        !t.close(&id, &owner("mallory"), 1),
        "a foreign DELETE ends nothing"
    );
    assert!(!t.mark_initialized(&id, &owner("mallory"), 1));
    assert_eq!(t.open_stream(&id, &owner("mallory"), 1), None);
    let stream = t.open_stream(&id, &owner("alice"), 1).unwrap();
    assert_eq!(t.push(&id, &owner("mallory"), stream, "x", 1), None);
    t.push(&id, &owner("alice"), stream, "secret", 1).unwrap();
    assert_eq!(
        t.replay(&id, &owner("mallory"), "0-0", 1),
        None,
        "a foreign resume reads nothing"
    );
    assert!(!t.is_initialized(&id, &owner("mallory"), 1));
    // ...and the owner's session survived every one of those.
    assert!(t.close(&id, &owner("alice"), 2));
    assert_eq!(t.revision(&id, &owner("alice"), 3), None);
}

#[test]
fn red_the_session_count_is_bounded_and_evicts_least_recently_used() {
    let mut t = small(3, 1 << 20, 1 << 30);
    let a = open(&mut t, 1, "p", 0);
    let b = open(&mut t, 2, "p", 1);
    let c = open(&mut t, 3, "p", 2);
    // Touch `a`, so `b` is now the least recently used.
    assert!(t.revision(&a, &owner("p"), 3).is_some());
    let d = open(&mut t, 4, "p", 4);
    assert_eq!(t.len(), 3);
    assert!(
        t.revision(&b, &owner("p"), 5).is_none(),
        "b was LRU and is gone"
    );
    for id in [&a, &c, &d] {
        assert!(t.revision(id, &owner("p"), 5).is_some());
    }
    for n in 10..100 {
        open(&mut t, n, "p", 6);
        assert!(t.len() <= 3);
    }
}

#[test]
fn red_a_sessions_buffer_is_bounded_in_bytes_oldest_first() {
    let mut t = small(10, 400, 1 << 30);
    let id = open(&mut t, 1, "p", 0);
    let s = t.open_stream(&id, &owner("p"), 0).unwrap();
    let base = t.total_bytes();
    let mut ids = Vec::new();
    for i in 0..50 {
        ids.push(
            t.push(&id, &owner("p"), s, &format!("{i:0>60}"), 0)
                .unwrap(),
        );
        assert!(
            t.total_bytes() - base <= 400,
            "session buffer over its bound"
        );
    }
    // The newest events survive; the oldest were trimmed and the replay says it is not whole.
    let r = t.replay(&id, &owner("p"), &ids[0], 0).unwrap();
    assert!(!r.complete);
    assert_eq!(r.events.last().unwrap().0, *ids.last().unwrap());
    let tail = t.replay(&id, &owner("p"), &ids[47], 0).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.events.len(), 2);
}

#[test]
fn red_the_whole_table_is_bounded_in_bytes() {
    let total = 4_000;
    let mut t = small(1_000, 1 << 20, total);
    for n in 1..200 {
        let id = open(&mut t, n, "p", n);
        let s = t.open_stream(&id, &owner("p"), n).unwrap();
        t.push(&id, &owner("p"), s, &"x".repeat(300), n).unwrap();
        assert!(t.total_bytes() <= total, "table over its bound at {n}");
    }
    assert!(t.len() < 200, "sessions were evicted to fit");
    // Even one session writing more than the whole table holds stays under it.
    let mut t = small(10, 1 << 20, total);
    let id = open(&mut t, 1, "p", 0);
    let s = t.open_stream(&id, &owner("p"), 0).unwrap();
    for _ in 0..100 {
        t.push(&id, &owner("p"), s, &"y".repeat(500), 0).unwrap();
        assert!(t.total_bytes() <= total);
    }
}

#[test]
fn red_the_byte_account_returns_to_zero() {
    let mut t = small(2, 1_000, 1 << 30);
    for n in 1..20 {
        let id = open(&mut t, n, "p", n);
        let s = t.open_stream(&id, &owner("p"), n).unwrap();
        t.push(&id, &owner("p"), s, "abc", n).unwrap();
        if n % 3 == 0 {
            t.close(&id, &owner("p"), n);
        }
    }
    t.sweep(u64::MAX);
    assert!(t.is_empty());
    assert_eq!(t.total_bytes(), 0, "every byte charged was given back");
}

#[test]
fn an_idle_session_expires() {
    let mut t = small(10, 1_000, 1 << 20);
    let id = open(&mut t, 1, "p", 0);
    assert!(t.revision(&id, &owner("p"), 999).is_some());
    assert!(
        t.revision(&id, &owner("p"), 1_998).is_some(),
        "the lookup refreshed it"
    );
    assert!(t.revision(&id, &owner("p"), 2_998).is_none());
    assert_eq!(t.total_bytes(), 0);
}

#[test]
fn the_stream_count_is_bounded_and_a_cursor_never_crosses_streams() {
    let mut t = small(10, 10_000, 1 << 20);
    let id = open(&mut t, 1, "p", 0);
    let s0 = t.open_stream(&id, &owner("p"), 0).unwrap();
    let s1 = t.open_stream(&id, &owner("p"), 0).unwrap();
    let e0 = t.push(&id, &owner("p"), s0, "zero", 0).unwrap();
    t.push(&id, &owner("p"), s1, "one", 0).unwrap();
    let r = t.replay(&id, &owner("p"), &format!("{s0}-0"), 0).unwrap();
    assert_eq!(r.events, vec![(e0.clone(), "zero".to_string())]);
    // A third stream drops the oldest, and its cursor no longer resumes anything.
    t.open_stream(&id, &owner("p"), 0).unwrap();
    assert!(t.replay(&id, &owner("p"), &e0, 0).is_none());
    assert!(t.replay(&id, &owner("p"), "garbage", 0).is_none());
    assert!(t
        .replay(&id, &owner("mallory"), &format!("{s1}-0"), 0)
        .is_none());
}

#[test]
fn only_a_well_formed_id_prefix_is_ever_logged() {
    assert_eq!(log_prefix("0123456789abcdef0123456789abcdef"), "01234567");
    assert_eq!(log_prefix("short"), "");
    assert_eq!(log_prefix("zz23456789abcdef0123456789abcdef"), "");
}

#[test]
fn red_the_upstream_memory_is_bounded() {
    let mut u = UpstreamTable::new(3, 2_000);
    let r = |s: &str| Remembered {
        revision: Revision::R2025_06_18,
        session: Some(s.to_string()),
        message_address: None,
    };
    u.put("a", r("1"));
    u.put("b", r("2"));
    u.put("c", r("3"));
    assert!(u.get("a").is_some());
    u.put("d", r("4"));
    assert_eq!(u.len(), 3);
    assert!(u.get("b").is_none(), "b was least recently used");
    for n in 0..100 {
        u.put(&format!("k{n}"), r(&"s".repeat(300)));
        assert!(u.len() <= 3 && u.bytes() <= 2_000);
    }
    u.put("huge", r(&"s".repeat(5_000)));
    assert!(
        u.get("huge").is_none(),
        "an entry larger than the table is not held"
    );
    for k in ["k97", "k98", "k99"] {
        u.forget(k);
    }
    assert_eq!(u.bytes(), 0);
}
