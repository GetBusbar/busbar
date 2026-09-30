// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE CONFORMANCE SUITE (TODO ABI-b4, store): the build's store, `busbar-store-memory`,
//! reached through the SAME store v3 table two ways, must answer the same script identically:
//!
//! * COMPILED IN: its `door` loaded through [`load_linked`] — the door the shipped build holds;
//! * DROPPED IN: its `cdylib`'s `busbar_plugin_door` loaded through [`load_dropped`].
//!
//! The script drives every kind slot of the table (the 1.5.5 op set through the synchronous
//! bridge, the v3 additions through the awaited `StoreCalls`), plus the lifecycle, and writes one
//! transcript line per answer. The two transcripts must be equal line for line.
//!
//! RED ARM, KEPT: [`the_compiled_in_shortcut_answers_a_replayed_write_differently`] runs the part
//! of the script the pre-table arrangement could answer against the store's Rust type called
//! directly (the compiled-in shortcut this table replaces) and shows the comparator catching the
//! divergence: the shortcut has no `op_id`, so a write replayed after a lost answer applies twice,
//! where both table doors apply it once.

use std::sync::Arc;

use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension};
use busbar_contract::abi::store::{OpId, KIND_SLOTS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, SecretForm, UsageDelta, UsageLedger,
    VirtualKey,
};
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_dropped, load_linked, Bind, DispatchConfig, Dispatcher, ManifestFacts, NoSink,
};
use crate::store_v3::LoadedStore;

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
    }
}

/// The shipped build's store: its compiled-in door.
fn compiled_in() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(crate::both_ways::store_fixture::door, bind(&d))
        .expect("the door loads");
    LoadedStore::open(p, d, b"{}", 1).expect("it opens")
}

/// The same door, dropped in (the `store_memory_door` example `cdylib`). `None` only in a scoped,
/// non-CI run that did not build it (`both_ways::example_cdylib` refuses to skip under CI).
fn dropped_in() -> Option<LoadedStore> {
    let path = crate::both_ways::example_cdylib("store_memory_door")?;
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let facts = ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: KindCode::Store,
        kind_abi: KindCode::Store.abi_version(),
    };
    let p = load_dropped::<Store>(&path, &facts, bind(&d)).expect("the dropped-in door loads");
    Some(LoadedStore::open(p, d, b"{}", 1).expect("it opens"))
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn op(n: u64) -> OpId {
    OpId::from_parts(2, n)
}

fn key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: format!("key {id}"),
        enabled: true,
        group: group.map(str::to_string),
        created_at: 100,
        ..Default::default()
    }
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

fn meter(key_id: &str, provider: &str, input: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.into(),
        bucket: 86_400,
        model: "m".into(),
        provider: provider.into(),
        tokens_input: input,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    }
}

fn audit(seq: u64, action: &str) -> AuditRecord {
    AuditRecord {
        seq,
        ts: seq * 10,
        action: action.into(),
        resource: "r".into(),
        outcome: "ok".into(),
        principal: "p".into(),
        prev_hash: format!("prev{seq}"),
        hash: format!("hash{seq}{action}"),
    }
}

fn secret(id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: "k1".into(),
            kind: "generic".into(),
            slot: 0,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 5,
            updated_at: 5,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: format!("s3cret-{id}"),
    }
}

fn plane(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: &[u8]) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_string),
        seq,
        ts: 7,
        disposition: if seq == 2 {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: body.to_vec(),
    }
}

fn cell_key(bucket: &'static str, dimension: Dimension<'static>) -> CellKey<'static> {
    CellKey {
        bucket,
        pool: None,
        dimension,
        window_start: 60_000,
    }
}

/// A result as one transcript line: `Ok` values by `Debug`, errors by their text.
fn line<T: std::fmt::Debug, E: std::fmt::Display>(what: &str, r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("{what} = {v:?}"),
        Err(e) => format!("{what} ! {e}"),
    }
}

fn keys_line(r: Result<Vec<VirtualKey>, busbar_contract::records::RecordStoreError>) -> String {
    line(
        "key list",
        r.map(|mut ks| {
            ks.sort_by(|a, b| a.id.cmp(&b.id));
            ks.into_iter()
                .map(|k| (k.id, k.revision, k.deleted_at.is_some(), k.group))
                .collect::<Vec<_>>()
        }),
    )
}

fn ledger_line(
    what: &str,
    r: Result<UsageLedger, busbar_contract::records::RecordStoreError>,
) -> String {
    line(what, r)
}

/// THE SCRIPT: every kind slot at least once, the lifecycle through open and release.
fn script(s: &LoadedStore) -> Vec<String> {
    let b: &dyn RecordStore = s;
    let mut t = vec![
        format!("facts {:?}", s.facts()),
        format!("name {}", s.name()),
    ];

    // keys: put_key, get_key, list_keys, delete_key, scrub_key, list_keys_since.
    t.push(line("put a", b.put_key(&key("a", Some("g")))));
    t.push(line("put b", b.put_key(&key("b", None))));
    t.push(line(
        "get a",
        b.get_key("a").map(|k| k.map(|k| (k.id, k.group))),
    ));
    t.push(line("get zz", b.get_key("zz").map(|k| k.map(|k| k.id))));
    t.push(keys_line(b.list_keys()));
    t.push(line("delete b", b.delete_key("b")));
    t.push(line("delete zz", b.delete_key("zz")));
    t.push(line("relive b", b.put_key(&key("b", None))));
    t.push(line("scrub b", b.scrub_key("b")));
    t.push(line("scrub a (live)", b.scrub_key("a")));
    t.push(keys_line(b.list_keys_since(0)));

    // usage: get_usage, put_usage, add_usage, purge_windows_before.
    t.push(ledger_line("usage untouched", b.get_usage("k", 60)));
    t.push(line("add usage", b.add_usage("k", 60, &delta(2, 30))));
    t.push(ledger_line("usage", b.get_usage("k", 60)));
    let mut set = UsageLedger::default();
    set.apply_delta(&delta(9, 1));
    t.push(line("put usage", b.put_usage("j", 120, &set)));
    t.push(ledger_line("usage j", b.get_usage("j", 120)));
    t.push(line("purge windows < 100", b.purge_windows_before(100)));
    t.push(ledger_line("usage k after purge", b.get_usage("k", 60)));

    // metering: add_metering, list_metering, purge_metering_before.
    t.push(line("meter", b.add_metering(&meter("a", "p", 3))));
    t.push(line("meter", b.add_metering(&meter("a", "p", 4))));
    t.push(line("meter", b.add_metering(&meter("a", "q", 1))));
    t.push(line(
        "metering",
        b.list_metering(86_400).map(|mut r| {
            r.sort_by(|x, y| x.provider.cmp(&y.provider));
            r
        }),
    ));
    t.push(line("purge metering a", b.purge_metering_before("a")));

    // credentials: put_credential, put_key_with_credential, list_credentials,
    // lookup_credential_secret, revoke_credential, list_credentials_since.
    t.push(line("put k1", b.put_key(&key("k1", None))));
    t.push(line("cred c1", b.put_credential(&secret("c1", "pub1"))));
    t.push(line(
        "cred c1 again (live slot)",
        b.put_credential(&secret("c9", "pub9")),
    ));
    let mut c2 = secret("c2", "pub2");
    c2.meta.key_id = "k2".into();
    t.push(line(
        "key+cred k2",
        b.put_key_with_credential(&key("k2", None), &c2),
    ));
    t.push(line(
        "creds k1",
        b.list_credentials("k1")
            .map(|v| v.into_iter().map(|c| c.id).collect::<Vec<_>>()),
    ));
    t.push(line(
        "lookup pub2",
        b.lookup_credential_secret("generic", "pub2")
            .map(|c| c.map(|c| (c.meta.id, c.secret))),
    ));
    t.push(line(
        "lookup none",
        b.lookup_credential_secret("generic", "pub-absent")
            .map(|c| c.map(|c| c.meta.id)),
    ));
    t.push(line("revoke c1", b.revoke_credential("c1", "rotated")));
    t.push(line("revoke zz", b.revoke_credential("zz", "x")));
    t.push(line(
        "creds since",
        b.list_credentials_since(0).map(|mut v| {
            v.sort_by(|x, y| x.meta.id.cmp(&y.meta.id));
            v.into_iter()
                .map(|c| (c.meta.id, c.meta.revoked_at.is_some()))
                .collect::<Vec<_>>()
        }),
    ));

    // audit + denylist: append_audit, list_audit, add_denylist, list_denylist, list_audit_tail.
    t.push(line("audit seq one", b.append_audit(&audit(1, "a"))));
    t.push(line("audit seq two", b.append_audit(&audit(2, "b"))));
    t.push(line(
        "audit seq two, forked",
        b.append_audit(&audit(2, "forked")),
    ));
    t.push(line("audit", b.list_audit()));
    t.push(line("audit tail 1", b.list_audit_tail(1)));
    t.push(line("deny x", b.add_denylist("x", "why")));
    t.push(line("deny", b.list_denylist()));

    // plane records (the request-path slots through the bridge).
    t.push(line(
        "upsert t1",
        b.upsert_plane_record(&plane("task", "t1", None, 0, b"{}")),
    ));
    t.push(line("get t1", b.get_plane_record("task", "t1")));
    t.push(line(
        "append e1",
        b.append_plane_record(&plane("ev", "e", Some("t1"), 1, b"1")),
    ));
    t.push(line(
        "append e2",
        b.append_plane_record(&plane("ev", "e", Some("t1"), 2, b"2")),
    ));
    t.push(line(
        "append e2 fork",
        b.append_plane_record(&plane("ev", "e", Some("t1"), 2, b"x")),
    ));
    t.push(line(
        "list ev t1",
        b.list_plane_records("ev", &PlaneSelector::Parent("t1".into())),
    ));
    t.push(line("parents ev", b.list_plane_record_parents("ev")));
    t.push(line(
        "purge ev < 100",
        b.purge_plane_records_before("ev", 100),
    ));
    t.push(line("delete t1", b.delete_plane_record("task", "t1")));
    t.push(line("get t1 after", b.get_plane_record("task", "t1")));
    t.push(line("token live", b.plane_token_live("tok", "x", 100, 1)));
    t.push(line("redeem", b.redeem_plane_token("tok", "x", 100, 1)));
    t.push(line(
        "redeem again",
        b.redeem_plane_token("tok", "x", 100, 1),
    ));

    // the typed surface: every v3 addition, awaited.
    let r = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("record");
    block(async {
        let caps = [
            Cap {
                key: cell_key("g", Dimension::Requests),
                cap: 3,
                config_gen: 1,
            },
            Cap {
                key: cell_key("g", Dimension::Class("input")),
                cap: 10,
                config_gen: 1,
            },
        ];
        t.push(line("caps", s.window_caps(op(1), &caps).await));
        let conflict = [Cap {
            key: cell_key("g", Dimension::Requests),
            cap: 4,
            config_gen: 1,
        }];
        t.push(line("caps conflict", s.window_caps(op(2), &conflict).await));
        t.push(line(
            "caps op reused",
            s.window_caps(op(1), &conflict).await,
        ));
        let draw = [
            Cell {
                key: cell_key("g", Dimension::Requests),
                amount: 2,
            },
            Cell {
                key: cell_key("g", Dimension::Class("input")),
                amount: 9,
            },
        ];
        let g = s.reserve(op(3), 0, &draw).await;
        t.push(line("reserve", g.clone()));
        t.push(line("reserve replay", s.reserve(op(3), 0, &draw).await));
        t.push(line("reserve over", s.reserve(op(4), 0, &draw).await));
        let nocap = [Cell {
            key: cell_key("uncapped", Dimension::NanoUnits),
            amount: 1,
        }];
        t.push(line("reserve no cap", s.reserve(op(5), 0, &nocap).await));
        if let Ok(g) = g {
            let items = [(g[0].slice_id, 1), (g[1].slice_id, 100)];
            t.push(line("release", s.slice_release(op(6), 0, &items).await));
            t.push(line(
                "release replay",
                s.slice_release(op(6), 0, &items).await,
            ));
        }
        t.push(line(
            "release unknown",
            s.slice_release(op(7), 0, &[(999, 1)]).await,
        ));
        let batch = [("k", 60, delta(1, 5)), ("k", 60, delta(1, 5))];
        t.push(line("usage batch", s.add_usage_batch(op(8), &batch).await));
        t.push(line(
            "usage batch replay",
            s.add_usage_batch(op(8), &batch).await,
        ));
        t.push(line(
            "usage batch conflict",
            s.add_usage_batch(op(8), &batch[..1]).await,
        ));
        t.push(line(
            "metering batch",
            s.add_metering_batch(op(9), &[meter("z", "p", 1)]).await,
        ));
        t.push(line(
            "audit batch fork",
            s.append_audit_batch(op(10), &[audit(3, "c"), audit(1, "forked")])
                .await,
        ));
        t.push(line(
            "audit batch",
            s.append_audit_batch(op(11), &[audit(3, "c")]).await,
        ));
        t.push(line(
            "append batch",
            s.append_batch(op(12), "journal", &[r(b"1"), r(b"2")]).await,
        ));
        t.push(line("heads", StoreCalls::heads(s).await));
        t.push(line("session put", s.session_put(1, "n1", "alice").await));
        t.push(line("session put", s.session_put(2, "n2", "alice").await));
        t.push(line("sessions", s.sessions_for("alice").await));
        t.push(line("session remove", s.session_remove(1).await));
        t.push(line("sessions", s.sessions_for("alice").await));
        t.push(line(
            "record put",
            s.record_put("sch", b"a/1", &r(b"one")).await,
        ));
        t.push(line(
            "record put",
            s.record_put("sch", b"a/2", &r(b"two")).await,
        ));
        t.push(line(
            "record get",
            StoreCalls::record_get(s, "sch", b"a/1").await,
        ));
        t.push(line("record scan", s.record_scan("sch", b"a/", 5).await));
        t.push(line(
            "typed upsert",
            StoreCalls::upsert_plane_record(s, &plane("task", "t2", None, 0, b"b")).await,
        ));
        t.push(line(
            "typed get",
            StoreCalls::get_plane_record(s, "task", "t2").await,
        ));
        t.push(line(
            "typed append",
            StoreCalls::append_plane_record(s, op(13), &plane("ev", "e", Some("t2"), 1, b"1"))
                .await,
        ));
        t.push(line(
            "typed list",
            StoreCalls::list_plane_records(s, "ev", &PlaneSelector::Parent("t2".into())).await,
        ));
        t.push(line(
            "typed delete",
            StoreCalls::delete_plane_record(s, "task", "t2").await,
        ));
        t.push(line(
            "typed redeem",
            StoreCalls::redeem_plane_token(s, "tok", "y", 100, 1).await,
        ));
        t.push(line(
            "typed live",
            StoreCalls::plane_token_live(s, "tok", "y", 100, 1).await,
        ));
    });
    t.push(ledger_line("usage k at the end", b.get_usage("k", 60)));
    t
}

/// The first line the two transcripts differ at, or `None` when they are equal.
fn compare(a: &[String], b: &[String]) -> Option<(usize, String, String)> {
    let n = a.len().max(b.len());
    (0..n).find_map(|i| {
        let (x, y) = (a.get(i), b.get(i));
        (x != y).then(|| {
            (
                i,
                x.cloned().unwrap_or_default(),
                y.cloned().unwrap_or_default(),
            )
        })
    })
}

#[test]
fn the_script_drives_every_kind_slot_of_the_table() {
    // One transcript section per slot group; the table has 47 kind slots and the script names
    // them all (by the ops it runs): this pins the count so a new slot fails here until scripted.
    assert_eq!(KIND_SLOTS, 47);
    let t = script(&compiled_in());
    assert!(
        t.last()
            .is_some_and(|l| l.starts_with("usage k at the end")),
        "the script ran to its end: {} lines",
        t.len()
    );
}

#[test]
fn compiled_in_and_dropped_in_answer_the_script_identically() {
    let linked = script(&compiled_in());
    let Some(dropped) = dropped_in() else {
        eprintln!("skip: the store's cdylib is not built in this scoped run");
        return;
    };
    let dropped = script(&dropped);
    if let Some((i, a, b)) = compare(&linked, &dropped) {
        panic!("the two doors diverge at line {i}:\n compiled in: {a}\n dropped in:  {b}");
    }
}

#[test]
fn the_script_answers_what_the_store_is_held_to() {
    let t = script(&compiled_in());
    let has = |p: &str| t.iter().any(|l| l.starts_with(p));
    let find = |p: &str| {
        t.iter()
            .find(|l| l.starts_with(p))
            .cloned()
            .unwrap_or_default()
    };
    assert!(find("delete zz").contains(" ! "), "an unknown delete fails");
    assert!(
        find("relive b").contains(" ! "),
        "a tombstoned key is not resurrected"
    );
    assert!(
        find("audit seq two, forked").contains(" ! "),
        "an audit fork fails"
    );
    assert!(find("caps conflict").contains("STORE_CAP_CONFLICT"));
    assert!(
        find("caps op reused").ends_with("! STORE_OPID_CONFLICT"),
        "a cap push replayed with a different body is the op_id conflict, not a fault"
    );
    assert!(find("reserve over").contains("Exhausted"));
    assert!(find("reserve no cap").contains("NoCap"));
    assert_eq!(
        find("reserve replay")
            .split_once(" = ")
            .map(|x| x.1.to_string()),
        find("reserve =").split_once(" = ").map(|x| x.1.to_string()),
        "a replayed reserve answers the original grants"
    );
    assert!(find("usage batch conflict").contains("STORE_OPID_CONFLICT"));
    assert!(find("audit batch fork").contains(" ! "));
    assert!(find("redeem again").ends_with("= false"));
    assert!(has("usage k at the end"));
    // add usage 2 + batch 2 (its replay applied nothing); the memory store purges no window (the
    // op's default, `Ok(0)`), so window 60's first write stands.
    assert!(find("purge windows < 100").ends_with("= 0"));
    assert!(
        find("usage k at the end").contains("requests: 4"),
        "{}",
        find("usage k at the end")
    );
}

/// THE RED ARM, KEPT. The pre-table arrangement reached the compiled-in store through its Rust
/// type. That shortcut has no `op_id`: a write the caller retried after losing the answer applies
/// twice. Through the table (either door) the retry carries the same `op_id` and applies once. The
/// comparator must see the difference.
#[test]
fn the_compiled_in_shortcut_answers_a_replayed_write_differently() {
    let table = compiled_in();
    let cells = [("k", 60u64, delta(1, 5))];
    block(async {
        table.add_usage_batch(op(1), &cells).await.expect("write");
        table.add_usage_batch(op(1), &cells).await.expect("retry");
    });
    let through_table = vec![format!(
        "{:?}",
        RecordStore::get_usage(&table, "k", 60).expect("read")
    )];

    let shortcut = crate::both_ways::store_fixture::MemoryStore::new();
    shortcut.add_usage("k", 60, &cells[0].2).expect("write");
    shortcut.add_usage("k", 60, &cells[0].2).expect("retry");
    let through_shortcut = vec![format!("{:?}", shortcut.get_usage("k", 60).expect("read"))];

    let diverged = compare(&through_table, &through_shortcut);
    assert!(
        diverged.is_some(),
        "the comparator must catch a door that double-applies a replayed write"
    );
    assert!(through_table[0].contains("requests: 1"));
    assert!(through_shortcut[0].contains("requests: 2"));
}
