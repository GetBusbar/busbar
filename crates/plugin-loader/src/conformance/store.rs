// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S SCRIPT. The store is driven as the KERNEL drives it: loaded through the one
//! loader, opened by the kernel's own host adapter ([`LoadedStore::open`]: the `open` crossing,
//! then the door's `ready` awaited), and called through the two surfaces the kernel calls — the
//! synchronous [`RecordStore`] bridge (ticket-less crossings) and the typed [`StoreCalls`]
//! (submitted on a ticket and awaited). Ported from busbar's own store proofs: the store v3 script
//! (every kind slot of the table, `store_v3_conformance_tests`), its per-op crossing sequence and
//! replay arm (`store_v3_crossing_conformance_tests`), the both-ways key fold
//! (`store_conformance_tests`, `store_door_conformance_tests`) and the scope-kind round trip
//! (`store_scope_kind_conformance_tests`), and the plugin's own wrong-kind arm.
//!
//! Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings the store opens over>,
//!   <store>: {        (the section under the kind's config root key, `Kind::Store`)
//!     "node": <this node's id: the high half of the op ids the bridge mints>,
//!     "caps":  { "bucket": "<the capped bucket>", "window_start": <ms>,
//!                "requests": <its requests cap>, "input": <its `input` class cap> },
//!     "draw":  { "requests": <one reserve's requests>, "input": <its `input`> },
//!     "usage": { "bucket": "<the usage bucket>", "window": <its window start> },
//!     "stream": "<the stream `append_batch` writes>",
//!     "schema": "<the schema the record ops write under>",
//!     "keys":  { "grouped": "<a key id>", "group": "<its group>", "plain": "<another>",
//!                "absent": "<an id never written>" } } }
//! ```
//!
//! A draw must fit its cap once and not twice (the second reserve is the EXHAUSTED one).
//!
//! THE PINS (M6/contract): every op is ONE crossing — a replay, a refusal and a conflict
//! included: the `op_id` dedupe (H4) is the store's to answer, so the host crosses to ask — but:
//!
//! * a bridge READ answered under a LEASE is TWO, the read and its lease's `release`
//!   ([`LEASED`]). The SDK leases a found record, a non-empty list and every ledger (a window
//!   never written answers the zero ledger); an absent record and an empty list hold no lease
//!   (one crossing). The typed `heads` is leased the same way. The request-path reads
//!   (`record_get`, `get_plane_record`, the lists into host buffers) write into the host's
//!   buffers and hold none;
//! * the `open` step is [`LoadedStore::open`]: the `open` crossing, plus one `ready` crossing when
//!   the door states `ready` (the kernel awaits it inside `open`), first invocations both; [`super::ready_step`]
//!   runs right after it, on the opened store's plugin (a door that states `ready` is awaited a
//!   second time there; one that states none, 0);
//! * the facts and the wrong-kind load make no crossing (0).

use std::fmt::{Debug, Display};
use std::sync::Arc;

use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension, Grant};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, ScopeRef, SecretForm, UsageDelta,
    UsageLedger, VirtualKey,
};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use super::{crossings, dispatcher, load, ready_step, Fold, Leg, Recorder, Subject};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::LoadError;
use crate::store_v3::LoadedStore;

/// This kind's section of the plugin's `conformance.json`, and its instance label: the kind's
/// config root key, read off the kind list (`busbar_contract::plugin::Kind::verb`).
const ROOT: &str = match busbar_contract::plugin::Kind::Store.root_key() {
    Some(key) => key,
    None => panic!("the store kind has a config root key"),
};

/// A bridge read answered under a lease: the read, then the `release` of its lease.
const LEASED: u64 = 2;

/// The plane scope kinds the engine registers at boot (busbar's data, not the plugin's: the
/// scope-kind round trip proves a dropped-in store needs none of them registered).
const PLANE_SCOPE_KINDS: &str = include_str!("../../tests/fixtures/plane_scope_kinds.txt");

fn plane_kind(key: &str) -> &'static str {
    PLANE_SCOPE_KINDS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/plane_scope_kinds.txt has no `{key}` row"))
}

/// A result as one answer line: `Ok` by `Debug`, an error by its text.
fn ans<T: Debug, E: Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("= {v:?}"),
        Err(e) => format!("! {e}"),
    }
}

fn text_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn block<T>(rt: &tokio::runtime::Runtime, f: impl std::future::Future<Output = T>) -> T {
    rt.block_on(f)
}

/// The node half of the op ids the bridge mints for the leg running (`node` in the inputs).
static MINT_NODE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// The counter half: reset at each leg's open, so both legs mint the same ids.
static MINT_NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The host's `op_id` allocator for one leg (`LoadedStore::open`'s mint): `node`'s half, counted
/// from 1.
pub(super) fn leg_mint() -> OpId {
    use std::sync::atomic::Ordering::Relaxed;
    OpId::from_parts(MINT_NODE.load(Relaxed), MINT_NEXT.fetch_add(1, Relaxed) + 1)
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

/// A credential of `kind` (Q-P4-7: the script writes, and looks up, the ONE kind the shipped store
/// schemas hold, 1.5.5's, `abi::cold`'s `PutCredential` "today only" kind; a store whose schema
/// constrains the kind refuses any other). The kind is the plugin's `conformance.json`
/// `store.credential_kind`, never a word this crate spells (`c1-literals`: the loader names no auth
/// style).
pub(super) fn secret(kind: &str, id: &str, key_id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: key_id.into(),
            kind: kind.into(),
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

/// The key the scope-kind round trip stores: a pool grant beside two plane grants the plugin's
/// process never registered.
fn scoped_key() -> VirtualKey {
    VirtualKey {
        id: "vk_scopekinds".into(),
        generation_hash: "binding:vk_scopekinds:1".into(),
        name: "scope-kinds".into(),
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: plane_kind("server").into(),
                value: "filesystem".into(),
            },
            ScopeRef {
                kind: plane_kind("tool").into(),
                value: "filesystem_read_file".into(),
            },
        ]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

/// `k` at a dotted `path`.
fn at<'v>(k: &'v serde_json::Value, path: &str) -> &'v serde_json::Value {
    path.split('.').fold(k, |v, p| &v[p])
}

/// The store's inputs, read once.
pub(super) struct Inputs<'a> {
    /// The credential kind the shipped store schemas hold (`store.credential_kind`, Q-P4-7).
    pub(super) credential_kind: &'a str,
    node: u64,
    cap_bucket: &'a str,
    window_start: u64,
    cap_requests: u64,
    cap_input: u64,
    draw_requests: u64,
    draw_input: u64,
    usage_bucket: &'a str,
    window: u64,
    stream: &'a str,
    schema: &'a str,
    grouped: &'a str,
    group: &'a str,
    plain: &'a str,
    absent: &'a str,
}

impl<'a> Inputs<'a> {
    pub(super) fn of(k: &'a serde_json::Value) -> Self {
        assert!(k.is_object(), "conformance.json has no `store` inputs");
        let s = |path: &str| -> &'a str {
            at(k, path)
                .as_str()
                .unwrap_or_else(|| panic!("conformance.json: store.{path} must be a string"))
        };
        let n = |path: &str| {
            at(k, path)
                .as_u64()
                .unwrap_or_else(|| panic!("conformance.json: store.{path} must be a number"))
        };
        let i = Self {
            credential_kind: s("credential_kind"),
            node: n("node"),
            cap_bucket: s("caps.bucket"),
            window_start: n("caps.window_start"),
            cap_requests: n("caps.requests"),
            cap_input: n("caps.input"),
            draw_requests: n("draw.requests"),
            draw_input: n("draw.input"),
            usage_bucket: s("usage.bucket"),
            window: n("usage.window"),
            stream: s("stream"),
            schema: s("schema"),
            grouped: s("keys.grouped"),
            group: s("keys.group"),
            plain: s("keys.plain"),
            absent: s("keys.absent"),
        };
        assert!(
            i.draw_requests <= i.cap_requests
                && i.draw_input <= i.cap_input
                && i.draw_requests * 2 > i.cap_requests,
            "conformance.json: store.draw must fit store.caps once and not twice"
        );
        i
    }
}

/// ONE STORE LEG AT A TIME, per process: [`leg_mint`] is a plain `fn` the bridge calls (it captures
/// nothing), so its node and counter are process statics, reset at each leg's `open`. The suite's
/// tests run in parallel threads (the both-ways arm, the RED count arm, the kind-ABI arm), and a leg
/// opening in one would rewind another's counter mid-leg — the store refuses the replayed op id
/// (`STORE_OPID_CONFLICT`), a failure of the suite, not of the plugin. Held for the whole leg.
static LEG: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let _one_leg = LEG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let i = Inputs::of(s.kind_inputs(ROOT));
    let settings = leg.settings(s);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    let d = dispatcher();
    let p = load::<Store>(s, leg, s.bind(&d, ROOT)).expect("the store door loads");
    // The instance's crossing gate, held across `open` (which takes the plugin by value).
    let held = p.clone();
    let mut r = Recorder::new(crossings(&held));
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={} {:?}",
            p.kind(),
            p.name(),
            p.max_inflight(),
            p.context::<StoreFacts>()
        )
    });
    r.line("refused as another kind", 0, || {
        let refused = load::<Hook>(s, leg, s.bind(&d, "wrong-kind")).err();
        let right = match leg {
            Leg::Linked => matches!(refused, Some(LoadError::WrongKind { .. })),
            Leg::Dropped => matches!(refused, Some(LoadError::ManifestKind { .. })),
        };
        format!("refused={right}")
    });
    // ONE first invocation for `open`, and one for the `ready` the kernel awaits inside it; their
    // resumes are reported (Q-P4-5).
    let open_pin = 1 + u64::from(p.has_ready());
    let st = r.step("open", open_pin, || {
        // The bridge mints its writes' op ids from this leg's allocator, on this node's half.
        MINT_NODE.store(i.node, std::sync::atomic::Ordering::Relaxed);
        MINT_NEXT.store(0, std::sync::atomic::Ordering::Relaxed);
        match LoadedStore::open(p, Arc::clone(&d), &settings, leg_mint) {
            Ok(st) => (format!("Ready {:?}", st.facts()), st),
            Err(e) => panic!("the store does not open: {e}"),
        }
    });
    ready_step(&mut r, s, st.plugin(), &d);
    let b: &dyn RecordStore = &st;

    // ── keys: put_key, get_key, list_keys, delete_key, scrub_key, list_keys_since ──
    let keys = |r: Result<Vec<VirtualKey>, busbar_contract::records::RecordStoreError>| {
        ans(r.map(|mut ks| {
            ks.sort_by(|a, b| a.id.cmp(&b.id));
            ks.into_iter()
                .map(|k| (k.id, k.revision, k.deleted_at.is_some(), k.group))
                .collect::<Vec<_>>()
        }))
    };
    r.line("put grouped", 1, || {
        ans(b.put_key(&key(i.grouped, Some(i.group))))
    });
    r.line("put plain", 1, || ans(b.put_key(&key(i.plain, None))));
    r.line("get grouped", LEASED, || {
        ans(b.get_key(i.grouped).map(|k| k.map(|k| (k.id, k.group))))
    });
    r.line("get absent", 1, || {
        ans(b.get_key(i.absent).map(|k| k.map(|k| k.id)))
    });
    r.line("key list", LEASED, || keys(b.list_keys()));
    r.line("delete plain", 1, || ans(b.delete_key(i.plain)));
    r.line("delete absent", 1, || ans(b.delete_key(i.absent)));
    r.line("relive plain", 1, || ans(b.put_key(&key(i.plain, None))));
    r.line("scrub plain", 1, || ans(b.scrub_key(i.plain)));
    r.line("scrub grouped (live)", 1, || ans(b.scrub_key(i.grouped)));
    r.line("keys since 0", LEASED, || keys(b.list_keys_since(0)));

    // ── usage: get_usage, add_usage, put_usage, purge_windows_before ──
    let (ub, w) = (i.usage_bucket, i.window);
    r.line("usage untouched", LEASED, || ans(b.get_usage(ub, w)));
    r.line("add usage", 1, || ans(b.add_usage(ub, w, &delta(2, 30))));
    r.line("usage", LEASED, || ans(b.get_usage(ub, w)));
    let mut set = UsageLedger::default();
    set.apply_delta(&delta(9, 1));
    r.line("put usage", 1, || ans(b.put_usage("j", w * 2, &set)));
    r.line("usage j", LEASED, || ans(b.get_usage("j", w * 2)));
    // Strictly before every window written: every store answers 0, whatever it purges.
    r.line("purge windows before", 1, || ans(b.purge_windows_before(w)));
    r.line("usage after purge", LEASED, || ans(b.get_usage(ub, w)));

    // ── metering: add_metering, list_metering, purge_metering_before ──
    // Metering names a key the script has PUT (the grouped key, still live): a store whose metering
    // rows reference its keys (a metering -> keys foreign key) holds them.
    r.line("meter p 3", 1, || {
        ans(b.add_metering(&meter(i.grouped, "p", 3)))
    });
    r.line("meter p 4", 1, || {
        ans(b.add_metering(&meter(i.grouped, "p", 4)))
    });
    r.line("meter q 1", 1, || {
        ans(b.add_metering(&meter(i.grouped, "q", 1)))
    });
    r.line("metering", LEASED, || {
        ans(b.list_metering(86_400).map(|mut v| {
            v.sort_by(|x, y| x.provider.cmp(&y.provider));
            v
        }))
    });
    r.line("purge metering", 1, || ans(b.purge_metering_before("a")));

    // ── credentials ──
    r.line("put k1", 1, || ans(b.put_key(&key("k1", None))));
    r.line("cred c1", 1, || {
        ans(b.put_credential(&secret(i.credential_kind, "c1", "k1", "pub1")))
    });
    r.line("cred c9 (live slot)", 1, || {
        ans(b.put_credential(&secret(i.credential_kind, "c9", "k1", "pub9")))
    });
    r.line("key+cred k2", 1, || {
        ans(b.put_key_with_credential(
            &key("k2", None),
            &secret(i.credential_kind, "c2", "k2", "pub2"),
        ))
    });
    r.line("creds k1", LEASED, || {
        ans(b
            .list_credentials("k1")
            .map(|v| v.into_iter().map(|c| c.id).collect::<Vec<_>>()))
    });
    r.line("lookup pub2", LEASED, || {
        ans(b
            .lookup_credential_secret(i.credential_kind, "pub2")
            .map(|c| c.map(|c| (c.meta.id, c.secret))))
    });
    r.line("lookup absent", 1, || {
        ans(b
            .lookup_credential_secret(i.credential_kind, "pub-absent")
            .map(|c| c.map(|c| c.meta.id)))
    });
    r.line("revoke c1", 1, || ans(b.revoke_credential("c1", "rotated")));
    r.line("revoke absent", 1, || ans(b.revoke_credential("zz", "x")));
    r.line("creds since", LEASED, || {
        ans(b.list_credentials_since(0).map(|mut v| {
            v.sort_by(|x, y| x.meta.id.cmp(&y.meta.id));
            v.into_iter()
                .map(|c| (c.meta.id, c.meta.revoked_at.is_some()))
                .collect::<Vec<_>>()
        }))
    });

    // ── audit and denylist ──
    r.line("audit 1", 1, || ans(b.append_audit(&audit(1, "a"))));
    r.line("audit 2", 1, || ans(b.append_audit(&audit(2, "b"))));
    r.line("audit 2 forked", 1, || {
        ans(b.append_audit(&audit(2, "forked")))
    });
    r.line("audit", LEASED, || ans(b.list_audit()));
    r.line("audit tail 1", LEASED, || ans(b.list_audit_tail(1)));
    r.line("deny x", 1, || ans(b.add_denylist("x", "why")));
    r.line("deny", LEASED, || {
        ans(b.list_denylist().map(|mut v| {
            v.sort();
            v
        }))
    });

    // ── plane records through the bridge (`get`/`list` write into host buffers: no lease) ──
    let bodies = |r: busbar_contract::records::RecordStoreResult<Vec<Vec<u8>>>| {
        ans(r.map(|v| {
            let mut v: Vec<String> = v.iter().map(|b| text_of(b)).collect();
            v.sort();
            v
        }))
    };
    r.line("upsert t1", 1, || {
        ans(b.upsert_plane_record(plane("task", "t1", None, 0, b"{}").view()))
    });
    r.line("get t1", 1, || {
        ans(b
            .get_plane_record("task", "t1")
            .map(|v| v.map(|v| text_of(&v))))
    });
    r.line("append e1", 1, || {
        ans(b.append_plane_record(plane("ev", "e", Some("t1"), 1, b"1").view()))
    });
    r.line("append e2", 1, || {
        ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"2").view()))
    });
    r.line("append e2 fork", 1, || {
        ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"x").view()))
    });
    r.line("list ev t1", 1, || {
        bodies(b.list_plane_records("ev", &PlaneSelector::Parent("t1".into())))
    });
    r.line("parents ev", LEASED, || {
        ans(b.list_plane_record_parents("ev").map(|mut v| {
            v.sort();
            v
        }))
    });
    r.line("purge ev", 1, || {
        ans(b.purge_plane_records_before("ev", 100))
    });
    r.line("delete t1", 1, || ans(b.delete_plane_record("task", "t1")));
    r.line("get t1 after", 1, || {
        ans(b
            .get_plane_record("task", "t1")
            .map(|v| v.map(|v| text_of(&v))))
    });
    r.line("token live", 1, || {
        ans(b.plane_token_live("tok", "x", 100, 1))
    });
    r.line(
        "redeem",
        1,
        || ans(b.redeem_plane_token("tok", "x", 100, 1)),
    );
    r.line("redeem again", 1, || {
        ans(b.redeem_plane_token("tok", "x", 100, 1))
    });

    // ── the typed surface: every v3 addition, submitted and awaited ──
    let cell_key = |dimension| CellKey {
        bucket: i.cap_bucket,
        pool: None,
        dimension,
        window_start: i.window_start,
    };
    let caps = [
        Cap {
            key: cell_key(Dimension::Requests),
            cap: i.cap_requests,
            config_gen: 1,
        },
        Cap {
            key: cell_key(Dimension::Class("input")),
            cap: i.cap_input,
            config_gen: 1,
        },
    ];
    let conflict = [Cap {
        key: cell_key(Dimension::Requests),
        cap: i.cap_requests + 1,
        config_gen: 1,
    }];
    let draw = [
        Cell {
            key: cell_key(Dimension::Requests),
            amount: i.draw_requests,
        },
        Cell {
            key: cell_key(Dimension::Class("input")),
            amount: i.draw_input,
        },
    ];
    let uncapped = [Cell {
        key: CellKey {
            bucket: "uncapped",
            pool: None,
            dimension: Dimension::NanoUnits,
            window_start: i.window_start,
        },
        amount: 1,
    }];
    // Grants by what they grant: a slice id and its validity are the store's own.
    let granted = |g: &Result<Vec<Grant>, StoreFailure>| match g {
        Ok(g) => format!("= {:?}", g.iter().map(|x| x.granted).collect::<Vec<_>>()),
        Err(e) => format!("! {e}"),
    };
    r.line("caps", 1, || ans(block(&rt, st.window_caps(op(1), &caps))));
    r.line("caps conflict", 1, || {
        ans(block(&rt, st.window_caps(op(2), &conflict)))
    });
    r.line("caps op reused", 1, || {
        ans(block(&rt, st.window_caps(op(1), &conflict)))
    });
    let g = r.step("reserve", 1, || {
        let g = block(&rt, StoreCalls::reserve(&st, op(3), 0, &draw));
        (granted(&g), g)
    });
    let slices: Vec<u64> = g
        .as_ref()
        .map(|g| g.iter().map(|x| x.slice_id).collect())
        .unwrap_or_default();
    r.line("reserve replay", 1, || {
        let again = block(&rt, StoreCalls::reserve(&st, op(3), 0, &draw));
        let same = again
            .as_ref()
            .ok()
            .map(|a| a.iter().map(|x| x.slice_id).collect::<Vec<_>>());
        format!(
            "{} same_slices={}",
            granted(&again),
            same.as_ref() == Some(&slices)
        )
    });
    r.line("reserve over", 1, || {
        granted(&block(&rt, StoreCalls::reserve(&st, op(4), 0, &draw)))
    });
    r.line("reserve no cap", 1, || {
        granted(&block(&rt, StoreCalls::reserve(&st, op(5), 0, &uncapped)))
    });
    let items: Vec<(u64, u64)> = slices
        .iter()
        .zip([1, 100])
        .map(|(s, unspent)| (*s, unspent))
        .collect();
    r.line("release", 1, || {
        ans(block(&rt, st.slice_release(op(6), 0, &items)))
    });
    r.line("release replay", 1, || {
        ans(block(&rt, st.slice_release(op(6), 0, &items)))
    });
    r.line("release unknown", 1, || {
        ans(block(&rt, st.slice_release(op(7), 0, &[(u64::MAX, 1)])))
    });
    let batch = [(ub, w, delta(1, 5)), (ub, w, delta(1, 5))];
    r.line("usage batch", 1, || {
        ans(block(&rt, st.add_usage_batch(op(8), &batch)))
    });
    r.line("usage batch replay", 1, || {
        ans(block(&rt, st.add_usage_batch(op(8), &batch)))
    });
    r.line("usage batch conflict", 1, || {
        ans(block(&rt, st.add_usage_batch(op(8), &batch[..1])))
    });
    r.line("metering batch", 1, || {
        ans(block(
            &rt,
            st.add_metering_batch(op(9), &[meter(i.grouped, "p", 1)]),
        ))
    });
    r.line("audit batch fork", 1, || {
        ans(block(
            &rt,
            st.append_audit_batch(op(10), &[audit(3, "c"), audit(1, "forked")]),
        ))
    });
    r.line("audit batch", 1, || {
        ans(block(&rt, st.append_audit_batch(op(11), &[audit(3, "c")])))
    });
    let rec = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
    r.line("append batch", 1, || {
        ans(block(
            &rt,
            st.append_batch(op(12), i.stream, &[rec(b"1"), rec(b"2")]),
        )
        .map(|h| h.seq))
    });
    r.line("heads", LEASED, || {
        ans(block(&rt, StoreCalls::heads(&st)).map(|mut v| {
            v.sort_by(|x, y| x.0.cmp(&y.0));
            v.into_iter().map(|(n, h)| (n, h.seq)).collect::<Vec<_>>()
        }))
    });
    let sessions = || {
        ans(block(&rt, st.sessions_for("alice")).map(|mut v| {
            v.sort();
            v
        }))
    };
    r.line("session put 1", 1, || {
        ans(block(&rt, st.session_put(1, "n1", "alice")))
    });
    r.line("session put 2", 1, || {
        ans(block(&rt, st.session_put(2, "n2", "alice")))
    });
    r.line("sessions", 1, sessions);
    r.line("session remove 1", 1, || {
        ans(block(&rt, st.session_remove(1)))
    });
    r.line("sessions after", 1, sessions);
    let shown = |v: Option<RecordBytes>| v.map(|v| text_of(v.as_slice()));
    r.line("record put a/1", 1, || {
        ans(block(&rt, st.record_put(i.schema, b"a/1", &rec(b"one"))))
    });
    r.line("record put a/2", 1, || {
        ans(block(&rt, st.record_put(i.schema, b"a/2", &rec(b"two"))))
    });
    r.line("record get", 1, || {
        ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"a/1")).map(shown))
    });
    r.line("record get absent", 1, || {
        ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"zz")).map(shown))
    });
    r.line("record scan", 1, || {
        ans(block(&rt, st.record_scan(i.schema, b"a/", 5)).map(|mut v| {
            v.sort_by(|x, y| x.0.cmp(&y.0));
            v.into_iter()
                .map(|(k, v)| (text_of(&k), text_of(v.as_slice())))
                .collect::<Vec<_>>()
        }))
    });
    r.line("typed upsert", 1, || {
        ans(block(
            &rt,
            StoreCalls::upsert_plane_record(&st, plane("task", "t2", None, 0, b"b").view()),
        ))
    });
    r.line("typed get", 1, || {
        ans(block(&rt, StoreCalls::get_plane_record(&st, "task", "t2"))
            .map(|v| v.map(|v| text_of(&v))))
    });
    r.line("typed append", 1, || {
        ans(block(
            &rt,
            StoreCalls::append_plane_record(
                &st,
                op(13),
                plane("ev", "f", Some("t2"), 1, b"1").view(),
            ),
        ))
    });
    r.line("typed list", 1, || {
        bodies(
            block(
                &rt,
                StoreCalls::list_plane_records(&st, "ev", &PlaneSelector::Parent("t2".into())),
            )
            .map_err(|e| busbar_contract::records::RecordStoreError(e.to_string())),
        )
    });
    r.line("typed delete", 1, || {
        ans(block(
            &rt,
            StoreCalls::delete_plane_record(&st, "task", "t2"),
        ))
    });
    r.line("typed redeem", 1, || {
        ans(block(
            &rt,
            StoreCalls::redeem_plane_token(&st, "tok", "y", 100, 1),
        ))
    });
    r.line("typed live", 1, || {
        ans(block(
            &rt,
            StoreCalls::plane_token_live(&st, "tok", "y", 100, 1),
        ))
    });
    r.line("usage at the end", LEASED, || ans(b.get_usage(ub, w)));

    // ── the scope-kind round trip (DECISIONS #11): the engine registers the plane kinds in ITS
    // process; a dropped-in store never does, and must hand the key back byte-identically ──
    busbar_contract::records::register_scope_kind(plane_kind("server"));
    busbar_contract::records::register_scope_kind(plane_kind("tool"));
    let sk = scoped_key();
    r.line("scope-kind put", 1, || ans(b.put_key(&sk)));
    let back = r.step("scope-kind get", LEASED, || match b.get_key(&sk.id) {
        Ok(Some(k)) => {
            let want = VirtualKey {
                revision: k.revision,
                ..scoped_key()
            };
            let same = serde_json::to_vec(&k).ok() == serde_json::to_vec(&want).ok();
            let line = format!(
                "identical={same} plane_grants={}",
                k.scope_allowed(plane_kind("tool"), "filesystem_read_file")
                    && k.scope_allowed(plane_kind("server"), "filesystem")
                    && !k.scope_allowed("pool", "filesystem_read_file")
            );
            (line, Some(k))
        }
        other => (ans(other.map(|k| k.map(|k| k.id))), None),
    });
    r.line("scope-kind list", LEASED, || match b.list_keys() {
        Ok(ks) => {
            let listed = ks.iter().find(|k| k.id == sk.id);
            format!(
                "identical={}",
                listed.is_some()
                    && listed.and_then(|k| serde_json::to_vec(k).ok())
                        == back.as_ref().and_then(|k| serde_json::to_vec(k).ok())
            )
        }
        Err(e) => format!("! {e}"),
    });

    let fold = r.fold();
    contract(&fold, &i);
    fold
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: the op_id
/// dedupe (H4: a replay answers the original and applies nothing, a different body under a used
/// op_id is `STORE_OPID_CONFLICT`), whole-or-nothing reserves against pushed caps, tombstones and
/// forks refused, a token redeemed once, the ledger counting each write once, and a key handed
/// back byte-identically whatever scope kinds it carries.
fn contract(fold: &Fold, i: &Inputs<'_>) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    let tail = |label: &str| at(label).split_once(' ').map_or("", |x| x.1);
    for s in fold {
        assert!(!s.answer.contains("faulted"), "{}: {}", s.label, s.answer);
    }
    assert!(at("open").starts_with("Ready "), "open: {}", at("open"));
    assert_eq!(at("refused as another kind"), "refused=true");
    for label in [
        "put grouped",
        "put plain",
        "delete plain",
        "scrub plain",
        "add usage",
        "put usage",
        "meter p 3",
        "cred c1",
        "key+cred k2",
        "revoke c1",
        "audit 1",
        "audit 2",
        "deny x",
        "upsert t1",
        "append e1",
        "append e2",
        "delete t1",
        "caps",
        "release",
        "usage batch",
        "metering batch",
        "audit batch",
        "session put 1",
        "session remove 1",
        "record put a/1",
        "typed upsert",
        "typed delete",
        "scope-kind put",
    ] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("get grouped"),
        format!("= Some(({:?}, Some({:?})))", i.grouped, i.group),
        "a key put is the key got"
    );
    for label in [
        "get absent",
        "lookup absent",
        "get t1 after",
        "record get absent",
    ] {
        assert_eq!(at(label), "= None", "{label}");
    }
    for label in [
        "delete absent",
        "relive plain",
        "audit 2 forked",
        "audit batch fork",
    ] {
        assert!(
            at(label).starts_with("! "),
            "refused: {label}: {}",
            at(label)
        );
    }
    assert!(
        at("scrub grouped (live)").starts_with("! "),
        "a live key is not scrubbed"
    );
    assert!(
        at("cred c9 (live slot)").starts_with("! "),
        "a live slot is not taken twice"
    );
    assert!(
        at("lookup pub2").contains("\"c2\""),
        "{}",
        at("lookup pub2")
    );
    assert_eq!(
        at("purge windows before"),
        "= 0",
        "nothing lies before the first window"
    );
    assert!(
        at("caps conflict").contains("STORE_CAP_CONFLICT"),
        "{}",
        at("caps conflict")
    );
    assert_eq!(
        at("caps op reused"),
        "! STORE_OPID_CONFLICT",
        "a used op_id with another body"
    );
    assert_eq!(
        at("reserve"),
        format!("= {:?}", [i.draw_requests, i.draw_input]),
        "a reserve within its caps grants every cell whole"
    );
    assert_eq!(
        at("reserve replay"),
        format!("{} same_slices=true", at("reserve")),
        "a replayed reserve answers the ORIGINAL grants"
    );
    assert!(
        at("reserve over").contains("Exhausted"),
        "{}",
        at("reserve over")
    );
    assert!(
        at("reserve no cap").contains("NoCap"),
        "{}",
        at("reserve no cap")
    );
    assert_eq!(
        at("release replay"),
        at("release"),
        "a replayed release answers the original"
    );
    assert_eq!(at("usage batch replay"), at("usage batch"));
    assert_eq!(at("usage batch conflict"), "! STORE_OPID_CONFLICT");
    assert!(
        at("append batch").starts_with("= "),
        "{}",
        at("append batch")
    );
    assert!(
        at("heads").contains(&format!("({:?}, ", i.stream)),
        "{}",
        at("heads")
    );
    assert_eq!(at("redeem"), "= true");
    assert_eq!(at("redeem again"), "= false", "a token is redeemed once");
    assert_eq!(at("record get"), "= Some(\"one\")");
    assert_eq!(at("sessions after"), "= [(2, \"n2\")]");
    // add_usage 2, then one batch of two cells of 1 applied once (its replay applied nothing).
    assert!(
        tail("usage after purge").contains("UsageLedger { requests: 2,"),
        "{}",
        at("usage after purge")
    );
    assert!(
        tail("usage at the end").contains("UsageLedger { requests: 4,"),
        "{}",
        at("usage at the end")
    );
    assert_eq!(at("scope-kind get"), "identical=true plane_grants=true");
    assert_eq!(at("scope-kind list"), "identical=true");
}
