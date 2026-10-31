// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S SCRIPT. The store is driven as the KERNEL drives it: loaded through the one
//! loader, opened by the kernel's own host adapter ([`LoadedStore::open`]: the `open` crossing,
//! then the door's `ready` awaited), and called through the two surfaces the kernel calls — the
//! synchronous [`RecordStore`] bridge (ticket-less crossings) and the typed [`StoreCalls`]
//! (submitted on a ticket and awaited). THE STORE KIND'S ONE SUITE: busbar's own store proofs were
//! ported here and the in-tree copies deleted (the store v3 script over every kind slot of the
//! table, its per-op crossing sequence and replay arm, the both-ways key fold, the scope-kind round
//! trip) and the plugin's own wrong-kind arm. busbar runs it over the build's store, linked and
//! dropped in (`conformance_store_runs_tests`), as every store repo runs it over its own.
//!
//! Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings the store opens over>,
//!   <store>: {        (the section under the kind's config root key, `Kind::Store`)
//!     "node": <this node's id: the high half of the op ids the bridge mints>,
//!     "usage": { "bucket": "<the usage bucket>", "window": <its window start> },
//!     "schema": "<the schema the record ops write under>",
//!     "keys":  { "grouped": "<a key id>", "group": "<its group>", "plain": "<another>",
//!                "absent": "<an id never written>" } } }
//! ```
//!
//! THE PINS (M6/contract): every op is ONE crossing — a replay, a refusal and a conflict
//! included: the `op_id` dedupe (H4) is the store's to answer, so the host crosses to ask — but:
//!
//! * a bridge READ answered under a LEASE is TWO, the read and its lease's `release`
//!   ([`LEASED`]). The SDK leases a found record, a non-empty list and every ledger (a window
//!   never written answers the zero ledger); an absent record and an empty list hold no lease
//!   (one crossing). The request-path reads
//!   (`record_get`, `get_plane_record`, the lists into host buffers) write into the host's
//!   buffers and hold none;
//! * the `open` step is [`LoadedStore::open`]: the `open` crossing, plus one `ready` crossing when
//!   the door states `ready` (the kernel awaits it inside `open`), first invocations both; [`super::ready_step`]
//!   runs right after it, on the opened store's plugin (a door that states `ready` is awaited a
//!   second time there; one that states none, 0);
//! * the facts and the wrong-kind load make no crossing (0).

use std::fmt::{Debug, Display};
use std::sync::{Arc, PoisonError};

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta, PlaneDisposition,
    PlaneRecord, PlaneSelector, RecordStore, ScopeRef, SecretForm, UsageDelta, UsageLedger,
    VirtualKey,
};
use busbar_contract::store_calls::StoreCalls;

use super::{
    answer, crossings_of, dispatcher, facts, load, ready_step, Fold, Leg, Recorder, Subject,
};
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

/// THE TABLE THIS SCRIPT DRIVES: 31 kind slots, every one of them stepped below. A slot added to
/// the store table fails the build here until the script drives it.
const _: () = assert!(busbar_contract::abi::store::KIND_SLOTS == 31);

/// THE HOST'S OP-ID ALLOCATORS, ONE PER FOLD RUNNING. The bridge's mint is a plain `fn() -> OpId`
/// (`OpIdMint`), so a fold's allocator is one of [`FOLDS`] static slots, each with its own node
/// half and counter, held by the fold for as long as it runs ([`LegMint`]). Two folds of one test
/// binary (libtest runs the emitted tests in parallel) never share a counter, so neither re-mints
/// an op id the other already used, and each leg counts from 1 on its node's half, as before.
const FOLDS: usize = 16;

struct MintSlot {
    node: std::sync::atomic::AtomicU64,
    next: std::sync::atomic::AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)] // the array's initializer, never read itself
const FREE_SLOT: MintSlot = MintSlot {
    node: std::sync::atomic::AtomicU64::new(0),
    next: std::sync::atomic::AtomicU64::new(0),
};
static MINT_SLOTS: [MintSlot; FOLDS] = [FREE_SLOT; FOLDS];
/// Which slots a running fold holds.
static MINT_HELD: std::sync::Mutex<[bool; FOLDS]> = std::sync::Mutex::new([false; FOLDS]);
static MINT_FREED: std::sync::Condvar = std::sync::Condvar::new();

/// Slot `N`'s allocator: its node's half, counted from 1.
fn mint_at<const N: usize>() -> OpId {
    use std::sync::atomic::Ordering::Relaxed;
    let slot = &MINT_SLOTS[N];
    OpId::from_parts(slot.node.load(Relaxed), slot.next.fetch_add(1, Relaxed) + 1)
}

macro_rules! mints {
    ($($n:literal)*) => { [$(mint_at::<$n>),*] };
}
const MINTS: [busbar_contract::store_calls::OpIdMint; FOLDS] =
    mints!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);

/// ONE FOLD'S OP-ID ALLOCATOR (`LoadedStore::open`'s mint), held until it drops: keep it alive
/// for as long as the store it minted for.
pub(super) struct LegMint {
    at: usize,
}

impl LegMint {
    /// A free allocator on `node`'s half, counting from 1 (waits for one while all are held).
    pub(super) fn take(node: u64) -> Self {
        use std::sync::atomic::Ordering::Relaxed;
        let mut held = MINT_HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let at = loop {
            if let Some(at) = held.iter().position(|h| !h) {
                break at;
            }
            held = MINT_FREED
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        };
        held[at] = true;
        MINT_SLOTS[at].node.store(node, Relaxed);
        MINT_SLOTS[at].next.store(0, Relaxed);
        Self { at }
    }

    /// The allocator, as the bridge takes it.
    pub(super) fn mint(&self) -> busbar_contract::store_calls::OpIdMint {
        MINTS[self.at]
    }
}

impl Drop for LegMint {
    fn drop(&mut self) {
        MINT_HELD.lock().unwrap_or_else(PoisonError::into_inner)[self.at] = false;
        MINT_FREED.notify_one();
    }
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

/// A credential of `kind` (Q-P4-7: the script writes, and looks up, the ONE kind the shipped store
/// schemas hold, 1.5.5's `PutCredential` "today only" kind; a store whose schema
/// constrains the kind refuses any other). The kind is the plugin's `conformance.json`
/// `store.credential_kind`, never a word this crate spells (`c1-literals`: the loader names no auth
/// style). Its secret is in the contract's at-rest form (`CredentialSecret::secret`, `v1:plain`).
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
        secret: format!("v1:plain:s3cret-{id}"),
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
    usage_bucket: &'a str,
    window: u64,
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
        Self {
            credential_kind: s("credential_kind"),
            node: n("node"),
            usage_bucket: s("usage.bucket"),
            window: n("usage.window"),
            schema: s("schema"),
            grouped: s("keys.grouped"),
            group: s("keys.group"),
            plain: s("keys.plain"),
            absent: s("keys.absent"),
        }
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
    // The instance's crossing gate, held across `open` (which takes the plugin by value; a
    // `Plugin` is `!Clone`, so the gate is held through its instance).
    let held = Arc::clone(&p.inner);
    let mut r = Recorder::new(crossings_of(&held));
    r.line("facts", 0, || {
        format!("{} {:?}", facts(&p), p.context::<StoreFacts>())
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
    // The bridge mints its writes' op ids from this fold's own allocator, on this node's half;
    // held until the fold ends (declared before the store, so it outlives it).
    let minted = LegMint::take(i.node);
    let st = r.step("open", open_pin, || {
        match LoadedStore::open(p, Arc::clone(&d), &settings, minted.mint()) {
            Ok(st) => (format!("Ready {:?}", st.facts()), st),
            Err(e) => panic!("the store does not open: {e}"),
        }
    });
    ready_step(&mut r, s, st.plugin(), &d);
    let b: &dyn RecordStore = &st;

    // ── keys: put_key, get_key, list_keys, delete_key, list_keys_since ──
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
    r.line("keys since 0", LEASED, || keys(b.list_keys_since(0)));

    // ── usage: get_usage, add_usage, put_usage ──
    let (ub, w) = (i.usage_bucket, i.window);
    r.line("usage untouched", LEASED, || ans(b.get_usage(ub, w)));
    r.line("add usage", 1, || ans(b.add_usage(ub, w, &delta(2, 30))));
    r.line("usage", LEASED, || ans(b.get_usage(ub, w)));
    let mut set = UsageLedger::default();
    set.apply_delta(&delta(9, 1));
    r.line("put usage", 1, || ans(b.put_usage("j", w * 2, &set)));
    r.line("usage j", LEASED, || ans(b.get_usage("j", w * 2)));
    r.line("usage again", LEASED, || ans(b.get_usage(ub, w)));

    // ── metering: add_metering, list_metering ──
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
    // No 1.5.5 audit row is written (no slot appends one), so both reads are empty lists, which hold
    // no lease: one crossing each.
    r.line("audit", 1, || ans(b.list_audit()));
    r.line("audit tail 1", 1, || ans(b.list_audit_tail(1)));
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
        ans(b.purge_plane_records("ev", 100, busbar_contract::records::Retention::Age))
    });
    // THE KIND'S RETENTION RULE (coordinator ruling (b)): the rule is the one the purge is handed,
    // never one the store infers from the kind's name. Under `TerminalOnly` an old ACTIVE row is
    // kept and an old TERMINAL one goes; under `Age` every old row goes.
    r.line("append rt1", 1, || {
        ans(b.append_plane_record(plane("rt", "r", Some("p"), 1, b"active").view()))
    });
    r.line("append rt2", 1, || {
        ans(b.append_plane_record(plane("rt", "r", Some("p"), 2, b"terminal").view()))
    });
    r.line("purge rt terminal-only", 1, || {
        ans(b.purge_plane_records("rt", 100, busbar_contract::records::Retention::TerminalOnly))
    });
    r.line("list rt kept", 1, || {
        bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into())))
    });
    r.line("purge rt age", 1, || {
        ans(b.purge_plane_records("rt", 100, busbar_contract::records::Retention::Age))
    });
    r.line("list rt aged", 1, || {
        bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into())))
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
    let rec = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
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
    let scan = || {
        ans(block(&rt, st.record_scan(i.schema, b"a/", 5)).map(|mut v| {
            v.sort_by(|x, y| x.0.cmp(&y.0));
            v.into_iter()
                .map(|(k, v)| (text_of(&k), text_of(v.as_slice())))
                .collect::<Vec<_>>()
        }))
    };
    r.line("record scan", 1, scan);
    // AN EMPTY PUT REMOVES THE ROW (slot 26; ARCHITECT 2026-10-21): the host's strike.
    r.line("record put a/1 empty", 1, || {
        ans(block(&rt, st.record_put(i.schema, b"a/1", &rec(b""))))
    });
    r.line("record get emptied", 1, || {
        ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"a/1")).map(shown))
    });
    r.line("record scan emptied", 1, scan);
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
    // The usage ledger's purge (slot 22 under `RETENTION_USAGE_WINDOWS`): every window started
    // before `2w` goes (the one at `w`), the one at `2w` stays.
    r.line("usage purge", 1, || {
        ans(block(&rt, st.purge_usage_before(w * 2)))
    });
    r.line("usage purged", LEASED, || ans(b.get_usage(ub, w)));
    r.line("usage kept", LEASED, || ans(b.get_usage("j", w * 2)));

    // ── the scope-kind round trip (DECISIONS #11): a plane's kinds are the key's own data, and a
    // dropped-in store must hand the key back byte-identically ──
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
/// op_id is `STORE_OPID_CONFLICT`), tombstones and forks refused, a token redeemed once, the ledger counting each write once, and a key handed
/// back byte-identically whatever scope kinds it carries.
fn contract(fold: &Fold, i: &Inputs<'_>) {
    let at = |label: &str| answer(fold, label);
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
        "add usage",
        "put usage",
        "meter p 3",
        "cred c1",
        "key+cred k2",
        "revoke c1",
        "deny x",
        "upsert t1",
        "append e1",
        "append e2",
        "delete t1",
        "usage batch",
        "metering batch",
        "record put a/1",
        "record put a/1 empty",
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
        "get t1 after",
        "record get absent",
        "record get emptied",
    ] {
        assert_eq!(at(label), "= None", "{label}");
    }
    for label in ["delete absent", "relive plain"] {
        assert!(
            at(label).starts_with("! "),
            "refused: {label}: {}",
            at(label)
        );
    }
    assert!(
        at("cred c9 (live slot)").starts_with("! "),
        "a live slot is not taken twice"
    );
    assert_eq!(at("usage batch replay"), at("usage batch"));
    assert_eq!(at("usage batch conflict"), "! STORE_OPID_CONFLICT");
    for label in ["append rt1", "append rt2"] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("purge rt terminal-only"),
        "= 1",
        "a terminal-only purge drops the old TERMINAL row and only it"
    );
    assert_eq!(
        at("list rt kept"),
        r#"= ["active"]"#,
        "a terminal-only purge keeps an ACTIVE row however old"
    );
    assert_eq!(
        at("purge rt age"),
        "= 1",
        "an age purge drops the old ACTIVE row"
    );
    assert_eq!(
        at("list rt aged"),
        "= []",
        "nothing old survives an age purge"
    );
    assert_eq!(at("redeem"), "= true");
    assert_eq!(at("redeem again"), "= false", "a token is redeemed once");
    assert_eq!(at("record get"), "= Some(\"one\")");
    assert_eq!(
        at("record scan"),
        "= [(\"a/1\", \"one\"), (\"a/2\", \"two\")]"
    );
    assert_eq!(
        at("record scan emptied"),
        "= [(\"a/2\", \"two\")]",
        "an empty put removes the row: the scan never returns it"
    );
    // add_usage 2, then one batch of two cells of 1 applied once (its replay applied nothing).
    assert!(
        tail("usage again").contains("UsageLedger { requests: 2,"),
        "{}",
        at("usage again")
    );
    assert!(
        tail("usage at the end").contains("UsageLedger { requests: 4,"),
        "{}",
        at("usage at the end")
    );
    assert_eq!(at("usage purge"), "= 1", "the one window before the cutoff");
    assert!(
        tail("usage purged").contains("UsageLedger { requests: 0,"),
        "{}",
        at("usage purged")
    );
    assert!(
        tail("usage kept").contains("UsageLedger { requests: 9,"),
        "{}",
        at("usage kept")
    );
    assert_eq!(at("scope-kind get"), "identical=true plane_grants=true");
    assert_eq!(at("scope-kind list"), "identical=true");
}

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_store_runs_tests.rs"]
mod runs_tests;

/// THE STORE KIND'S FORWARD-COMPATIBILITY CASE (`abi::store`, FORWARD COMPATIBILITY): a durable
/// store opened over a schema newer than its build refuses to open.
///
/// A door of another kind has no schema: nothing to prove. An EPHEMERAL store (its Statement's
/// mark) keeps no schema and states no stamp. A durable store must state its stamp
/// (`conformance_suite! { …, newer_schema: stamp }`): the case opens it in a fold's namespace (a
/// first open records this build's schema), stamps the schema newer, and requires the next open to
/// refuse with a text of its own.
///
/// # Panics
/// On a durable store that states no stamp, does not open over its own schema, or opens over a
/// newer one (the test's verdict).
pub fn store_newer_schema(s: &Subject) {
    if s.kind() != busbar_contract::abi::mechanism::KindCode::Store {
        return;
    }
    s.apply_env();
    let d = dispatcher();
    let open = |settings: &[u8]| {
        let p = load::<Store>(s, Leg::Linked, s.bind(&d, ROOT)).expect("the store door loads");
        let minted = LegMint::take(0);
        LoadedStore::open(p, Arc::clone(&d), settings, minted.mint()).map(drop)
    };
    let p = load::<Store>(s, Leg::Linked, s.bind(&d, ROOT)).expect("the store door loads");
    let ephemeral = p.context::<StoreFacts>().is_some_and(|f| f.ephemeral);
    drop(p);
    if ephemeral {
        assert!(
            s.newer_schema.is_none(),
            "an ephemeral store keeps no schema, so it states no `newer_schema` stamp"
        );
        return;
    }
    let stamp = s.newer_schema.unwrap_or_else(|| {
        panic!(
            "a durable store states how its schema is stamped newer than its build \
             (`conformance_suite! {{ …, newer_schema: <fn(&str, &[u8])> }}`): the store kind's \
             forward-compatibility rule (`abi::store`, FORWARD COMPATIBILITY)"
        )
    });
    let settings = s.fold_settings("newer-schema");
    if let Err(e) = open(&settings) {
        panic!("the store does not open over its own schema: {e}");
    }
    stamp(settings.namespace(), &settings);
    match open(&settings) {
        Ok(()) => panic!(
            "the store opened over a schema newer than its build: a durable store refuses one \
             (`abi::store`, FORWARD COMPATIBILITY)"
        ),
        Err(e) => assert!(!e.is_empty(), "the refusal states why"),
    }
}
