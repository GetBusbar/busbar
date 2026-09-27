// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: store`, BOTH WAYS** (DECISIONS #2 rule (1)). The store kind's in-tree fixture
//! registered through the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door
//! (its `cdylib`, signed into `plugins/`) resolves to the byte-identical registry row, and the
//! store each door's `open_store` opens answers one script byte-identically. See
//! [`super::both_ways`].
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to
//! [`PluginRegistry::link`] and never registered — which leaves the linked registry with no row for
//! the name.
//!
//! The store is the store kind's REAL both-ways proof (owner FIXTURES ruling; R-FIX1): the build's
//! default RAM store, whose `cdylib` is its dropped-in door. Below the row test, the FOLD test runs
//! every store operation through the row the composition root links and through the dropped-in
//! `cdylib`, and requires the two folds byte-identical; its RED arm replays the pre-variant wire
//! over the same `cdylib` and is kept in the file as the witness of what the fold catches.

use super::both_ways::{both_doors, statement};
use busbar_contract::records::{RecordStore, ScopeRef, VirtualKey};

/// The script: put a key carrying a pool grant, read it back, list every key — the transcript is
/// what the host was handed, serialized as the engine would persist or serve it.
fn script(store: &dyn RecordStore) -> String {
    let key = VirtualKey {
        id: "vk_both_ways".into(),
        generation_hash: "binding:vk_both_ways:1".into(),
        name: "both-ways".into(),
        allowed_scopes: Some(vec![ScopeRef::pool("fast")]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    let put = store.put_key(&key).map_err(|e| e.to_string());
    let got = store.get_key(&key.id).map_err(|e| e.to_string());
    let listed = store.list_keys().map_err(|e| e.to_string());
    format!(
        "put={put:?}\nget={}\nlist={}",
        serde_json::to_string(&got.ok()).unwrap(),
        serde_json::to_string(&listed.ok()).unwrap()
    )
}

/// THE EXIT TEST: the store fixture linked and dropped in registers the same row and opens a store
/// that answers the same.
#[test]
fn a_linked_and_a_dropped_in_store_register_byte_identical_rows() {
    let manifest = statement(
        "store",
        "store-fixture",
        "the-store",
        busbar_contract::abi::cold::ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        |registry| {
            registry
                .open_store("the-store", "{}")
                .expect("the store opens through its alias")
        },
        |opened| script(opened.as_ref()),
    ) else {
        eprintln!("skip: the store fixture's cdylib is not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("vk_both_ways"),
        "the linked store ran the script: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}

/// THE LINKED DOOR ADMITS WHAT THE DROPPED-IN DOOR ADMITS. A linked row passes the structural gate a
/// signed manifest passes (every check but the artifact's integrity): a name the directory would
/// refuse, a kind the door does not serve and a payload schema this binary cannot speak are each
/// refused, naming the row; a well-formed built-in store row registers, opens through `open_store`
/// and carries its own ephemeral statement.
#[test]
fn the_linked_door_refuses_what_the_structural_gate_refuses() {
    use crate::{LinkedPlugin, PluginRegistry};
    fn ram(_: &str) -> Result<Box<dyn RecordStore>, String> {
        Err("never opened".into())
    }
    let refused = |row: LinkedPlugin| match PluginRegistry::empty().link(vec![row]) {
        Ok(_) => panic!("the linked door admitted a row the structural gate refuses"),
        Err(e) => e,
    };
    let e = refused(LinkedPlugin::store("Not A Name", ram, false));
    assert!(e.contains("is not a valid plugin name"), "{e}");
    let mut wrong_kind = LinkedPlugin::store("a-plane", ram, false);
    wrong_kind.manifest.kind = "plane".into();
    wrong_kind.manifest.abi_version = 1;
    assert!(refused(wrong_kind).contains("is not linked through this door"));
    let mut future = LinkedPlugin::store("a-store", ram, false);
    future.manifest.abi_version = u32::MAX;
    assert!(refused(future).contains("is not supported for kind 'store'"));

    let reg = PluginRegistry::empty()
        .link(vec![LinkedPlugin::store("a-store", ram, true)])
        .expect("a well-formed row registers");
    let row = reg.resolve("a-store").expect("resolves by name");
    assert!(row.ephemeral && reg.loadable().is_empty() && reg.linked().len() == 1);
    let Err(e) = reg.open_store("a-store", "{}") else {
        panic!("open_store must call the row's own constructor");
    };
    assert_eq!(e, "never opened");
}

// ── THE FOLD, BOTH WAYS: every store operation, byte for byte ─────────────────────────────────────
//
// The row-and-script test above proves the two doors register one row and agree on a key. What a
// dropped-in store has actually been caught doing is narrower and quieter than that: answering the
// operations its wire carries and silently accepting-and-keeping-nothing for the ones it does not,
// because every store verb past the first few is DEFAULTED on the trait. So this fold runs EVERY
// store operation — keys, tombstone and scrub, credentials, the usage and metering ledgers and their
// retention, the audit chain and its fork refusal, the denylist, and every plane-record verb with its
// retention, fork refusal, spent-token ledger and live-capability check — through the store the
// composition root LINKS (`linked::STORE`, the row a shipped build registers) and through the SAME
// crate's `cdylib`, DROPPED IN (signed into `plugins/`, scanned, opened over the C ABI), and requires
// the two folds to be byte-identical.

/// One fold line: an operation's name and what the HOST was handed for it, serialized as the engine
/// would persist or serve it — `{"ok":…}` or `{"err":"<the store's own message>"}`.
type Fold = Vec<(&'static str, String)>;

/// `r` as the host sees it. `sorted` renders a list whose ORDER the trait does not promise (a
/// backend may answer a hash-ordered map) as a sorted set, so the fold compares what was stored, not
/// the iteration order of one process's hasher.
fn seen<T: serde::Serialize>(
    r: busbar_contract::records::RecordStoreResult<T>,
    sorted: bool,
) -> String {
    let value = match r {
        Ok(v) => {
            let mut v = serde_json::to_value(v).expect("the host serializes what it was handed");
            if let (true, Some(items)) = (sorted, v.as_array_mut()) {
                items.sort_by_key(|i| i.to_string());
            }
            serde_json::json!({ "ok": unstamped(v) })
        }
        Err(e) => serde_json::json!({ "err": e.to_string() }),
    };
    value.to_string()
}

/// The two columns a store stamps from ITS OWN wall clock (a tombstone's `deleted_at`, a
/// revocation's `revoked_at`) read as "stamped" — present or absent is compared, the second is not:
/// the two arms run a moment apart and a clock tick between them is not a difference between doors.
fn unstamped(mut v: serde_json::Value) -> serde_json::Value {
    match &mut v {
        serde_json::Value::Object(map) => {
            for (k, field) in map.iter_mut() {
                if (k == "deleted_at" || k == "revoked_at") && !field.is_null() {
                    *field = serde_json::Value::String("stamped".into());
                } else {
                    *field = unstamped(field.take());
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                *item = unstamped(item.take());
            }
        }
        _ => {}
    }
    v
}

/// A key, distinguishable per `n` (distinct `created_at`, so `list_keys`' created-at order is total).
fn key(id: &str, n: u64) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: format!("binding:{id}:1"),
        name: format!("fold-{n}"),
        allowed_scopes: Some(vec![ScopeRef::pool("fast")]),
        enabled: true,
        created_at: 1_700_000_000 + n,
        ..Default::default()
    }
}

/// A recoverable credential `id` on `key_id`.
fn credential(id: &str, key_id: &str) -> busbar_contract::records::CredentialSecret {
    use busbar_contract::records::{CredentialMeta, CredentialSecret, SecretForm};
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: key_id.into(),
            kind: "generic".into(),
            slot: 0,
            public_id: format!("PUB{id}"),
            secret_form: SecretForm::Recoverable,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: format!("v1:plain:{id}"),
    }
}

/// One audit record at `seq`, its hash naming `action`.
fn audit(seq: u64, action: &str) -> busbar_contract::records::AuditRecord {
    busbar_contract::records::AuditRecord {
        seq,
        ts: 1_700_000_000 + seq,
        action: action.into(),
        resource: "fold".into(),
        outcome: "applied".into(),
        principal: "fold".into(),
        prev_hash: String::new(),
        hash: format!("{action}@{seq}"),
    }
}

/// One plane record of `kind` — an upserted row (`parent: None`, `seq` 0) or a chain link.
fn record(
    kind: &str,
    id: &str,
    parent: Option<&str>,
    seq: u64,
    ts: u64,
    terminal: bool,
    body: &str,
) -> busbar_contract::records::PlaneRecord {
    use busbar_contract::records::PlaneDisposition;
    busbar_contract::records::PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(Into::into),
        seq,
        ts,
        disposition: if terminal {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: body.as_bytes().to_vec(),
    }
}

/// Where the plane-record verbs start in the fold: every line before this index is a verb the wire
/// carried before the plane-record variants existed.
const PLANE_RECORD_OPS_FROM: &str = "upsert_plane_record";

/// THE FOLD: every store operation, in an order that makes each answer depend on the ones before it.
fn fold(s: &dyn RecordStore) -> Fold {
    use busbar_contract::records::{MeteringDelta, ModelTokensDelta, PlaneSelector, UsageLedger};
    use busbar_contract::records::{UsageDelta, UNIT_INPUT, UNIT_OUTPUT};
    let usage_delta = UsageDelta {
        requests: 2,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "m-fold".into(),
            usage_units: [
                (UNIT_INPUT.to_string(), 6i64),
                (UNIT_OUTPUT.to_string(), 12),
            ]
            .into_iter()
            .collect(),
        }],
    };
    let metering = |model: &str| MeteringDelta {
        key_id: "vk_fold_a".into(),
        bucket: 1_700_000_000,
        model: model.into(),
        provider: "p-fold".into(),
        tokens_input: 3,
        tokens_output: 4,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let chain = |seq, ts, body| record("fold_link", "p1", Some("p1"), seq, ts, false, body);
    vec![
        // keys, the tombstone and the scrub
        ("put_key a", seen(s.put_key(&key("vk_fold_a", 1)), false)),
        ("put_key b", seen(s.put_key(&key("vk_fold_b", 2)), false)),
        ("get_key a", seen(s.get_key("vk_fold_a"), false)),
        ("get_key absent", seen(s.get_key("vk_fold_none"), false)),
        ("list_keys", seen(s.list_keys(), false)),
        ("delete_key b", seen(s.delete_key("vk_fold_b"), false)),
        (
            "put_key b over its tombstone",
            seen(s.put_key(&key("vk_fold_b", 2)), false),
        ),
        ("scrub_key b", seen(s.scrub_key("vk_fold_b"), false)),
        ("scrub_key a (live)", seen(s.scrub_key("vk_fold_a"), false)),
        ("list_keys_since 0", seen(s.list_keys_since(0), true)),
        // credentials
        (
            "put_credential",
            seen(s.put_credential(&credential("cr1", "vk_fold_a")), false),
        ),
        (
            "put_key_with_credential",
            seen(
                s.put_key_with_credential(&key("vk_fold_c", 3), &credential("cr3", "vk_fold_c")),
                false,
            ),
        ),
        (
            "list_credentials a",
            seen(s.list_credentials("vk_fold_a"), true),
        ),
        (
            "lookup_credential_secret",
            seen(s.lookup_credential_secret("generic", "PUBcr1"), false),
        ),
        (
            "revoke_credential",
            seen(s.revoke_credential("cr1", "rotated"), false),
        ),
        (
            "list_credentials_since 0",
            seen(s.list_credentials_since(0), true),
        ),
        // the usage and metering ledgers
        (
            "get_usage empty",
            seen(s.get_usage("b-fold", 1_700_000_000), false),
        ),
        (
            "put_usage",
            seen(
                s.put_usage("b-fold", 1_700_000_000, &UsageLedger::default()),
                false,
            ),
        ),
        (
            "add_usage",
            seen(s.add_usage("b-fold", 1_700_000_000, &usage_delta), false),
        ),
        (
            "get_usage",
            seen(s.get_usage("b-fold", 1_700_000_000), false),
        ),
        (
            "purge_windows_before",
            seen(s.purge_windows_before(1), false),
        ),
        (
            "add_metering m1",
            seen(s.add_metering(&metering("m1")), false),
        ),
        (
            "add_metering m1 again",
            seen(s.add_metering(&metering("m1")), false),
        ),
        (
            "add_metering m2",
            seen(s.add_metering(&metering("m2")), false),
        ),
        ("list_metering", seen(s.list_metering(1_700_000_000), true)),
        (
            "purge_metering_before",
            seen(s.purge_metering_before("1"), false),
        ),
        // the audit chain
        (
            "append_audit 1",
            seen(s.append_audit(&audit(1, "create")), false),
        ),
        (
            "append_audit 2",
            seen(s.append_audit(&audit(2, "rotate")), false),
        ),
        (
            "append_audit 1 retried",
            seen(s.append_audit(&audit(1, "create")), false),
        ),
        (
            "append_audit 1 forked",
            seen(s.append_audit(&audit(1, "forged")), false),
        ),
        ("list_audit", seen(s.list_audit(), false)),
        ("list_audit_tail 1", seen(s.list_audit_tail(1), false)),
        // the denylist
        (
            "add_denylist",
            seen(s.add_denylist("sub-fold", "revoked"), false),
        ),
        ("list_denylist", seen(s.list_denylist(), true)),
        // the plane-record verbs
        (
            PLANE_RECORD_OPS_FROM,
            seen(
                s.upsert_plane_record(&record("fold_row", "r1", None, 0, 100, false, "r1-v1")),
                false,
            ),
        ),
        (
            "upsert_plane_record replaces",
            seen(
                s.upsert_plane_record(&record("fold_row", "r1", None, 0, 100, false, "r1-v2")),
                false,
            ),
        ),
        (
            "upsert_plane_record terminal",
            seen(
                s.upsert_plane_record(&record("fold_row", "r2", None, 0, 100, true, "r2")),
                false,
            ),
        ),
        (
            "get_plane_record",
            seen(s.get_plane_record("fold_row", "r1"), false),
        ),
        (
            "get_plane_record absent",
            seen(s.get_plane_record("fold_row", "r9"), false),
        ),
        (
            "append_plane_record 1",
            seen(s.append_plane_record(&chain(1, 100, "l1")), false),
        ),
        (
            "append_plane_record 2",
            seen(s.append_plane_record(&chain(2, 300, "l2")), false),
        ),
        (
            "append_plane_record 1 retried",
            seen(s.append_plane_record(&chain(1, 100, "l1")), false),
        ),
        (
            "append_plane_record 1 forked",
            seen(s.append_plane_record(&chain(1, 100, "lX")), false),
        ),
        (
            "list_plane_records all",
            seen(s.list_plane_records("fold_row", &PlaneSelector::All), true),
        ),
        (
            "list_plane_records parent",
            seen(
                s.list_plane_records("fold_link", &PlaneSelector::Parent("p1".into())),
                false,
            ),
        ),
        (
            "list_plane_record_parents",
            seen(s.list_plane_record_parents("fold_link"), false),
        ),
        (
            "purge_plane_records_before",
            seen(s.purge_plane_records_before("fold_link", 200), false),
        ),
        (
            "list_plane_records after purge",
            seen(
                s.list_plane_records("fold_link", &PlaneSelector::Parent("p1".into())),
                false,
            ),
        ),
        (
            "delete_plane_record",
            seen(s.delete_plane_record("fold_row", "r1"), false),
        ),
        (
            "get_plane_record deleted",
            seen(s.get_plane_record("fold_row", "r1"), false),
        ),
        (
            "redeem_plane_token",
            seen(s.redeem_plane_token("fold_nonce", "n1", 500, 400), false),
        ),
        (
            "redeem_plane_token replayed",
            seen(s.redeem_plane_token("fold_nonce", "n1", 500, 401), false),
        ),
        (
            "upsert_plane_record capability",
            seen(
                s.upsert_plane_record(&record("fold_cap", "t1", None, 0, 100, false, "cap")),
                false,
            ),
        ),
        (
            "plane_token_live",
            seen(s.plane_token_live("fold_cap", "t1", 500, 400), false),
        ),
        (
            "plane_token_live lapsed",
            seen(s.plane_token_live("fold_cap", "t1", 500, 600), false),
        ),
    ]
}

/// The store the composition root LINKS: the store proof's own `linked::STORE` row, registered as a
/// shipped build registers it (`LinkedPlugin::store`), opened through the kind's `open_store`.
fn linked_store() -> Box<dyn RecordStore> {
    let (name, ephemeral, open) = super::both_ways::store_fixture::linked::STORE;
    crate::PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::store(name, open, ephemeral)])
        .expect("the linked row registers")
        .open_store(name, "{}")
        .expect("the linked row opens")
}

/// The SAME crate's `cdylib`, DROPPED IN: signed first-party into `plugins/`, scanned, and opened over
/// the C ABI. `None` when the `cdylib` is not built in this (scoped, non-CI) run.
fn dropped_store() -> Option<Box<dyn RecordStore>> {
    let (crate_snake, _) = super::both_ways::fixture("store");
    let lib = std::fs::read(super::both_ways::cdylib(crate_snake)?).expect("read the cdylib");
    let manifest = statement(
        "store",
        "store-fold",
        "the-fold",
        busbar_contract::abi::cold::ABI_VERSION,
    );
    let registry = super::both_ways::dropped("store-fold", manifest, &lib);
    Some(
        registry
            .open_store("the-fold", "{}")
            .expect("the dropped-in store opens through its alias"),
    )
}

/// **THE EXIT TEST.** The store the composition root links and the same crate dropped in answer every
/// store operation byte-identically.
#[test]
fn a_linked_and_a_dropped_in_store_fold_every_operation_byte_identically() {
    let linked = fold(linked_store().as_ref());
    let Some(dropped) = dropped_store() else {
        eprintln!("skip: the store proof's cdylib is not built");
        return;
    };
    let dropped = fold(dropped.as_ref());
    // Not vacuous: the linked fold holds what was written, and each refusal the store makes.
    let line = |f: &Fold, op: &str| f.iter().find(|(o, _)| *o == op).unwrap().1.clone();
    assert_eq!(
        line(&linked, "get_plane_record"),
        r#"{"ok":[114,49,45,118,50]}"#
    );
    assert!(line(&linked, "append_audit 1 forked").contains("err"));
    assert!(line(&linked, "put_key b over its tombstone").contains("tombstoned"));
    assert!(line(&linked, "redeem_plane_token replayed").contains("false"));
    for ((op, l), (_, d)) in linked.iter().zip(&dropped) {
        assert_eq!(
            l, d,
            "`{op}`: the linked and the dropped-in store must answer alike"
        );
    }
    assert_eq!(linked, dropped);
}

/// The pre-variant wire's `busbar_call`: the real store's `call`, for every verb the wire carried
/// before the plane-record variants existed; `STATUS_UNSUPPORTED` for those variants, exactly as a
/// plugin built against that wire answers a request it cannot decode.
static REAL_CALL: std::sync::OnceLock<busbar_contract::abi::cold::CallFn> =
    std::sync::OnceLock::new();

unsafe extern "C-unwind" fn pre_variant_call(
    handle: *mut std::os::raw::c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let request: serde_json::Value =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("request JSON");
    let variant = match &request {
        serde_json::Value::Object(m) => m.keys().next().cloned().unwrap_or_default(),
        serde_json::Value::String(s) => s.clone(),
        _ => String::new(),
    };
    if variant.contains("PlaneRecord") || variant.contains("PlaneToken") {
        *out = std::ptr::null_mut();
        *out_len = 0;
        return busbar_contract::abi::cold::STATUS_UNSUPPORTED;
    }
    (REAL_CALL.get().expect("set before the first call"))(handle, req, req_len, out, out_len)
}

/// **THE RED ARM — what the old wire did, kept as the witness.**
///
/// Before the plane-record variants, a dropped-in store had no variant for those verbs; `DynStore`
/// inherited the trait's accept-and-keep-nothing defaults for them, while the linked build of the
/// same source answered. Nothing errored — the writes reported `Ok(())` and the reads came back empty.
///
/// This REPLAYS that arrangement over the production seam: the REAL store `cdylib` staged and wired
/// (`stage::load_library_from_bytes` + `wire_up_raw`, its real `busbar_open`), its real `call`
/// answering every verb the old wire carried and `STATUS_UNSUPPORTED` for the rest, behind the
/// loader's real `DynStore`. The fold above, run over it, must DIVERGE from the linked fold exactly
/// where the wire stopped carrying verbs, and nowhere before. If the fold stops seeing the plane
/// records, or starts diverging on verbs the old wire carried, an assertion below fails.
#[test]
fn the_pre_variant_wire_loses_a_dropped_in_stores_plane_records() {
    let linked = fold(linked_store().as_ref());
    let Some(path) = super::both_ways::cdylib(super::both_ways::fixture("store").0) else {
        eprintln!("skip: the store proof's cdylib is not built");
        return;
    };
    let bytes = std::fs::read(&path).expect("read the cdylib");
    let (lib, staged) = crate::stage::load_library_from_bytes(&bytes, "pre-variant")
        .expect("stage the store proof");
    let mut raw = crate::wire_up_raw(
        lib,
        "{}",
        "pre-variant".to_string(),
        busbar_contract::abi::cold::kind::STORE,
        busbar_contract::abi::cold::kind::STORE,
        Some(staged),
    )
    .expect("wire up the real store");
    let _ = REAL_CALL.set(raw.call);
    raw.call = pre_variant_call;
    let old = crate::DynStore::new(raw, busbar_contract::abi::cold::ABI_VERSION);
    let old = fold(&old);

    let from = linked
        .iter()
        .position(|(op, _)| *op == PLANE_RECORD_OPS_FROM)
        .expect("the fold runs the plane-record verbs");
    assert_eq!(
        linked[..from],
        old[..from],
        "every verb the old wire carried answers alike through it"
    );
    let lost: Vec<&str> = linked[from..]
        .iter()
        .zip(&old[from..])
        .filter(|(l, o)| l != o)
        .map(|(l, _)| l.0)
        .collect();
    assert!(
        lost.contains(&"get_plane_record") && lost.contains(&"list_plane_records parent"),
        "the pre-variant wire must lose the plane records the linked store keeps; diverged: {lost:?}"
    );
    assert_ne!(linked, old, "the two builds diverge on the old wire");
}
