// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/journal.rs`.

use super::*;
use crate::plane_host::{recover, with_dispatch_scope, HostState};
use busbar_plugin::hot::host::PlaneHostVtable;
use busbar_plugin::hot::POD_VERSION;
use std::sync::atomic::{AtomicU32, Ordering};

/// A distinct scope per test run so the process-global registry never collides across parallel
/// tests (each test owns a fresh chain).
static NEXT_SCOPE: AtomicU32 = AtomicU32::new(1);
fn fresh_scope() -> u32 {
    NEXT_SCOPE.fetch_add(1, Ordering::SeqCst)
}

fn framing_desc(framing: AbiFraming, digests_scope: u8) -> FramingDesc {
    FramingDesc {
        size: core::mem::size_of::<FramingDesc>() as u32,
        version: POD_VERSION,
        framing,
        digests_scope,
    }
}

fn query(scope: u32) -> JournalQuery {
    JournalQuery {
        size: core::mem::size_of::<JournalQuery>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope,
        _reserved2: 0,
        from_seq: 0,
        limit: 0,
    }
}

fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: live HostState minted by `with_dispatch_scope`.
        let _state: &HostState = unsafe { recover(host) };
        f(host, vt)
    })
}

/// The task's gate: append two records to a scope via the VTABLE, then the REAL `verify_chain`
/// passes on the result and the second record's `prev_hash` byte-exactly links the first.
fn append_two_and_verify(framing: AbiFraming, digests_scope: u8) {
    let scope = fresh_scope();
    let fd = framing_desc(framing, digests_scope);
    with_test_state(|host, vt| {
        let append = vt.journal_append.unwrap();
        let c1 = b"|ts1|first"; // Option A: leading `|` is inert under LengthPrefixed, load-bearing under PipeSeparated
        let c2 = b"|ts2|second";
        let s1 = append(
            host,
            scope,
            c1.as_ptr(),
            c1.len(),
            &fd as *const FramingDesc,
        );
        let s2 = append(
            host,
            scope,
            c2.as_ptr(),
            c2.len(),
            &fd as *const FramingDesc,
        );
        assert_eq!(s1, Seq(1), "genesis record is seq 1");
        assert_eq!(s2, Seq(2), "second record is seq 2");
    });

    // Read the rows back through the real audit chain: verify_chain must pass, and the link must
    // be byte-exact (record 2's prev_hash == record 1's hash, record 1's prev_hash empty).
    let map = lock();
    let st = map.get(&scope).expect("scope has rows");
    assert!(
        crate::audit::verify_chain(&st.rows).is_ok(),
        "the appended chain must verify byte-identically"
    );
    assert_eq!(st.rows.len(), 2);
    assert_eq!(st.rows[0].prev_hash(), "", "genesis prev_hash is empty");
    assert!(!st.rows[0].hash().is_empty());
    assert_eq!(
        st.rows[1].prev_hash(),
        st.rows[0].hash(),
        "record 2 links record 1 byte-exactly"
    );
}

#[test]
fn append_two_verifies_length_prefixed_with_scope() {
    append_two_and_verify(AbiFraming::LengthPrefixed, 1);
}

#[test]
fn append_two_verifies_pipe_separated_with_scope() {
    // The PipeSeparated landmine: the leading `|` in the suffix + the always-first empty/nonempty
    // prev_hash must reproduce the legacy join. verify_chain re-runs the SAME digest, so a missing
    // `|` at the join would surface here as DigestMismatch.
    append_two_and_verify(AbiFraming::PipeSeparated, 1);
}

#[test]
fn append_two_verifies_pipe_separated_no_scope() {
    // admin-style: digests_scope = 0 — scope must NOT enter the digest.
    append_two_and_verify(AbiFraming::PipeSeparated, 0);
}

/// The digest is byte-exact against a hand-built `frame_prelude ⧺ content` recompute — this
/// localizes any failure to the reframe rather than the whole chain walk.
#[test]
fn genesis_digest_matches_hand_built_prelude_join() {
    let scope = fresh_scope();
    let fd = framing_desc(AbiFraming::PipeSeparated, 1);
    with_test_state(|host, vt| {
        let content = b"|ts|kind|state";
        let seq = (vt.journal_append.unwrap())(
            host,
            scope,
            content.as_ptr(),
            content.len(),
            &fd as *const FramingDesc,
        );
        assert_eq!(seq, Seq(1));
    });
    let map = lock();
    let st = map.get(&scope).unwrap();
    let mut expected_input = frame_prelude(Framing::PipeSeparated, "", Some(&scope.to_string()), 1);
    expected_input.extend_from_slice(b"|ts|kind|state");
    let expected = busbar_api::sha256_hex(&expected_input);
    assert_eq!(
        st.rows[0].hash(),
        expected,
        "genesis hash == sha256(prelude ⧺ suffix)"
    );
}

#[test]
fn journal_read_returns_ok_and_writes_bytes() {
    let scope = fresh_scope();
    let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
    let q = query(scope);
    with_test_state(|host, vt| {
        let c = b"payload";
        (vt.journal_append.unwrap())(host, scope, c.as_ptr(), c.len(), &fd as *const FramingDesc);

        let mut out_written: usize = 0;
        let read = vt.journal_read.unwrap();
        // Undersized buffer: Refused, required length reported.
        let mut tiny = [0u8; 1];
        let s = read(
            host,
            &q as *const JournalQuery,
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut out_written as *mut usize,
        );
        assert_eq!(s, StatusClass::Refused);
        assert!(out_written > tiny.len(), "reports the required size");

        let needed = out_written;
        let mut big = vec![0u8; needed];
        let s = read(
            host,
            &q as *const JournalQuery,
            big.as_mut_ptr(),
            big.len(),
            &mut out_written as *mut usize,
        );
        assert_eq!(s, StatusClass::Ok);
        assert_eq!(out_written, needed);
        // First 4 bytes are the row count = 1.
        assert_eq!(u32::from_le_bytes(big[0..4].try_into().unwrap()), 1);
    });
}

// ── THE DURABLE SEAM — register + append_scoped + verify/read/restore over a real store ────────

use crate::audit::journal::NeutralBody;
use busbar_plugin::hot::{JournalStreamDesc, ReframeOut, RestoredHdr, VerifyChainHdr};
use std::sync::Arc;

// Base 10_000 so these unit streams never collide in the process-global registry with the
// production ids (1 = A2A `task_event`, 2 = MCP `call`) a within-core plane test registers, nor
// with the plane test ranges (taskstore 100_000+, calllog 200_000+).
static NEXT_KIND_ID: AtomicU32 = AtomicU32::new(10_000);
fn fresh_kind_id() -> u32 {
    NEXT_KIND_ID.fetch_add(1, Ordering::SeqCst)
}

/// A test PLANE reframe: decode the journal's own neutral `{seq, prev_hash, hash, content}` body
/// back into a record's chain fields (the durable path's decode bridge for CORE-written bodies).
/// This stream digests its scope, so it reports `digests_scope = 1`. Always initializes `out`.
extern "C-unwind" fn neutral_reframe(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    // SAFETY: a live borrowed body range for the call (ABI).
    let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
    let nb: NeutralBody = match serde_json::from_slice(body) {
        Ok(nb) => nb,
        Err(_) => {
            // An undecodable body: fail-closed like the production reframe (reframe_bridge), never
            // panic. Still initialize `out` (the length-report discipline) so the caller can read it.
            let o = ReframeOut {
                size: core::mem::size_of::<ReframeOut>() as u32,
                version: POD_VERSION,
                digests_scope: 1,
                _r: 0,
                seq: 0,
                prev_len: 0,
                hash_len: 0,
                suffix_len: 0,
            };
            // SAFETY: `out` is a live, writable slot (ABI).
            unsafe { (*out).write(o) };
            return StatusClass::Fault;
        }
    };
    let prev = nb.prev_hash.as_bytes();
    let hash = nb.hash.as_bytes();
    let suffix = &nb.content;
    let o = ReframeOut {
        size: core::mem::size_of::<ReframeOut>() as u32,
        version: POD_VERSION,
        digests_scope: 1,
        _r: 0,
        seq: nb.seq,
        prev_len: prev.len(),
        hash_len: hash.len(),
        suffix_len: suffix.len(),
    };
    // SAFETY: `out` is a live, writable slot; always initialized (the length-report discipline).
    unsafe { (*out).write(o) };
    if prev.len() > prev_cap || hash.len() > hash_cap || suffix.len() > suffix_cap {
        return StatusClass::Refused;
    }
    // SAFETY: each destination has cap >= the source length (checked above); ranges are live.
    unsafe {
        std::ptr::copy_nonoverlapping(prev.as_ptr(), prev_buf, prev.len());
        std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, hash.len());
        std::ptr::copy_nonoverlapping(suffix.as_ptr(), suffix_buf, suffix.len());
    }
    StatusClass::Ok
}

/// A generic PERSISTING `Store` double: the shipped `busbar_store_memory` keeps NO plane records
/// (the lossy RAM default), so this delegates the required key/usage/metering surface to a real
/// memory store (so `GovState::new` sees genuine governance behaviour) and PERSISTS the neutral
/// plane-record verbs generically by `(kind, parent)` — exactly what a durable backend does.
struct GenericPlaneStore {
    inner: busbar_store_memory::MemoryStore,
    rows: Mutex<Vec<busbar_api::PlaneRecord>>,
}

impl GenericPlaneStore {
    fn new() -> Self {
        Self {
            inner: busbar_store_memory::MemoryStore::new(),
            rows: Mutex::new(Vec::new()),
        }
    }
    fn rows(&self) -> std::sync::MutexGuard<'_, Vec<busbar_api::PlaneRecord>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl busbar_api::Store for GenericPlaneStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    // ── The neutral kind-tagged verbs — the durable half this double actually keeps ─────────────
    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        self.rows().push(record.clone());
        Ok(())
    }
    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        self.rows().push(record.clone());
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &busbar_api::PlaneSelector,
    ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
        Ok(self
            .rows()
            .iter()
            .filter(|r| r.kind == kind)
            .filter(|r| match selector {
                busbar_api::PlaneSelector::All => true,
                busbar_api::PlaneSelector::Parent(p) => r.parent.as_deref() == Some(p.as_str()),
            })
            .map(|r| r.body.clone())
            .collect())
    }
    fn list_plane_record_parents(&self, kind: &str) -> busbar_api::StoreResult<Vec<String>> {
        let mut parents: Vec<String> = self
            .rows()
            .iter()
            .filter(|r| r.kind == kind)
            .filter_map(|r| r.parent.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }
}

fn durable_app() -> Arc<crate::state::App> {
    durable_app_over(Arc::new(GenericPlaneStore::new()))
}

fn durable_app_over(store: Arc<GenericPlaneStore>) -> Arc<crate::state::App> {
    let gov = Arc::new(
        crate::governance::GovState::new(store, None).expect("governance store constructs"),
    );
    crate::test_support::TestApp::new().governance(gov).build()
}

fn register(host: HostCtx, vt: &PlaneHostVtable, kind_id: u32, framing: AbiFraming) {
    let kind = b"durable_test_event";
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing,
        digests_scope: 1,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    assert_eq!(
        (vt.journal_register.unwrap())(host, &desc as *const JournalStreamDesc, neutral_reframe),
        StatusClass::Ok
    );
}

/// The durable analogue of `append_two_and_verify`: register a store-backed stream, append two
/// records via `journal_append_scoped` (each PERSISTED to the store as a neutral body), then the
/// durable `journal_verify_scoped` reframes them back and the REAL `verify_chain` passes; a
/// `journal_restore` counts both records and one scope; a `journal_read_scoped` yields the rows.
fn durable_append_two_and_verify(framing: AbiFraming) {
    let app = durable_app();
    let kind_id = fresh_kind_id();
    let scope = b"task-1";
    with_dispatch_scope(&app, |host, vt| {
        register(host, vt, kind_id, framing);

        let c1 = b"|ts1|first"; // Option A leading `|` (load-bearing under PipeSeparated)
        let c2 = b"|ts2|second";
        let s1 = (vt.journal_append_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            c1.as_ptr(),
            c1.len(),
        );
        let s2 = (vt.journal_append_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            c2.as_ptr(),
            c2.len(),
        );
        assert_eq!(s1, Seq(1), "genesis record is seq 1");
        assert_eq!(s2, Seq(2), "second record is seq 2");

        // VERIFY: reframes the persisted neutral bodies and runs the real verifier.
        let mut vout = MaybeUninit::<VerifyChainHdr>::uninit();
        assert_eq!(
            (vt.journal_verify_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                &mut vout as *mut MaybeUninit<VerifyChainHdr>,
            ),
            StatusClass::Ok
        );
        // SAFETY: Ok published the slot.
        let vhdr = unsafe { vout.assume_init() };
        assert_eq!(
            vhdr.verified, 1,
            "the persisted durable chain verifies byte-identically"
        );

        // RESTORE: counts both durable records under the one scope, zero breaks.
        let mut rout = MaybeUninit::<RestoredHdr>::uninit();
        assert_eq!(
            (vt.journal_restore.unwrap())(
                host,
                kind_id,
                &mut rout as *mut MaybeUninit<RestoredHdr>,
            ),
            StatusClass::Ok
        );
        // SAFETY: Ok published the slot.
        let rhdr = unsafe { rout.assume_init() };
        assert_eq!(rhdr.records, 2, "both records were durable");
        assert_eq!(rhdr.scopes, 1);
        assert_eq!(rhdr.chain_breaks, 0);

        // READ the window back: the encoded blob's row count is 2.
        let mut written: usize = 0;
        let s = (vt.journal_read_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            0,
            0,
            std::ptr::null_mut(),
            0,
            &mut written as *mut usize,
        );
        assert_eq!(
            s,
            StatusClass::Refused,
            "a zero buffer reports the required size"
        );
        let mut big = vec![0u8; written];
        let s = (vt.journal_read_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            0,
            0,
            big.as_mut_ptr(),
            big.len(),
            &mut written as *mut usize,
        );
        assert_eq!(s, StatusClass::Ok);
        assert_eq!(
            u32::from_le_bytes(big[0..4].try_into().unwrap()),
            2,
            "two rows read back"
        );
    });
}

/// F5: the neutral `journal_restore` must SURFACE the undecodable-row aggregate, not compute it on the
/// host and drop it. `restore_scoped` counts each unreadable body into `Restored.unreadable` and fires
/// the per-row diagnostic, but `RestoredHdr` carried no field for the count, so the aggregate was
/// write-only dead state on the RAM journal. With the count now on the header, a boot summary can log
/// it. This registers a stream, persists ONE good record, injects a raw UNDECODABLE sibling body under
/// the same scope, then asserts `journal_restore` reports `unreadable == 1` (and `records == 1`).
#[test]
fn journal_restore_surfaces_the_unreadable_row_count() {
    use busbar_api::Store as _;
    let store = Arc::new(GenericPlaneStore::new());
    let app = durable_app_over(store.clone());
    let kind_id = fresh_kind_id();
    let scope = b"principal-x";
    with_dispatch_scope(&app, |host, vt| {
        register(host, vt, kind_id, AbiFraming::LengthPrefixed);

        // One GOOD record — persisted to the store as a decodable neutral body.
        let good = b"|ts1|good";
        let s1 = (vt.journal_append_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            good.as_ptr(),
            good.len(),
        );
        assert_eq!(s1, Seq(1), "the good record is genesis");

        // A raw UNDECODABLE body under the SAME (kind, parent) — decodes as neither a neutral body nor
        // a legacy row. The registered kind is `durable_test_event` (see `register`).
        store
            .append_plane_record(&busbar_api::PlaneRecord {
                kind: "durable_test_event".to_string(),
                id: String::from_utf8_lossy(scope).to_string(),
                parent: Some(String::from_utf8_lossy(scope).to_string()),
                seq: 2,
                ts: 0,
                disposition: busbar_api::PlaneDisposition::Active,
                body: b"{ not a neutral body".to_vec(),
            })
            .unwrap();

        let mut rout = MaybeUninit::<RestoredHdr>::uninit();
        assert_eq!(
            (vt.journal_restore.unwrap())(
                host,
                kind_id,
                &mut rout as *mut MaybeUninit<RestoredHdr>,
            ),
            StatusClass::Ok
        );
        // SAFETY: Ok published the slot.
        let rhdr = unsafe { rout.assume_init() };
        assert_eq!(
            rhdr.unreadable, 1,
            "the undecodable sibling must be surfaced on the restore header, not dropped"
        );
        assert_eq!(
            rhdr.records, 1,
            "only the decodable row is a restored record"
        );
        assert_eq!(rhdr.scopes, 1);
    });
}

#[test]
fn durable_append_two_and_verify_length_prefixed() {
    durable_append_two_and_verify(AbiFraming::LengthPrefixed);
}

#[test]
fn durable_append_two_and_verify_pipe_separated() {
    // The PipeSeparated genesis landmine, now through the DURABLE store round-trip.
    durable_append_two_and_verify(AbiFraming::PipeSeparated);
}

/// An unregistered `kind_id` fails closed on every scoped op, never fabricating a sequence.
#[test]
fn durable_unregistered_kind_fails_closed() {
    let app = durable_app();
    let scope = b"nope";
    with_dispatch_scope(&app, |host, vt| {
        let s = (vt.journal_append_scoped.unwrap())(
            host,
            9_999_001,
            scope.as_ptr(),
            scope.len(),
            scope.as_ptr(),
            scope.len(),
        );
        assert_eq!(s, Seq::NONE, "an unregistered stream mints no sequence");
    });
}

// ── THE CHAIN-COMPAT GOLDEN (minor-9) — frozen PRE-CHANGE bodies through the DURABLE seam ──────
//
// The SECOND, independent tripwire beside `audit::boot_verify_golden`. Those same frozen
// `serde_json` bodies a store held before the cleave are fed through the NEW durable seam
// (`journal_register` + `journal_restore` + `journal_verify_scoped`), reframed PLANE-SIDE back into
// records, and the host's ONE verifier RECOMPUTES each digest from the reframed prelude ⧺ suffix.
// If that recompute no longer equals the frozen `hash`, restore reports a chain break and verify
// fails — RED before a single deployed store does. The frozen bytes are DUPLICATED from
// `boot_verify_golden.rs` on purpose: two independent tripwires, so a slip in one is caught by the
// other. DO NOT regenerate these bytes to make a failing test pass.

const G_MCP_1: &[u8] = br#"{"principal":"vk_alice","seq":1,"ts":1700000000,"server":"srv","tool":"srv_tool","outcome":"dispatched","reason":"","tool_digest":"abc123","pin_generation":7,"request_id":"req-1","prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718"}"#;
const G_MCP_2: &[u8] = br#"{"principal":"vk_alice","seq":2,"ts":1700000060,"server":"srv","tool":"srv_other","outcome":"refused","reason":"not_granted","tool_digest":"","pin_generation":7,"request_id":"req-2","prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a"}"#;
// The A2A task-event fixture was RELOCATED with the task subsystem: the A2A plane computes its chain
// plane-side over its own `TaskEventRow` now (no host-side journal stream), and its byte-layout golden
// lives in `busbar_a2a::taskstore`. This neutral seam golden keeps the MCP `call` (LengthPrefixed) and
// admin `audit` (PipeSeparated, no scope) fixtures.
const G_AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
const G_AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

const G_MCP_TAIL: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
const G_AD_TAIL: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

/// The NEUTRAL local shape a frozen `call`-stream body decodes into for this seam test — its fields
/// match the on-disk names one-for-one, so this core test names no plane record type. The reframe
/// below reads its suffix fields; the restore assertion reads only `hash`. The frozen bytes are opaque
/// persisted evidence: all the golden proves of them is that the digest the past build sealed still
/// recomputes from these fields.
#[derive(serde::Deserialize)]
struct FrozenCallBody {
    seq: u64,
    ts: u64,
    server: String,
    tool: String,
    outcome: String,
    reason: String,
    tool_digest: String,
    pin_generation: u64,
    prev_hash: String,
    hash: String,
}

// Mirrors the FFI `JournalReframeFn` buffer-out signature verbatim, so the arg count is fixed by the ABI.
#[allow(clippy::too_many_arguments)]
fn write_reframe(
    out: *mut MaybeUninit<ReframeOut>,
    seq: u64,
    digests_scope: u8,
    prev: &[u8],
    hash: &[u8],
    suffix: &[u8],
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    let o = ReframeOut {
        size: core::mem::size_of::<ReframeOut>() as u32,
        version: POD_VERSION,
        digests_scope,
        _r: 0,
        seq,
        prev_len: prev.len(),
        hash_len: hash.len(),
        suffix_len: suffix.len(),
    };
    // SAFETY: `out` is a live writable slot; always initialized (the length-report discipline).
    unsafe { (*out).write(o) };
    if prev.len() > prev_cap || hash.len() > hash_cap || suffix.len() > suffix_cap {
        return StatusClass::Refused;
    }
    // SAFETY: each destination cap >= source length (checked above); ranges are live for the call.
    unsafe {
        std::ptr::copy_nonoverlapping(prev.as_ptr(), prev_buf, prev.len());
        std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, hash.len());
        std::ptr::copy_nonoverlapping(suffix.as_ptr(), suffix_buf, suffix.len());
    }
    StatusClass::Ok
}

/// A plane's `call`-stream reframe: decode the frozen per-call body and emit the LengthPrefixed suffix
/// (every field self-delimits: `u64` big-endian length + bytes; a num is its 8-byte big-endian
/// form). `frame_prelude(prev_hash, principal, seq) ⧺ suffix` == the record's sealed digest fields.
extern "C-unwind" fn mcp_reframe(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    // SAFETY: live borrowed body range (ABI).
    let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
    let r: FrozenCallBody = serde_json::from_slice(body).expect("frozen call body decodes");
    let mut suffix = Vec::new();
    let lp = |buf: &mut Vec<u8>, b: &[u8]| {
        buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
        buf.extend_from_slice(b);
    };
    lp(&mut suffix, &r.ts.to_be_bytes());
    lp(&mut suffix, r.server.as_bytes());
    lp(&mut suffix, r.tool.as_bytes());
    lp(&mut suffix, r.outcome.as_bytes());
    lp(&mut suffix, r.reason.as_bytes());
    lp(&mut suffix, r.tool_digest.as_bytes());
    lp(&mut suffix, &r.pin_generation.to_be_bytes());
    write_reframe(
        out,
        r.seq,
        1,
        r.prev_hash.as_bytes(),
        r.hash.as_bytes(),
        &suffix,
        prev_buf,
        prev_cap,
        hash_buf,
        hash_cap,
        suffix_buf,
        suffix_cap,
    )
}

/// Admin plane reframe: decode the legacy `AuditEntry` and emit the PipeSeparated suffix, scope
/// NOT in the digest (`digests_scope = 0`). `frame_prelude(prev_hash, <no scope>, seq) ⧺ suffix`
/// == `AuditEntry::digest_fields`.
extern "C-unwind" fn admin_reframe(
    _host: HostCtx,
    _kind_id: u32,
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
) -> StatusClass {
    // SAFETY: live borrowed body range (ABI).
    let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
    let r: crate::admin::audit::AuditEntry =
        serde_json::from_slice(body).expect("AuditEntry decodes");
    let suffix = format!("|{}|{}|{}|{}", r.ts, r.action, r.resource, r.outcome);
    // The last field is `principal`; append it (kept off the format! line only for readability).
    let suffix = format!("{suffix}|{}", r.principal);
    write_reframe(
        out,
        r.seq,
        0,
        r.prev_hash.as_bytes(),
        r.hash.as_bytes(),
        suffix.as_bytes(),
        prev_buf,
        prev_cap,
        hash_buf,
        hash_cap,
        suffix_buf,
        suffix_cap,
    )
}

fn put_frozen(store: &GenericPlaneStore, kind: &str, parent: &str, seq: u64, body: &[u8]) {
    use busbar_api::{PlaneDisposition, PlaneRecord, Store};
    store
        .append_plane_record(&PlaneRecord {
            kind: kind.to_string(),
            id: parent.to_string(),
            parent: Some(parent.to_string()),
            seq,
            ts: 0,
            disposition: PlaneDisposition::Active,
            body: body.to_vec(),
        })
        .expect("frozen body persists");
}

fn register_stream(
    host: HostCtx,
    vt: &PlaneHostVtable,
    kind_id: u32,
    kind: &[u8],
    framing: AbiFraming,
    digests_scope: u8,
    reframe: JournalReframeFn,
) {
    let desc = JournalStreamDesc {
        size: core::mem::size_of::<JournalStreamDesc>() as u32,
        version: POD_VERSION,
        framing,
        digests_scope,
        kind_id,
        _reserved: 0,
        kind_ptr: kind.as_ptr(),
        kind_len: kind.len(),
    };
    assert_eq!(
        (vt.journal_register.unwrap())(host, &desc as *const JournalStreamDesc, reframe),
        StatusClass::Ok
    );
}

fn restore_and_verify(
    host: HostCtx,
    vt: &PlaneHostVtable,
    kind_id: u32,
    scope: &[u8],
    expect_tail: &str,
    tail_hash: &str,
) {
    // RESTORE: both frozen records, one scope, zero breaks (the digest recompute matched).
    let mut rout = MaybeUninit::<RestoredHdr>::uninit();
    assert_eq!(
        (vt.journal_restore.unwrap())(host, kind_id, &mut rout as *mut MaybeUninit<RestoredHdr>),
        StatusClass::Ok
    );
    // SAFETY: Ok published the slot.
    let r = unsafe { rout.assume_init() };
    assert_eq!(
        r.chain_breaks, 0,
        "a frozen chain reported TAMPERED means the durable-seam digest drifted"
    );
    assert_eq!(r.records, 2, "both frozen records restored");
    assert_eq!(r.scopes, 1);

    // VERIFY the scope explicitly.
    let mut vout = MaybeUninit::<VerifyChainHdr>::uninit();
    assert_eq!(
        (vt.journal_verify_scoped.unwrap())(
            host,
            kind_id,
            scope.as_ptr(),
            scope.len(),
            &mut vout as *mut MaybeUninit<VerifyChainHdr>,
        ),
        StatusClass::Ok
    );
    // SAFETY: Ok published the slot.
    let v = unsafe { vout.assume_init() };
    assert_eq!(
        v.verified, 1,
        "the frozen chain verifies through the durable seam"
    );
    assert_eq!(expect_tail, tail_hash, "the frozen tail hash is intact");
}

/// The chain-compat golden: the frozen A2A/MCP/Admin bodies restore + verify through the DURABLE
/// seam byte-identically — all three framings, including the PipeSeparated genesis landmine and the
/// `digests_scope = false` admin shape.
#[test]
fn frozen_chains_boot_verify_through_the_durable_seam() {
    let store = Arc::new(GenericPlaneStore::new());
    put_frozen(&store, "call", "vk_alice", 1, G_MCP_1);
    put_frozen(&store, "call", "vk_alice", 2, G_MCP_2);
    put_frozen(&store, "admin_audit", "log", 1, G_AD_1);
    put_frozen(&store, "admin_audit", "log", 2, G_AD_2);

    let app = durable_app_over(store);
    let mcp_id = fresh_kind_id();
    let admin_id = fresh_kind_id();
    with_dispatch_scope(&app, |host, vt| {
        register_stream(
            host,
            vt,
            mcp_id,
            b"call",
            AbiFraming::LengthPrefixed,
            1,
            mcp_reframe,
        );
        register_stream(
            host,
            vt,
            admin_id,
            b"admin_audit",
            AbiFraming::PipeSeparated,
            0,
            admin_reframe,
        );

        let mcp_tail: FrozenCallBody = serde_json::from_slice(G_MCP_2).unwrap();
        let ad_tail: crate::admin::audit::AuditEntry = serde_json::from_slice(G_AD_2).unwrap();

        restore_and_verify(host, vt, mcp_id, b"vk_alice", &mcp_tail.hash, G_MCP_TAIL);
        restore_and_verify(host, vt, admin_id, b"log", &ad_tail.hash, G_AD_TAIL);
    });
}

#[test]
fn null_pods_fail_closed() {
    let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
    with_test_state(|host, vt| {
        // Null framing → Seq::NONE, not a fabricated sequence.
        let s = (vt.journal_append.unwrap())(host, 999_001, std::ptr::null(), 0, std::ptr::null());
        assert_eq!(s, Seq::NONE);
        let _ = fd;
        // Null query → Refused.
        let mut out_written: usize = 0;
        let s = (vt.journal_read.unwrap())(
            host,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut out_written as *mut usize,
        );
        assert_eq!(s, StatusClass::Refused);
    });
}

/// ALLOC-BOMB CLOSED (F-AVAIL1 / PH1): `unpack_bodies` reads a `u32` count from the packed header and
/// pre-sizes its Vec from it. A hostile/corrupt header can claim up to `u32::MAX` records; pre-sizing
/// from that raw count reserves gigabytes from a few-byte buffer BEFORE any per-record bounds check.
/// The pre-allocation must be BOUNDED against the remaining input length: at least 4 bytes per record,
/// so a `remaining`-byte blob can hold at most `remaining / 4` records, and the count is clamped to it.
#[test]
fn seed_capacity_bounds_preallocation_against_remaining_len() {
    // A hostile count in a tiny buffer is clamped to what the remaining bytes could possibly hold —
    // NOT the raw billions the header claimed (before the fix this pre-allocated from `u32::MAX`).
    assert_eq!(seed_capacity(u32::MAX as usize, 8), 2);
    assert_eq!(seed_capacity(u32::MAX as usize, 3), 0);
    assert_eq!(seed_capacity(u32::MAX as usize, 0), 0);
    // A well-formed count already within budget is preserved EXACTLY — no behaviour change on good
    // input, so a real seed still reserves precisely what it needs.
    assert_eq!(seed_capacity(3, 4096), 3);
    assert_eq!(seed_capacity(0, 4096), 0);
}

/// The full `unpack_bodies` path stays fail-closed on the same hostile header: an oversized count with
/// a truncated body returns `None` (never a partial or a panic), and it does so without pre-allocating
/// from the raw count — the bound above is what makes that safe rather than an allocation bomb.
#[test]
fn unpack_bodies_fails_closed_on_oversized_count() {
    // count = u32::MAX, then only 8 bytes of payload: wildly short of the claimed records.
    let mut packed = (u32::MAX).to_le_bytes().to_vec();
    packed.extend_from_slice(&[0u8; 8]);
    assert_eq!(unpack_bodies(&packed), None);

    // A well-formed blob still round-trips: count = 2, two 3-byte bodies.
    let mut good = 2u32.to_le_bytes().to_vec();
    for body in [b"abc", b"xyz"] {
        good.extend_from_slice(&(body.len() as u32).to_le_bytes());
        good.extend_from_slice(body);
    }
    assert_eq!(
        unpack_bodies(&good),
        Some(vec![b"abc".to_vec(), b"xyz".to_vec()])
    );
}
