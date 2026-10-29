// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MEMORY A STORE CALL LENDS LIVES UNTIL ITS CROSSING RETURNS (`BUSBAR-1.6.0.md` THE DESIGN §2:
//! "The memory a call lends a plugin lives until that call completes, abandoned or not, for every
//! kind (a submit that the watchdog can abandon uses the lending submit)").
//!
//! A store door whose `record_get` and `get_plane_record` hold their crossing past the Call-class
//! watchdog budget: the watchdog faults the op and the caller gets its answer (FAULT) while the
//! crossing still runs. The caller then has its own key back and overwrites it. When the crossing
//! is let go it reads the key its `in` names: it must still read the bytes the call lent, never the
//! caller's reused (or freed) memory. Both surfaces: the typed [`StoreCalls`] and the synchronous
//! [`RecordStore`] bridge.

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::Slot;
use busbar_contract::abi::store::{GetPlaneRecordIn, HostBytesOut, OpId, RecordGetIn};
use busbar_contract::records::RecordStore;
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, Budgets, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

/// One wedged slot's gate: (let go, what the crossing read once let go).
struct Gate {
    state: Mutex<(bool, Option<Vec<u8>>)>,
    cv: Condvar,
}

impl Gate {
    const fn new() -> Self {
        Self {
            state: Mutex::new((false, None)),
            cv: Condvar::new(),
        }
    }

    /// The plugin's side: hold until let go, then read `len` bytes at `ptr` and post them.
    fn hold_then_read(&self, ptr: *const u8, len: usize) {
        let mut g = self.state.lock().unwrap();
        while !g.0 {
            g = self.cv.wait(g).unwrap();
        }
        // SAFETY: the bytes the op's `in` names; the host keeps them alive until the crossing
        // returns (the property under test).
        let read = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        g.1 = Some(read);
        self.cv.notify_all();
    }

    /// The test's side: let the crossing go and wait for what it read.
    fn release_and_read(&self) -> Vec<u8> {
        let mut g = self.state.lock().unwrap();
        g.0 = true;
        self.cv.notify_all();
        let (mut g, timeout) = self
            .cv
            .wait_timeout_while(g, Duration::from_secs(10), |s| s.1.is_none())
            .unwrap();
        assert!(!timeout.timed_out(), "the wedged crossing never returned");
        g.1.take().unwrap()
    }
}

static GET_GATE: Gate = Gate::new();
static PLANE_GATE: Gate = Gate::new();

/// `record_get`: holds its crossing until [`GET_GATE`] lets it go, then reads its key.
struct WedgedGet;
impl Slot for WedgedGet {
    type In = RecordGetIn;
    type Out = HostBytesOut;
    fn call(_: *mut c_void, i: &RecordGetIn, _: &mut HostBytesOut) -> Outcome {
        GET_GATE.hold_then_read(i.key.ptr, i.key.len);
        Outcome::Ready
    }
}

/// `get_plane_record`: holds its crossing until [`PLANE_GATE`] lets it go, then reads its id.
struct WedgedPlaneGet;
impl Slot for WedgedPlaneGet {
    type In = GetPlaneRecordIn;
    type Out = HostBytesOut;
    fn call(_: *mut c_void, i: &GetPlaneRecordIn, _: &mut HostBytesOut) -> Outcome {
        PLANE_GATE.hold_then_read(i.id.ptr, i.id.len);
        Outcome::Ready
    }
}

mod wedged {
    use super::{WedgedGet, WedgedPlaneGet};
    use crate::both_ways::store_fixture::MemoryStore as M;
    use busbar_contract::abi::sdk::life as l;
    use busbar_contract::abi::sdk::store::door as d;
    use busbar_contract::abi::sdk::Safe as S;

    const TAIL: busbar_contract::abi::store::StoreTail = d::tail::<M>();
    const DIAGS: [busbar_contract::abi::mechanism::call::AbiStr; 1] = d::DIAG_IDS;

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::store::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            diag_ids: DIAGS.as_ptr(),
            diag_ids_len: 1,
            kind_tail: ::core::ptr::from_ref(&TAIL)
                .cast::<busbar_contract::abi::mechanism::door::KindTailHead>(),
            ..busbar_contract::abi::sdk::door::statement("wedged", "0", 64)
        },
                lifecycle: {
                    validate: S<l::Validate<d::Served<M>>>,
                    open: S<d::Open<M>>,
                    refresh: S<l::Refresh<d::Served<M>>>,
                    retire: S<l::Retire<d::Served<M>>>,
                    tick: S<l::Tick<d::Served<M>>>,
                    drive: S<l::Drive<d::Served<M>>>,
                    cancel: S<l::Cancel<d::Served<M>>>,
                    release: S<l::Release<d::Served<M>>>,
                    close: S<l::Close<d::Served<M>>>,
                },
                kind_ops: {
                    put_key: S<d::PutKey<M>>,
                    get_key: S<d::GetKey<M>>,
                    list_keys: S<d::ListKeys<M>>,
                    delete_key: S<d::DeleteKey<M>>,
                    list_keys_since: S<d::ListKeysSince<M>>,
                    get_usage: S<d::GetUsage<M>>,
                    put_usage: S<d::PutUsage<M>>,
                    list_metering: S<d::ListMetering<M>>,
                    put_credential: S<d::PutCredential<M>>,
                    put_key_with_credential: S<d::PutKeyWithCredential<M>>,
                    list_credentials: S<d::ListCredentials<M>>,
                    revoke_credential: S<d::RevokeCredential<M>>,
                    list_credentials_since: S<d::ListCredentialsSince<M>>,
                    list_audit: S<d::ListAudit<M>>,
                    add_denylist: S<d::AddDenylist<M>>,
                    list_denylist: S<d::ListDenylist<M>>,
                    list_audit_tail: S<d::ListAuditTail<M>>,
                    upsert_plane_record: S<d::UpsertPlaneRecord<M>>,
                    get_plane_record: WedgedPlaneGet,
                    append_plane_record: S<d::AppendPlaneRecord<M>>,
                    list_plane_records: S<d::ListPlaneRecords<M>>,
                    list_plane_record_parents: S<d::ListPlaneRecordParents<M>>,
                    purge_plane_records_before: S<d::PurgePlaneRecordsBefore<M>>,
                    delete_plane_record: S<d::DeletePlaneRecord<M>>,
                    redeem_plane_token: S<d::RedeemPlaneToken<M>>,
                    plane_token_live: S<d::PlaneTokenLive<M>>,
                    record_put: S<d::RecordPut<M>>,
                    record_get: WedgedGet,
                    record_scan: S<d::RecordScan<M>>,
                    add_usage_batch: S<d::AddUsageBatch<M>>,
                    add_metering_batch: S<d::AddMeteringBatch<M>>,
                },
    }
}

/// A store on a dispatcher whose watchdog faults a Call-class crossing past 50 ms.
fn open() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets {
            call: Duration::from_millis(50),
            ..Budgets::default()
        },
        watchdog_period: Duration::from_millis(10),
        ..DispatchConfig::default()
    }));
    let row = LinkedRow::of(wedged::door).expect("the wedged door states its Statement");
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the wedged door loads");
    LoadedStore::open(p, d, b"{}", mint).expect("it opens")
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x1e47,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

const LENT: u8 = 0xab;

/// RED before the store's typed calls used the lending submit: the watchdog-faulted `record_get`
/// returned to its caller while its crossing ran on over the caller's own key, so the crossing
/// read the bytes the caller wrote after it had them back.
#[test]
fn a_watchdog_faulted_typed_call_keeps_the_memory_it_lent() {
    let s = open();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let mut key = vec![LENT; 64];
    let answered = rt.block_on(StoreCalls::record_get(&s, "sch", &key));
    assert!(
        answered.is_err(),
        "the watchdog faults the wedged op and the caller is answered: {answered:?}"
    );
    // The caller has its key back: it is the caller's to reuse.
    key.fill(0);
    let read = GET_GATE.release_and_read();
    assert_eq!(
        read,
        vec![LENT; 64],
        "the abandoned crossing read the caller's memory after the call returned"
    );
    drop(key);
}

/// RED before the bridge used the lending submit: as above, through the synchronous
/// [`RecordStore`] surface.
#[test]
fn a_watchdog_faulted_bridge_call_keeps_the_memory_it_lent() {
    let s = open();
    let mut id = String::from_utf8(vec![b'q'; 48]).unwrap();
    let answered = RecordStore::get_plane_record(&s, "kind", &id);
    assert!(
        answered.is_err(),
        "the watchdog faults the wedged op and the caller is answered: {answered:?}"
    );
    // SAFETY: ASCII over ASCII keeps the string valid UTF-8.
    unsafe { id.as_bytes_mut() }.fill(b'z');
    let read = PLANE_GATE.release_and_read();
    assert_eq!(
        read,
        vec![b'q'; 48],
        "the abandoned crossing read the caller's memory after the call returned"
    );
    drop(id);
}
