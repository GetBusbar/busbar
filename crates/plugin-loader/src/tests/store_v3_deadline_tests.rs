// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE'S DEADLINE CLASSES, over a store door whose ops PEND and never wake:
//!
//! * a WriteBehind op (`add_usage_batch`) to a hung store does NOT hold a reload drain, which
//!   waits only on Call/Stream/Connection ops (H5: its own deadline class);
//! * a Call-class op (`record_get`) to the same hung store DOES hold the drain.
//!
//! (A synchronous bridge call that PENDS is no longer FAULT: it is submitted on a ticket and
//! completes on the wake, ARCHITECT ruling 2026-10-03 on Q-L14-1; `store_v3_pend_tests` proves it.)
//!
//! Every other slot is the memory store's, through the store SDK.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::Slot;
use busbar_contract::abi::store::{AddUsageBatchIn, HostBytesOut, OpId, RecordGetIn};
use busbar_contract::records::UsageDelta;
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

/// `add_usage_batch`: PENDING, and no wake ever comes.
struct HangsWriteBehind;
impl Slot for HangsWriteBehind {
    type In = AddUsageBatchIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &AddUsageBatchIn, _: &mut OutHead) -> Outcome {
        Outcome::Pending
    }
}

/// `record_get`: PENDING, and no wake ever comes.
struct HangsCall;
impl Slot for HangsCall {
    type In = RecordGetIn;
    type Out = HostBytesOut;
    fn call(_: *mut c_void, _: &RecordGetIn, _: &mut HostBytesOut) -> Outcome {
        Outcome::Pending
    }
}

mod hung {
    use super::{HangsCall, HangsWriteBehind};
    use crate::both_ways::store_fixture::MemoryStore as M;
    use busbar_contract::abi::sdk::store::door as d;
    use busbar_contract::abi::sdk::Safe as S;

    const TAIL: busbar_contract::abi::store::StoreTail = d::tail::<M>();
    const DIAGS: [busbar_contract::abi::mechanism::call::AbiStr; 2] = d::DIAG_IDS;

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::store::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            diag_ids: DIAGS.as_ptr(),
            diag_ids_len: 2,
            kind_tail: ::core::ptr::from_ref(&TAIL)
                .cast::<busbar_contract::abi::mechanism::door::KindTailHead>(),
            ..busbar_contract::abi::sdk::door::statement("hung", "0", 64)
        },
                lifecycle: {
                    validate: S<d::Validate<M>>,
                    open: S<d::Open<M>>,
                    refresh: S<d::Refresh<M>>,
                    retire: S<d::Retire<M>>,
                    tick: S<d::Tick<M>>,
                    drive: S<d::Drive<M>>,
                    cancel: S<d::Cancel<M>>,
                    release: S<d::Release<M>>,
                    close: S<d::Close<M>>,
                },
                kind_ops: {
                    put_key: S<d::PutKey<M>>,
                    get_key: S<d::GetKey<M>>,
                    list_keys: S<d::ListKeys<M>>,
                    delete_key: S<d::DeleteKey<M>>,
                    scrub_key: S<d::ScrubKey<M>>,
                    list_keys_since: S<d::ListKeysSince<M>>,
                    get_usage: S<d::GetUsage<M>>,
                    put_usage: S<d::PutUsage<M>>,
                    add_usage: S<d::AddUsage<M>>,
                    add_metering: S<d::AddMetering<M>>,
                    list_metering: S<d::ListMetering<M>>,
                    purge_windows_before: S<d::PurgeWindowsBefore<M>>,
                    purge_metering_before: S<d::PurgeMeteringBefore<M>>,
                    put_credential: S<d::PutCredential<M>>,
                    put_key_with_credential: S<d::PutKeyWithCredential<M>>,
                    list_credentials: S<d::ListCredentials<M>>,
                    lookup_credential_secret: S<d::LookupCredentialSecret<M>>,
                    revoke_credential: S<d::RevokeCredential<M>>,
                    list_credentials_since: S<d::ListCredentialsSince<M>>,
                    append_audit: S<d::AppendAudit<M>>,
                    list_audit: S<d::ListAudit<M>>,
                    add_denylist: S<d::AddDenylist<M>>,
                    list_denylist: S<d::ListDenylist<M>>,
                    list_audit_tail: S<d::ListAuditTail<M>>,
                    upsert_plane_record: S<d::UpsertPlaneRecord<M>>,
                    get_plane_record: S<d::GetPlaneRecord<M>>,
                    append_plane_record: S<d::AppendPlaneRecord<M>>,
                    list_plane_records: S<d::ListPlaneRecords<M>>,
                    list_plane_record_parents: S<d::ListPlaneRecordParents<M>>,
                    purge_plane_records_before: S<d::PurgePlaneRecordsBefore<M>>,
                    delete_plane_record: S<d::DeletePlaneRecord<M>>,
                    redeem_plane_token: S<d::RedeemPlaneToken<M>>,
                    plane_token_live: S<d::PlaneTokenLive<M>>,
                    append_batch: S<d::AppendBatch<M>>,
                    reserve: S<d::Reserve<M>>,
                    slice_release: S<d::SliceRelease<M>>,
                    heads: S<d::Heads<M>>,
                    session_put: S<d::SessionPut<M>>,
                    session_remove: S<d::SessionRemove<M>>,
                    sessions_for: S<d::SessionsFor<M>>,
                    record_put: S<d::RecordPut<M>>,
                    record_get: HangsCall,
                    record_scan: S<d::RecordScan<M>>,
                    add_usage_batch: HangsWriteBehind,
                    add_metering_batch: S<d::AddMeteringBatch<M>>,
                    append_audit_batch: S<d::AppendAuditBatch<M>>,
                    window_caps: S<d::WindowCaps<M>>,
                },
    }
}

fn open() -> (LoadedStore, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(hung::door).expect("the hung door states its Statement");
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
    .expect("the hung door loads");
    (
        LoadedStore::open(p, d.clone(), b"{}", mint).expect("it opens"),
        d,
    )
}

/// This test process's `op_id` allocator: one counter, as the kernel's `door::op_id` is.
fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x7e59,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn a_hung_write_behind_op_does_not_hold_the_reload_drain() {
    let (s, d) = open();
    let s = Arc::new(s);
    let rt = runtime();
    let bg = s.clone();
    let task = rt.spawn(async move {
        let cells = [("k", 60u64, UsageDelta::default())];
        let _ = bg.add_usage_batch(OpId([1; 16]), &cells).await;
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        d.drain(s.plugin(), Duration::from_millis(200)),
        "the drain waits on no WriteBehind op"
    );
    task.abort();
}

#[test]
fn a_hung_call_op_holds_the_reload_drain() {
    let (s, d) = open();
    let s = Arc::new(s);
    let rt = runtime();
    let bg = s.clone();
    let task = rt.spawn(async move {
        let _ = StoreCalls::record_get(&*bg, "sch", b"k").await;
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !d.drain(s.plugin(), Duration::from_millis(200)),
        "a Call-class op in flight is waited on"
    );
    task.abort();
}
