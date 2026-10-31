// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND: `abi/store/`. Every op whose `out` states something beyond the mechanism's head
//! is checked by its validator in `abi/store/check.rs`, through the contract's one call per answer,
//! `store::check_answer`:
//!
//! * the request-path results written into host buffers (`record_get`/`get_plane_record`'s bytes,
//!   `list_plane_records` and `record_scan`'s lists), each of which has a short-buffer path;
//! * the off-path results held under a lease (single records, record lists, string lists);
//! * the token verdicts and the lifecycle `cancel`'s disposition;
//! * the purge's [`CountOut`].
//!
//! Every slice a plugin-reported count names (list items, rows, entries, leased items) is built
//! through `check::reported` against the host's own capacity (the leased lists, which have none,
//! against `LIST_ITEMS_HARD_MAX`), so a count above it is FAULT before any slice exists.
//!
//! Every validator runs on every outcome and decides for itself which fields that outcome states.
//! The only READY gate left here guards building a slice from plugin memory, which is live only
//! under a READY answer's lease.
//!
//! The ops whose `out` is a bare `OutHead` are answered by the head only and checked by the
//! mechanism (the table's list on `abi::store::OPS`), and `check_answer` passes them: `put_key`,
//! `delete_key`, `put_usage`, `put_credential`, `put_key_with_credential`, `revoke_credential`,
//! `add_denylist`, `upsert_plane_record`, `append_plane_record`, `delete_plane_record`,
//! `record_put`, `add_usage_batch`, `add_metering_batch`, and every lifecycle slot but `cancel`.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::store::{
    self, slot, AddUsageBatchIn, AppendPlaneRecordIn, BlobIn, CountOut, GetPlaneRecordIn,
    HostBytesOut, HostListOut, IdIn, IdReasonIn, KeyWithCredentialIn, KindBeforeIn, KindIdIn,
    LeasedBlobOut, LeasedListOut, LeasedStrListOut, ListPlaneRecordsIn, OpBlobsIn, PutUsageIn,
    RecordGetIn, RecordPutIn, RecordScanIn, TokenIn, U64In, UpsertPlaneRecordIn, VerdictOut,
    WindowIn, KIND_SLOTS, NAMES,
};

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The store tail's last frozen size: it has not grown, so it is this host's (THE KIND TAIL
/// GROWTH RULE, `abi::mechanism::door::tail_read_len`).
const STORE_TAIL_FROZEN: usize = std::mem::size_of::<store::StoreTail>();

/// The store kind.
#[derive(Debug, Clone, Copy)]
pub struct Store;

// SAFETY: `#[repr(C)]` in `abi/store/`, each leading with its head; their pointers are host
// buffers or plugin memory under a lease, never borrowed data.
unsafe impl InFrame for IdIn {}
unsafe impl InFrame for U64In {}
unsafe impl InFrame for WindowIn {}
unsafe impl InFrame for PutUsageIn {}
unsafe impl InFrame for BlobIn {}
unsafe impl InFrame for KeyWithCredentialIn {}
unsafe impl InFrame for KindIdIn {}
unsafe impl InFrame for IdReasonIn {}
unsafe impl InFrame for UpsertPlaneRecordIn {}
unsafe impl InFrame for AppendPlaneRecordIn {}
unsafe impl InFrame for GetPlaneRecordIn {}
unsafe impl InFrame for ListPlaneRecordsIn {}
unsafe impl InFrame for KindBeforeIn {}
unsafe impl InFrame for TokenIn {}
unsafe impl InFrame for RecordPutIn {}
unsafe impl InFrame for RecordGetIn {}
unsafe impl InFrame for RecordScanIn {}
unsafe impl InFrame for AddUsageBatchIn {}
unsafe impl InFrame for OpBlobsIn {}
unsafe impl OutFrame for LeasedBlobOut {}
unsafe impl OutFrame for LeasedListOut {}
unsafe impl OutFrame for LeasedStrListOut {}
unsafe impl OutFrame for CountOut {}
unsafe impl OutFrame for HostBytesOut {}
unsafe impl OutFrame for HostListOut {}
unsafe impl OutFrame for VerdictOut {}

/// What a store states in its Statement ([`store::StoreTail`] and the `MARK_EPHEMERAL` mark), read
/// once at bind: the instance's [`Kind::context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFacts {
    /// What it holds is lost on restart.
    pub ephemeral: bool,
    /// It holds plane records durably.
    pub durable_plane: bool,
    /// A different record at a used `seq` is refused as a fork.
    pub fork_refusal: bool,
}

/// The store's tail, read from the Statement: a whole [`store::StoreTail`] whose flags are `0` or
/// `1`. A store states one: the flags are what the host reads instead of a load-time guess.
fn store_facts(st: &Statement) -> Result<StoreFacts, String> {
    // SAFETY: `StoreTail` is a `#[repr(C)]` kind tail of integers (all-zero valid); a non-NULL kind
    // tail is `'static` plugin data of its stated size.
    let t: store::StoreTail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "a store", STORE_TAIL_FROZEN) }?;
    let flag = |v: u8, name: &str| match v {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(format!("the store tail's {name} is {n}, not 0 or 1")),
    };
    Ok(StoreFacts {
        // One Statement: `ephemeral` is the Statement's mark, not a tail fact.
        ephemeral: st.marks & busbar_contract::abi::mechanism::door::MARK_EPHEMERAL != 0,
        durable_plane: flag(t.durable_plane, "durable_plane")?,
        fork_refusal: flag(t.fork_refusal, "fork_refusal")?,
    })
}

impl Kind for Store {
    const CODE: KindCode = KindCode::Store;
    type Ops = store::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<crate::dispatch::Context>>, String> {
        Ok(Some(Box::new(store_facts(st)?)))
    }

    fn op_name(s: u32) -> &'static str {
        match s.checked_sub(LIFECYCLE_SLOTS) {
            Some(k) if k < KIND_SLOTS => NAMES[k as usize],
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        let (input, in_size, out, out_size) = a.frames();
        // SAFETY: `Answer::new`'s contract: the op's live host-owned frames, unwritten while the
        // answer lives; every buffer the `in` lends is the host's own, of its stated capacity, and
        // a READY answer's leased list is plugin memory held under its lease until `release`.
        unsafe { store::check_answer(a.slot, a.outcome, input, in_size, out, out_size, &()) }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::RECORD_GET | slot::GET_PLANE_RECORD => {
                a.out::<HostBytesOut>().is_ok_and(|o| o.needed != 0)
            }
            slot::LIST_PLANE_RECORDS | slot::RECORD_SCAN => a
                .out::<HostListOut>()
                .is_ok_and(|o| o.needed_items != 0 || o.needed_bytes != 0),
            _ => false,
        }
    }
}
