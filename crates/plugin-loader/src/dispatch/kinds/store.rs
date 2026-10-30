// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND: `abi/store/`. Every op whose `out` states something beyond the mechanism's head
//! is checked by its validator in `abi/store/check.rs`:
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
//! mechanism (the table's list on `abi::store::OPS`), and answer `Ok` here: `put_key`,
//! `delete_key`, `put_usage`, `put_credential`, `put_key_with_credential`, `revoke_credential`,
//! `add_denylist`, `upsert_plane_record`, `append_plane_record`, `delete_plane_record`,
//! `record_put`, `add_usage_batch`, `add_metering_batch`, and every lifecycle slot but `cancel`.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::{reported, Fault};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut, LIFECYCLE_SLOTS};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::store::check::{self as sc, LIST_ITEMS_HARD_MAX};
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

/// `n` as `u64` (a `usize` always fits).
fn u(n: usize) -> u64 {
    n as u64
}

/// `list_plane_records`: blobs the plugin reported into the host's [`store::HostBlobs`].
fn list_plane_records(a: &Answer) -> Result<(), Fault> {
    let host = &a.input::<ListPlaneRecordsIn>()?.out;
    let out = a.out::<HostListOut>()?;
    // SAFETY: `host.items` is the host's own array of `items_cap` blobs; `reported` refuses an
    // `items_written` above that cap before any slice exists.
    let items = unsafe {
        reported(
            host.items.cast_const(),
            out.items_written,
            u(host.items_cap),
            "list_plane_records.items",
        )
    }?;
    sc::check_list_plane_records(a.outcome, out, host, items)
}

/// `record_scan`: entries the plugin reported into the host's [`store::HostRecords`].
fn record_scan(a: &Answer) -> Result<(), Fault> {
    let input = a.input::<RecordScanIn>()?;
    let host = &input.out;
    let out = a.out::<HostListOut>()?;
    // SAFETY: `host.items` is the host's own array of `items_cap` entries; `reported` refuses an
    // `items_written` above that cap before any slice exists.
    let entries = unsafe {
        reported(
            host.items.cast_const(),
            out.items_written,
            u(host.items_cap),
            "record_scan.entries",
        )
    }?;
    sc::check_record_scan(a.outcome, out, host, entries, input.limit)
}

/// An off-path list of records under a lease. Only a READY answer holds a lease, so only it is
/// read; the plugin's count is capped at [`LIST_ITEMS_HARD_MAX`] before any slice exists.
fn leased_list(a: &Answer, field: &'static str) -> Result<(), Fault> {
    let out = a.out::<LeasedListOut>()?;
    // This gate guards the slice, not the check: `items` is plugin memory live only under a
    // READY answer's lease. Any other outcome is checked with no items.
    if a.outcome != Outcome::Ready {
        return sc::check_leased_list(a.outcome, out, &[]);
    }
    // SAFETY: on READY `items` is plugin memory held under `head.lease` until `release`; the
    // count is capped and a NULL pointer with a count refused before the slice is built.
    let items = unsafe { reported(out.items, u(out.items_len), LIST_ITEMS_HARD_MAX, field) }?;
    sc::check_leased_list(a.outcome, out, items)
}

/// An off-path list of strings under a lease, as [`leased_list`].
fn leased_strs(a: &Answer, field: &'static str) -> Result<(), Fault> {
    let out = a.out::<LeasedStrListOut>()?;
    // Guards the slice only, as `leased_list`.
    if a.outcome != Outcome::Ready {
        return sc::check_leased_strs(a.outcome, out, &[]);
    }
    // SAFETY: as `leased_list`.
    let items = unsafe { reported(out.items, u(out.items_len), LIST_ITEMS_HARD_MAX, field) }?;
    sc::check_leased_strs(a.outcome, out, items)
}

/// What a store states in its Statement ([`store::StoreTail`] and the `MARK_EPHEMERAL` mark), read
/// once at bind: the instance's [`Kind::context`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFacts {
    /// What it holds is lost on restart.
    pub ephemeral: bool,
    /// It holds plane records durably.
    pub durable_plane: bool,
    /// A different record at a used `seq` is refused as a fork.
    pub fork_refusal: bool,
    /// The settings paths the Statement declares secret (`secret_refs`): taken out of the settings
    /// and lent to `open` as `OpenIn.secrets`, as every other kind's are.
    pub secret_refs: Vec<String>,
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
    // SAFETY: the loader's Statement check ran on `st`: every Statement list is its stated count of
    // `'static` entries, and the rendering bounds each list and string before it reads it.
    let rendering = unsafe { busbar_contract::abi::mechanism::rendering::render(st) }
        .map_err(|e| e.to_string())?;
    let secret_refs = busbar_contract::abi::mechanism::rendering::read(&rendering)
        .map_err(|e| {
            format!(
                "the store Statement rendering does not read back: byte {} is not {}",
                e.at, e.what
            )
        })?
        .secret_refs;
    Ok(StoreFacts {
        // One Statement: `ephemeral` is the Statement's mark, not a tail fact.
        ephemeral: st.marks & busbar_contract::abi::mechanism::door::MARK_EPHEMERAL != 0,
        durable_plane: flag(t.durable_plane, "durable_plane")?,
        fork_refusal: flag(t.fork_refusal, "fork_refusal")?,
        secret_refs,
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
        match a.slot {
            // Request path, host buffers, each with a short-buffer path.
            slot::RECORD_GET => {
                let cap = u(a.input::<RecordGetIn>()?.value.cap);
                sc::check_record_get(a.outcome, a.out::<HostBytesOut>()?, cap)
            }
            slot::GET_PLANE_RECORD => {
                let cap = u(a.input::<GetPlaneRecordIn>()?.body.cap);
                sc::check_get_plane_record(a.outcome, a.out::<HostBytesOut>()?, cap)
            }
            slot::LIST_PLANE_RECORDS => list_plane_records(a),
            slot::RECORD_SCAN => record_scan(a),
            // Off path, under a lease.
            slot::GET_KEY | slot::GET_USAGE => {
                sc::check_leased_blob(a.outcome, a.out::<LeasedBlobOut>()?)
            }
            slot::LIST_KEYS => leased_list(a, "list_keys.items"),
            slot::LIST_KEYS_SINCE => leased_list(a, "list_keys_since.items"),
            slot::LIST_METERING => leased_list(a, "list_metering.items"),
            slot::LIST_CREDENTIALS => leased_list(a, "list_credentials.items"),
            slot::LIST_CREDENTIALS_SINCE => leased_list(a, "list_credentials_since.items"),
            slot::LIST_AUDIT => leased_list(a, "list_audit.items"),
            slot::LIST_AUDIT_TAIL => leased_list(a, "list_audit_tail.items"),
            slot::LIST_DENYLIST => leased_strs(a, "list_denylist.items"),
            slot::LIST_PLANE_RECORD_PARENTS => leased_strs(a, "list_plane_record_parents.items"),
            // Verdicts, the cancel disposition.
            slot::REDEEM_PLANE_TOKEN | slot::PLANE_TOKEN_LIVE => {
                sc::check_verdict(a.outcome, a.out::<VerdictOut>()?)
            }
            life::CANCEL => sc::check_cancel(a.outcome, a.out::<CancelOut>()?),
            // A purge's rows removed.
            slot::PURGE_PLANE_RECORDS_BEFORE => sc::check_count(a.outcome, a.out::<CountOut>()?),
            // Answered by the head only: the `out` is a bare `OutHead`, checked by the mechanism.
            slot::PUT_KEY
            | slot::DELETE_KEY
            | slot::PUT_USAGE
            | slot::PUT_CREDENTIAL
            | slot::PUT_KEY_WITH_CREDENTIAL
            | slot::REVOKE_CREDENTIAL
            | slot::ADD_DENYLIST
            | slot::UPSERT_PLANE_RECORD
            | slot::APPEND_PLANE_RECORD
            | slot::DELETE_PLANE_RECORD
            | slot::RECORD_PUT
            | slot::ADD_USAGE_BATCH
            | slot::ADD_METERING_BATCH => Ok(()),
            // The other lifecycle slots.
            _ => Ok(()),
        }
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
