// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFacts {
    /// What it holds is lost on restart.
    pub ephemeral: bool,
    /// It holds plane records durably.
    pub durable_plane: bool,
    /// A different record at a used `seq` is refused as a fork.
    pub fork_refusal: bool,
    /// Negotiated version-one conditional record transaction support.
    pub record_transaction: bool,
    /// Negotiated version-one atomic raw-usage correction support.
    pub usage_correction: bool,
    /// The settings paths the Statement declares secret (`secret_refs`): taken out of the settings
    /// and lent to `open` as `OpenIn.secrets`, as every other kind's are.
    pub secret_refs: Vec<String>,
    /// Explicit slot-8 envelope CAS capability, read from the Statement extensions.
    pub credential_rewrap: bool,
}

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
        ephemeral: st.marks & busbar_contract::abi::mechanism::door::MARK_EPHEMERAL != 0,
        durable_plane: flag(t.durable_plane, "durable_plane")?,
        fork_refusal: flag(t.fork_refusal, "fork_refusal")?,
        record_transaction: st.extensions.fmt == busbar_contract::abi::mechanism::call::BLOB_OCTETS
            && st.extensions.flags == 0
            && st.extensions.len as u64 <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES
            // SAFETY: the raw byte length passed HARD_MAX_BYTES before any slice was formed.
            // Statement extensions are static plugin memory; `lent` also checks the pointer.
            && unsafe { crate::dispatch::validate::lent(st.extensions.ptr, st.extensions.len) }
                .is_some_and(busbar_contract::abi::sdk::store::conditional::supported),
        usage_correction: st.extensions.fmt == busbar_contract::abi::mechanism::call::BLOB_OCTETS
            && st.extensions.flags == 0
            && st.extensions.len as u64 <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES
            // SAFETY: bounded static Statement bytes; `lent` also checks the pointer.
            && unsafe { crate::dispatch::validate::lent(st.extensions.ptr, st.extensions.len) }
                .is_some_and(busbar_contract::abi::sdk::store::correction::supported),
        secret_refs,
        credential_rewrap: {
            // SAFETY: the checked Statement owns its static extension bytes.
            let bytes = unsafe { crate::dispatch::plugin::blob_bytes(st.extensions) };
            busbar_contract::abi::mechanism::extensions::get(
                bytes,
                busbar_contract::abi::sdk::store::rewrap::INTENT,
            ) == Some(b"1".as_slice())
        },
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
