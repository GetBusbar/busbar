// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::*;
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut, RawSlot};
use busbar_contract::abi::sdk::store::conditional::{self, Decision};
use busbar_contract::abi::sdk::store::correction;
use busbar_contract::abi::store::*;

pub const NAME: &str = "conditional-store-witness";

struct State {
    mode: String,
    wake: Option<WakeFn>,
    data: Mutex<Data>,
}

struct Data {
    tx_calls: u64,
    get_calls: u64,
    released: u64,
    cancelled: u64,
    writes: u64,
    receipts: u64,
    first: Option<Vec<u8>>,
    same: bool,
    class: u8,
    deadline: u64,
    get_class: u8,
    get_deadline: u64,
    schema: String,
    key: Vec<u8>,
    next_lease: u64,
    leases: BTreeMap<u64, Box<[u8]>>,
    unleased: Vec<Box<[u8]>>,
    pending: Option<(HostCtx, Ticket)>,
    finished: bool,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            tx_calls: 0,
            get_calls: 0,
            released: 0,
            cancelled: 0,
            writes: 0,
            receipts: 0,
            first: None,
            same: true,
            class: 0,
            deadline: 0,
            get_class: 0,
            get_deadline: 0,
            schema: String::new(),
            key: Vec::new(),
            next_lease: 0,
            leases: BTreeMap::new(),
            unleased: Vec::new(),
            pending: None,
            finished: false,
        }
    }
}

impl Data {
    fn lease(&mut self, bytes: Vec<u8>, head: &mut OutHead, leased: bool) {
        let bytes = bytes.into_boxed_slice();
        head.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        if leased {
            self.next_lease += 1;
            head.lease = self.next_lease;
            self.leases.insert(head.lease, bytes);
        } else {
            self.unleased.push(bytes);
        }
    }
}

// SAFETY: every raw body is entered only with the instance its Open allocated, before Close.
unsafe fn state<'a>(instance: *mut c_void) -> &'a State {
    unsafe { &*instance.cast::<State>() }
}

struct Open;
impl RawSlot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    unsafe fn call(_: *mut c_void, input: &OpenIn, out: &mut OpenOut) -> Outcome {
        // SAFETY: the settings and host tables are the live host-owned OpenIn fields.
        let settings: serde_json::Value =
            serde_json::from_slice(unsafe { input.settings.bytes() }).unwrap();
        let wake = if input.host.is_null() {
            None
        } else {
            unsafe { (*input.host).wake }
        };
        out.instance = Box::into_raw(Box::new(State {
            mode: settings["mode"].as_str().unwrap_or("applied").into(),
            wake,
            data: Mutex::new(Data::default()),
        }))
        .cast();
        Outcome::Ready
    }
}

struct Close;
impl RawSlot for Close {
    type In = InHead;
    type Out = OutHead;
    unsafe fn call(instance: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        // SAFETY: the host serializes Close after all crossings stop and calls it once.
        drop(unsafe { Box::from_raw(instance.cast::<State>()) });
        Outcome::Ready
    }
}

struct Release;
impl RawSlot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    unsafe fn call(instance: *mut c_void, input: &ReleaseIn, _: &mut OutHead) -> Outcome {
        // SAFETY: this is the live instance Open created.
        let state = unsafe { state(instance) };
        let removed = {
            let mut data = state.data.lock().unwrap();
            let removed = data.leases.remove(&input.lease);
            if removed.is_some() {
                data.released += 1;
            }
            removed
        };
        let found = removed.is_some();
        drop(removed);
        if found {
            Outcome::Ready
        } else {
            Outcome::Refused
        }
    }
}

struct Cancel;
impl RawSlot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    unsafe fn call(instance: *mut c_void, _: &CancelIn, out: &mut CancelOut) -> Outcome {
        // SAFETY: this is the live instance Open created.
        unsafe { state(instance) }.data.lock().unwrap().cancelled += 1;
        out.disposition = CANCEL_UNKNOWN;
        Outcome::Ready
    }
}

struct Ready<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> RawSlot for Ready<I, O> {
    type In = I;
    type Out = O;
    unsafe fn call(_: *mut c_void, _: &I, _: &mut O) -> Outcome {
        Outcome::Ready
    }
}
struct Refuse<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> RawSlot for Refuse<I, O> {
    type In = I;
    type Out = O;
    unsafe fn call(_: *mut c_void, _: &I, _: &mut O) -> Outcome {
        Outcome::Refused
    }
}

struct Get;
impl RawSlot for Get {
    type In = RecordGetIn;
    type Out = HostBytesOut;
    unsafe fn call(instance: *mut c_void, input: &RecordGetIn, out: &mut HostBytesOut) -> Outcome {
        // SAFETY: the host retains the complete request until this operation finishes, including
        // across PENDING and after its original caller is canceled (the property under test).
        let state = unsafe { state(instance) };
        let encoded = unsafe { input.head.extensions.bytes() };
        let candidate = conditional::intent(encoded).unwrap();
        let mut data = state.data.lock().unwrap();
        if let Some(candidate) = candidate {
            data.tx_calls += 1;
            data.class = input.head.deadline_class;
            data.deadline = input.head.deadline_ns;
            // SAFETY: the carrier schema/key are live fields of the same retained request.
            data.schema = String::from_utf8(unsafe { input.schema.bytes() }.to_vec()).unwrap();
            data.key = unsafe { input.key.bytes() }.to_vec();
            let same = data.first.as_ref().is_none_or(|first| first == encoded);
            data.same &= same;
            if data.first.is_none() {
                data.first = Some(encoded.to_vec());
            }
            if candidate.carrier() != Some((data.schema.as_str(), data.key.as_slice())) {
                return Outcome::Fault;
            }
            if data.class != DeadlineClass::WriteBehind as u8 || data.deadline != 0 {
                return Outcome::Refused;
            }
            if state.mode == "hold" && !data.finished {
                data.pending = Some((input.head.host, input.head.ticket));
                return Outcome::Pending;
            }
            if state.mode == "op-id-conflict" {
                out.head.error = AbiStr {
                    ptr: DIAG_OPID_CONFLICT.as_ptr(),
                    len: DIAG_OPID_CONFLICT.len(),
                };
                return Outcome::Refused;
            }
            let decision = if state.mode == "conflict" {
                Decision::ConditionConflict
            } else {
                Decision::Applied
            };
            let mut result = conditional::encode_result(&candidate, decision);
            if (data.tx_calls == 1 && matches!(state.mode.as_str(), "pending" | "short"))
                || state.mode == "short-twice"
            {
                data.lease(
                    extensions::encode(&[(conditional::RESULT, &result)]),
                    &mut out.head,
                    true,
                );
                if state.mode == "pending" {
                    out.head.wake_at_ns = 1;
                    return Outcome::Pending;
                }
                out.needed = input.value.cap as u64 + 1;
                return Outcome::Failed;
            }
            if decision == Decision::Applied && data.writes == 0 {
                data.writes = 1;
                data.receipts = 1;
            }
            if state.mode == "failed-once" && data.tx_calls == 1 {
                out.head.error = AbiStr {
                    ptr: b"lost commit reply".as_ptr(),
                    len: b"lost commit reply".len(),
                };
                return Outcome::Failed;
            }
            match state.mode.as_str() {
                "missing" => return Outcome::Ready,
                "malformed" => result.truncate(7),
                "wrong-version" => result[0] ^= 1,
                "wrong-id" => result[4] ^= 1,
                "wrong-digest" => result[20] ^= 1,
                "wrong-decision" => *result.last_mut().unwrap() = 9,
                _ => {}
            }
            let mut result_extensions = match state.mode.as_str() {
                "missing-result" => extensions::encode(&[("other-result", &result)]),
                "duplicate-result" => extensions::encode(&[
                    (conditional::RESULT, &result),
                    (conditional::RESULT, &result),
                ]),
                _ => extensions::encode(&[(conditional::RESULT, &result)]),
            };
            if state.mode == "trailing-result" {
                result_extensions.push(0);
            }
            data.lease(result_extensions, &mut out.head, state.mode != "unleased");
            match state.mode.as_str() {
                "wrong-format" => out.head.extensions.fmt = BLOB_JSON,
                "wrong-flags" => out.head.extensions.flags = 1,
                "null-result" => out.head.extensions.ptr = std::ptr::null(),
                "oversize-result" => {
                    out.head.extensions.len =
                        busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize + 1
                }
                _ => {}
            }
            return Outcome::Ready;
        }
        data.get_calls += 1;
        data.get_class = input.head.deadline_class;
        data.get_deadline = input.head.deadline_ns;
        // SAFETY: the ordinary GET key is live for this crossing.
        let finish = unsafe { input.key.bytes() } == b"finish";
        let wake = if finish {
            data.finished = true;
            data.pending.take()
        } else {
            None
        };
        let bytes = serde_json::to_vec(&serde_json::json!({
            "tx_calls": data.tx_calls, "get_calls": data.get_calls, "released": data.released,
            "cancelled": data.cancelled, "held": data.leases.len(), "writes": data.writes,
            "receipts": data.receipts, "same": data.same, "class": data.class, "deadline": data.deadline,
            "get_class": data.get_class, "get_deadline": data.get_deadline, "schema": data.schema, "key": data.key,
        })).unwrap();
        drop(data);
        if let (Some(wake), Some((ctx, ticket))) = (state.wake, wake) {
            wake(ctx, ticket);
        }
        if bytes.len() > input.value.cap {
            out.needed = bytes.len() as u64;
            return Outcome::Failed;
        }
        // SAFETY: the host lends `value.cap` writable bytes; the length was checked above.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), input.value.ptr, bytes.len()) };
        out.found = FOUND;
        out.written = bytes.len() as u64;
        Outcome::Ready
    }
}

const TAIL: StoreTail = StoreTail {
    head: KindTailHead {
        size: std::mem::size_of::<StoreTail>() as u32,
        ..KindTailHead::ZERO
    },
    ..StoreTail::ZERO
};
busbar_contract::statement_extensions!(CAP: [
    (conditional::CAPABILITY, b"1"),
    (correction::CAPABILITY, correction::CAPABILITY_VALUE),
]);

struct Correction;
impl RawSlot for Correction {
    type In = AddUsageBatchIn;
    type Out = OutHead;
    unsafe fn call(instance: *mut c_void, input: &AddUsageBatchIn, out: &mut OutHead) -> Outcome {
        // SAFETY: the dispatcher retains the immutable input and instance for this crossing.
        let state = unsafe { state(instance) };
        let encoded = unsafe { input.head.extensions.bytes() };
        let candidate = correction::intent(encoded).unwrap().unwrap();
        let mut data = state.data.lock().unwrap();
        data.tx_calls += 1;
        data.class = input.head.deadline_class;
        data.deadline = input.head.deadline_ns;
        if input.op_id != candidate.op_id
            || input.cells_len != 0
            || data.class != DeadlineClass::WriteBehind as u8
            || data.deadline != 0
        {
            return Outcome::Fault;
        }
        let same = data.first.as_ref().is_none_or(|first| first == encoded);
        data.same &= same;
        if data.first.is_none() {
            data.first = Some(encoded.to_vec());
        }
        if state.mode == "hold" && !data.finished {
            data.pending = Some((input.head.host, input.head.ticket));
            return Outcome::Pending;
        }
        if state.mode == "pending" && data.tx_calls == 1 {
            out.wake_at_ns = 1;
            return Outcome::Pending;
        }
        if state.mode == "op-id-conflict" {
            out.error = AbiStr {
                ptr: DIAG_OPID_CONFLICT.as_ptr(),
                len: DIAG_OPID_CONFLICT.len(),
            };
            return Outcome::Refused;
        }
        let decision = if state.mode == "conflict" {
            correction::Decision::ConditionConflict
        } else {
            correction::Decision::Applied
        };
        if decision == correction::Decision::Applied && data.writes == 0 {
            data.writes = 1;
            data.receipts = 1;
        }
        if state.mode == "failed-once" && data.tx_calls == 1 {
            const LOST_REPLY: &str = "lost correction commit reply";
            out.error = AbiStr {
                ptr: LOST_REPLY.as_ptr(),
                len: LOST_REPLY.len(),
            };
            return Outcome::Failed;
        }
        if state.mode == "missing" {
            return Outcome::Ready;
        }
        let result_candidate = if state.mode == "wrong-digest" {
            let mut changed = candidate.clone();
            changed.usage[0].replacement.requests += 1;
            changed
        } else if state.mode == "wrong-id" {
            let mut changed = candidate.clone();
            changed.op_id = OpId::from_parts(0xc0de, 99);
            changed
        } else {
            candidate
        };
        let mut result = correction::encode_result(&result_candidate, decision);
        if state.mode == "malformed" {
            result.pop();
        }
        let mut bytes = if state.mode == "duplicate-result" {
            extensions::encode(&[(correction::RESULT, &result), (correction::RESULT, &result)])
        } else {
            extensions::encode(&[(correction::RESULT, &result)])
        };
        if state.mode == "trailing-result" {
            bytes.push(0);
        }
        data.lease(bytes, out, state.mode != "unleased");
        if state.mode == "wrong-format" {
            out.extensions.fmt = BLOB_JSON;
        }
        if state.mode == "wrong-flags" {
            out.extensions.flags = 1;
        }
        Outcome::Ready
    }
}

macro_rules! witness_door {
    ($extensions:expr) => {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::store::Ops,
            statement: Statement {
                extensions: $extensions,
                kind_tail: std::ptr::from_ref(&TAIL).cast::<KindTailHead>(),
                ..busbar_contract::abi::sdk::door::statement(NAME, "0", 64)
            },
            lifecycle: {
                validate: Ready<ValidateIn, OutHead>, open: Open, refresh: Ready<RefreshIn, OutHead>,
                retire: Ready<GenIn, OutHead>, tick: Ready<TickIn, TickOut>, drive: Ready<DriveIn, OutHead>,
                cancel: Cancel, release: Release, close: Close,
            },
            kind_ops: {
                put_key: Refuse<BlobIn, OutHead>, get_key: Refuse<IdIn, LeasedBlobOut>,
                list_keys: Refuse<InHead, LeasedListOut>, delete_key: Refuse<IdIn, OutHead>,
                list_keys_since: Refuse<U64In, LeasedListOut>, get_usage: Refuse<WindowIn, LeasedBlobOut>,
                put_usage: Refuse<PutUsageIn, OutHead>, list_metering: Refuse<U64In, LeasedListOut>,
                put_credential: Refuse<BlobIn, OutHead>, put_key_with_credential: Refuse<KeyWithCredentialIn, OutHead>,
                list_credentials: Refuse<IdIn, LeasedListOut>, revoke_credential: Refuse<IdReasonIn, OutHead>,
                list_credentials_since: Refuse<U64In, LeasedListOut>, list_audit: Refuse<InHead, LeasedListOut>,
                add_denylist: Refuse<IdReasonIn, OutHead>, list_denylist: Refuse<InHead, LeasedStrListOut>,
                list_audit_tail: Refuse<U64In, LeasedListOut>, upsert_plane_record: Refuse<UpsertPlaneRecordIn, OutHead>,
                get_plane_record: Refuse<GetPlaneRecordIn, HostBytesOut>, append_plane_record: Refuse<AppendPlaneRecordIn, OutHead>,
                list_plane_records: Refuse<ListPlaneRecordsIn, HostListOut>, list_plane_record_parents: Refuse<IdIn, LeasedStrListOut>,
                purge_plane_records_before: Refuse<KindBeforeIn, CountOut>, delete_plane_record: Refuse<KindIdIn, OutHead>,
                redeem_plane_token: Refuse<TokenIn, VerdictOut>, plane_token_live: Refuse<TokenIn, VerdictOut>,
                record_put: Refuse<RecordPutIn, OutHead>, record_get: Get, record_scan: Refuse<RecordScanIn, HostListOut>,
                add_usage_batch: Correction, add_metering_batch: Refuse<OpBlobsIn, OutHead>,
            },
        }
    };
}

pub mod negotiated {
    use super::*;
    witness_door!(CAP);
}
pub mod legacy {
    use super::*;
    witness_door!(Blob::ABSENT);
}
