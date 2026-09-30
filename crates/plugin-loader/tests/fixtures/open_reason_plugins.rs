// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPEN-REASON WITNESS — a store whose `open` never succeeds, built with its kind's SDK door
//! (`store_door!`), so the reason rides the SDK's own failed-open path into the host's lent reason
//! buffer (`OpenIn::err_buf`).
//!
//! The settings ARE the reason: `open` fails with the settings text verbatim, and with NO text
//! when the settings are absent or `{}`.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED door) and built as
//! the `open_reason_store_door` example cdylib behind one `export_door!` line (the DROPPED door).
#![allow(dead_code)]

/// The reason a witness fails its `open` with: its settings, verbatim; none for absent settings.
fn reason(settings: &str) -> String {
    match settings {
        "" | "{}" => String::new(),
        s => s.to_owned(),
    }
}

/// The store witness: a store that never opens, so no other slot is ever reached.
pub mod store {
    use busbar_contract::abi::sdk::store::{
        Cap, CapsRefused, Cell, Grant, OpResult, ReserveRefused, StoreSlots, Tail,
    };
    use busbar_contract::abi::store::OpId;
    use busbar_contract::kinds::{Head, RecordBytes};
    use busbar_contract::records::{
        AuditRecord, MeteringDelta, MeteringRow, PlaneRecord, RecordStore, RecordStoreResult,
        UsageDelta, UsageLedger, VirtualKey,
    };

    /// Its Statement name: the name the host knows it by.
    pub const NAME: &str = "open-reason-store";

    /// A store that never opens.
    pub struct NeverOpens;

    /// Every slot but `open`: unreachable, since no instance ever exists.
    macro_rules! never {
        ($($name:ident(&self $(, $a:ident: $t:ty)*) -> $r:ty;)*) => {$(
            fn $name(&self $(, $a: $t)*) -> $r {
                $(let _ = $a;)*
                unreachable!("the open-reason store never opens")
            }
        )*};
    }

    impl RecordStore for NeverOpens {
        never! {
            put_key(&self, key: &VirtualKey) -> RecordStoreResult<()>;
            get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>>;
            list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>>;
            delete_key(&self, id: &str) -> RecordStoreResult<()>;
            get_usage(&self, bucket: &str, window_start: u64) -> RecordStoreResult<UsageLedger>;
            put_usage(&self, bucket: &str, window_start: u64, ledger: &UsageLedger)
                -> RecordStoreResult<()>;
            add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()>;
            list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;
        }
    }

    impl StoreSlots for NeverOpens {
        const TAIL: Tail = Tail {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
        };

        fn open(settings: &[u8]) -> Result<Self, String> {
            Err(super::reason(&String::from_utf8_lossy(settings)))
        }

        never! {
            add_usage_op(&self, op: OpId, bucket: &str, window_start: u64, delta: &UsageDelta)
                -> OpResult<()>;
            add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()>;
            append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()>;
            append_plane_record_op(&self, op: OpId, record: &PlaneRecord) -> OpResult<()>;
            append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head>;
            heads(&self) -> Result<Vec<(String, Head)>, String>;
            session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String>;
            session_remove(&self, session: u64) -> Result<(), String>;
            sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String>;
            record_put(&self, schema: &str, key: &[u8], value: &RecordBytes)
                -> Result<(), String>;
            record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String>;
            record_scan(&self, schema: &str, prefix: &[u8], limit: u32)
                -> Result<Vec<(Vec<u8>, RecordBytes)>, String>;
            reserve(&self, op: OpId, epoch: u64, cells: &[Cell<'_>])
                -> Result<Vec<Grant>, ReserveRefused>;
            slice_release(&self, op: OpId, epoch: u64, items: &[(u64, u64)])
                -> OpResult<Vec<u64>>;
            add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
            add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()>;
            append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()>;
            window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused>;
        }
    }

    busbar_contract::store_door!(NeverOpens, NAME, "0", 1);
}
