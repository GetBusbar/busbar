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
//!
//! The `life` witness is a kind built on the SDK's generic lifecycle (`lifecycle: life(L)`), whose
//! `validate` and `open` both refuse with an OWNED reason: no instance exists to keep it, so the
//! SDK writes it into the reason buffer the host lent the call.
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
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::store::{
        Cap, CapsRefused, Cell, Grant, Op, OpResult, ReserveRefused, Scanned, Step, StoreSlots,
        Tail,
    };
    use busbar_contract::abi::store::OpId;
    use busbar_contract::kinds::{Head, RecordBytes};
    use busbar_contract::records::{
        AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
        PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
    };

    /// Its Statement name: the name the host knows it by.
    pub const NAME: &str = "open-reason-store";

    /// A store that never opens.
    pub struct NeverOpens;

    impl StoreSlots for NeverOpens {
        const TAIL: Tail = Tail {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
        };

        fn validate(_: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn open(settings: &[u8], _: Option<Host>) -> Result<Self, String> {
            Err(super::reason(&String::from_utf8_lossy(settings)))
        }
        fn add_usage_op(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &str,
            _: u64,
            _: &UsageDelta,
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn add_metering_op(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &MeteringDelta,
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn append_audit_op(&self, _: &mut Op<'_>, _: OpId, _: &AuditRecord) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn append_plane_record_op(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: PlaneRecordRef<'_>,
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn append_batch(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &str,
            _: &[RecordBytes],
        ) -> Step<OpResult<Head>> {
            unreachable!("the open-reason store never opens")
        }
        fn heads(&self, _: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
            unreachable!("the open-reason store never opens")
        }
        fn session_put(
            &self,
            _: &mut Op<'_>,
            _: u64,
            _: &str,
            _: &str,
        ) -> Step<Result<(), String>> {
            unreachable!("the open-reason store never opens")
        }
        fn session_remove(&self, _: &mut Op<'_>, _: u64) -> Step<Result<(), String>> {
            unreachable!("the open-reason store never opens")
        }
        fn sessions_for(
            &self,
            _: &mut Op<'_>,
            _: &str,
        ) -> Step<Result<Vec<(u64, String)>, String>> {
            unreachable!("the open-reason store never opens")
        }
        fn record_put(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &[u8],
            _: &[u8],
        ) -> Step<Result<(), String>> {
            unreachable!("the open-reason store never opens")
        }
        fn record_get(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &[u8],
        ) -> Step<Result<Option<RecordBytes>, String>> {
            unreachable!("the open-reason store never opens")
        }
        fn record_scan(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &[u8],
            _: u32,
        ) -> Step<Result<Scanned, String>> {
            unreachable!("the open-reason store never opens")
        }
        fn reserve<'c>(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: u64,
            _: impl Iterator<Item = Cell<'c>> + Clone,
            _: &mut impl Extend<Grant>,
        ) -> Step<Result<(), ReserveRefused>> {
            unreachable!("the open-reason store never opens")
        }
        fn slice_release(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: u64,
            _: impl Iterator<Item = (u64, u64)> + Clone,
            _: &mut impl Extend<u64>,
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn add_usage_batch(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &[(&str, u64, UsageDelta)],
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn add_metering_batch(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &[MeteringDelta],
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn append_audit_batch(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &[AuditRecord],
        ) -> Step<OpResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn window_caps(
            &self,
            _: &mut Op<'_>,
            _: OpId,
            _: &[Cap<'_>],
        ) -> Step<Result<(), CapsRefused>> {
            unreachable!("the open-reason store never opens")
        }
        fn put_key(&self, _: &mut Op<'_>, _: &VirtualKey) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn get_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_keys(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
            unreachable!("the open-reason store never opens")
        }
        fn delete_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn scrub_key(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_keys_since(
            &self,
            _: &mut Op<'_>,
            _: u64,
        ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
            unreachable!("the open-reason store never opens")
        }
        fn get_usage(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: u64,
        ) -> Step<RecordStoreResult<UsageLedger>> {
            unreachable!("the open-reason store never opens")
        }
        fn put_usage(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: u64,
            _: &UsageLedger,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_metering(
            &self,
            _: &mut Op<'_>,
            _: u64,
        ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
            unreachable!("the open-reason store never opens")
        }
        fn purge_windows_before(&self, _: &mut Op<'_>, _: u64) -> Step<RecordStoreResult<u64>> {
            unreachable!("the open-reason store never opens")
        }
        fn purge_metering_before(&self, _: &mut Op<'_>, _: &str) -> Step<RecordStoreResult<u64>> {
            unreachable!("the open-reason store never opens")
        }
        fn put_credential(
            &self,
            _: &mut Op<'_>,
            _: &CredentialSecret,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn put_key_with_credential(
            &self,
            _: &mut Op<'_>,
            _: &VirtualKey,
            _: &CredentialSecret,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_credentials(
            &self,
            _: &mut Op<'_>,
            _: &str,
        ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
            unreachable!("the open-reason store never opens")
        }
        fn lookup_credential_secret(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
        ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
            unreachable!("the open-reason store never opens")
        }
        fn revoke_credential(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_credentials_since(
            &self,
            _: &mut Op<'_>,
            _: u64,
        ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_audit(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
            unreachable!("the open-reason store never opens")
        }
        fn add_denylist(&self, _: &mut Op<'_>, _: &str, _: &str) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_denylist(&self, _: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_audit_tail(
            &self,
            _: &mut Op<'_>,
            _: u64,
        ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
            unreachable!("the open-reason store never opens")
        }
        fn upsert_plane_record(
            &self,
            _: &mut Op<'_>,
            _: PlaneRecordRef<'_>,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn get_plane_record(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
        ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_plane_records(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &PlaneSelector<'_>,
        ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
            unreachable!("the open-reason store never opens")
        }
        fn list_plane_record_parents(
            &self,
            _: &mut Op<'_>,
            _: &str,
        ) -> Step<RecordStoreResult<Vec<String>>> {
            unreachable!("the open-reason store never opens")
        }
        fn purge_plane_records_before(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: u64,
        ) -> Step<RecordStoreResult<u64>> {
            unreachable!("the open-reason store never opens")
        }
        fn delete_plane_record(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
        ) -> Step<RecordStoreResult<()>> {
            unreachable!("the open-reason store never opens")
        }
        fn redeem_plane_token(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
            _: u64,
            _: u64,
        ) -> Step<RecordStoreResult<bool>> {
            unreachable!("the open-reason store never opens")
        }
        fn plane_token_live(
            &self,
            _: &mut Op<'_>,
            _: &str,
            _: &str,
            _: u64,
            _: u64,
        ) -> Step<RecordStoreResult<bool>> {
            unreachable!("the open-reason store never opens")
        }
    }

    busbar_contract::store_door!(NeverOpens, NAME, "0", 1);
}

/// The generic-lifecycle witness: a secret kind whose `validate` and `open` refuse in their own
/// (owned) words.
pub mod life {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

    /// Its Statement name: the name the host knows it by.
    pub const NAME: &str = "open-reason-life";

    /// A state that never opens.
    pub struct Words;

    impl Life for Words {
        const CANCEL: u32 = 0;

        fn validate(settings: &[u8]) -> Result<(), Refusal> {
            Err(Refusal::failed(format!(
                "invalid: {}",
                String::from_utf8_lossy(settings)
            )))
        }

        fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Err(Refusal::failed(super::reason(&String::from_utf8_lossy(
                settings,
            ))))
        }

        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    /// `resolve`: unreachable, since no instance ever exists.
    pub struct Resolve;
    impl SafeSlot for Resolve {
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<Words>;
        fn call(
            _: Instance<'_, Held<Words>>,
            _: Lent<'_, ResolveIn>,
            _: Out<'_, ResolveOut>,
        ) -> Outcome {
            Outcome::Refused
        }
    }

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 1),
        lifecycle: life(Words),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
    }
}
