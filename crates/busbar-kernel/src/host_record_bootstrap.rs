// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Operator-attested cold record migration. A quiet host queue is never backend quiescence.

use std::sync::Arc;

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::services::Caller;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::host_records::{record_key, RecordRows};

/// Existing entitlement carrier; this entire scope kind is reserved by the host.
pub const ENTITLEMENT: &str = "record-quota-bootstrap:";
/// Durable consumed receipts. Plugins cannot declare or purge this host namespace.
pub const RECEIPT_SCHEMA: RecordSchemaId = RecordSchemaId::new("busbar.record-bootstrap.v1");
/// Startup-only operator input, never a plugin setting or an admin scope grant.
pub const RECEIPT_ENV: &str = "BUSBAR_RECORD_BOOTSTRAP_RECEIPT";

/// An exact existing public row identifying the operator's selected backing store/namespace.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreWitness {
    pub schema: String,
    pub key_hex: String,
    pub value_hex: String,
}

/// The operator must stop every old sender AND settle/abort its backend commands before issuing
/// this receipt. Neither process death, plugin unload, nor lease expiry establishes these facts.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColdRecordReceipt {
    pub version: u32,
    pub epoch: String,
    pub instance: String,
    pub namespace_hex: String,
    pub store_config_sha256: String,
    pub store_witness: StoreWitness,
    pub sender_quiesced: bool,
    pub backend_quiesced: bool,
    pub actor: String,
    pub reason: String,
}

/// Hash the exact effective store configuration selected for this cold process.
#[must_use]
pub fn store_fingerprint(store: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(store.to_string().as_bytes()))
}

pub(crate) struct Bootstrap {
    pub instance: String,
    // Kept for audit/debug correlation. This receipt can never authorize another cold process.
    pub epoch: String,
    caller: Option<Caller>,
}

impl Bootstrap {
    /// Receipt consumption and the store witness comparison are one durable transaction. An
    /// unknown outcome grants nothing, even if the consume later commits. A fresh attestation and
    /// epoch are required after any failed boot, including a crash following consumption.
    pub fn consume(
        receipt: ColdRecordReceipt,
        expected_store: &str,
        rows: &dyn RecordRows,
    ) -> Result<Self, &'static str> {
        let epoch = hex::decode(&receipt.epoch).map_err(|_| "invalid bootstrap epoch")?;
        if receipt.version != 1
            || epoch.len() != 16
            || epoch.iter().all(|byte| *byte == 0)
            || hex::encode(&epoch) != receipt.epoch
            || receipt.instance.is_empty()
            || receipt.instance.len() > usize::from(u16::MAX)
            || receipt.instance.chars().any(char::is_control)
            || receipt.namespace_hex != hex::encode(record_key(&receipt.instance, &[]))
            || receipt.store_config_sha256 != expected_store
            || !receipt.sender_quiesced
            || !receipt.backend_quiesced
            || receipt.actor.trim().is_empty()
            || receipt.actor.len() > 256
            || receipt.reason.trim().is_empty()
            || receipt.reason.len() > 4096
            || !rows.supports_record_transaction()
        {
            return Err("invalid cold record bootstrap receipt or store binding");
        }
        let witness = &receipt.store_witness;
        let key = hex::decode(&witness.key_hex).map_err(|_| "invalid store witness key")?;
        let value = hex::decode(&witness.value_hex).map_err(|_| "invalid store witness value")?;
        if witness.schema.is_empty()
            || witness.schema.len() > 256
            || witness.schema == RECEIPT_SCHEMA.as_str()
            || value.is_empty()
        {
            return Err("invalid store witness");
        }
        // Global per-store epoch, rather than per-instance: editing the instance cannot reuse it.
        let receipt_key = epoch;
        let receipt_digest = Sha256::digest(
            serde_json::to_vec(&receipt).map_err(|_| "invalid bootstrap receipt encoding")?,
        );
        let request = zeroize::Zeroizing::new(Request {
            version: VERSION,
            op_id: crate::door::op_id(),
            predicates: vec![
                Predicate {
                    schema: witness.schema.clone(),
                    key,
                    expected: Expected::Bytes(value),
                },
                Predicate {
                    schema: RECEIPT_SCHEMA.as_str().into(),
                    key: receipt_key.clone(),
                    expected: Expected::Absent,
                },
            ],
            mutations: vec![Mutation::Put {
                schema: RECEIPT_SCHEMA.as_str().into(),
                key: receipt_key,
                value: receipt_digest.to_vec(),
            }],
        });
        request
            .encode_held()
            .map_err(|_| "invalid bootstrap store transaction")?;
        match rows.record_transaction(&request) {
            Ok(Decision::Applied) => Ok(Self {
                instance: receipt.instance,
                epoch: receipt.epoch,
                caller: None,
            }),
            Ok(Decision::ConditionConflict) => {
                Err("bootstrap receipt consumed or wrong store witness")
            }
            Err(_) => Err("bootstrap receipt consumption was not definitively acknowledged"),
        }
    }

    /// Host-issued caller identity, not an instance-label comparison. Clones share this identity;
    /// a new opened plugin with identical text cannot inherit the first generation's grant.
    pub fn accepts(&self, caller: &Caller) -> bool {
        if caller.instance.as_ref() != self.instance {
            return true;
        }
        self.caller.as_ref().is_some_and(|held| {
            Arc::ptr_eq(&held.instance, &caller.instance)
                && Arc::ptr_eq(&held.plugin, &caller.plugin)
                && held.kind == caller.kind
        })
    }

    pub fn bind_caller(&mut self, caller: &Caller) -> Result<(), &'static str> {
        if self.caller.is_some() {
            return Err("cold bootstrap caller was already bound");
        }
        self.caller = Some(caller.clone());
        Ok(())
    }

    pub fn bound(&self) -> bool {
        self.caller.is_some()
    }
}

#[cfg(test)]
#[path = "tests/host_record_bootstrap_tests.rs"]
mod tests;
