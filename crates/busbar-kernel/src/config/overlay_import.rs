// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit migration into an empty Store overlay, never a runtime file fallback.

use super::*;

const RECEIPT: &[u8] = b"migration:1.5.5:file";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    source_sha256: [u8; 32],
    overlay_sha256: [u8; 32],
}

impl OverlayStore {
    /// Publish a validated, converted old overlay exactly once. The receipt and the visible
    /// head commit in one conditional transaction. Source bytes never enter the receipt.
    /// `false` means this same import already committed, even if later admin edits changed it.
    /// The caller must stop the old deployment, validate the effective configuration, and exit
    /// after this maintenance operation rather than serving a partly recovered generation.
    pub fn import_once(&self, source_sha256: [u8; 32], doc: &OverlayDoc) -> Result<bool, String> {
        let mut value = serde_json::to_value(doc).map_err(|e| e.to_string())?;
        value["version"] = super::super::overlay::OVERLAY_VERSION.into();
        canonicalize(&mut value);
        let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        let receipt = Receipt {
            version: 1,
            source_sha256,
            overlay_sha256: Sha256::digest(&bytes).into(),
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        if let Some(saved) =
            wait(self.calls.record_get(SCHEMA, RECEIPT)).map_err(|e| e.to_string())?
        {
            check_receipt(saved.as_slice(), &receipt)?;
            self.read_required()?
                .ok_or("overlay migration receipt has no readable destination head")?;
            return Ok(false);
        }
        if wait(self.calls.record_get(SCHEMA, HEAD))
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("overlay migration refuses an existing Store overlay without its matching migration receipt".into());
        }

        // A retry after an interrupted write uses the same immutable chunks and transaction.
        // The domain separates this id from ordinary randomly generated admin transactions.
        let mut hash = Sha256::new();
        hash.update(b"busbar.overlay.file-import.v1\0");
        hash.update(&receipt_bytes);
        let digest: [u8; 32] = hash.finalize().into();
        let generation: [u8; 16] = digest[..16].try_into().expect("fixed digest width");
        let head = Head {
            version: 1,
            generation,
            length: bytes.len() as u64,
            digest: receipt.overlay_sha256,
        };
        for (index, chunk) in bytes.chunks(busbar_contract::MAX_RECORD_BYTES).enumerate() {
            let value = RecordBytes::new(chunk.to_vec()).map_err(|e| e.to_string())?;
            wait(
                self.calls
                    .record_put(SCHEMA, &chunk_key(&generation, index as u64), &value),
            )
            .map_err(|e| e.to_string())?;
        }
        let request = Request {
            version: VERSION,
            op_id: busbar_contract::abi::store::OpId(generation),
            predicates: vec![
                Predicate {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    expected: Expected::Absent,
                },
                Predicate {
                    schema: SCHEMA.into(),
                    key: RECEIPT.to_vec(),
                    expected: Expected::Absent,
                },
            ],
            mutations: vec![
                Mutation::Put {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    value: serde_json::to_vec(&head).map_err(|e| e.to_string())?,
                },
                Mutation::Put {
                    schema: SCHEMA.into(),
                    key: RECEIPT.to_vec(),
                    value: receipt_bytes,
                },
            ],
        };
        match wait(self.calls.record_transaction(&request)).map_err(|e| e.to_string())? {
            Decision::Applied => Ok(true),
            Decision::ConditionConflict => {
                // Another process may have completed this exact import. Never overwrite its head
                // or remove its chunks; a differing source or conversion remains a hard refusal.
                let saved = wait(self.calls.record_get(SCHEMA, RECEIPT))
                    .map_err(|e| e.to_string())?
                    .ok_or(
                        "overlay changed while migration was committing; no import receipt exists",
                    )?;
                check_receipt(saved.as_slice(), &receipt)?;
                self.read_required()?
                    .ok_or("overlay migration receipt has no readable destination head")?;
                Ok(false)
            }
        }
    }
}

fn check_receipt(bytes: &[u8], expected: &Receipt) -> Result<(), String> {
    let receipt: Receipt =
        serde_json::from_slice(bytes).map_err(|_| "overlay migration receipt is unreadable")?;
    if &receipt != expected {
        return Err("overlay migration source or converted configuration differs from the committed receipt".into());
    }
    Ok(())
}

fn canonicalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let ordered: std::collections::BTreeMap<_, _> =
                std::mem::take(map).into_iter().collect();
            for (key, mut child) in ordered {
                canonicalize(&mut child);
                map.insert(key, child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(canonicalize),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_overlay_import_survives_reopen_and_never_replays_over_admin_changes() {
        let calls = crate::real_store::store();
        let source = Sha256::digest(b"old deployment and overlay").into();
        let mut doc = OverlayDoc::default();
        doc.deleted = vec!["removed-security-hook".into()];
        doc.deleted_groups = vec!["removed-grant".into()];
        doc.root = Some(super::super::super::overlay::RootSettings {
            per_request_fee: Some(7),
            ..Default::default()
        });
        let store = OverlayStore::new(calls.clone()).unwrap();
        assert!(store.import_once(source, &doc).unwrap());
        let restarted = OverlayStore::new(calls.clone()).unwrap();
        let loaded = restarted.read_required().unwrap().unwrap();
        assert_eq!(loaded.deleted, doc.deleted);
        assert_eq!(loaded.deleted_groups, doc.deleted_groups);
        assert_eq!(loaded.root.unwrap().per_request_fee, Some(7));
        restarted
            .update(|current| current.deleted_groups.push("later-revocation".into()))
            .unwrap();
        let again = OverlayStore::new(calls).unwrap();
        assert!(!again.import_once(source, &doc).unwrap());
        assert!(again
            .read_required()
            .unwrap()
            .unwrap()
            .deleted_groups
            .contains(&"later-revocation".into()));
        assert!(again
            .import_once([9; 32], &doc)
            .unwrap_err()
            .contains("differs"));
    }

    #[test]
    fn old_overlay_import_refuses_an_unrelated_existing_destination() {
        let store = OverlayStore::new(crate::real_store::store()).unwrap();
        store
            .update(|doc| doc.deleted_groups.push("current-revocation".into()))
            .unwrap();
        assert!(store
            .import_once([1; 32], &OverlayDoc::default())
            .unwrap_err()
            .contains("existing Store overlay"));
        assert_eq!(
            store.read_required().unwrap().unwrap().deleted_groups,
            ["current-revocation"]
        );
    }
}
