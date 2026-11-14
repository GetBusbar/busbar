// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::records::ModelTokens;
use std::collections::BTreeMap;

fn usage(model: &str, sum: bool, requests: u64, billable: u64, input: i128) -> UsageCell {
    UsageCell {
        bucket: "bucket".into(),
        window: 0,
        model: model.into(),
        sum_requests: sum,
        ledger: UsageLedger {
            requests,
            billable_requests: billable,
            models: if model.is_empty() {
                vec![]
            } else {
                vec![ModelTokens {
                    scale: 6,
                    model: model.into(),
                    usage_units: BTreeMap::from([("input".into(), input)]),
                }]
            },
        },
    }
}
#[test]
fn explicit_request_aggregation_preserves_counts_without_rescaling() {
    let row = assemble_usage(&[
        usage("m", false, 0, 0, 7_000_000),
        usage("", false, 4, 3, 0),
    ])
    .unwrap();
    assert_eq!(
        (row.requests, row.billable_requests, row.total_input()),
        (4, 3, 7_000_000)
    );
    let row = assemble_usage(&[
        usage("a", true, 4, 3, 7_000_000),
        usage("b", true, 4, 3, 7_000_000),
    ])
    .unwrap();
    assert_eq!(
        (row.requests, row.billable_requests, row.total_input()),
        (8, 6, 14_000_000)
    );
    assert!(assemble_usage(&[usage("a", true, 4, 3, 7), usage("b", false, 4, 3, 7)]).is_err());
}
#[test]
fn admitted_credential_envelope_and_wide_metadata_keep_native_custody_rules() {
    let mut meta = CredentialMeta {
        id: "id".into(),
        key_id: "key".into(),
        kind: "fixture".into(),
        slot: 0,
        public_id: "public".into(),
        secret_form: busbar_contract::records::SecretForm::Recoverable,
        created_at: 1u64 << 63,
        updated_at: 1u64 << 63,
        expires_at: Some((1u64 << 63) + 1),
        revoked_at: None,
        revoke_reason: None,
        revision: 1,
    };
    let row = HistoricalRow::Credential(Credential {
        meta: meta.clone(),
        envelope: Some(b"v1:plain:secret"),
    });
    let live = canonical_identity(&row, false).unwrap();
    assert!(live
        .iter()
        .any(|(_, v)| v.expose(&crate::seal::lend()) == b"v1:plain:secret"));
    // A deleted owner cannot legitimize a still-live historical credential.
    assert!(canonical_identity(&row, true).is_err());
    meta.revoked_at = Some((1u64 << 63) + 2);
    let rows = canonical_identity(
        &HistoricalRow::Credential(Credential {
            meta,
            envelope: Some(b"v1:plain:secret"),
        }),
        false,
    )
    .unwrap();
    assert!(rows
        .iter()
        .all(|(_, v)| v.expose(&crate::seal::lend()) != b"v1:plain:secret"));
}
