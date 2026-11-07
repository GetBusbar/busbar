// SPDX-License-Identifier: Apache-2.0
//! Historical node-journal transformations remain separate from serving boot.
use super::*;
use busbar_kernel::config::RateEntryCfg;

fn card(input: f64, fee: i64) -> CardFields {
    CardFields {
        rate_card: Some(BTreeMap::from([(
            "m".to_string(),
            RateEntryCfg {
                input_utok: input,
                output_utok: input * 2.0,
                ..RateEntryCfg::default()
            },
        )])),
        per_request_fee: fee,
        ..CardFields::default()
    }
}

#[test]
fn the_journals_cards_migrate_under_time_keys_and_collapse_duplicates() {
    use crate::root::kernel::{card_from_raw, CardApplied, CardForm};
    let applied = |card: &CardFields, from: u64, at: u64| {
        let rates = card.rates();
        let built = card_from_raw(&rates.raw());
        CardApplied {
            effective_from: from,
            appended_at: at,
            policy_epoch: 0,
            form: CardForm::of(&rates.raw(), &built),
        }
    };
    let record = |node: u64, seq: u64, a: &CardApplied| busbar_kernel_wal::JournalRecord {
        class: busbar_kernel_wal::RecordClass::Policy,
        node,
        node_seq: seq,
        lease_epoch: 0,
        policy_epoch: 0,
        wall: a.appended_at / 1000,
        mono: 0,
        body: a.body(),
        body_hash: [0; 32],
        prev_hash: [0; 32],
        hash: [0; 32],
    };
    let boot = card(1.0, 0);
    let edit = card(1.0, 3);
    let chains = vec![
        (
            1,
            vec![
                record(1, 1, &applied(&boot, 0, 1_000)),
                record(1, 2, &applied(&edit, 5_000, 5_000)),
            ],
        ),
        // Node 2 opened later with the same card and journalled the same edit too.
        (
            2,
            vec![
                record(2, 1, &applied(&boot, 0, 2_000)),
                record(2, 2, &applied(&edit, 5_000, 5_000)),
            ],
        ),
    ];
    let migrated = super::migrated(&chains, 9);
    assert_eq!(migrated.len(), 2, "one opening and one edit: {migrated:#?}");
    assert_eq!(migrated[0].key.t_ms(), 1_000, "the oldest opening is kept");
    assert_eq!(migrated[0].card, boot);
    assert_eq!(migrated[1].card, edit);
    assert_eq!(migrated[1].key, EntryKey::new(5_000, 1u64.to_be_bytes(), 2));

    let snapshot = busbar_kernel::governance::persistence::prices::Snapshot {
        entries: migrated
            .into_iter()
            .map(|entry| (entry.key, entry))
            .collect(),
        ..Default::default()
    };
    let history = snapshot.history(super::rate_card_of);
    assert_eq!(
        history
            .current()
            .card_at(4_999)
            .map(|(_, card)| card.clone()),
        Some(super::rate_card_of(&boot))
    );
    assert_eq!(
        history
            .current()
            .card_at(5_000)
            .map(|(_, card)| card.clone()),
        Some(super::rate_card_of(&edit))
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn the_migration_prices_every_instant_as_devs_rebuild_did_with_a_refused_correction() {
    for keyed in [false, true] {
        use crate::root::kernel::{
            card_from_raw, CardApplied, CardForm, CorrectionBase, RootHistory,
        };
        use crate::root::units_admin::{amendment_body, AmendmentRecord};
        let applied = |card: &CardFields, from: u64, at: u64| {
            let rates = card.rates();
            let built = card_from_raw(&rates.raw());
            CardApplied {
                effective_from: from,
                appended_at: at,
                policy_epoch: 0,
                form: CardForm::of(&rates.raw(), &built),
            }
        };
        let record = |seq: u64, body: Vec<u8>| busbar_kernel_wal::JournalRecord {
            class: busbar_kernel_wal::RecordClass::Policy,
            node: 1,
            node_seq: seq,
            lease_epoch: 0,
            policy_epoch: 0,
            wall: 0,
            mono: 0,
            body,
            body_hash: [0; 32],
            prev_hash: [0; 32],
            hash: [0; 32],
        };
        let correction = |seq: u64, digest: [u8; 32], at: u64, nanos: u64| AmendmentRecord {
            version: if keyed {
                crate::root::units_admin::AmendmentVersion::V4
            } else {
                crate::root::units_admin::AmendmentVersion::V3
            },
            effective_from: 5_000,
            effective_until: Some(6_000),
            amended_at_ms: at,
            sealed_over: Some(if keyed {
                CorrectionBase::Key {
                    key: EntryKey::new(5_000, [0; 8], 1),
                    card_digest: digest,
                }
            } else {
                CorrectionBase::LegacyOrdinal {
                    seq: busbar_kernel_ledger::cost::HistorySeq(seq),
                    card_digest: digest,
                }
            }),
            sealed_fee: 3,
            rates: vec![("m".to_string(), "input".to_string(), Some(nanos))],
            operator_fingerprint: String::new(),
            reason_hash: [1; 32],
            principal: "op".to_string(),
            dual_control: "single".to_string(),
            signed_payload: Vec::new(),
            signature: String::new(),
        };
        let (boot, edit) = (card(1.0, 0), card(1.0, 3));
        let (a0, a1) = (applied(&boot, 0, 1_000), applied(&edit, 5_000, 5_000));
        let edit_digest = a1.form.card().digest();
        let records = vec![
            record(1, a0.body()),
            record(2, a1.body()),
            // Sealed over entry 1 with the WRONG digest: dev's rebuild refuses it.
            record(
                3,
                amendment_body(&correction(1, [9; 32], 7_000, 50_000))
                    .expect("valid legacy correction"),
            ),
            // Sealed over entry 1 with its own digest: rebuilt.
            record(
                4,
                amendment_body(&correction(1, edit_digest, 8_000, 4_000))
                    .expect("valid legacy correction"),
            ),
        ];
        let dev = RootHistory::restore(crate::root::kernel::journalled_cards(&records), Vec::new());
        assert_eq!(
            dev.history.len(),
            3,
            "dev's rebuild left the refused correction out"
        );

        let migrated = super::migrated(&[(1, records.clone())], 9);
        assert_eq!(
            migrated.len(),
            3,
            "and so does the migration: {migrated:#?}"
        );
        let snapshot = busbar_kernel::governance::persistence::prices::Snapshot {
            entries: migrated
                .into_iter()
                .map(|entry| (entry.key, entry))
                .collect(),
            ..Default::default()
        };
        let ours = snapshot.history(super::rate_card_of);
        for t in [0, 4_999, 5_000, 5_500, 5_999, 6_000, 9_999] {
            let dev_view = dev.history.current();
            let our_view = ours.current();
            let dev_card = dev_view.card_at(t).map(|(_, c)| c.clone());
            let our_card = our_view.card_at(t).map(|(_, c)| c.clone());
            assert_eq!(our_card, dev_card, "the card at {t} is dev's");
        }
    }
}
