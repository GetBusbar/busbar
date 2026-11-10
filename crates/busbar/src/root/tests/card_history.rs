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
    let migrated = super::migrated(&chains, 9).expect("representable journal sequences");
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

        let migrated =
            super::migrated(&[(1, records.clone())], 9).expect("representable journal sequences");
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

fn same_timestamp_chain(sequences: &[u64]) -> Chain {
    use crate::root::kernel::{card_from_raw, CardApplied, CardForm};
    let records = sequences
        .iter()
        .enumerate()
        .map(|(index, &node_seq)| {
            let fields = card(1.0, i64::try_from(index).unwrap());
            let rates = fields.rates();
            let applied = CardApplied {
                effective_from: u64::try_from(index).unwrap() * 100,
                appended_at: 1_000,
                policy_epoch: 0,
                form: CardForm::of(&rates.raw(), &card_from_raw(&rates.raw())),
            };
            busbar_kernel_wal::JournalRecord {
                class: busbar_kernel_wal::RecordClass::Policy,
                node: 1,
                node_seq,
                lease_epoch: 0,
                policy_epoch: 0,
                wall: 1,
                mono: 0,
                body: applied.body(),
                body_hash: [0; 32],
                prev_hash: [0; 32],
                hash: [0; 32],
            }
        })
        .collect();
    (1, records)
}

#[test]
fn migration_refuses_large_sequences_without_returning_partial_or_colliding_history() {
    let max = u64::from(u32::MAX);
    for sequences in [
        // Truncation aliases sequence 1; saturation aliases the maximum counter.
        vec![1, max + 2],
        vec![max, max + 1],
        // Saturation also collapses different large sequences onto each other.
        vec![1, max + 1, max + 2],
        vec![1, u64::MAX - 1, u64::MAX],
    ] {
        let refused = *sequences.iter().find(|&&seq| seq > max).unwrap();
        let chains = [same_timestamp_chain(&sequences)];
        let error = super::migrated(&chains, 9)
            .expect_err("an unrepresentable sequence must refuse the entire history");
        assert_eq!(
            error,
            format!(
                "cannot migrate rate-card history: node 1 journal sequence {refused} exceeds \
                 the entry key's 32-bit counter; no history was converted"
            )
        );
        assert_eq!(chains[0].1.len(), sequences.len(), "source remains intact");
    }
}

#[test]
fn migration_preserves_boundary_sequences_and_same_timestamp_order_in_stored_history() {
    let sequences = [1, u64::from(u32::MAX) - 1, u64::from(u32::MAX)];
    let entries = super::migrated(&[same_timestamp_chain(&sequences)], 9)
        .expect("every sequence fits without remapping");
    assert_eq!(entries.len(), sequences.len());
    let mut snapshot = busbar_kernel::governance::persistence::prices::Snapshot::default();
    for (index, entry) in entries.into_iter().enumerate() {
        assert_eq!(
            entry.key,
            EntryKey::new(
                1_000,
                1u64.to_be_bytes(),
                u32::try_from(sequences[index]).unwrap()
            )
        );
        assert!(
            matches!(entry.author, EntryAuthor::Migrated { node_seq, .. } if node_seq == sequences[index])
        );
        let restored = StoredEntry::from_value(entry.key, &entry.value()).unwrap();
        assert_eq!(restored, entry);
        assert!(snapshot.entries.insert(restored.key, restored).is_none());
    }
    assert_eq!(snapshot.entries.len(), sequences.len());
    let history = snapshot.history(super::rate_card_of);
    for (at, fee) in [(0, 0), (99, 0), (100, 1), (199, 1), (200, 2), (1_000, 2)] {
        assert_eq!(
            history.current().card_at(at).map(|(_, card)| card.clone()),
            Some(super::rate_card_of(&card(1.0, fee))),
            "same-timestamp ordering preserves the price at {at}"
        );
    }
}
