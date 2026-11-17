// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::budget::*;

#[test]
fn general_saturation_preserves_one_protected_reply_and_rolls_back_failure() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let general = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert!(unit
        .reserve(
            Claim {
                bytes: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    let before = unit.used();
    let reply = unit
        .reserve_reply(
            Claim {
                bytes: REPLY_BYTES,
                completions: 1,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(unit.used().bytes, UNIT_BYTES);
    assert!(unit
        .reserve_reply(
            Claim {
                completions: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    drop(reply);
    assert_eq!(unit.used(), before);
    drop(general);
    assert_eq!(unit.used(), Claim::default());
}

#[test]
fn instance_accounts_span_units_and_process_accounts_span_instances() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(
            instance
                .unit()
                .reserve(
                    Claim {
                        keys: 8,
                        ..Claim::default()
                    },
                    None,
                )
                .unwrap(),
        );
    }
    assert!(instance
        .unit()
        .reserve(
            Claim {
                keys: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    for _ in 0..3 {
        held.push(
            process
                .instance()
                .unit()
                .reserve(
                    Claim {
                        keys: 64,
                        ..Claim::default()
                    },
                    None,
                )
                .unwrap(),
        );
    }
    assert!(process
        .instance()
        .unit()
        .reserve(
            Claim {
                keys: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    held.clear();
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn channel_scope_rejects_foreign_instances_and_keeps_reply_writer_cell() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let channel = instance.link();
    let other = process.instance().unit();
    assert!(other
        .reserve(
            Claim {
                messages: 1,
                ..Claim::default()
            },
            Some(&channel)
        )
        .is_err());
    let unit = instance.unit();
    let held = unit
        .reserve(
            Claim {
                messages: 63,
                ..Claim::default()
            },
            Some(&channel),
        )
        .unwrap();
    assert!(unit
        .reserve(
            Claim {
                messages: 1,
                ..Claim::default()
            },
            Some(&channel)
        )
        .is_err());
    let reply = unit
        .reserve_reply(
            Claim {
                messages: 1,
                ..Claim::default()
            },
            Some(&channel),
        )
        .unwrap();
    assert!(unit
        .reserve_reply(
            Claim {
                messages: 1,
                ..Claim::default()
            },
            Some(&channel)
        )
        .is_err());
    drop((held, reply));
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn split_charge_survives_origin_drop_and_reclassification_is_atomic() {
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let mut charge = unit
        .reserve_reply(
            Claim {
                bytes: REPLY_BYTES,
                completions: 1,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let writer = charge
        .split(Claim {
            bytes: 100,
            ..Claim::default()
        })
        .unwrap();
    drop(charge);
    drop(unit);
    assert_eq!(process.used().bytes, 100);
    let mut writer = writer;
    writer.reclassify_general().unwrap();
    drop(writer);
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn failed_general_reclassification_preserves_all_protected_charges() {
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let general = unit
        .reserve(
            Claim {
                bytes: UNIT_BYTES - REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let mut reply = unit
        .reserve_reply(
            Claim {
                bytes: 100,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    let before = process.used();
    assert!(reply.reclassify_general().is_err());
    assert_eq!(process.used(), before);
    drop((reply, general));
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn storage_source_uses_the_same_general_owner_and_never_spends_reply_capacity() {
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let source = unit.storage();
    let mut credit = source.try_reserve(UNIT_BYTES - REPLY_BYTES).unwrap();
    assert!(unit
        .reserve(
            Claim {
                bytes: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    assert!(source.try_reserve(1).is_err());
    let part = credit.split(100).unwrap();
    credit.try_merge(part).unwrap();
    let reply = unit
        .reserve_reply(
            Claim {
                bytes: REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(process.used().bytes, UNIT_BYTES);
    drop((reply, credit));
    assert_eq!(process.used(), Claim::default());
    let mut original = source.try_reserve(1).unwrap();
    original
        .try_merge(unit.clone().storage().try_reserve(1).unwrap())
        .unwrap();
    let foreign = process.instance().unit().storage().try_reserve(1).unwrap();
    assert!(original.try_merge(foreign).is_err());
}
