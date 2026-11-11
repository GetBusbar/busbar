// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::{
    abi::mechanism::{rendering::ReadMeasurementClass, KindCode},
    conn::InstanceId,
    services::Caller,
};
use busbar_kernel_ledger::cost::UnitRate;

fn binding(kind: KindCode) -> Binding {
    Binding {
        caller: Caller::issue(&busbar_kernel::seal::acquire(), "primary".into(), kind),
        instance: InstanceId(7),
        statement_digest: [1; 32],
        classes: vec![ReadMeasurementClass {
            class: "images".into(),
            family: "count".into(),
        }]
        .into(),
    }
}

#[test]
fn measurement_root_checks_declared_classes_for_every_kind() {
    for kind in KindCode::ALL {
        let authority = RootAuthority::default();
        let binding = binding(kind);
        assert!(authority.admit(&binding).is_ok()); // Missing price warns; measurement remains legal.
        authority.0.write().unwrap().rates.insert(
            kind.word().into(),
            [(
                "primary".into(),
                [("tokens".into(), UnitRate::from_nanos(0))].into(),
            )]
            .into(),
        );
        assert_eq!(authority.admit(&binding), Err(Refusal::Malformed));
        authority.0.write().unwrap().rates.insert(
            kind.word().into(),
            [(
                "primary".into(),
                [("images".into(), UnitRate::from_nanos(0))].into(),
            )]
            .into(),
        );
        assert!(authority.admit(&binding).is_ok());
    }
}

#[test]
fn measurement_root_lifecycle_cannot_report_or_bypass_operational_custody() {
    let authority = RootAuthority::default();
    for kind in KindCode::ALL {
        let binding = binding(kind);
        let open = authority.reserve(&binding, None, slot::OPEN).unwrap();
        assert!(open.is_maintenance());
        assert_eq!(open.revision(), 0);
        assert_eq!(
            open.capture(CapturedBatch {
                revision: 1,
                counts: vec![]
            }),
            Err(Refusal::Malformed)
        );
        assert!(matches!(
            authority.reserve(&binding, None, slot::TICK),
            Err(Refusal::Unavailable)
        ));
        assert!(matches!(
            authority.reserve(&binding, None, slot::DRIVE),
            Err(Refusal::Unavailable)
        ));
        let foreign: Context = Arc::new("untrusted attribution");
        assert!(matches!(
            authority.reserve(&binding, Some(&foreign), slot::OPEN),
            Err(Refusal::Malformed)
        ));
        let maintenance: Context = Arc::new(Maintenance);
        assert!(authority
            .reserve(&binding, Some(&maintenance), 9)
            .unwrap()
            .is_maintenance());
    }
}

#[test]
fn measurement_root_lost_request_never_becomes_system_usage() {
    let authority = RootAuthority::default();
    let context: Context = Arc::new(Request {
        money: Weak::new(),
        unit: UnitKey::new(1),
        preadmission: MeasurementContext::request(
            &busbar_kernel::seal::acquire(),
            1,
            "original".into(),
            String::new(),
            vec![],
            1,
            busbar_kernel_ledger::cost::RawRateEra::legacy(0),
        )
        .unwrap(),
    });
    assert!(matches!(
        authority.reserve(&binding(KindCode::Hook), Some(&context), 9),
        Err(Refusal::Unavailable)
    ));
}
