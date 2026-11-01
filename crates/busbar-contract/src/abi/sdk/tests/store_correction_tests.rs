// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::extensions;
use crate::abi::sdk::store::dedupe::{Dedupe, Seen};
use crate::abi::store::OpId;
use crate::records::{ModelTokens, UsageLedger, UNIT_INPUT};

fn candidate() -> Request {
    let expected = UsageLedger {
        requests: u64::MAX,
        billable_requests: u64::MAX,
        models: vec![ModelTokens {
            model: "historical-model".into(),
            usage_units: [(UNIT_INPUT.into(), u64::MAX)].into(),
        }],
    };
    let mut replacement = expected.clone();
    replacement.models[0]
        .usage_units
        .insert(UNIT_INPUT.into(), u64::MAX - 1);
    Request {
        version: VERSION,
        op_id: OpId::from_parts(4, 7),
        key_id: "historical-key".into(),
        day_start: 0,
        metering: vec![],
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: "historical-key".into(),
                window_start: 0,
            },
            expected,
            replacement,
        }],
    }
}

#[test]
fn exact_unsigned_rows_roundtrip_and_bind_the_dedupe_body() {
    let request = candidate();
    let encoded = request.encode().unwrap();
    assert_eq!(Request::decode(&encoded), Ok(request.clone()));
    assert_eq!(
        intent(&extensions::encode(&[(INTENT, &encoded)])),
        Ok(Some(request.clone()))
    );
    let dedupe = Dedupe::usage_correction(&request);
    assert_eq!(dedupe.seen(Some(dedupe.body())), Seen::Replay);
    let mut changed = request.clone();
    changed.usage[0].replacement.models[0]
        .usage_units
        .insert(UNIT_INPUT.into(), u64::MAX - 2);
    assert_eq!(
        Dedupe::usage_correction(&changed).seen(Some(dedupe.body())),
        Seen::Conflict
    );
    changed = request.clone();
    changed.day_start += 1;
    assert_eq!(
        Dedupe::usage_correction(&changed).seen(Some(dedupe.body())),
        Seen::Conflict
    );
}

#[test]
fn only_exact_explicit_capability_and_complete_intent_are_accepted() {
    assert!(!supported(&[]));
    assert!(supported(&extensions::encode(&[(
        CAPABILITY,
        CAPABILITY_VALUE
    )])));
    assert!(!supported(&extensions::encode(&[(CAPABILITY, b"future")])));
    assert!(!supported(&extensions::encode(&[
        (CAPABILITY, CAPABILITY_VALUE),
        (CAPABILITY, CAPABILITY_VALUE)
    ])));
    let encoded = candidate().encode().unwrap();
    let ext = extensions::encode(&[(INTENT, &encoded)]);
    for end in 2 + INTENT.len()..ext.len() {
        assert!(intent(&ext[..end]).is_err());
    }
    assert!(intent(&extensions::encode(&[
        (INTENT, &encoded),
        (INTENT, &encoded)
    ]))
    .is_err());
    assert_eq!(intent(&[]), Ok(None));
    let mut future = candidate();
    future.version += 1;
    let encoded = serde_json::to_vec(&future).unwrap();
    assert!(intent(&extensions::encode(&[(INTENT, &encoded)])).is_err());
}

#[test]
fn missing_leases_plain_ready_and_uncorrelated_results_leave_outcome_unknown() {
    let request = candidate();
    for decision in [Decision::Applied, Decision::ConditionConflict] {
        let result = encode_result(&request, decision);
        let ext = extensions::encode(&[(RESULT, &result)]);
        assert_eq!(
            read_result(Outcome::Ready, true, &ext, &request),
            Ok(decision)
        );
        assert!(read_result(Outcome::Ready, false, &ext, &request).is_err());
        assert!(read_result(Outcome::Failed, true, &ext, &request).is_err());
        assert!(read_result(Outcome::Ready, true, &[], &request).is_err());
        let mut changed = request.clone();
        changed.op_id = OpId::from_parts(4, 8);
        assert!(read_result(Outcome::Ready, true, &ext, &changed).is_err());
        changed = request.clone();
        changed.usage[0].replacement.requests -= 1;
        assert!(read_result(Outcome::Ready, true, &ext, &changed).is_err());
        for end in 0..result.len() {
            assert!(read_result(
                Outcome::Ready,
                true,
                &extensions::encode(&[(RESULT, &result[..end])]),
                &request
            )
            .is_err());
        }
        assert!(read_result(
            Outcome::Ready,
            true,
            &extensions::encode(&[(RESULT, &result), (RESULT, &result)]),
            &request
        )
        .is_err());
    }
}
