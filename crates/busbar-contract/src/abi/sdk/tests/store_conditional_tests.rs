// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::store::dedupe::{Dedupe, Seen};

fn candidate() -> Request {
    Request {
        version: VERSION,
        op_id: OpId::from_parts(4, 7),
        predicates: vec![Predicate {
            schema: "opaque".into(),
            key: vec![0xff, 0, 7],
            expected: Expected::Absent,
        }],
        mutations: vec![Mutation::Put {
            schema: "opaque".into(),
            key: vec![0xff, 0, 7],
            value: b"value".to_vec(),
        }],
    }
}

#[test]
fn codec_preserves_binary_keys_all_predicates_and_mutations() {
    let mut request = candidate();
    request.predicates.push(Predicate {
        schema: "other".into(),
        key: vec![2],
        expected: Expected::Bytes(vec![0, 0xff]),
    });
    request.mutations.push(Mutation::Delete {
        schema: "other".into(),
        key: vec![2],
    });
    let encoded = request.encode().unwrap();
    assert_eq!(Request::decode(&encoded), Ok(request.clone()));
    assert_eq!(request.carrier(), Some(("opaque", [0xff, 0, 7].as_slice())));
    let ext = extensions::encode(&[(INTENT, &encoded)]);
    assert_eq!(intent(&ext), Ok(Some(request)));
}

#[test]
fn all_truncations_trailing_bytes_and_unknown_versions_refuse() {
    let bytes = candidate().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Request::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    let mut future = bytes;
    future[..4].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert!(intent(&extensions::encode(&[(INTENT, &future)])).is_err());
}

#[test]
fn malformed_recognized_intent_never_falls_back() {
    let encoded = candidate().encode().unwrap();
    let ext = extensions::encode(&[(INTENT, &encoded)]);
    // Even a missing value-length is a recognized malformed intent.
    for end in 2 + INTENT.len()..ext.len() {
        assert!(intent(&ext[..end]).is_err(), "end={end}");
    }
    assert!(intent(&extensions::encode(&[
        (INTENT, &encoded),
        (INTENT, &encoded)
    ]))
    .is_err());
    assert_eq!(intent(&[]), Ok(None));
    assert_eq!(
        intent(&extensions::encode(&[("unrelated", b"data")])),
        Ok(None)
    );
    assert_eq!(
        intent(&[0xff]),
        Ok(None),
        "ordinary GET retains unknown-extension tolerance"
    );
}

#[test]
fn no_unchecked_count_allocation_or_invalid_variant() {
    let bytes = candidate().encode().unwrap();
    let mut huge = bytes.clone();
    huge[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Request::decode(&huge).is_err());
    let mut request = candidate();
    request.version += 1;
    assert!(request.encode().is_err());
    request = candidate();
    request.predicates.clear();
    assert!(request.encode().is_err());
    request = candidate();
    request.mutations.clear();
    assert!(request.encode().is_err());
}

#[test]
fn duplicate_addresses_refuse_but_predicate_mutation_overlap_is_allowed() {
    let mut request = candidate();
    assert_eq!(request.validate(), Ok(()));
    request.predicates.push(request.predicates[0].clone());
    assert!(request.validate().is_err());
    request = candidate();
    request.mutations.push(Mutation::Delete {
        schema: "opaque".into(),
        key: vec![0xff, 0, 7],
    });
    assert!(request.validate().is_err());
    request = candidate();
    if let Mutation::Put { value, .. } = &mut request.mutations[0] {
        value.clear();
    }
    assert!(request.validate().is_err());
}

#[test]
fn statement_support_is_exact_explicit_and_versioned() {
    assert!(!supported(&[]));
    assert!(supported(&extensions::encode(&[(CAPABILITY, b"1")])));
    assert!(!supported(&extensions::encode(&[(CAPABILITY, b"2")])));
    assert!(!supported(&extensions::encode(&[(INTENT, b"1")])));
    assert!(!supported(&extensions::encode(&[
        (CAPABILITY, b"1"),
        (CAPABILITY, b"1")
    ])));
    let mut malformed = extensions::encode(&[(CAPABILITY, b"1")]);
    malformed.pop();
    assert!(!supported(&malformed));
}

#[test]
fn result_requires_ready_lease_presence_and_complete_correlation() {
    let request = candidate();
    for decision in [Decision::Applied, Decision::ConditionConflict] {
        let value = encode_result(&request, decision);
        let ext = extensions::encode(&[(RESULT, &value)]);
        assert_eq!(
            read_result(Outcome::Ready, true, &ext, &request),
            Ok(decision)
        );
        assert!(read_result(Outcome::Ready, false, &ext, &request).is_err());
        // SHORT is a FAILED answer in the existing ABI, even if it incorrectly carries a lease.
        for outcome in [
            Outcome::Failed,
            Outcome::Pending,
            Outcome::Refused,
            Outcome::Fault,
        ] {
            assert!(read_result(outcome, true, &ext, &request).is_err());
        }
        assert!(
            read_result(Outcome::Ready, true, &[], &request).is_err(),
            "old SDK GET READY is never Applied"
        );
        for index in [0, 4, 20, 52] {
            let mut malformed = value.clone();
            malformed[index] ^= 0x80;
            assert!(read_result(
                Outcome::Ready,
                true,
                &extensions::encode(&[(RESULT, &malformed)]),
                &request
            )
            .is_err());
        }
        let mut changed = request.clone();
        changed.op_id = OpId::from_parts(4, 8);
        assert!(read_result(Outcome::Ready, true, &ext, &changed).is_err());
        changed = request.clone();
        changed.predicates[0].expected = Expected::Bytes(vec![1]);
        assert!(read_result(Outcome::Ready, true, &ext, &changed).is_err());
        for end in 0..value.len() {
            assert!(read_result(
                Outcome::Ready,
                true,
                &extensions::encode(&[(RESULT, &value[..end])]),
                &request
            )
            .is_err());
        }
    }
}

#[test]
fn digest_covers_domain_version_addresses_predicates_mutations_and_order() {
    let request = candidate();
    let body = request.fingerprint();
    let mut variants = Vec::new();
    let mut changed = request.clone();
    changed.version += 1;
    variants.push(changed);
    let mut changed = request.clone();
    changed.predicates[0].schema.push('x');
    variants.push(changed);
    let mut changed = request.clone();
    changed.predicates[0].key.push(0);
    variants.push(changed);
    let mut changed = request.clone();
    changed.predicates[0].expected = Expected::Bytes(vec![]);
    variants.push(changed);
    let mut changed = request.clone();
    changed.predicates[0].expected = Expected::Bytes(vec![1]);
    variants.push(changed);
    let mut changed = request.clone();
    changed.mutations[0] = Mutation::Delete {
        schema: "opaque".into(),
        key: vec![0xff, 0, 7],
    };
    variants.push(changed);
    let mut changed = request.clone();
    changed.mutations[0] = Mutation::Put {
        schema: "other".into(),
        key: vec![0xff, 0, 7],
        value: b"value".to_vec(),
    };
    variants.push(changed);
    let mut changed = request.clone();
    changed.mutations[0] = Mutation::Put {
        schema: "opaque".into(),
        key: vec![0xff, 0, 8],
        value: b"value".to_vec(),
    };
    variants.push(changed);
    let mut changed = request.clone();
    changed.mutations[0] = Mutation::Put {
        schema: "opaque".into(),
        key: vec![0xff, 0, 7],
        value: b"changed".to_vec(),
    };
    variants.push(changed);
    for changed in variants {
        assert_ne!(body, changed.fingerprint());
    }
    let mut reordered = request.clone();
    reordered.predicates.push(Predicate {
        schema: "second".into(),
        key: vec![9],
        expected: Expected::Absent,
    });
    reordered.mutations.push(Mutation::Delete {
        schema: "second".into(),
        key: vec![9],
    });
    let before = reordered.fingerprint();
    reordered.predicates.reverse();
    assert_ne!(before, reordered.fingerprint());
    reordered.predicates.reverse();
    reordered.mutations.reverse();
    assert_ne!(before, reordered.fingerprint());
    assert_ne!(body, *Dedupe::usage(&[]).body());
    assert_eq!(
        Dedupe::record_transaction(&request).seen(Some(&body)),
        Seen::Replay
    );
    assert_eq!(
        Dedupe::record_transaction(&request).seen(Some(b"old-debug-body")),
        Seen::Conflict
    );
    let mut same_body = request.clone();
    same_body.op_id = OpId::from_parts(5, 9);
    assert_eq!(
        body,
        same_body.fingerprint(),
        "id is the receipt key, not part of its value digest"
    );
}

struct OldHost;
macro_rules! old_host_calls {
    ($life:lifetime; $($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$(
        fn $name<$life>(&$life self, $($arg: $ty),*) -> crate::store_calls::StoreCall<$life, $out> {
            let _ = ($($arg,)*);
            unreachable!("the unsupported conditional call must not dispatch an older operation")
        }
    )*};
}
impl crate::store_calls::StoreCalls for OldHost {
    old_host_calls! {
        'a;
        add_usage_batch(op: OpId, cells: &'a [(&'a str, u64, crate::records::UsageDelta)]) -> ();
        add_metering_batch(op: OpId, deltas: &'a [crate::records::MeteringDelta]) -> ();
        record_put(schema: &'a str, key: &'a [u8], value: &'a crate::kinds::RecordBytes) -> ();
        record_get(schema: &'a str, key: &'a [u8]) -> Option<crate::kinds::RecordBytes>;
        record_scan(schema: &'a str, prefix: &'a [u8], limit: u32) -> Vec<(Vec<u8>, crate::kinds::RecordBytes)>;
        upsert_plane_record(record: crate::records::PlaneRecordRef<'a>) -> ();
        get_plane_record(kind: &'a str, id: &'a str) -> Option<Vec<u8>>;
        append_plane_record(op: OpId, record: crate::records::PlaneRecordRef<'a>) -> ();
        list_plane_records(kind: &'a str, selector: &'a crate::records::PlaneSelector<'a>) -> Vec<Vec<u8>>;
        delete_plane_record(kind: &'a str, id: &'a str) -> ();
        redeem_plane_token(kind: &'a str, token: &'a str, expires_at: u64, now: u64) -> bool;
        plane_token_live(kind: &'a str, token: &'a str, expires_at: u64, now: u64) -> bool;
    }
}

#[test]
fn old_host_defaults_refuse_without_any_legacy_operation() {
    use crate::store_calls::{StoreCalls, StoreFailure};
    let host = OldHost;
    assert!(!host.supports_record_transaction());
    let request = candidate();
    assert!(matches!(
        futures::executor::block_on(host.record_transaction(&request)),
        Err(StoreFailure::Refused(_))
    ));
}

#[test]
fn range_codec_is_fixed_width_and_its_complete_selector_changes_the_digest() {
    let mut request = candidate();
    request.mutations.push(Mutation::DeleteRange {
        schema: "range".into(),
        prefix: vec![0xff, 0],
        exact_key_length: 12,
    });
    let bytes = request.encode().unwrap();
    assert_eq!(Request::decode(&bytes), Ok(request.clone()));
    assert_eq!(&bytes[bytes.len() - 8..], &12u64.to_le_bytes());
    assert_eq!(
        request.mutations[1].address(),
        ("range", [0xff, 0].as_slice())
    );
    let body = request.fingerprint();
    for replacement in [
        Mutation::DeleteRange {
            schema: "changed".into(),
            prefix: vec![0xff, 0],
            exact_key_length: 12,
        },
        Mutation::DeleteRange {
            schema: "range".into(),
            prefix: vec![0xff, 1],
            exact_key_length: 12,
        },
        Mutation::DeleteRange {
            schema: "range".into(),
            prefix: vec![0xff, 0],
            exact_key_length: 13,
        },
        Mutation::Delete {
            schema: "range".into(),
            key: vec![0xff, 0],
        },
    ] {
        let mut changed = request.clone();
        changed.mutations[1] = replacement;
        assert_ne!(body, changed.fingerprint());
    }
    for end in bytes.len() - 8..bytes.len() {
        assert!(Request::decode(&bytes[..end]).is_err());
    }
}

#[test]
fn invalid_range_length_and_all_mutation_overlaps_refuse() {
    let range = |prefix: &[u8], length: u64| Mutation::DeleteRange {
        schema: "range".into(),
        prefix: prefix.to_vec(),
        exact_key_length: length,
    };
    let point = |key: &[u8]| Mutation::Delete {
        schema: "range".into(),
        key: key.to_vec(),
    };
    let mut request = candidate();
    request.mutations = vec![range(b"abcd", 3)];
    assert!(request.validate().is_err());
    // Reversing mutation order must not change overlap refusal.
    for pair in [
        vec![range(b"ab", 4), point(b"abcd")],
        vec![range(b"ab", 4), range(b"abc", 4)],
        vec![range(b"ab", 4), range(b"ab", 4)],
        vec![range(b"", 4), point(b"abcd")],
    ] {
        request.mutations = pair;
        assert!(request.validate().is_err());
        request.mutations.reverse();
        assert!(request.validate().is_err());
    }
    request.mutations = vec![
        range(b"ab", 4),
        range(b"ab", 5),
        range(b"ac", 4),
        point(b"ab"),
        point(b"zzzz"),
    ];
    assert_eq!(
        request.validate(),
        Ok(()),
        "different exact lengths and disjoint prefixes are disjoint"
    );
    request.predicates = vec![Predicate {
        schema: "range".into(),
        key: b"abcd".to_vec(),
        expected: Expected::Bytes(vec![9]),
    }];
    assert_eq!(
        request.validate(),
        Ok(()),
        "a range predicate reads prestate before range deletion"
    );
    request.mutations = vec![range(b"", 0)];
    assert_eq!(
        request.validate(),
        Ok(()),
        "empty opaque key is not reserved"
    );
    if usize::BITS < 64 {
        request.mutations = vec![range(b"", u64::MAX)];
        assert!(request.validate().is_err());
    }
}
