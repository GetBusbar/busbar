// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::auth::POINT_HEAD_BODY;
use crate::abi::host::service::AuthRef;
use crate::abi::transport::route::{FIELD_PRESENT, FIELD_VALUE_PREFIX, METHOD_POST, PATH_PATTERN};

fn line() -> GuestLine {
    GuestLine {
        line: 0,
        points: POINT_HEAD_BODY,
        auth: AuthRef { id: 71, mac: 29 },
        body_limit: 8192,
        methods: METHOD_POST,
        path_form: PATH_PATTERN,
        path: "/work/{name}".into(),
        fields: vec![
            (FIELD_PRESENT, "x-present".into(), Vec::new()),
            (FIELD_VALUE_PREFIX, "x-bytes".into(), vec![0, 255, 10]),
        ],
        rung: 3,
    }
}

#[test]
fn a_policy_preserves_match_order_routes_binary_predicates_and_generation() {
    let first = line();
    let next = GuestLine {
        line: 9,
        path: "/other/{name}".into(),
        auth: AuthRef { id: 73, mac: 31 },
        ..line()
    };
    let lines = vec![first, next];
    let bytes = encode(17, u64::MAX, &lines).unwrap();
    assert_eq!(
        decode(&bytes).unwrap(),
        Policy {
            listener: 17,
            generation: u64::MAX,
            lines
        }
    );
}

#[test]
fn truncated_unknown_and_trailing_policy_data_never_becomes_an_open_list() {
    let bytes = encode(17, 3, &[line()]).unwrap();
    for end in 0..bytes.len() {
        assert!(
            decode(&bytes[..end]).is_err(),
            "accepted a truncated policy at {end}"
        );
    }
    let mut unknown = bytes.clone();
    unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode(&unknown).is_err());
    let mut no_generation = bytes.clone();
    no_generation[12..20].fill(0);
    assert!(decode(&no_generation).is_err());
    let mut oversized_count = bytes.clone();
    oversized_count[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode(&oversized_count).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode(&trailing).is_err());
}

#[test]
fn invalid_route_handle_line_and_body_point_pairs_are_refused_before_encoding() {
    assert!(encode(17, 0, &[line()]).is_err());
    assert!(encode(0, 3, &[line()]).is_err());
    assert!(encode(17, 3, &[line(), line()]).is_err());
    let mut bad = line();
    bad.auth = AuthRef::NONE;
    assert!(encode(17, 3, &[bad]).is_err());
    let mut bad = line();
    bad.methods = 0;
    assert!(encode(17, 3, &[bad]).is_err());
    let mut bad = line();
    bad.body_limit = 0;
    assert!(encode(17, 3, &[bad]).is_err());
    let mut bad = line();
    bad.fields[0].0 = u32::MAX;
    assert!(encode(17, 3, &[bad]).is_err());
}

#[test]
fn openings_and_unchanged_policy_replies_are_exact_versioned_values() {
    for open in [
        Open {
            stream: 0,
            known_generation: 0,
        },
        Open {
            stream: u64::MAX,
            known_generation: u64::MAX,
        },
    ] {
        let bytes = open.encode();
        assert_eq!(Open::decode(&bytes).unwrap(), open);
        for end in 0..bytes.len() {
            assert!(Open::decode(&bytes[..end]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Open::decode(&extra).is_err());
    }
    let identity = Identity {
        listener: 17,
        generation: 3,
    };
    assert_eq!(
        Identity::decode(&identity.encode().unwrap()).unwrap(),
        identity
    );
    assert!(Identity {
        listener: 0,
        generation: 3
    }
    .encode()
    .is_err());
    assert!(Identity {
        listener: 17,
        generation: 0
    }
    .encode()
    .is_err());
    assert!(Identity::decode(
        &Open {
            stream: 0,
            known_generation: 3
        }
        .encode()
    )
    .is_err());
}
