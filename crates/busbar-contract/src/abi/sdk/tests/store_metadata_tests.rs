// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

#[test]
fn instance_durability_is_optional_and_independent_for_each_open() {
    assert_eq!(decode(&[]), Ok(None));
    assert_eq!(decode(&encode(true)), Ok(Some(true)));
    assert_eq!(decode(&encode(false)), Ok(Some(false)));
    assert_eq!(
        decode(&extensions::encode(&[("another.property", b"opaque")])),
        Ok(None)
    );
}

#[test]
fn malformed_or_duplicate_durability_never_falls_back_to_durable() {
    for value in [b"".as_slice(), &[2], &[0, 1], b"true"] {
        assert!(decode(&extensions::encode(&[(EPHEMERAL, value)])).is_err());
    }
    assert!(decode(&extensions::encode(&[(EPHEMERAL, &[0]), (EPHEMERAL, &[1])])).is_err());
    let encoded = encode(true);
    for end in 1..encoded.len() {
        assert!(decode(&encoded[..end]).is_err(), "prefix {end}");
    }
    let mut extra = encoded;
    extra.push(1);
    assert!(decode(&extra).is_err());
}
