// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral recorder declaration and its supported version.

#[test]
fn recorder_protocol_requires_an_explicit_supported_version() {
    use crate::abi::mechanism::extensions::encode;
    use crate::export_calls::{recorder_protocol, RecorderRequirements, EXT_RECORDER_REQUIREMENTS};
    assert_eq!(recorder_protocol(&[]), Ok(false));
    assert_eq!(
        recorder_protocol(&encode(&[(EXT_RECORDER_REQUIREMENTS, b"1")])),
        Ok(true)
    );
    assert!(recorder_protocol(&encode(&[
        (EXT_RECORDER_REQUIREMENTS, b"1"),
        (EXT_RECORDER_REQUIREMENTS, b"2"),
    ]))
    .is_err());
    for wrong in [b"2".as_slice(), b"true", b"null", b"{}", b"\"1\""] {
        assert!(recorder_protocol(&encode(&[(EXT_RECORDER_REQUIREMENTS, wrong)])).is_err());
    }
    assert!(serde_json::from_str::<RecorderRequirements>(
        r#"{"retention_seconds":1,"key_gauge_limit":0,"buffer_seconds":4}"#
    )
    .is_err());
    assert!(serde_json::from_str::<RecorderRequirements>(r#"{"retention_seconds":1}"#).is_err());
    assert!(RecorderRequirements {
        retention_seconds: 0,
        key_gauge_limit: 0
    }
    .validate()
    .is_err());
}
