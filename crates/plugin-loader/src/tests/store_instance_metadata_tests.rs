// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::abi::mechanism::call::{BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::sdk::store::metadata;

#[test]
fn legacy_open_and_instance_specific_memory_or_durable_answers_are_distinct() {
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&[], BLOB_ABSENT, 0)),
        Ok(None)
    );
    let memory = metadata::encode(true);
    let durable = metadata::encode(false);
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&memory, BLOB_OCTETS, 0)),
        Ok(Some(true))
    );
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&durable, BLOB_OCTETS, 0)),
        Ok(Some(false))
    );
    assert!(instance_ephemeral(lifecycle::blob(&memory, BLOB_JSON, 0)).is_err());
}

#[test]
fn invalid_open_metadata_ranges_are_refused_before_reading_them() {
    let bytes = metadata::encode(true);
    let mut blob = lifecycle::blob(&bytes, BLOB_OCTETS, 0);
    blob.ptr = std::ptr::null();
    assert!(instance_ephemeral(blob).is_err());
    blob.ptr = bytes.as_ptr();
    blob.len = usize::MAX;
    assert!(instance_ephemeral(blob).is_err());
}
