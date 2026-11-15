// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::store_v4`.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS, BLOB_SECRET};
use busbar_contract::persistence as owned;
use busbar_contract::secure::SecureVec;

use crate::store_v4::OpenFailure;

/// Boot: a loaded store instance keeps its label.
#[cold]
pub(crate) fn instance(label: &str) -> Arc<str> {
    Arc::from(label)
}

/// Boot: names why the store plugin did not load.
#[cold]
pub(crate) fn load_refused(error: &crate::dispatch::LoadError) -> String {
    error.to_string()
}

impl OpenFailure {
    /// Error: a store open failed and says why.
    #[cold]
    pub(crate) fn new(code: owned::lifecycle::Error, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Error: the store plugin refused to open.
#[cold]
pub(crate) fn open_refused(name: &str) -> String {
    format!("primitive store open failed: plugin answered {name}")
}

/// Error: the store plugin's open answer had no frame.
#[cold]
pub(crate) fn open_frameless() -> String {
    "primitive store open has no frame".to_string()
}

/// Error: the store returned invalid or missing instance metadata.
#[cold]
pub(crate) fn metadata_invalid() -> String {
    "primitive store returned invalid or missing instance metadata".to_string()
}

/// Boot: a store open lends its secret fields out of its settings once. Answers the settings
/// with those fields taken out, the lent secrets, and one blob borrowing each secret.
#[cold]
pub(crate) fn lend_secrets(
    refs: &[String],
    settings: &[u8],
) -> (SecureVec, Vec<SecureVec>, Vec<Blob>) {
    let mut settings = SecureVec::from(settings);
    let secrets: Vec<SecureVec> = if refs.is_empty() {
        Vec::new()
    } else if let Ok(mut block) = serde_json::from_slice::<serde_json::Value>(&settings) {
        let as_bytes = |value: Option<serde_json::Value>| match value {
            Some(serde_json::Value::String(value)) => SecureVec::from(value.into_bytes()),
            _ => SecureVec::new(),
        };
        let values = busbar_contract::secret_fields::lend(
            &mut block,
            refs,
            false,
            |_, value| Ok::<_, std::convert::Infallible>(as_bytes(value)),
            |_, value| Ok(as_bytes(Some(value))),
        )
        .unwrap_or_else(|error| match error {});
        settings.clear();
        let _ = serde_json::to_writer(&mut settings, &block);
        values
    } else {
        Vec::new()
    };
    let blobs = secrets
        .iter()
        .map(|bytes| Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
        .collect();
    (settings, secrets, blobs)
}
