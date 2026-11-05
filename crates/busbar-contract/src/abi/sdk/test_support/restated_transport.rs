// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable declaration variants of a trusted SDK transport factory for host tests.

use std::sync::OnceLock;

use crate::abi::mechanism::door::{Door, DoorParts};
use crate::abi::mechanism::extensions;
use crate::abi::mechanism::KindCode;
use crate::abi::sdk::door::{abi_str, MacroDoor};

/// A test-owned, process-lived declaration variant retaining the source's typed operations.
/// Only the SDK's sealed factory can supply the source; raw function pointers are not accepted.
#[derive(Debug, Default)]
pub struct RestatedTransport {
    address: OnceLock<usize>,
}

impl RestatedTransport {
    /// An uninitialized declaration fixture suitable for a static item.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            address: OnceLock::new(),
        }
    }

    /// Rename every claim and replace or remove keyed extensions once. All replacement data
    /// is copied into immutable process-lived storage. The source tail, operations, lifecycle,
    /// and migration entry remain unchanged. Subsequent calls return the original variant.
    ///
    /// Panics if the source is not a transport or the replacement claim count differs.
    pub fn get_or_init(
        &self,
        source: MacroDoor,
        claims: &[&str],
        edits: &[(&str, Option<&[u8]>)],
    ) -> &'static Door {
        let address = *self.address.get_or_init(|| {
            let original = source.door_fn()();
            assert_eq!(original.kind(), KindCode::Transport as u32);
            // SAFETY: MacroDoor's sealed construction contract retains the SDK Statement and
            // every list, string, tail and operation table in static storage.
            let mut statement = unsafe { *original.statement() };
            assert_eq!(
                claims.len(),
                statement.claims_len,
                "restatement must preserve claim count"
            );
            let claims = Box::leak(
                claims
                    .iter()
                    .map(|claim| abi_str(Box::leak((*claim).to_owned().into_boxed_str())))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
            statement.claims = claims.as_ptr();
            if !edits.is_empty() {
                let original_extensions = if statement.extensions.len == 0 {
                    &[]
                } else {
                    // SAFETY: the sealed source retains the original declaration bytes.
                    unsafe {
                        std::slice::from_raw_parts(
                            statement.extensions.ptr,
                            statement.extensions.len,
                        )
                    }
                };
                let mut entries: Vec<_> = extensions::entries(original_extensions)
                    .map(|(key, value)| {
                        (
                            std::str::from_utf8(key).expect("extension key is UTF-8"),
                            value,
                        )
                    })
                    .filter(|(key, _)| !edits.iter().any(|(edit, _)| edit == key))
                    .collect();
                for (index, (key, value)) in edits.iter().enumerate() {
                    assert!(!edits[..index].iter().any(|(previous, _)| previous == key));
                    if let Some(value) = value {
                        entries.push((key, value));
                    }
                }
                let bytes = Box::leak(extensions::encode(&entries).into_boxed_slice());
                statement.extensions = extensions::statement_blob(bytes);
            }
            let statement = Box::leak(Box::new(statement));
            // SAFETY: only copied static claim names and extension bytes change. The source's
            // sealed typed table, tail, lifecycle and migration entry remain static and intact.
            let door = unsafe {
                Door::__from_parts(DoorParts {
                    statement,
                    ..original.parts()
                })
                .__with_migrate(original.migrate())
            };
            Box::into_raw(Box::new(door)) as usize
        });
        // SAFETY: this private cell contains only the immutable leaked Door allocated above.
        unsafe { &*(address as *const Door) }
    }
}
