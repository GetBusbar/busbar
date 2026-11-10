// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact physical evidence and explicit native routes. An archive record proves
//! retention, never that an unknown historical attempt did not apply.
use super::*;
use busbar_contract::persistence::{Address, NamespaceId};

pub const NAMESPACE: NamespaceId = NamespaceId(*b"busbar.legacy1\0\0");
#[derive(Clone, Copy)]
pub struct Provenance {
    pub dataset: [u8; 16],
    pub catalogue: [u8; 32],
}
#[derive(Clone, Copy)]
pub enum Scope {
    Unscoped,
    Instance,
}
pub struct Binding<'a> {
    pub schema: &'a str,
    pub instance: &'a str,
    pub private: bool,
    pub source_scope: Scope,
}

pub struct Receipt<'a> {
    pub operation: &'a [u8; 16],
    pub body: &'a [u8],
    pub answer: &'a [u8],
    pub recorded_at: Option<u64>,
    pub expires_at_ms: Option<i64>,
    /// Original historical digest only. Its hash domain is NOT a new receipt's.
    pub historical_digest: Option<[u8; 32]>,
    pub completed_shape: bool,
}
pub enum Route<'a> {
    Record {
        address: Address,
        value: &'a [u8],
    },
    Prepared(CanonicalRows),
    JournalPart {
        key: &'a [u8],
        value: &'a [u8],
    },
    /// Admitted logical record retained pending a declared owner binding. This is an
    /// explicit activation blocker, not a skipped record or a guessed owner.
    RequiresBinding,
}
pub fn authorizes(address: &Address) -> bool {
    if address.namespace != NAMESPACE.0 {
        return false;
    }
    let Ok(parts) =
        busbar_kernel::persistence::import_target::records::keys::components(&address.key, b'E')
    else {
        return false;
    };
    parts.len() == 4
        && parts[0].len() == 16
        && parts[1].len() == 32
        && std::str::from_utf8(parts[2]).is_ok()
}
fn scoped_key<'a>(scope: Scope, instance: &str, key: &'a [u8]) -> Result<&'a [u8], Error> {
    match scope {
        Scope::Unscoped => Ok(key),
        Scope::Instance => {
            let len = u16::from_be_bytes(
                key.get(..2)
                    .ok_or(Error::Invalid)?
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            ) as usize;
            let end = len.checked_add(2).ok_or(Error::Range)?;
            if key.get(2..end) != Some(instance.as_bytes()) {
                return Err(Error::Invalid);
            }
            key.get(end..).ok_or(Error::Invalid)
        }
    }
}
pub fn route_record<'a>(
    schema: &str,
    key: &'a [u8],
    bytes: &'a [u8],
    bindings: &[Binding<'_>],
) -> Result<Route<'a>, Error> {
    if schema == "busbar.journal.v1" {
        return Ok(Route::JournalPart { key, value: bytes });
    }
    if let Some(address) =
        busbar_kernel::persistence::import_target::records::builtin_record_address(
            schema, key, bytes,
        )
        .map_err(|_| Error::Invalid)?
    {
        return Ok(Route::Record {
            address,
            value: bytes,
        });
    }
    let mut matches = bindings.iter().filter(|binding| {
        binding.schema == schema
            && match binding.source_scope {
                Scope::Unscoped => true,
                Scope::Instance => scoped_key(Scope::Instance, binding.instance, key).is_ok(),
            }
    });
    let Some(binding) = matches.next() else {
        return Ok(Route::RequiresBinding);
    };
    if matches.next().is_some() {
        return Err(Error::Invalid);
    }
    use busbar_kernel::persistence::import_target::records::{self, RecordBinding, RecordScope};
    let address = records::witness_address(
        schema,
        key,
        bytes,
        Some(RecordBinding {
            instance: binding.instance,
            private: binding.private,
            scope: match binding.source_scope {
                Scope::Unscoped => RecordScope::Unscoped,
                Scope::Instance => RecordScope::Instance,
            },
        }),
    )
    .map_err(|_| Error::Invalid)?;
    Ok(Route::Record {
        address,
        value: bytes,
    })
}

/// Retain the ENTIRE original protected legacy-row frame at its full native
/// source identity before routing a payload. Every known table validates exact
/// column names. Unrecognized tables fail rather than disappear.
pub trait HistoricalReceiptResolution: Send + Sync {
    fn resolve_original(
        &self,
        provenance: Provenance,
        evidence_address: &Address,
        receipt: &Receipt<'_>,
    ) -> Result<[u8; 32], super::super::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_recovery_and_principal_rows_reuse_native_owner_addresses() {
        let op = [3u8; 16];
        let head = br#"{"version":1,"node":9,"sequence":4,"revision":2,"event_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
        let Route::Record { address, value } =
            route_record("busbar.usage-recovery-head.v1", &op, head, &[]).unwrap()
        else {
            panic!()
        };
        assert!(
            busbar_kernel::persistence::import_target::records::recovery::legacy_head_authorizes(
                &address
            )
        );
        assert_eq!(value, head);
        let Route::Record { address, value } = route_record(
            "busbar.principal-transition.v1",
            b"head",
            b"original-signed-transition",
            &[],
        )
        .unwrap() else {
            panic!()
        };
        assert!(
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                true,
                "busbar.principal-transition",
                "busbar.principal-transition.v1",
                &address
            )
        );
        assert_eq!(value, b"original-signed-transition");
    }
    #[test]
    fn synthetic_instance_binding_cannot_adopt_another_instances_record() {
        let bindings = [
            Binding {
                schema: "plane-schema",
                instance: "one",
                private: false,
                source_scope: Scope::Instance,
            },
            Binding {
                schema: "plane-schema",
                instance: "two",
                private: false,
                source_scope: Scope::Instance,
            },
        ];
        let key = busbar_kernel::persistence::import_target::records::host_records::record_key(
            "two", b"key",
        );
        let Route::Record { address, .. } =
            route_record("plane-schema", &key, b"body", &bindings).unwrap()
        else {
            panic!()
        };
        assert!(
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                false,
                "two",
                "plane-schema",
                &address
            )
        );
        assert!(
            !busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                false,
                "one",
                "plane-schema",
                &address
            )
        );
        assert!(matches!(
            route_record("unknown", b"key", b"body", &bindings).unwrap(),
            Route::RequiresBinding
        ));
    }
}
