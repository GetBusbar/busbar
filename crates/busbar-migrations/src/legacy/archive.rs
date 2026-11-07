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
    Receipt(Receipt<'a>),
    Plane {
        record: busbar_contract::records::PlaneRecordRef<'a>,
        append: Option<bool>,
    },
    Token {
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
    },
    /// Known physical row retained pending a compiled owner binding. This is an
    /// explicit activation blocker, not a skipped record or a guessed owner.
    RequiresBinding,
}
pub struct Retained<'a> {
    pub address: Address,
    pub original: &'a [u8],
    pub route: Route<'a>,
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
fn value<'a>(c: &Columns<'a, '_>, name: &str) -> Result<&'a [u8], Error> {
    c.bytes(name)
}
fn text<'a>(c: &Columns<'a, '_>, name: &str) -> Result<&'a str, Error> {
    std::str::from_utf8(c.bytes(name)?).map_err(|_| Error::Type)
}
fn optional_text<'a>(c: &Columns<'a, '_>, name: &str) -> Result<Option<&'a str>, Error> {
    if c.cell(name) == Cell::Null {
        Ok(None)
    } else {
        text(c, name).map(Some)
    }
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
pub fn sql<'a>(
    profile: Profile,
    provenance: Provenance,
    table: &str,
    columns: &[&str],
    native_key: &[u8],
    original: &'a [u8],
    bindings: &[Binding<'_>],
) -> Result<Retained<'a>, Error> {
    let row = Row::decode(original).map_err(|_| Error::Invalid)?;
    let mysql = matches!(
        profile,
        Profile::MysqlDev4 | Profile::MysqlDev5 | Profile::MysqlDev7
    );
    let pg = matches!(
        profile,
        Profile::PostgresDev7 | Profile::PostgresDev8 | Profile::PostgresDev9
    );
    let sqlite = matches!(
        profile,
        Profile::SqliteDev7 | Profile::SqliteDev8 | Profile::SqliteDev9
    );
    if !(mysql || pg || sqlite) {
        return Err(Error::Unsupported);
    }
    let expected: &[&str] = match table {
        "store_ops" => &["op_id", "body", "answer", "recorded_at"],
        "schema_records" if sqlite => &["schema", "record_key", "value"],
        "store_records" if pg => &["schema_id", "key", "value"],
        "store_records" if mysql => &["schema_id", "rkey", "value"],
        "plane_records" if pg => &["kind", "id", "parent", "seq", "ts", "disposition", "body"],
        "plane_records" if sqlite => &[
            "kind",
            "identity",
            "seq",
            "id",
            "parent",
            "ts",
            "disposition",
            "body",
        ],
        "plane_records" if mysql => &[
            "kind", "ident", "seq", "id", "parent", "ts", "terminal", "body",
        ],
        "plane_chain" if pg => &[
            "kind",
            "parent",
            "seq",
            "id",
            "ts",
            "disposition",
            "body",
            "has_parent",
        ],
        "plane_tokens" => &["kind", "token", "expires_at"],
        _ => return Err(Error::Unsupported),
    };
    let c = Columns::new(mysql, columns, row, expected)?;
    let route = match table {
        "store_ops" => {
            let operation = value(&c, "op_id")?.try_into().map_err(|_| Error::Invalid)?;
            let body = value(&c, "body")?;
            let answer = value(&c, "answer")?;
            let historical_digest = if mysql && body.len() == 32 {
                Some(body.try_into().map_err(|_| Error::Invalid)?)
            } else if !mysql
                && body.len() == 64
                && body.iter().all(|b| matches!(*b,b'0'..=b'9'|b'a'..=b'f'))
            {
                Some(
                    hex::decode(body)
                        .map_err(|_| Error::Invalid)?
                        .try_into()
                        .map_err(|_| Error::Invalid)?,
                )
            } else {
                None
            };
            let completed_shape = historical_digest.is_some()
                && if pg {
                    answer.is_empty()
                } else if mysql {
                    answer == b"null"
                } else {
                    answer == b"\"Done\""
                };
            Route::Receipt(Receipt {
                operation,
                body,
                answer,
                recorded_at: Some(c.timestamp("recorded_at")?),
                expires_at_ms: None,
                historical_digest,
                completed_shape,
            })
        }
        "schema_records" => route_record(
            text(&c, "schema")?,
            value(&c, "record_key")?,
            value(&c, "value")?,
            bindings,
        )?,
        "store_records" => route_record(
            text(&c, "schema_id")?,
            value(&c, if mysql { "rkey" } else { "key" })?,
            value(&c, "value")?,
            bindings,
        )?,
        "plane_tokens" => {
            let kind = text(&c, "kind")?;
            let token = text(&c, "token")?;
            let expires_at = c.timestamp("expires_at")?;
            if kind == "ticket-spent" {
                Route::Prepared(vec![busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_token(
                    kind, token, expires_at,
                )
                .map_err(|_| Error::Invalid)?])
            } else {
                Route::Token {
                    kind,
                    token,
                    expires_at,
                }
            }
        }
        "plane_records" | "plane_chain" => {
            let kind = text(&c, "kind")?;
            let id = text(&c, "id")?;
            let mut parent = optional_text(&c, "parent")?;
            let seq = c.uint("seq")?;
            let append = if pg {
                Some(table == "plane_chain")
            } else {
                let identity = text(&c, if mysql { "ident" } else { "identity" })?;
                let chain_position = parent == Some(identity);
                let upsert_position = identity == id && seq == 0;
                match (chain_position, upsert_position) {
                    (true, true) => None,
                    (true, false) => Some(true),
                    (false, true) => Some(false),
                    (false, false) => return Err(Error::Invalid),
                }
            };
            if pg && append == Some(true) {
                if c.boolean("has_parent")? && parent.is_none() {
                    return Err(Error::Invalid);
                }
                if !c.boolean("has_parent")? {
                    if parent != Some("") {
                        return Err(Error::Invalid);
                    }
                    parent = None;
                }
            }
            let disposition = if mysql {
                if c.boolean("terminal")? {
                    busbar_contract::records::PlaneDisposition::Terminal
                } else {
                    busbar_contract::records::PlaneDisposition::Active
                }
            } else {
                match text(&c, "disposition")? {
                    "active" => busbar_contract::records::PlaneDisposition::Active,
                    "terminal" => busbar_contract::records::PlaneDisposition::Terminal,
                    _ => return Err(Error::Invalid),
                }
            };
            let record = busbar_contract::records::PlaneRecordRef {
                kind,
                id,
                parent,
                seq,
                ts: c.timestamp("ts")?,
                disposition,
                body: value(&c, "body")?,
            };
            if append == Some(false) && seq != 0 {
                return Err(Error::Invalid);
            }
            if matches!(kind, "demotion" | "trust_decision") {
                if append != Some(false) || seq != 0 || parent.is_some() {
                    return Err(Error::Invalid);
                }
                Route::Prepared(vec![busbar_kernel::persistence::import_target::records::trust::migration_trust_rows(
                    kind,
                    id,
                    record.body,
                )
                .map_err(|_| Error::Invalid)?])
            } else if kind == "ticket" {
                if append != Some(false)
                    || parent.is_some()
                    || disposition != busbar_contract::records::PlaneDisposition::Active
                {
                    return Err(Error::Invalid);
                }
                Route::Prepared(vec![
                    busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_record(id, record.ts, record.body)
                        .map_err(|_| Error::Invalid)?,
                    busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_expiry(id, record.ts)
                        .map_err(|_| Error::Invalid)?,
                ])
            } else if kind == "busbar.admin-idempotency" {
                if append != Some(false) || parent.is_some() {
                    return Err(Error::Invalid);
                }
                let address =
                    busbar_kernel::persistence::import_target::records::scoped::migration_address(
                        true,
                        "busbar.admin",
                        kind,
                        id.as_bytes(),
                    )
                    .map_err(|_| Error::Invalid)?;
                Route::Record {
                    address,
                    value: record.body,
                }
            } else {
                Route::Plane { record, append }
            }
        }
        _ => return Err(Error::Unsupported),
    };
    let address = Address {
        namespace: NAMESPACE.0,
        key: busbar_kernel::persistence::import_target::records::keys::framed(
            b'E',
            &[
                &provenance.dataset,
                &provenance.catalogue,
                table.as_bytes(),
                native_key,
            ],
        )
        .map_err(|_| Error::Range)?,
    };
    Ok(Retained {
        address,
        original,
        route,
    })
}

/// Native verifier capability, selected by compiled host code. Implementations
/// must prove irreversible fencing of the old execution scope and compare exact
/// original evidence. Actual selected pending debt additionally requires its
/// recognized original candidate hash; unrelated receipts remain opaque archive
/// evidence. Shape, age or an operator boolean cannot implement this capability.
pub trait HistoricalReceiptResolution: Send + Sync {
    fn resolve_original(
        &self,
        provenance: Provenance,
        evidence_address: &Address,
        receipt: &Receipt<'_>,
    ) -> Result<[u8; 32], super::super::Error>;
}

/// Compare native-read archive evidence and require actual historical resolution
/// for every receipt. No receipt is executable in the new receipt namespace.
pub fn verify_retained(
    retained: &Retained<'_>,
    native_address: &Address,
    native_original: &[u8],
    provenance: Provenance,
    resolution: &dyn HistoricalReceiptResolution,
) -> Result<Option<[u8; 32]>, super::super::Error> {
    use super::super::Error as MigrationError;
    if native_address != &retained.address || native_original != retained.original {
        return Err(MigrationError::Verification);
    }
    match &retained.route {
        Route::Receipt(receipt) => {
            let digest = resolution.resolve_original(provenance, &retained.address, receipt)?;
            if digest == [0; 32] {
                return Err(MigrationError::Verification);
            }
            Ok(Some(digest))
        }
        Route::RequiresBinding => Err(MigrationError::UnsupportedPath),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::persistence::legacy_row;
    busbar_contract::own_seal!(Own);
    #[test]
    fn synthetic_historical_receipt_is_exact_archive_evidence_never_a_new_receipt() {
        let operation = [7u8; 16];
        let body = [b'a'; 64];
        let encoded = legacy_row::encode::<Own>(
            &[
                Cell::Blob(&operation),
                Cell::Text(&body),
                Cell::Text(b""),
                Cell::Integer(12),
            ],
            4096,
        )
        .unwrap();
        let original = encoded.expose_own(&Own::here());
        let retained = sql(
            Profile::PostgresDev9,
            Provenance {
                dataset: [1; 16],
                catalogue: [2; 32],
            },
            "store_ops",
            &["op_id", "body", "answer", "recorded_at"],
            &operation,
            original,
            &[],
        )
        .unwrap();
        assert!(authorizes(&retained.address));
        assert_eq!(retained.original, original);
        let Route::Receipt(receipt) = retained.route else {
            panic!()
        };
        assert_eq!(receipt.operation, &operation);
        assert_eq!(receipt.body, &body);
        assert!(receipt.completed_shape);
        assert_eq!(receipt.historical_digest, Some([0xaa; 32]));
    }
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
