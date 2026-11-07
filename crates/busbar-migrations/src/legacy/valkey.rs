// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure decoding of complete physical Valkey hashes from a frozen source.
//! Header/type/TTL, membership indexes, source identities and duplicate SCAN
//! cells must be verified by the import coordinator before these are called.
use super::Error;
use busbar_contract::records::{MeteringRow, ModelTokens, UsageLedger, RESERVED_UNITS};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Released6,
    Dev7,
    Dev8,
    Dev9,
}
impl Profile {
    fn scale(self) -> u32 {
        if matches!(self, Self::Released6 | Self::Dev7) {
            0
        } else {
            6
        }
    }
}
fn text(bytes: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(bytes).map_err(|_| Error::Type)
}
fn counter(bytes: &[u8]) -> Result<u64, Error> {
    text(bytes)?.parse().map_err(|_| Error::Range)
}
fn quantity(bytes: &[u8], profile: Profile) -> Result<i128, Error> {
    let value: i128 = text(bytes)?.parse().map_err(|_| Error::Range)?;
    if value < 0 {
        return Err(Error::Range);
    }
    busbar_contract::count::Count::from_stored(value, profile.scale())
        .map(|v| v.micros())
        .map_err(|_| Error::Range)
}

/// Every field is consumed exactly once. Unknown fields, aliases and negative
/// quantities fail; historical negative-as-zero readers are not reused.
pub fn usage(profile: Profile, fields: &[(&[u8], &[u8])]) -> Result<UsageLedger, Error> {
    let mut seen = BTreeSet::new();
    let mut requests = None;
    let mut billable = None;
    let mut models = BTreeMap::<String, BTreeMap<String, i128>>::new();
    for (name, value) in fields {
        if !seen.insert(*name) {
            return Err(Error::Columns);
        }
        let name = text(name)?;
        match name {
            "requests" => {
                requests = Some(counter(value)?);
                continue;
            }
            "billable_requests" => {
                billable = Some(counter(value)?);
                continue;
            }
            _ => {}
        }
        let (model, unit) = if let Some(rest) = name.strip_prefix("m:") {
            let (model, unit) = rest.rsplit_once(':').ok_or(Error::Columns)?;
            if !RESERVED_UNITS.contains(&unit) {
                return Err(Error::Columns);
            }
            (model.to_owned(), unit.to_owned())
        } else if profile != Profile::Released6 {
            let rest = name.strip_prefix("u:").ok_or(Error::Columns)?;
            let (hex, model) = rest.split_once(':').ok_or(Error::Columns)?;
            let unit = String::from_utf8(hex::decode(hex).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Type)?;
            if RESERVED_UNITS.contains(&unit.as_str()) {
                return Err(Error::Columns);
            }
            (model.to_owned(), unit)
        } else {
            return Err(Error::Columns);
        };
        if models
            .entry(model)
            .or_default()
            .insert(unit, quantity(value, profile)?)
            .is_some()
        {
            return Err(Error::Columns);
        }
    }
    // An absent physical hash is a known empty cell; a nonempty hash missing a
    // request column is not guessed to be complete.
    if !fields.is_empty() && (requests.is_none() || billable.is_none()) {
        return Err(Error::Columns);
    }
    Ok(UsageLedger {
        requests: requests.unwrap_or(0),
        billable_requests: billable.unwrap_or(0),
        models: models
            .into_iter()
            .map(|(model, usage_units)| ModelTokens {
                scale: 6,
                model,
                usage_units,
            })
            .collect(),
    })
}

pub fn metering(profile: Profile, fields: &[(&[u8], &[u8])]) -> Result<MeteringRow, Error> {
    let mut columns = BTreeMap::new();
    let mut units = BTreeMap::new();
    for (name, value) in fields {
        let name = text(name)?;
        if let Some(unit) = name.strip_prefix("u:") {
            if profile == Profile::Released6
                || RESERVED_UNITS.contains(&unit)
                || units
                    .insert(unit.to_owned(), quantity(value, profile)?)
                    .is_some()
            {
                return Err(Error::Columns);
            }
        } else if columns.insert(name, *value).is_some() {
            return Err(Error::Columns);
        }
    }
    let expected = [
        "key_id",
        "model",
        "provider",
        "tokens_input",
        "tokens_output",
        "tokens_cache_read",
        "tokens_cache_write",
        "requests",
        "billable_requests",
        "key_group_at_use",
        "pricing_version",
    ];
    if columns.keys().any(|name| {
        !expected.contains(name) && !(profile != Profile::Released6 && *name == "priced_from_ms")
    }) || expected.iter().any(|name| !columns.contains_key(name))
    {
        return Err(Error::Columns);
    }
    let get = |name: &str| columns.get(name).copied().ok_or(Error::Columns);
    Ok(MeteringRow {
        scale: 6,
        key_id: text(get("key_id")?)?.to_owned(),
        model: text(get("model")?)?.to_owned(),
        provider: text(get("provider")?)?.to_owned(),
        tokens_input: quantity(get("tokens_input")?, profile)?,
        tokens_output: quantity(get("tokens_output")?, profile)?,
        tokens_cache_read: quantity(get("tokens_cache_read")?, profile)?,
        tokens_cache_write: quantity(get("tokens_cache_write")?, profile)?,
        requests: counter(get("requests")?)?,
        billable_requests: counter(get("billable_requests")?)?,
        key_group_at_use: text(get("key_group_at_use")?)?.to_owned(),
        pricing_version: text(get("pricing_version")?)?.to_owned(),
        priced_from_ms: columns
            .get("priced_from_ms")
            .map(|v| counter(v))
            .transpose()?
            .unwrap_or(0),
        usage_units: units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::persistence::legacy_row::Cell;
    busbar_contract::own_seal!(Own);
    #[test]
    fn snapshot_layout_keeps_real_capture_facts_without_exporter_claims() {
        let counts = 3u64.to_le_bytes();
        let encoded = busbar_contract::persistence::legacy_row::encode::<Own>(
            &[
                Cell::Text(b"busbar.valkey.native-snapshot/1"),
                Cell::Integer(0),
                Cell::Integer(6),
                Cell::Blob(b"8.1.3"),
                Cell::Blob(&[1; 32]),
                Cell::Blob(&[2; 32]),
                Cell::Integer(1),
                Cell::Blob(&counts),
            ],
            4096,
        )
        .unwrap();
        let decoded = NativeLayout::decode(encoded.expose_own(&Own::here())).unwrap();
        assert_eq!(decoded.source_rdb, [2; 32]);
        assert_eq!(decoded.database_key_counts, [3]);
        assert!(
            matches!(decoded.evidence, NativeEvidence::Snapshot { engine_version, native_anchor } if engine_version == "8.1.3" && native_anchor == [1;32])
        );
        let inspection = busbar_contract::persistence::legacy_row::encode::<Own>(
            &[
                Cell::Text(b"busbar.valkey.native-session/1"),
                Cell::Integer(0),
                Cell::Integer(6),
                Cell::Blob(b"8.1.3"),
                Cell::Integer(1),
            ],
            4096,
        )
        .unwrap();
        assert!(NativeLayout::decode(inspection.expose_own(&Own::here())).is_err());
    }
    #[test]
    fn synthetic_whole_and_micro_hashes_have_explicit_scale_and_no_counter_scaling() {
        let fields: &[(&[u8], &[u8])] = &[
            (b"requests", b"4"),
            (b"billable_requests", b"3"),
            (b"m:model:with:colon:input", b"7"),
        ];
        let old = usage(Profile::Released6, fields).unwrap();
        let micro = usage(Profile::Dev8, fields).unwrap();
        assert_eq!(
            (old.requests, old.billable_requests, old.total_input()),
            (4, 3, 7_000_000)
        );
        assert_eq!(micro.total_input(), 7);
    }
    #[test]
    fn synthetic_unknown_fields_negative_counts_and_unit_aliases_are_errors() {
        assert!(usage(
            Profile::Released6,
            &[
                (b"requests", b"0"),
                (b"billable_requests", b"0"),
                (b"unknown", b"1")
            ]
        )
        .is_err());
        assert!(usage(
            Profile::Released6,
            &[
                (b"requests", b"0"),
                (b"billable_requests", b"0"),
                (b"m:m:input", b"-1")
            ]
        )
        .is_err());
        assert!(usage(
            Profile::Dev8,
            &[
                (b"requests", b"0"),
                (b"billable_requests", b"0"),
                (b"u:696e707574:m", b"1")
            ]
        )
        .is_err());
    }
}

#[cfg(test)]
mod released_fixture {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn recorded_155_hashes_decode_exact_released_quantities() {
        let bytes = include_bytes!("fixtures/valkey-1.5.5-rows.json");
        let manifest = include_str!("fixtures/valkey-1.5.5-MANIFEST.tsv");
        let digest = manifest
            .lines()
            .find_map(|line| line.strip_prefix("file\trows.json "))
            .unwrap();
        assert_eq!(hex::encode(Sha256::digest(bytes)), digest);
        let rows: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut checked = 0;
        for (physical_key, value) in rows.as_object().unwrap() {
            if let Some(id) = physical_key.strip_prefix("busbar:key:") {
                key(
                    Profile::Released6,
                    id,
                    value["value"].as_str().unwrap().as_bytes(),
                )
                .unwrap();
                checked += 1;
            }
            if physical_key == "busbar:audit" {
                for item in value["value"].as_array().unwrap() {
                    audit(item[0].as_str().unwrap().as_bytes()).unwrap();
                    checked += 1;
                }
            }
            if value["type"] != "hash" {
                continue;
            }
            let fields = value["value"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| (name.as_bytes(), value.as_str().unwrap().as_bytes()))
                .collect::<Vec<_>>();
            if physical_key.starts_with("busbar:usage:") {
                usage(Profile::Released6, &fields).unwrap();
                checked += 1;
            } else if physical_key.starts_with("busbar:metering:") {
                metering(Profile::Released6, &fields).unwrap();
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}

/// Validate field names without materializing credential values in an unwiped
/// JSON tree. Domain deserialization below allocates credentials only in the
/// existing wiping `CredentialSecret` owner.
fn json_fields(bytes: &[u8], fields: &'static [&'static str], nested: bool) -> Result<(), Error> {
    use serde::de::{DeserializeSeed, MapAccess, Visitor};
    struct Names {
        fields: &'static [&'static str],
        nested: bool,
    }
    impl<'de> DeserializeSeed<'de> for Names {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
            decoder.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Names {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("historical object")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            let mut seen = BTreeSet::new();
            while let Some(name) = map.next_key::<String>()? {
                if !self.fields.contains(&name.as_str()) || !seen.insert(name.clone()) {
                    return Err(serde::de::Error::custom("unsupported historical field"));
                }
                if self.nested && name == "meta" {
                    map.next_value_seed(Names {
                        fields: META_FIELDS,
                        nested: false,
                    })?;
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Names { fields, nested }
        .deserialize(&mut decoder)
        .map_err(|_| Error::Invalid)?;
    decoder.end().map_err(|_| Error::Invalid)
}
const META_FIELDS: &[&str] = &[
    "id",
    "key_id",
    "kind",
    "slot",
    "public_id",
    "secret_form",
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "revision",
];
const KEY_FIELDS: &[&str] = &[
    "id",
    "generation_hash",
    "name",
    "allowed_pools",
    "enabled",
    "created_at",
    "group",
    "labels",
    "expires_at",
    "deleted_at",
    "revision",
];
const DEV_KEY_FIELDS: &[&str] = &[
    "id",
    "generation_hash",
    "name",
    "allowed_pools",
    "enabled",
    "created_at",
    "group",
    "labels",
    "expires_at",
    "deleted_at",
    "revision",
    "idp_subject",
    "binding_mode",
    "minted_by",
    "idp_provider",
    "allowed_agents",
];

pub fn key(
    profile: Profile,
    expected_id: &str,
    bytes: &[u8],
) -> Result<busbar_contract::records::VirtualKey, Error> {
    json_fields(
        bytes,
        if profile == Profile::Released6 {
            KEY_FIELDS
        } else {
            DEV_KEY_FIELDS
        },
        false,
    )?;
    let key: busbar_contract::records::VirtualKey =
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if key.id != expected_id {
        return Err(Error::Invalid);
    }
    Ok(key)
}

pub fn credential(
    _profile: Profile,
    expected_key_id: &str,
    expected_kind: &str,
    expected_slot: u8,
    bytes: &[u8],
) -> Result<busbar_contract::records::CredentialSecret, Error> {
    use busbar_contract::records::CredentialSecret;
    json_fields(bytes, &["meta", "secret"], true)?;
    let value: CredentialSecret = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let meta = &value.meta;
    if meta.key_id != expected_key_id
        || meta.kind != expected_kind
        || meta.slot != expected_slot
        || meta.slot > 1
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}

pub fn audit(bytes: &[u8]) -> Result<busbar_contract::records::AuditRecord, Error> {
    json_fields(
        bytes,
        &[
            "seq",
            "ts",
            "action",
            "resource",
            "outcome",
            "principal",
            "prev_hash",
            "hash",
        ],
        false,
    )?;
    serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalKind {
    Header,
    String,
    Hash,
    Set,
    SortedSet,
    List,
}
#[derive(Clone, Copy)]
pub struct PhysicalCell<'a> {
    pub database: u32,
    pub kind: PhysicalKind,
    /// Absolute Unix milliseconds; never restarted as a fresh relative TTL.
    pub expires_at_ms: Option<i64>,
    pub key: &'a [u8],
    pub position: &'a [u8],
    pub value: &'a [u8],
}
/// Decode the official frozen-RDB export's lossless six-cell contract frame.
pub fn physical(
    row: busbar_contract::persistence::legacy_row::Row<'_>,
) -> Result<PhysicalCell<'_>, Error> {
    use busbar_contract::persistence::legacy_row::Cell;
    let mut cells = row.cells();
    if cells.len() != 6 {
        return Err(Error::Columns);
    }
    let Cell::Integer(database) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    let database = u32::try_from(database).map_err(|_| Error::Range)?;
    let Cell::Integer(kind) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    let kind = match kind {
        0 => PhysicalKind::Header,
        1 => PhysicalKind::String,
        2 => PhysicalKind::Hash,
        3 => PhysicalKind::Set,
        4 => PhysicalKind::SortedSet,
        5 => PhysicalKind::List,
        _ => return Err(Error::Unsupported),
    };
    let Cell::Integer(expiry) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    let expires_at_ms = match expiry {
        -1 => None,
        0.. => Some(expiry),
        _ => return Err(Error::Range),
    };
    let Cell::Blob(key) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    let Cell::Blob(position) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    let Cell::Blob(value) = cells.next().ok_or(Error::Columns)? else {
        return Err(Error::Type);
    };
    if matches!(kind, PhysicalKind::Header | PhysicalKind::String) && !position.is_empty()
        || kind == PhysicalKind::Set && !value.is_empty()
    {
        return Err(Error::Invalid);
    }
    Ok(PhysicalCell {
        database,
        kind,
        expires_at_ms,
        key,
        position,
        value,
    })
}

pub struct CompleteGroup<'a> {
    pub header: PhysicalCell<'a>,
    /// Sorted exact native positions. ZSET scores remain their original bytes.
    pub values: Vec<(&'a [u8], &'a [u8])>,
}
/// Validate one complete frozen native key, deduplicating only byte-identical
/// SCAN observations. Missing headers, expiry drift, mixed types, list gaps and
/// conflicting duplicates fail; unknown native types are never omitted.
pub fn complete_group<'a>(
    cells: &[PhysicalCell<'a>],
    max_items: usize,
    max_bytes: usize,
) -> Result<CompleteGroup<'a>, Error> {
    if cells.is_empty() || cells.len() > max_items {
        return Err(Error::Range);
    }
    let mut bytes = 0usize;
    let mut header = None;
    let mut values = BTreeMap::new();
    let first = cells[0];
    for cell in cells {
        bytes = bytes
            .checked_add(cell.key.len())
            .and_then(|v| v.checked_add(cell.position.len()))
            .and_then(|v| v.checked_add(cell.value.len()))
            .ok_or(Error::Range)?;
        if bytes > max_bytes
            || cell.database != first.database
            || cell.key != first.key
            || cell.expires_at_ms != first.expires_at_ms
        {
            return Err(Error::Invalid);
        }
        if cell.kind == PhysicalKind::Header {
            if header.is_some_and(|previous: PhysicalCell<'_>| previous.value != cell.value) {
                return Err(Error::Invalid);
            }
            header = Some(*cell);
        } else if values
            .insert(cell.position, (cell.kind, cell.value))
            .is_some_and(|previous| previous != (cell.kind, cell.value))
        {
            return Err(Error::Invalid);
        }
    }
    let header = header.ok_or(Error::Invalid)?;
    let kind = header_kind(header.value)?;
    if values.values().any(|(actual, _)| *actual != kind) {
        return Err(Error::Invalid);
    }
    if kind == PhysicalKind::String && (values.len() != 1 || !values.contains_key(b"".as_slice())) {
        return Err(Error::Invalid);
    }
    if kind == PhysicalKind::List {
        let mut positions = BTreeSet::new();
        for position in values.keys() {
            let index = counter(position)?;
            if index.to_string().as_bytes() != *position || !positions.insert(index) {
                return Err(Error::Invalid);
            }
        }
        if positions
            .iter()
            .copied()
            .enumerate()
            .any(|(expected, actual)| actual != expected as u64)
        {
            return Err(Error::Invalid);
        }
    }
    Ok(CompleteGroup {
        header,
        values: values
            .into_iter()
            .map(|(position, (_, value))| (position, value))
            .collect(),
    })
}

pub const NATIVE_COLUMNS: &[&str] = &["db", "kind", "absolute_expiry", "key", "position", "value"];
pub const IMPORTER_OWNER: [u8; 16] = *b"legacy.valkey.v1";
pub enum NativeEvidence {
    Exporter {
        engine_version: u32,
        native_export: [u8; 32],
        engine_artifact: [u8; 32],
        export_module: [u8; 32],
    },
    Snapshot {
        engine_version: String,
        native_anchor: [u8; 32],
    },
}
pub struct NativeLayout {
    pub source_db: u32,
    pub profile: Profile,
    pub source_rdb: [u8; 32],
    pub evidence: NativeEvidence,
    pub database_key_counts: Vec<u64>,
}
impl NativeLayout {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        use busbar_contract::persistence::legacy_row::{Cell, Row};
        let mut cells = Row::decode(bytes).map_err(|_| Error::Invalid)?.cells();
        if cells.len() == 8 {
            return Self::snapshot(bytes);
        }
        if cells.len() != 10
            || cells.next() != Some(Cell::Text(b"busbar.valkey.native-inventory/1"))
        {
            return Err(Error::Unsupported);
        }
        let mut uint = || match cells.next() {
            Some(Cell::Integer(v)) => u32::try_from(v).map_err(|_| Error::Range),
            _ => Err(Error::Type),
        };
        let source_db = uint()?;
        let schema = uint()?;
        let engine_version = uint()?;
        let profile = match schema {
            6 => Profile::Released6,
            7 => Profile::Dev7,
            8 => Profile::Dev8,
            9 => Profile::Dev9,
            _ => return Err(Error::Unsupported),
        };
        let mut digest = || match cells.next() {
            Some(Cell::Blob(v)) => {
                let value: [u8; 32] = v.try_into().map_err(|_| Error::Invalid)?;
                if value == [0; 32] {
                    return Err(Error::Invalid);
                }
                Ok(value)
            }
            _ => Err(Error::Type),
        };
        let source_rdb = digest()?;
        let native_export = digest()?;
        let engine_artifact = digest()?;
        let export_module = digest()?;
        let count = match cells.next() {
            Some(Cell::Integer(v)) if (1..=1024).contains(&v) => v as usize,
            _ => return Err(Error::Range),
        };
        let Some(Cell::Blob(counts)) = cells.next() else {
            return Err(Error::Type);
        };
        if engine_version == 0
            || source_db as usize >= count
            || counts.len() != count.checked_mul(8).ok_or(Error::Range)?
        {
            return Err(Error::Invalid);
        }
        let database_key_counts = counts
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| u64::from_le_bytes(*bytes))
            .collect::<Vec<_>>();
        if database_key_counts[source_db as usize] == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            source_db,
            profile,
            source_rdb,
            evidence: NativeEvidence::Exporter {
                engine_version,
                native_export,
                engine_artifact,
                export_module,
            },
            database_key_counts,
        })
    }
    fn snapshot(bytes: &[u8]) -> Result<Self, Error> {
        use busbar_contract::persistence::legacy_row::{Cell, Row};
        let mut cells = Row::decode(bytes).map_err(|_| Error::Invalid)?.cells();
        if cells.len() != 8 || cells.next() != Some(Cell::Text(b"busbar.valkey.native-snapshot/1"))
        {
            return Err(Error::Unsupported);
        }
        let source_db = match cells.next() {
            Some(Cell::Integer(v)) => u32::try_from(v).map_err(|_| Error::Range)?,
            _ => return Err(Error::Type),
        };
        let profile = match cells.next() {
            Some(Cell::Integer(6)) => Profile::Released6,
            Some(Cell::Integer(7)) => Profile::Dev7,
            Some(Cell::Integer(8)) => Profile::Dev8,
            Some(Cell::Integer(9)) => Profile::Dev9,
            _ => return Err(Error::Unsupported),
        };
        let engine_version = match cells.next() {
            Some(Cell::Blob(v))
                if !v.is_empty() && v.len() <= 128 && v.iter().all(u8::is_ascii_graphic) =>
            {
                text(v)?.to_owned()
            }
            _ => return Err(Error::Invalid),
        };
        let mut digest = || match cells.next() {
            Some(Cell::Blob(v)) => {
                let digest: [u8; 32] = v.try_into().map_err(|_| Error::Invalid)?;
                if digest == [0; 32] {
                    return Err(Error::Invalid);
                }
                Ok(digest)
            }
            _ => Err(Error::Type),
        };
        let native_anchor = digest()?;
        let source_rdb = digest()?;
        let count = match cells.next() {
            Some(Cell::Integer(v)) if (1..=1024).contains(&v) => v as usize,
            _ => return Err(Error::Range),
        };
        let counts = match cells.next() {
            Some(Cell::Blob(v)) if v.len() == count * 8 && (source_db as usize) < count => v,
            _ => return Err(Error::Invalid),
        };
        let database_key_counts = counts
            .as_chunks::<8>()
            .0
            .iter()
            .map(|v| u64::from_le_bytes(*v))
            .collect::<Vec<_>>();
        if database_key_counts[source_db as usize] == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            source_db,
            profile,
            source_rdb,
            evidence: NativeEvidence::Snapshot {
                engine_version,
                native_anchor,
            },
            database_key_counts,
        })
    }
    pub fn importer_format(&self) -> super::super::Format {
        super::super::Format {
            owner: IMPORTER_OWNER,
            physical: match self.profile {
                Profile::Released6 => 6,
                Profile::Dev7 => 7,
                Profile::Dev8 => 8,
                Profile::Dev9 => 9,
            },
            logical: 1,
            codec: 1,
        }
    }
}

pub fn native_identity_matches(cell: PhysicalCell<'_>, native_key: &[u8]) -> bool {
    use busbar_contract::persistence::legacy_row::{Cell, Row};
    let Ok(row) = Row::decode(native_key) else {
        return false;
    };
    let kind = match cell.kind {
        PhysicalKind::Header => 0,
        PhysicalKind::String => 1,
        PhysicalKind::Hash => 2,
        PhysicalKind::Set => 3,
        PhysicalKind::SortedSet => 4,
        PhysicalKind::List => 5,
    };
    row.cells().eq([
        Cell::Integer(i64::from(cell.database)),
        Cell::Integer(kind),
        Cell::Blob(cell.key),
        Cell::Blob(cell.position),
    ])
}

pub(super) fn pointer(bytes: &[u8]) -> Result<(&str, &str, u8), Error> {
    let (rest, slot) = text(bytes)?.rsplit_once(':').ok_or(Error::Invalid)?;
    let (owner, kind) = rest.rsplit_once(':').ok_or(Error::Invalid)?;
    let slot = slot.parse::<u8>().map_err(|_| Error::Invalid)?;
    if slot > 1 || kind.is_empty() {
        return Err(Error::Invalid);
    }
    Ok((owner, kind, slot))
}

busbar_contract::own_seal!(InventoryOwn);
fn identity_frame(
    cell: PhysicalCell<'_>,
    kind: i64,
    position: &[u8],
    budget: usize,
) -> Result<busbar_contract::Secret<Vec<u8>, InventoryOwn>, super::super::Error> {
    use busbar_contract::persistence::legacy_row::{self, Cell};
    legacy_row::encode::<InventoryOwn>(
        &[
            Cell::Integer(i64::from(cell.database)),
            Cell::Integer(kind),
            Cell::Blob(cell.key),
            Cell::Blob(position),
        ],
        budget,
    )
    .map_err(|_| super::super::Error::Bounds)
}
fn header_kind(value: &[u8]) -> Result<PhysicalKind, Error> {
    match value {
        b"string" => Ok(PhysicalKind::String),
        b"hash" => Ok(PhysicalKind::Hash),
        b"set" => Ok(PhysicalKind::Set),
        b"zset" => Ok(PhysicalKind::SortedSet),
        b"list" => Ok(PhysicalKind::List),
        _ => Err(Error::Unsupported),
    }
}

/// Streaming global physical census against the seekable, already SHA-verified
/// archive. The archive's native-identity index rejects duplicates before this
/// pass. Only fixed database counters and one protected frame remain resident.
/// Every child must resolve its original header/type/absoluteexpiry; metadata
/// key counts alone cannot manufacture a complete native snapshot.
pub fn verify_inventory(
    layout: &NativeLayout,
    source: &mut dyn super::super::archive_source::ArchiveRows,
    metadata_bytes: usize,
) -> Result<(), super::super::Error> {
    use super::super::Error as MigrationError;
    use busbar_contract::persistence::legacy_row::Row;
    if source.header().owner != IMPORTER_OWNER
        || source.header().physical != layout.importer_format().physical
        || source.header().tables.len() != 1
        || source.header().tables[0].name != "valkey"
    {
        return Err(MigrationError::IdentityMismatch);
    }
    if let NativeEvidence::Snapshot { native_anchor, .. } = &layout.evidence {
        if *native_anchor != source.header().native_anchor_digest {
            return Err(MigrationError::IdentityMismatch);
        }
    }
    if layout
        .database_key_counts
        .len()
        .checked_mul(std::mem::size_of::<u64>())
        .is_none_or(|bytes| bytes > metadata_bytes)
    {
        return Err(MigrationError::Bounds);
    }
    let mut counts = vec![0u64; layout.database_key_counts.len()];
    let mut schema_cells = 0u64;
    let mut highest_revision = 0u64;
    let mut allocator_revision = None;
    let mut secondary = SecondaryCensus {
        observations: Vec::new(),
        charge: counts.len() * 2 * std::mem::size_of::<u64>(),
        limit: metadata_bytes,
    };
    let seal = crate::seal::lend();
    for ordinal in 0..source.row_count() {
        let record = source.read_row(ordinal)?;
        if record.table != 0 {
            return Err(MigrationError::Corrupt);
        }
        let cell =
            physical(Row::decode(record.value.expose(&seal)).map_err(|_| MigrationError::Corrupt)?)
                .map_err(|_| MigrationError::Corrupt)?;
        if !native_identity_matches(cell, record.native_key.expose(&seal)) {
            return Err(MigrationError::Corrupt);
        }
        let count = counts
            .get_mut(cell.database as usize)
            .ok_or(MigrationError::Corrupt)?;
        let header_key = identity_frame(cell, 0, b"", record.native_key.expose(&seal).len())?;
        let header_ordinal = source
            .find_native(0, header_key.expose_own(&InventoryOwn::here()))?
            .ok_or(MigrationError::Verification)?;
        let header_row = source.read_row(header_ordinal)?;
        let header = physical(
            Row::decode(header_row.value.expose(&seal)).map_err(|_| MigrationError::Corrupt)?,
        )
        .map_err(|_| MigrationError::Corrupt)?;
        if header.kind != PhysicalKind::Header
            || header.database != cell.database
            || header.key != cell.key
            || header.expires_at_ms != cell.expires_at_ms
        {
            return Err(MigrationError::Verification);
        }
        let kind = header_kind(header.value).map_err(|_| MigrationError::UnsupportedVersion)?;
        if cell.kind == PhysicalKind::Header {
            *count = count.checked_add(1).ok_or(MigrationError::Bounds)?;
            if kind == PhysicalKind::String {
                let key = identity_frame(cell, 1, b"", record.native_key.expose(&seal).len())?;
                if source
                    .find_native(0, key.expose_own(&InventoryOwn::here()))?
                    .is_none()
                {
                    return Err(MigrationError::Verification);
                }
            }
            if kind == PhysicalKind::List {
                let key = identity_frame(
                    cell,
                    5,
                    b"0",
                    record
                        .native_key
                        .expose(&seal)
                        .len()
                        .checked_add(1)
                        .ok_or(MigrationError::Bounds)?,
                )?;
                if source
                    .find_native(0, key.expose_own(&InventoryOwn::here()))?
                    .is_none()
                {
                    return Err(MigrationError::Verification);
                }
            }
        } else if cell.kind != kind {
            return Err(MigrationError::Verification);
        }
        if cell.kind == PhysicalKind::List {
            let index = counter(cell.position).map_err(|_| MigrationError::Corrupt)?;
            if index.to_string().as_bytes() != cell.position {
                return Err(MigrationError::Corrupt);
            }
            if index != 0 {
                let previous = (index - 1).to_string();
                let key = identity_frame(
                    cell,
                    5,
                    previous.as_bytes(),
                    record.native_key.expose(&seal).len(),
                )?;
                if source
                    .find_native(0, key.expose_own(&InventoryOwn::here()))?
                    .is_none()
                {
                    return Err(MigrationError::Verification);
                }
            }
        }
        if cell.database == layout.source_db && cell.key == b"busbar:schema" {
            if kind != PhysicalKind::String || cell.expires_at_ms.is_some() {
                return Err(MigrationError::Verification);
            }
            if cell.kind == PhysicalKind::String {
                schema_cells = schema_cells.checked_add(1).ok_or(MigrationError::Bounds)?;
                let actual = text(cell.value)
                    .map_err(|_| MigrationError::Corrupt)?
                    .parse::<i64>()
                    .map_err(|_| MigrationError::Corrupt)?;
                if actual != i64::from(layout.importer_format().physical) {
                    return Err(MigrationError::UnsupportedVersion);
                }
            }
        }
        if cell.database == layout.source_db && cell.kind == PhysicalKind::String {
            if cell.key == b"busbar:revision" {
                let revision = counter(cell.value).map_err(|_| MigrationError::Corrupt)?;
                if allocator_revision.replace(revision).is_some() {
                    return Err(MigrationError::Verification);
                }
            } else if let Some(id) = cell.key.strip_prefix(b"busbar:key:") {
                let record = key(
                    layout.profile,
                    text(id).map_err(|_| MigrationError::Corrupt)?,
                    cell.value,
                )
                .map_err(|_| MigrationError::Corrupt)?;
                highest_revision = highest_revision.max(record.revision);
            } else if let Some(raw) = cell.key.strip_prefix(b"busbar:cred:") {
                if !raw.starts_with(b"id:") && !raw.starts_with(b"pub:") {
                    let (owner, kind, slot) = pointer(raw).map_err(|_| MigrationError::Corrupt)?;
                    let record = credential(layout.profile, owner, kind, slot, cell.value)
                        .map_err(|_| MigrationError::Corrupt)?;
                    highest_revision = highest_revision.max(record.meta.revision);
                }
            }
        }
        secondary_inventory(layout, source, cell, &mut secondary)?;
    }
    secondary.finish()?;
    if counts != layout.database_key_counts
        || schema_cells != 1
        || allocator_revision.unwrap_or(0) < highest_revision
    {
        return Err(MigrationError::Verification);
    }
    Ok(())
}

pub(crate) struct Sidecar {
    pub id: String,
    pub parent: Option<String>,
    pub seq: u64,
    pub ts: u64,
    pub disposition: busbar_contract::records::PlaneDisposition,
}
pub(crate) fn sidecar(bytes: &[u8]) -> Result<Sidecar, Error> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        id: String,
        parent: Option<String>,
        seq: u64,
        ts: u64,
    }
    let flags = bytes.get(..2).ok_or(Error::Invalid)?;
    if !matches!(flags, b"0a" | b"0t" | b"1a" | b"1t") {
        return Err(Error::Invalid);
    }
    let wire: Wire = serde_json::from_slice(bytes.get(2..).ok_or(Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    if (flags[0] == b'1') != wire.parent.is_some() {
        return Err(Error::Invalid);
    }
    Ok(Sidecar {
        id: wire.id,
        parent: wire.parent,
        seq: wire.seq,
        ts: wire.ts,
        disposition: if flags[1] == b't' {
            busbar_contract::records::PlaneDisposition::Terminal
        } else {
            busbar_contract::records::PlaneDisposition::Active
        },
    })
}
pub(crate) fn plane_key(key: &[u8]) -> Result<(String, &str), Error> {
    let rest = text(key)?
        .strip_prefix("busbar:plane:")
        .ok_or(Error::Invalid)?;
    let (kind, suffix) = rest.split_once(':').ok_or(Error::Invalid)?;
    let decoded = String::from_utf8(hex::decode(kind).map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Type)?;
    if hex::encode(decoded.as_bytes()) != kind {
        return Err(Error::Invalid);
    }
    Ok((decoded, suffix))
}
pub(crate) fn plane_position(position: &[u8]) -> Result<(u64, &str), Error> {
    let (seq, identity) = text(position)?.split_once(':').ok_or(Error::Invalid)?;
    let parsed = seq.parse::<u64>().map_err(|_| Error::Invalid)?;
    if parsed.to_string() != seq {
        return Err(Error::Invalid);
    }
    Ok((parsed, identity))
}

struct ParentObservation {
    key: busbar_contract::Secret<Vec<u8>>,
    declared: Option<u64>,
    contributes: bool,
}
struct SecondaryCensus {
    observations: Vec<ParentObservation>,
    charge: usize,
    limit: usize,
}
impl SecondaryCensus {
    fn scratch(&self, bytes: usize) -> Result<(), super::super::Error> {
        if self
            .charge
            .checked_add(bytes)
            .is_none_or(|v| v > self.limit)
        {
            Err(super::super::Error::Bounds)
        } else {
            Ok(())
        }
    }
    fn parent(
        &mut self,
        database: u32,
        kind: &str,
        parent: &str,
        declared: Option<u64>,
    ) -> Result<(), super::super::Error> {
        let size = 17usize
            .checked_add(kind.len())
            .and_then(|n| n.checked_add(parent.len()))
            .ok_or(super::super::Error::Bounds)?;
        let extra = size
            .checked_add(std::mem::size_of::<ParentObservation>())
            .ok_or(super::super::Error::Bounds)?;
        self.scratch(extra)?;
        self.observations
            .try_reserve_exact(1)
            .map_err(|_| super::super::Error::Bounds)?;
        let key = busbar_kernel::persistence::import_target::records::keys::framed(
            b'P',
            &[&database.to_be_bytes(), kind.as_bytes(), parent.as_bytes()],
        )
        .map_err(|_| super::super::Error::Bounds)?;
        self.charge += extra;
        self.observations.push(ParentObservation {
            key: busbar_contract::Secret::new(key),
            declared,
            contributes: declared.is_none(),
        });
        Ok(())
    }
    fn finish(mut self) -> Result<(), super::super::Error> {
        let seal = crate::seal::lend();
        self.observations
            .sort_by(|a, b| a.key.expose(&seal).cmp(b.key.expose(&seal)));
        let mut key = None;
        let mut actual = 0u64;
        let mut declared = None;
        for row in self.observations {
            if key.as_ref().is_some_and(|key| key != &row.key) {
                if declared != Some(actual) || actual == 0 {
                    return Err(super::super::Error::Verification);
                }
                actual = 0;
                declared = None;
            }
            if row.contributes {
                actual = actual.checked_add(1).ok_or(super::super::Error::Bounds)?;
            } else if declared
                .replace(row.declared.ok_or(super::super::Error::Corrupt)?)
                .is_some()
            {
                return Err(super::super::Error::Verification);
            }
            key = Some(row.key);
        }
        if key.is_some() && (declared != Some(actual) || actual == 0) {
            return Err(super::super::Error::Verification);
        }
        Ok(())
    }
}
fn indexed_cell(
    source: &mut dyn super::super::archive_source::ArchiveRows,
    cell: PhysicalCell<'_>,
    kind: i64,
    key: &[u8],
    position: &[u8],
    budget: usize,
) -> Result<busbar_contract::persistence::archive::ArchiveRow, super::super::Error> {
    let expected = PhysicalCell { key, ..cell };
    let encoded = identity_frame(expected, kind, position, budget)?;
    let ordinal = source
        .find_native(0, encoded.expose_own(&InventoryOwn::here()))?
        .ok_or(super::super::Error::Verification)?;
    let row = source.read_row(ordinal)?;
    let parsed = physical(
        busbar_contract::persistence::legacy_row::Row::decode(
            row.value.expose(&crate::seal::lend()),
        )
        .map_err(|_| super::super::Error::Corrupt)?,
    )
    .map_err(|_| super::super::Error::Corrupt)?;
    let expected_kind = match kind {
        1 => PhysicalKind::String,
        2 => PhysicalKind::Hash,
        3 => PhysicalKind::Set,
        4 => PhysicalKind::SortedSet,
        5 => PhysicalKind::List,
        _ => return Err(super::super::Error::Corrupt),
    };
    if parsed.kind != expected_kind
        || parsed.database != cell.database
        || parsed.key != key
        || parsed.position != position
        || parsed.expires_at_ms != cell.expires_at_ms
    {
        return Err(super::super::Error::Verification);
    }
    Ok(row)
}
fn secondary_inventory(
    layout: &NativeLayout,
    source: &mut dyn super::super::archive_source::ArchiveRows,
    cell: PhysicalCell<'_>,
    census: &mut SecondaryCensus,
) -> Result<(), super::super::Error> {
    use super::super::Error as MigrationError;
    if cell.database != layout.source_db
        || cell.kind == PhysicalKind::Header
        || !cell.key.starts_with(b"busbar:")
    {
        return Ok(());
    }
    let key = text(cell.key).map_err(|_| MigrationError::Corrupt)?;
    let seal = crate::seal::lend();
    if let Some(rest) = key.strip_prefix("busbar:records:") {
        if layout.profile == Profile::Released6 {
            return Err(MigrationError::UnsupportedPath);
        }
        let (schema, suffix) = rest.rsplit_once(':').ok_or(MigrationError::Corrupt)?;
        let schema_bytes = hex::decode(schema).map_err(|_| MigrationError::Corrupt)?;
        if hex::encode(&schema_bytes) != schema {
            return Err(MigrationError::Corrupt);
        }
        let scratch = cell
            .key
            .len()
            .checked_add(cell.position.len())
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_add(128))
            .ok_or(MigrationError::Bounds)?;
        census.scratch(scratch)?;
        let other = match (suffix, cell.kind) {
            ("v", PhysicalKind::Hash) => {
                if cell.value.len() > busbar_contract::bounded::MAX_RECORD_BYTES {
                    return Err(MigrationError::Corrupt);
                }
                format!("busbar:records:{schema}:k")
            }
            ("k", PhysicalKind::SortedSet) if cell.value == b"0" => {
                format!("busbar:records:{schema}:v")
            }
            _ => return Err(MigrationError::Corrupt),
        };
        let row = indexed_cell(
            source,
            cell,
            if suffix == "v" { 4 } else { 2 },
            other.as_bytes(),
            cell.position,
            scratch,
        )?;
        let other = physical(
            busbar_contract::persistence::legacy_row::Row::decode(row.value.expose(&seal))
                .map_err(|_| MigrationError::Corrupt)?,
        )
        .map_err(|_| MigrationError::Corrupt)?;
        if suffix == "v" && other.value != b"0" {
            return Err(MigrationError::Verification);
        }
        return Ok(());
    }
    if !key.starts_with("busbar:plane:") {
        return Ok(());
    }
    if layout.profile == Profile::Released6 {
        return Err(MigrationError::UnsupportedPath);
    }
    let (kind, suffix) = plane_key(cell.key).map_err(|_| MigrationError::Corrupt)?;
    let kind_hex = hex::encode(kind.as_bytes());
    let prefix = format!("busbar:plane:{kind_hex}:");
    let scratch = cell
        .key
        .len()
        .checked_add(cell.position.len())
        .and_then(|n| n.checked_add(cell.value.len()))
        .and_then(|n| n.checked_mul(6))
        .and_then(|n| n.checked_add(256))
        .ok_or(MigrationError::Bounds)?;
    census.scratch(scratch)?;
    if suffix == "pcount" {
        if cell.kind != PhysicalKind::Hash {
            return Err(MigrationError::Corrupt);
        }
        let count = counter(cell.value).map_err(|_| MigrationError::Corrupt)?;
        if count == 0 {
            return Err(MigrationError::Verification);
        }
        census.parent(
            cell.database,
            &kind,
            text(cell.position).map_err(|_| MigrationError::Corrupt)?,
            Some(count),
        )?;
        return Ok(());
    }
    if suffix.starts_with("tok:") {
        return Ok(());
    }
    let (sequence, identity) =
        plane_position(cell.position).map_err(|_| MigrationError::Corrupt)?;
    let rec_key = format!("{prefix}rec");
    let body_key = format!("{prefix}body");
    let side_row = indexed_cell(source, cell, 2, rec_key.as_bytes(), cell.position, scratch)?;
    let side_cell = physical(
        busbar_contract::persistence::legacy_row::Row::decode(side_row.value.expose(&seal))
            .map_err(|_| MigrationError::Corrupt)?,
    )
    .map_err(|_| MigrationError::Corrupt)?;
    let side = sidecar(side_cell.value).map_err(|_| MigrationError::Corrupt)?;
    if side.seq != sequence || identity != side.id && side.parent.as_deref() != Some(identity) {
        return Err(MigrationError::Verification);
    }
    indexed_cell(source, cell, 2, body_key.as_bytes(), cell.position, scratch)?;
    match suffix {
        "rec" => {
            if cell.kind != PhysicalKind::Hash {
                return Err(MigrationError::Corrupt);
            }
            let byts = format!("{prefix}byts");
            indexed_cell(source, cell, 4, byts.as_bytes(), cell.position, scratch)?;
            let index = format!("{prefix}idx:{}", hex::encode(identity.as_bytes()));
            indexed_cell(source, cell, 4, index.as_bytes(), cell.position, scratch)?;
            if let Some(parent) = side.parent.as_deref() {
                census.parent(cell.database, &kind, parent, None)?;
                if parent != identity {
                    let index = format!("{prefix}idx:{}", hex::encode(parent.as_bytes()));
                    indexed_cell(source, cell, 4, index.as_bytes(), cell.position, scratch)?;
                }
            }
        }
        "body" if cell.kind == PhysicalKind::Hash => {}
        "byts" if cell.kind == PhysicalKind::SortedSet => {}
        _ if suffix.starts_with("idx:") && cell.kind == PhysicalKind::SortedSet => {
            let encoded = suffix.strip_prefix("idx:").ok_or(MigrationError::Corrupt)?;
            let scope =
                String::from_utf8(hex::decode(encoded).map_err(|_| MigrationError::Corrupt)?)
                    .map_err(|_| MigrationError::Corrupt)?;
            if hex::encode(scope.as_bytes()) != encoded
                || scope != identity && side.parent.as_deref() != Some(scope.as_str())
            {
                return Err(MigrationError::Verification);
            }
        }
        _ => return Err(MigrationError::UnsupportedPath),
    }
    Ok(())
}
