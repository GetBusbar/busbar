// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// Every whole entry of `blob`, in order: `(key, value)`.
pub fn entries(blob: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let k = usize::from(u16::from_le_bytes(blob.get(at..at + 2)?.try_into().ok()?));
        let key = blob.get(at + 2..at + 2 + k)?;
        let v_at = at + 2 + k;
        let v = u32::from_le_bytes(blob.get(v_at..v_at + 4)?.try_into().ok()?);
        let v = usize::try_from(v).ok()?;
        let value = blob.get(v_at + 4..(v_at + 4).checked_add(v)?)?;
        at = v_at + 4 + v;
        Some((key, value))
    })
}

/// The value `blob` states under `key` (its first entry so named); `None` when it states none.
#[must_use]
pub fn get<'a>(blob: &'a [u8], key: &str) -> Option<&'a [u8]> {
    entries(blob)
        .find(|(k, _)| *k == key.as_bytes())
        .map(|(_, v)| v)
}

/// The `declares` document's key in a door's `Statement::extensions`.
pub const EXT_DECLARES: &str = "declares";

/// The reference-capable, non-secret settings fields' key in a door's `Statement::extensions`.
pub const EXT_REFERENCE_FIELDS: &str = "reference_fields";

/// The reference-capable paths a Statement's extensions state under [`EXT_REFERENCE_FIELDS`];
pub fn reference_fields(extensions: &[u8]) -> Result<Vec<String>, String> {
    let Some(value) = get(extensions, EXT_REFERENCE_FIELDS) else {
        return Ok(Vec::new());
    };
    let paths: Vec<String> = busbar_json::parse(value).map_err(|_| {
        format!("extensions.{EXT_REFERENCE_FIELDS} is not a JSON list of settings paths")
    })?;
    if paths.iter().any(String::is_empty) {
        return Err(format!(
            "extensions.{EXT_REFERENCE_FIELDS} names an empty settings path"
        ));
    }
    Ok(paths)
}
