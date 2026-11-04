// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Declaration-owned mappings from legacy configuration bind slots to transport claims.

/// Statement extension carrying a JSON array of [`ListenerBinding`] records.
pub const EXT_LISTENER_BINDINGS: &str = "listener-bindings";

/// One configuration bind slot served by a claim of the declaring transport.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerBinding {
    /// Configuration slot, independent of the wire protocol.
    pub slot: String,
    /// Exact claim selected for this slot.
    pub claim: String,
}

/// Resolve a slot across distinct accepting transport instances, refusing ambiguity.
pub fn resolve<'a>(
    slot: &str,
    bindings: impl IntoIterator<Item = &'a ListenerBinding>,
) -> Result<String, String> {
    let mut matches = bindings.into_iter().filter(|binding| binding.slot == slot);
    let claim = matches.next().ok_or_else(|| {
        format!("{slot}: no accepting transport declares this configuration bind slot")
    })?;
    if matches.next().is_some() {
        return Err(format!(
            "{slot}: multiple accepting transports declare this configuration bind slot"
        ));
    }
    Ok(claim.claim.clone())
}

/// Read bounded bindings, refusing duplicate slots and claims outside the owning declaration.
pub fn read(extensions: &[u8], claims: &[&str]) -> Result<Vec<ListenerBinding>, String> {
    let Some(bytes) = crate::abi::mechanism::extensions::get(extensions, EXT_LISTENER_BINDINGS)
    else {
        return Ok(Vec::new());
    };
    if bytes.len() > 64 * 1024 {
        return Err("listener-bindings exceeds its declaration bound".into());
    }
    let rows: Vec<ListenerBinding> = serde_json::from_slice(bytes)
        .map_err(|_| "listener-bindings must be a list of slot/claim records".to_string())?;
    if rows.len() > 64 {
        return Err("listener-bindings contains too many records".into());
    }
    for (i, row) in rows.iter().enumerate() {
        if row.slot.is_empty()
            || row.slot.len() > 128
            || !row
                .slot
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("listener-bindings contains an invalid configuration slot".into());
        }
        if !claims.contains(&row.claim.as_str()) {
            return Err("listener-bindings names a claim the transport does not declare".into());
        }
        if rows[..i].iter().any(|prior| prior.slot == row.slot) {
            return Err("listener-bindings repeats a configuration slot".into());
        }
    }
    Ok(rows)
}

#[cfg(test)]
#[path = "../tests/listener_bindings_tests.rs"]
mod tests;
