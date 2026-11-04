// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opaque, bounded numbering declarations owned by a transport snapshot.

use std::sync::Arc;

/// Maximum UTF-8 byte length of a numbering key.
pub const MAX_NAMESPACE_BYTES: usize = 128;
/// Statement extension containing claim/opening-namespace records.
pub const EXT_HANDOFF_STATUS: &str = "handoff-status";

/// A claim's separate numbering for opening/handoff response pieces.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffStatus {
    claim: String,
    namespace: String,
}

/// Copy a validated nonempty namespace into snapshot-owned storage.
pub fn namespace(value: &str) -> Result<Option<Arc<str>>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_NAMESPACE_BYTES || value.chars().any(char::is_control) {
        return Err("status namespace exceeds its bound or contains control characters".into());
    }
    Ok(Some(Arc::from(value)))
}

/// Read opening namespaces in claim order, rejecting unknown or repeated claims.
pub fn handoff(extensions: &[u8], claims: &[&str]) -> Result<Vec<Option<Arc<str>>>, String> {
    let mut result = vec![None; claims.len()];
    let Some(bytes) = crate::abi::mechanism::extensions::get(extensions, EXT_HANDOFF_STATUS) else {
        return Ok(result);
    };
    if bytes.len() > 64 * 1024 {
        return Err("handoff-status exceeds its declaration bound".into());
    }
    let rows: Vec<HandoffStatus> = serde_json::from_slice(bytes)
        .map_err(|_| "handoff-status must be a list of claim/namespace records".to_owned())?;
    if rows.len() > claims.len() {
        return Err("handoff-status contains too many records".into());
    }
    for row in rows {
        let index = claims
            .iter()
            .position(|claim| *claim == row.claim)
            .ok_or("handoff-status names an undeclared claim")?;
        if result[index].is_some() {
            return Err("handoff-status repeats a claim".into());
        }
        result[index] =
            Some(namespace(&row.namespace)?.ok_or("handoff-status requires a namespace")?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::mechanism::extensions::encode;

    #[test]
    fn opening_namespaces_are_bounded_and_owned_by_the_exact_claim() {
        let bytes = encode(&[(
            EXT_HANDOFF_STATUS,
            br#"[{"claim":"second","namespace":"opening-vendor"}]"#,
        )]);
        let rows = handoff(&bytes, &["first", "second"]).unwrap();
        assert!(rows[0].is_none());
        assert_eq!(rows[1].as_deref(), Some("opening-vendor"));
        drop(bytes);
        assert_eq!(rows[1].as_deref(), Some("opening-vendor"));
        for json in [
            br#"[{"claim":"unknown","namespace":"opening"}]"#.as_slice(),
            br#"[{"claim":"first","namespace":"opening"},{"claim":"first","namespace":"other"}]"#
                .as_slice(),
            br#"[{"claim":"first","namespace":""}]"#.as_slice(),
        ] {
            assert!(handoff(&encode(&[(EXT_HANDOFF_STATUS, json)]), &["first", "second"]).is_err());
        }
        assert!(namespace(&"x".repeat(MAX_NAMESPACE_BYTES + 1)).is_err());
        assert!(namespace("bad\nnamespace").is_err());
        assert_eq!(handoff(&[], &["first"]).unwrap(), vec![None]);
    }
}
