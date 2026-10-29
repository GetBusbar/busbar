// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S SHARED PIECES (`abi::plane`): what the planes wrote alike, stated once.
//!
//! * [`dealt_section`] — the section a plane declares, read out of the blob `validate` is dealt
//!   (`{<verb>: <section>}` for each stated verb the document writes; architect ruling R-6).

/// The refusal of a dealt blob that is JSON but not an object.
pub const NOT_A_MAP: &str = "the dealt settings are not a map of the plane's sections";

/// The section `verb` names in the dealt blob `settings`: `None` when the blob is empty, writes no
/// `verb`, or writes it `null` (the empty section); the section's value otherwise.
///
/// # Errors
/// The blob is not JSON (serde's words), or not an object ([`NOT_A_MAP`]).
pub fn dealt_section(settings: &[u8], verb: &str) -> Result<Option<serde_json::Value>, String> {
    if settings.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let serde_json::Value::Object(mut verbs) = value else {
        return Err(NOT_A_MAP.to_string());
    };
    Ok(verbs.remove(verb).filter(|section| !section.is_null()))
}

#[cfg(test)]
#[path = "tests/plane_tests.rs"]
mod tests;
