// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CREDENTIAL IN A HOST RECORD: the one serde path a [`Cred`] has, for a plane that keeps a
//! credential a caller handed it (a webhook credential) in a host record it writes and reads back.
//!
//! A field marked `#[serde(with = "busbar_contract::abi::sdk::cred::record")]` writes its
//! credential only inside [`to_vec`], the SDK's record encoder. Anywhere else (a `serde_json`
//! line for a log, an assert message, a `to_value`) the field REFUSES with [`REFUSED`], so the
//! whole serialization fails and quotes nothing. Reading back is open: a [`Cred`] is captured from
//! the record's string and the string the deserializer handed over is wiped.
//! The record keeps the bytes only, not [`Cred::secure_required`]: the reader states it again
//! ([`Cred::secure_for`] over the URL the credential goes to).
//!
//! THE RESIDUAL, STATED. Plane host records are plain bytes: no plane-reachable host service seals
//! a record field at rest (the chip design's at-rest key, `credentials.at_rest`, is not a
//! plane service), so the record carries the credential as the JSON string it always held, and the
//! [`to_vec`] answer holds it until the plugin hands the value to its record write. That answer is
//! a [`Zeroizing`] buffer the plugin moves into the write and nowhere else. A plugin's own
//! `Serialize` impl running inside [`to_vec`] could still reach the field: this path stops a
//! careless log line, not code that sets out to read process memory (the in-process residual the
//! owner accepted, the chip design's option C). When a plane record-seal service lands, this module
//! seals under it and its callers do not change.

use std::cell::Cell;

use serde::de::Visitor;
use serde::ser::Error as _;
use serde::{Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use super::Cred;

/// What a credential field answers when it is serialized outside [`to_vec`].
pub const REFUSED: &str =
    "a credential serializes only into a host record (busbar_contract::abi::sdk::cred::record::to_vec)";

const NOT_TEXT: &str = "a credential that is not UTF-8 text has no record form";

thread_local! {
    static WRITING: Cell<u32> = const { Cell::new(0) };
}

/// Open while a record is encoded on this thread; closed on drop, a failed encode or a panic
/// included.
struct Scope;

impl Scope {
    fn open() -> Self {
        WRITING.with(|w| w.set(w.get().saturating_add(1)));
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        WRITING.with(|w| w.set(w.get().saturating_sub(1)));
    }
}

/// `value` encoded as a host record's JSON value, its credential fields written. Hand the answer
/// to the record write and nowhere else; it is wiped where it drops.
///
/// # Errors
/// What `serde_json` answers (a credential that is not UTF-8 text among them); no error quotes a
/// credential.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let _scope = Scope::open();
    let mut out = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *out, value)?;
    Ok(out)
}

/// The field's serializer: the credential as a JSON string, inside [`to_vec`] only.
///
/// # Errors
/// [`REFUSED`] outside [`to_vec`]; a credential that is not UTF-8 text.
pub fn serialize<S: Serializer>(cred: &Cred, s: S) -> Result<S::Ok, S::Error> {
    if WRITING.with(Cell::get) == 0 {
        return Err(S::Error::custom(REFUSED));
    }
    let text = std::str::from_utf8(cred.wire()).map_err(|_| S::Error::custom(NOT_TEXT))?;
    s.serialize_str(text)
}

/// The field's deserializer: the record's string captured as a [`Cred`].
///
/// # Errors
/// The value is not a string.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Cred, D::Error> {
    d.deserialize_string(Captured)
}

struct Captured;

impl Visitor<'_> for Captured {
    type Value = Cred;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a credential string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Cred, E> {
        Ok(Cred::captured(Zeroizing::new(v.as_bytes().to_vec())))
    }

    fn visit_string<E: serde::de::Error>(self, mut v: String) -> Result<Cred, E> {
        let cred = Cred::captured(Zeroizing::new(v.as_bytes().to_vec()));
        v.zeroize();
        Ok(cred)
    }
}

#[cfg(test)]
#[path = "../tests/cred_record_tests.rs"]
mod tests;
