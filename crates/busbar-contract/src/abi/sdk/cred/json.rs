// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON WHOSE STRING MEMBERS MAY BE CREDENTIALS (the chip design, its sections on secrets at rest and on

use core::fmt;

use serde::de::DeserializeOwned;

use super::{Cred, SealedWrite};
use crate::secure::SecureString;

/// The class of a reply that did not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFailure {
    /// The body could not be read.
    Io,
    /// The body is not well-formed JSON.
    Syntax,
    /// A member is missing or has the wrong type.
    Data,
    /// The body ends before the JSON does.
    Eof,
}

/// Why a reply did not read: the class of the failure and where it sits, never the decoder's own
/// text (a data error quotes the offending value, which may be the credential).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonReplyError {
    failure: JsonFailure,
    line: usize,
    column: usize,
}

impl JsonReplyError {
    /// The class of the failure.
    #[must_use]
    pub const fn failure(&self) -> JsonFailure {
        self.failure
    }

    /// The line it sits on (1-based).
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// The column it sits at (1-based).
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }
}

/// `<the class> (line <l>, column <c>; the decoder's text is withheld)`.
impl fmt::Display for JsonReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.failure {
            JsonFailure::Io => "the body could not be read",
            JsonFailure::Syntax => "it is not well-formed JSON",
            JsonFailure::Data => "a field is missing or has the wrong type",
            JsonFailure::Eof => "it ends before the JSON does",
        };
        write!(
            f,
            "{class} (line {}, column {}; the decoder's text is withheld)",
            self.line, self.column
        )
    }
}

impl std::error::Error for JsonReplyError {}

/// Read a JSON reply `body` into `T`. Every [`Cred`] member of `T` is captured as it is read (from
pub fn json_reply<T: DeserializeOwned>(body: &[u8]) -> Result<T, JsonReplyError> {
    serde_json::from_slice(body).map_err(JsonReplyError::from)
}

impl From<serde_json::Error> for JsonReplyError {
    fn from(e: serde_json::Error) -> Self {
        use serde_json::error::Category;
        Self {
            failure: match e.classify() {
                Category::Io => JsonFailure::Io,
                Category::Syntax => JsonFailure::Syntax,
                Category::Data => JsonFailure::Data,
                Category::Eof => JsonFailure::Eof,
            },
            line: e.line(),
            column: e.column(),
        }
    }
}

impl Cred {
    /// Whether it begins with `prefix`: a public format marker (a provider's `ek_` on the tokens it
    #[must_use]
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.wire().starts_with(prefix)
    }
}

/// A member's value: a public value already encoded as JSON (in custody), or a credential.
#[derive(Clone)]
enum Member {
    Public(crate::secure::SecureVec),
    Sealed(Cred),
}

/// Equal when the encodings (or the credentials) are equal.
impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Public(a), Self::Public(b)) => a[..] == b[..],
            (Self::Sealed(a), Self::Sealed(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Member {}

/// A JSON object whose members are public values or credentials, in the order named. The SDK
/// encodes it ([`SealedJson::encoded`]) as `serde_json::to_vec` writes the same members in the same
/// order: compact, every string escaped as `serde_json` escapes it. (`serde_json::json!` without
/// `preserve_order` writes an object's members sorted by name: name them sorted to match it.)
#[derive(Clone, Default)]
pub struct SealedJson {
    /// The members; a name is held in custody and wiped when the object drops.
    members: Vec<(SecureString, Member)>,
    /// The union of the credential members' connection-security requirements, kept up to date
    /// as each is appended.
    secure: bool,
}

/// Equal when the members are equal: the kept requirement follows from them.
impl PartialEq for SealedJson {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl Eq for SealedJson {}

/// The member names only.
impl fmt::Debug for SealedJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.members.iter().map(|(n, _)| n.as_str()))
            .finish()
    }
}

/// A credential member that is not UTF-8 text: JSON has no spelling for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotJsonText {
    member: String,
}

impl NotJsonText {
    /// The member's name.
    #[must_use]
    pub fn member(&self) -> &str {
        &self.member
    }
}

impl fmt::Display for NotJsonText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential member `{}` is not UTF-8 text", self.member)
    }
}

impl std::error::Error for NotJsonText {}

impl SealedJson {
    /// An empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `name: value` (public), encoded as `serde_json` writes `value` (no JSON tree is kept).
    #[must_use]
    pub fn public(mut self, name: &str, value: impl serde::Serialize) -> Self {
        let encoded = erased::Json::to_json(&value);
        self.members
            .push((SecureString::from(name), Member::Public(encoded)));
        self
    }

    /// Append `name: <the credential, as a JSON string>`.
    #[must_use]
    pub fn sealed(mut self, name: &str, value: &Cred) -> Self {
        self.secure |= value.secure_required();
        self.members
            .push((SecureString::from(name), Member::Sealed(value.clone())));
        self
    }

    /// The member names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(n, _)| n.as_str())
    }

    /// The encoded object, ready to write.
    pub fn encoded(&self) -> Result<SealedWrite, NotJsonText> {
        let mut len = 0;
        self.write(&mut |b| len += b.len())?;
        let mut buf = crate::secure::SecureVec::from(Vec::with_capacity(len));
        // Sized by the counting pass, so the wiping buffer never grows (LINT-RULES LR-117).
        self.write(&mut |b| buf.extend_from_slice(b))?;
        debug_assert_eq!(buf.len(), buf.capacity());
        Ok(SealedWrite::from_bytes(buf, self.secure))
    }

    /// Hand the encoding to `put`, piece by piece. A credential's piece is encoded into a buffer
    fn write(&self, put: &mut dyn FnMut(&[u8])) -> Result<(), NotJsonText> {
        let json = |v: &dyn erased::Json| v.to_json();
        put(b"{");
        for (i, (name, member)) in self.members.iter().enumerate() {
            if i > 0 {
                put(b",");
            }
            put(&json(&name.as_str()));
            put(b":");
            match member {
                Member::Public(encoded) => put(encoded),
                Member::Sealed(c) => {
                    let text = core::str::from_utf8(c.wire()).map_err(|_| NotJsonText {
                        member: crate::abi::sdk::cold::cred::member_name(name),
                    })?;
                    put(&json(&text));
                }
            }
        }
        put(b"}");
        Ok(())
    }
}

/// One JSON-serializable value, encoded whole.
mod erased {
    use crate::secure::SecureVec;

    pub(super) trait Json {
        fn to_json(&self) -> SecureVec;
    }
    impl<T: serde::Serialize + ?Sized> Json for T {
        fn to_json(&self) -> SecureVec {
            // Growth moves into a new block and wipes the old (`serde_json::to_vec` would not).
            let mut out = SecureVec::from(Vec::with_capacity(128));
            if serde_json::to_writer(&mut out, self).is_err() {
                out.clear();
            }
            out
        }
    }
}

#[cfg(test)]
#[path = "../tests/cred_json_tests.rs"]
mod tests;
