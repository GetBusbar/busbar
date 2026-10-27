// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON WHOSE STRING MEMBERS MAY BE CREDENTIALS (the chip design, its sections on secrets at rest and on
//! the fresh-verification changes: "the show-once mint is JSON-safe"): a plugin that is handed a credential in a JSON reply (a minted token) and hands
//! it on in a JSON answer never holds it as text.
//!
//! * [`json_reply`] reads a reply body into the plugin's own type: every [`Cred`] member is
//!   captured as the parser meets it, the public members are read as usual, and the error names
//!   the class of the failure and where it is, never a value ([`JsonReplyError`]).
//! * [`SealedJson`] is a JSON object whose members are public values or [`Cred`]s, encoded by the
//!   SDK into a [`SealedWrite`] exactly as `serde_json::to_vec` writes the same object.
//! * [`SealedWrite::stream_into`] moves a sealed answer into the host buffer the call fills (a
//!   plane's `reply_buf`).
//!
//! THE IN-PROCESS RESIDUAL. The bytes a [`SealedJson`] encodes are the answer: the host's buffer
//! receives them in clear, as the destination must. The SDK copies them there from its own
//! zeroizing buffer and the plugin never reads them. A capture parses in this process too:
//! `serde_json` unescapes an escaped string through a scratch buffer of its own that is freed, not
//! wiped; an unescaped string (every token the providers mint) is copied straight from the body
//! into the credential.

use core::fmt;

use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::{Cred, SealedWrite};

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
/// the body straight into the credential's zeroizing buffer); the error names a class and a
/// position, never a value.
///
/// # Errors
/// The body is not JSON, or does not match `T`.
pub fn json_reply<T: DeserializeOwned>(body: &[u8]) -> Result<T, JsonReplyError> {
    use serde_json::error::Category;
    serde_json::from_slice(body).map_err(|e| JsonReplyError {
        failure: match e.classify() {
            Category::Io => JsonFailure::Io,
            Category::Syntax => JsonFailure::Syntax,
            Category::Data => JsonFailure::Data,
            Category::Eof => JsonFailure::Eof,
        },
        line: e.line(),
        column: e.column(),
    })
}

impl Cred {
    /// Whether it begins with `prefix`: a public format marker (a provider's `ek_` on the tokens it
    /// mints), checked on a captured token with no getter. Answers only that.
    #[must_use]
    pub fn starts_with(&self, prefix: &[u8]) -> bool {
        self.wire().starts_with(prefix)
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Member {
    Public(serde_json::Value),
    Sealed(Cred),
}

/// A JSON object whose members are public values or credentials, in the order named. The SDK
/// encodes it ([`SealedJson::encoded`]) as `serde_json::to_vec` writes the same members in the same
/// order: compact, every string escaped as `serde_json` escapes it. (`serde_json::json!` without
/// `preserve_order` writes an object's members sorted by name: name them sorted to match it.)
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SealedJson {
    members: Vec<(String, Member)>,
}

/// The member names only.
impl fmt::Debug for SealedJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.members.iter().map(|(n, _)| n))
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

    /// Append `name: value` (public).
    #[must_use]
    pub fn public(mut self, name: &str, value: impl Into<serde_json::Value>) -> Self {
        self.members
            .push((name.to_owned(), Member::Public(value.into())));
        self
    }

    /// Append `name: <the credential, as a JSON string>`.
    #[must_use]
    pub fn sealed(mut self, name: &str, value: &Cred) -> Self {
        self.members
            .push((name.to_owned(), Member::Sealed(value.clone())));
        self
    }

    /// The member names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|(n, _)| n.as_str())
    }

    /// The encoded object, ready to write.
    ///
    /// # Errors
    /// A credential member is not UTF-8 text.
    pub fn encoded(&self) -> Result<SealedWrite, NotJsonText> {
        // Measured first, then written into a buffer of exactly that size: a growing buffer would
        // leave the credential behind in every allocation it outgrew.
        let mut len = 0;
        self.write(&mut |b| len += b.len())?;
        let mut buf = Zeroizing::new(Vec::with_capacity(len));
        self.write(&mut |b| buf.extend_from_slice(b))?;
        debug_assert_eq!(buf.len(), buf.capacity());
        let secure = self.members.iter().any(|(_, m)| match m {
            Member::Sealed(c) => c.secure_required(),
            Member::Public(_) => false,
        });
        Ok(SealedWrite::from_bytes(buf, secure))
    }

    /// Hand the encoding to `put`, piece by piece. A credential's piece is encoded into a buffer
    /// wiped on drop.
    fn write(&self, put: &mut dyn FnMut(&[u8])) -> Result<(), NotJsonText> {
        // A `Value` or a `str` always serializes: the one refusal is a credential that is not text.
        let json = |v: &dyn erased::Json| Zeroizing::new(v.to_json());
        put(b"{");
        for (i, (name, member)) in self.members.iter().enumerate() {
            if i > 0 {
                put(b",");
            }
            put(&json(&name.as_str()));
            put(b":");
            match member {
                Member::Public(v) => put(&json(v)),
                Member::Sealed(c) => {
                    let text = core::str::from_utf8(c.wire()).map_err(|_| NotJsonText {
                        member: name.clone(),
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
    pub(super) trait Json {
        fn to_json(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize + ?Sized> Json for T {
        fn to_json(&self) -> Vec<u8> {
            serde_json::to_vec(self).unwrap_or_default()
        }
    }
}

#[cfg(test)]
#[path = "../tests/cred_json_tests.rs"]
mod tests;
