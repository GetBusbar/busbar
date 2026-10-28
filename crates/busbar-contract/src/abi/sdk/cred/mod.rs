// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN'S CREDENTIALS (the chip design, its section on plugin credentials). A plugin never holds a credential as text:
//!
//! * [`Cred`] is a credential the plugin was configured with. It has no getter, no `Debug`, no
//!   `Display` and no `Serialize`; the plugin asks it to perform an auth step (the chip's recipes,
//!   `abi::sdk::chip`) and gets a [`Seal`] back.
//! * [`Seal`] is a recipe's output (a whole auth message, a header value, a signature). It has no
//!   getter either; it reaches the wire only through [`SealedWrite`].
//! * [`CredUrl`] is a URL or DSN setting split at parse: the plugin reads the public text, and the
//!   password inside it is a [`Cred`].
//! * [`settings`] parses a plugin's settings so every `Cred`/`CredUrl` field is sealed as it is read,
//!   the parse tree is wiped, and no error text quotes a settings value.
//! * [`record`] is a `Cred`'s one serde path: a field a plane keeps in a host record it writes
//!   ([`record::to_vec`]) and reads back. Serialized anywhere else it refuses.
//! * [`Held`] is the zeroizing holder for material that is not a configured credential (SRTP keys,
//!   a presented assertion): no getter outside this crate either.
//!
//! None of these types implements `Debug`, so a struct that holds one cannot derive it: printing a
//! credential does not compile.
//!
//! ```compile_fail
//! let c: busbar_contract::abi::sdk::cred::Cred = busbar_contract::abi::sdk::cred::settings(br#""pw""#).unwrap();
//! println!("{c:?}");
//! ```
//!
//! ```compile_fail
//! let c: busbar_contract::abi::sdk::cred::Cred = busbar_contract::abi::sdk::cred::settings(br#""pw""#).unwrap();
//! println!("{c}");
//! ```
//!
//! ```compile_fail
//! let c: busbar_contract::abi::sdk::cred::Cred = busbar_contract::abi::sdk::cred::settings(br#""pw""#).unwrap();
//! let _ = serde_json::to_string(&c);
//! ```
//!
//! ```compile_fail
//! let c: busbar_contract::abi::sdk::cred::Cred = busbar_contract::abi::sdk::cred::settings(br#""pw""#).unwrap();
//! let _ = c.wire();
//! ```
//!
//! ```compile_fail
//! let c: busbar_contract::abi::sdk::cred::Cred = busbar_contract::abi::sdk::cred::settings(br#""pw""#).unwrap();
//! let s = c.basic("u");
//! let _: &[u8] = s.as_ref();
//! ```

mod floor;
mod form;
mod form_body;
pub mod record;
mod settings;
pub(crate) mod write;

use zeroize::{Zeroize, Zeroizing};

pub use floor::{AuthFloor, PgAuth, RequireAuth};
pub use form::{CredUrl, PasswordAt, UserinfoUrl};
pub use form_body::{FormBody, FormValue};
pub use settings::{settings, SettingsError};
pub(crate) use write::confirm_secure;
pub use write::{Parts, SealedWrite};

/// Zeroizing material with no way out of this crate: no getter, no `Debug`, no `Display`, no
/// `Serialize`. Equality is constant-time.
#[allow(missing_debug_implementations)]
pub struct Held<T: Zeroize>(T);

impl<T: Zeroize> Held<T> {
    /// Hold `value`; it is wiped when the `Held` drops.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn wire(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + AsRef<[u8]>> Held<T> {
    /// The length in bytes (a length is public).
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// Whether it holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

impl<T: Zeroize> Drop for Held<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + AsRef<[u8]>> PartialEq for Held<T> {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Held<T> {}

type Bytes = Zeroizing<Vec<u8>>;

/// A credential this plugin was configured with. It performs auth steps (`abi::sdk::chip`); its
/// bytes never leave it. See the module docs.
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct Cred {
    held: std::sync::Arc<Held<Bytes>>,
    secure: bool,
    floor: AuthFloor,
}

/// The URL schemes whose connection is secured from the first byte: a credential the operator
/// wrote with one of them never goes out on a connection that is not.
const SECURE_SCHEMES: &[&str] = &["https", "wss", "rediss", "ldaps", "grpcs", "mqtts", "amqps"];

/// Whether a framed request's `target` is secured by its scheme ([`SECURE_SCHEMES`]); a target
/// with no scheme is the need's own and answers `true`.
pub(crate) fn secure_target(target: &str) -> bool {
    !target.contains("://") || secure_scheme(target)
}

/// Whether `url`'s scheme is one of [`SECURE_SCHEMES`] (case-insensitive).
pub(crate) fn secure_scheme(url: &str) -> bool {
    url.split_once("://").is_some_and(|(scheme, _)| {
        SECURE_SCHEMES
            .iter()
            .any(|s| s.eq_ignore_ascii_case(scheme))
    })
}

impl Cred {
    /// A credential this plugin captured itself (a token from a reply it decoded), taken by value so
    /// no copy stays behind.
    pub fn captured(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            held: std::sync::Arc::new(Held::new(bytes)),
            secure: false,
            floor: AuthFloor::STRICT,
        }
    }

    /// SECURE_REQUIRED (CHIP-DESIGN v4.1 change 4): this credential goes out only on a connection
    /// the host connector reports secured. Set from the operator's URL, never relaxed: a
    /// [`CredUrl`] or [`UserinfoUrl`] whose scheme or parameters ask for a secure connection sets
    /// it itself; a credential configured beside its URL takes it with [`Cred::secure_for`].
    #[must_use]
    pub fn secure_required(&self) -> bool {
        self.secure
    }

    /// This credential, required to go out secured when the operator's `url` names a secure
    /// scheme (`https`, `wss`, `rediss`, `ldaps`, …). A requirement already set stays.
    #[must_use]
    pub fn secure_for(mut self, url: &str) -> Self {
        self.secure |= secure_scheme(url);
        self
    }

    /// THE AUTH FLOOR (rulings S4, S5): the auth methods weaker than a protocol's best that the
    /// operator's connection string allows this credential, which the chip's recipes check. Set
    /// only when a [`CredUrl`] is split from the operator's text; nothing relaxes it.
    #[must_use]
    pub fn floor(&self) -> AuthFloor {
        self.floor
    }

    pub(crate) fn with_floor(mut self, floor: AuthFloor) -> Self {
        self.floor = floor;
        self
    }

    /// This credential, required to go out secured.
    #[must_use]
    pub fn require_secure(mut self) -> Self {
        self.secure = true;
        self
    }

    /// A seal of `bytes` this credential made: it carries the credential's requirement.
    pub(crate) fn seal(&self, bytes: Bytes) -> Seal {
        Seal {
            held: Held::new(bytes),
            secure: self.secure,
        }
    }

    /// Take a credential setting out of a parsed settings document, wiping the string where it
    /// was. `None`: `v` is not a string (left as it was).
    pub fn take(v: &mut serde_json::Value) -> Option<Self> {
        let serde_json::Value::String(s) = v else {
            return None;
        };
        let bytes = Zeroizing::new(core::mem::take(s).into_bytes());
        *v = serde_json::Value::Null;
        Some(Self::from_bytes(bytes))
    }

    /// No credential (an empty password): every recipe answers as the protocol does for one.
    pub fn empty() -> Self {
        Self::from_bytes(Zeroizing::new(Vec::new()))
    }

    pub(crate) fn from_bytes(bytes: Bytes) -> Self {
        Self::captured(bytes)
    }

    pub(crate) fn wire(&self) -> &[u8] {
        self.held.wire()
    }

    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether the credential is empty (an empty password).
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Whether it is UTF-8 text (a client that sends only text leaves out one that is not).
    pub fn is_text(&self) -> bool {
        std::str::from_utf8(self.wire()).is_ok()
    }

    /// Whether it may stand as a header field value: tab, space, visible ASCII and non-ASCII bytes,
    /// no other control byte and no DEL (RFC 9110).
    pub fn is_field_value(&self) -> bool {
        self.wire()
            .iter()
            .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
    }
}

/// Equality is constant-time over the bytes and answers only whether they match: a reload compares
/// its settings with it.
impl PartialEq for Cred {
    fn eq(&self, other: &Self) -> bool {
        *self.held == *other.held
    }
}

impl Eq for Cred {}

/// A recipe's output: bytes that go to the wire through [`SealedWrite`] and nowhere else.
#[allow(missing_debug_implementations)]
pub struct Seal {
    held: Held<Bytes>,
    secure: bool,
}

impl Seal {
    pub(crate) fn wire(&self) -> &[u8] {
        self.held.wire()
    }

    /// The length in bytes (public: a framer needs it for a length prefix).
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether the seal is empty.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Whether the credential it was made from goes out only secured ([`Cred::secure_required`]).
    pub fn secure_required(&self) -> bool {
        self.secure
    }

    /// This seal, required to go out secured (a recipe whose output the operator did not allow in
    /// the open).
    pub(crate) fn require_secure(mut self) -> Self {
        self.secure = true;
        self
    }
}

/// The refusal a credential that must go out secured meets on a connection that is not.
pub const NOT_SECURE: &str = "a credential the operator's URL requires a secure connection \
     for was not sent: the host connector reports this connection is not secured";

mod json;
#[cfg(test)]
#[path = "../tests/cred_tests.rs"]
mod tests;
pub use json::{json_reply, JsonFailure, JsonReplyError, NotJsonText, SealedJson};
