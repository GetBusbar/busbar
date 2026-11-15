// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! See [`super`].

/// [`super::super::cred::Cred::rsa_pkcs8_check`]'s refusal.
#[cold]
pub(in crate::abi::sdk) fn not_a_pkcs8_rsa_key() -> String {
    String::from("the key is not a supported PKCS #8 RSA key")
}

/// [`super::super::cred::Cred::redact_echo`]'s answer when the redaction split a character.
#[cold]
pub(in crate::abi::sdk) fn redaction_split_a_character() -> String {
    String::from("[redacted]")
}

/// [`resolved`](fn@super::super::cred::resolved)'s refusal of a secret over the size limit.
#[cold]
pub(in crate::abi::sdk) fn oversized_secret(len: usize) -> String {
    format!(
        "the secret is {len} bytes, over the {}-byte limit a secret may be",
        crate::abi::secret::MAX_SECRET_BYTES
    )
}

/// The member a [`super::super::cred::NotJsonText`] refusal names.
#[cold]
pub(in crate::abi::sdk) fn member_name(name: &str) -> String {
    String::from(name)
}

/// The exchange's refusal of a sealed field name that is a pseudo-field or carries a line break.
#[cold]
pub(in crate::abi::sdk) fn sealed_name_refused(name: &[u8]) -> String {
    format!(
        "the sealed request field `{}` is a pseudo-field or carries a line break",
        String::from_utf8_lossy(name)
    )
}

/// The exchange's refusal of a sealed value that carries a line break or NUL.
#[cold]
pub(in crate::abi::sdk) fn sealed_value_refused(name: &[u8]) -> String {
    format!(
        "the sealed request field `{}` carries a line break or NUL",
        String::from_utf8_lossy(name)
    )
}

/// The exchange's refusal of a request field named as a pseudo-field.
#[cold]
pub(in crate::abi::sdk) fn pseudo_field_refused(name: &[u8]) -> String {
    format!(
        "a request field `{}` is a pseudo-field; the framer names its own head",
        String::from_utf8_lossy(name)
    )
}

/// The exchange's refusal of a request field that carries a line break.
#[cold]
pub(in crate::abi::sdk) fn line_break_refused(name: &[u8]) -> String {
    format!(
        "the request field `{}` carries a line break",
        String::from_utf8_lossy(name)
    )
}

/// The exchange's refusal of a prepared request given the wrong number of sealed values.
#[cold]
pub(in crate::abi::sdk) fn sealed_count_refused(named: usize, given: usize) -> String {
    format!("the prepared request names {named} sealed fields and was given {given}")
}

/// A failed exchange's text, owned (`ConnFailure::Failed` owns its text).
#[cold]
pub(in crate::abi::sdk) fn failure_text(text: &str) -> String {
    String::from(text)
}
