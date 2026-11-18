// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! See [`super`].

use std::borrow::Cow;

/// `url::ambiguous_url`'s refusal, the URL's credential cut.
#[cold]
pub(in crate::abi::sdk) fn ambiguous_url(url: &str) -> String {
    let mut cut = String::new();
    crate::abi::sdk::url::cut_userinfo(url, "***@", &mut cut);
    format!(
        "settings: url `{}` is ambiguous: it has an `@` after its host, so what comes before that \
         `@` would be read as the host and path, not as a credential. Percent-encode a `/`, `?` or \
         `#` inside the credential (`%2F`, `%3F`, `%23`), or write an `@` meant for the path as \
         `%40`",
        cut
    )
}

/// A failure's words, owned.
#[cold]
pub(in crate::abi::sdk) fn display_text(error: &impl std::fmt::Display) -> String {
    error.to_string()
}

/// `export::one_instance_reason`'s refusal: `why`, the one reason.
#[cold]
pub(in crate::abi::sdk) fn one_reason(why: &str) -> Vec<String> {
    vec![why.to_string()]
}

/// `auth_kit::json_error`'s answer for a decode of `what` that failed with `e`:
/// serde's words for a missing or unknown field, else the class and position only.
#[cold]
pub(in crate::abi::sdk) fn json_error(what: &str, e: &serde_json::Error) -> String {
    let text = e.to_string();
    if e.is_data() && (text.starts_with("missing field `") || text.starts_with("unknown field `")) {
        return format!("{what}: {text}");
    }
    let class = match e.classify() {
        serde_json::error::Category::Io => "the input could not be read",
        serde_json::error::Category::Syntax => "it is not well-formed JSON",
        serde_json::error::Category::Data => "a field is missing or has the wrong type",
        serde_json::error::Category::Eof => "it ends before the JSON does",
    };
    let (line, column) = (e.line(), e.column());
    format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
}

/// The host's failure text, owned (lossily read as UTF-8).
#[cold]
pub(in crate::abi::sdk) fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A refused `open_outbound`'s answer text: its lines, one per line.
#[cold]
pub(in crate::abi::sdk) fn joined_lines(lines: &[Cow<'static, str>]) -> String {
    lines.join("\n")
}

/// A failed stream's reason, owned.
#[cold]
pub(in crate::abi::sdk) fn owned_text(why: &str) -> String {
    why.to_owned()
}

/// `Reach::Gone`'s text for `what`.
#[cold]
pub(in crate::abi::sdk) fn no_such(what: &str) -> String {
    format!("no such {what}")
}

/// `Reach::Busy`'s text for `what`.
#[cold]
pub(in crate::abi::sdk) fn busy(what: &str) -> String {
    format!("{what} busy: another op holds it")
}
