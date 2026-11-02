// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HTTP HEADER VALUE HELPERS SHARED ACROSS AUTH MECHANISMS: pure, stateless, kind-neutral — neither

/// Whether `s` is a legal header value — byte for byte the rule `HeaderValue::from_str` applies
pub fn is_legal_header_value(s: &str) -> bool {
    s.bytes().all(|b| (b >= 0x20 && b != 0x7F) || b == b'\t')
}

/// Whether `name` is an RFC 9110 `token` (one or more `tchar`): the only shape a header field name
pub fn is_header_name_token(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// The `Authorization` value for a bearer credential: the one place the scheme word and the
pub fn token_value(key: &str) -> String {
    format!("Bearer {key}")
}

#[cfg(test)]
#[path = "tests/header_tests.rs"]
mod tests;
