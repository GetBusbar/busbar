// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HTTP HEADER VALUE HELPERS SHARED ACROSS AUTH MECHANISMS: pure, stateless, kind-neutral —
//! neither touches an ABI shape nor holds state — and needed by more than one auth-kind plugin
//! crate (`busbar-auth-header`'s static schemes, `busbar-auth-sigv4`'s signed value and session
//! token, `busbar-auth-oauth`'s minted bearer), so each duplicating it would be the same helper
//! copied three times. MOVED VERBATIM from the identity unit's `egress_auth/mod.rs` in the kernel,
//! then staged `busbar-auth-outbound::present` (KERNEL<>PLUGINS step 22); this is its one home now
//! (KERNEL<>PLUGINS AUTH-SPLIT).

/// Whether `s` is a legal header value — byte for byte the rule `HeaderValue::from_str` applies
/// (every byte `>= 0x20` except DEL `0x7F`, plus horizontal tab), which is the rule every egress
/// credential header builder has always been judged by. A config system that injects a stray
/// CR/LF/NUL must not produce a request-smuggling header; the mechanism omits the header entirely
/// instead (the upstream then answers 401, exactly like every other misconfigured-credential
/// path).
pub fn is_legal_header_value(s: &str) -> bool {
    s.bytes().all(|b| (b >= 0x20 && b != 0x7F) || b == b'\t')
}

/// Whether `name` is an RFC 9110 `token` (one or more `tchar`): the only shape a header field name
/// may take on the wire. A name that is not one (a `:` above all) is re-read as a DIFFERENT field
/// wherever a head is rendered and parsed again (`authorization:x` + `v` reads back as
/// `authorization` = `x: v`), which steps around any same-name replacement made on whole names.
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
/// credential are joined.
pub fn token_value(key: &str) -> String {
    format!("Bearer {key}")
}

#[cfg(test)]
#[path = "tests/header_tests.rs"]
mod tests;
