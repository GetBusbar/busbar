// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONSENT SCREEN'S RETURN TARGET, adversarially. Each value below is one a browser reads as a
//! URL on ANOTHER host once it lands in a `Location` header, so each must be refused. The first
//! group were accepted before the fix (a prefix check that a browser's own URL cleaning walks past):
//! each one is its own RED.

use super::is_local_path;

/// What the authorization endpoint actually sends the screen: its own request target.
#[test]
fn the_authorization_request_target_is_a_local_path() {
    for ok in [
        "/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
         &state=s1&scope=read&code_challenge=x&code_challenge_method=S256",
        "/as/authorize?client_id=https%3A%2F%2Fclient.example%2Foauth-client&request_uri=urn%3Ax",
        "/",
        "/a/b%2F%2Fc",
    ] {
        assert!(is_local_path(ok), "`{ok}` is a local path and was refused");
    }
}

/// THE BYPASSES THE OLD CHECK LET THROUGH. A browser removes every ASCII tab and newline from a
/// URL before it reads it, so each of these is `//evil.example` (or `/\evil.example`, which it reads
/// the same way) to the browser that follows the redirect.
#[test]
fn a_control_character_that_a_browser_strips_is_refused() {
    for bypass in [
        "/\t/evil.example",
        "/\n/evil.example",
        "/\r/evil.example",
        "/\r\n/evil.example",
        "/\t\t/evil.example/authorize",
        "/\t\\evil.example",
        "/\u{0}/evil.example",
        "/\u{7f}/evil.example",
        "/\u{85}/evil.example",
        "/ /evil.example",
        "/\u{a0}/evil.example",
        "/\u{3000}/evil.example",
        "/authorize?x=\t",
    ] {
        assert!(
            !is_local_path(bypass),
            "{bypass:?} is an off-site redirect once a browser cleans it, and was accepted"
        );
    }
}

/// THE FORMS THE OLD CHECK ALREADY REFUSED, held: a scheme-relative URL, a backslash anywhere (a
/// browser reads `\` as `/` in a special URL), an absolute URL, and nothing at all.
#[test]
fn scheme_relative_backslash_and_absolute_forms_are_refused() {
    for bypass in [
        "//evil.example",
        "///evil.example",
        "/\\evil.example",
        "/\\/evil.example",
        "\\/evil.example",
        "/authorize\\..\\evil",
        "https://evil.example/authorize",
        "http:/evil.example",
        "javascript:alert(1)",
        "evil.example/authorize",
        " /authorize",
        "\t/authorize",
        "",
    ] {
        assert!(!is_local_path(bypass), "{bypass:?} was accepted");
    }
}
