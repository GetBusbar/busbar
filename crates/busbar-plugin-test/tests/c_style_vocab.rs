// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STYLE-VOCAB (ABI-MIN3-INTERFACE §14): The outbound style vocabulary (§12.18). The auth arms run in their
//! repos.
//!
//! Core's arm pins the vocabulary those arms are written against: `CORE_DIALECT_STYLES` and
//! `CORE_UPSTREAM_STYLES` are the fixed tables from a D_DIALECT_AUTH row class and an `upstreams.<name>.auth`
//! form to a style word, every word is one of the five an auth plugin declares as a D_OUTBOUND_STYLE item, a
//! class has exactly one word, and the words are the documented ones (a rename here fails this case in core, and
//! the auth plugin's copy of it in its own CI).

use busbar_contract::config::dialect_styles::{
    dialect_style, upstream_style, RowClass, UpstreamForm, API_KEY, BEARER, CONNECTION,
    CORE_DIALECT_STYLES, CORE_UPSTREAM_STYLES, SIGV4, TOKEN_EXCHANGE,
};

#[test]
fn style_vocabulary_core_arm() {
    assert_eq!(
        [BEARER, API_KEY, SIGV4, TOKEN_EXCHANGE, CONNECTION],
        [
            "bearer",
            "api-key",
            "sigv4",
            "oauth-token-exchange",
            "oauth-connection"
        ]
    );
    assert_eq!(dialect_style(RowClass::HeaderBearer), "bearer");
    assert_eq!(dialect_style(RowClass::HeaderKey), "api-key");
    assert_eq!(dialect_style(RowClass::Sign), "sigv4");
    assert_eq!(upstream_style(UpstreamForm::Bearer), "bearer");
    assert_eq!(upstream_style(UpstreamForm::ApiKey), "api-key");
    assert_eq!(
        upstream_style(UpstreamForm::TokenExchange),
        "oauth-token-exchange"
    );
    assert_eq!(upstream_style(UpstreamForm::Connection), "oauth-connection");

    let known = [BEARER, API_KEY, SIGV4, TOKEN_EXCHANGE, CONNECTION];
    // One row per class: no class twice, no word empty or outside the vocabulary.
    for (n, (class, word)) in CORE_DIALECT_STYLES.iter().enumerate() {
        assert!(known.contains(word), "{class:?} -> {word}");
        assert!(
            CORE_DIALECT_STYLES
                .iter()
                .skip(n + 1)
                .all(|(c, _)| c != class),
            "{class:?} listed twice"
        );
    }
    for (n, (form, word)) in CORE_UPSTREAM_STYLES.iter().enumerate() {
        assert!(known.contains(word), "{form:?} -> {word}");
        assert!(
            CORE_UPSTREAM_STYLES
                .iter()
                .skip(n + 1)
                .all(|(f, _)| f != form),
            "{form:?} listed twice"
        );
    }
}
