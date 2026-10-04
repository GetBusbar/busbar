// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `jwt-bearer` and `oauth-client-credentials` bind from their settings,
//! and every refusal is 1.5.5's own words in the `credential:` / `settings:` lines the kernel
//! composes (ARCHITECT ruling Q5).

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct Cache(Mutex<HashMap<[u8; 32], Arc<Minted>>>);

impl TokenCache for Cache {
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
        self.0
            .lock()
            .unwrap()
            .entry(key)
            .or_insert_with(|| Arc::new(Minted::new(minter, max)))
            .clone()
    }
}

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
        &Cache::default(),
    )
}

fn lines(r: Result<Arc<Minted>, Vec<Refusal>>) -> Vec<String> {
    match r {
        Ok(_) => panic!("the binding is refused"),
        Err(refusals) => refusals.iter().map(Refusal::line).collect(),
    }
}

/// `oauth-client-credentials`: 1.5.5's `config_validate` findings, in its order, each the words
/// BOOT-030 / BOOT-034 / BOOT-035 pin after the kernel's `provider '<p>' ` prefix.
#[test]
fn oauth_client_credentials_refuses_in_1_5_5_words_and_order() {
    assert_eq!(
        lines(open(OAUTH_CLIENT_CREDENTIALS, Some("unused"), r#"{"scope":"oracle"}"#)),
        [
            "settings: uses auth: oauth-client-credentials but has no `token_url` (the OAuth token \
             endpoint the client credentials are POSTed to)",
            "credential: oauth-client-credentials key must be `client_id:client_secret`",
        ]
    );
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            Some("unused"),
            r#"{"token_url":"https://127.0.0.1/token"}"#
        )),
        [
            "settings: uses auth: oauth-client-credentials but has no `scope`",
            "credential: oauth-client-credentials key must be `client_id:client_secret`",
        ]
    );
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            None,
            r#"{"token_url":"https://t","scope":"s"}"#
        )),
        ["settings: uses auth: oauth-client-credentials but declares `api_key: none`; that grant \
          mints its token FROM the credential (`client_id:client_secret`), so there is nothing to \
          declare keyless"]
    );
    let r = open(
        OAUTH_CLIENT_CREDENTIALS,
        Some("id:secret"),
        r#"{"token_url":"https://t","scope":"s"}"#,
    );
    assert!(r.is_ok());
}

/// `jwt-bearer`: BOOT-036's credential clause is the redacted 1.6.0 sentence (accepted difference
/// F-BOOT-036: the argument is never echoed), and a keyless declaration is refused.
#[test]
fn jwt_bearer_refuses_in_the_accepted_words() {
    let l = lines(open(JWT_BEARER, Some("unused"), "{}"));
    assert_eq!(l.len(), 1);
    assert!(
        l[0].starts_with(
            "credential: could not read service-account key file named by this lane's \
             credential: "
        ),
        "{l:?}"
    );
    assert!(!l[0].contains("'unused'"), "the argument is never echoed");
    assert_eq!(
        lines(open(JWT_BEARER, None, "{}")),
        [
            "settings: uses auth: jwt-bearer but declares `api_key: none`; that grant signs its \
          assertion WITH the credential (the service-account JSON or key file), so there is \
          nothing to declare keyless"
        ]
    );
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}")),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(OAUTH_CLIENT_CREDENTIALS, Some("k"), "[1]")),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("bearer", Some("k"), "{}")),
        ["settings: outbound auth style `bearer` is not served by this plugin"],
        "bearer is a different mechanism, busbar-auth-header"
    );
    assert_eq!(
        lines(open("sigv4", Some("k"), "{}")),
        ["settings: outbound auth style `sigv4` is not served by this plugin"],
        "sigv4 is a different mechanism, busbar-auth-sigv4"
    );
}

/// THE TOKEN CACHE OUTLIVES A HANDLE: a re-open of the same (style, credential, settings) shares
/// the cell a previous generation minted into; any change makes a new one.
#[test]
fn a_reopen_shares_the_token_cell_and_a_change_does_not() {
    let cache = Cache::default();
    let s = br#"{"token_url":"https://t","scope":"s"}"#;
    let cell = |cred: &str, settings: &[u8]| {
        open_binding(
            OAUTH_CLIENT_CREDENTIALS,
            Some(cred.as_bytes()),
            Some(settings),
            &cache,
        )
        .expect("the binding opens")
    };
    let a = cell("id:secret", s);
    assert!(Arc::ptr_eq(&a, &cell("id:secret", s)));
    assert!(!Arc::ptr_eq(&a, &cell("id:other", s)));
    assert!(!Arc::ptr_eq(
        &a,
        &cell("id:secret", br#"{"token_url":"https://t","scope":"t"}"#)
    ));
}
