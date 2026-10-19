// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET SUGAR, READ OFF THE LOADED STATEMENTS (owner law 2026-09-27: the kernel knows zero
//! plugin names; the sugar is a shorthand the plugins declare and the kernel resolves generically;
//! DoD item 2). The kernel reads every configured reference against what the installed secret
//! axis's Statements declare ([`super::sugars`]), so:
//!
//! * the operator's 1.5.5 spellings read exactly as they did, and every refusal keeps its words, its
//!   path and its line and column (the oracle's BOOT-P33..P39 cells pin them over a whole
//!   configuration; these cells pin the words);
//! * a sugar no loaded Statement declares is refused;
//! * a THIRD source, declaring its own sugar, reads and resolves through the same path the shipped
//!   two take.

use super::*;
use crate::test_support::secrets::{with_third_source, THIRD, THIRD_ENTRY};

/// `text` without the library's trailing ` at line L column C`, which it must carry.
fn located(text: &str) -> String {
    let at = text
        .rfind(" at line ")
        .unwrap_or_else(|| panic!("a refusal carries its position: {text}"));
    assert!(text[at..].contains(" column "), "{text}");
    text[..at].to_string()
}

/// A `tls:` block whose `cert:` is written `cert`, read as boot reads it.
fn tls(cert: &str) -> Result<crate::config::TlsCfg, String> {
    serde_yaml::from_str::<crate::config::TlsCfg>(&format!(
        "cert:\n  {cert}\nkey:\n  {{ module: some-source, settings: {{}} }}\n"
    ))
    .map_err(|e| located(&e.to_string()))
}

/// RED: a sugar no loaded Statement declares is REFUSED where it stands, in serde's own words and
/// with its path, listing the canonical keys and then the declared sugars (oracle BOOT-P39).
#[test]
fn a_sugar_no_loaded_statement_declares_is_refused() {
    assert_eq!(
        tls("bogus: X").unwrap_err(),
        "cert: unknown field `bogus`, expected one of `module`, `settings`, `env`, `file`"
    );
    assert_eq!(
        tls(&format!("{THIRD}: {}", THIRD_ENTRY.0)).unwrap_err(),
        format!(
            "cert: unknown field `{THIRD}`, expected one of `module`, `settings`, `env`, `file`"
        )
    );
}

/// The refusals that list the sugars list the declared ones, in 1.5.5's words (oracle
/// BOOT-P33..P38), and the operator's spellings read as they did.
#[test]
fn the_declared_sugars_read_and_refuse_in_1_5_5s_words() {
    for (cert, want) in [
        (
            "env: A\n  file: B",
            "cert: a secret reference takes exactly one of `env:` / `file:`",
        ),
        (
            "module: vault\n  env: A",
            "cert: a secret reference is either `{ module: …, settings: … }` or the `{ env: … }` \
             / `{ file: … }` sugar, not both",
        ),
        (
            "env: A\n  settings: {}",
            "cert: the `{ env: … }` / `{ file: … }` sugar takes no `settings:` (use the canonical \
             `{ module: …, settings: … }` form instead)",
        ),
        (
            "env: \"\"",
            "cert: a `{ env: … }` secret reference must name a non-empty value",
        ),
        (
            "{}",
            "cert: a secret reference needs `module:` (with optional `settings:`) or the \
             `{ env: <VAR> }` / `{ file: <path> }` sugar",
        ),
        (
            "s3cret-literal",
            "cert: a secret value must be a REFERENCE, never an inline literal (the value is not \
             echoed): use { env: <VAR> }, { file: <path> }, { module: <secret-module>, settings: \
             {…} }, or the bare scalar `none` to declare an upstream that takes NO credential",
        ),
    ] {
        assert_eq!(tls(cert).unwrap_err(), want, "{cert}");
    }
    // `{ env: X }` is `{ module: env, settings: { key: X } }`, as in 1.5.5.
    let read = tls("env: TLS_CERT_PEM").expect("the fill sugar reads");
    assert_eq!(
        read.cert,
        crate::test_support::secrets::fill_ref("TLS_CERT_PEM")
    );
    assert_eq!(
        read.cert.settings.get("key").and_then(|v| v.as_str()),
        Some("TLS_CERT_PEM")
    );
    let read = tls("file: /run/c.pem").expect("the path sugar reads");
    assert_eq!(
        read.cert,
        crate::test_support::secrets::path_ref("/run/c.pem")
    );
    assert_eq!(describe(&read.cert), "file:/run/c.pem");
}

/// RED: A THIRD SECRET SOURCE, declaring its own sugar in its Statement, reads and resolves through
/// the one path the shipped two take: the configuration's reading, the axis, the source. Its word
/// joins every refusal's list; outside it, the word is refused (above).
#[test]
fn a_third_source_declaring_its_own_sugar_resolves_through_the_same_path() {
    with_third_source(|| {
        let read = tls(&format!("{THIRD}: {}", THIRD_ENTRY.0)).expect("the third sugar reads");
        assert_eq!(
            serde_json::to_value(&read.cert).unwrap(),
            serde_json::json!({"module": THIRD, "settings": {"entry": THIRD_ENTRY.0}})
        );
        assert_eq!(describe(&read.cert), format!("{THIRD}:{}", THIRD_ENTRY.0));
        let resolver = SecretResolver::builtins_only();
        let revealed = crate::test_support::revealed;
        assert_eq!(
            resolver.resolve_string(&read.cert).map(revealed),
            Ok(THIRD_ENTRY.1.to_string())
        );
        // The same reference read without a table (a plugin's own settings, handed back) lands on
        // the declared key and resolves the same.
        let free = SecretRef::sugar(THIRD, THIRD_ENTRY.0);
        assert_eq!(
            resolver
                .resolve_string(&free)
                .map(crate::test_support::revealed),
            Ok(THIRD_ENTRY.1.to_string())
        );
        assert_eq!(
            tls("bogus: X").unwrap_err(),
            format!(
                "cert: unknown field `bogus`, expected one of `module`, `settings`, `env`, `file`, \
                 `{THIRD}`"
            )
        );
    });
}

/// A `${VAR}` names the FILL sugar's value and a key file the PATH sugar's: each found by the role
/// its Statement declares, never by a name.
#[test]
fn the_fill_and_the_path_are_the_roles_the_statements_declare() {
    assert_eq!(
        fill_reference("V"),
        Some(crate::test_support::secrets::fill_ref("V"))
    );
    assert_eq!(
        fill_reference("V").and_then(|r| r.settings.get("key").cloned()),
        Some(serde_json::Value::String("V".into()))
    );
    assert_eq!(
        path_reference("/k.json").and_then(|r| r.settings.get("path").cloned()),
        Some(serde_json::Value::String("/k.json".into()))
    );
    assert_eq!(example_reference("MY_SECRET_VAR"), "{ env: MY_SECRET_VAR }");
    assert_eq!(sugar_words(" | "), "`env` | `file`");
}
