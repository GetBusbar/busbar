// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! H9 (CREDENTIAL-LOCKDOWN): `--validate` hands the resolved provider credential to the auth
//! plugin serving its style (`check_outbound`) and prints the refusals it answers. A plugin that
//! echoes the credential, raw or encoded, must not put it on stdout or into a CI log: the printed
//! text carries a fixed marker where the credential was. Text that does not carry it is printed
//! byte for byte.

use super::*;
use base64::Engine as _;
use busbar_contract::auth_calls::AuthAxis;

/// An auth axis whose outbound check answers the refusals it was built with, `{cred}` in each
/// replaced by the credential it was handed (a third-party plugin that echoes it).
struct Echoing(Vec<&'static str>);

impl AuthAxis for Echoing {
    fn linked_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn answers(&self, _: &str) -> bool {
        false
    }
    fn linked(&self, _: &str) -> bool {
        false
    }
    fn operator(&self) -> Option<(String, String)> {
        None
    }
    fn open(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>, String> {
        Err("no inbound row".to_string())
    }
    fn check_outbound(
        &self,
        _: &str,
        credential: &[u8],
        _: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        let cred = String::from_utf8_lossy(credential);
        let b64 = base64::engine::general_purpose::STANDARD.encode(credential);
        let secret = cred.split_once(':').map_or("", |(_, s)| s).to_string();
        Ok(self
            .0
            .iter()
            .map(|t| {
                t.replace("{cred}", &cred)
                    .replace("{b64}", &b64)
                    .replace("{secret}", &secret)
            })
            .collect())
    }
}

const CRED: &str = "client-h9:s3cr3t-H9-value";

fn refusals(echo: Vec<&'static str>) -> Vec<String> {
    credential_refusals_from(
        &Echoing(echo),
        "oauth-client-credentials",
        CRED,
        &serde_json::json!({}),
    )
}

/// RED (base: the plugin's text was printed as it answered).
#[test]
fn a_plugin_that_echoes_the_credential_has_it_redacted_from_validate_output() {
    let got = refusals(vec![
        "credential '{cred}' is malformed",
        "would send Basic {b64}",
        "secret {secret} too short",
    ]);
    let b64 = base64::engine::general_purpose::STANDARD.encode(CRED);
    for line in &got {
        assert!(
            !line.contains("s3cr3t-H9-value"),
            "the credential leaks: {line}"
        );
        assert!(!line.contains(&b64), "its base64 leaks: {line}");
    }
    assert_eq!(
        got,
        vec![
            "credential '[redacted]' is malformed".to_string(),
            "would send Basic [redacted]".to_string(),
            "secret [redacted] too short".to_string(),
        ]
    );
}

/// GUARD (passes before and after): a refusal that does not carry the credential is printed
/// exactly as the plugin answered it, 1.5.5's own words included.
#[test]
fn a_refusal_without_the_credential_is_byte_identical() {
    let words = "oauth-client-credentials key must be `client_id:client_secret`";
    assert_eq!(refusals(vec![words]), vec![words.to_string()]);
}

/// A `jwt-bearer` credential is a service account; a plugin quoting its `private_key` back, as
/// parsed or as its JSON spells it, has the key redacted.
#[test]
fn a_service_accounts_private_key_echoed_back_is_redacted() {
    let key = "-----BEGIN PRIVATE KEY-----\nMIIEvQ-H9-key-body\n-----END PRIVATE KEY-----\n";
    let account = serde_json::json!({ "type": "service_account", "private_key": key }).to_string();
    let escaped = serde_json::to_string(key).unwrap();
    let escaped = escaped.trim_matches('"');
    let needles = credential_needles(&account);
    for echoed in [format!("bad key {key}"), format!("bad key {escaped}")] {
        let printed = redact_credential(echoed, &needles);
        assert!(!printed.contains("MIIEvQ-H9-key-body"), "{printed}");
        assert_eq!(printed, "bad key [redacted]");
    }
}
