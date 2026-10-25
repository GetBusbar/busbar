// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A BOUND CREDENTIAL'S HEADERS ARE SENSITIVE (CREDENTIAL-LOCKDOWN A.3): every header built from a
//! field the auth plugin answered is marked `set_sensitive(true)`, so `http`'s `Debug` prints
//! `Sensitive` in place of the value and an h2 encoder never adds it to its HPACK table. The
//! dialect's own static fields are not credentials and stay as they were.

use super::*;
use busbar_contract::auth_calls::{AuthField, Fielding, OutboundServing};

const VALUE: &[u8] = b"Bearer sk-bound-s3cr3t";

/// One outbound instance whose `fields` answers a single credential field, on the spot.
struct Presenting;

impl OutboundAuth for Presenting {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(7)
    }
    fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: Secret::new(VALUE.to_vec()),
            sensitive: true,
        }]))
    }
    fn fields(&self, _: u64, _: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        unreachable!("the field answers on the spot")
    }
}

/// An auth axis that serves every style with [`Presenting`].
struct Serving;

impl AuthAxis for Serving {
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
    ) -> Result<Arc<dyn busbar_contract::auth_calls::AuthCalls>, String> {
        Err("no inbound row".to_string())
    }
    fn serving(&self, _: &str, _: &serde_json::Value) -> Result<Option<OutboundServing>, String> {
        Ok(Some(OutboundServing {
            auth: Arc::new(Presenting),
            flags: 0,
            points: AuthPoints::default().0,
        }))
    }
}

fn bound() -> Arc<dyn CredentialProvider> {
    let binding = StyleBinding {
        style: "bearer".to_string(),
        params: serde_json::json!({}),
        uses_key: true,
        statics: &[("anthropic-version", "2023-06-01")],
        sent: Vec::new(),
    };
    bind(&Serving, &binding, b"sk-bound-s3cr3t").expect("it binds")
}

/// RED (base: `HeaderValue::from_bytes` alone, never marked sensitive).
#[test]
fn a_header_built_from_an_auth_plugin_field_is_sensitive() {
    let ctx = SigningContext {
        host: "upstream.example.test",
        canonical_uri: "",
        body: &[],
        timestamp_epoch: 0,
        upstream_creds: UpstreamCreds::Own,
    };
    let headers = bound().headers_for("sk-bound-s3cr3t", &ctx);
    let (name, value) = &headers[0];
    assert_eq!(name.as_str(), "authorization");
    assert_eq!(value.as_bytes(), VALUE, "the bytes sent are unchanged");
    assert!(value.is_sensitive(), "the credential header is sensitive");
    assert!(
        !format!("{headers:?}").contains("s3cr3t"),
        "a Debug print of the headers leaks the credential: {headers:?}"
    );
    // The dialect's static field is not a credential.
    let (name, value) = &headers[1];
    assert_eq!(name.as_str(), "anthropic-version");
    assert!(!value.is_sensitive());

    // The boot prebuild is the same call: its map carries the mark too.
    let prebuilt = prebuild_auth(&bound(), "sk-bound-s3cr3t", "upstream.example.test")
        .expect("a lane-constant binding prebuilds");
    assert!(prebuilt["authorization"].is_sensitive());
}
