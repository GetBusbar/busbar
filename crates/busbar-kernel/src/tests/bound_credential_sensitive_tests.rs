// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::auth_calls::{AuthField, Fielding, OutboundServing};

const VALUE: &[u8] = b"Bearer sk-bound-s3cr3t";

struct Presenting {
    require_secure: bool,
}

impl OutboundAuth for Presenting {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(7)
    }
    fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: Secret::new(VALUE.to_vec()),
            sensitive: true,
            query: false,
            require_secure: self.require_secure,
        }]))
    }
    fn fields(&self, _: u64, _: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        unreachable!("the field answers on the spot")
    }
}

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
            auth: Arc::new(Presenting {
                require_secure: false,
            }),
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

    let (name, value) = &headers[1];
    assert_eq!(name.as_str(), "anthropic-version");
    assert!(!value.is_sensitive());

    let prebuilt = prebuild_auth(&bound(), "sk-bound-s3cr3t", "upstream.example.test")
        .expect("a lane-constant binding prebuilds");
    assert!(prebuilt["authorization"].is_sensitive());
}

#[test]
fn a_legacy_header_only_consumer_never_erases_required_connection_security() {
    let bound = BoundCredential {
        auth: Arc::new(Presenting {
            require_secure: true,
        }),
        handle: 7,
        points: AuthPoints::default(),
        uses_key: true,
        statics: &[],
        headers: Vec::new(),
    };
    let ctx = SigningContext {
        host: "upstream.example.test",
        canonical_uri: "",
        body: &[],
        timestamp_epoch: 0,
        upstream_creds: UpstreamCreds::Own,
    };
    assert!(bound.headers_for("key", &ctx).is_empty());
}
