// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TOKEN ENDPOINT'S USERINFO, FROM THE CONFIG TO THE AXIS (row 74, F25): the endpoint a plane
//! builds its binding from carries no `user:pass@`, and the Basic value that userinfo spelled
//! reaches the auth axis from the host, beside the settings and never inside them.

use super::*;

/// One outbound serving asked for: the style, its settings and the credential handed with it.
type Asked = (String, serde_json::Value, Option<Vec<u8>>);

/// An auth axis that records each outbound serving it is asked for, and serves none.
#[derive(Default)]
struct Recording {
    seen: std::sync::Mutex<Vec<Asked>>,
}

impl AuthAxis for Recording {
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

    fn serving_presenting(
        &self,
        style: &str,
        settings: &serde_json::Value,
        endpoint_basic: Option<&[u8]>,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        self.seen.lock().unwrap().push((
            style.to_string(),
            settings.clone(),
            endpoint_basic.map(<[u8]>::to_vec),
        ));
        Ok(None)
    }
}

#[test]
fn a_token_endpoints_userinfo_reaches_the_axis_beside_the_settings_never_inside_them() {
    use base64::Engine as _;
    let (plane_visible, endpoint) = crate::appbuild::lane_token_endpoint(Some(
        "https://svcuser:hunter2-P4ss@login.example.com/tenant/token",
    ));
    assert_eq!(
        plane_visible.as_deref(),
        Some("https://login.example.com/tenant/token"),
        "the endpoint a plane is handed carries no userinfo"
    );
    let endpoint = endpoint.expect("the userinfo is held, opaque");
    assert!(
        crate::appbuild::lane_token_endpoint(Some("https://login.example.com/tenant/token"))
            .1
            .is_none(),
        "an endpoint with no userinfo holds none"
    );
    let binding = StyleBinding {
        style: "s".to_string(),
        params: serde_json::json!({ "token_url": plane_visible }),
        uses_key: false,
        statics: &[],
        sent: Vec::new(),
    };
    let axis = Recording::default();
    assert!(bind_presenting(&axis, &binding, b"id:secret", Some(&endpoint)).is_err());
    let seen = axis.seen.lock().unwrap();
    let (style, settings, basic) = &seen[0];
    assert_eq!(style, "s");
    assert!(
        !settings.to_string().contains("hunter2") && !settings.to_string().contains("svcuser"),
        "the settings carry no userinfo: {settings}"
    );
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
    );
    assert_eq!(
        basic.as_deref(),
        Some(expected.as_bytes()),
        "the Basic value, from the host"
    );
    // A binding with no endpoint userinfo hands none.
    drop(seen);
    assert!(bind(&axis, &binding, b"id:secret").is_err());
    assert_eq!(axis.seen.lock().unwrap()[1].2, None);
}
