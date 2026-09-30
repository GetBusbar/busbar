// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S REPLY AGAINST THE ENGINE'S. The plane judges a far-end error with its own copy of
//! the class rule (it cannot name the breaker unit's); for every raw error shape and error map the
//! engine's normalizer places an error in the class the plane's does.

use busbar_contract::upstream::RawUpstreamError;
use std::collections::HashMap;

#[test]
fn the_planes_class_rule_is_the_breakers() {
    let maps: Vec<HashMap<String, String>> = vec![
        HashMap::new(),
        [
            ("1302", "rate_limit"),
            ("quota", "billing"),
            ("ctx", "context_length"),
            ("typo", "rate_limt"),
            ("overloaded_error", "overloaded"),
            ("invalid_request_error", "context_length"),
            ("auth", "auth"),
            ("slow", "timeout"),
            ("net", "network"),
            ("bad", "client_error"),
            ("boom", "server_error"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    ];
    let codes = [
        None,
        Some("1302"),
        Some("quota"),
        Some("ctx"),
        Some("typo"),
        Some("context_length_exceeded"),
        Some("auth"),
        Some("unmapped"),
    ];
    let types = [
        None,
        Some("overloaded_error"),
        Some("invalid_request_error"),
        Some("slow"),
        Some("net"),
        Some("bad"),
        Some("boom"),
        Some("unmapped"),
    ];
    let statuses = [
        200, 302, 400, 401, 403, 404, 408, 413, 422, 429, 500, 502, 503, 504, 529,
    ];
    let mut checked = 0;
    for em in &maps {
        for code in codes {
            for ty in types {
                for status in statuses {
                    for retry in [None, Some(7)] {
                        let raw = RawUpstreamError {
                            http_status: status,
                            provider_code: code.map(str::to_string),
                            structured_type: ty.map(str::to_string),
                            retry_after_secs: retry,
                        };
                        assert_eq!(
                            busbar_plane_llm::exchange::reply::failure::normalize(&raw, em),
                            crate::engine::normalize_raw_error(&raw, em),
                            "{raw:?} under {em:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 2 * 8 * 8 * 15 * 2);
}
