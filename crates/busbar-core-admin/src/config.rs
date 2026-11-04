// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Configuration for the built-in operator HTTP surface.

use busbar_contract::net::{extract_normalized_host, host_is_private_or_loopback, scheme_is};
use busbar_kernel::config_validate::ssrf_blocked_host;

/// Validate the public operator origin without DNS, I/O, or runtime state.
pub fn validate_public_url(url: &str, blocked: &[String]) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    collect_public_url_errors(url, blocked, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn collect_public_url_errors(url: &str, blocked: &[String], errors: &mut Vec<String>) {
    let is_https = scheme_is(url, "https");
    let is_http = scheme_is(url, "http");
    if !is_https && !is_http {
        errors.push(format!(
            "public_url must be an absolute http(s) URL (got '{url}')"
        ));
        return;
    }
    let Some(host) = extract_normalized_host(url) else {
        errors.push(format!("public_url '{url}' has no host"));
        return;
    };
    if is_http && !host_is_private_or_loopback(&host) {
        errors.push(format!(
            "public_url must use https for a public host (got '{url}'); plaintext http is permitted \
             only for a loopback/private base"
        ));
    }

    if let Some((_, rest)) = url.split_once("://") {
        let rest = rest.replace('\\', "/");
        if let Some(pos) = rest.find(['/', '?', '#']) {
            let delim = rest.as_bytes()[pos];
            let tail = &rest[pos + 1..];
            if delim != b'/' || !tail.is_empty() {
                errors.push(format!(
                    "public_url must be a bare origin (scheme://host[:port]) with no path, query, or \
                     fragment (got '{url}'); BYOK clients append their own suffix"
                ));
            }
        }
    }

    if let Some(bad) = ssrf_blocked_host(url, &[], false, blocked) {
        errors.push(format!(
            "public_url '{url}' targets a blocked cloud-metadata host '{bad}'"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_origin_retains_tls_origin_and_metadata_rules() {
        for url in [
            "https://api.example",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(validate_public_url(url, &[]).is_ok(), "{url}");
        }
        for url in [
            "http://api.example",
            "foreign://api.example",
            "https://api.example/path",
            "https://api.example?q=1",
            "https://169.254.169.254",
            "https://0xa9fea9fe",
        ] {
            assert!(validate_public_url(url, &[]).is_err(), "{url}");
        }
    }
}
