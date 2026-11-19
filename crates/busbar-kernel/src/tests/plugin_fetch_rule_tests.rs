// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` RULES the boot download is held to (SEC-2, #297): the URL is https only on
//! every host, and a redirect answer is refused, never followed. The download itself
//! (`busbar-core-connector` `fetch::download`) is proved against a far end beside the connector.

use super::{plugin_fetch_admits, plugin_fetch_status_refusal};

/// A plaintext `plugins.fetch` URL is refused on a public, a private and a loopback host alike, in
/// the rule's own words; the same URLs over https are admitted.
#[test]
fn a_plaintext_plugins_fetch_url_is_refused_on_every_host_in_its_words() {
    for host in [
        "registry.example.com",
        "10.0.0.7",
        "127.0.0.1",
        "localhost",
    ] {
        let url = format!("http://{host}:8443/releases/busbar-oracle-fetch-1.0.0.tar.gz");
        assert_eq!(
            plugin_fetch_admits(&url, &[]),
            Err(format!(
                "plugins.fetch url must use https (got '{url}'): a plugin download is never \
                 admitted over plaintext, on any host"
            )),
            "{host}"
        );
        let secured = format!("https://{host}:8443/releases/busbar-oracle-fetch-1.0.0.tar.gz");
        assert_eq!(plugin_fetch_admits(&secured, &[]), Ok(()), "{host}");
    }
}

/// A 3xx answer to the download is refused in the redirect-SSRF words, whichever redirect it is; a
/// 2xx is no refusal and any other status is named as it stands.
#[test]
fn a_plugins_fetch_redirect_is_refused_in_the_redirect_ssrf_words() {
    let url = "https://registry.example.com/releases/a.tar.gz";
    for (code, shown) in [
        (301, "301 Moved Permanently"),
        (302, "302 Found"),
        (307, "307 Temporary Redirect"),
        (308, "308 Permanent Redirect"),
    ] {
        assert_eq!(
            plugin_fetch_status_refusal(url, code),
            Some(format!(
                "GET {url}: HTTP {shown} — refusing to follow a plugins.fetch redirect \
                 (redirect-SSRF guard)"
            ))
        );
    }
    assert_eq!(plugin_fetch_status_refusal(url, 200), None);
    assert_eq!(
        plugin_fetch_status_refusal(url, 404),
        Some(format!("GET {url}: HTTP 404 Not Found"))
    );
}
