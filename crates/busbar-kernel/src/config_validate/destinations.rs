// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure declaration-owned location and host-owned provider destination policy.

use busbar_contract::net::{host_is_private_or_loopback, target_host, url_authority};

use super::{MetadataPosture, ssrf_blocked_host};
use crate::config::RootCfg;

/// The selected transport's target interpretation, before DNS or connection establishment.
/// `secure` is intent, never evidence that a credential may already be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDestination {
    /// Explicit host and port returned by the selected transport.
    pub authority: String,
    /// Whether the transport asks the connector to establish connection security.
    pub secure: bool,
    /// The name the transport asks connection security to verify, if any.
    pub name: Option<String>,
}

impl ProviderDestination {
    /// Independently read an authority returned by an untrusted transport.
    pub fn host(&self) -> Result<String, String> {
        if self.authority.is_empty()
            || self
                .authority
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.authority.contains(['/', '\\', '@', '?', '#'])
        {
            return Err("transport locate returned an invalid authority".into());
        }
        let (host, port) = if let Some(bracketed) = self.authority.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or("transport locate returned an invalid IPv6 authority")?;
            host.parse::<std::net::Ipv6Addr>()
                .map_err(|_| "transport locate returned an invalid IPv6 address")?;
            (host, tail.strip_prefix(':'))
        } else {
            let (host, port) = self
                .authority
                .rsplit_once(':')
                .ok_or("transport locate authority must include a port")?;
            if host.contains(':') {
                return Err("transport locate IPv6 authority needs brackets".into());
            }
            (host, Some(port))
        };
        if host.is_empty()
            || port
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .is_none()
        {
            return Err("transport locate authority must name a host and valid port".into());
        }
        let host = target_host(&self.authority)
            .ok_or_else(|| "transport locate returned an invalid host".to_owned())?;
        let host = busbar_contract::net::judged_host(&host)
            .map_err(|_| "transport locate returned an invalid host".to_owned())?;
        Ok(busbar_contract::net::host_ip(&host).map_or(host, |ip| ip.to_string()))
    }
}

/// Validate every concrete provider target through its registered transport, then independently
/// judge the returned destination. This phase never resolves DNS, opens a stream, or reads secrets.
/// Deferred environment values retain the semantic pass's treatment.
pub fn validate_provider_destinations(
    cfg: &RootCfg,
    unset_env_vars: &[String],
    locate: &dyn Fn(&str) -> Result<ProviderDestination, String>,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let global = MetadataPosture::global(cfg);
    for (provider, settings) in &cfg.providers {
        let base = &settings.base_url;
        if !base.contains("://")
            && unset_env_vars
                .iter()
                .any(|v| !v.is_empty() && base.contains(v))
        {
            continue;
        }
        let posture = global.for_provider(settings);
        let targets = std::iter::once(("base_url", base.clone()))
            .chain(
                settings
                    .path
                    .as_ref()
                    .map(|p| ("base_url+path", format!("{base}{p}"))),
            )
            .chain(
                settings
                    .path_base
                    .as_ref()
                    .map(|p| ("base_url+path_base", format!("{base}{p}"))),
            );
        for (field, target) in targets {
            let claim = target.split_once("://").map_or("<missing>", |(s, _)| s);
            let prefix = format!("provider '{provider}' {field} claim '{claim}'");
            if url_authority(&target).userinfo.is_some() {
                errors.push(format!(
                    "{prefix}: userinfo is not permitted in an endpoint"
                ));
                continue;
            }
            let destination = match locate(&target) {
                Ok(destination) => destination,
                Err(reason) => {
                    errors.push(format!("{prefix}: {reason}"));
                    continue;
                }
            };
            let host = match destination.host() {
                Ok(host) => host,
                Err(reason) => {
                    errors.push(format!("{prefix}: {reason}"));
                    continue;
                }
            };
            if !destination.secure && !host_is_private_or_loopback(&host) {
                errors.push(format!("{prefix} must use a secure connection for a public host; plaintext is permitted only for a private/loopback local-model upstream"));
                continue;
            }
            // Shared authority normalization retains the existing metadata override ordering.
            if let Some(blocked) = ssrf_blocked_host(
                &destination.authority,
                &posture.allow_overrides,
                posture.allow_all,
                &posture.blocked_hosts,
            ) {
                errors.push(format!("{prefix} targets a blocked cloud-metadata host '{blocked}' (cloud-metadata/IMDS endpoints are denied; override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)"));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_authority_is_not_trusted_as_a_url() {
        for authority in [
            "host:443/path",
            "user@host:443",
            "[::1]junk",
            "host:65536",
            "host:0",
            "host",
            "::1:443",
        ] {
            assert!(
                ProviderDestination {
                    authority: authority.into(),
                    secure: true,
                    name: None
                }
                .host()
                .is_err(),
                "{authority}"
            );
        }
        for (authority, expected) in [
            ("[::1]:443", "::1"),
            ("0x7f000001:80", "127.0.0.1"),
            ("EXAMPLE.COM:443", "example.com"),
        ] {
            assert_eq!(
                ProviderDestination {
                    authority: authority.into(),
                    secure: false,
                    name: None
                }
                .host()
                .unwrap(),
                expected
            );
        }
    }
}
