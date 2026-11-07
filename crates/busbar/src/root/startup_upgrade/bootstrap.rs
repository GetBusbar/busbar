// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Non-serving Store projection; historical source lists remain intact for final validation.
use busbar_kernel::config::{DeployCfg, RootCfg};

pub fn bootstrap(deploy: &DeployCfg) -> Result<RootCfg, Vec<String>> {
    let mut projected = deploy.security.clone();
    if let Some(security) = projected.as_mut() {
        security.blocked_metadata_hosts = busbar_migrations::config::bootstrap_metadata_projection(
            &security.blocked_metadata_hosts,
        );
        security.allow_metadata_hosts = busbar_migrations::config::bootstrap_metadata_projection(
            &security.allow_metadata_hosts,
        );
    }
    busbar_kernel::config::bootstrap::resolve_store_bootstrap_with_security(deploy, &projected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_projection_retains_original_hostless_entries() {
        let deploy: DeployCfg = serde_yaml::from_str("store: {module: memory}\nsecurity: {blocked_metadata_hosts: ['not-an-ip.123', '169.254.169.254'], allow_metadata_hosts: ['not-an-ip.456']}\n").unwrap();
        assert!(busbar_kernel::config::bootstrap::resolve_store_bootstrap(&deploy).is_err());
        let projected = bootstrap(&deploy)
            .unwrap_or_else(|errors| panic!("bootstrap projection refused: {errors:?}"));
        assert_eq!(projected.blocked_metadata_hosts, ["169.254.169.254"]);
        assert!(projected.allow_metadata_hosts.is_empty());
        let security = deploy.security.unwrap();
        assert_eq!(
            security.blocked_metadata_hosts,
            ["not-an-ip.123", "169.254.169.254"]
        );
        assert_eq!(security.allow_metadata_hosts, ["not-an-ip.456"]);

        // Slash entries are intentionally outside the approved hostless projection.
        // Their existing explicit refusal must survive the temporary bootstrap view.
        let cidr: DeployCfg = serde_yaml::from_str(
            "store: {module: memory}\nsecurity: {blocked_metadata_hosts: ['169.254.0.0/16']}\n",
        )
        .unwrap();
        let errors = bootstrap(&cidr).unwrap_err();
        assert!(
            errors.iter().any(|error| error.contains("CIDR")),
            "{errors:?}"
        );
        assert_eq!(
            cidr.security.unwrap().blocked_metadata_hosts,
            ["169.254.0.0/16"]
        );
    }
}
