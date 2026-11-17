// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `identity-providers.<name>.provisioning` semantics (IF §12.29 "Config"). W1-K7 parses the block into
//! [`ProvisioningCfg`] and calls [`check_provisioning`] at load; every refusal is a CONFIG text naming the instance
//! and the key.

use crate::config::min3::ProvisioningCfg;

use super::store::MAX_INDEX_NAME;

/// What config load knows about the instance the block sits on.
#[derive(Clone, Copy, Debug)]
pub struct ProvisioningFacts {
    /// The image declared FB_PROVISION.
    pub fb_provision: bool,
    /// The image serves `verify` or `verify_io`.
    pub verifies: bool,
}

const MAX_CLIENTS: usize = 64;
const MAX_PRINCIPAL: usize = 256;
const MAX_LINK_AUTH: usize = 16;
const REFRESH_MS: core::ops::RangeInclusive<u32> = 250..=10_000;
const GUARD_MAX: core::ops::RangeInclusive<u32> = 1..=100_000;
const WINDOW_S: core::ops::RangeInclusive<u64> = 60..=604_800;

/// Every refusal of `identity-providers.<name>.provisioning`. `inbound(n)` = `n` is a configured inbound auth instance.
pub fn check_provisioning(
    name: &str,
    cfg: &ProvisioningCfg,
    facts: ProvisioningFacts,
    inbound: &dyn Fn(&str) -> bool,
) -> Result<(), Vec<String>> {
    let key = |k: &str| format!("identity-providers.{name}.provisioning{k}");
    let mut refused = Vec::new();
    if !facts.fb_provision {
        refused.push(format!(
            "{}: the image of auth instance '{name}' does not declare FB_PROVISION",
            key("")
        ));
    }
    if !facts.verifies {
        refused.push(format!(
            "{}: the image of auth instance '{name}' serves neither verify nor verify_io",
            key("")
        ));
    }
    if let Some(link) = &cfg.link {
        for (i, auth) in link.auth.iter().enumerate() {
            if !inbound(auth) {
                refused.push(format!(
                    "{}: '{auth}' is not a configured inbound auth instance",
                    key(&format!(".link.auth[{i}]"))
                ));
            }
        }
    }
    if let Err(mut reasons) = check_provisioning_shape(name, cfg) {
        refused.append(&mut reasons);
    }
    if refused.is_empty() {
        Ok(())
    } else {
        Err(refused)
    }
}

/// Structural policy checks available before image admission and the typed boot walk.
pub fn check_provisioning_shape(name: &str, cfg: &ProvisioningCfg) -> Result<(), Vec<String>> {
    let key = |k: &str| format!("identity-providers.{name}.provisioning{k}");
    let mut refused = Vec::new();
    if cfg.clients.is_empty() || cfg.clients.len() > MAX_CLIENTS {
        refused.push(format!(
            "{}: 1 to {MAX_CLIENTS} principals required",
            key(".clients")
        ));
    }
    for (i, client) in cfg.clients.iter().enumerate() {
        if client.is_empty() || client.len() > MAX_PRINCIPAL {
            refused.push(format!(
                "{}: each principal is 1 to {MAX_PRINCIPAL} bytes",
                key(&format!(".clients[{i}]"))
            ));
        }
    }
    if let Some(link) = &cfg.link {
        if link.index.is_empty() || link.index.len() > MAX_INDEX_NAME {
            refused.push(format!(
                "{}: an index name of 1 to {MAX_INDEX_NAME} bytes",
                key(".link.index")
            ));
        }
        if link.auth.is_empty() || link.auth.len() > MAX_LINK_AUTH {
            refused.push(format!(
                "{}: 1 to {MAX_LINK_AUTH} inbound auth instances required",
                key(".link.auth")
            ));
        }
        if !REFRESH_MS.contains(&link.refresh_ms) {
            refused.push(format!(
                "{}: {} to {} ms",
                key(".link.refresh_ms"),
                REFRESH_MS.start(),
                REFRESH_MS.end()
            ));
        }
    }
    if !GUARD_MAX.contains(&cfg.guard.max) {
        refused.push(format!(
            "{}: {} to {} (the guard has no off switch)",
            key(".guard.max"),
            GUARD_MAX.start(),
            GUARD_MAX.end()
        ));
    }
    if !WINDOW_S.contains(&cfg.guard.window_s) {
        refused.push(format!(
            "{}: {} to {} s",
            key(".guard.window_s"),
            WINDOW_S.start(),
            WINDOW_S.end()
        ));
    }
    if refused.is_empty() {
        Ok(())
    } else {
        Err(refused)
    }
}
