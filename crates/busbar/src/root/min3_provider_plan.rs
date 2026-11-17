// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned candidate provider/auth preparation, before any auth instance is opened.

use std::collections::{BTreeMap, BTreeSet};

use busbar_kernel::auth_bindings::{
    self, CredentialFrom, OperatorAuth, ProviderBindings, ProviderView,
};
use busbar_kernel::config::RootCfg;
use busbar_kernel::plane_driver::port_egress::SeatPool;
use busbar_kernel::plane_driver::provider_catalog::{
    CatalogPlan, CatalogPool, ProviderAuthSelection, ProviderCatalogs, ProviderPlane,
};
use busbar_kernel::upstreams::ConfiguredUpstreams;
use busbar_plugin_abi::types::KindCode;
use serde_json::Value;

use super::boot::images::FileImages;
use super::min3_boot::Configured;
use super::min3_outbound_auth::AdmittedStyle;
use super::min3_provider_catalog::{self, Allocations, StagedCatalog};

pub(crate) struct Plan {
    pub(crate) bindings: ProviderBindings,
    pub(crate) styles: BTreeMap<Box<str>, AdmittedStyle>,
    /// Replace the configured Auth rows with this complete set before reserving instances.
    pub(crate) auth: Vec<Configured>,
    pub(crate) pools: BTreeMap<String, BTreeMap<String, CatalogPool>>,
}

impl Plan {
    pub(crate) fn stage(
        &self,
        cfg: &RootCfg,
        plan: &CatalogPlan,
        allocations: &Allocations,
        registered: &SeatPool,
        definitions: &ConfiguredUpstreams,
    ) -> Result<StagedCatalog, String> {
        min3_provider_catalog::prepare(
            cfg,
            plan,
            allocations,
            registered,
            definitions,
            &self.bindings,
            &self.styles,
        )
    }
}

/// Same admitted image identity and signed alias used by native plane instance construction.
pub(crate) fn descriptors(files: &FileImages) -> Result<Vec<ProviderPlane>, String> {
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for (identity, alias) in &files.aliases {
        let described = files
            .images
            .described(identity)
            .ok_or("candidate image description is missing")?;
        if described.kind != KindCode::Plane {
            continue;
        }
        let instance = if alias.is_empty() { identity } else { alias };
        if !names.insert(instance) {
            return Err("candidate plane aliases collide".into());
        }
        let Some(schema) = described
            .paths(busbar_plugin_abi::plane::tag::D_PROVIDER_SCHEMA)
            .next()
        else {
            continue;
        };
        out.push(ProviderPlane {
            instance: instance.clone(),
            image: identity.clone(),
            dialects: described
                .paths(busbar_plugin_abi::plane::tag::D_DIALECT)
                .map(str::to_owned)
                .collect(),
            schema: schema.to_owned(),
        });
    }
    Ok(out)
}

struct Operator {
    name: String,
    identity: String,
    config: Value,
}

pub(crate) fn capture(
    files: &FileImages,
    cfg: &RootCfg,
    catalogs: &ProviderCatalogs,
) -> Result<Plan, String> {
    let descriptors = descriptors(files)?;
    let mut selections = BTreeMap::new();
    for plan in catalogs.values() {
        if !descriptors
            .iter()
            .any(|one| one.instance == plan.instance && one.image == plan.image)
        {
            return Err("provider catalog does not belong to candidate image descriptions".into());
        }
        for target in plan.targets().values() {
            selection(&mut selections, &target.provider, &target.auth_selection)?;
        }
    }
    let kernel_seal = busbar_kernel::seal::acquire();
    let seal = busbar_contract::caps::Grant::<busbar_contract::caps::Sign>::mint(&kernel_seal);
    let mut operators = Vec::new();
    for (name, provider) in &cfg.identity_providers {
        if busbar_kernel::config::is_builtin_identity_module(&provider.module) {
            continue;
        }
        let identity = files
            .images
            .identity_of(&provider.module)
            .ok_or("configured auth image is not admitted")?;
        if files
            .images
            .described(&identity)
            .is_none_or(|one| one.kind != KindCode::Auth)
        {
            return Err("configured auth module is not an Auth image".into());
        }
        let encoded = provider
            .settings
            .encode()
            .map_err(|_| "auth settings cannot be encoded")?
            .into_exposed(&seal);
        let config =
            serde_json::from_slice(&encoded).map_err(|_| "auth settings are not valid JSON")?;
        operators.push(Operator {
            name: name.clone(),
            identity,
            config,
        });
    }
    operators.sort_by(|a, b| a.name.cmp(&b.name));
    let operator_views: Vec<_> = operators
        .iter()
        .map(|one| OperatorAuth {
            name: &one.name,
            module: &one.identity,
            style: one.config.get("style").and_then(Value::as_str),
            settings_keys: one
                .config
                .get("settings")
                .and_then(Value::as_object)
                .map(|settings| settings.keys().map(String::as_str).collect())
                .unwrap_or_default(),
        })
        .collect();
    let mut providers = Vec::new();
    for (name, auth) in &selections {
        let provider = cfg
            .providers
            .get(name)
            .ok_or("catalog provider is missing from candidate config")?;
        let protocol = provider
            .table
            .get("protocol")
            .and_then(Value::as_str)
            .ok_or("catalog provider protocol is missing")?;
        providers.push(ProviderView {
            name,
            protocol,
            base_url: Some(&provider.base_url),
            auth: auth.as_view(),
            has_api_key: !provider.api_key.is_none(),
            token_url: provider.token_url.as_deref(),
            scope: provider.scope.as_deref(),
            subject: provider.subject.as_deref(),
        });
    }
    let members: Vec<_> = catalogs
        .values()
        .flat_map(CatalogPlan::auth_members)
        .collect();
    let rows = files.images.dialect_auth();
    let styles = files.images.outbound_styles();
    let bindings = auth_bindings::bind_providers(&auth_bindings::ProviderPlan {
        members: &members,
        providers: &providers,
        rows: &rows,
        styles: &styles,
        operator: &operator_views,
    })
    .map_err(|errors| errors.join("; "))?;
    let mut admitted = BTreeMap::new();
    let mut auth = Vec::new();
    for mut one in operators {
        if let Some(fills) = bindings.fills.get(one.name.as_str()) {
            fill_config(&mut one.config, fills)?;
        }
        if let Some(style) = one.config.get("style").and_then(Value::as_str) {
            admitted.insert(
                one.name.as_str().into(),
                AdmittedStyle {
                    flags: files.images.style_flags(&one.identity, style),
                },
            );
        }
        auth.push(Configured {
            kind: KindCode::Auth,
            identity: one.identity,
            limits: busbar_kernel::appbuild::instance_limits(cfg, "identity-providers", &one.name),
            name: one.name,
            config: serde_json::to_vec(&one.config).map_err(|_| "auth config cannot be encoded")?,
        });
    }
    for implicit in &bindings.implicit {
        let credential = match &implicit.credential {
            CredentialFrom::ProviderApiKey(name) => {
                let provider = cfg
                    .providers
                    .get(name.as_ref())
                    .ok_or("implicit provider credential is absent")?;
                Some(
                    serde_json::to_string(&provider.api_key.authoring(&kernel_seal))
                        .map_err(|_| "provider reference cannot be encoded")?,
                )
            }
            CredentialFrom::None => None,
            CredentialFrom::UpstreamForm(_) => {
                return Err("provider plan contains a registration credential".into())
            }
        };
        admitted.insert(
            implicit.name.clone(),
            AdmittedStyle {
                flags: files.images.style_flags(&implicit.module, &implicit.style),
            },
        );
        auth.push(Configured {
            kind: KindCode::Auth,
            identity: implicit.module.to_string(),
            name: implicit.name.to_string(),
            config: implicit.config_json(credential.as_deref()).into_bytes(),
            limits: busbar_plugin_abi::host_side::caller::InstanceLimits::default(),
        });
    }
    Ok(Plan {
        bindings,
        styles: admitted,
        auth,
        pools: catalogs
            .iter()
            .map(|(name, plan)| (name.clone(), plan.pools().clone()))
            .collect(),
    })
}

fn selection(
    out: &mut BTreeMap<String, ProviderAuthSelection>,
    provider: &str,
    auth: &ProviderAuthSelection,
) -> Result<(), String> {
    if out.get(provider).is_some_and(|existing| existing != auth) {
        return Err("provider auth provenance differs between candidate catalogs".into());
    }
    out.insert(provider.to_owned(), auth.clone());
    Ok(())
}

fn fill_config(config: &mut Value, fills: &auth_bindings::Fills) -> Result<(), String> {
    let config = config
        .as_object_mut()
        .ok_or("outbound auth config must be an object")?;
    let settings = config
        .entry("settings")
        .or_insert_with(|| Value::Object(Default::default()));
    let settings = settings
        .as_object_mut()
        .ok_or("outbound auth settings must be an object")?;
    for (key, value) in fills {
        settings
            .entry(*key)
            .or_insert_with(|| Value::String(value.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_preserve_operator_values_and_credential_reference() {
        let mut config = serde_json::json!({"style":"bearer","credential":{"file":"key"},"settings":{"audience":"authored"}});
        fill_config(
            &mut config,
            &[
                ("audience", "generated".into()),
                ("scope", "scope-a".into()),
            ],
        )
        .unwrap();
        assert_eq!(config["settings"]["audience"], "authored");
        assert_eq!(config["settings"]["scope"], "scope-a");
        assert_eq!(config["credential"], serde_json::json!({"file":"key"}));
    }

    #[test]
    fn fills_refuse_non_object_settings_without_echoing_values() {
        let mut config = serde_json::json!({"settings":"private-value"});
        let error = fill_config(&mut config, &[("scope", "private-fill".into())]).unwrap_err();
        assert!(!error.contains("private"));
    }

    #[test]
    fn provider_provenance_is_not_reinterpreted_as_an_instance_name() {
        let mut selections = BTreeMap::new();
        selection(
            &mut selections,
            "p",
            &ProviderAuthSelection::Style("shared".into()),
        )
        .unwrap();
        assert!(selection(
            &mut selections,
            "p",
            &ProviderAuthSelection::Instance("shared".into())
        )
        .is_err());
    }
}
