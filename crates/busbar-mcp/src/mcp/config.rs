// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` SECTION, as the host reads it. The grammar itself (the entry and section types,
//! [`validate_server`], the kernel-owned [`TRUST_KEYS`], the published-name rule) is the plane's,
//! defined in the plane crate (`busbar_plane_mcp::config`) and re-exported here so every caller path
//! resolves the same items. What stays here is what names the host: the section as the kernel's
//! config trait object ([`ToolsSectionCfg`]), a `pin:` as the kernel's trust declaration
//! ([`pin_declaration`]), the hook attach list over the kernel's one combine
//! ([`effective_hooks`]), and the verification cadence as the kernel's policy
//! ([`verify_policy_for`]).

pub use crate::plane_config::*;

/// This `pin:` object as the plane-neutral reader takes it. A projection, not a decision: every
/// question asked of it is [`busbar_kernel::trust::declared`]'s, and this plane's answers are its
/// [`busbar_kernel::trust::declared::Declares`] impl in [`super::client::catalogue`].
///
/// `fingerprint` is `None` and there is no field for it. An MCP server offers ONE opaque
/// transport-layer value and no manifest fingerprint an operator could have approved out of
/// band, so this grammar has nothing to put there — which is the arity difference that made the
/// artifact a type parameter in the first place.
pub(crate) fn pin_declaration(
    pin: &ServerPinCfg,
) -> busbar_kernel::trust::declared::Declaration<'_, McpPinMechanism> {
    busbar_kernel::trust::declared::Declaration {
        mechanism: pin.mechanism,
        key: pin.key.as_deref(),
        fingerprint: None,
    }
}

/// The effective hook set for one server: `tools.hooks ∪ tools.<server>.hooks`, deduped, in
/// declaration order (`hooks` is a LIST, and a LIST combines ADDITIVELY). The rule itself lives on
/// the neutral seam (`plane::config::attach_list`), where the sibling plane reads it too: the combine
/// is a property of the config GRAMMAR, and a second copy here is how the two planes come to
/// dedupe differently.
#[cfg_attr(any(not(test), not(feature = "test-support")), allow(dead_code))]
pub(crate) fn effective_hooks(cfg: &ToolsCfg, server: &str) -> Vec<String> {
    busbar_kernel::plane::config::attach_list(
        &cfg.all_server_hooks,
        cfg.servers.get(server).map_or(&[], |d| d.hooks.as_slice()),
    )
}

/// The `tools:` section as the kernel's config trait object: the plane's [`ToolsCfg`], wrapped so
/// the host's trait is implemented where the host is named. `as_any` yields the inner
/// [`ToolsCfg`], so every downcast reads the plane's type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolsSectionCfg(pub ToolsCfg);

impl busbar_kernel::plane::config::PlaneCfg for ToolsSectionCfg {
    /// The MCP plane's secret references: `tools.<name>.token_exchange.subject_token` (busbar's OWN
    /// token, the SUBJECT of an RFC 8693 exchange, never the caller's) and each reference-valued
    /// `tools.<name>.env.<var>` a stdio child is handed. Moved here VERBATIM from the core
    /// `config_validate::secret_refs` walk so the exhaustive destructure that forces a
    /// secret/not-secret decision on every new field lives beside the fields it guards.
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)> {
        // EXHAUSTIVE, no `..`: adding a field to `McpServerDefCfg` / `TokenExchangeCfg` fails to build
        // with `E0027 pattern does not mention field` until somebody decides, here, whether it carries
        // a secret. That force used to live in `config_validate::secret_refs`; it moved with the sweep.
        let mut refs: Vec<(String, &busbar_contract::secret_ref::SecretRef)> = Vec::new();
        for (name, server) in &self.0.servers {
            let McpServerDefCfg {
                token_exchange,
                // A STDIO CHILD'S ENVIRONMENT, and it is the second place on this plane a credential can
                // be written. A pipe has no header block, so `token_exchange:` is refused on that
                // transport and `env:` is the only channel a child gets a credential through — which
                // makes it exactly as owed a `--validate` resolution as the subject token above.
                env,
                // Not credentials, each for the reason recorded at the destructure above.
                url: _,
                // The binary busbar spawns, its argv, and its working directory. Operator-authored
                // paths and arguments; the SECRETS in a spawn are in `env` and nowhere else, which is
                // deliberate — an argv is world-readable on every platform busbar runs on.
                command: _,
                args: _,
                cwd: _,
                pin: _,
                // A duration string bounding max verification staleness on the call path. Not a
                // credential.
                verify_ttl: _,
                // A duration string bounding one outbound leg to this server. Not a credential.
                timeout: _,
                transport: _,
                aud: _,
                grants: _,
                // The filesystem roots busbar may disclose to this server on a granted `roots/list`
                // ask. Operator-authored `file://` URIs and display names — locations, never
                // credentials, so there is nothing here for `--validate` to resolve.
                roots: _,
                // The sampling policy a granted `sampling/createMessage` ask spends against: a pool
                // name and two ceilings. Operator-authored routing and budget numbers, never a
                // credential, so there is nothing here for `--validate` to resolve.
                sampling: _,
                max_input_required_rounds: _,
                max_caller_ask_rounds: _,
                upstream_credentials: _,
                hooks: _,
                // The SSRF posture for this server. A boolean, and the guard that reads it is the one
                // place it means anything.
                allow_private: _,
                tools_allow: _,
                prompts_allow: _,
                resources_allow: _,
                // The exposed capabilities. Each is operator-authored CONTENT — a description, a
                // template, a typed message, a URI template and the bytes it answers with — and none of
                // them is a credential reference: a resource's `blob:` is base64 media the operator
                // pasted, not a pointer into a secret store, so there is nothing here for `--validate`
                // to resolve. Named rather than covered by `..` so the compiler keeps asking.
                resource_templates_allow: _,
            } = server;
            if let Some(tx) = token_exchange {
                let TokenExchangeCfg {
                    subject_token,
                    // A URL and an RFC 8693 token-type URN; neither is a secret.
                    token_url: _,
                    subject_token_type: _,
                } = tx;
                refs.push((
                    format!("tools.{name}.token_exchange.subject_token"),
                    subject_token,
                ));
            }
            for (var, value) in env {
                // The PLAIN arm is a literal the operator typed; there is nothing to resolve and nothing
                // that can fail at runtime. Only the reference arm is owed a `--validate`.
                if let ChildEnvValue::Secret(r) = value {
                    refs.push((format!("tools.{name}.env.{var}"), r));
                }
            }
        }
        refs
    }

    fn contains_def(&self, name: &str) -> bool {
        self.0.servers.contains_key(name)
    }

    fn def_names(&self) -> Vec<&str> {
        self.0.servers.keys().map(|s| s.as_str()).collect()
    }

    fn entry_document(&self, name: &str) -> Option<serde_json::Value> {
        self.0
            .servers
            .get(name)
            .and_then(|cfg| serde_json::to_value(cfg).ok())
    }

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        // THE SAME typed parse the file runs, through the SAME error wording — `deny_unknown_fields`
        // rejects a typo'd key HERE exactly as `config.yaml` would. The value rules already ran
        // through the plane's `config_validate` seam at the write path's `parse_def`, so this parse
        // cannot fail on a definition that reached install; the `?` is the fail-closed backstop.
        let cfg: McpServerDefCfg = serde_json::from_value(def.clone())
            .map_err(|e| format!("invalid `tools.{name}` definition: {e}"))?;
        self.0.servers.insert(name.to_string(), cfg);
        Ok(())
    }

    fn container_gates(&self) -> busbar_kernel::plane::config::ContainerGateInputs {
        busbar_kernel::plane::config::ContainerGateInputs {
            section_hooks: self.0.all_server_hooks.clone(),
            containers: self
                .0
                .servers
                .iter()
                .map(|(name, def)| (name.clone(), def.hooks.clone()))
                .collect(),
        }
    }

    fn validate_registry(&self) -> Result<(), String> {
        validate_published_names(&self.0)
    }

    fn is_present(&self) -> bool {
        !self.0.servers.is_empty()
            || !self.0.all_server_hooks.is_empty()
            || self.0.all_server_upstream_credentials.is_some()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        &self.0
    }

    fn clone_box(&self) -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.0.clone())
    }
}

/// THE OPERATOR'S MAX VERIFICATION STALENESS for one registration, lifted into the plane-neutral
/// [`busbar_kernel::trust::reverify::Policy`] the verify-on-call gate consumes.
///
/// Config in, policy out, no clock and no I/O — so the bound an operator wrote and the bound the
/// decision uses are provably the same value rather than two parallel readings of it. Deliberately
/// the same shape as the A2A plane's `policy_for` (`busbar_a2a::a2a::config`), because it feeds the same `due`.
///
/// `recovery_backoff_ms` is **zero**, and that is a stated difference from the A2A plane rather than
/// an oversight. The backoff exists to disbelieve a CLEAN answer for a while after a drift, and
/// applying it needs a `settle` step that can decline to adopt an observation. The MCP cache's
/// [`crate::mcp::client::catalogue::ServerCatalogue::observe`] has no such arm — it adopts what it
/// saw — so a non-zero value here would be a number that is read and then ignored, which is worse
/// than no number at all. `due` does not consult it. Giving MCP the recovery hold is real work on
/// `observe`, and it is not what verify-on-call is: verify-on-call is that the DEMOTION happens
/// BEFORE the call, and demotion is the half that is never held on either plane.
pub(crate) fn verify_policy_for(
    def: &McpServerDefCfg,
) -> Result<busbar_kernel::trust::reverify::Policy, String> {
    let ttl = def.verify_ttl.as_deref().unwrap_or(DEFAULT_MCP_VERIFY_TTL);
    let ttl_ms = busbar_contract::duration::parse_duration_secs(ttl)?.saturating_mul(1_000);
    Ok(busbar_kernel::trust::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms: 0,
    })
}

/// Boot's whole judgement of one registration, for tests: the kernel's (the declared trust keys and
/// the hook references), then this section's value rules, in that order.
#[cfg(all(test, feature = "test-support"))]
pub(crate) fn validate_server_at_boot(name: &str, def: &McpServerDefCfg) -> Result<(), String> {
    use busbar_kernel::plane::config as kernel;
    let entry = serde_yaml::to_value(def).map_err(|e| e.to_string())?;
    let section = super::PLANE_DECLARATION.config_section;
    kernel::validate_plane_entry(section, name, &entry, TRUST_KEYS, &kernel::plane_sections())?;
    validate_server(name, def)
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/tools_config_tests.rs"]
mod tools_config_tests;
