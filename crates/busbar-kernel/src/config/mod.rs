// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod card;
pub mod overlay;
mod overlay_store;

pub mod filled;

pub mod groups;

pub mod migrate;
pub mod migrate_catalog;
pub mod migrate_export;
pub mod migrate_plugins;

pub mod migration_table;

pub mod named_map;

pub mod parse;

pub mod patch;

pub mod prepass;
pub mod secret;

pub mod settings_public;

pub mod transaction;

pub use prepass::{deploy_from_deserializer, deploy_from_yaml_str, deploy_from_yaml_value};

pub use credentials::{AtRestCfg, CredentialsCfg};
pub use groups::GroupCfg;
pub use groups::LimitCfg;
pub use secret::SecretRef;

use crate::config::plane_sections::{DeclaredSections, EndpointSection};
use crate::diagnostics::{
    diag_warn, CONFIG_ANTIDOWNGRADE_FLOOR_INVALID, CONFIG_FIRSTPARTY_FLOOR_INVALID,
};
use busbar_kernel_ledger::cost::compose_plane_cards;

fn reject_yaml_unsafe_value(var_name: &str, value: &str) -> Result<(), String> {
    if let Some(bad) = value
        .chars()
        .find(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err(format!(
            "environment variable '{var_name}' contains a control character (U+{:04X}) that could \
             inject YAML structure during config interpolation; remove it",
            bad as u32
        ));
    }
    Ok(())
}

/// How [`interpolate_env_with`] treats a `${VAR}` whose environment variable is unset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EnvSubst {
    /// Boot / reload: an unset variable is a hard error (fail loud — a real deployment must have its
    /// secrets present before it serves traffic).
    Strict,
    /// `busbar --validate`: an unset variable is substituted with a placeholder (its own name) and
    /// recorded, so config STRUCTURE can be validated without secrets present (CI, pre-reload dry runs).
    Lenient,
}

pub fn interpolate_env(s: &str) -> Result<String, String> {
    interpolate_env_with(s, EnvSubst::Strict, &mut Vec::new())
}

struct Occurrence {
    var_name: String,
    real_value: String,
    placeholder: String,
}

/// See [`interpolate_env`]. In [`EnvSubst::Lenient`] mode each unset variable name is pushed into
/// `unset` (first-seen, deduped) and a placeholder substituted; in `Strict` mode `unset` is untouched.
///
/// Two independent layers guard every substituted value against breaking out of the raw YAML text
/// it is spliced into, verbatim, BEFORE parsing:
///
/// 1. [`reject_yaml_unsafe_value`] rejects a NEWLINE (or other YAML-structural control character)
///    in the value outright — cheap, and gives a precise error for that shape.
/// 2. A structural-equivalence check (this function, below): after interpolation, the SAME raw
///    template is interpolated a second time with every `${VAR}` replaced by a unique, YAML-inert
///    placeholder token instead of its real value. Both results are parsed to `serde_yaml::Value`
///    and their trees are compared for structural equivalence (same map keys, same sequence
///    lengths, same node kind, at every position — NOT scalar leaf values, which are expected and
///    allowed to differ in content and even inferred type). Any difference means a substituted
///    value injected or removed YAML structure — the config would parse into a different SHAPE
///    than the template declares — and interpolation is rejected. This closes injection shapes
///    that need no newline at all (flow-collection `,`/`"`/`'` breakout, anchor/tag games), which
///    (1) alone cannot see.
pub fn interpolate_env_with(
    s: &str,
    mode: EnvSubst,
    unset: &mut Vec<String>,
) -> Result<String, String> {
    let mut result = String::with_capacity(s.len());
    let mut occurrences: Vec<Occurrence> = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut var_name = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                var_name.push(ch);
            }

            if !closed {
                return Err(format!(
                    "unclosed variable reference starting at '${{{var_name}'"
                ));
            }
            if var_name.is_empty() {
                return Err("empty variable name in ${}".into());
            }
            let value = match std::env::var(&var_name) {
                Ok(v) => v,
                Err(_) => match mode {
                    EnvSubst::Strict => {
                        return Err(format!("unset environment variable: {}", var_name));
                    }
                    EnvSubst::Lenient => {
                        if !unset.contains(&var_name) {
                            unset.push(var_name.clone());
                        }
                        var_name.clone()
                    }
                },
            };

            reject_yaml_unsafe_value(&var_name, &value)?;
            result.push_str(&value);

            let placeholder = structural_placeholder(occurrences.len());
            occurrences.push(Occurrence {
                var_name,
                real_value: value,
                placeholder,
            });
        } else {
            result.push(ch);
        }
    }

    if !occurrences.is_empty() {
        assert_interpolation_preserves_structure(s, &result, &occurrences)?;
    }

    Ok(result)
}

fn structural_placeholder(occurrence_index: usize) -> String {
    format!("__BUSBAR_INTERP_PLACEHOLDER_{occurrence_index}__")
}

fn splice_occurrences(
    template: &str,
    occurrences: &[Occurrence],
    keep_real: Option<usize>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    let mut idx = 0usize;
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
            }
            let occ = &occurrences[idx];
            if keep_real == Some(idx) {
                out.push_str(&occ.real_value);
            } else {
                out.push_str(&occ.placeholder);
            }
            idx += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn assert_interpolation_preserves_structure(
    template: &str,
    real: &str,
    occurrences: &[Occurrence],
) -> Result<(), String> {
    let real_value: serde_yaml::Value = match serde_yaml::from_str(real) {
        Ok(v) => v,
        Err(error) => {
            let mut vars: Vec<&str> = occurrences.iter().map(|o| o.var_name.as_str()).collect();
            vars.sort_unstable();
            vars.dedup();
            let position = error.location().map_or_else(String::new, |at| {
                format!(" at line {} column {}", at.line(), at.column())
            });
            return Err(format!(
                "could not verify that environment-variable interpolation preserves config \
                 structure: interpolated YAML could not be parsed{position}; inspect variable(s) \
                 {}; refusing to proceed",
                vars.join(", ")
            ));
        }
    };

    let placeholder_text = splice_occurrences(template, occurrences, None);
    let placeholder_value: serde_yaml::Value = match serde_yaml::from_str(&placeholder_text) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "could not verify that environment-variable interpolation preserves config \
                 structure (internal placeholder document failed to parse: {e}); refusing to \
                 proceed"
            ));
        }
    };

    if structural_shapes_match(&real_value, &placeholder_value, 0) {
        let vars: Vec<&str> = occurrences.iter().map(|o| o.var_name.as_str()).collect();
        filled::record(
            &real_value,
            &placeholder_value,
            &vars,
            &structural_placeholder,
        );
        return Ok(());
    }

    let mut culprits: Vec<String> = Vec::new();
    for (i, occ) in occurrences.iter().enumerate() {
        let hybrid_text = splice_occurrences(template, occurrences, Some(i));
        let matches = match serde_yaml::from_str::<serde_yaml::Value>(&hybrid_text) {
            Ok(hybrid_value) => structural_shapes_match(&hybrid_value, &placeholder_value, 0),
            Err(_) => false,
        };
        if !matches && !culprits.contains(&occ.var_name) {
            culprits.push(occ.var_name.clone());
        }
    }

    if culprits.is_empty() {
        let mut all: Vec<String> = occurrences.iter().map(|o| o.var_name.clone()).collect();
        all.sort();
        all.dedup();
        Err(format!(
            "environment-variable interpolation would change the config's YAML structure (extra \
             or missing key, different sequence length, or different node kind at some position), \
             but no single variable reproduces it in isolation — inspect: {}",
            all.join(", ")
        ))
    } else {
        Err(format!(
            "environment variable(s) {} would change the config's YAML structure when \
             interpolated (extra or missing key, different sequence length, or different node \
             kind) — a substituted value must only ever change a scalar leaf's content, never the \
             document's shape",
            culprits.join(", ")
        ))
    }
}

const MAX_STRUCTURAL_COMPARE_DEPTH: usize = 128;

fn structural_shapes_match(a: &serde_yaml::Value, b: &serde_yaml::Value, depth: usize) -> bool {
    use serde_yaml::Value;
    if depth > MAX_STRUCTURAL_COMPARE_DEPTH {
        return false;
    }
    match (a, b) {
        (Value::Mapping(ma), Value::Mapping(mb)) => {
            let mut ka: Vec<String> = ma.iter().map(|(k, _)| mapping_key_repr(k)).collect();
            let mut kb: Vec<String> = mb.iter().map(|(k, _)| mapping_key_repr(k)).collect();
            ka.sort();
            kb.sort();

            if ka != kb {
                return false;
            }
            ma.iter().all(|(k, va)| match mb.get(k.clone()) {
                Some(vb) => structural_shapes_match(va, vb, depth + 1),
                None => false,
            })
        }
        (Value::Sequence(sa), Value::Sequence(sb)) => {
            sa.len() == sb.len()
                && sa
                    .iter()
                    .zip(sb.iter())
                    .all(|(va, vb)| structural_shapes_match(va, vb, depth + 1))
        }
        (Value::Tagged(ta), Value::Tagged(tb)) => {
            ta.tag == tb.tag && structural_shapes_match(&ta.value, &tb.value, depth + 1)
        }
        (Value::Mapping(_), _) | (_, Value::Mapping(_)) => false,
        (Value::Sequence(_), _) | (_, Value::Sequence(_)) => false,
        (Value::Tagged(_), _) | (_, Value::Tagged(_)) => false,

        _ => true,
    }
}

fn mapping_key_repr(key: &serde_yaml::Value) -> String {
    match key {
        serde_yaml::Value::String(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// The fully-resolved runtime config. NOT deserialized from YAML: the on-disk shape is `DeployCfg`
/// (+ provider definitions), and `RootCfg` is constructed exclusively by [`resolve`]. It therefore
/// carries no `Deserialize` derive and no field-level serde defaults — those would be inert, and
/// implying a YAML parse path here would mislead a reader into reasoning about defaults that never
/// fire.
#[derive(Debug)]
pub struct RootCfg {
    pub listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`). The externally-reachable origin used to
    /// build `/auth/token` links AND shown to devs as the `base_url` they point BYOK clients at (no
    /// `/v1` suffix — clients append their own). Absent ⇒ no hosted-login/token links can be built.
    /// Validated (absolute https; loopback http allowed; no path/query, no cloud-metadata host).
    pub public_url: Option<String>,
    /// The VALIDATED per-plane endpoint resources, keyed by the owning plane's CONFIG SECTION and
    /// each type-erased as `Arc<dyn Any>`. Empty when no endpoint plane is configured. Each is lowered
    /// and refused at boot by that plane's `lower_endpoint` seam hook, so core names no plane resource
    /// type and nothing downstream re-parses the canonical URI or re-derives the mount path. The
    /// plane's own module downcasts its entry back to its concrete resource; read it via
    /// [`RootCfg::endpoint_resource`] keyed by the plane's config section — never a per-plane field.
    ///
    /// A plane section the kernel carries RAW ([`DeployCfg::plane_raw`] — a plane with no typed
    /// grammar of its own, such as one that states itself over the C ABI) is its plane's resource too,
    /// as `(section, value)`: its plane's `build` reads it through the same `BuildCtx::endpoint_slot`.
    pub endpoint_resources:
        std::collections::HashMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    /// The `oauth_as:` block, OPAQUE to the kernel, or `None` when this deployment is not an
    /// authorization server. It was handed to its owner (`oauth_as::seam::AsPlaneSeam::check`) and
    /// accepted by `resolve`, so a value here is a block the owner has already validated, with the
    /// secret references the owner listed in it.
    pub oauth_as: Option<crate::oauth_as::seam::CheckedAsBlock>,
    /// The `credentials:` block, carried through `resolve` verbatim: the at-rest key references,
    /// resolved at boot and at reload ([`CredentialsCfg`]).
    pub credentials: CredentialsCfg,
    /// EVERY REGISTERED PLANE'S DECLARED SECTION this document writes, by config section, carried
    /// through `resolve` VERBATIM.
    ///
    /// Verbatim on purpose: this is operator intent, and the only derivation that
    /// happens to it is building the plane's own snapshot, which is a separate value with its own
    /// generation. Lowering it here would give a registry two representations that could disagree
    /// about what the operator approved — precisely the disagreement the trust lifecycle removes by
    /// DERIVING state from intent-versus-observation instead of storing it.
    pub plane_defs: std::collections::BTreeMap<
        &'static str,
        Box<dyn busbar_kernel::config::plane_sections::PlaneCfg>,
    >,
    /// Optional native inbound TLS. `None` ⇒ plain HTTP (today's path, byte-for-byte).
    pub tls: Option<TlsCfg>,
    /// Separate admin listen address — the admin API is served ONLY here, never on the data
    /// listener. Defaults to loopback (`127.0.0.1:8081`).
    pub admin_listen: String,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`).
    pub admin_tls: Option<TlsCfg>,
    pub auth: Option<AuthCfg>,
    /// The resolved providers: each catalog definition merged with its deployment, the kernel-owned
    /// keys typed and the plane's an opaque table ([`ResolvedProvider`]).
    pub providers: HashMap<String, ResolvedProvider>,
    pub models: HashMap<String, ModelCfg>,
    pub pools: HashMap<String, PoolCfg>,
    /// The ALL-POOLS `upstream_credentials:` default, resolved from the reserved
    /// `pools.upstream_credentials:` key (1.5.3 — moved off the retired `auth.upstream_credentials:`).
    /// A pool's own `upstream_credentials:` OVERRIDES this (SCALAR combine rule).
    pub upstream_credentials: crate::auth::UpstreamCreds,
    /// The RUNTIME hook registry, LOWERED by `resolve` from the top-level `hooks:` NAMED-DEFINITION
    /// map (1.5.3: [`DeployCfg::hooks`] — a hook is DEFINED once and REFERENCED by bare name from
    /// `pools.hooks:` / `pools.<p>.hooks:`). Admin-registered hooks land here too.
    pub hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain module names (from `auth.admin_auth:`, in order) gating
    /// `/api/v1/admin/*`. Default: the operator credential (`default_admin_auth_names`). `[]` = OPEN
    /// admin (dev only; loud boot warning).
    pub admin_auth: Vec<String>,
    /// The top-level `groups:` limit tree.
    pub groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source. See `DeployCfg::rate_card`. Every other
    /// plane's own card rides in it under plane-qualified keys
    /// (`busbar_kernel_ledger::cost::compose_plane_cards`); with none, it is `rate_card:` verbatim.
    pub rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents charged per request (default 0).
    pub per_request_fee: i64,
    /// Every other plane's own fees, by plane registry key. See `DeployCfg::plane_fees`.
    pub plane_fees: PlaneFeesMap,
    /// The `store:` block as configured; `None` = the block was ABSENT, which `--validate` and boot
    /// refuse ([`store_required`], Q-STORE = (B)).
    pub store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name (the top-level
    /// `secrets:` block). Empty = every secret plugin opens with `{}` (the prior behavior). The
    /// built-in `env` / `file` modules take no config and must not appear here.
    pub secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Names of hooks that fire on EVERY request — the registry names lowered from the reserved
    /// all-pools attach key `pools.hooks:` (1.5.3), in order. RUNTIME-only: there is no
    /// config-facing `global_hooks:` key any more.
    pub global_hooks: Vec<String>,
    /// Operator-supplied additions to the hardcoded cloud-metadata denylist (see
    /// [`SecurityCfg::blocked_metadata_hosts`]). Resolved from `DeployCfg.security`; empty when no
    /// `security:` block is present. Threaded into `config_validate::validate` so a provider
    /// `base_url` (and any path-override composition) targeting one of these hosts is rejected at
    /// boot unless that host is carved out by an allow-override.
    pub blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: cloud-metadata hosts/IPs to UNBLOCK for ALL providers
    /// (`security.allow_metadata_hosts`). Unioned with each provider's own `allow_metadata_hosts`
    /// when the guard runs; a host on the denylist is permitted iff it appears in this union (or
    /// `allow_all_metadata` is set). Matched with the same canonicalization as the block check (an IP
    /// entry unblocks all its spellings). Default empty.
    pub allow_metadata_hosts: Vec<String>,
    /// Nuclear override (`security.allow_all_metadata`): when true the metadata SSRF guard is fully
    /// DISABLED — every cloud-metadata endpoint is reachable by every provider. Logs a startup WARN.
    /// Default false.
    pub allow_all_metadata: bool,
    /// The `advanced` destination-guard keys, as written ([`RootCfg::destinations`] adds the rest).
    pub guard: Destinations,
    /// Fully-resolved operational limits ("NEVER CODED CAPS"), projected from the `limits:` /
    /// `observability:` / `governance:` / `metrics:` / `health:` / `routing:` config sections. Every
    /// value defaults to its historical hardcoded const, so an all-default config is unchanged. Read
    /// by `config_validate::validate`, threaded into the store/client/TLS/App at startup, and
    /// installed into the process-wide `crate::limits` statics for the deep call-stack use sites.
    pub limits: LimitsResolved,
    /// The resolved `export:` block — the built-in observability exporters. Default
    /// (all-`None`) ⇒ collection inert. Read at App construction to install the recorder + build the
    /// `/metrics` plugin route (prometheus) and to configure the request-log sinks.
    pub export: ExportCfg,
    /// The `identity-providers:` NAMED-DEFINITION map, carried through resolve VERBATIM (the
    /// EFFECTIVE map: base `config.yaml` + the overlay's API-applied entries, merged pre-resolve).
    /// `auth`/`admin_auth` above are the RESOLVED projection of it; this is the definition surface
    /// the admin API reads and rewrites (`GET/PUT/PATCH/DELETE /identity-providers/{name}`).
    pub identity_providers: IdentityProviders,
    /// The `export:` NAMED-DEFINITION map, carried through resolve VERBATIM — the definition twin of
    /// the typed `export` projection above, for the same reason `identity_providers` is carried:
    /// the admin API serves DEFINITIONS, not the lowered per-module runtime shape.
    pub export_defs: ExportDefs,
    /// EACH PLANE'S FAILOVER POOLS, by config section: the section's reserved `pools` sub-key,
    /// carried through `resolve` VERBATIM — operator intent, like `plane_defs` beside it, projected
    /// onto `state::App::plane_pools` at build. A section with no pools has no entry.
    pub plane_pools: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, crate::config::pools::CandidatePoolCfg>,
    >,
    /// LAW 7 — the plane config sections this config writes content into (the deletion gate's
    /// `is_present()`). A linked plane whose section is absent hydrates, starts, builds and serves
    /// nothing; see `state::App::plane_configured`.
    pub plane_sections: std::collections::BTreeSet<&'static str>,
}

impl RootCfg {
    pub fn endpoint_resource(
        &self,
        section: &str,
    ) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        self.endpoint_resources.get(section).cloned()
    }
}

pub use busbar_kernel::config::sections::TlsCfg;

pub use busbar_kernel::config::auth::{
    builtin_identity_providers, is_builtin_identity_module, names_operator, operator_module,
    operator_principal_id, operator_provider,
};

pub use busbar_kernel::config::auth::{
    AuthCfg, AuthChainEntry, AuthDeployCfg, AuthMethodCfg, AuthMethods, AuthPolicyCfg, BindingMode,
    BrowserLoginCfg, IdentityProviderCfg, IdentityProviders, MintCeilingCfg, RoleBindingCfg,
    RoleBindings, VerbGrant, ALL_ADMIN_VERBS, DEFAULT_MAX_ADMIN_SCOPE, KEYS_MODULE,
};

pub const CONFIG_TARGET_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn validate_token_placement(name: &str, module: &str, has_token: bool) -> Result<(), String> {
    if has_token && !names_operator(module) {
        let op = operator_provider();
        return Err(busbar_kernel_identity::operator::misplaced_definition_token(op, name, module));
    }
    Ok(())
}

pub fn resolve_auth(
    auth: &AuthDeployCfg,
    providers: &IdentityProviders,
    errors: &mut Vec<String>,
) -> AuthCfg {
    let mut resolve_one = |plane: &str, name: &String| -> AuthChainEntry {
        match providers.get(name) {
            Some(def) => {
                let module = def.module.trim().to_string();
                if module.is_empty() {
                    errors.push(format!(
                        "identity-providers.{name}.module must be a non-empty module name"
                    ));
                }
                if let Err(e) = validate_token_placement(name, &module, def.token.is_some()) {
                    errors.push(e);
                }
                let max_admin_scope = def.max_admin_scope.clone().or_else(|| {
                    (!names_operator(&module)).then(|| DEFAULT_MAX_ADMIN_SCOPE.to_string())
                });
                AuthChainEntry {
                    name: name.clone(),
                    module,
                    max_admin_scope,
                    token: def.token.clone(),
                    settings: def.settings.clone(),
                }
            }

            None if builtin_identity_providers().contains(&name.as_str()) => {
                AuthChainEntry::bare(name.clone())
            }
            None => {
                errors.push(format!(
                    "auth.{plane} references '{name}', which is not defined in \
                     `identity-providers:` (and is not a built-in: {}). Define it, or reference a \
                     built-in by its bare name.",
                    builtin_identity_providers().join(" / ")
                ));
                AuthChainEntry::bare(name.clone())
            }
        }
    };

    let chain = auth
        .chain
        .iter()
        .map(|n| resolve_one("chain", n))
        .collect::<Vec<_>>();
    let admin_auth = auth
        .admin_auth
        .iter()
        .map(|n| resolve_one("admin_auth", n))
        .collect::<Vec<_>>();

    let methods: AuthMethods = providers
        .iter()
        .filter(|(_, def)| !is_builtin_identity_module(def.module.trim()))
        .map(|(name, def)| {
            (
                name.clone(),
                AuthMethodCfg {
                    module: def.module.trim().to_string(),
                    browser_login: def.browser_login.clone(),
                    settings: def.settings.clone(),
                },
            )
        })
        .collect();

    AuthCfg {
        signing_key: auth.signing_key.clone(),
        chain,
        admin_auth,
        role_bindings: auth.role_bindings.clone(),
        methods,
        key_ttl: auth.key_ttl.clone(),
        policy: auth.policy.clone(),
    }
}

pub fn augment_config_error(err: impl std::fmt::Display) -> String {
    let msg = err.to_string();
    if msg.contains("unknown field `mode`") {
        format!(
            "{msg}\n  hint: the `auth.mode:` key was removed in favor of `auth.chain:` — `mode: none` \
             maps to an empty/omitted chain, `mode: token` or `mode: apikey` to `chain: [tokens]`, and \
             `mode: passthrough` to `auth.upstream_credentials: passthrough`"
        )
    } else if let Some((old, new)) = RENAMED_HOOK_STAGES
        .iter()
        .copied()
        .find(|(old, _)| msg.contains(&format!("unknown variant `{old}`")))
    {
        format!(
            "{msg}\n  hint: hook tap stage `{old}` was renamed to `{new}` in 1.5.3 — run \
             `busbar --migrate-config <config.yaml>` or update the `at:` value to `{new}`"
        )
    } else if let Some((old, new)) = retired_observability_keys()
        .into_iter()
        .find(|(old, _)| msg.contains(&format!("unknown field `{old}`")))
    {
        format!(
            "{msg}\n  hint: `{old}` was retired in 1.5.3 — the observability sink moved to the \
             built-in EXPORTERS (`{new}`). Run `busbar --migrate-config <config.yaml>` or move the \
             field yourself"
        )
    } else if let Some((old, new)) = retired_config_keys_1_5_3()
        .into_iter()
        .find(|(old, _)| msg.contains(&format!("unknown field `{old}`")))
    {
        format!(
            "{msg}\n  hint: `{old}` was retired in 1.5.3 — it is now `{new}`. Run \
             `busbar --migrate-config <config.yaml>` to rewrite it in place"
        )
    } else {
        msg
    }
}

pub fn retired_config_keys_1_5_3() -> Vec<(&'static str, String)> {
    let trace_home = format!(
        "an `export:` instance with `module: {}` and `settings.url`",
        migration_table::text("export_trace_module")
    );
    [


        ("observability", migration_table::text("observability_home").to_string()),

        ("admin_insecure", "admin_require_mtls (INVERTED: `admin_insecure: true` ⇒ `admin_require_mtls: false`)".to_string()),

        ("upstream_credentials", "pools.upstream_credentials (the all-pools default) + a per-pool `pools.<p>.upstream_credentials` override".to_string()),

        ("methods", "the matching `identity-providers:` definition (browser_login + settings are per-provider)".to_string()),

        (migration_table::text("observability_trace_key"), trace_home.clone()),
        (migration_table::text("observability_trace_key_1_4"), trace_home),
    ]
    .into_iter()
    .filter(|(old, _)| !old.is_empty())
    .collect()
}

pub const RENAMED_HOOK_STAGES: &[(&str, &str)] = &[
    ("route", "candidate"),
    ("attempt", "routing"),
    ("completion", "response"),
];

pub fn retired_observability_keys() -> Vec<(&'static str, String)> {
    let log = migration_table::text("observability_log_type_key");
    let mut out: Vec<(&'static str, String)> = migration_table::pairs("observability_log_keys")
        .into_iter()
        .map(|(old, leaf)| (old, format!("export.{log}.settings.{leaf}")))
        .collect();
    out.push((
        "metrics",
        format!(
            "export.{}.settings (buffer_seconds / key_gauge_limit)",
            migration_table::text("metrics_type_key")
        ),
    ));
    out
}

pub use busbar_kernel::config::providers::{
    neg1, HealthCfg, HealthMode, ModelCfg, ProviderCfg, ProviderDef, ProviderDeploy, ProviderTable,
    ResolvedProvider,
};

pub use busbar_kernel::config::hooks::{
    caller_in_hook_groups, default_on_error, default_policy_timeout_ms, is_reserved_hook_name,
    on_error_terminal, HookCfg, HookDefCfg, HookDefs, HookKind, HookStage, OnErrorCfg,
    PromptAccess, UserAccess, ALL_HOOK_STAGES, CORE_HOOK_PHASES, DEFAULT_POLICY_TIMEOUT_MS,
    FROZEN_HOOK_NAME_WORD_SPACE, ON_ERROR_FIRST, ON_ERROR_NOTHING, ON_ERROR_REJECT,
    ON_ERROR_WEIGHTED, RESERVED_HOOK_NAMES,
};
pub use busbar_kernel::config::pools::{
    default_consecutive_n, default_cooldown, default_failover_timeout, default_max_cooldown,
    default_max_hops, default_min_requests, default_threshold, default_trip_mode, default_weight,
    default_window_secs, is_strategy_name, parse_strategy, AffinityCfg, AffinityMode, BreakerCfg,
    BreakerTripConfig, BreakerTripMode, FailoverCfg, OnExhausted, OnExhaustedCfg, PoolCfg,
    PoolMember, PoolPolicy, DEFAULT_BREAKER_BASE_COOLDOWN_SECS, DEFAULT_BREAKER_CONSECUTIVE_N,
    DEFAULT_BREAKER_MAX_COOLDOWN_SECS, DEFAULT_BREAKER_MIN_REQUESTS, DEFAULT_BREAKER_THRESHOLD,
    DEFAULT_BREAKER_WINDOW_SECS, STRATEGY_CHEAPEST, STRATEGY_FASTEST, STRATEGY_LEAST_BUSY,
    STRATEGY_USAGE,
};

pub use busbar_kernel::config::pools::{
    DEFAULT_FAILOVER_CAP, DEFAULT_FAILOVER_DEADLINE_SECS, MAX_FAILOVER_DEADLINE_SECS,
};

pub use busbar_kernel::config::auth::{default_admin_auth, default_admin_auth_names};

#[allow(clippy::too_many_arguments)]
fn check_failover_pool(
    errors: &mut Vec<String>,
    section: &str,
    pool: &str,
    def: &pools::CandidatePoolCfg,
    on_this_plane: impl Fn(&str) -> bool,
    elsewhere: impl Fn(&str) -> Option<&'static str>,
    this_registry: &str,
) {
    if def.members.len() < 2 {
        errors.push(format!(
            "{section}.{pool}: a failover pool needs at least TWO members (it has {}). A pool with \
             one member has nowhere to fail over to, so it changes nothing; remove it or add the \
             second registration.",
            def.members.len()
        ));
    }

    if def.members.len() > crate::store::MAX_POOL_MEMBERS {
        errors.push(format!(
            "{section}.{pool}: {} members exceeds the supported maximum of {} per failover pool \
             (the breaker's per-member lane table is fixed at process start). Split the pool or \
             drop members.",
            def.members.len(),
            crate::store::MAX_POOL_MEMBERS
        ));
    }

    if on_this_plane(pool) {
        errors.push(format!(
            "{section}.{pool}: `{pool}` is also the id of a `{this_registry}:` registration. A \
             pool's name shares the breaker keyspace with registration ids on its plane, so it \
             must not collide with one; rename the pool."
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for member in &def.members {
        if !seen.insert(member.as_str()) {
            errors.push(format!(
                "{section}.{pool}: `{member}` is named twice. A repeated member would be tried \
                 twice against the same upstream, which is a retry wearing a failover's clothes."
            ));
        }
        if on_this_plane(member) {
            continue;
        }
        if let Some(other_registry) = elsewhere(member) {
            errors.push(format!(
                "{section}.{pool}: `{member}` is an entry in the top-level `{other_registry}:` \
                 section, not `{this_registry}:`. A failover pool may not straddle two planes — the \
                 section a pool is written in IS which plane it is on."
            ));
        } else {
            errors.push(format!(
                "{section}.{pool}: `{member}` is not defined in the top-level `{this_registry}:` \
                 map. Define it there, or remove it from the pool."
            ));
        }
    }

    for op in &def.repeatable {
        if op.trim().is_empty() {
            errors.push(format!(
                "{section}.{pool}: `repeatable:` holds an empty entry. Every entry names ONE \
                 operation that may be performed twice; an empty one names nothing."
            ));
        }
    }
}

/// The top-level `pools:` map (1.5.3), which carries the two reserved section keys
/// ([`busbar_contract::section::RESERVED_SECTION_KEYS`]) alongside the
/// pools themselves. Every key that is NOT one of those two reserved words is a pool. A pool may NOT be
/// named `hooks` or `upstream_credentials` — both are REJECTED at parse with a clear error. The custom
/// `Deserialize` lifts the reserved keys out first, then parses the remainder as the pool map.
#[derive(Debug, Clone, Default)]
pub struct PoolsCfg {
    /// The ALL-POOLS attach list — hook names that fire for EVERY pool (the reserved `pools.hooks:`
    /// key). Empty when absent. Firing order: these fire BEFORE a pool's own hooks. LIST ⇒ ADDITIVE
    /// a pool's own `hooks:` are appended to this, deduped by name (see
    /// [`combine_hook_refs`]).
    pub all_pool_hooks: Vec<String>,
    /// The ALL-POOLS `upstream_credentials:` default (the reserved `pools.upstream_credentials:`
    /// key). SCALAR ⇒ OVERRIDE: a pool's own value REPLACES this. `None` = absent ⇒ the
    /// built-in default (`own`).
    pub all_pool_upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// The real pools, keyed by name (every top-level key except the two reserved section keys).
    pub pools: HashMap<String, PoolCfg>,
}

impl<'de> Deserialize<'de> for PoolsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let section = crate::config::plane_sections::split_section_for_plane::<D, PoolCfg>(
            deserializer,
            crate::plane_driver::dispatch::fallback_key(),
            |_, _| Ok(()),
        )?;
        Ok(PoolsCfg {
            all_pool_hooks: section.hooks,
            all_pool_upstream_credentials: section.upstream_credentials,

            pools: section.entries.into_iter().collect::<HashMap<_, _>>(),
        })
    }
}

pub fn combine_hook_refs(section: &[String], entity: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(section.len() + entity.len());
    for name in section.iter().chain(entity.iter()) {
        if !out.iter().any(|existing| existing == name) {
            out.push(name.clone());
        }
    }
    out
}

pub fn entity_only_hook_refs(section: &[String], entity: &[String]) -> Vec<String> {
    combine_hook_refs(section, entity)
        .into_iter()
        .skip(combine_hook_refs(section, &[]).len())
        .collect()
}

pub use busbar_kernel::config::sections::{DEFAULT_ADMIN_LISTEN_ADDR, DEFAULT_LISTEN_ADDR};

fn default_listen() -> String {
    DEFAULT_LISTEN_ADDR.into()
}

fn default_admin_listen() -> String {
    DEFAULT_ADMIN_LISTEN_ADDR.into()
}

fn default_admin_require_mtls() -> bool {
    true
}

pub fn bind_is_loopback(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _port)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

pub type PlaneRateCards =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, RateEntryCfg>>;

pub type PlaneFeesMap = std::collections::BTreeMap<String, busbar_kernel_ledger::cost::PlaneFees>;

/// A plane section's reserved `fees:` (#44: `{ per_request | per_session }`), in minor units; an
/// absent key is a fee of 0. Never rounded, never divided — each is one flat fee per unit.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PlaneFeesCfg {
    /// Charged once per billable request of the plane.
    pub per_request: u32,
    /// Charged once per session the plane opens.
    pub per_session: u32,
}

/// Deployment configuration - operator-owned config.yaml structure.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployCfg {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// busbar's PUBLIC base URL (top-level `public_url:`) — see [`RootCfg::public_url`]. Absent by
    /// default; required once a `browser_login` method or `/auth/token` link generation is in play.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Optional native inbound TLS / mTLS. Absent ⇒ the unencrypted transport (unchanged default).
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    /// SEPARATE listen address for the management surface (`/api/v1/admin/*`). That surface ALWAYS
    /// runs here and is NEVER mounted on the data `listen` — it stays isolated so it can carry its
    /// own TLS/mTLS, bind, and firewall posture independent of the data plane's own traffic. Defaults
    /// to loopback (`127.0.0.1:8081`); set an exposed address (+ `admin_tls`) to manage off-host.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Config-MANAGEMENT policy (`config:` block, 1.5.3): whether the admin API may mutate config and
    /// WHERE those changes persist. Absent ⇒ durable-by-default (mutable + a file overlay next to
    /// config.yaml). See [`ConfigMgmtCfg`].
    #[serde(default)]
    pub config: ConfigMgmtCfg,
    /// Optional pointer to the providers CATALOG file (`providers_file:`, 1.5.3). Relative paths
    /// resolve against the config.yaml directory. Absent ⇒ `providers.yaml` next to the resolved
    /// config.yaml. The `--providers <path>` CLI flag overrides this (1.6.0). The two-file model is
    /// preserved: this names the vetted, shippable catalog that config.yaml's `providers:` map
    /// references.
    #[serde(default)]
    pub providers_file: Option<String>,
    /// The top-level `mcp:` block (1.6.0): this section's owning plane's own endpoint, as an OAuth 2.1
    /// resource server. Its PRESENCE is what mounts that plane's endpoint — absent, the deployment
    /// carries no ingress for it and no `.well-known` document, and nothing joins the route table.
    /// See that plane's own endpoint config type.
    ///
    /// A CARRIER, not a parsed field: the key is lifted off the document by
    /// [`crate::config::prepass`] before this struct parses, so it is never in this struct's
    /// accepted key set and never named in its unknown-key refusal. See that module for why. The
    /// field is named for what it carries, not for its wire key: the pre-pass ties the key to its
    /// owner's endpoint door (`EndpointSection::OWNER`).
    #[serde(skip)]
    pub endpoint: EndpointSection,
    /// `oauth_as:` — busbar AS an OAuth 2.1 authorization server, for the deployment that has no
    /// identity provider (or has one that will not do dynamic registration). ABSENT BY DEFAULT, and
    /// absent means nothing is built: see `crate::oauth_as`.
    ///
    /// A lifted CARRIER, exactly as `mcp:` above is.
    #[serde(skip)]
    pub oauth_as: Option<serde_yaml::Value>,
    /// `credentials:` — how a recoverable credential is kept at rest ([`CredentialsCfg`]): the
    /// `at_rest` key it is sealed under, and the `previous` one a rotation still opens. A lifted
    /// CARRIER, exactly as `oauth_as:` above is: 1.5.5 refuses the key as unknown.
    #[serde(skip)]
    pub credentials: CredentialsCfg,
    /// TLS/mTLS for the management-surface listener (only meaningful with `admin_listen`). Its own
    /// cert + optional `client_ca_file`, so the management surface can require client certificates
    /// without forcing them on data-plane clients. A network-exposed `admin_listen` REQUIRES
    /// `client_ca_file` here unless `admin_require_mtls: false`.
    #[serde(default)]
    pub admin_tls: Option<TlsCfg>,
    /// TOP-LEVEL boot-policy flag: does a network-exposed management surface REQUIRE mTLS?
    /// `true` (the DEFAULT) ⇒ a non-loopback `admin_listen` without `admin_tls.client_ca` REFUSES to
    /// boot. `false` ⇒ the operator deliberately accepts a token-only management surface on an
    /// exposed address (mTLS terminated upstream by a mesh). Loopback binds are exempt either way.
    ///
    /// 1.5.3 BREAKING: this INVERTS and replaces the retired `admin_insecure:` boolean, so the safe
    /// posture is what an omitted key gives you. It lives at the TOP LEVEL, not under `admin_tls:`,
    /// precisely because the mesh case has NO `admin_tls` block at all — nesting it would make the
    /// waiver unreachable for the deployment that needs it. It is NOT redundant with
    /// `admin_tls.client_ca`: that says "here is the CA", this says "an exposed plane must have one".
    #[serde(default = "default_admin_require_mtls")]
    pub admin_require_mtls: bool,
    /// Read by [`prepass::auth_section`], which lifts the 1.6.0 `policy:` off it first.
    #[serde(default, deserialize_with = "prepass::auth_section")]
    pub auth: Option<AuthDeployCfg>,
    /// The top-level `identity-providers:` NAMED-DEFINITION map (1.5.3): provider NAME →
    /// [`IdentityProviderCfg`]. An IdP is DEFINED here once and REFERENCED by bare name from
    /// `auth.chain:`, `auth.admin_auth:` and `auth.role_bindings:`. Absent ⇒ only the bare built-ins
    /// ([`builtin_identity_providers`]) are referenceable.
    #[serde(default, rename = "identity-providers")]
    pub identity_providers: IdentityProviders,
    /// `providers:` and `models:` are REQUIRED only when a registered plane declares it requires
    /// them (`PlaneDeclaration::required_config_sections`); the pre-pass refuses such a document
    /// with serde's own missing-field message. No such plane: an omitted section reads empty.
    /// Each entry's keys beyond busbar's own are its options, read aside
    /// ([`providers::deployments`]) for the plane that speaks its dialect to judge.
    #[serde(default, deserialize_with = "providers::deployments")]
    pub providers: HashMap<String, ProviderDeploy>,
    #[serde(default)]
    pub models: HashMap<String, ModelCfg>,
    /// Pools are optional: a deployment can route to models directly (`/<model>/v1/messages`)
    /// without defining any pool. Carries the reserved `pools.hooks:` all-pools attach key (1.5.3);
    /// see [`PoolsCfg`].
    #[serde(default)]
    pub pools: PoolsCfg,
    /// The top-level `hooks:` NAMED-DEFINITION map (1.5.3): instance name → [`HookDefCfg`]. This
    /// REPLACES the removed `global_hooks:` list — hooks are DEFINED here once (which plugin backs
    /// each, its `groups:`/`phase:` scope, its role/projection) and REFERENCED by bare name from the
    /// all-pools `pools.hooks:` list or a per-pool `hooks:` list. Absent ⇒ no hooks.
    #[serde(default)]
    pub hooks: HookDefs,
    /// The top-level `groups:` block - THE one limit tree. Optional; absent = no groups.
    #[serde(default)]
    pub groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source. Per-model entry; ALL-OR-NOTHING:
    /// absent => token pricing is 0 for every model; present => AUTHORITATIVE and COMPLETE (every
    /// configured model must have an entry or boot/`--validate` FAIL naming the missing models).
    /// The numbers are ABSTRACT cost units (no currency, no FX).
    #[serde(default)]
    pub rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents (abstract minor units) charged per request for budget accounting. Default 0.
    #[serde(default = "default_per_request_fee")]
    pub per_request_fee: i64,
    /// Every OTHER plane's own card (#47), keyed by plane registry key: the reserved `rate_card:`
    /// sub-key of that plane's section, stripped off it before the plane parses the rest (#43).
    /// A lifted CARRIER, like the plane sections below; [`resolve`] composes it beside `rate_card:`.
    #[serde(skip)]
    pub plane_rate_cards: PlaneRateCards,
    /// Every OTHER plane's own fees (#47): the reserved `fees:` sub-key of that plane's section,
    /// lifted like its card. The pools plane's fee is `per_request_fee:`.
    #[serde(skip)]
    pub plane_fees: PlaneFeesMap,
    /// THE GENERIC CARRIER: every REGISTERED plane's declaring section that no other carrier holds
    /// (a named one, or the generic singular one) and core does not own — lifted by the pre-pass off
    /// the plane registry, card and fees stripped, the remainder kept RAW for the plane to read.
    /// [`resolve`] hands each present one to its plane's `build` as its section-keyed resource. A
    /// section no registered plane declares is still refused as an unknown field.
    #[serde(skip)]
    pub plane_raw: std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    /// Every declaring section its plane owns the grammar of ([`DeployCfg::declared`]), AS WRITTEN
    /// (card and fees stripped): the settings that plane's door opens with when it is served through
    /// its door, beside the parse its grammar made. See [`DeployCfg::door_sections`].
    #[serde(skip)]
    pub declared_raw: std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    /// The durable store as `{ module, settings }`. Required: absent is refused at validation
    /// ([`store_required`], Q-STORE = (B)).
    #[serde(default)]
    pub store: Option<StoreCfg>,
    /// Module-level `open()` config for `kind: secret` plugins, keyed by module name — the delivery
    /// path a Vault-style secret plugin needs (address / namespace / auth token / CA). Absent = every
    /// secret plugin opens with `{}`. Mirrors `store.settings` for the store plugin.
    #[serde(default)]
    pub secrets: std::collections::BTreeMap<String, SecretModuleCfg>,
    /// Internal tuning knobs (the `advanced:` block).
    #[serde(default)]
    pub advanced: AdvancedCfg,
    /// The top-level `export:` NAMED-DEFINITION map (1.5.3): instance name → [`ExportDefCfg`]. THE
    /// single telemetry-egress surface. Absent/empty ⇒ collection inert (no recorder, no request-log
    /// sink, no tracer).
    ///
    /// 1.5.3 also DELETED the `observability:` block outright: its last remaining field
    /// (`otlp_url`) is now an `export:` instance with `module: otlp`. A config still carrying
    /// `observability:` LOUD-FAILS with the `--migrate-config` breadcrumb.
    #[serde(default)]
    pub export: ExportDefs,
    /// THE DECLARED SECTIONS (1.6.0): every top-level section a registered plane declares AND owns
    /// the grammar of, keyed by that section and parsed by that plane (#47/#49) — see
    /// [`DeclaredSections`]. Its mere EXISTENCE in the document declares that plane (LAW 7). A build
    /// that compiled the plane out declares nothing for it, so its section is refused at parse as an
    /// unknown field (Option A, S11b (c) / Q67).
    ///
    /// A lifted CARRIER, exactly as `mcp:` above is: one field for every such section.
    #[serde(skip)]
    pub declared: DeclaredSections,

    /// The dynamic plugin subsystem (`plugins:` block, top-level). Absent = disabled (the default
    /// `enabled: false` master switch): no plugin is ever discovered or loaded.
    #[serde(default)]
    pub plugins: PluginsCfg,
    /// Optional security controls. Today this carries only `blocked_metadata_hosts`, the operator
    /// extension to the hardcoded cloud-metadata SSRF denylist. Absent ⇒ only the hardcoded denylist
    /// applies.
    #[serde(default)]
    pub security: Option<SecurityCfg>,
    /// Operator-tunable global operational limits ("NEVER CODED CAPS"). Whole block optional; each
    /// field defaults to its historical hardcoded value (absent = today's behavior).
    #[serde(default)]
    pub limits: LimitsCfg,
    /// Process-wide active-probe fallbacks (per-lane overrides still win).
    #[serde(default)]
    pub health: HealthDefaultsCfg,
    /// Routing global default policy timeout (per-policy override still wins).
    #[serde(default)]
    pub routing: RoutingCfg,
}

impl DeployCfg {
    #[must_use]
    pub fn door_sections(&self) -> std::collections::BTreeMap<&'static str, serde_yaml::Value> {
        self.plane_raw
            .iter()
            .chain(&self.declared_raw)
            .map(|(k, v)| (*k, v.clone()))
            .filter(|(_, v)| !v.is_null())
            .collect()
    }

    pub fn providers_file(&self) -> Option<&str> {
        self.providers_file.as_deref()
    }

    pub fn plane_section(
        &self,
        section: &str,
    ) -> Option<&dyn busbar_kernel::config::plane_sections::PlaneCfg> {
        self.declared.get(section)
    }

    pub fn plane_section_mut(
        &mut self,
        section: &str,
    ) -> Option<&mut dyn busbar_kernel::config::plane_sections::PlaneCfg> {
        self.declared.get_or_default(section)
    }
}

pub use busbar_kernel::config::sections::{Destinations, SecurityCfg};

/// The top-level `plugins:` block — the ONLY configuration surface of the dynamic plugin subsystem.
/// A plugin is a plugin: store, auth, and hook plugins share this one block (one directory, one
/// trust model, one master switch); the manifest `kind` inside each signed tarball selects which
/// engine subsystem consumes it.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginsCfg {
    /// MASTER SWITCH, default FALSE. When false (or the whole `plugins:` block is absent), NO
    /// plugin is ever loaded — a tarball dropped into the directory is INERT. Referencing a plugin
    /// while disabled (`store.module:` other than `memory`) is a BOOT ERROR naming this flag.
    #[serde(default)]
    pub enabled: bool,
    /// Directory the signed plugin tarballs live in. Default `plugins` (relative to the working
    /// directory).
    #[serde(default = "default_plugins_dir")]
    pub dir: String,
    /// Trust policy for plugin signatures. busbar's OWN release key is EMBEDDED in the binary —
    /// first-party plugins verify with zero configuration; this block is for THIRD-PARTY keys and
    /// the explicit untrusted opt-ins.
    #[serde(default)]
    pub trust: PluginsTrustCfg,
    /// ANTI-DOWNGRADE floors: plugin canonical `name` -> minimum acceptable `version`. Applies to
    /// first- and third-party alike, and is SEPARATE from the automatic first-party floor (the
    /// per-name high-water mark the registry build maintains, which needs no
    /// configuration). A floored plugin must prove (trusted signature, version at/above the floor)
    /// that it meets the floor; nothing else loads it. Sibling of `trust` (a version axis, not a
    /// trust axis).
    #[serde(default)]
    pub min_versions: std::collections::BTreeMap<String, String>,
    /// RUNTIME-ONLY (never in config, `#[serde(skip)]`): PER-PLUGIN FIRST-PARTY anti-downgrade floor
    /// OVERRIDES for EXPLICIT operator rollbacks (1.5.0). Empty (the default, and the ONLY value the
    /// automatic boot/reload path ever sees) = every first-party plugin faces its own automatic
    /// floor, the per-name HIGH-WATER MARK (the highest version of that name this deployment has
    /// seen and loaded, kept by the registry build). An explicit, audited `POST /plugins/rollback` of a
    /// FIRST-PARTY plugin adds a `name -> pinned target version` entry so the trust evaluation
    /// admits the prior artifact for THAT NAME ONLY (an unpinned first-party plugin still faces the full
    /// floor — replacing the earlier single global floor). Derived from the persisted
    /// `plugin_versions` pins during a rebuild (`overlay::apply_plugin_versions_to_deploy`); it is
    /// never deserialized, so config parsing + `deny_unknown_fields` are unchanged.
    #[serde(skip)]
    pub first_party_floors: std::collections::BTreeMap<String, String>,
    /// Declarative plugin FETCH list (`plugins.fetch:`): tarballs busbar downloads into `dir` at
    /// boot (fatal-on-miss) and on `POST /plugins/reload` (warn-on-miss) BEFORE preflight. Each entry
    /// is a github release ref, a direct url, or an env var holding one — optionally sha256-pinned
    /// (integrity + download-skip cache key). NOT consulted by `--validate` (zero-network contract).
    /// Signature verification remains the trust gate; sha256 is integrity/cache only. Default empty.
    #[serde(default)]
    pub fetch: Vec<PluginFetch>,
    /// PLUGIN LOGS (`plugins.logs:`): every plugin instance logs to its own file, which the host
    /// writes from what the plugin reported on its replies (`BUSBAR-1.6.0.md` decision #85).
    #[serde(default)]
    pub logs: PluginLogsCfg,
}

/// `plugins.logs:` — `dir` (default `logs/plugins`), `level` (default `info`), per-instance
/// `levels`, `rotate_mb` (unset: never rotate; the host's rename rotation) and `keep` (default 5).
/// Every default and every refusal is the plugin log configuration's own; the binary resolves this
/// block at boot, so a bad value fails the boot naming its key.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct PluginLogsCfg {
    pub dir: Option<String>,
    pub level: Option<String>,
    #[serde(default)]
    pub levels: std::collections::BTreeMap<String, String>,
    pub rotate_mb: Option<u64>,
    pub keep: Option<u32>,
}

/// One `plugins.fetch:` entry — an UNTAGGED enum discriminated by which key is present. `github` is a
/// `org/repo@tag` release ref (asset resolved by the loader); `url` is a direct tarball URL; `env`
/// names an environment variable holding a URL (or `url@sha256`). `sha256` (github/url) is the
/// lowercase-hex integrity pin: it is BOTH the download-skip cache key (a file in `dir` already
/// hashing to it ⇒ no network) and the verify-before-write gate. Per-variant `deny_unknown_fields`
/// so a typo'd key can't be silently reinterpreted as a different variant.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum PluginFetch {
    /// `- { github: "org/repo@v1.2.3", sha256?: "…" }`
    Github(GithubFetch),
    /// `- { url: "https://host/plugin.tar.gz", sha256?: "…" }`
    Url(UrlFetch),
    /// `- { env: "BUSBAR_PLUGIN_URL" }` (the VAR holds a url, or `url@sha256`)
    Env(EnvFetch),
}

/// The `{ github, sha256? }` fetch shape. `deny_unknown_fields` on each variant struct is what gives
/// the untagged enum real typo rejection: an entry with a stray key matches NO variant and errors,
/// rather than being silently reinterpreted.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubFetch {
    pub github: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ url, sha256? }` fetch shape.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UrlFetch {
    pub url: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ env }` fetch shape (the VAR's value is a url, optionally `url@sha256`).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvFetch {
    pub env: String,
}

fn fetch_filename_from_url(url: &str) -> Result<String, String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let path = match path.split_once("://") {
        Some((_, authority_and_path)) => authority_and_path
            .split_once('/')
            .map_or("", |(_, path)| path),
        None => path,
    };
    let base = path.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        let shown = busbar_kernel_egress::trust::net::strip_userinfo(url);
        return Err(format!(
            "plugins.fetch url '{shown}' has no filename (a signed tarball basename is required)"
        ));
    }
    Ok(base.to_string())
}

/// One `plugins.fetch` entry, resolved: the URL, its optional sha256 pin and the tarball filename
/// inside `plugins.dir` it writes to. The composition root's fetch downloads it
/// ([`crate::preflight::PluginsFetch`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchTarget {
    /// The URL.
    pub url: String,
    /// The sha256 pin (hex), if any.
    pub sha256: Option<String>,
    /// The filename inside `plugins.dir`.
    pub filename: String,
}

fn fetch_target_from(f: &PluginFetch) -> Result<FetchTarget, String> {
    match f {
        PluginFetch::Github(g) => {
            let (repo_path, tag) = g.github.split_once('@').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing '@tag')",
                    g.github
                )
            })?;
            let (org, repo) = repo_path.split_once('/').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing 'org/repo')",
                    g.github
                )
            })?;
            if org.is_empty() || repo.is_empty() || tag.is_empty() {
                return Err(format!(
                    "plugins.fetch github '{}' must be a non-empty 'org/repo@tag'",
                    g.github
                ));
            }
            let filename = format!("{repo}.tar.gz");
            let url = format!("https://github.com/{org}/{repo}/releases/download/{tag}/{filename}");
            Ok(FetchTarget {
                url,
                sha256: g.sha256.clone(),
                filename,
            })
        }
        PluginFetch::Url(u) => Ok(FetchTarget {
            url: u.url.clone(),
            sha256: u.sha256.clone(),
            filename: fetch_filename_from_url(&u.url)?,
        }),
        PluginFetch::Env(e) => {
            let raw = std::env::var(&e.env).map_err(|_| {
                format!(
                    "plugins.fetch env '{}' is not set (it must hold a url or 'url@sha256')",
                    e.env
                )
            })?;

            let (url, sha256) = match raw.rsplit_once('@') {
                Some((u, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    (u.to_string(), Some(s.to_string()))
                }
                _ => (raw.clone(), None),
            };
            Ok(FetchTarget {
                filename: fetch_filename_from_url(&url)?,
                url,
                sha256,
            })
        }
    }
}

impl Default for PluginsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_plugins_dir(),
            trust: PluginsTrustCfg::default(),
            min_versions: std::collections::BTreeMap::new(),
            first_party_floors: std::collections::BTreeMap::new(),
            fetch: Vec::new(),
            logs: PluginLogsCfg::default(),
        }
    }
}

/// `plugins.trust` — how the engine treats plugin signatures. A first-party (busbar-signed) plugin
/// verifies against the EMBEDDED release key; a third-party plugin verifies against `publishers`;
/// anything else (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT, logged and
/// SKIPPED (never `dlopen`ed) unless the matching opt-in flag is set.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginsTrustCfg {
    /// THIRD-PARTY allowlist: publishers whose signatures mark a plugin TRUSTED. Each maps a
    /// publisher name to a hex ed25519 public key. The first-party `busbar` key is embedded in the
    /// binary and never configured here.
    #[serde(default)]
    pub publishers: Vec<PluginPublisher>,
    /// EXPLICIT opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default
    /// `false` — an unsigned plugin found in `plugins.dir` is LOGGED and SKIPPED (never `dlopen`ed
    /// / executed), at boot and in the admin catalog.
    #[serde(default)]
    pub allow_unsigned: bool,
    /// EXPLICIT opt-in: load plugins that ARE validly signed but by a publisher NOT in
    /// `publishers`. Default `false` — a third-party-signed plugin is LOGGED and SKIPPED.
    #[serde(default)]
    pub allow_third_party: bool,
}

/// One allowlisted plugin publisher: a name and its hex ed25519 public key.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginPublisher {
    pub name: String,
    pub public_key: String,
}

impl PluginsCfg {
    pub fn fetch_targets(&self) -> Result<Vec<FetchTarget>, String> {
        self.fetch.iter().map(fetch_target_from).collect()
    }

    pub fn publisher_keys(&self) -> Vec<(&str, &str)> {
        self.trust
            .publishers
            .iter()
            .map(|p| (p.name.as_str(), p.public_key.as_str()))
            .collect()
    }

    pub fn warn_invalid_floors(&self) {
        for (name, floor) in &self.min_versions {
            if !floor.is_empty() && !busbar_contract::plugin::valid_semver(floor) {
                diag_warn!(
                    CONFIG_ANTIDOWNGRADE_FLOOR_INVALID,
                    key = %format!("plugins.min_versions['{name}']"),
                    value = %floor,
                    "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                     'v'); it cannot be satisfied, so this plugin will be refused. Fix or remove \
                     the entry."
                );
            }
        }
        for (name, floor) in &self.first_party_floors {
            if !floor.is_empty() && !busbar_contract::plugin::valid_semver(floor) {
                diag_warn!(
                    CONFIG_FIRSTPARTY_FLOOR_INVALID,
                    key = %format!("plugins.first_party_floors['{name}']"),
                    value = %floor,
                    "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                     'v'); it cannot be satisfied, so this plugin will be refused — and this pin \
                     REPLACES the binary-version floor, so the plugin is refused unconditionally \
                     until this is fixed. Fix or remove the entry."
                );
            }
        }
    }
}

pub use busbar_kernel::config::sections::{
    migrated_store_module, store_required, SecretModuleCfg, StoreCfg,
};

pub use busbar_kernel::config::sections::{
    default_response_headers_route_policy, default_response_headers_server_timing, AdvancedCfg,
    ResponseHeadersCfg, DEFAULT_RESPONSE_HEADERS_ROUTE_POLICY,
    DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
};

pub use busbar_kernel::config::sections::{
    rate_entry_per_mtok, ConfigMgmtCfg, ExportDefCfg, ExportDefs, OverlayBackend, OverlayCfg,
    RateEntryCfg,
};

fn default_per_request_fee() -> i64 {
    0
}

/// The RESOLVED `export:` block: the typed, per-module projection [`resolve_export`] lowers the named
/// definition map into, and the shape every runtime consumer reads. NOT deserialized from YAML (the
/// on-disk shape is [`ExportDefs`]).
///
/// Every module is served by a sink on the export AXIS (a plugin, compiled in or dropped in), so
/// every instance is one of [`ExportCfg::plugins`]. The scrape sink is at most ONE — it owns the
/// single well-known `/metrics` route, so a second instance could not do anything except silently
/// lose — and a second instance of its module is a loud boot error, never a silent no-op; a sink
/// that refuses a second instance of its own module does so through its checks.
///
/// Each sink's settings carry that instance's resolved [`crate::export::projection::Projection`] —
/// the streams + fields THAT sink is granted. Core builds every payload TO that projection, so an
/// ungranted field is never serialized and never crosses the ABI.
#[derive(Debug, Clone, Default)]
pub struct ExportCfg {
    /// The RECORDER's settings, read off the SCRAPE SINK's instance (see
    /// [`PluginExportSettings::scrape`]), if one is configured. `None` ⇒ no recorder installed,
    /// `/metrics` not mounted, every emit site a true no-op (the zero-config default).
    pub recorder: Option<PrometheusSettings>,
    /// Every instance whose `module:` names an export module registered on the EXPORT AXIS
    /// ([`crate::export::plugin::register_module`]) — a plugin sink, compiled in or dropped in — in
    /// config order. Opened once at boot ([`crate::export::plugin::open`]).
    pub plugins: Vec<PluginExportSettings>,
}

/// One `export:` instance served by a module on the export axis: its name, its definition as the
/// operator wrote it (the `settings:` bag is the plugin's to read), and its projection resolved at
/// CONFIG time. That projection is provisional — the sink's declared streams are known only once it
/// is opened, where the projection is resolved again against them — and it is what the union's
/// compute gate reads.
#[derive(Debug, Clone)]
pub struct PluginExportSettings {
    /// The instance name (`export.<name>`).
    pub name: String,
    /// The instance's definition.
    pub def: ExportDefCfg,
    pub(crate) projection: crate::export::projection::Projection,
    /// THE SCRAPE SINK: this instance's sink is granted first-party (linked, or signed by the release
    /// key), carries the `metrics` stream, and the instance subscribes to it — the host serves the well-known `/metrics` (it holds the recorder) and has
    /// this sink render the recorder's snapshot (`crate::export::scrape`). At most one instance.
    pub(crate) scrape: bool,
}

impl ExportCfg {
    pub(crate) fn projection_union(&self) -> crate::export::projection::ProjectionUnion {
        crate::export::projection::ProjectionUnion::of(self.plugins.iter().map(|s| &s.projection))
    }
}

impl From<&ExportCfg> for busbar_kernel::config::limits::ExportLimits {
    fn from(export: &ExportCfg) -> Self {
        let key_gauge_limit = export
            .recorder
            .as_ref()
            .map_or_else(default_key_gauge_limit, |p| p.key_gauge_limit);
        Self { key_gauge_limit }
    }
}

/// `settings:` of an `export.<name>.module: prometheus` instance — relocated from the retired
/// `observability.metrics` block. They are the RECORDER's settings (the host holds the recorder):
/// the sink validates them as it validates its instance, and the host reads them off the scrape
/// sink's instance ([`ExportCfg::recorder`]).
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrometheusSettings {
    /// Retention window (SECONDS) for the rolling quantile summary — REQUIRED, exactly as the retired
    /// `observability.metrics.buffer_seconds` was (turning metrics on is a deliberate choice + a
    /// memory cost the operator names).
    pub buffer_seconds: u64,
    #[serde(default = "default_key_gauge_limit")]
    pub key_gauge_limit: usize,
}

pub fn resolve_export(defs: &ExportDefs, errors: &mut Vec<String>) -> ExportCfg {
    let mut out = ExportCfg::default();

    let mut seen_once: Vec<&str> = Vec::new();
    let mut refused: Vec<&str> = Vec::new();

    for (name, def) in defs {
        let settings = serde_json::Value::Object(def.settings.clone());
        let module = def.module.trim();

        let axis = crate::export::plugin::probe(name, module, &def.settings);
        let declared = axis.as_ref().and_then(|(streams, _)| streams.as_deref());
        let projection = crate::export::projection::resolve_projection(
            name,
            module,
            declared,
            def.streams.as_deref(),
            def.fields.as_deref(),
            def.durable,
            errors,
        );

        if crate::export::plugin::one_instance(module) {
            if seen_once.contains(&module) {
                if !refused.contains(&module) {
                    refused.push(module);
                    let instances: Vec<(String, serde_json::Value)> = defs
                        .iter()
                        .filter(|(_, d)| d.module.trim() == module)
                        .map(|(n, d)| (n.clone(), serde_json::Value::Object(d.settings.clone())))
                        .collect();
                    errors.extend(crate::export::plugin::check_one_instance(
                        module, &instances,
                    ));
                }
                continue;
            }
            seen_once.push(module);
        }
        let first_party = axis
            .as_ref()
            .is_some_and(|_| crate::export::plugin::first_party(module));
        let (scrape, recorder) = crate::export::plugin::scrape_instance(
            projection,
            declared,
            first_party,
            out.plugins.iter().any(|p| p.scrape),
            settings,
        );
        if let Some(instance) = crate::export::plugin::configured_instance(
            name,
            def,
            projection,
            axis.map(|(_, problems)| problems),
            scrape,
            crate::export::plugin::linked_modules,
            errors,
        ) {
            if scrape {
                out.recorder = recorder;
            }
            out.plugins.push(instance);
        }
    }
    out
}

pub use busbar_kernel::config::limits::{
    default_default_max_tokens, default_hard_down_cooldown_secs, default_hook_content_max_bytes,
    default_key_gauge_limit, default_max_auto_provisioned_groups,
    default_max_honored_retry_after_secs, default_max_inbound_concurrent,
    default_max_keys_per_principal, default_pool_idle_timeout_secs, default_pool_max_idle_per_host,
    default_probe_interval_secs, default_probe_timeout_secs, default_rate_sweep_interval,
    default_reasoning_high, default_reasoning_low, default_reasoning_medium,
    default_reasoning_minimal, default_request_body_max_bytes,
    default_request_body_read_timeout_secs, default_tls_handshake_timeout_secs,
    default_upstream_error_body_max_bytes, default_upstream_request_timeout_secs,
    default_usage_flush_interval_ms, ExportLimits, HealthDefaultsCfg, LimitsCfg, LimitsResolved,
    ReasoningEffortBudgets, RoutingCfg, DEFAULT_DEFAULT_MAX_TOKENS,
    DEFAULT_HARD_DOWN_COOLDOWN_SECS, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
    DEFAULT_MAX_INBOUND_CONCURRENT, DEFAULT_PLUGIN_FETCH_MAX_BYTES, DEFAULT_POOL_IDLE_TIMEOUT_SECS,
    DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_PROBE_INTERVAL_SECS, DEFAULT_PROBE_TIMEOUT_SECS,
    DEFAULT_RATE_SWEEP_INTERVAL, DEFAULT_REQUEST_BODY_MAX_BYTES,
    DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS, DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS,
    DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES, DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
    DEFAULT_USAGE_FLUSH_INTERVAL_MS, REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR,
};

fn default_plugins_dir() -> String {
    "plugins".to_string()
}

fn hook_cfg_from_def(def: &HookDefCfg) -> Result<HookCfg, String> {
    let plugin = def.module.trim().to_string();
    if plugin.is_empty() {
        return Err(
            "a hook definition must name a non-empty `module:` (a `kind: hook` plugin)".to_string(),
        );
    }
    Ok(HookCfg {
        kind: def.kind.unwrap_or(HookKind::Gate),
        plugin,
        timeout_ms: def.timeout_ms.unwrap_or(DEFAULT_POLICY_TIMEOUT_MS),
        on_error: def
            .on_error
            .as_ref()
            .map(|o| o.as_name().to_string())
            .unwrap_or_else(default_on_error),
        prompt: def.prompt.unwrap_or_default(),
        user: def.user.unwrap_or_default(),
        priority: def.priority.unwrap_or(0),

        at: None,
        on_empty: def.on_empty.clone(),
        settings: def.settings.clone(),

        signals: Vec::new(),
        global: false,
        default: false,
        groups: def.groups.clone(),
        phase: def.phase.clone(),
    })
}

pub fn merge_provider_fallback(def: &ProviderDef, deploy_cfg: &ProviderDeploy) -> ResolvedProvider {
    ResolvedProvider::merge(def, deploy_cfg)
}

#[cold]
#[inline(never)]
pub fn resolve(
    deploy: &DeployCfg,
    defs: &HashMap<String, ProviderDef>,
) -> Result<RootCfg, Vec<String>> {
    let mut errors = Vec::new();

    let export = resolve_export(&deploy.export, &mut errors);

    let mut resolved_providers: HashMap<String, ResolvedProvider> = HashMap::new();

    let resolve_provider_hook = crate::plane_driver::registry::plane_decl_for(
        crate::plane_driver::dispatch::fallback_key(),
    )
    .and_then(|d| d.resolve_provider);

    let mut catalog_names: Vec<&String> = defs.keys().collect();
    catalog_names.sort();
    for name in catalog_names {
        let judged = if deploy.providers.is_empty() {
            providers::judge_unused_catalog_entry(name, &defs[name])
        } else {
            providers::judge_catalog_entry(name, &defs[name])
        };
        if let Err(refusal) = judged {
            errors.push(format!("providers.yaml: {refusal}"));
        }
    }

    for (deploy_name, deploy_cfg) in &deploy.providers {
        let Some(def) = defs.get(deploy_name) else {
            errors.push(format!(
                "provider '{}' referenced in config.yaml not found in providers.yaml",
                deploy_name
            ));
            continue;
        };

        let merged = match resolve_provider_hook {
            Some(f) => f(def, deploy_cfg),
            None => merge_provider_fallback(def, deploy_cfg),
        };
        resolved_providers.insert(deploy_name.clone(), merged);
    }

    let mut hooks_registry: HashMap<String, HookCfg> = HashMap::new();
    let mut pools = deploy.pools.pools.clone();

    for pool in pools.values_mut() {
        pool.gates = entity_only_hook_refs(&deploy.pools.all_pool_hooks, &pool.gates);
    }

    let mut plane_pools: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, pools::CandidatePoolCfg>,
    > = std::collections::BTreeMap::new();
    for (&section, written) in &deploy.declared_raw {
        let Some(stated) = written
            .get(busbar_contract::section::RESERVED_POOLS_KEY)
            .filter(|v| !v.is_null())
        else {
            continue;
        };
        match serde_yaml::from_value::<std::collections::BTreeMap<String, pools::CandidatePoolCfg>>(
            stated.clone(),
        ) {
            Ok(stated) => {
                plane_pools.insert(section, stated);
            }
            Err(e) => errors.push(format!(
                "{section}.{}: {e}",
                busbar_contract::section::RESERVED_POOLS_KEY
            )),
        }
    }

    for pool in pools.values_mut() {
        for m in pool.members.iter_mut() {
            if let Some(&w) = pool.weights.get(&m.model) {
                if m.weight == default_weight() {
                    m.weight = w;
                }
            }
            if m.tier.is_none() {
                m.tier = pool.tier.clone();
            }
            if m.attempt_timeout_ms.is_none() {
                m.attempt_timeout_ms = pool.attempt_timeout_ms;
            }
        }
    }

    for (&section, pools) in &plane_pools {
        let at = format!("{section}.{}", busbar_contract::section::RESERVED_POOLS_KEY);
        let this = deploy.plane_section(section);
        let on_this_plane = |m: &str| this.is_some_and(|c| c.contains_def(m));
        let elsewhere = |m: &str| -> Option<&'static str> {
            deploy
                .declared
                .0
                .iter()
                .find(|(s, c)| **s != section && c.contains_def(m))
                .map(|(s, _)| *s)
        };
        for (pool, def) in pools {
            check_failover_pool(
                &mut errors,
                &at,
                pool,
                def,
                on_this_plane,
                elsewhere,
                section,
            );
        }

        let mut owner: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for (pool, def) in pools {
            for member in &def.members {
                if let Some(first) = owner.insert(member.as_str(), pool.as_str()) {
                    if first != pool.as_str() {
                        errors.push(format!(
                            "{at}: `{member}` is a member of both `{first}` and `{pool}`. A \
                             registration belongs to at most ONE failover pool — its learned \
                             health lives in that pool's breaker cells, and two pools would keep \
                             two contradictory histories for one upstream."
                        ));
                    }
                }
            }
        }
    }
    for (name, def) in &deploy.hooks {
        if is_reserved_hook_name(name) {
            errors.push(format!(
                "hooks.{name}: '{name}' is a reserved name (an on_error terminal, built-in ranking \
                 strategy, or built-in auth module) and cannot name a hook definition"
            ));
            continue;
        }
        match hook_cfg_from_def(def) {
            Ok(cfg) => {
                hooks_registry.insert(name.clone(), cfg);
            }
            Err(e) => errors.push(format!("hooks.{name}: {e}")),
        }
    }

    let global_hook_names: Vec<String> = deploy.pools.all_pool_hooks.clone();

    let raw_judged: Vec<(
        &'static str,
        Box<dyn crate::config::plane_sections::PlaneCfg>,
    )> = deploy
        .plane_raw
        .iter()
        .filter(|(_, v)| !v.is_null())
        .filter_map(|(&section, value)| {
            let decl = crate::plane_driver::registry::plane_decls()
                .iter()
                .find(|d| d.config_section == section)?;
            let parse = decl.parse_section?;
            parse(decl, value)
                .map_err(|e| errors.push(format!("`{section}:` is not valid: {e}")))
                .ok()
                .map(|cfg| (section, cfg))
        })
        .collect();
    let judged = deploy
        .declared
        .0
        .iter()
        .map(|(s, c)| (*s, c))
        .chain(raw_judged.iter().map(|(s, c)| (*s, c)));
    for (section, cfg) in judged {
        let g = cfg.container_gates();

        if let Err(e) = crate::config::plane_sections::validate_section_hooks(
            &format!("`{section}.hooks`"),
            &g.section_hooks,
            &crate::config::plane_sections::config_sections(),
        ) {
            errors.push(e);
        }
        for hook in &g.section_hooks {
            if !deploy.hooks.contains_key(hook) {
                errors.push(format!(
                    "{section}.hooks: names `{hook}`, which is not defined in the top-level `hooks:` \
                     map. Define it there, or remove the reference."
                ));
            }
        }

        for (entry, hooks) in &g.containers {
            for hook in hooks {
                if !deploy.hooks.contains_key(hook) {
                    errors.push(format!(
                        "{section}.{entry}: `hooks:` names `{hook}`, which is not defined in the \
                         top-level `hooks:` map. Define it there, or remove the reference."
                    ));
                }
            }
        }
    }

    let declared = deploy
        .declared
        .0
        .values()
        .chain(raw_judged.iter().map(|(_, c)| c))
        .map(AsRef::as_ref);
    for section in declared {
        for (path, provider_name) in section.model_provider_refs() {
            match resolved_providers.get(&provider_name) {
                None => {
                    let mut names: Vec<&str> =
                        resolved_providers.keys().map(String::as_str).collect();
                    names.sort_unstable();
                    errors.push(format!(
                        "{path} names '{provider_name}', which is not defined in the top-level \
                         `providers:` map. Valid providers: {}. Define it there, or fix the \
                         reference.",
                        if names.is_empty() {
                            "(none configured)".to_string()
                        } else {
                            names.join(", ")
                        }
                    ));
                }
                Some(p) => {
                    if let Some(known) = section.known_dialects() {
                        if !known.contains(&p.dialect()) {
                            errors.push(format!(
                                "{path} '{provider_name}' resolves to protocol '{}', but this plane \
                                 speaks only: {}. Point it at a provider whose protocol resolves to \
                                 one of those, or remove the reference.",
                                p.dialect(),
                                known.join(", ")
                            ));
                        }
                    }
                }
            }
        }
    }

    for cfg in deploy.declared.0.values() {
        if let Err(e) = cfg.validate_registry() {
            errors.push(e);
        }
    }

    let mut plane_sections = std::collections::BTreeSet::new();
    for (section, present) in deploy.declared.0.iter().map(|(s, c)| (*s, c.is_present())) {
        if present {
            plane_sections.insert(section);
        }
    }

    {
        let admin_listen = &deploy.admin_listen;
        let exposed = !bind_is_loopback(admin_listen);
        let has_client_mtls = deploy
            .admin_tls
            .as_ref()
            .is_some_and(|t| t.client_ca.is_some());
        if exposed && !has_client_mtls && deploy.admin_require_mtls {
            errors.push(format!(
                "admin_listen '{admin_listen}' is network-exposed but the admin plane has no mTLS \
                 (admin_tls.client_ca is unset). Require client certificates by supplying \
                 admin_tls.client_ca, bind admin_listen to loopback, or set admin_require_mtls: \
                 false to deliberately run a token-only admin plane (e.g. behind a mesh)."
            ));
        }
    }

    let resolved_auth = deploy
        .auth
        .as_ref()
        .map(|a| resolve_auth(a, &deploy.identity_providers, &mut errors));
    let admin_auth_names: Vec<String> = resolved_auth.as_ref().map_or_else(
        || {
            default_admin_auth()
                .iter()
                .map(|e| e.name.clone())
                .collect()
        },
        |a| a.admin_auth.iter().map(|e| e.name.clone()).collect(),
    );

    let endpoint_block = deploy.endpoint.0.as_ref();

    let endpoint_section = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
    let lower = crate::plane_driver::registry::plane_decl_for_config_section(endpoint_section)
        .and_then(|d| d.lower_endpoint);

    if endpoint_block.is_some_and(|ep| ep.is_present()) {
        plane_sections.insert(endpoint_section);
    }
    let lowered_endpoint = endpoint_block
        .zip(lower)
        .and_then(|(ep, lower)| lower(&**ep).map_err(|e| errors.push(e)).ok());

    let mut endpoint_resources: std::collections::HashMap<_, _> = lowered_endpoint
        .map(|resource| (endpoint_section, resource))
        .into_iter()
        .collect();

    for (&section, value) in deploy.plane_raw.iter().filter(|(_, v)| !v.is_null()) {
        plane_sections.insert(section);
        endpoint_resources.insert(section, std::sync::Arc::new((section, value.clone())));
    }

    let oauth_as = deploy
        .oauth_as
        .clone()
        .filter(|block| !block.is_null())
        .and_then(|block| {
            let Some(seam) = crate::oauth_as::seam::seam() else {
                errors.push(
                    "oauth_as: configured, but the authorization-server plane (busbar-core-oauth2) \
                     is not linked into this binary"
                        .to_string(),
                );
                return None;
            };
            match (seam.check)(&block) {
                Ok(secret_refs) => {
                    Some(crate::oauth_as::seam::CheckedAsBlock { block, secret_refs })
                }
                Err(e) => {
                    errors.push(e);
                    None
                }
            }
        });

    if errors.is_empty() {
        let security = deploy.security.clone().unwrap_or_default();
        Ok(RootCfg {
            listen: deploy.listen.clone(),
            public_url: deploy.public_url.clone(),
            endpoint_resources,
            oauth_as,
            credentials: deploy.credentials.clone(),
            plane_defs: deploy
                .declared
                .0
                .iter()
                .map(|(s, c)| (*s, c.clone_box()))
                .collect(),
            plane_pools,
            tls: deploy.tls.clone(),
            admin_listen: deploy.admin_listen.clone(),
            admin_tls: deploy.admin_tls.clone(),
            auth: resolved_auth,
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools,
            upstream_credentials: deploy
                .pools
                .all_pool_upstream_credentials
                .unwrap_or_default(),
            hooks: hooks_registry,

            admin_auth: admin_auth_names,
            groups: deploy.groups.clone(),
            rate_card: compose_plane_cards(deploy.rate_card.as_ref(), &deploy.plane_rate_cards),
            per_request_fee: deploy.per_request_fee,
            plane_fees: deploy.plane_fees.clone(),
            store: deploy.store.clone(),
            secrets: deploy.secrets.clone(),
            global_hooks: global_hook_names,
            blocked_metadata_hosts: security.blocked_metadata_hosts,
            allow_metadata_hosts: security.allow_metadata_hosts,
            allow_all_metadata: security.allow_all_metadata,
            guard: Destinations {
                block_private_addresses: deploy.advanced.block_private_addresses,
                allow: deploy.advanced.allow_destinations.clone(),
                ..Destinations::default()
            },

            limits: LimitsResolved::from_sections(
                &deploy.limits,
                &deploy.advanced,
                &export,
                &deploy.health,
                &deploy.routing,
            ),
            export,
            identity_providers: deploy.identity_providers.clone(),
            export_defs: deploy.export.clone(),
            plane_sections,
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/advanced_destinations_tests.rs"]
mod advanced_destinations_tests;

#[cfg(test)]
#[path = "tests/config_backcompat_corpus.rs"]
mod config_backcompat_corpus;

#[cfg(test)]
#[path = "tests/provider_refusal_pins.rs"]
mod provider_refusal_pins;

#[cfg(test)]
#[path = "tests/resolved_provider_tests.rs"]
mod resolved_provider_tests;

#[cfg(test)]
#[path = "tests/provider_debug_redaction_tests.rs"]
mod provider_debug_redaction_tests;

pub mod auth;
pub mod credentials;
pub mod hooks;
pub mod limits;
pub mod plane_sections;
pub mod pools;
pub mod providers;
pub mod sections;

/// A resolved on_error/on_empty TERMINAL. `Weighted` (default) is the non-negotiable safety
/// stance: a broken/slow policy is indistinguishable from no policy and NEVER blocks or fails a
/// request. `Reject` is fail-closed (503). `First` uses the configured member order (a
/// deterministic degraded pick). The `on_error` CONFIG field is a free string (a fallback chain of
/// hook names bottoming out on one of these three reserved terminals); `on_empty` parses this enum
/// directly.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOnError {
    #[default]
    Weighted,
    Reject,
    First,
}

pub use providers::ProviderAuth;

#[cfg(test)]
#[path = "tests/config_boundary_tests.rs"]
mod config_boundary_tests;

mod provider_grammar;
