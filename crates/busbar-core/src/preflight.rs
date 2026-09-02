//! PLUGIN + SECRET PREFLIGHT — the boot-order half of app construction: load and verify the
//! plugin registry, resolve the admin token and the signing key, validate every secret reference
//! against the modules that can serve it, and build the `SecretResolver`. Split from `appbuild`
//! along the call order (preflight runs first; the App builder consumes its outputs), and kept
//! whole because every fn here is one refusal surface: a plugin or secret that cannot resolve is
//! a boot error naming its source, never a warning.

use std::sync::Arc;

use crate::diagnostics::{diag_warn, PLUGIN_LOADED_UNVERIFIED, PLUGIN_SKIPPED_TRUST_POLICY};

#[allow(unused_imports)]
use crate::{
    admin, audit, auth, auth_cache, billing, breaker, catalogue, config, config_validate,
    core_routes, cost, durable, egress_auth, endpoints, eventstream, export, failover, governance,
    handlers, hooks, ingress, ir, json, limits, lossless, media, metrics, net_guard, oauth_as,
    observability, operation, plane, plugin_routes, profile, proto, proxy, sigv4, state, store,
    telemetry, tls, transport, trust,
};

/// Build a complete `App` from a RESOLVED config — the ONE construction path shared by boot
/// (`prior = None`) and the config plane's apply/reload (`prior = Some(current)`). On apply,
/// process-lifetime state is REUSED from the prior snapshot (HTTP client pool, governance key DB,
/// version history, mutation-rate windows) and the health store is rebuilt with every surviving
/// lane's learned state RESTORED BY STABLE IDENTITY — so a lane-set change never
/// misattributes or discards breaker/latency knowledge. Errors are returned (never process-exit):
/// boot maps them to `die`, the apply endpoints to `invalid_request` — an invalid apply changes
/// nothing.
///
/// PLUGIN PRE-FLIGHT — the ONE pipeline shared byte-for-byte by BOOT (`build_app_from_config`),
/// config APPLY/RELOAD, and `busbar --validate`, so the pre-flight gate can never drift from real
/// boot behavior. Fail-closed at every step:
///
/// 1. CONSISTENCY: a non-`memory` `store.module` with `plugins.enabled: false` (or the block
///    absent) is an error NAMING THE FLAG — a dropped-in tarball is inert until the switch is on.
/// 2. POLICY: `plugins.trust` resolves (embedded first-party key + third-party publishers + the
///    explicit opt-ins + anti-downgrade floors); a malformed key is an error.
/// 3. SCAN: when enabled, every tarball in `plugins.dir` runs the three-phase pipeline
///    (structural -> trust -> conflict) via [`busbar_plugin_loader::scan_and_validate`]. ANY
///    invalid tarball/manifest or ANY name/alias conflict aborts with every problem named; an
///    untrusted plugin is SKIPPED (warn-logged, never `dlopen`ed).
/// 4. RESOLUTION: the configured `store.module` (alias OR canonical name, resolved against the
///    manifest registry — never a filename) must resolve to a loadable `kind: store` plugin.
///
/// Returns the validated registry (empty when plugins are disabled and no plugin is referenced).
/// NO plugin code runs in this function (manifest-only; `dlopen` happens later, at store open).
pub fn plugins_preflight(
    store_cfg: Option<&config::StoreCfg>,
    auth_cfg: Option<&config::AuthCfg>,
    identity_providers: &config::IdentityProviders,
    hooks_cfg: &std::collections::HashMap<String, config::HookCfg>,
    plugins_cfg: &config::PluginsCfg,
    export_cfg: &config::ExportCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let store_ref = store_cfg
        .map(|g| g.module.as_str())
        .unwrap_or(config::GOVERNANCE_STORE_MEMORY);
    let store_is_plugin = store_ref != config::GOVERNANCE_STORE_MEMORY;

    // Every non-builtin `auth.chain` module is a `kind: auth` plugin — the same manifest-only
    // pre-flight the store ref gets, so `--validate` catches a missing/wrong-kind/untrusted auth
    // plugin BEFORE boot. `keys` is engine-handled (never a plugin); `test-groups-module` is the
    // compiled-in test stand-in — ONLY actually registered under `#[cfg(test)]`
    // (`AuthMiddleware::new`, `crates/busbar-core/src/auth/mod.rs`), so filtering it out
    // unconditionally here made `--validate`/`config_validate::validate` silently agree a RELEASE
    // config naming it is fine, while real boot still hard-failed (the invariant `--validate`
    // clean => the plugin half of boot succeeds too, documented a few lines below, broke). Gate
    // the exemption the same way the module itself is gated.
    let auth_plugin_refs: Vec<&str> = auth_cfg
        .map(|a| {
            a.chain
                .iter()
                .map(|e| e.module.as_str())
                .filter(|m| is_real_auth_plugin_ref(m, cfg!(any(test, feature = "test-support"))))
                .collect()
        })
        .unwrap_or_default();
    let has_auth_plugin = !auth_plugin_refs.is_empty();

    // Every `identity-providers:` DEFINITION whose `module:` is not a built-in is likewise a
    // `kind: auth` plugin reference — checked here over the DEFINITION map rather than over the
    // resolved chain, because that is the only layer that sees an UNREFERENCED definition.
    // `resolve_auth` is keyed off `auth.chain:`/`auth.admin_auth:`, and `AuthCfg.methods` only
    // exists at all when an `auth:` block does, so a provider defined through
    // `PUT /identity-providers/{name}` and not yet referenced was validated by NOTHING: the API
    // answered 200 and stored a `module:` that can never authenticate anyone. `export:` has had the
    // equivalent check since 1.5.3 (`resolve_export` refuses an unknown exporter and names the
    // built-ins); it just needed no registry, because the export vocabulary is a const list.
    // Carries (name, module) pairs so the diagnostics can name the offending DEFINITION, not only
    // the module string — two providers can share one typo'd module.
    let idp_plugin_refs: Vec<(&str, &str)> = identity_providers
        .iter()
        .map(|(name, def)| (name.as_str(), def.module.trim()))
        // An EMPTY module is `resolve_auth`'s rule ("must be a non-empty module name"), reported
        // there in its own words; do not shadow it with a less specific "no such plugin".
        .filter(|(_, m)| !m.is_empty() && is_real_identity_provider_plugin_ref(m, cfg!(test)))
        .collect();
    let idp_refs_human = |refs: &[(&str, &str)]| {
        refs.iter()
            .map(|(n, m)| format!("identity-providers.{n} (module '{m}')"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Every hook references a `kind: hook` plugin — the same manifest-only pre-flight the store/auth
    // refs get. Deduped for the messages, but validated as the set of names each hook declares.
    let hook_plugin_refs: Vec<String> = {
        let mut v: Vec<String> = hooks_cfg.values().map(|h| h.plugin.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let has_hook_plugin = !hook_plugin_refs.is_empty();

    // 1. Consistency: referencing a plugin store while the master switch is off is a NAMED error.
    if store_is_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "store.module: '{store_ref}' requires the plugin subsystem, but plugins.enabled is \
             false (the default). Set plugins.enabled: true and place the signed \
             '{store_ref}' store plugin tarball in the plugins directory ('{}'), or set \
             store.module: memory.",
            plugins_cfg.dir
        ));
    }
    // Same consistency gate for an auth plugin: a configured `kind: auth` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-open front door.
    if has_auth_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "auth.chain names plugin module(s) [{}], which require the plugin subsystem, but \
             plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed auth plugin tarball(s) in the plugins directory ('{}').",
            auth_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for a hook plugin: a configured `kind: hook` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-absent gate.
    if has_hook_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "the hooks registry names plugin module(s) [{}], which require the plugin subsystem, \
             but plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed `kind: hook` plugin tarball(s) in the plugins directory ('{}').",
            hook_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for an identity-provider DEFINITION: with the plugin subsystem off the
    // registry is empty by construction, so the only modules that can ever back a provider are the
    // built-ins — naming anything else is a config error today, not a latent one. Ordered AFTER the
    // `auth.chain` gate on purpose: a provider that IS on a chain gets that gate's more specific
    // "auth.chain names plugin module(s)" wording, and this one covers the definitions no chain
    // reaches.
    if !idp_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "{} require(s) the plugin subsystem, but plugins.enabled is false (the default). With \
             plugins off, a provider's `module:` must be one of the built-ins: {}. Set \
             plugins.enabled: true and place the signed `kind: auth` plugin tarball(s) in the \
             plugins directory ('{}'), or name a built-in.",
            idp_refs_human(&idp_plugin_refs),
            config::BUILTIN_IDENTITY_PROVIDERS.join(" | "),
            plugins_cfg.dir
        ));
    }

    // 2. Policy resolution (embedded first-party key + configured third-party trust).
    let policy = plugins_cfg
        .to_policy()
        .map_err(|e| format!("plugins.trust is invalid: {e}"))?;

    // Disabled and nothing referenced: the registry is empty and NOTHING in the directory is even
    // read (drop-is-inert).
    if !plugins_cfg.enabled {
        tracing::info!(
            "plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
        );
        return Ok(busbar_plugin_loader::PluginRegistry::empty());
    }

    // 3. Three-phase scan over the plugins directory. Fail-closed on invalid/conflict.
    let dir = std::path::Path::new(&plugins_cfg.dir);
    let registry = busbar_plugin_loader::scan_and_validate(dir, &policy)
        .map_err(|errs| format!("plugin validation failed:\n  - {}", errs.join("\n  - ")))?;
    tracing::info!(
        dir = %plugins_cfg.dir,
        loadable = registry.loadable().len(),
        skipped = registry.skipped().len(),
        "plugins: enabled"
    );
    for s in registry.skipped() {
        diag_warn!(
            PLUGIN_SKIPPED_TRUST_POLICY,
            plugin = %s.manifest.name,
            file = %s.file,
            reason = %s.reason,
            "plugin present but NOT loaded (trust policy)"
        );
    }
    for p in registry.loadable() {
        match &p.verdict {
            busbar_plugin_sign::Verdict::Trusted {
                publisher,
                first_party,
            } => tracing::info!(
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                version = %p.manifest.version,
                publisher = %publisher,
                first_party,
                "plugin validated"
            ),
            busbar_plugin_sign::Verdict::Allowed { reason, .. } => diag_warn!(
                PLUGIN_LOADED_UNVERIFIED,
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                reason = %reason,
                "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
            ),
        }
    }

    // 4. The configured store must resolve to a loadable store plugin.
    if store_is_plugin {
        match registry.resolve(store_ref) {
            Some(p) if p.manifest.kind == "store" => {}
            Some(p) => {
                return Err(format!(
                    "store.module: '{store_ref}' resolves to plugin '{}' of kind '{}', not a \
                     store plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(store_ref) {
                    Some(s) => format!(
                        "store.module: '{store_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching store.module: '{store_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed tarball actually IN the \
                         folder? Add it to plugins.fetch or drop the signed tarball in the \
                         directory, or set store.module: memory.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 5. Every configured auth-chain plugin must resolve to a loadable `kind: auth` plugin. Same
    // manifest-only resolution as the store ref (no `dlopen` here; the real load happens in
    // `AuthMiddleware::new` at App construction). A missing/wrong-kind/untrusted auth plugin fails
    // `--validate` and boot alike — a typo'd or absent front-door module must never pass silently.
    for auth_ref in &auth_plugin_refs {
        match registry.resolve(auth_ref) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "auth.chain module '{auth_ref}' resolves to plugin '{}' of kind '{}', not an \
                     `auth` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(auth_ref) {
                    Some(s) => format!(
                        "auth.chain module '{auth_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching auth.chain module '{auth_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: auth` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove it from auth.chain.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6. Every hook's `plugin:` ref must resolve to a loadable `kind: hook` plugin. Same manifest-only
    // resolution as store/auth (no `dlopen` here; the real load happens in `resolve_gate_transport` at
    // App construction). A missing/wrong-kind/untrusted hook plugin fails `--validate` and boot alike.
    for hook_ref in &hook_plugin_refs {
        match registry.resolve(hook_ref) {
            Some(p) if p.manifest.kind == "hook" => {}
            Some(p) => {
                return Err(format!(
                    "a hook references plugin '{hook_ref}', which resolves to plugin '{}' of kind \
                     '{}', not a `hook` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(hook_ref) {
                    Some(s) => format!(
                        "a hook references plugin '{hook_ref}', matching plugin '{}' ({}) but it \
                         was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching the hook reference '{hook_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: hook` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove the hook.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6b. Every `identity-providers:` DEFINITION's non-built-in `module:` must resolve to a loadable
    // `kind: auth` plugin — the definition-side counterpart of the `auth.chain` resolution above,
    // and the check that finally covers a provider NO chain references (the admin API's whole write
    // surface). Manifest-only, like its siblings.
    for (name, module) in &idp_plugin_refs {
        match registry.resolve(module) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "identity-providers.{name}.module: '{module}' resolves to plugin '{}' of kind \
                     '{}', not an `auth` plugin. A provider's `module:` must be a built-in or a \
                     `kind: auth` plugin; the modules available right now are: {}.",
                    p.manifest.name,
                    p.manifest.kind,
                    valid_identity_provider_modules(&registry)
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "identity-providers.{name}.module: '{module}' matches plugin '{}' ({}) but \
                         it was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(&registry)
                    ),
                });
            }
        }
    }

    // 7. PLUGIN HTTP ROUTE COLLISION CHECK — MANIFEST-LEVEL, nothing dlopened. Walk every
    // loadable export/hook plugin's DECLARED routes in the SAME deterministic scan order the registry
    // produced, namespace-confine each, and fail LOUD naming the owning plugin on the first
    // {path, method} collision — e.g. `plugin "datadog" cannot register GET /metrics — already
    // registered by "prometheus"`. The IDENTICAL check backs boot and `--validate` (both call this
    // preflight), and the SAME confinement + first-to-claim logic backs the live table built at App
    // construction (`plugin_routes::build_route_table`), so the manifest check and what actually mounts
    // cannot diverge. Route declarations are read straight from each signed manifest; a plugin that
    // declares none contributes nothing (today's manifests carry no routes, so the set is empty until
    // the export/hook route-manifest field lands — the wiring is here so that is a data change, not a
    // control-flow one).
    let route_owners: Vec<(String, crate::plugin_routes::RouteKind)> = registry
        .loadable()
        .iter()
        .filter_map(|p| match p.manifest.kind.as_str() {
            "export" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Export,
            )),
            "hook" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Hook,
            )),
            _ => None,
        })
        .collect();
    let mut route_decls: Vec<(
        String,
        crate::plugin_routes::RouteKind,
        busbar_plugin_loader::Route,
    )> = route_owners
        .into_iter()
        .flat_map(|(name, kind)| {
            // A plugin's DECLARED routes are read straight from its signed manifest. The manifest
            // route field is not yet defined, so this yields nothing today; when it lands, map each
            // declared route to `(name, kind, route)` HERE — the confinement + collision logic is
            // already wired and tested.
            Vec::<busbar_plugin_loader::Route>::new()
                .into_iter()
                .map(move |r| (name.clone(), kind, r))
        })
        .collect();
    // The BUILT-IN exporters (`crate::export`) also claim routes (the `prometheus` exporter's
    // `GET /metrics`). Prepend them in the SAME collision set so a loaded third-party export/hook
    // plugin that tries to claim a path a built-in already owns fails LOUD at `--validate`/boot, e.g.
    // `plugin "datadog" cannot register GET /metrics — already registered by "prometheus"`.
    let mut built_in = crate::export::route_owners(export_cfg);
    built_in.append(&mut route_decls);
    let route_decls = built_in;
    crate::plugin_routes::preflight_route_collisions(&route_decls)
        .map_err(|e| format!("plugin route registration conflict: {e}"))?;

    Ok(registry)
}

/// Resolve the operator ADMIN credential — the `admin-tokens` chain entry's `token:` secret ref —
/// with the BLANK-TOKEN guard. Shared by boot and the apply/reload path so the two cannot drift.
///
/// FAIL-CLOSED twice over:
/// * an unresolvable ref refuses boot/apply (a silently-absent token would lock the admin API
///   while the operator believes it is guarded);
/// * a ref that resolves to EMPTY or ALL-WHITESPACE is refused too. The
///   documented boot guard for this had been lost in the move to secret refs, and the consequence
///   is worse than the docs described: the digest is computed over the blank string, so
///   `admin_token_hash` is `Some(sha256(""))` — a REAL credential that an `Authorization: Bearer `
///   with an empty value satisfies. An env var that expanded to nothing would silently hand the
///   whole admin surface to an unauthenticated caller.
pub(crate) fn resolve_admin_token(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<busbar_api::Redacted<String>>, String> {
    let Some(r) = auth.and_then(|a| a.admin_token_ref()) else {
        return Ok(None);
    };
    let token = resolver
        .resolve_string(r)
        .map_err(|e| format!("auth.admin_auth admin-tokens token did not resolve: {e}"))?;
    if token.trim().is_empty() {
        return Err(
            "auth.admin_auth admin-tokens `token:` resolved to an EMPTY/whitespace-only value. \
             Refusing to start: the digest would be taken over the blank string, so an empty \
             credential would authenticate as the operator. Check the referenced env var / file \
             actually holds the token, or remove the `token:` to disable the admin API deliberately."
                .to_string(),
        );
    }
    Ok(Some(busbar_api::Redacted::new(token)))
}

/// Parse resolved bytes into a 32-byte ed25519 secret: accept RAW 32 bytes or 64 hex chars. Shared
/// by the signing-key resolver and the `--generate-signing-key` self-check.
pub(crate) fn parse_signing_secret(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 {
            if let Ok(v) = hex::decode(s) {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                return Ok(out);
            }
        }
    }
    Err(
        "auth.signing_key must resolve to a 32-byte ed25519 secret key (raw 32 bytes or 64 hex \
         characters)"
            .to_string(),
    )
}

/// Resolve the KEY-SIGNING key. `auth.signing_key` is a reference to an EXISTING secret
/// (env/file/plugin) resolving to the ed25519 secret material (32 raw bytes, or 64 hex chars) busbar
/// mints + verifies virtual-key tokens with. Fleet-shared: every node resolves the SAME secret so
/// they verify each other's tokens.
///
/// 1.5.1 BREAKING CHANGE: busbar NO LONGER auto-generates and persists a signing key at boot (the
/// 1.5.0 behavior wrote `busbar-signing.key` beside the config, which boot-looped a read-only config
/// mount with a misleading Permission-denied). When `auth.signing_key` is absent this returns `None`;
/// `config_validate` fails CLOSED at `--validate`/boot if the deployment actually uses signed-token
/// auth (the `keys` verifier in the chain), and the mint path fails closed with a clear message
/// otherwise. Generate a key with `busbar --generate-signing-key`.
///
/// FAIL-CLOSED: a configured-but-unresolvable / malformed signing key refuses boot.
pub(crate) fn resolve_signing_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<governance::signing::TokenSigner>, String> {
    use governance::signing::{TokenSigner, DEFAULT_KID};

    let Some(sk) = auth.and_then(|a| a.signing_key.as_ref()) else {
        // No configured key: busbar does not generate one (1.5.1). A deployment that verifies
        // busbar-signed keys is REQUIRED to provide it (enforced fail-closed by config_validate);
        // one that never issues signed tokens simply has no signer.
        return Ok(None);
    };
    let bytes = resolver.resolve(sk).map_err(|e| {
        format!(
            "auth.signing_key did not resolve: {e}. auth.signing_key is a reference to an EXISTING \
             secret (env/file/plugin) - it does NOT generate a key. Provide the key first (a \
             32-byte raw or 64-hex-char ed25519 secret: `busbar --generate-signing-key`, or \
             `openssl rand -hex 32`), or OMIT auth.signing_key entirely if this deployment never \
             issues busbar-signed keys."
        )
    })?;
    let secret = parse_signing_secret(&bytes)?;
    Ok(Some(TokenSigner::from_secret_bytes(&secret, DEFAULT_KID)))
}

/// Validate ONE `secrets:` block key against the plugin registry and return the plugin's CANONICAL
/// name. Fail-closed (an `Err`) when the key names a reserved built-in resolver (`env`/`file`, which
/// take no module-level config), when no loadable plugin is named or aliased by it, or when the
/// resolved plugin is not `kind: secret`. Shared by `build_secret_resolver` (boot) and the
/// `--validate` pre-flight so both apply the identical policy (a mistyped/aliased
/// `secrets:` key must never silently open a plugin with `{}`).
pub(crate) fn validate_secret_module(
    registry: &busbar_plugin_loader::PluginRegistry,
    module: &str,
) -> Result<String, String> {
    if module == config::secret::SECRET_MODULE_ENV || module == config::secret::SECRET_MODULE_FILE {
        return Err(format!(
            "secrets.{module}: '{module}' is a built-in secret resolver, not a plugin; it takes no \
             module-level configuration. Remove this `secrets:` entry (reference it inline as \
             {{ {module}: … }} where the secret is used)."
        ));
    }
    match registry.resolve(module) {
        Some(p) if p.manifest.kind == "secret" => Ok(p.manifest.name.clone()),
        Some(p) => Err(format!(
            "secrets.{module}: plugin '{}' has kind '{}', not 'secret'; only a kind: secret plugin \
             can back a `secrets:` block entry",
            p.manifest.name, p.manifest.kind
        )),
        None => Err(format!(
            "secrets.{module}: no loadable `kind: secret` plugin is named or aliased '{module}' \
             (check the spelling against the plugin's manifest name/alias, and that the plugin \
             loaded — see --list-plugins)"
        )),
    }
}

/// THE POST-RESOLVE HALF OF `--validate`, in one place.
///
/// `config_validate::validate` is only part of what makes a config valid: the plugin pre-flight
/// (consistency, trust resolution, the three-phase tarball scan, store resolution) and the two
/// secret-reference checks are the rest, and they cannot run until the registry exists. Every caller
/// that asks "is this config valid?" must run ALL of it -- `--validate` assembled the steps by hand
/// and `POST /api/v1/admin/config/validate` ran only the first, so the admin dry-run answered
/// `ok: true` for configs the CLI rejects and an operator could ship one straight into a failed boot.
///
/// Whether `m` names a REAL `auth.chain` plugin ref that must resolve against the plugin registry
/// (`true`) vs a builtin/test stand-in that's exempt (`false`). `keys` is engine-handled, never a
/// plugin. `test-groups-module` is ONLY actually registered as a chain module under
/// `#[cfg(test)]` (`AuthMiddleware::new`, `crates/busbar-core/src/auth/mod.rs`) — `is_test_build` MUST
/// be `cfg!(test)` at the real call site, so this exemption only fires in a test binary. Module-
/// level (not inlined into the `.filter(...)` closure) so the exact predicate that determines
/// `--validate`/`config_validate::validate`'s pass/fail is unit-testable independent of which
/// binary flavor happens to be running `cargo test` — see `tests/tests.rs`. A prior version
/// exempted `test-groups-module` UNCONDITIONALLY (no `is_test_build` gate at all), which made
/// `--validate` silently agree a RELEASE config naming it was fine while real boot still hard-
/// failed (`AuthMiddleware::new` has no non-test arm for it) — breaking the documented invariant
/// a few lines below ("a clean `--validate` means the plugin half of boot succeeds too").
pub(crate) fn is_real_auth_plugin_ref(m: &str, is_test_build: bool) -> bool {
    m != config::KEYS_MODULE && !(is_test_build && m == "test-groups-module")
}

/// The DEFINITION-side twin of [`is_real_auth_plugin_ref`]: whether an
/// `identity-providers.<name>.module:` is a REAL `kind: auth` plugin reference that must resolve
/// against the registry, as opposed to a built-in the engine handles inline
/// ([`config::BUILTIN_IDENTITY_PROVIDERS`] — `keys` and `admin-tokens`) or a compiled-in test
/// stand-in. Separate from the chain predicate because the two answer different questions over
/// different vocabularies: `auth.chain:` never carries `admin-tokens` (that plane is `admin_auth:`),
/// so the chain predicate exempts only `keys`, while EVERY built-in is legal as a definition's
/// module. Same `is_test_build` discipline for the same reason: `test-scope-module` /
/// `test-groups-module` are only ever registered under `#[cfg(test)]` (`AuthPlugins::build`,
/// `crates/busbar-core/src/auth/mod.rs`), so exempting them unconditionally would make `--validate`
/// silently bless a RELEASE config that real boot still hard-fails.
pub(crate) fn is_real_identity_provider_plugin_ref(m: &str, is_test_build: bool) -> bool {
    !config::BUILTIN_IDENTITY_PROVIDERS.contains(&m)
        && !(is_test_build && matches!(m, "test-groups-module" | "test-scope-module"))
}

/// The human list of every module an `identity-providers.<name>.module:` may legally name RIGHT NOW:
/// the built-ins, plus every loaded `kind: auth` plugin. Named as a SET, never counted — the same
/// "name the whole valid vocabulary" discipline the `export.<n>.streams:` diagnostic follows.
pub(crate) fn valid_identity_provider_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
) -> String {
    let mut names: Vec<String> = config::BUILTIN_IDENTITY_PROVIDERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    names.extend(
        registry
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == "auth")
            .map(|p| p.manifest.name.clone()),
    );
    names.join(" | ")
}

/// Manifest-only, like the pre-flight it wraps: nothing is `dlopen`ed and no store is opened, so it
/// is safe on the admin read path.
pub fn preflight_plugins_and_secrets(
    deploy: &config::DeployCfg,
    cfg: &config::RootCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let registry = plugins_preflight(
        deploy.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &deploy.plugins,
        &cfg.export,
    )?;
    validate_secret_modules(&registry, &cfg.secrets)?;
    validate_secret_refs(&registry, cfg)?;
    Ok(registry)
}

/// Validate EVERY `secrets:` block entry against the registry (the `--validate` counterpart of the
/// per-entry check `build_secret_resolver` runs at boot). Returns the FIRST offending entry's error.
pub(crate) fn validate_secret_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<(), String> {
    for module in secret_modules.keys() {
        validate_secret_module(registry, module)?;
    }
    Ok(())
}

/// Validate every SECRET REFERENCE's module against the plugin registry — the deferred half of the
/// secret-reference check `config_validate` cannot do (it runs before the registry exists). The
/// built-in `env`/`file` modules always pass; ANY OTHER module name is a `kind: secret` PLUGIN
/// reference (the 1.5.0 "secrets are plugins" feature: `api_key: { module: acme-vault, … }`, TLS
/// cert/key, `auth.signing_key`, the admin token) and must resolve to a LOADED, TRUSTED, `kind:
/// secret` plugin. A genuine typo (no built-in, no plugin) is a hard boot / `--validate` error;
/// an installed vault/aws-sm plugin PASSES. Shared by boot (`build_app_from_config`) and the
/// `--validate` pre-flight so the two cannot drift. Returns the FIRST offending reference's error.
pub(crate) fn validate_secret_refs(
    registry: &busbar_plugin_loader::PluginRegistry,
    cfg: &config::RootCfg,
) -> Result<(), String> {
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module == config::secret::SECRET_MODULE_ENV
            || r.module == config::secret::SECRET_MODULE_FILE
        {
            continue; // built-in resolver — already structurally checked in config_validate
        }
        match registry.resolve(&r.module) {
            Some(p) if p.manifest.kind == "secret" => {}
            Some(p) => {
                return Err(format!(
                    "{what} references secret module '{}', but plugin '{}' has kind '{}', not \
                     'secret'; only a `kind: secret` plugin can back a secret reference",
                    r.module, p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(format!(
                    "{what} references secret module '{}', which is not a built-in (`env` | `file`) \
                     and no loadable `kind: secret` plugin is named or aliased '{}'. Fix the \
                     spelling, install/trust the plugin (see --list-plugins), or use a built-in, \
                     e.g.:\n\n    {what}: {{ env: MY_SECRET_VAR }}\n",
                    r.module, r.module
                ));
            }
        }
    }
    Ok(())
}

/// RESOLVE every built-in (`env` / `file`) secret reference, for `--validate` ONLY.
///
/// `config_validate` proves a reference is well-FORMED; it cannot prove the variable is set or the
/// file is readable, because it runs before anything touches the environment. Without this,
/// `--validate` reported a config VALID while boot would warn and then serve a gateway whose every
/// upstream request fails on a missing credential: success reported for something that cannot work.
///
/// DELIBERATELY NOT IN `preflight_plugins_and_secrets`. That pre-flight is SHARED with boot and with
/// the admin apply/reload path, where an unresolvable secret is a WARNING by design, not a refusal
/// (`test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects` pins that). A live
/// config change must not be rejected for a secret that may resolve on the next deploy. The operator
/// asking `--validate` is asking a different question, and deserves the strict answer.
///
/// Returns the FIRST unresolvable reference's error, naming the field so it is actionable.
pub fn validate_builtin_secrets_resolve(cfg: &config::RootCfg) -> Result<(), String> {
    let builtins = config::secret::SecretResolver::builtins_only();
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module != config::secret::SECRET_MODULE_ENV
            && r.module != config::secret::SECRET_MODULE_FILE
        {
            continue; // plugin-backed: the plugin may not be loadable here, and preflight covers it
        }
        if let Err(e) = builtins.resolve(r) {
            return Err(format!("{what}: {e}"));
        }
    }
    Ok(())
}

/// Build the [`config::secret::SecretResolver`] the engine resolves every secret reference through:
/// the built-in `env`/`file` modules inline, and any OTHER module name via a loaded `kind: secret`
/// plugin from `registry` (opened per resolution; a secret module is off every hot path so the
/// per-call open + resolve is fine). FAIL-CLOSED: `open_secret` errors surface as an unresolvable
/// secret. When the plugin subsystem is off the registry is empty and every non-built-in reference
/// is a fail-closed error at resolve time.
pub(crate) fn build_secret_resolver(
    registry: Arc<busbar_plugin_loader::PluginRegistry>,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<config::secret::SecretResolver, String> {
    // MODULE-LEVEL config delivery for `kind: secret` plugins: resolve each configured
    // `secrets.<module>.settings` ONCE at boot and hand it to the plugin's `open()`, exactly as
    // `store.settings` configures the store plugin. Without this a secret plugin's `open()` always
    // received `{}`, so a Vault-style plugin's address/namespace/token/CA had to be repeated in EVERY
    // SecretRef — multiplying secret exposure and defeating the open-vs-resolve separation the ABI
    // is designed around.
    //
    // The module config is resolved against the BUILT-IN env/file resolvers ONLY (a `builtins_only`
    // resolver). A secret module cannot resolve its OWN `open()` config through a secret plugin —
    // that would be a bootstrap cycle — so `{ token: { env: VAULT_TOKEN } }` resolves but
    // `{ token: { module: some-other-secret-plugin } }` is a fail-closed error.
    let builtins = config::secret::SecretResolver::builtins_only();
    // Key the open-config map by the plugin's CANONICAL name, not by the literal `secrets:` block
    // key: a `SecretRef` may name the plugin by EITHER its canonical name or its alias, and
    // the registry resolves both — but a bare string-equality lookup on the block key would MISS the
    // other spelling and silently open the plugin with `{}` (dropping the operator's configured
    // address/token/CA). Canonicalize the block key through the SAME by_name/by_alias resolution the
    // registry uses, so a `secrets:` entry written under an alias and a `SecretRef` written under the
    // canonical name (or vice versa) line up. A `secrets:` entry that resolves to NOTHING — a typo, or
    // a module that names one of the reserved built-in resolvers (`env`/`file`, which take no
    // module-level open config) — is a hard boot error: silently passing `{}` for a mis-typed module
    // is exactly the failure this closes. The `--validate` path applies the identical policy via the
    // shared `validate_secret_module`/`validate_secret_modules` helpers.
    let mut open_config: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    // Which `secrets:` block key produced each canonical entry, so an ALIAS/CANONICAL collision can
    // be named precisely.
    let mut claimed_by: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (module, mcfg) in secret_modules {
        // Validate + canonicalize the block key against the registry (shared with --validate). A
        // reserved built-in name, an unknown module, or a non-secret plugin is a hard error here.
        let canonical = validate_secret_module(&registry, module)?;
        // TWO SPELLINGS, ONE MODULE: a `secrets:` block written under BOTH a plugin's alias and its
        // canonical name canonicalizes to the same key, and the second insert silently DROPPED the
        // first entry's open() config — one of the two blocks (address, token, CA) just vanished,
        // with the module still loading happily on the survivor. Ambiguous by construction: there is
        // no defensible rule for which one wins. Fail LOUD and name both spellings.
        if let Some(previous) = claimed_by.get(&canonical) {
            return Err(format!(
                "secrets: the module '{canonical}' is configured TWICE — once as '{previous}' and \
                 once as '{module}' (an alias and its canonical name resolve to the same plugin). \
                 One of the two blocks would be silently dropped; keep exactly one."
            ));
        }
        let resolved = config::secret::resolve_settings(&mcfg.settings, &builtins)
            .map_err(|e| format!("secrets.{module} settings: {e}"))?;
        claimed_by.insert(canonical.clone(), module.clone());
        open_config.insert(canonical, serde_json::Value::Object(resolved).to_string());
    }
    Ok(config::secret::SecretResolver::with_plugin(Box::new(
        move |module: &str, settings: &str| -> Result<Vec<u8>, String> {
            // Canonicalize the referenced module the SAME way, so an alias-vs-name spelling difference
            // between the `secrets:` block and this `SecretRef` still finds the configured open() JSON.
            // A module that does not resolve falls through to `open_secret` below, which produces the
            // authoritative "no such plugin" error.
            let canonical = registry
                .resolve(module)
                .map(|p| p.manifest.name.as_str())
                .unwrap_or(module);
            // Deliver the module's configured open() JSON (default `{}` for an unconfigured module).
            let open_cfg = open_config
                .get(canonical)
                .map(String::as_str)
                .unwrap_or("{}");
            let m = registry.open_secret(module, open_cfg)?;
            m.resolve(
                &serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(settings)
                    .map_err(|e| format!("secret settings are not a JSON object: {e}"))?,
            )
            .map_err(|e| e.to_string())
        },
    )))
}

/// The `plugins.fetch` download closure the engine hands to `busbar_plugin_loader::fetch_plugins`.
/// Enforces the SAME cloud-metadata SSRF denylist provider URLs face (fetch is off-box, key-adjacent
/// I/O) and requires https for a public host, then performs the GET. The GET runs on a DEDICATED
/// std::thread with its own current-thread runtime, so it is safe whether the caller sits on a tokio
/// worker (boot) or a `spawn_blocking` thread (reload) — a nested `block_on` on a runtime thread would
/// otherwise panic. The loader owns cache/verify/atomic-write; this owns network + SSRF.
pub(crate) fn plugin_fetch_downloader(
    blocked: &[String],
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    plugin_fetch_downloader_with_cap(blocked, config::DEFAULT_PLUGIN_FETCH_MAX_BYTES)
}

/// Same as [`plugin_fetch_downloader`] with an explicit download-size cap — split out so a test can
/// exercise the over-cap rejection path against a small in-memory server without actually moving
/// hundreds of megabytes through loopback. Production always calls [`plugin_fetch_downloader`], which
/// pins `cap` to [`config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`].
pub(crate) fn plugin_fetch_downloader_with_cap(
    blocked: &[String],
    cap: usize,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| -> Result<Vec<u8>, String> {
        // Scheme: https required for a public host; plaintext http only for loopback/private (a local
        // dev registry). Mirrors the provider base_url rule.
        let https = config_validate::scheme_is(url, "https");
        if !https {
            let host_local = config_validate::extract_normalized_host(url)
                .as_deref()
                .map(config_validate::host_is_private_or_loopback)
                .unwrap_or(false);
            if !(config_validate::scheme_is(url, "http") && host_local) {
                return Err(format!(
                    "plugins.fetch url must use https for a public host (got '{url}')"
                ));
            }
        }
        // SSRF: never fetch from a cloud-metadata host (no per-provider carve-outs; the operator
        // denylist still extends the built-in list).
        if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, &blocked) {
            return Err(format!(
                "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
            ));
        }
        let url = url.to_string();
        std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<u8>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(async {
                    // The ENGINE, on a cold one-shot posture (`llm_lane` values, one idle slot):
                    // webpki trust, system DNS, boot-env proxy — and redirect non-following is
                    // STRUCTURAL now (hyper follows nothing), where reqwest needed
                    // `Policy::none()`: the SSRF guard above only vets the ORIGINAL url, so a 3xx
                    // `Location` from the semi-trusted plugin registry could otherwise bounce the
                    // fetch to an internal/cloud-metadata target with no re-check — the same
                    // redirect-SSRF vector the OTLP exporter and provider clients already close.
                    // A redirect arrives as a 3xx status and falls into the non-success arm below.
                    let client = crate::proxy::build_egress_client(
                        &crate::proxy::EgressClientSpec::llm_lane(1, 4, false, false),
                    );
                    let uri: http::Uri = url
                        .parse()
                        .map_err(|e| format!("GET {url}: not a valid URI: {e}"))?;
                    let request = busbar_substrate::egress::engine::request(
                        http::Method::GET,
                        uri,
                        http::HeaderMap::new(),
                        bytes::Bytes::new(),
                    );
                    let resp = client
                        .request(request)
                        .await
                        .map_err(|e| {
                            format!("GET {url}: {}", busbar_substrate::egress::with_cause(&e))
                        })?;
                    let status = resp.status();
                    if !status.is_success() {
                        if status.is_redirection() {
                            return Err(format!(
                                "GET {url}: HTTP {status} — refusing to follow a plugins.fetch \
                                 redirect (redirect-SSRF guard)"
                            ));
                        }
                        return Err(format!("GET {url}: HTTP {status}"));
                    }
                    // A declared Content-Length over the cap is rejected BEFORE reading a single body
                    // byte — the fast, cheap path for the common case of an honest oversized response.
                    // Not load-bearing on its own (a dishonest/absent header falls through to the
                    // streamed cap below), just an early exit.
                    if let Some(len) = resp
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                    {
                        if len as usize > cap {
                            return Err(format!(
                                "GET {url}: declared Content-Length {len} exceeds the {cap}-byte \
                                 plugins.fetch download cap"
                            ));
                        }
                    }
                    // Stream with a running byte counter (never a whole-body buffer, which would
                    // hold the ENTIRE — possibly multi-gigabyte — body before any cap could apply)
                    // so a mistyped or compromised URL serving an unbounded body is rejected with a
                    // clear error instead of OOMing busbar on boot or `/plugins/reload`.
                    use http_body_util::BodyExt;
                    let (bytes, end) =
                        crate::proxy::read_capped(resp.into_body().into_data_stream(), cap).await;
                    match end {
                        crate::proxy::ReadEnd::Complete => Ok(bytes.to_vec()),
                        crate::proxy::ReadEnd::Truncated => Err(format!(
                            "GET {url}: response exceeded the {cap}-byte plugins.fetch download cap; \
                             refusing to buffer a truncated download"
                        )),
                        crate::proxy::ReadEnd::TransportError => {
                            Err(format!("read body {url}: connection failed mid-download"))
                        }
                    }
                })
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_string())?
        })
    }
}
