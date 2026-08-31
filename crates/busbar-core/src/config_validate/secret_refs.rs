// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY secret reference in the resolved config, and the guard that makes omitting one impossible.
//!
//! Split out of `config_validate/mod.rs` when B1 turned a hand-written list into a compiler-enforced
//! walk: the walk, its exhaustive destructures and the type inventory the coverage test checks the
//! source against are one unit, and they are easier to review as one.

use super::RootCfg;

/// Enumerate EVERY secret reference in the resolved config as `(what, &SecretRef)`, where `what` is
/// the human-readable config path used in error messages. The SINGLE source of truth for which
/// references are secrets: the structural check in `validate_cost_model` and the registry-backed
/// module-existence check in `main::validate_secret_refs` (deferred until the plugin registry exists)
/// both walk this list, so a new secret-bearing field is covered by both the moment it is added here.
///
/// THIS FUNCTION USED TO FAIL OPEN. It was a hand-written list of config paths, and a secret-bearing
/// field that nobody remembered to add here was SILENTLY SKIPPED: no compile error, no test failure,
/// and `--validate` printed `ok: config valid` for a config whose credential could not resolve.
/// That was not hypothetical. `identity-providers.<name>.browser_login.client_secret` (the OAuth
/// confidential-client secret the core itself presents during the code-to-token exchange) had been
/// absent from the list since the block was introduced, so a deployment whose OIDC secret env var was
/// unset was told its config was good and then failed every hosted login at runtime.
///
/// TWO LAYERS NOW MAKE OMISSION IMPOSSIBLE RATHER THAN REMEMBERED, because each layer catches a
/// different way of introducing one:
///
/// 1. A NEW FIELD ON A TYPE ALREADY WALKED HERE is a COMPILE ERROR. Every struct below is taken
///    apart with an EXHAUSTIVE destructure and no `..`, the idiom already used by
///    `RootSettings::is_empty` and `config::patch`. Adding a field to `RootCfg`, `TlsCfg`,
///    `AuthCfg`, `AuthChainEntry`, `AuthMethodCfg`, `BrowserLoginCfg`, `IdentityProviderCfg` or
///    `ProviderCfg` fails to build with `E0027 pattern does not mention field` until somebody has
///    decided, here, whether it carries a secret.
/// 2. A NEW SECRET-BEARING TYPE is a TEST failure. The compiler cannot help with a `SecretRef`
///    added to a struct this function never destructures, so
///    `config_validate::tests::secret_ref_coverage` reads the crate's own sources, finds every
///    field anywhere in the tree whose type mentions `SecretRef`, and requires the declaring type to
///    appear in [`SECRET_BEARING_TYPES`] below. A new one fails the test with the type named.
pub(crate) fn secret_refs(cfg: &RootCfg) -> Vec<(String, &crate::config::SecretRef)> {
    // EXHAUSTIVE, no `..`: see layer 1 above. Fields bound with a leading underscore carry no secret
    // reference, and the grouped comments say why. If you are here because the compiler stopped you,
    // the question to answer is "can this field hold a `SecretRef`, at any depth?" — not "is it
    // convenient to ignore".
    let RootCfg {
        // ── SECRET-BEARING: walked below ──
        tls,
        admin_tls,
        auth,
        providers,
        identity_providers,
        // ── ADDRESSES, NAMES AND REFERENCES: strings the operator types in the clear. A listen
        // address, a public URL, a module name or a bare provider/hook/group name is not a
        // credential and has no `SecretRef` anywhere beneath it. ──
        listen: _,
        public_url: _,
        admin_listen: _,
        admin_auth: _,
        global_hooks: _,
        // ── LIMIT, COST AND POLICY VALUES: numbers, booleans and host lists. ──
        groups: _,
        rate_card: _,
        per_request_fee: _,
        limits: _,
        blocked_metadata_hosts: _,
        allow_metadata_hosts: _,
        allow_all_metadata: _,
        upstream_credentials: _,
        // ── OPAQUE MODULE SETTINGS BAGS (`serde_json::Value` trees, not typed config): `store`,
        // `secrets`, `hooks`, `export` and `export_defs` all carry a plugin's own `settings:`, which
        // MAY contain `SecretRef`-SHAPED documents. Those are NOT `SecretRef`-typed values and are
        // deliberately NOT enumerated here: they are resolved against the built-in env/file modules
        // at the seam that consumes them (`build_secret_resolver` for `secrets.<module>.settings`,
        // the store/exporter/hook open paths for the rest), where the module that owns the bag knows
        // which of its own keys are credentials. This function's contract is the TYPED config
        // surface. `SECRET_BEARING_TYPES` is keyed off the `SecretRef` TYPE for exactly that reason,
        // so this exclusion cannot quietly widen: give any of these a `SecretRef`-typed field and
        // layer 2 fails until it is walked here. ──
        store: _,
        secrets: _,
        hooks: _,
        export: _,
        export_defs: _,
        // `models` names a provider and a model id; the credential lives on the provider.
        models: _,
        pools: _,
        // The per-plane ENDPOINT RESOURCES carry NO credential, and the reason is checkable rather
        // than asserted: an endpoint resource's fields — its canonical URI, authorization servers,
        // supported scopes, allowed origins — are published VERBATIM in the RFC 9728 protected-resource
        // metadata document, which is served to unauthenticated callers by design. A secret cannot live
        // in a struct whose every field is deliberately public. busbar is the RESOURCE server here: it
        // VERIFIES tokens the operator's IdP mints and holds no issuing key of its own. Each resource is
        // type-erased as `Arc<dyn Any>` behind the neutral seam, so no `SecretRef` can be reached here
        // even in principle.
        //
        // This arm exists because B1 made omission impossible: adding the field to `RootCfg` FAILED TO
        // COMPILE until someone decided, and that is the whole value of the exhaustive destructure.
        endpoint_resources: _,
        // `oauth_as:` DOES carry a `SecretRef` — the ES256 signing key — and it is walked below
        // rather than declined here. It is the one secret on that plane, and it is the highest-value
        // one in the process: whoever holds it forges every token this deployment will ever issue.
        oauth_as,
        // `tool_defs` (the MCP `tools:` plane) DOES carry credentials — the RFC 8693 token-exchange
        // subject token and a stdio child's `env:` references — but they are NO LONGER walked here.
        // The exhaustive destructure that forces the secret/not-secret decision on every MCP field
        // now lives in `ToolsCfg`'s `PlaneCfg::secret_refs` impl, beside the fields it guards, and
        // this binding is handed to that impl by the plane loop below. It stays NAMED (not `_`) so a
        // new TOP-LEVEL `RootCfg` field is still a compile error somebody has to answer.
        tool_defs,
        // `agent_defs` (the A2A `agents:` plane) DOES carry credentials — each agent's leased outbound
        // delegation secret and both halves of its outbound client identity — but, like `tool_defs`,
        // they are gathered by the plane's own `AgentsCfg::secret_refs` impl through the loop below,
        // not walked here. Bound by name for the same reason: the RootCfg destructure keeps forcing a
        // decision on a new top-level field.
        agent_defs,
        // THE TWO FAILOVER POOL MAPS hold BARE NAMES and nothing else: a `members:` list of
        // registrations defined elsewhere, and a `repeatable:` list of operation names. Both are
        // references INTO sections this walk already covers, so a credential could only appear here
        // by somebody putting one in a pool member's name. Declined, and the decline is checkable the
        // same way every other one on this list is: layer 2 fails by TYPE NAME the day
        // `CandidatePoolCfg` grows a field that holds a `SecretRef`.
        tool_pools: _,
        agent_pools: _,
    } = cfg;

    let mut refs: Vec<(String, &crate::config::SecretRef)> = Vec::new();

    // THE AUTHORIZATION SERVER'S SIGNING KEY. `--validate` must be able to resolve it, because the
    // alternative is a deployment that boots, advertises a JWKS, and fails on the first token
    // request of the day with a secret module error.
    //
    // Destructured EXHAUSTIVELY rather than read through `identity.signing_key()`, because the
    // accessor would keep compiling on the day a second `SecretRef` is added to the validated
    // identity, and that second secret would then be one `--validate` calls fine and the process
    // fails on at runtime. Everything below `signing_key` is a derived endpoint path or a policy
    // number, and none of them can ever carry a credential — but each is named here so that
    // ADDING one is a compile error somebody has to answer.
    if let Some(identity) = oauth_as {
        let crate::oauth_as::config::AsIdentity {
            signing_key,
            // The issuer and the eight paths derived from it. Public by construction: every one of
            // them is published in the RFC 8414 metadata document.
            issuer: _,
            issuer_path: _,
            metadata_path: _,
            authorize_path: _,
            token_path: _,
            register_path: _,
            jwks_path: _,
            consent_path: _,
            // Policy, not credential: the scope ceiling, the token lifetime, and the advisory
            // `kid` that appears in every published JWKS entry.
            default_grant: _,
            access_token_ttl: _,
            key_id: _,
        } = identity;
        if let Some(key) = signing_key {
            refs.push(("oauth_as.signing_key".to_string(), key));
        }
    }

    for (name, p) in providers {
        let crate::config::ProviderCfg {
            api_key,
            // Everything else on a provider is a URL, a protocol/auth-scheme selector, an error map
            // or a host allowlist.
            protocol: _,
            base_url: _,
            health: _,
            error_map: _,
            path: _,
            path_base: _,
            token_url: _,
            scope: _,
            subject: _,
            auth: _,
            allow_metadata_hosts: _,
        } = p;
        refs.push((format!("providers.{name}.api_key"), api_key));
    }
    push_tls_refs(&mut refs, "tls", tls.as_ref());
    push_tls_refs(&mut refs, "admin_tls", admin_tls.as_ref());

    // The `identity-providers:` DEFINITION map is walked directly rather than through the resolved
    // auth chains. `resolve_auth` projects a definition onto an `AuthChainEntry` only for a provider
    // NAMED in `auth.chain:`/`auth.admin_auth:`, and `AuthCfg::admin_token_ref` then returns at most
    // ONE token (the first `admin-tokens` entry it finds), so walking the chains alone missed both a
    // second operator credential and every secret on a defined-but-not-yet-referenced provider. A
    // definition the operator wrote down is a definition busbar must be able to resolve.
    for (name, def) in identity_providers {
        let crate::config::IdentityProviderCfg {
            token,
            browser_login,
            module: _,
            max_admin_scope: _,
            settings: _, // opaque plugin settings bag; see the `RootCfg` note above.
        } = def;
        if let Some(tok) = token {
            refs.push((format!("identity-providers.{name}.token"), tok));
        }
        push_browser_login_refs(
            &mut refs,
            &format!("identity-providers.{name}"),
            browser_login.as_ref(),
        );
    }

    if let Some(auth) = auth {
        let crate::config::AuthCfg {
            signing_key,
            chain,
            admin_auth,
            methods,
            // Role bindings map a role name onto pool/group/scope grants: no credentials.
            role_bindings: _,
            // A duration string.
            key_ttl: _,
            // Token-mint policy: bools, duration strings, pool-name strings, binding-mode enums —
            // no secret references anywhere in the block.
            policy: _,
        } = auth;
        if let Some(sk) = signing_key {
            refs.push(("auth.signing_key".to_string(), sk));
        }
        // The RESOLVED chains and methods are projections of the definitions walked above, so in a
        // config built by `resolve` these add nothing new. They are walked anyway because they are
        // separate types with their own `SecretRef` fields, they are reachable from `RootCfg`, and a
        // future construction path that does not go through `identity-providers:` (a synthesized
        // entry, an admin-applied chain) would otherwise reintroduce exactly this blind spot.
        // Duplicate paths are harmless: both consumers are pure checks over the list.
        for (plane, entries) in [("chain", chain), ("admin_auth", admin_auth)] {
            for entry in entries {
                let crate::config::AuthChainEntry {
                    token,
                    name,
                    module: _,
                    max_admin_scope: _,
                    settings: _,
                } = entry;
                if let Some(tok) = token {
                    refs.push((format!("auth.{plane}.{name}.token"), tok));
                }
            }
        }
        for (name, method) in methods {
            let crate::config::AuthMethodCfg {
                browser_login,
                module: _,
                settings: _,
            } = method;
            push_browser_login_refs(
                &mut refs,
                &format!("auth.methods.{name}"),
                browser_login.as_ref(),
            );
        }
    }

    // ── THE PLANE SECTIONS, each asked for its OWN secret references. The exhaustive no-`..`
    // destructure that forces a secret/not-secret decision on every new MCP / A2A field has moved
    // OUT of this walk and INTO each plane's `PlaneCfg::secret_refs` impl, beside the fields it
    // guards (`ToolsCfg`, `AgentsCfg`). Core no longer names the plane's credential-bearing types —
    // `McpServerDefCfg`, `TokenExchangeCfg`, `AgentDefCfg`, `OutboundCredential`, `ClientIdentityCfg`
    // — to enumerate them; it loops the trait over the section bindings the RootCfg destructure
    // above already forced a decision on. Each impl returns FULLY-QUALIFIED paths
    // (`tools.<name>.…`, `agents.<name>.…`), so nothing is prefixed here. Order within the returned
    // list is not observed: every consumer (`validate`, `validate_secret_refs`,
    // `validate_builtin_secrets_resolve`) is a per-reference check, and the coverage test compares by
    // SET.
    for plane_cfg in [tool_defs.as_ref(), agent_defs.as_ref()] {
        refs.extend(plane_cfg.secret_refs());
    }

    refs
}

/// The three PEM secret references on one `tls:`/`admin_tls:` block, prefixed with the block's config
/// path. Split out so the two call sites cannot drift (they did not, but they were two copies).
fn push_tls_refs<'a>(
    refs: &mut Vec<(String, &'a crate::config::SecretRef)>,
    at: &str,
    tls: Option<&'a crate::config::TlsCfg>,
) {
    let Some(tls) = tls else {
        return;
    };
    let crate::config::TlsCfg {
        cert,
        key,
        client_ca,
    } = tls;
    refs.push((format!("{at}.cert"), cert));
    refs.push((format!("{at}.key"), key));
    if let Some(ca) = client_ca {
        refs.push((format!("{at}.client_ca"), ca));
    }
}

/// The confidential-client secret on one `browser_login:` block, prefixed with the owning provider's
/// config path. THIS IS THE FIELD THE OLD HAND-WRITTEN LIST MISSED: an unset `client_secret` env var
/// passed `--validate` as `ok: config valid` and then failed every hosted login.
fn push_browser_login_refs<'a>(
    refs: &mut Vec<(String, &'a crate::config::SecretRef)>,
    at: &str,
    login: Option<&'a crate::config::BrowserLoginCfg>,
) {
    let Some(login) = login else {
        return;
    };
    let crate::config::BrowserLoginCfg {
        client_secret,
        // The client id is advertised on the authorize URL in the clear; it is public by design.
        client_id: _,
    } = login;
    if let Some(secret) = client_secret {
        refs.push((format!("{at}.browser_login.client_secret"), secret));
    }
}

/// EVERY type in the tree that declares a `SecretRef`-typed field, and how [`secret_refs`] accounts
/// for it. This is layer 2 of the anti-omission guard described on `secret_refs`: the compiler can
/// force a NEW FIELD on a type that is already destructured, but it cannot say a word about a
/// `SecretRef` added to a struct `secret_refs` never looks at. `tests::secret_ref_coverage` derives
/// the real set from the SOURCE and fails if it is not exactly this one.
///
/// It is a checked inventory, NOT a waiver list. Nothing can be added to it to silence a failure: an
/// entry that is `Walked` must genuinely be destructured by `secret_refs`, and an entry that is
/// `NotInResolvedConfig` must genuinely be unreachable from `RootCfg` — the test verifies both, so
/// mislabelling a live type as unreachable fails just as loudly as leaving it out.
#[cfg(test)]
pub(crate) const SECRET_BEARING_TYPES: &[(&str, SecretBearing)] = &[
    ("TlsCfg", SecretBearing::Walked),
    ("ProviderCfg", SecretBearing::Walked),
    ("AuthCfg", SecretBearing::Walked),
    ("AuthChainEntry", SecretBearing::Walked),
    ("IdentityProviderCfg", SecretBearing::Walked),
    ("BrowserLoginCfg", SecretBearing::Walked),
    // `tools.<name>.token_exchange.subject_token` — busbar's OWN token, the SUBJECT of an RFC 8693
    // exchange, never the caller's.
    ("TokenExchangeCfg", SecretBearing::Walked),
    // The A2A plane's LEASED outbound delegation credential. Reached from `RootCfg` through
    // `agent_defs -> agents.<name>.upstream_credential`.
    ("OutboundCredential", SecretBearing::Walked),
    // The A2A plane's OUTBOUND CLIENT CERTIFICATE — busbar's own end of a mutual handshake with a
    // registered agent. Reached from `RootCfg` through `agent_defs -> agents.<name>.client_identity`.
    ("ClientIdentityCfg", SecretBearing::Walked),
    // The authorization server's ES256 signing key — the highest-value secret in the process, since
    // whoever holds it forges every token this deployment will ever issue. Reached from `RootCfg`
    // through `oauth_as`, which is the VALIDATED identity, which is why that type carries the
    // reference verbatim rather than consuming it at `resolve` time.
    ("AsIdentity", SecretBearing::Walked),
    (
        "OauthAsCfg",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side `oauth_as:` block. `resolve` lowers it into `AsIdentity`, which \
             IS walked, and every `--validate`/boot check runs against the RESOLVED config. Same \
             shape as any endpoint plane's `resolve`-lowered resource, and the same reason.",
        ),
    ),
    (
        "AuthDeployCfg",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side `auth:` block. `resolve_auth` lowers it into `AuthCfg`, which IS \
             walked, and every `--validate`/boot check runs against the RESOLVED config.",
        ),
    ),
    (
        "ProviderDeploy",
        SecretBearing::NotInResolvedConfig(
            "the DESERIALIZE-side provider entry (providers.yaml). `resolve` lowers it into \
             `ProviderCfg`, which IS walked.",
        ),
    ),
];

/// How [`secret_refs`] accounts for one secret-bearing type. See [`SECRET_BEARING_TYPES`].
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretBearing {
    /// Exhaustively destructured by [`secret_refs`], so every one of its `SecretRef` fields reaches
    /// the returned list and a new field is a compile error.
    Walked,
    /// Not reachable from `RootCfg` at all, with the reason it is not. A type here is a config shape
    /// that is LOWERED into a walked type before any validation runs.
    NotInResolvedConfig(&'static str),
}

#[cfg(test)]
#[path = "tests/secret_ref_coverage.rs"]
mod secret_ref_coverage;
