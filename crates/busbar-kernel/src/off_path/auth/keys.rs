// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for the auth key and instance slices (`auth::instances`, `auth::effect`,
//! `auth::self_keys`, `auth::relend`): work a config build, a reload, an admin verb or a key mint
//! runs once, never per request.

pub(crate) mod instances {
    //! THE AUTH INSTANCES OF ONE CONFIG BUILD, keyed by provider name (the `identity-providers` key).
    //!
    //! A provider is defined once and `resolve_auth` hands every role that names it (`auth.chain`,
    //! `auth.admin_auth`, the hosted login methods) the same definition, so one provider is ONE
    //! instance per build: one OPEN, one READY (an OIDC discovery and JWKS fetch), one tick schedule
    //! and one verdict cache, shared by every role (WASTE-AUTH-SECRETS W1). The first role to name a
    //! provider opens it with the provider's whole resolved settings, including the login-only
    //! additions (`browser_login.client_id`, the lent `client_secret`) that the same plugin received
    //! in its login role before; every later role is handed the same instance. Core owns this
    //! decision (decision 185): the loader opens what it is asked to.

    use std::sync::{Arc, OnceLock};

    use busbar_contract::auth_calls::{AuthAxis, AuthCalls};
    use busbar_contract::plugin_rows::PluginRows;
    use busbar_contract::plugin_settings::ResolvedSettings;

    /// Why a provider's instance was opened in this build rather than carried from the prior one
    /// (WASTE-AUTH-SECRETS W2). Audited with the provider on every open.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Opening {
        /// No prior build held the provider.
        New,
        /// The provider's resolved settings changed.
        Settings,
        /// A resolved secret value changed (a rotation behind the same reference).
        Secret,
        /// The plugin binary the row admits changed (or the row is gone).
        Binary,
        /// The prior instance is not `reusable()`: quarantined, closed, metadata invalid, its tick
        /// schedule failed, or an implementor that cannot tell.
        Unhealthy,
    }

    impl Opening {
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                Self::New => "new",
                Self::Settings => "settings",
                Self::Secret => "secret",
                Self::Binary => "binary",
                Self::Unhealthy => "unhealthy",
            }
        }
    }

    /// A keyed digest of what one provider's instance was opened over. HMAC-SHA256 under a key drawn
    /// once per process and never persisted, so no secret-equivalent hash is kept, not even in memory.
    /// Used ONLY to decide whether the next build may carry the instance (W2); sharing within one
    /// build is by provider name (W1).
    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct InstanceIdentity {
        binary: [u8; 32],
        settings: [u8; 32],
        secrets: [u8; 32],
    }

    fn identity_key() -> &'static busbar_contract::crypto::HmacSha256Key {
        static KEY: OnceLock<busbar_contract::crypto::HmacSha256Key> = OnceLock::new();
        KEY.get_or_init(|| {
            let seed = busbar_contract::crypto::random::<32>()
                .map(|bytes| bytes.to_vec())
                .unwrap_or_else(|_| {
                    // No system randomness: a key no two processes share is still required, never a
                    // fixed one. Fall back to the clock and the address of this static.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_nanos());
                    let mut seed = now.to_le_bytes().to_vec();
                    seed.extend_from_slice(&(std::ptr::addr_of!(KEY) as usize).to_le_bytes());
                    seed
                });
            busbar_contract::crypto::HmacSha256Key::new(&seed)
                .expect("a 24- or 32-byte HMAC-SHA256 key is always accepted")
        })
    }

    fn keyed(parts: &[&[u8]]) -> [u8; 32] {
        let lengths: Vec<[u8; 8]> = parts
            .iter()
            .map(|part| (part.len() as u64).to_le_bytes())
            .collect();
        let mut framed: Vec<&[u8]> = Vec::with_capacity(parts.len() * 2);
        for (length, part) in lengths.iter().zip(parts) {
            framed.push(length);
            framed.push(part);
        }
        identity_key().sign_parts(&framed)
    }

    impl InstanceIdentity {
        /// The identity of `module` opened over `resolved`: the admitted row (its archive digest, or
        /// its name and version for a linked row), the settings document without its secret slots,
        /// and each secret slot's bytes. `None` when the row is gone or the settings cannot be
        /// encoded: such an instance is never carried.
        fn of(
            registry: &dyn PluginRows,
            module: &str,
            resolved: &ResolvedSettings,
        ) -> Option<Self> {
            let row = registry.resolve(module)?;
            let archive = registry.archive_sha256(module).unwrap_or_default();
            let binary = keyed(&[
                module.as_bytes(),
                row.name.as_bytes(),
                row.version.as_bytes(),
                &[u8::from(row.linked)],
                archive.as_bytes(),
            ]);
            let (plain, secrets) = resolved.lend_secrets(&registry.secret_slots(module));
            let encoded = plain.encode().ok()?;
            let seal = crate::seal::lend();
            let settings = keyed(&[module.as_bytes(), encoded.expose(&seal).as_slice()]);
            let slots: Vec<&[u8]> = secrets.iter().map(|s| s.expose(&seal).as_slice()).collect();
            let secrets = keyed(&slots);
            Some(Self {
                binary,
                settings,
                secrets,
            })
        }

        fn differs(&self, prior: &Self) -> Option<Opening> {
            if self.binary != prior.binary {
                Some(Opening::Binary)
            } else if self.settings != prior.settings {
                Some(Opening::Settings)
            } else if self.secrets != prior.secrets {
                Some(Opening::Secret)
            } else {
                None
            }
        }
    }

    struct Held {
        calls: Arc<dyn AuthCalls>,
        identity: Option<InstanceIdentity>,
    }

    /// What a role builder prepares for a provider no role of this build has yet: the provider's
    /// resolved settings (the superset, login additions included) and the axis that opens it. The
    /// role's own checks (`answers`) have passed. `reresolve`, when the plugin lends secret
    /// references, re-resolves those settings so the host re-lends a rotated credential in place
    /// (`auth::relend`).
    pub(crate) struct Prepared {
        pub(crate) axis: Arc<dyn AuthAxis>,
        pub(crate) resolved: ResolvedSettings,
        pub(crate) reresolve: Option<crate::auth::relend::Reresolve>,
    }

    /// The instances one build holds, by provider name. Carried into the next build as its prior
    /// (WASTE-AUTH-SECRETS W2): an unchanged, healthy instance is handed to the new build's roles as
    /// is, with no OPEN, no READY fetch and no new tick schedule.
    #[derive(Default)]
    pub struct AuthInstances {
        by_provider: indexmap::IndexMap<String, Held>,
        prior: Option<Arc<AuthInstances>>,
        opened: Vec<(String, Opening)>,
        reused: Vec<String>,
    }

    impl std::fmt::Debug for AuthInstances {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AuthInstances")
                .field("providers", &self.by_provider.keys().collect::<Vec<_>>())
                .finish()
        }
    }

    impl AuthInstances {
        /// A build's map over the build before it (`None` at boot).
        #[must_use]
        pub fn carrying(prior: Option<Arc<AuthInstances>>) -> Self {
            Self {
                prior,
                ..Self::default()
            }
        }

        /// The finished build's map, without its prior: the prior build's unchanged instances it
        /// took are held here, the rest go with the prior App.
        #[must_use]
        pub fn sealed(mut self) -> Arc<Self> {
            self.prior = None;
            Arc::new(self)
        }

        /// Each provider this build OPENED, with why, in order.
        #[must_use]
        pub fn opened(&self) -> &[(String, Opening)] {
            &self.opened
        }

        /// Each provider this build carried from the prior build unchanged.
        #[must_use]
        pub fn reused(&self) -> &[String] {
            &self.reused
        }

        /// `provider`'s instance: the one this build already holds for another role; else the prior
        /// build's, when it was opened over the same identity and reports `reusable()`; else a new
        /// OPEN over `prepare()`'s settings. A refusal is not kept.
        pub(crate) fn instance(
            &mut self,
            provider: &str,
            module: &str,
            registry: &dyn PluginRows,
            prepare: impl FnOnce() -> Result<Prepared, String>,
            refused: impl FnOnce(String) -> String,
        ) -> Result<Arc<dyn AuthCalls>, String> {
            if let Some(held) = self.by_provider.get(provider) {
                return Ok(Arc::clone(&held.calls));
            }
            let Prepared {
                axis,
                resolved,
                reresolve,
            } = prepare()?;
            let identity = InstanceIdentity::of(registry, module, &resolved);
            let prior = self
                .prior
                .as_ref()
                .and_then(|p| p.by_provider.get(provider))
                .map(|held| (Arc::clone(&held.calls), held.identity.clone()));
            let opening = match (&prior, &identity) {
                (None, _) => Some(Opening::New),
                (Some(_), None) | (Some((_, None)), Some(_)) => Some(Opening::Binary),
                (Some((calls, Some(was))), Some(now)) => match now.differs(was) {
                    Some(why) => Some(why),
                    None if calls.reusable() => None,
                    None => Some(Opening::Unhealthy),
                },
            };
            let (opening, carried) = match (opening, prior) {
                (Some(opening), _) => (opening, None),
                (None, Some((calls, _))) => (Opening::New, Some(calls)),
                (None, None) => (Opening::New, None),
            };
            if let Some(calls) = carried {
                drop(resolved);
                tracing::info!(
                    provider,
                    module,
                    "auth instance carried into the new build unchanged"
                );
                self.reused.push(provider.to_string());
                self.by_provider.insert(
                    provider.to_string(),
                    Held {
                        calls: Arc::clone(&calls),
                        identity,
                    },
                );
                return Ok(calls);
            }
            let opened = super::relend::open(
                &axis,
                module,
                &instance_label(provider),
                &resolved,
                reresolve,
            );
            drop(resolved);
            let calls = opened.map_err(refused)?;
            tracing::info!(
                provider,
                module,
                reason = opening.as_str(),
                "auth instance opened"
            );
            self.opened.push((provider.to_string(), opening));
            self.by_provider.insert(
                provider.to_string(),
                Held {
                    calls: Arc::clone(&calls),
                    identity,
                },
            );
            Ok(calls)
        }
    }

    /// The label one provider's shared instance opens under; the role is attributed at the call site.
    #[must_use]
    pub(crate) fn instance_label(provider: &str) -> String {
        format!("identity-providers.{provider}")
    }

    /// The settings one provider's instance opens with: its definition's settings resolved, plus the
    /// login-only additions when the provider has a `browser_login` block (the same values the plugin
    /// received in its login role; a role-local override cannot exist, `resolve_auth`). `settings_err`
    /// words a resolution refusal in the calling role's terms.
    pub(crate) fn provider_settings(
        cfg: &crate::config::AuthCfg,
        provider: &str,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        settings_err: impl FnOnce(String) -> String,
    ) -> Result<busbar_contract::plugin_settings::ResolvedSettings, String> {
        let mut resolved = crate::config::secret::resolve_settings(
            settings,
            &registry.secret_slots(module),
            &registry.reference_slots(module),
            module,
            secret_resolver,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(settings_err)?;
        if let Some(cid) = login_block(cfg, provider, module).and_then(|bl| bl.client_id.as_ref()) {
            resolved.default_text("client_id", cid.clone());
        }
        Ok(resolved)
    }

    /// Lend the provider's `browser_login.client_secret` into `resolved`, when it has one: the login
    /// role's secret, lent to the one shared instance.
    pub(crate) fn lend_login_secret(
        cfg: &crate::config::AuthCfg,
        provider: &str,
        module: &str,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
        resolved: &mut busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<(), String> {
        crate::auth::login::lend_browser_login_secret(
            provider,
            module,
            login_block(cfg, provider, module),
            &registry.secret_slots(module),
            secret_resolver,
            resolved,
        )
    }

    /// How one provider's instance re-resolves its settings when the plugin lends secret references
    /// (`auth::relend`): the same steps [`provider_settings`] and [`lend_login_secret`] opened it
    /// with, run again through the build's resolver. `None` when the plugin lends no secrets.
    pub(crate) fn reresolve(
        cfg: &crate::config::AuthCfg,
        provider: &str,
        module: &str,
        settings: &busbar_contract::plugin_settings::Settings,
        registry: &dyn busbar_contract::plugin_rows::PluginRows,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Option<crate::auth::relend::Reresolve> {
        let base =
            crate::off_path::auth::chain::relender(settings, registry, module, secret_resolver)?;
        let browser = login_block(cfg, provider, module).cloned();
        let slots = registry.secret_slots(module);
        let (provider, module, resolver) = (
            provider.to_string(),
            module.to_string(),
            secret_resolver.clone(),
        );
        Some(Box::new(move || {
            let mut resolved = base()?;
            if let Some(cid) = browser.as_ref().and_then(|bl| bl.client_id.clone()) {
                resolved.default_text("client_id", cid);
            }
            crate::auth::login::lend_browser_login_secret(
                &provider,
                &module,
                browser.as_ref(),
                &slots,
                &resolver,
                &mut resolved,
            )?;
            Ok(resolved)
        }))
    }

    fn login_block<'c>(
        cfg: &'c crate::config::AuthCfg,
        provider: &str,
        module: &str,
    ) -> Option<&'c crate::config::BrowserLoginCfg> {
        cfg.methods
            .get(provider)
            .filter(|mc| mc.module == module)
            .and_then(|mc| mc.browser_login.as_ref())
    }

    /// The admin flush: every instance `admin` and `chain` hold for `provider` (all, for `None`) is
    /// refreshed ONCE, however many roles hold it, and its flushed count is summed once. The first
    /// refusal is answered after every instance was asked.
    pub fn flush_distinct(
        admin: &crate::auth::AdminAuthChain,
        chain: &crate::auth::AuthMiddleware,
        provider: Option<&str>,
    ) -> Result<u64, String> {
        let mut distinct: Vec<&Arc<dyn AuthCalls>> = Vec::new();
        let admin = admin
            .modules
            .iter()
            .filter(|(name, _)| provider.is_none_or(|p| p == name.as_str()))
            .map(|(_, module)| &module.calls);
        for calls in admin.chain(chain.chain_instances(provider)) {
            if !distinct.iter().any(|seen| Arc::ptr_eq(seen, calls)) {
                distinct.push(calls);
            }
        }
        crate::state::credential_flush_results(distinct.into_iter().map(|calls| calls.refresh()))
    }
}

/// An admin change's effect context (`auth::effect`): built once per admitted admin verb, and
/// rechecked only by that verb's effect admission.
pub(crate) mod effect {
    use crate::auth::effect::{actor, Context};
    use crate::auth::AdminDoor;
    use axum::http::HeaderMap;

    /// The roles an admin door was authorized under.
    pub(crate) fn roles(door: &AdminDoor) -> std::collections::BTreeSet<String> {
        match door {
            AdminDoor::Identified(p, _) | AdminDoor::Listed(p, _, _) => {
                p.roles.iter().cloned().collect()
            }
            _ => Default::default(),
        }
    }

    /// The context an admin change's effect keeps: what it was authorized for, and under whom.
    pub(crate) fn context(
        method: &str,
        target: &str,
        headers: HeaderMap,
        admitted: &AdminDoor,
    ) -> Context {
        Context {
            native: None,
            method: method.into(),
            target: target.into(),
            headers,
            actor: actor(admitted).map(str::to_owned),
            roles: roles(admitted),
        }
    }

    impl crate::inbound::RequestAdmission {
        pub fn effect_context(&self) -> Context {
            let head = &self.inner.original;
            let target = match &head.query {
                Some(query) => format!("{}?{query}", head.target),
                None => head.target.clone(),
            };
            Context::new(
                &head.method,
                &target,
                self.original_headers().clone(),
                &self.admin_verdict().door,
            )
        }
    }
}

/// Opening a re-lending auth instance (`auth::relend`): once per provider per config build.
pub(crate) mod relend {
    use std::sync::{Arc, Mutex, Weak};
    use std::time::Instant;

    use busbar_contract::auth_calls::{AuthAxis, AuthCalls};
    use busbar_contract::plugin_settings::ResolvedSettings;

    use crate::auth::relend::{RelendingAuth, Reresolve};
    use crate::preflight::{RelendStreak, RELEND_EVERY};

    /// OPEN `module` as `label` over `resolved` through `axis`; when `reresolve` is given (the
    /// plugin lends secret references), the instance is kept by the host refresher and re-lent on
    /// rotation.
    pub(crate) fn open(
        axis: &Arc<dyn AuthAxis>,
        module: &str,
        label: &str,
        resolved: &ResolvedSettings,
        reresolve: Option<Reresolve>,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        let calls = axis.open(module, label, resolved)?;
        let Some(reresolve) = reresolve else {
            return Ok(calls);
        };
        let relending = Arc::new(RelendingAuth::new(
            Arc::clone(axis),
            module,
            label,
            reresolve,
            calls,
            &crate::refresh::HOST_REPORT,
        ));
        crate::refresh::keep(
            Arc::downgrade(&relending) as Weak<dyn crate::refresh::Refreshable>,
            Instant::now() + crate::retry::spread(RELEND_EVERY, 0.1, crate::retry::unit()),
        );
        Ok(relending)
    }

    impl RelendingAuth {
        pub fn new(
            axis: Arc<dyn AuthAxis>,
            module: &str,
            label: &str,
            reresolve: Reresolve,
            calls: Arc<dyn AuthCalls>,
            report: &'static dyn crate::refresh::Report,
        ) -> Self {
            Self {
                name: calls.name().to_string(),
                module: module.to_string(),
                label: label.to_string(),
                axis,
                reresolve,
                current: arc_swap::ArcSwap::from_pointee(calls),
                streak: Mutex::new(RelendStreak::default()),
                report,
            }
        }
    }
}
