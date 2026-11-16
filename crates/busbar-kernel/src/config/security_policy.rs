// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One semantic admission policy for all config representations and reloads.
use super::transaction::TxnError;
use crate::auth::effect::{Authority, Context};
use crate::hashing::Sha256;
use crate::state::App;
use serde_json::json;

pub(super) fn digest(value: &serde_json::Value) -> [u8; 32] {
    let text = busbar_contract::secure::SecureString::from_args(format_args!("{value}"));
    Sha256::digest(text.as_bytes())
}

/// THE SECURITY-RELEVANT FIELDS of one configuration, as its build resolves them
/// (SECRET-SHORTHAND-BOOT §3.12): what a caller without full-operator authority may not change.
/// The build's digest and the authority pre-check's read the same view through one function,
/// [`security_digest`].
pub struct SecurityView<'a> {
    pub auth: Option<&'a super::AuthCfg>,
    pub identity_providers: &'a super::IdentityProviders,
    pub secrets: &'a std::collections::BTreeMap<String, super::SecretModuleCfg>,
    pub credentials: &'a super::CredentialsCfg,
    pub tls: Option<&'a super::TlsCfg>,
    pub admin_tls: Option<&'a super::TlsCfg>,
    pub admin_listen: &'a str,
    pub blocked_metadata_hosts: &'a [String],
    pub allow_metadata_hosts: &'a [String],
    pub allow_all_metadata: bool,
    pub plugins: &'a super::PluginsCfg,
}

impl<'a> SecurityView<'a> {
    /// The view of a resolved configuration and the plugin policy its build admits under.
    #[must_use]
    pub fn of(cfg: &'a super::RootCfg, plugins: &'a super::PluginsCfg) -> Self {
        Self {
            auth: cfg.auth.as_ref(),
            identity_providers: &cfg.identity_providers,
            secrets: &cfg.secrets,
            credentials: &cfg.credentials,
            tls: cfg.tls.as_ref(),
            admin_tls: cfg.admin_tls.as_ref(),
            admin_listen: &cfg.admin_listen,
            blocked_metadata_hosts: &cfg.blocked_metadata_hosts,
            allow_metadata_hosts: &cfg.allow_metadata_hosts,
            allow_all_metadata: cfg.allow_all_metadata,
            plugins,
        }
    }
}

/// One digest per field class of a [`SecurityView`], in a fixed order: two configurations are
/// security-equal when every class is, and a refusal names the classes that differ. Held in memory
/// only (never persisted).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityDigest(Vec<(&'static str, [u8; 32])>);

impl SecurityDigest {
    /// The field classes whose values differ between `self` and `other`.
    #[must_use]
    pub fn changed(&self, other: &Self) -> Vec<&'static str> {
        let value = |digest: &Self, class: &str| {
            digest
                .0
                .iter()
                .find(|(named, _)| *named == class)
                .map(|(_, value)| *value)
        };
        let mut changed: Vec<&'static str> = Vec::new();
        for &(class, _) in self.0.iter().chain(other.0.iter()) {
            if value(self, class) != value(other, class) && !changed.contains(&class) {
                changed.push(class);
            }
        }
        changed
    }

    /// Every field class this digest covers.
    fn classes(&self) -> Vec<&'static str> {
        self.0.iter().map(|(class, _)| *class).collect()
    }
}

/// THE SECURITY DIGEST of one configuration (SECRET-SHORTHAND-BOOT §3.12): `auth`, the identity
/// providers, `secrets`, `credentials.at_rest`, both TLS blocks, the admin listener, the metadata
/// guard, and the plugin policy (`enabled`, `dir`, trust and publishers, version floors, and
/// `plugins.fetch`). The build stores it on the generation; the authority pre-check and the build's
/// own check compare against it.
#[must_use]
pub fn security_digest(view: &SecurityView<'_>) -> SecurityDigest {
    let seal = crate::seal::acquire();
    let plugins = view.plugins;
    let classes: [(&'static str, serde_json::Value); 13] = [
        ("auth", json!(view.auth.map(|value| value.authoring(&seal)))),
        (
            "identity-providers",
            json!(view
                .identity_providers
                .iter()
                .map(|(name, value)| (name, value.authoring(&seal)))
                .collect::<indexmap::IndexMap<_, _>>()),
        ),
        (
            "secrets",
            json!(view
                .secrets
                .iter()
                .map(|(name, value)| (name, value.authoring(&seal)))
                .collect::<std::collections::BTreeMap<_, _>>()),
        ),
        (
            "credentials.at_rest",
            json!(view.credentials.at_rest.as_ref().map(|keys| json!({
                "key": keys.key.authoring(&seal),
                "previous": keys.previous.as_ref().map(|value| value.authoring(&seal)),
            }))),
        ),
        ("tls", json!(view.tls.map(|value| value.authoring(&seal)))),
        (
            "admin_tls",
            json!(view.admin_tls.map(|value| value.authoring(&seal))),
        ),
        ("admin_listen", json!(view.admin_listen)),
        (
            "security",
            json!({
                "blocked_metadata_hosts": view.blocked_metadata_hosts,
                "allow_metadata_hosts": view.allow_metadata_hosts,
                "allow_all_metadata": view.allow_all_metadata,
            }),
        ),
        ("plugins.enabled", json!(plugins.enabled)),
        ("plugins.dir", json!(plugins.dir)),
        (
            "plugins.trust",
            json!({
                "allow_untrusted": plugins.trust.allow_untrusted,
                "publishers": plugins.publisher_keys(),
            }),
        ),
        (
            "plugins.min_versions",
            json!({
                "min_versions": plugins.min_versions,
                "first_party_floors": plugins.first_party_floors,
            }),
        ),
        ("plugins.fetch", json!(fetch_digest(&plugins.fetch))),
    ];
    SecurityDigest(
        classes
            .into_iter()
            .map(|(class, value)| (class, digest(&value)))
            .collect(),
    )
}

pub(super) fn root_digest(cfg: &super::RootCfg, plugins: &super::PluginsCfg) -> SecurityDigest {
    security_digest(&SecurityView::of(cfg, plugins))
}

/// The top-level keys a candidate's security fields are read from: the [`SecurityView`] fields,
/// and what their resolution reads beside them (`admin_require_mtls`, `advanced`).
const SECURITY_KEYS: &[&str] = &[
    "auth",
    "identity-providers",
    "secrets",
    "credentials",
    "tls",
    "admin_tls",
    "admin_listen",
    "admin_require_mtls",
    "security",
    "plugins",
    "advanced",
];

/// The class a candidate names when its security fields do not read under the running
/// generation's grammar: they are treated as changed.
const UNREAD_UNDER_RUNNING: &str = "auth, identity-providers, secrets, credentials or tls (they \
                                    do not read under the running configuration's grammar)";

/// A CANDIDATE CONFIGURATION before its own grammar exists (SECRET-SHORTHAND-BOOT §3.12): the
/// effective `plugins:` block its phase 1 judges (typed without a grammar: it holds no secret
/// reference, G18) with the Store's version pins applied as its build applies them, the metadata
/// guard its phase 1 fetch obeys, and its security digest. The grammar-bearing fields are read
/// under the RUNNING generation's grammar: a candidate whose fields do not read under it (a word
/// the running generation does not know) counts as changed.
pub struct Candidate {
    pub plugins: super::PluginsCfg,
    pub blocked_metadata_hosts: Vec<String>,
    /// `config.locked`: the document is managed in the file alone (no Store overlay applies).
    pub locked: bool,
    digest: Option<SecurityDigest>,
}

impl Candidate {
    /// An admin request body's `config` (the `config.yaml` shape), with the Store's `overlay`.
    pub fn of_json(
        config: &serde_json::Value,
        running: &super::Grammar,
        overlay: Option<&super::overlay::OverlayDoc>,
    ) -> Result<Self, String> {
        let subset = |keys: &[&str]| {
            serde_json::Value::Object(
                config
                    .as_object()
                    .map(|object| {
                        object
                            .iter()
                            .filter(|(key, _)| keys.contains(&key.as_str()))
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        };
        let policy = super::deploy_from_deserializer(
            subset(&["plugins", "security", "config"]),
            &no_words(),
        )
        .map_err(|e| format!("malformed config body: {e}"))?;
        let fields = super::deploy_from_deserializer(subset(SECURITY_KEYS), running).ok();
        Ok(Self::judged(policy, fields, overlay))
    }

    /// An interpolated deployment document (`config.yaml` with any durable patch), with the
    /// Store's `overlay`.
    pub fn of_yaml(
        text: &str,
        running: &super::Grammar,
        overlay: Option<&super::overlay::OverlayDoc>,
    ) -> Result<Self, String> {
        use busbar_contract::yaml::Value;
        let doc = busbar_contract::yaml::from_str::<Value>(text)
            .map_err(|e| format!("config.yaml: invalid YAML: {e}"))?;
        let subset = |keys: &[&str]| match &doc {
            Value::Map(pairs) => Value::Map(
                pairs
                    .iter()
                    .filter(|(key, _)| key.as_text().is_some_and(|key| keys.contains(&key)))
                    .cloned()
                    .collect(),
            ),
            _ => Value::Map(Vec::new()),
        };
        let policy =
            super::deploy_from_yaml_value(subset(&["plugins", "security", "config"]), &no_words())
                .map_err(|e| format!("config.yaml: {e}"))?;
        let fields = super::deploy_from_yaml_value(subset(SECURITY_KEYS), running).ok();
        Ok(Self::judged(policy, fields, overlay))
    }

    fn judged(
        mut policy: super::DeployCfg,
        fields: Option<super::DeployCfg>,
        overlay: Option<&super::overlay::OverlayDoc>,
    ) -> Self {
        if let Some(doc) = overlay {
            if let Some(root) = &doc.root {
                root.apply_to_deploy(&mut policy);
            }
            super::overlay::apply_plugin_versions_to_deploy(&mut policy, doc);
        }
        let digest = fields.and_then(|mut deploy| {
            if let Some(doc) = overlay {
                super::overlay::apply_root_to_deploy(&mut deploy, doc).ok()?;
            }
            let mut errors = Vec::new();
            let auth = deploy
                .auth
                .as_ref()
                .map(|auth| super::resolve_auth(auth, &deploy.identity_providers, &mut errors));
            let security = deploy.security.clone().unwrap_or_default();
            Some(security_digest(&SecurityView {
                auth: auth.as_ref(),
                identity_providers: &deploy.identity_providers,
                secrets: &deploy.secrets,
                credentials: &deploy.credentials,
                tls: deploy.tls.as_ref(),
                admin_tls: deploy.admin_tls.as_ref(),
                admin_listen: &deploy.admin_listen,
                blocked_metadata_hosts: &security.blocked_metadata_hosts,
                allow_metadata_hosts: &security.allow_metadata_hosts,
                allow_all_metadata: security.allow_all_metadata,
                plugins: &deploy.plugins,
            }))
        });
        let blocked_metadata_hosts = policy
            .security
            .clone()
            .unwrap_or_default()
            .blocked_metadata_hosts;
        Self {
            locked: policy.config.locked,
            plugins: policy.plugins,
            blocked_metadata_hosts,
            digest,
        }
    }
}

/// The grammar of a block that holds no secret reference (`plugins:`, `security:`).
fn no_words() -> super::Grammar {
    super::Grammar::new(
        busbar_contract::secret_ref::Sugars::default(),
        std::collections::BTreeMap::new(),
        Vec::new(),
    )
}

/// THE AUTHORITY PRE-CHECK (SECRET-SHORTHAND-BOOT §3.12): the field classes `candidate` changes
/// against the running generation, when `authority` is not full-operator; `None` when the caller
/// may proceed (no HTTP principal, full-operator authority, or nothing security-relevant changed).
/// It reads nothing from `plugins.dir` and reaches no network: every reload-class operation runs it
/// before any fetch or scan, and admin validate answers `needs full operator` where it refuses.
#[must_use]
pub fn needs_full_operator(
    current: &App,
    candidate: &Candidate,
    authority: Option<Authority>,
) -> Option<Vec<&'static str>> {
    if authority?.full_operator {
        return None;
    }
    let running = current
        .configured_view
        .as_ref()
        .map(|view| &view.security_digest);
    let changed = match (running, candidate.digest.as_ref()) {
        (_, None) => vec![UNREAD_UNDER_RUNNING],
        (None, Some(digest)) => digest.classes(),
        (Some(running), Some(digest)) => running.changed(digest),
    };
    (!changed.is_empty()).then_some(changed)
}

/// [`needs_full_operator`] inside a config transaction, under the authority the transaction
/// holds: refused as [`TxnError::Forbidden`], before the operation fetches or scans anything.
pub fn precheck(current: &App, candidate: &Candidate) -> Result<(), TxnError> {
    let authority = BUILD_AUTHORITY.with(|held| held.borrow().authority);
    match needs_full_operator(current, candidate, authority) {
        Some(_) => Err(TxnError::Forbidden),
        None => Ok(()),
    }
}

/// `plugins.fetch` as written: what a reload downloads into `plugins.dir` before it scans, so a
/// change is security-relevant (SECRET-SHORTHAND-BOOT F10). An `{env: NAME}` entry contributes its
/// variable's name, never its value.
fn fetch_digest(fetch: &[super::PluginFetch]) -> Vec<serde_json::Value> {
    fetch
        .iter()
        .map(|entry| match entry {
            super::PluginFetch::Github(g) => json!({"github": g.github, "sha256": g.sha256}),
            super::PluginFetch::Url(u) => json!({"url": u.url, "sha256": u.sha256}),
            super::PluginFetch::Env(e) => json!({"env": e.env}),
        })
        .collect()
}

fn security_changed(current: &App, next: &App) -> bool {
    current.admin_chain != next.admin_chain
        || current.role_bindings != next.role_bindings
        || current.identity_providers != next.identity_providers
        || current.auth_scope_caps != next.auth_scope_caps
        || current
            .configured_view
            .as_ref()
            .map(|v| (&v.security_digest, v.deployment_security_digest))
            != next
                .configured_view
                .as_ref()
                .map(|v| (&v.security_digest, v.deployment_security_digest))
}

pub(crate) fn admit(
    current: &App,
    next: &App,
    context: Option<&Context>,
    authority: Option<Authority>,
) -> Result<(), TxnError> {
    // Internal boot/kernel maintenance has no HTTP principal. Every admin transport installs the
    // host context; detached effects must explicitly carry it. No privilege is derived from ids.
    let Some(authority) = authority else {
        return Ok(());
    };
    admit_fields(
        current,
        &next.admin_chain,
        &next.identity_providers,
        &next.hook_registry,
    )?;
    if security_changed(current, next) {
        if !authority.full_operator {
            return Err(TxnError::Forbidden);
        }
        // The named auth-chain operation's self-lockout rule applies equally to document/apply/
        // parent replacement/reset/reload. This is a probe, not a second replay-claim spend.
        if current.admin_chain != next.admin_chain
            && context.is_some_and(|context| !context.survives(next))
        {
            return Err(TxnError::Conflict(
                "the proposed admin chain does not preserve this operator's full authority".into(),
            ));
        }
    }
    Ok(())
}

fn admit_fields(
    current: &App,
    chain: &[String],
    providers: &super::IdentityProviders,
    hooks: &std::collections::HashMap<String, super::HookCfg>,
) -> Result<(), TxnError> {
    if !current.admin_chain.is_empty() && chain.is_empty() {
        return Err(TxnError::Conflict("a protected deployment cannot clear admin_auth through the admin API; select open development posture at startup".into()));
    }
    // A provider ceiling is immutable upward through EVERY API representation, including full
    // operators. Removing a definition cannot smuggle a higher ceiling in under the same name.
    use busbar_contract::authz::Scope;
    for (name, provider) in providers {
        let ceiling = |token: Option<&str>| token.and_then(Scope::parse).unwrap_or(Scope::ReadOnly);
        let old = ceiling(
            current
                .identity_providers
                .get(name)
                .and_then(|p| p.max_admin_scope.as_deref()),
        );
        if !old.allows(ceiling(provider.max_admin_scope.as_deref())) {
            return Err(TxnError::Conflict(format!(
                "refusing to raise identity-providers.{name}.max_admin_scope through the admin API"
            )));
        }
    }
    for (name, hook) in hooks {
        if let Some(old) = current.hook_registry.get(name) {
            if (old.kind, old.prompt, old.user) != (hook.kind, hook.prompt, hook.user) {
                return Err(TxnError::Conflict(format!(
                    "hook {name} grants are immutable; delete and re-register to change them"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct BuildAuthority {
    authority: Option<Authority>,
    refusal: Option<TxnError>,
}

thread_local! {
    static BUILD_AUTHORITY: std::cell::RefCell<BuildAuthority> = std::cell::RefCell::default();
}

// The synchronous transaction owns the context on this thread, including while builders open
// plugins. Restore it on unwinding too; a blocking worker must never lend it to its next job.
pub(super) fn scoped<T, E: From<TxnError>>(
    authority: Option<Authority>,
    body: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    struct Reset(Option<BuildAuthority>);
    impl Drop for Reset {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                BUILD_AUTHORITY.with(|held| {
                    held.replace(previous);
                });
            }
        }
    }
    let previous = BUILD_AUTHORITY.with(|held| {
        held.replace(BuildAuthority {
            authority,
            refusal: None,
        })
    });
    let _reset = Reset(Some(previous));
    let result = body();
    match result {
        Err(error) => match BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal.take()) {
            Some(refusal) => Err(E::from(refusal)),
            None => Err(error),
        },
        ok => ok,
    }
}

/// Restore synchronous builder authority separately on every future poll. No thread-local
/// authority is left installed when native persistence yields to another task.
pub(super) async fn scoped_async<T, E: From<TxnError>>(
    authority: Option<Authority>,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut future = std::pin::pin!(future);
    let mut refusal = None;
    std::future::poll_fn(move |context| {
        match scoped(authority, || {
            if let Some(saved) = refusal.take() {
                BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(saved));
            }
            match future.as_mut().poll(context) {
                std::task::Poll::Pending => {
                    refusal = BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal.take());
                    Ok(std::task::Poll::Pending)
                }
                std::task::Poll::Ready(result) => result.map(std::task::Poll::Ready),
            }
        }) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(value)) => std::task::Poll::Ready(Ok(value)),
            Err(error) => std::task::Poll::Ready(Err(error)),
        }
    })
    .await
}

/// Same semantic rules, before builder work can open a proposed auth/secret/plugin instance.
/// The transaction transports the typed refusal through the builder's existing String API.
pub(crate) fn check_candidate(
    current: Option<&App>,
    cfg: &super::RootCfg,
    plugins: &super::PluginsCfg,
) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    let Some(authority) = BUILD_AUTHORITY.with(|held| held.borrow().authority) else {
        return Ok(());
    };
    let result = admit_fields(
        current,
        &cfg.admin_auth,
        &cfg.identity_providers,
        &cfg.hooks,
    )
    .and_then(|()| {
        let changed = current
            .configured_view
            .as_ref()
            .is_none_or(|view| view.security_digest != root_digest(cfg, plugins));
        if changed && !authority.full_operator {
            Err(TxnError::Forbidden)
        } else {
            Ok(())
        }
    });
    result.map_err(|refusal| {
        let message = refusal.message();
        BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(refusal));
        message
    })
}

#[cfg(test)]
#[path = "tests/security_policy_tests.rs"]
mod async_scope_tests;
