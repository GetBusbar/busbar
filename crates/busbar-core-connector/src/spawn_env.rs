// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROGRAM'S ENVIRONMENT, RESOLVED AT CONFIG TIME AND HELD FOR ITS SPAWNS.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::config_time::ConfigScope;
use busbar_contract::kept::Text;
use busbar_contract::redacted::Secret;
use busbar_contract::secret_ref::SecretRef;

/// How a program's environment REFERENCE turns into its value: a string secret resolved through
pub type SpawnSecretFn = fn(&SecretRef, &ConfigScope) -> Result<Secret<String>, String>;

/// THE LINKED SPAWN RESOLVER: one member program's `env` reference, resolved at config time through
pub fn linked_spawn_secret(
    secret: &SecretRef,
    scope: &ConfigScope,
) -> Result<Secret<String>, String> {
    busbar_kernel::config::secret::resolve_linked_string_at_config(secret, scope)
}

/// How often a held environment is re-resolved, off the request path: the refresher's lease.
pub(crate) const SPAWN_ENV_LEASE: Duration = Duration::from_secs(60);

/// What a program's spawn hands its child now: every reference's value, name and value in the
pub struct Resolved(pub(crate) Result<Vec<(String, Secret<String>)>, Text>);

impl Resolved {
    /// The values, or the refusal: its reason as shared text, made once when the references were
    /// resolved, so a spawn it refuses shares the words and copies none.
    pub fn env(&self) -> Result<&[(String, Secret<String>)], &Text> {
        self.0.as_deref()
    }
}

/// One program's environment references and what they resolved to at the last load or refresh.
pub(crate) struct SpawnEnv {
    pub(crate) refs: Vec<(String, SecretRef)>,
    /// How the references resolve: what the connector that loaded this environment was handed.
    pub(crate) secrets: Option<SpawnSecretFn>,
    pub(crate) held: arc_swap::ArcSwap<Resolved>,
    /// Taken by a reload alone, so two reloads never race their stores; no spawn ever waits on it.
    pub(crate) reloading: Mutex<()>,
}

/// A program's HELD ENVIRONMENT, shared by the need that declared the program, the destination its
/// carrier dials and the host's admission of the spawn. Two are equal only when they are one.
#[derive(Clone)]
pub struct HeldEnv(pub(crate) Arc<SpawnEnv>);

impl PartialEq for HeldEnv {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HeldEnv {}

// A held environment NAMES NO VALUE in a debug line (its references' sources and whether they
// resolved): its Debug is in `off_path::lines`.

/// `refs` resolved now, through `secrets`, with the proof.
pub(crate) fn resolve(
    refs: &[(String, SecretRef)],
    secrets: Option<SpawnSecretFn>,
    scope: &ConfigScope,
) -> Resolved {
    Resolved(crate::off_path::lines::resolve_spawn_env(
        refs, secrets, scope,
    ))
}

impl HeldEnv {
    /// A program that writes no reference: nothing to resolve, nothing to refresh.
    #[must_use]
    pub fn written_only() -> Self {
        Self(Arc::new(SpawnEnv {
            refs: Vec::new(),
            secrets: None,
            held: arc_swap::ArcSwap::from_pointee(Resolved(Ok(Vec::new()))),
            reloading: Mutex::new(()),
        }))
    }

    /// RE-RESOLVE every reference, at config time, and swap what is held whole: a spawn sees the
    pub fn reload(&self, scope: &ConfigScope) {
        self.0.reload(scope);
    }

    /// What a spawn hands its child NOW: one load, no resolution, no lock.
    #[must_use]
    pub fn now(&self) -> Arc<Resolved> {
        self.0.held.load_full()
    }
}

impl SpawnEnv {
    fn reload(&self, scope: &ConfigScope) {
        if self.refs.is_empty() {
            return;
        }
        let _one = self
            .reloading
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.held
            .store(Arc::new(resolve(&self.refs, self.secrets, scope)));
    }

    /// The refresher's re-resolution, on its own thread: config time, off every request path.
    fn refresh(&self) {
        self.reload(&ConfigScope::config_time());
    }
}

/// THE HOST'S ENVIRONMENT REFRESHER: the host's one refresher (`busbar_kernel::refresh`), the same
/// bounded pool that keeps every served credential, renewing each held environment once a
/// [`SPAWN_ENV_LEASE`]. Its threads that cannot start stop the process (exit 2).
pub(crate) use refresher::keep;

mod refresher {
    use super::{SpawnEnv, SPAWN_ENV_LEASE};
    use std::sync::{Arc, Weak};
    use std::time::Instant;

    impl busbar_kernel::refresh::Refreshable for SpawnEnv {
        fn refresh(&self, now: Instant) -> Instant {
            SpawnEnv::refresh(self);
            now + SPAWN_ENV_LEASE
        }
    }

    /// Keep `env`, first due one lease from now (its load has just resolved it); the reason if
    /// the process's refresher did not start (the environment is then not kept fresh).
    pub(crate) fn keep(env: &Arc<SpawnEnv>) -> Result<(), &'static str> {
        busbar_kernel::refresh::keep(
            Arc::downgrade(env) as Weak<dyn busbar_kernel::refresh::Refreshable>,
            crate::off_path::lines::first_spawn_env_due(),
        )
    }

    /// Refresh every live held item NOW, on the calling thread (a cell that rotates a reference).
    #[cfg(test)]
    pub(crate) fn refresh_all() {
        busbar_kernel::refresh::process()
            .expect("the process refresher started")
            .refresh_all_now();
    }
}

/// [`refresher`]'s refresh of every live held environment, for this crate's cells.
#[cfg(test)]
pub(crate) fn refresh_all() {
    refresher::refresh_all();
}

#[cfg(test)]
pub(crate) use source_fixture::{
    counting_source, resolutions_of, set_source_value, source_reference, source_template,
};

/// Neutral source fixture: exercise config-time custody without interpreting any plugin's schema.
#[cfg(test)]
mod source_fixture {
    use super::*;
    use busbar_contract::secret::SecretResolve;
    use busbar_contract::secret_ref::Sugars;
    use busbar_kernel::config::secret::SecretResolver;
    use std::collections::BTreeMap;

    struct Entry {
        reference: SecretRef,
        value: Option<Secret<Vec<u8>>>,
        resolutions: usize,
    }
    static SOURCES: Mutex<BTreeMap<String, Entry>> = Mutex::new(BTreeMap::new());

    fn sources() -> Sugars {
        use busbar_contract::plugin_settings::sugar_words::{
            REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL,
        };
        let mut sources = Sugars::default();
        sources
            .declare(
                "test-spawn-source",
                &[
                    (REWRITE_SUGAR, "fixture".into(), "slot".into()),
                    (REWRITE_SUGAR_ROLE, "fixture".into(), SUGAR_ROLE_FILL.into()),
                ],
            )
            .unwrap();
        sources
    }
    pub(crate) fn source_reference(key: &str) -> SecretRef {
        let reference = sources().get("fixture").unwrap().reference(key);
        SOURCES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.into())
            .or_insert_with(|| Entry {
                reference: reference.clone(),
                value: None,
                resolutions: 0,
            });
        reference
    }
    pub(crate) fn source_template(text: impl Into<String>) -> SecretRef {
        SecretRef::template(text, &sources()).expect("fixture declares the fill source")
    }
    pub(crate) fn set_source_value(key: &str, value: Option<&str>) {
        source_reference(key);
        SOURCES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(key)
            .unwrap()
            .value = value.map(|v| Secret::new(v.as_bytes().to_vec()));
    }
    pub(crate) fn counting_source(
        reference: &SecretRef,
        scope: &ConfigScope,
    ) -> Result<Secret<String>, String> {
        let resolver = SecretResolver::with_plugin(Box::new(|module, settings| {
            let mut sources = SOURCES.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = sources
                .values_mut()
                .find(|entry| {
                    entry
                        .reference
                        .source()
                        .is_some_and(|s| s.module == module && &s.settings == settings)
                })
                .ok_or_else(|| "fixture source unavailable".to_owned())?;
            entry.resolutions += 1;
            entry
                .value
                .clone()
                .ok_or_else(|| "fixture source unavailable".to_owned())
        }));
        resolver.resolve_string_at_config(reference, scope)
    }
    pub(crate) fn resolutions_of(key: &str) -> usize {
        SOURCES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map_or(0, |e| e.resolutions)
    }
}
