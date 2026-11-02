// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROGRAM'S ENVIRONMENT, RESOLVED AT CONFIG TIME AND HELD FOR ITS SPAWNS.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::config_time::ConfigScope;
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
pub const SPAWN_ENV_LEASE: Duration = Duration::from_secs(60);

/// What a program's spawn hands its child now: every reference's value, name and value in the
pub struct Resolved(Result<Vec<(String, Secret<String>)>, String>);

impl Resolved {
    /// The values, or the refusal.
    pub fn env(&self) -> Result<&[(String, Secret<String>)], &str> {
        self.0.as_deref().map_err(String::as_str)
    }
}

/// One program's environment references and what they resolved to at the last load or refresh.
struct SpawnEnv {
    refs: Vec<(String, SecretRef)>,
    /// How the references resolve: what the connector that loaded this environment was handed.
    secrets: Option<SpawnSecretFn>,
    held: arc_swap::ArcSwap<Resolved>,
    /// Taken by a reload alone, so two reloads never race their stores; no spawn ever waits on it.
    reloading: Mutex<()>,
}

/// A program's HELD ENVIRONMENT, shared by the need that declared the program, the destination its
/// carrier dials and the host's admission of the spawn. Two are equal only when they are one.
#[derive(Clone)]
pub struct HeldEnv(Arc<SpawnEnv>);

impl PartialEq for HeldEnv {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HeldEnv {}

/// A held environment NAMES NO VALUE in a debug line: its references' sources and whether they
impl std::fmt::Debug for HeldEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let refs: Vec<String> = self
            .0
            .refs
            .iter()
            .map(|(name, reference)| format!("{name} = {}", reference.describe()))
            .collect();
        f.debug_struct("HeldEnv")
            .field("refs", &refs)
            .field("resolved", &self.0.held.load().0.is_ok())
            .finish()
    }
}

/// `refs` resolved now, through `secrets`, with the proof.
fn resolve(
    refs: &[(String, SecretRef)],
    secrets: Option<SpawnSecretFn>,
    scope: &ConfigScope,
) -> Resolved {
    Resolved(resolve_each(refs, secrets, scope))
}

fn resolve_each(
    refs: &[(String, SecretRef)],
    secrets: Option<SpawnSecretFn>,
    scope: &ConfigScope,
) -> Result<Vec<(String, Secret<String>)>, String> {
    let mut env = Vec::with_capacity(refs.len());
    for (name, reference) in refs {
        let secret = secrets.ok_or_else(|| {
            format!(
                "the program's environment `{name}` is a secret reference and no secret \
                 resolver is installed"
            )
        })?;
        let value = reference
            .resolve_template(&|r| {
                secret(r, scope).map(|held| held.expose(&busbar_kernel::seal::lend()).clone())
            })
            .map_err(|e| {
                format!(
                    "the program's environment `{name}` ({}) did not resolve: {e}",
                    reference.describe()
                )
            })?;
        env.push((name.clone(), Secret::new(value)));
    }
    Ok(env)
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

    /// `refs` RESOLVED NOW through `secrets` (the resolver the connector was handed; `None`
    #[must_use]
    pub fn load(
        refs: &[(String, SecretRef)],
        secrets: Option<SpawnSecretFn>,
        scope: &ConfigScope,
    ) -> Self {
        if refs.is_empty() {
            return Self::written_only();
        }
        let held = Self(Arc::new(SpawnEnv {
            refs: refs.to_vec(),
            secrets,
            held: arc_swap::ArcSwap::from_pointee(resolve(refs, secrets, scope)),
            reloading: Mutex::new(()),
        }));
        refresher::keep(&held.0);
        held
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

/// THE HOST'S ENVIRONMENT REFRESHER, as the host's credential refresher keeps a served credential:
mod refresher {
    use super::{SpawnEnv, SPAWN_ENV_LEASE};
    use std::sync::{Arc, Condvar, Mutex, Once, PoisonError, Weak};
    use std::time::Instant;

    struct Kept {
        env: Weak<SpawnEnv>,
        due: Instant,
    }

    struct Book {
        kept: Mutex<Vec<Kept>>,
        woken: Condvar,
    }

    static BOOK: Book = Book {
        kept: Mutex::new(Vec::new()),
        woken: Condvar::new(),
    };

    /// The process's one book, its thread started the first time it is reached. A thread the
    fn book() -> &'static Book {
        static STARTED: Once = Once::new();
        STARTED.call_once(|| {
            let _ = std::thread::Builder::new()
                .name("busbar-spawn-env-refresh".into())
                .spawn(|| run(&BOOK));
        });
        &BOOK
    }

    /// Keep `env`, first due one lease from now (its load has just resolved it).
    pub(super) fn keep(env: &Arc<SpawnEnv>) {
        let book = book();
        book.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Kept {
                env: Arc::downgrade(env),
                due: Instant::now() + SPAWN_ENV_LEASE,
            });
        book.woken.notify_one();
    }

    /// The thread: refresh every held environment that is due, forget every one dropped, sleep to
    fn run(book: &'static Book) {
        let mut kept = book.kept.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let now = Instant::now();
            kept.retain(|k| k.env.strong_count() > 0);
            let mut due = Vec::new();
            for k in kept.iter_mut().filter(|k| k.due <= now) {
                if let Some(env) = k.env.upgrade() {
                    k.due = now + SPAWN_ENV_LEASE;
                    due.push(env);
                }
            }
            if !due.is_empty() {
                drop(kept);
                for env in due {
                    env.refresh();
                }
                kept = book.kept.lock().unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let next = kept.iter().map(|k| k.due).min();
            kept = match next {
                Some(at) => {
                    book.woken
                        .wait_timeout(kept, at.saturating_duration_since(now))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => book
                    .woken
                    .wait(kept)
                    .unwrap_or_else(PoisonError::into_inner),
            };
        }
    }

    /// Refresh every live held environment NOW, on the calling thread (a cell that rotates a
    #[cfg(test)]
    pub(crate) fn refresh_all() {
        let live: Vec<Arc<SpawnEnv>> = book()
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|k| k.env.upgrade())
            .collect();
        for env in live {
            env.refresh();
        }
    }
}

/// [`refresher`]'s refresh of every live held environment, for this crate's cells.
#[cfg(test)]
pub(crate) fn refresh_all() {
    refresher::refresh_all();
}

/// THE CELLS' RESOLVER: an `env` reference reads its variable (nothing else resolves), and every
#[cfg(test)]
pub(crate) fn counting_env(r: &SecretRef, _scope: &ConfigScope) -> Result<Secret<String>, String> {
    let var = r
        .env_var()
        .ok_or_else(|| format!("{} does not resolve", r.describe()))?;
    *RESOLUTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(var.to_string())
        .or_insert(0) += 1;
    std::env::var(var)
        .map(Secret::new)
        .map_err(|_| format!("{} does not resolve", r.describe()))
}

#[cfg(test)]
static RESOLUTIONS: Mutex<std::collections::BTreeMap<String, usize>> =
    Mutex::new(std::collections::BTreeMap::new());

/// How many times [`counting_env`] resolved `var`.
#[cfg(test)]
pub(crate) fn resolutions_of(var: &str) -> usize {
    RESOLUTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(var)
        .copied()
        .unwrap_or(0)
}
