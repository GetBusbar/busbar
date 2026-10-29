// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROGRAM'S ENVIRONMENT, RESOLVED AT CONFIG TIME AND HELD FOR ITS SPAWNS (row 166, ARCHITECT
//! ruling 2026-10-13 on THE DESIGN §11.11 R4 as the OWNER amended it).
//!
//! A program's environment entries written as SECRET REFERENCES (`Program::env_refs`) resolve
//! when the need that names the program is DECLARED — a plane's load, a config apply — with the
//! config-time proof, and again on the refresher's lease, off the request path. A spawn only LOADS
//! what is held ([`HeldEnv::now`]): no resolution, no lock. A spawn is reached from a request (a
//! member program's first lease, a respawn after its child ended, every open of a program need), and
//! a secret resolution blocks its thread up to its deadline, so it is never made there. A reference
//! that no longer resolves at a refresh EMPTIES what is held (fail closed): every spawn after it is
//! refused, never handed a stale value; a running child keeps the environment it was spawned with.
//!
//! A ROTATED SECRET REACHES THE FIRST NEW CHILD AFTER THE NEXT REFRESH (at most one
//! [`SPAWN_ENV_LEASE`] after the rotation, or at the next config apply). Program members are new in
//! 1.6.0: there is no 1.5.5 timing to keep (ARCHITECT, 2026-10-13).
//!
//! The values live here, in the host's records, and in the child's environment: never in the table
//! that holds the program, never in the destination the carrier is handed.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::config_time::ConfigScope;
use busbar_contract::redacted::Secret;
use busbar_contract::secret_ref::SecretRef;

/// How a program's environment REFERENCE turns into its value: a string secret resolved through
/// the secret plugins the build links, at config time (it takes the proof). `Err` names the
/// reference's source, never a byte of the secret.
///
/// The composition root hands it to the connector it builds (`Connector::resolving_spawn_secrets`),
/// and the connector hands it to every environment it loads: no process-wide static holds it. A
/// connector handed none resolves no reference, and a program that states one is not spawned
/// (fail-closed). The value stays in its zeroizing holder until the environment is rendered.
pub type SpawnSecretFn = fn(&SecretRef, &ConfigScope) -> Result<Secret<String>, String>;

/// THE LINKED SPAWN RESOLVER: one member program's `env` reference, resolved at config time through
/// the linked secret plugins, still in its zeroizing holder. OWED (row 7): an environment template
/// is rendered as text, so the value leaves the holder when the template renders, into the
/// [`Secret`] the spawn holds.
///
/// # Errors
/// The reference does not resolve; the text names it, never a value.
pub fn linked_spawn_secret(
    secret: &SecretRef,
    scope: &ConfigScope,
) -> Result<Secret<String>, String> {
    busbar_kernel::config::secret::resolve_linked_string_at_config(secret, scope)
}

/// How often a held environment is re-resolved, off the request path: the refresher's lease.
pub const SPAWN_ENV_LEASE: Duration = Duration::from_secs(60);

/// What a program's spawn hands its child now: every reference's value, name and value in the
/// settings' order; or why the environment did not resolve (a refusal naming the variable and the
/// reference's source, never a value).
pub struct Resolved(Result<Vec<(String, Secret<String>)>, String>);

impl Resolved {
    /// The values, or the refusal.
    ///
    /// # Errors
    /// Why the environment did not resolve at its last load or refresh.
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
/// resolved.
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
    /// resolves nothing), at config time (`scope`: the need's declaration at a plane's load or a
    /// config apply), and kept on the refresher's lease from here on, through the same resolver.
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
    /// old environment or the new one; one that no longer resolves empties it (fail closed).
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

/// THE HOST'S ENVIRONMENT REFRESHER, as the host's credential refresher keeps a served credential
/// (#787's `PerHop`): one thread of its own (never a runtime worker) that re-resolves each live held
/// environment once per [`SPAWN_ENV_LEASE`]. It keeps each WEAKLY, so one its need dropped (a
/// re-declaration that changed the program, a plane that closed) is forgotten at its next due time.
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
    /// operating system will not give leaves every held environment as its load resolved it.
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
    /// the next due time (or a new one). The book's lock is never held across a refresh.
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
    /// secret, then asserts what the first new child after the refresh is handed).
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
/// resolution is counted by variable, so a cell can tell a spawn resolved nothing. A cell hands it
/// to the connector or the environment it builds.
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
