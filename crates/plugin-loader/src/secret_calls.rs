// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S CALLS over the one dispatcher (THE DESIGN, "Plugins" and the plugin ABI; TODO step 28): the
//! contract's [`SecretAxis`] and [`SecretCalls`], implemented here over [`Plugin`]`<`[`Secret`]`>`.
//! [`SecretRows`] holds every secret plugin the composition root admitted — a compiled-in row (its
//! linked door) and a dropped-in one (its verified library, discovered off its signed manifest) —
//! as the [`Candidate`]s the boot stages read, and loads each through the one loader path
//! ([`load_linked`] / [`load_dropped_bytes`]) only when a reference first names it. Nothing here
//! reads which door a plugin came in by once it is loaded.
//!
//! `open` is a ticket-less crossing (it may not pend); `resolve` is submitted on a ticket and the
//! calling thread waits for its answer, which may PEND (the dispatcher's worker drives it). The
//! material is copied out of the plugin's lease into a [`Redacted`] and the lease is released before
//! `resolve` returns, so no plugin memory outlives the call. An instance is closed when its last
//! handle drops.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::{slot, ResolveIn, ResolveOut, ERROR_KIND_INTERNAL};
use busbar_contract::conn::DeclaredConns;
use busbar_contract::redacted::Redacted;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use crate::boot::{Candidate, Origin};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, now_ns, out_head, Bind, Dispatcher, Frame, NoSink,
    Plugin, NO_BLOB,
};

/// How long a `resolve` may pend before the dispatcher cancels it (the Call budget).
const CALL_DEADLINE: Duration = Duration::from_secs(30);

/// The longest the calling thread waits for one answer: past the Call budget, so the dispatcher's
/// own cancel ends a slow op first; this bounds a wait on a dispatcher that stopped.
const WAIT: Duration = Duration::from_secs(40);

/// How many calls one secret instance holds in flight, at most.
const MAX_INFLIGHT_CAP: u32 = 16;

/// ONE OPENED SECRET PLUGIN INSTANCE: its calls through the one dispatcher. Closed on drop.
pub struct LoadedSecret {
    plugin: Plugin<Secret>,
    dispatcher: Arc<Dispatcher>,
    next_worker: AtomicU32,
}

impl std::fmt::Debug for LoadedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedSecret")
            .field("plugin", &self.plugin.name())
            .finish_non_exhaustive()
    }
}

/// `bytes` as a blob the host owns for the call (`NO_BLOB` when empty).
fn blob(bytes: &[u8], fmt: u32, flags: u32) -> Blob {
    if bytes.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags,
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

impl LoadedSecret {
    /// `open` `plugin` over its module `settings` (JSON bytes, empty = none) and the material its
    /// Statement's `secret_refs` resolved to, in order, on `dispatcher`.
    ///
    /// # Errors
    /// The plugin's refusal, in 1.5.5's words (`plugin '<name>' open failed: <reason>`).
    pub fn open(
        plugin: Plugin<Secret>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        secrets: &[Redacted<Vec<u8>>],
    ) -> Result<Self, String> {
        let lent: Vec<Blob> = secrets
            .iter()
            .map(|s| blob(s.expose_secret(), BLOB_OCTETS, BLOB_SECRET))
            .collect();
        let mut f = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings, BLOB_JSON, 0),
                secrets: lent.as_ptr(),
                secrets_len: lent.len(),
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let c = plugin.call(life::OPEN, &mut f);
        if c.outcome != Outcome::Ready {
            return Err(c.open_failure(plugin.name()));
        }
        Ok(Self {
            plugin,
            dispatcher,
            next_worker: AtomicU32::new(0),
        })
    }

    /// The plugin's Statement name.
    pub fn name(&self) -> &str {
        self.plugin.name()
    }

    /// Hand `lease` back (ticket-less; a release never pends).
    fn release(&self, lease: u64) {
        let mut f = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        let _ = self.plugin.call(life::RELEASE, &mut f);
    }
}

impl Drop for LoadedSecret {
    fn drop(&mut self) {
        let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        let _ = self.plugin.call(life::CLOSE, &mut f);
    }
}

impl SecretCalls for LoadedSecret {
    fn resolve(&self, settings: &[u8]) -> Result<Redacted<Vec<u8>>, SecretRefused> {
        let name = self.plugin.name();
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' could not be called: no ticket"),
            ));
        };
        // The settings ride with the job: a crossing the watchdog answered still owns them until
        // it returns.
        let owned: Arc<Vec<u8>> = Arc::new(settings.to_vec());
        let frame = Frame::new(
            ResolveIn {
                head: in_head(),
                settings: blob(&owned, BLOB_JSON, 0),
            },
            ResolveOut {
                head: out_head(),
                secret: NO_BLOB,
                error_kind: 0,
                _reserved: 0,
            },
        );
        let deadline = now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64);
        let done = self
            .dispatcher
            .submit_lent(
                &self.plugin,
                ticket,
                slot::RESOLVE,
                frame,
                DeadlineClass::Call,
                deadline,
                owned,
            )
            .wait(WAIT);
        self.dispatcher.recycle(ticket);
        let Some(done) = done else {
            return Err(refused(
                ERROR_KIND_INTERNAL,
                format!("secret module '{name}' did not answer its resolve"),
            ));
        };
        let text = |fallback: String| {
            done.error
                .as_deref()
                .map(|e| String::from_utf8_lossy(e).into_owned())
                .filter(|t| !t.is_empty())
                .unwrap_or(fallback)
        };
        match (done.outcome, done.frame.as_deref()) {
            (Outcome::Ready, Some(f)) => {
                let b = f.out.secret;
                // SAFETY: a READY resolve's `secret` names plugin memory held under the answer's
                // lease until `release` (the secret kind's answer rule, checked by `check_resolve`
                // before this answer was settled); it is copied here, before the release below.
                let material = if b.ptr.is_null() || b.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
                };
                let material = Redacted::new(material);
                if done.lease != 0 {
                    self.release(done.lease);
                }
                Ok(material)
            }
            (Outcome::Failed | Outcome::Refused, f) => Err(refused(
                f.map_or(ERROR_KIND_INTERNAL, |f| f.out.error_kind),
                text(format!("secret module '{name}' failed to resolve")),
            )),
            (o, _) => Err(refused(
                ERROR_KIND_INTERNAL,
                text(format!("secret module '{name}' answered {o:?} to resolve")),
            )),
        }
    }
}

/// THE PROCESS'S SECRET PLUGINS, by Statement name and alias: the linked rows (fixed at build) and
/// the dropped-in ones (replaced at each registry build), each loaded on first use through the one
/// loader and called through the one dispatcher. A linked row answers ahead of a dropped-in plugin
/// spelling the same word (the boot stages' selection rule). The composition root builds it and
/// installs it as the kernel's [`SecretAxis`].
pub struct SecretRows {
    /// The process dispatcher, asked for at first use: a plugin is opened on it, never before.
    dispatcher: fn() -> Arc<Dispatcher>,
    /// The host's one connection table, asked for at each load: a plugin that declares a need (a
    /// dropped-in vault's http exchange) is declared on it and lent its connector.
    conns: fn() -> Option<Arc<dyn DeclaredConns>>,
    linked: Vec<Candidate>,
    dropped: RwLock<Vec<Candidate>>,
    shared: Mutex<BTreeMap<String, Arc<LoadedSecret>>>,
}

impl std::fmt::Debug for SecretRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |c: &[Candidate]| c.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        f.debug_struct("SecretRows")
            .field("linked", &names(&self.linked))
            .field(
                "dropped",
                &names(&self.dropped.read().unwrap_or_else(PoisonError::into_inner)),
            )
            .finish_non_exhaustive()
    }
}

/// Whether config names `c` by `word` (its name or an alias).
fn answers(c: &Candidate, word: &str) -> bool {
    c.name == word || c.aliases.iter().any(|a| a == word)
}

impl SecretRows {
    /// No rows yet; every instance opens on the dispatcher `dispatcher` answers, asked for at the
    /// first open (so the rows can be built before the process dispatcher is), its needs declared on
    /// the connection table `conns` answers.
    pub fn new(
        dispatcher: fn() -> Arc<Dispatcher>,
        conns: fn() -> Option<Arc<dyn DeclaredConns>>,
    ) -> Self {
        Self {
            dispatcher,
            conns,
            linked: Vec::new(),
            dropped: RwLock::new(Vec::new()),
            shared: Mutex::new(BTreeMap::new()),
        }
    }

    /// Add a COMPILED-IN secret plugin by its door: its Statement is rendered and read here (the
    /// door's head and Statement checks); nothing is loaded or opened.
    ///
    /// # Errors
    /// The door's refusal, or a door of another kind.
    pub fn link(&mut self, door: DoorFn) -> Result<&mut Self, String> {
        let c = Candidate::linked(door)?;
        if c.kind != KindCode::Secret {
            return Err(format!(
                "`{}` is a {:?} door, not a secret one",
                c.name, c.kind
            ));
        }
        self.linked.push(c);
        Ok(self)
    }

    /// The DROPPED-IN secret plugins: every secret-kind candidate among `candidates` (the registry's
    /// discovered rows), replacing the last set.
    pub fn set_dropped(&self, candidates: impl IntoIterator<Item = Candidate>) {
        let secrets = candidates
            .into_iter()
            .filter(|c| c.kind == KindCode::Secret)
            .collect();
        *self.dropped.write().unwrap_or_else(PoisonError::into_inner) = secrets;
    }

    /// The candidate `module` names, linked first; `None` when no row answers it.
    fn find(&self, module: &str) -> Option<Candidate> {
        self.linked
            .iter()
            .find(|c| answers(c, module))
            .cloned()
            .or_else(|| {
                self.dropped
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .find(|c| answers(c, module))
                    .cloned()
            })
    }

    /// Load `c` through the one loader, bound under its own name.
    fn load(&self, c: &Candidate) -> Result<Plugin<Secret>, String> {
        let bind = Bind {
            instance: Arc::from(c.name.as_str()),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: Arc::new(NoSink),
            dispatcher: (self.dispatcher)().adopter(),
            conns: (self.conns)(),
        };
        match &c.origin {
            Origin::Linked(row) => load_linked::<Secret>(row, bind),
            Origin::Dropped { file, bytes } => {
                load_dropped_bytes::<Secret>(bytes, file, &c.stated, bind)
            }
        }
        .map_err(|e| format!("secret module '{}' could not be loaded: {e}", c.name))
    }

    /// The settings keys `c`'s Statement names as secret references.
    fn secret_refs(c: &Candidate) -> Result<Vec<String>, String> {
        busbar_contract::abi::mechanism::rendering::read(&c.stated)
            .map(|r| r.secret_refs)
            .map_err(|e| {
                format!(
                    "secret module '{}': its Statement does not read back (byte {}: {})",
                    c.name, e.at, e.what
                )
            })
    }
}

impl SecretAxis for SecretRows {
    fn answers(&self, module: &str) -> bool {
        self.find(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        self.linked.iter().any(|c| answers(c, module))
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .linked
            .iter()
            .find(|c| answers(c, module))
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))?;
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = shared.get(&c.name) {
            return Ok(s.clone());
        }
        let s = Arc::new(LoadedSecret::open(
            self.load(c)?,
            (self.dispatcher)(),
            &[],
            &[],
        )?);
        shared.insert(c.name.clone(), s.clone());
        Ok(s)
    }

    fn open(
        &self,
        module: &str,
        settings: &serde_json::Value,
        resolve: &dyn Fn(&SecretRef) -> Result<Vec<u8>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        let c = self
            .find(module)
            .ok_or_else(|| format!("no secret module answers to '{module}'"))?;
        let mut secrets = Vec::new();
        for key in Self::secret_refs(&c)? {
            let material = match settings.get(&key) {
                None => Vec::new(),
                Some(v) => {
                    // The decoder's own text is withheld: the value may be the secret itself.
                    let r = serde_json::from_value::<SecretRef>(v.clone()).map_err(
                        crate::boot::not_a_reference(format!("secrets.{module}.settings.{key}")),
                    )?;
                    resolve(&r).map_err(|e| format!("secrets.{module}.settings.{key}: {e}"))?
                }
            };
            secrets.push(Redacted::new(material));
        }
        let bytes = if settings.is_null() {
            Vec::new()
        } else {
            settings.to_string().into_bytes()
        };
        Ok(Arc::new(LoadedSecret::open(
            self.load(&c)?,
            (self.dispatcher)(),
            &bytes,
            &secrets,
        )?))
    }
}

#[cfg(test)]
#[path = "tests/secret_calls_tests.rs"]
mod tests;
