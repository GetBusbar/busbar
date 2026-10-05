// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE** (TODO ABI-b4; BUSBAR-1.6.0.md THE DESIGN §11.4 "compiled in
//! or dropped in, the same table", §11.11 M6/contract; Part 2 #2 and #11). OWNER 2026-10-03: *"NO
//! TEST PLUGINS. We have real plugins for everything. PLUGINS test themselves against busbar.
//! busbar doesn't test plugins."* So busbar PUBLISHES this suite and every real plugin repo RUNS it,
//! in its own CI (`plugin-ci.yml`'s conformance step), at the busbar commit it pins (§9).
//!
//! A plugin repo calls it from its own `tests/conformance.rs`, one line:
//!
//! ```ignore
//! busbar_plugin_loader::conformance_suite! {
//!     door: busbar_secret_env::door::door,          // the LINKED door (its logic crate's)
//!     cdylib: "busbar_secret_env_plugin",           // the crate whose cdylib is the DROPPED door
//!     inputs: include_str!("conformance.json"),     // what the kind's script drives
//! }
//! ```
//!
//! A NETWORKED plugin over a framed scheme, or one that secures a stream through the host's TLS,
//! names busbar's HOST connector too ([`Host`]: busbar's connector composed as production composes
//! it, carrier -> [TLS] -> framer, Q-P4-4), and, for TLS, the test CA its local endpoint's
//! certificate chains to; both go to the HOST, never to the plugin:
//!
//! ```ignore
//! busbar_plugin_loader::conformance_suite! {
//!     door: …, cdylib: …, inputs: …,
//!     host: <busbar's host connector, a `conformance::Host`>,
//!     tls: include_str!("test-ca.pem"),
//! }
//! ```
//!
//! with `busbar-plugin-loader = { git = …, rev = <the pin>, features = ["conformance"] }` as a
//! dev-dependency. The macro emits the suite's tests; `plugin-ci.yml` runs them under `--release`.
//!
//! WHAT ONE RUN PROVES, for the kind the door states:
//!
//! * the dropped-in library states exactly the linked door's Statement (the signed manifest's
//!   rendering IS the linked row's), and both are admitted by the ONE loader ([`load_linked`] /
//!   [`load_dropped`]) and bound to a dispatcher of their own, as the kernel binds them;
//! * the KIND'S SCRIPT (one module per kind, below) drives each leg through the same table, step by
//!   step, and records per step its answer and the crossings the instance made, counted by the
//!   dispatcher's own crossing gate;
//! * every step's crossings equal the count the script PINS, EXACTLY (M6/contract: never "above
//!   zero"), on both legs, and the two folds are equal step for step;
//! * the mechanism's optional `ready` (discovery at boot) is a step of every kind's script: a door
//!   that states none is not called (0 crossings); one that states it is awaited on a real ticket.
//!
//! THE CONNECTION TABLE (ARCHITECT, "SUITE CONNECTIONS"): a plugin whose Statement declares a
//! need the table serves (`tcp`: `host:port`, `unix:/path`) is bound, on each leg, to a connection
//! table of its own built the same way ([`Subject::conns`], the loader's test table
//! [`TcpConns`](crate::tcp_conns::TcpConns) over the leg dispatcher's conn waker), so a networked
//! plugin dials the REAL local endpoint its `conformance.json` settings name, through the host
//! connector's slots, reads PENDING and is woken. A plugin that declares no need is bound with no
//! table, as before (the loader hands a table only to a Statement with a need). With busbar's HOST
//! connector named (Q-P4-4: carrier -> [TLS] -> framer, as production composes it), every need over
//! any scheme it serves binds over that connector instead, and its TLS trusts the suite's test
//! anchors.
//!
//! THE RED ARMS, run in the plugin's own run: a perturbed pinned count is refused by the same
//! comparator; the door restated at its kind ABI ± 1 is refused, linked (`KindAbi`) and dropped in
//! (`ManifestKindAbi`, before `dlopen`); the door with a `ready` that fails refuses the boot with the
//! plugin's text; a networked door (the real one, or restated with a `tcp` need) bound to serve with
//! no connection table is refused at bind, naming the plugin. And `BUSBAR_CONFORMANCE_RED=count` perturbs the both-ways arm itself, so the CI
//! step can require that the suite FAILS when a count moves.
//!
//! THE SEAM (QUESTIONS, slot CONF-SUITE): the suite lives here, behind the `conformance` feature,
//! because this is the one crate that both links and dlopens through the one loader, and holds the
//! kernel's own host adapters (`store_v3::LoadedStore`). Everything a plugin repo names is in this
//! module; a move to another home moves this directory and the macro's path, nothing else.
//!
//! [`load_linked`]: crate::dispatch::load_linked
//! [`load_dropped`]: crate::dispatch::load_dropped

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::{self as rendering, RENDERING_MAGIC};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use busbar_contract::conn::DeclaredConns;

use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, rendering_of_library, Bind, Called,
    ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, Kind, LinkedRow, LoadError, NoSink,
    OutFrame, Plugin,
};
use crate::tcp_conns::TcpConns;

mod auth;
mod export;
mod hook;
mod plane;
mod secret;
mod store;
mod transport;

/// How long the suite waits for one `ready`: the boot's own budget.
pub const READY_DEADLINE: Duration = crate::dispatch::ready::READY_DEADLINE;

/// The environment variable that perturbs the both-ways arm (`count`): the CI step's RED run.
pub const RED_ENV: &str = "BUSBAR_CONFORMANCE_RED";

/// The environment variable that makes the suite refuse a debug build (`plugin-ci.yml` sets it
/// with `--release`: M6/contract, the release binary).
pub const EXPECT_RELEASE_ENV: &str = "BUSBAR_EXPECT_RELEASE";

/// The plugin under test: its linked door, the crate whose cdylib is its dropped-in door, and the
/// inputs its kind's script drives.
pub struct Subject {
    /// The LINKED door: the plugin's logic crate's door function, compiled into the test binary.
    pub door: DoorFn,
    /// The DROPPED door: the built cdylib of this crate (snake case), found in the test's target.
    pub cdylib_crate: &'static str,
    /// The plugin's `conformance.json`.
    pub inputs: serde_json::Value,
    /// THE HOST CONNECTOR the suite binds a networked plugin over (`conformance_suite! { …, host: …
    /// }`): busbar's own connector, composed as the root composes it ([`Host`]). `None`: the
    /// loader's test table ([`TcpConns`], plain `tcp` only).
    pub host: Option<Host>,
    /// TEST TRUST ANCHORS (CA certificates, PEM) for the HOST connector's TLS
    /// (`conformance_suite! { …, tls: … }`): never handed to the plugin.
    pub anchors: Option<String>,
    /// THE PER-FOLD NAMESPACE HOOKS (`conformance_suite! { …, namespace: (create, drop) }`):
    /// `create` makes a fold's namespace before its open, `drop` removes it after the fold.
    pub namespace: Option<(NamespaceHook, NamespaceHook)>,
}

/// A per-fold namespace hook: called with the fold's namespace (what [`FOLD`] was filled with) and
/// the fold's filled settings. The PLUGIN implements it with its own test client (a store that never
/// creates a schema on demand: `CREATE SCHEMA` / `DROP SCHEMA … CASCADE`); nothing in the store's
/// behaviour changes.
pub type NamespaceHook = fn(&str, &[u8]);

/// One fold's settings, its [`FOLD`] filled with a namespace of its own, created by the subject's
/// `create` hook when it was made and dropped by its `drop` hook when this goes (the fold's end,
/// its failure included). Reads as the settings bytes.
pub struct FoldSettings<'s> {
    subject: &'s Subject,
    namespace: String,
    settings: Vec<u8>,
}

impl FoldSettings<'_> {
    /// The fold's namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl std::fmt::Debug for FoldSettings<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoldSettings")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for FoldSettings<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.settings
    }
}

impl Drop for FoldSettings<'_> {
    fn drop(&mut self) {
        let Some((_, drop)) = self.subject.namespace else {
            return;
        };
        if std::thread::panicking() {
            // The fold failed: drop its namespace still, never turning the failure into an abort.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(&self.namespace, &self.settings);
            }));
        } else {
            drop(&self.namespace, &self.settings);
        }
    }
}

/// The suite's HOST CONNECTOR, as the busbar side builds it for one leg: its parked reads woken
/// through the leg dispatcher's conn waker, its TLS trusting the test anchors (PEM) when named.
/// INJECTED, never named here: this crate cannot depend on the connector (the connector depends on
/// the kernel, which depends on this crate), so the busbar side that composes it hands it in.
pub type Host = fn(Arc<dyn Fn(u64) + Send + Sync>, Option<&str>) -> Arc<dyn DeclaredConns>;

impl Subject {
    /// `inputs` is the plugin's `conformance.json` text.
    ///
    /// # Panics
    /// When `inputs` is not a JSON object.
    #[must_use]
    pub fn new(door: DoorFn, cdylib_crate: &'static str, inputs: &str) -> Self {
        let inputs: serde_json::Value = serde_json::from_str(inputs)
            .unwrap_or_else(|e| panic!("conformance.json is not JSON: {e}"));
        assert!(inputs.is_object(), "conformance.json is not a JSON object");
        Self {
            door,
            cdylib_crate,
            inputs,
            host: None,
            anchors: None,
            namespace: None,
        }
    }

    /// Each fold's namespace is made by `create` before its open and removed by `drop` after it
    /// (Q-P4-8).
    #[must_use]
    pub fn with_namespace(mut self, create: NamespaceHook, drop: NamespaceHook) -> Self {
        self.namespace = Some((create, drop));
        self
    }

    /// One fold's settings, tagged `tag` (its leg, or the RED arm that opens): [`FOLD`] filled with
    /// a namespace no other fold uses ([`fold_namespace`]), made by the `create` hook now and
    /// removed by the `drop` hook when the returned settings go.
    #[must_use]
    pub fn fold_settings(&self, tag: &str) -> FoldSettings<'_> {
        let namespace = fold_namespace(tag);
        let settings = self.settings_in(&namespace);
        if let Some((create, _)) = self.namespace {
            create(&namespace, &settings);
        }
        FoldSettings {
            subject: self,
            namespace,
            settings,
        }
    }

    /// This subject's networked needs bind over `host` (the busbar side's host connector).
    #[must_use]
    pub fn with_host(mut self, host: Host) -> Self {
        self.host = Some(host);
        self
    }

    /// The host connector's TLS trusts `pem` (test CA certificates) too.
    #[must_use]
    pub fn with_anchors(mut self, pem: &str) -> Self {
        self.anchors = Some(pem.to_owned());
        self
    }

    /// The kind the linked door states.
    ///
    /// # Panics
    /// When the door is NULL or names no kind.
    #[must_use]
    pub fn kind(&self) -> KindCode {
        let p = (self.door)();
        assert!(!p.is_null(), "the door function answered NULL");
        // SAFETY: a door function answers a `'static` door; only its `kind` word is read.
        let raw = unsafe { std::ptr::addr_of!((*p).kind).read_unaligned() };
        KindCode::from_raw(raw).unwrap_or_else(|| panic!("the door names kind {raw}"))
    }

    /// The dropped-in library: this crate's cdylib in the test binary's target directory, uplifted
    /// or under `deps` with its metadata hash, newest wins. A missing one is a FAILURE: this suite
    /// IS the dropped-in door's proof, and never skips.
    ///
    /// # Panics
    /// When the cdylib is not built.
    #[must_use]
    pub fn cdylib(&self) -> PathBuf {
        cdylib_of(self.cdylib_crate)
    }

    /// The Statement rendering the signed manifest states: the dropped-in library's own.
    ///
    /// # Panics
    /// When the library does not load or exports no door.
    #[must_use]
    pub fn stated(&self) -> Vec<u8> {
        rendering_of_library(&self.cdylib())
            .unwrap_or_else(|e| panic!("the cdylib's Statement does not render: {e}"))
            .expect("the cdylib exports busbar_plugin_door")
    }

    /// The settings the plugin opens over (`inputs.settings`, a JSON value, serialized), its
    /// [`FOLD`] placeholder filled with a namespace of its own ([`fold_namespace`]`("suite")`).
    #[must_use]
    pub fn settings(&self) -> Vec<u8> {
        self.settings_in(&fold_namespace("suite"))
    }

    /// The settings the plugin opens over, every [`FOLD`] placeholder in them replaced by
    /// `namespace` (Q-P4-8: each fold writes into its own schema or key prefix). Settings that name
    /// no placeholder are exactly `inputs.settings`.
    #[must_use]
    pub fn settings_in(&self, namespace: &str) -> Vec<u8> {
        let raw = match self.inputs.get("settings") {
            None | Some(serde_json::Value::Null) => b"{}".to_vec(),
            Some(serde_json::Value::String(s)) => s.as_bytes().to_vec(),
            Some(v) => v.to_string().into_bytes(),
        };
        let text = String::from_utf8_lossy(&raw);
        if text.contains(FOLD) {
            text.replace(FOLD, namespace).into_bytes()
        } else {
            raw
        }
    }

    /// The kind's own inputs (`inputs.<kind>`), `Null` when absent.
    #[must_use]
    pub fn kind_inputs(&self, kind: &str) -> &serde_json::Value {
        self.inputs.get(kind).unwrap_or(&serde_json::Value::Null)
    }

    /// The needs the linked door's Statement declares (the dropped-in library states the same
    /// Statement: [`both_ways`] proves it), in Statement order.
    ///
    /// # Panics
    /// When the door's Statement does not render or read back.
    #[must_use]
    pub fn needs(&self) -> Vec<rendering::ReadNeed> {
        let row =
            LinkedRow::of(self.door).unwrap_or_else(|e| panic!("the linked door is refused: {e}"));
        rendering::read(&row.statement)
            .unwrap_or_else(|e| panic!("the door's Statement does not read back: {e:?}"))
            .needs
    }

    /// THE LEG'S CONNECTION TABLE, built the same way for the linked and the dropped-in leg: the
    /// loader's test table ([`TcpConns`]) waking a parked read's ticket through `d`'s conn waker,
    /// when the Statement declares a need and the table serves every one it declares (`tcp`; a need
    /// naming no transport asks for none). `None` when it declares no need (bound as before), or a
    /// need over a scheme the table does not serve (`http`, `https`, ...: the host connector's
    /// framing, which the test table has not; bound with no table, as before). `upgrade_secure` is
    /// refused: the table secures no stream (it names no TLS library).
    ///
    /// With a HOST connector ([`Subject::host`]) every need, over any scheme it serves (`tcp`,
    /// `http`, `https`, …), binds over it, built the same way for each leg; its TLS trusts the
    /// subject's [`Subject::anchors`].
    ///
    /// # Panics
    /// Test anchors are named with no host connector to trust them.
    #[must_use]
    pub fn conns(&self, d: &Dispatcher) -> Option<Arc<dyn DeclaredConns>> {
        let needs = self.needs();
        if needs.is_empty() {
            return None;
        }
        if let Some(host) = self.host {
            return Some(host(d.conn_waker(), self.anchors.as_deref()));
        }
        assert!(
            self.anchors.is_none(),
            "conformance_suite!'s `tls:` anchors are the HOST connector's: name its `host:` too"
        );
        let table = TcpConns::new(d.conn_waker());
        let served = needs
            .iter()
            .all(|n| n.transport.is_empty() || table.serves_scheme(&n.transport));
        (!needs.is_empty() && served).then(|| Arc::new(table) as Arc<dyn DeclaredConns>)
    }

    /// The bind the kernel makes for this plugin on `d` ([`bind`]), SERVING over the leg's
    /// connection table ([`Subject::conns`]); a door that declares no need serves with none. (A
    /// need over a scheme the test table does not serve binds as a probe: no table, not refused.)
    #[must_use]
    pub fn bind(&self, d: &Dispatcher, instance: &str) -> Bind {
        let conns = match self.conns(d) {
            Some(table) => ConnTable::Host(table),
            None if self.needs().is_empty() => ConnTable::NoNeeds,
            None => ConnTable::Probe,
        };
        Bind {
            conns,
            ..bind(d, instance)
        }
    }

    /// Set the environment the plugin's inputs name (`inputs.env`: name → value; `null` unsets).
    pub fn apply_env(&self) {
        let Some(env) = self.inputs.get("env").and_then(|e| e.as_object()) else {
            return;
        };
        for (k, v) in env {
            match v {
                serde_json::Value::Null => std::env::remove_var(k),
                serde_json::Value::String(s) => std::env::set_var(k, s),
                other => std::env::set_var(k, other.to_string()),
            }
        }
    }
}

/// `crate_snake`'s cdylib beside the running test binary (`target/<profile>/`, its `deps/` or its
/// `examples/`).
///
/// # Panics
/// When it is not built.
#[must_use]
pub fn cdylib_of(crate_snake: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>");
    let name = crate::plugin_library_filename(crate_snake);
    let (prefix, suffix) = name
        .split_once(crate_snake)
        .expect("the library name carries the crate's");
    // `deps/` (a lib target's cdylib, hashed or not) and `examples/` (an in-tree crate whose
    // dropped-in door is a `cdylib` example).
    let in_deps = ["deps", "examples"]
        .iter()
        .filter_map(|d| std::fs::read_dir(profile.join(d)).ok())
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .and_then(|f| f.strip_prefix(prefix))
                .and_then(|f| f.strip_suffix(suffix))
                .and_then(|f| f.strip_prefix(crate_snake))
                .is_some_and(|stem| {
                    stem.is_empty()
                        || stem.strip_prefix('-').is_some_and(|h| {
                            !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        });
    std::iter::once(profile.join(&name))
        .chain(in_deps)
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the plugin's cdylib ({name}) is not built under {profile:?}"))
}

/// THE PER-FOLD NAMESPACE PLACEHOLDER (Q-P4-8): `{fold}` anywhere in `conformance.json`'s
/// `settings` (a schema name, a key prefix, a database name) is filled per fold with a namespace
/// no other fold uses ([`fold_namespace`]), so two folds of one store, in one run or in two (CI's
/// debug, release and RED runs), never see each other's rows or tombstones.
///
/// The store ABI offers no op that makes or drops a namespace, so a plugin whose backend never
/// creates one on demand (a schema) names HOOKS that do, with its own test client
/// (`conformance_suite! { …, namespace: (create, drop) }`, [`Subject::with_namespace`]): the suite
/// creates each fold's namespace before its open and drops it after the fold, its failure
/// included. Without hooks the suite leaves the namespace: a plugin's settings name a THROWAWAY
/// backend (a test database or a key space it may litter), never one that holds data.
pub const FOLD: &str = "{fold}";

/// A namespace no other fold uses: `bbconf_<pid>_<tag>_<n>`, the process, the fold's tag (its leg)
/// and a counter of this process's; lower-case letters, digits and `_` only, so it is a valid
/// schema name and key prefix as it stands.
#[must_use]
pub fn fold_namespace(tag: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tag: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "bbconf_{}_{tag}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// How a leg reaches the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The compiled-in row: the linked door.
    Linked,
    /// The dropped-in library, admitted against the Statement its manifest states.
    Dropped,
}

impl Leg {
    /// The settings this leg's fold opens over: `s`'s, its [`FOLD`] filled with a namespace of
    /// the fold's own, made and removed by the subject's namespace hooks ([`Subject::fold_settings`]).
    #[must_use]
    pub fn settings(self, s: &Subject) -> FoldSettings<'_> {
        s.fold_settings(match self {
            Self::Linked => "linked",
            Self::Dropped => "dropped",
        })
    }
}

/// A dispatcher of the leg's own.
#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The bind the kernel makes: a label, the inflight clamp, no envelope sink, the adopting
/// dispatcher, SERVING with no connection table (a door that declares a need is refused;
/// [`Subject::bind`] adds the plugin's table).
#[must_use]
pub fn bind(d: &Dispatcher, instance: &str) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    }
}

/// The subject's door as kind `K`, reached by `leg`, through the ONE loader.
///
/// # Errors
/// The loader's refusal.
pub fn load<K: Kind>(s: &Subject, leg: Leg, b: Bind) -> Result<Plugin<K>, LoadError> {
    match leg {
        Leg::Linked => load_linked::<K>(&LinkedRow::of(s.door)?, b),
        Leg::Dropped => load_dropped::<K>(&s.cdylib(), &s.stated(), b),
    }
}

/// The crossings `p` has made, by the dispatcher's own crossing gate: every crossing, and of them
/// the RESUME re-invocations, counted apart (Q-P4-5).
pub(crate) fn crossings<K: Kind>(p: &Plugin<K>) -> Counts<'_> {
    Counts {
        total: &p.inner.crossings,
        resumes: &p.inner.resumes,
    }
}

/// One instance's crossing counters, as the dispatcher keeps them.
#[derive(Clone, Copy)]
pub struct Counts<'a> {
    total: &'a AtomicU64,
    resumes: &'a AtomicU64,
}

impl Counts<'_> {
    /// (first invocations, resumes) so far: "one op = one crossing", however often it pended.
    #[must_use]
    pub fn read(&self) -> (u64, u64) {
        let resumes = self.resumes.load(Ordering::SeqCst);
        (self.total.load(Ordering::SeqCst) - resumes, resumes)
    }
}

// ---- the fold ----

/// One step of a kind's script: what it is, what it answered (as the host reads it), the crossings
/// it made and the crossings the script pins for it. THE PIN IS FIRST INVOCATIONS (Q-P4-5; THE
/// DESIGN §11.2 Ready | Pending(wake), A.3 "Resume"): one op is one crossing however often it
/// pends; the RESUME re-invocations an op made on its ticket after it answered PENDING are counted
/// apart and reported (`resumes`), never pinned: how often a real backend makes an op wait is the
/// network's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The step's label.
    pub label: String,
    /// Its answer, one transcript line.
    pub answer: String,
    /// The FIRST-INVOCATION crossings the instance made while it ran.
    pub crossed: u64,
    /// The crossings the kind's script pins for it (first invocations).
    pub pinned: u64,
    /// The RESUME re-invocations it made while it ran (reported, not pinned).
    pub resumes: u64,
}

/// A leg's fold: its steps, in script order.
pub type Fold = Vec<Step>;

/// Records a script's steps against one instance's crossing counters.
pub struct Recorder<'a> {
    counter: Counts<'a>,
    steps: Fold,
}

impl<'a> Recorder<'a> {
    /// A recorder over `counter` (the instance's crossing gate).
    #[must_use]
    pub fn new(counter: Counts<'a>) -> Self {
        Self {
            counter,
            steps: Vec::new(),
        }
    }

    /// Run `f` as step `label`, pinned at `pinned` crossings; its answer is what `f` returns.
    pub fn step<T>(&mut self, label: &str, pinned: u64, f: impl FnOnce() -> (String, T)) -> T {
        let (first, resumed) = self.counter.read();
        let (answer, value) = f();
        let (first_after, resumed_after) = self.counter.read();
        self.steps.push(Step {
            label: label.to_string(),
            answer,
            crossed: first_after - first,
            pinned,
            resumes: resumed_after - resumed,
        });
        value
    }

    /// [`Recorder::step`] for a step whose answer is all it gives back.
    pub fn line(&mut self, label: &str, pinned: u64, f: impl FnOnce() -> String) {
        self.step(label, pinned, || (f(), ()));
    }

    /// Move the steps of `other` (another instance's recorder) in after these.
    pub fn absorb(&mut self, other: Recorder<'_>) {
        self.steps.extend(other.steps);
    }

    /// The fold.
    #[must_use]
    pub fn fold(self) -> Fold {
        self.steps
    }
}

/// THE EXACT COMPARATOR: `Err` names the first step whose crossings are not its pinned count.
/// Never "above zero" (M6/contract): one crossing too many, or one skipped, is refused.
///
/// # Errors
/// The first step that crossed otherwise than pinned.
pub fn exact(fold: &[Step]) -> Result<(), String> {
    for s in fold {
        if s.crossed != s.pinned {
            return Err(format!(
                "step '{}': {} crossing(s), pinned {} ({} resume(s); answer: {})",
                s.label, s.crossed, s.pinned, s.resumes, s.answer
            ));
        }
    }
    Ok(())
}

/// The two legs agree step for step: label, answer and crossings.
///
/// # Errors
/// The first step where they part.
pub fn same(linked: &[Step], dropped: &[Step]) -> Result<(), String> {
    for (l, d) in linked.iter().zip(dropped) {
        if (&l.label, &l.answer, l.crossed) != (&d.label, &d.answer, d.crossed) {
            return Err(format!(
                "the two doors part at '{}':\n  linked:  {} [{} crossing(s), {} resume(s)]\n  dropped: {} [{} crossing(s), {} resume(s)]",
                l.label, l.answer, l.crossed, l.resumes, d.answer, d.crossed, d.resumes
            ));
        }
    }
    if linked.len() != dropped.len() {
        return Err(format!(
            "the linked fold has {} steps, the dropped {}",
            linked.len(),
            dropped.len()
        ));
    }
    Ok(())
}

/// THE NETWORKED DOOR'S RESUMES (Q-P4-5): a door whose Statement declares a need the suite's table
/// serves reaches a REAL endpoint through it, so the ops that dial answer PENDING and are
/// RESUMED on their ticket (THE DESIGN §11.2 Ready | Pending(wake)): each step `dialing` names
/// (`conformance.json`'s `dialing_steps`) resumed at least once, or, when it names none, at least
/// one step of the fold did. A door that declares no need is not held to it.
///
/// # Errors
/// The first dialing step that never resumed, or a networked fold with no resume at all.
pub fn resumed(fold: &[Step], networked: bool, dialing: &[String]) -> Result<(), String> {
    if !networked {
        return Ok(());
    }
    for label in dialing {
        match fold.iter().find(|st| &st.label == label) {
            None => return Err(format!("dialing step '{label}' is not in the fold")),
            Some(st) if st.resumes == 0 => {
                return Err(format!(
                    "dialing step '{label}' never resumed: a networked op answered READY on its \
                     first invocation (answer: {})",
                    st.answer
                ))
            }
            Some(_) => {}
        }
    }
    if dialing.is_empty() && fold.iter().all(|st| st.resumes == 0) {
        return Err(
            "a networked door's fold resumed no op: nothing answered PENDING on the network".into(),
        );
    }
    Ok(())
}

/// `fold` with step `at`'s pinned count moved by one: the RED arm's input.
#[must_use]
pub fn perturbed(mut fold: Fold, at: usize) -> Fold {
    if let Some(s) = fold.get_mut(at) {
        s.pinned += 1;
    }
    fold
}

// ---- the frames every kind shares (lifecycle) ----

/// An `in` of `T`, every field zero but its head.
#[must_use]
pub fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, raw pointers, `Option<fn>` and nested plain
    // structs, for which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

/// An `out` of `T`, every field zero but its head.
#[must_use]
pub fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}

/// A JSON blob over `bytes`.
#[must_use]
pub fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// A call's answer as one transcript line: outcome, whether it leased, the error text.
#[must_use]
pub fn called(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

/// `validate` over `settings`.
pub fn validate<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut err = [0_u8; 512];
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.err_buf = err.as_mut_ptr();
    f.input.err_cap = err.len();
    p.call(life::VALIDATE, &mut f)
}

/// `open` over `settings`, generation 1, in the frame the kernel opens kind `K` with: a plane's
/// `open` is `PlaneOpenIn`/`PlaneOpenOut` (its `out` carries the first generation's snapshot, and
/// the kind's check FAULTs an `open` whose `out` cannot hold it); every other kind's is the
/// lifecycle's `OpenIn`/`OpenOut`.
pub fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    if K::CODE == KindCode::Plane {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        f.input.open.settings = json(settings);
        f.input.open.generation = 1;
        return p.call(life::OPEN, &mut f);
    }
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.generation = 1;
    p.call(life::OPEN, &mut f)
}

/// `open` over `settings` THE WAY THE KERNEL OPENS IT (Q-P4-6): submitted on a ticket of `d`'s, so
/// an `open` that answers PENDING (a store connecting to its backend) is RESUMED on its wake until
/// it answers; the frame [`open`]'s.
pub fn open_resumed<K: Kind>(p: &Plugin<K>, d: &Dispatcher, settings: &[u8]) -> Called {
    fn on_ticket<K: Kind, I: InFrame, O: OutFrame>(
        p: &Plugin<K>,
        d: &Dispatcher,
        f: Frame<I, O>,
    ) -> Called {
        let Some(ticket) = d.mint(0) else {
            return Called {
                outcome: Outcome::Refused,
                error: None,
                lease: 0,
                recall: None,
            };
        };
        let deadline = crate::dispatch::now_ns().saturating_add(OPEN_DEADLINE.as_nanos() as u64);
        let done = d
            .submit(
                p,
                ticket,
                life::OPEN,
                f,
                busbar_contract::abi::mechanism::call::DeadlineClass::Call,
                deadline,
            )
            .wait_done();
        d.recycle(ticket);
        Called {
            outcome: done.outcome,
            error: done.error,
            lease: done.lease,
            recall: None,
        }
    }
    if K::CODE == KindCode::Plane {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        f.input.open.settings = json(settings);
        f.input.open.generation = 1;
        return on_ticket(p, d, f);
    }
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.generation = 1;
    on_ticket(p, d, f)
}

/// How long the suite waits for one resumed `open`: the store bridge's call deadline.
const OPEN_DEADLINE: Duration = Duration::from_secs(30);

/// `refresh` over `settings`, generation 2.
pub fn refresh<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.generation = 2;
    p.call(life::REFRESH, &mut f)
}

/// `release` of `lease`.
pub fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut f: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    f.input.lease = lease;
    p.call(life::RELEASE, &mut f)
}

/// `tick` at `now_ns`: its answer and the next tick it asks for.
pub fn tick<K: Kind>(p: &Plugin<K>, now_ns: u64) -> (Called, u64) {
    let mut f: Frame<TickIn, TickOut> = Frame::new(input(), output());
    f.input.now_ns = now_ns;
    let c = p.call(life::TICK, &mut f);
    (c, f.out.next_tick_ns)
}

/// `close`.
pub fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut f: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(life::CLOSE, &mut f)
}

/// THE `ready` STEP every kind's script runs right after its `open` answered READY (the
/// mechanism's discovery at boot, awaited before any listener binds). A door that states no
/// `ready` is not called: pinned at 0 crossings. One that states it is pinned at ONE first
/// invocation, its resumes reported (Q-P4-5; `inputs.ready_crossings` is no longer read).
pub fn ready_step<K: Kind>(rec: &mut Recorder<'_>, _s: &Subject, p: &Plugin<K>, d: &Dispatcher) {
    let pinned = u64::from(p.has_ready());
    rec.line("ready", pinned, || {
        format!(
            "has_ready={} {:?}",
            p.has_ready(),
            p.ready(d, READY_DEADLINE)
        )
    });
}

// ---- the kind dispatch ----

/// One leg's fold, by the kind its door states.
fn fold(s: &Subject, leg: Leg) -> Fold {
    match s.kind() {
        KindCode::Store => store::fold(s, leg),
        KindCode::Secret => secret::fold(s, leg),
        KindCode::Auth => auth::fold(s, leg),
        KindCode::Hook => hook::fold(s, leg),
        KindCode::Export => export::fold(s, leg),
        KindCode::Plane => plane::fold(s, leg),
        KindCode::Transport => transport::fold(s, leg),
    }
}

/// **THE BOTH-WAYS ARM.** The dropped-in library states the linked door's Statement; each leg's
/// fold makes exactly its pinned crossings; the two folds are equal.
///
/// # Panics
/// On any of those failing (the test's verdict).
pub fn both_ways(s: &Subject) {
    s.apply_env();
    assert_eq!(
        LinkedRow::of(s.door)
            .unwrap_or_else(|e| panic!("the linked door is refused: {e}"))
            .statement,
        s.stated(),
        "the dropped-in library must state exactly the linked door's Statement"
    );
    let red = std::env::var(RED_ENV).is_ok_and(|v| v == "count");
    // Networked: its needs are SERVED by the suite's table (it dials a real endpoint); a door whose
    // needs the suite cannot serve binds as a probe and dials nothing.
    let networked = s.conns(&dispatcher()).is_some();
    let dialing: Vec<String> = s.inputs["dialing_steps"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut folds = Vec::new();
    for leg in [Leg::Linked, Leg::Dropped] {
        let mut f = fold(s, leg);
        assert!(!f.is_empty(), "the {leg:?} leg ran no step");
        assert!(
            f.iter().any(|st| st.label == "ready"),
            "the {leg:?} leg skipped the ready step"
        );
        if red {
            // THE CI STEP'S RED RUN: one pinned count moved by one must fail this arm.
            f = perturbed(f, 0);
        }
        if let Err(e) = exact(&f) {
            panic!("{leg:?}: {e}");
        }
        if let Err(e) = resumed(&f, networked, &dialing) {
            panic!("{leg:?}: {e}");
        }
        folds.push(f);
    }
    if let Err(e) = same(&folds[0], &folds[1]) {
        panic!("{e}");
    }
}

/// **RED: the exact comparator refuses a moved count.** The linked leg's real fold passes it; the
/// same fold with any one step's pinned count moved by one does not, nor does a fold whose every
/// count doubled (the "above zero" check a loose comparator would wave through).
///
/// # Panics
/// When the comparator accepts a moved count.
pub fn red_count(s: &Subject) {
    s.apply_env();
    let f = fold(s, Leg::Linked);
    exact(&f).unwrap_or_else(|e| panic!("the honest fold fails before the RED arm runs: {e}"));
    for at in 0..f.len() {
        assert!(
            exact(&perturbed(f.clone(), at)).is_err(),
            "a pinned count moved at step {at} ('{}') passed the comparator",
            f[at].label
        );
    }
    let doubled: Fold = f
        .iter()
        .cloned()
        .map(|mut st| {
            st.crossed *= 2;
            st
        })
        .collect();
    if f.iter().any(|st| st.pinned > 0) {
        assert!(
            exact(&doubled).is_err(),
            "a door crossing twice per op passed"
        );
    }
}

// ---- the perturbed doors (the RED arms' subjects: the real door, restated) ----

/// The real door restated, served by a door function of its own.
struct Restated {
    door: AtomicPtr<Door>,
}

impl Restated {
    const fn new() -> Self {
        Self {
            door: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn set(&self, d: Door) {
        self.door
            .store(Box::into_raw(Box::new(d)), Ordering::SeqCst);
    }

    fn get(&self) -> *const Door {
        self.door.load(Ordering::SeqCst)
    }
}

static ABI_UP: Restated = Restated::new();
static ABI_DOWN: Restated = Restated::new();
static READY_FAILS: Restated = Restated::new();
static NETWORKED: Restated = Restated::new();

extern "C" fn abi_up_door() -> *const Door {
    ABI_UP.get()
}
extern "C" fn abi_down_door() -> *const Door {
    ABI_DOWN.get()
}
extern "C" fn networked_door() -> *const Door {
    NETWORKED.get()
}
extern "C" fn ready_fails_door() -> *const Door {
    READY_FAILS.get()
}

/// The text the RED `ready` fails with.
pub const READY_FAILURE: &str = "conformance: discovery refused";

/// A `ready` that answers FAILED with [`READY_FAILURE`].
extern "C" fn ready_fails(
    _instance: *mut std::ffi::c_void,
    _input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let failed = RawOutcome::of(Outcome::Failed);
    // SAFETY: the host hands `ready` an `OutHead` of its own size; only its head is written.
    unsafe {
        let head = out.cast::<OutHead>();
        (*head).outcome = failed;
        (*head).error = AbiStr {
            ptr: READY_FAILURE.as_ptr(),
            len: READY_FAILURE.len(),
        };
    }
    failed
}

/// The subject's door, read.
fn real_door(s: &Subject) -> Door {
    let p = (s.door)();
    assert!(!p.is_null(), "the door function answered NULL");
    // SAFETY: a door function answers a `'static` door at least its stated size; the whole
    // struct is read only when its size covers it (a door ending before `ready` reads `None`).
    unsafe {
        let size = std::ptr::addr_of!((*p).size).read_unaligned() as usize;
        if size >= std::mem::size_of::<Door>() {
            p.read_unaligned()
        } else {
            Door {
                magic: std::ptr::addr_of!((*p).magic).read_unaligned(),
                mechanism_version: std::ptr::addr_of!((*p).mechanism_version).read_unaligned(),
                size: std::mem::size_of::<Door>() as u32,
                kind: std::ptr::addr_of!((*p).kind).read_unaligned(),
                kind_abi: std::ptr::addr_of!((*p).kind_abi).read_unaligned(),
                statement: std::ptr::addr_of!((*p).statement).read_unaligned(),
                ops: std::ptr::addr_of!((*p).ops).read_unaligned(),
                ready: None,
            }
        }
    }
}

/// `rendering` with its kind ABI word set to `abi`.
fn stating_abi(rendering: &[u8], abi: u32) -> Vec<u8> {
    let mut r = rendering.to_vec();
    let at = RENDERING_MAGIC.len() + 8;
    r[at..at + 4].copy_from_slice(&abi.to_le_bytes());
    r
}

/// Run `$body` with `$K` bound to the kind type of `$code`.
macro_rules! by_kind {
    ($code:expr, $K:ident => $body:expr) => {
        match $code {
            KindCode::Store => {
                type $K = Store;
                $body
            }
            KindCode::Secret => {
                type $K = Secret;
                $body
            }
            KindCode::Auth => {
                type $K = Auth;
                $body
            }
            KindCode::Hook => {
                type $K = Hook;
                $body
            }
            KindCode::Export => {
                type $K = Export;
                $body
            }
            KindCode::Plane => {
                type $K = Plane;
                $body
            }
            KindCode::Transport => {
                type $K = Transport;
                $body
            }
        }
    };
}

/// **RED: a door at another kind ABI is refused, both ways.** The real door restated at its kind
/// ABI + 1 and − 1 is refused by the linked row (`KindAbi`, naming the rebuild); the dropped-in
/// library under a manifest stating either is refused before `dlopen` (`ManifestKindAbi`). The
/// honest door loads beside them, both ways.
///
/// # Panics
/// When a restated door loads, or the honest one does not.
pub fn red_kind_abi(s: &Subject) {
    let kind = s.kind();
    let host = kind.abi_version();
    let real = real_door(s);
    assert_eq!(
        real.kind_abi, host,
        "the door states its kind's current ABI"
    );
    ABI_UP.set(Door {
        kind_abi: host + 1,
        ..real
    });
    ABI_DOWN.set(Door {
        kind_abi: host.wrapping_sub(1),
        ..real
    });
    let stated = s.stated();
    by_kind!(kind, K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest-linked")).expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
        for (door, abi) in [(abi_up_door as DoorFn, host + 1), (abi_down_door, host.wrapping_sub(1))] {
            let want = LoadError::KindAbi { kind, door: abi, host };
            assert_eq!(rendering_of(door).err(), Some(want.clone()), "the pack tool signs no ABI {abi} door");
            let refused = LinkedRow::of(door)
                .and_then(|row| load_linked::<K>(&row, s.bind(&d, "red-linked")).map(|_| ()))
                .expect_err("a linked door at another kind ABI is refused");
            assert_eq!(refused, want);
            assert!(refused.to_string().contains("rebuild"), "{refused}");
            let refused = load_dropped::<K>(&s.cdylib(), &stating_abi(&stated, abi), s.bind(&d, "red-dropped"))
                .map(|_| ())
                .expect_err("a manifest stating another kind ABI is refused");
            assert_eq!(refused, LoadError::ManifestKindAbi { stated: abi, host });
        }
    });
}

/// **RED: a `ready` that fails refuses the boot with the plugin's text** (#391's arm, on the real
/// plugin). The real door restated with a `ready` that answers FAILED is loaded and opened AS THE
/// KERNEL OPENS IT (Q-P4-6: a store through [`LoadedStore::open`](crate::store_v3::LoadedStore::open),
/// which awaits `ready` inside it; every other kind's `open` resumed on its ticket
/// ([`open_resumed`]), never one raw crossing, so a door that connects in its `open` answers
/// PENDING there and is resumed); its `ready` is awaited and refused, naming the plugin and the
/// reason, in one first invocation. The honest door's `ready` (its own, or none) serves.
///
/// # Panics
/// When the failing `ready` serves.
pub fn red_ready(s: &Subject) {
    s.apply_env();
    let real = real_door(s);
    READY_FAILS.set(Door {
        size: std::mem::size_of::<Door>() as u32,
        ready: Some(ready_fails),
        ..real
    });
    let settings = s.fold_settings("red");
    if s.kind() == KindCode::Store {
        let d = dispatcher();
        let row = LinkedRow::of(ready_fails_door).expect("the restated door states its Statement");
        let p =
            load_linked::<Store>(&row, s.bind(&d, "red-ready")).expect("the restated door loads");
        assert!(p.has_ready());
        let name = p.name().to_owned();
        let held = p.clone();
        let (before, _) = crossings(&held).read();
        let refused =
            crate::store_v3::LoadedStore::open(p, Arc::clone(&d), &settings, store::leg_mint)
                .map(|_| ())
                .expect_err("a failing ready refuses the store's open");
        assert_eq!(
            refused,
            format!("plugin '{name}' ready failed: {READY_FAILURE}")
        );
        assert_eq!(
            crossings(&held).read().0 - before,
            2,
            "one open and one ready, first invocations, the ready not retried"
        );
        return;
    }
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        let row = LinkedRow::of(ready_fails_door).expect("the restated door states its Statement");
        let p = load_linked::<K>(&row, s.bind(&d, "red-ready")).expect("the restated door loads");
        assert!(p.has_ready());
        let o = open_resumed(&p, &d, &settings);
        assert_eq!(o.outcome, Outcome::Ready, "open: {}", called(&o));
        let (before, _) = crossings(&p).read();
        let refused = p.ready(&d, READY_DEADLINE).expect_err("a failing ready refuses the boot");
        assert_eq!(
            refused,
            format!("plugin '{}' ready failed: {READY_FAILURE}", p.name())
        );
        assert_eq!(crossings(&p).read().0 - before, 1, "one crossing, not retried");
    });
}

/// The real door restated with one outbound `tcp` need, its target its own (the RED arm's subject
/// for a door that declares none).
fn with_a_tcp_need(real: Door) -> Door {
    use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
    use busbar_contract::abi::mechanism::door::Statement;
    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    const TCP: &str = "tcp";
    let needs: &'static [Need] = Box::leak(Box::new([Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: AbiStr {
            ptr: TCP.as_ptr(),
            len: TCP.len(),
        },
        auth: NONE,
        target_from: NONE,
        trust_from: NONE,
        details: crate::dispatch::NO_BLOB,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }]));
    // SAFETY: a door's Statement is `'static`; only its needs are restated.
    let st: Statement = unsafe { real.statement.read_unaligned() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    Door {
        statement: st,
        ..real
    }
}

/// **RED: a networked door bound to serve with NO connection table is refused, naming the plugin**
/// (Q-P4-3). A door that declares a need is bound as the kernel serves it but with no table
/// ([`bind`]: [`ConnTable::NoNeeds`]), linked and dropped in, and refused at bind with
/// [`LoadError::NoConnectionTable`]; a door that declares none is restated with one `tcp` need (as
/// [`red_ready`] restates its `ready`) and bound linked. The GREEN twins: the same door bound as a
/// PROBE binds, and the honest door binds over the suite's own table ([`Subject::bind`]).
///
/// # Panics
/// When a networked door binds to serve with no table, or a twin does not bind.
pub fn red_no_table(s: &Subject) {
    let real = real_door(s);
    let needs = s.needs().len();
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest")).expect("the honest door binds over the suite's table");
        let restated = needs == 0;
        let (door, needs): (DoorFn, usize) = if restated {
            NETWORKED.set(with_a_tcp_need(real));
            (networked_door, 1)
        } else {
            (s.door, needs)
        };
        let row = LinkedRow::of(door).expect("the door states its Statement");
        let plugin = rendering::read(&row.statement).expect("its Statement reads back").name;
        let want = LoadError::NoConnectionTable { plugin: plugin.clone(), needs };
        let refused = load_linked::<K>(&row, bind(&d, "red-no-table"))
            .map(|_| ())
            .expect_err("a networked door serving with no connection table is refused");
        assert_eq!(refused, want);
        assert!(refused.to_string().contains(&format!("plugin '{plugin}'")), "{refused}");
        if !restated {
            let refused = load::<K>(s, Leg::Dropped, bind(&d, "red-no-table-dropped"))
                .map(|_| ())
                .expect_err("dropped in, the same door serving with no table is refused");
            assert_eq!(refused, want);
        }
        load_linked::<K>(&row, Bind { conns: ConnTable::Probe, ..bind(&d, "probe") })
            .expect("bound as a probe, with no table, it binds");
    });
}

/// THE PROFILE GUARD: asked for the release binary (M6/contract), the suite refuses a debug build.
/// `debug` is the caller's `cfg!(debug_assertions)` (the plugin's test crate's, not this one's).
///
/// # Panics
/// When the release binary was asked for and this is a debug build.
pub fn profile(debug: bool) {
    assert!(
        !(debug && std::env::var_os(EXPECT_RELEASE_ENV).is_some()),
        "{EXPECT_RELEASE_ENV} is set: run the conformance suite with `--release`"
    );
}

/// **THE SUITE, IN A PLUGIN REPO'S `tests/conformance.rs`.** Emits the suite's tests over the
/// plugin's linked door, its cdylib and its inputs; `plugin-ci.yml` runs them under `--release`
/// and requires every one to RUN. The names are the contract the CI step reads.
#[macro_export]
macro_rules! conformance_suite {
    (
        door: $door:path,
        cdylib: $cdylib:expr,
        inputs: $inputs:expr
        $(, host: $host:path)?
        $(, tls: $tls:expr)?
        $(, namespace: ($create:path, $drop:path))?
        $(,)?
    ) => {
        fn __busbar_conformance_subject() -> $crate::conformance::Subject {
            #[allow(unused_mut)]
            let mut s = $crate::conformance::Subject::new($door, $cdylib, $inputs);
            $(s = s.with_host($host);)?
            $(s = s.with_anchors($tls);)?
            $(s = s.with_namespace($create, $drop);)?
            s
        }

        /// THE BOTH-WAYS ARM: linked vs dropped in, exact crossings, equal folds.
        #[test]
        fn the_linked_and_the_dropped_in_door_are_one_plugin() {
            $crate::conformance::both_ways(&__busbar_conformance_subject());
        }

        /// RED: a moved crossing count is refused by the exact comparator.
        #[test]
        fn red_a_moved_crossing_count_is_refused() {
            $crate::conformance::red_count(&__busbar_conformance_subject());
        }

        /// RED: the door at its kind ABI ± 1 is refused, linked and dropped in.
        #[test]
        fn red_a_door_at_another_kind_abi_is_refused() {
            $crate::conformance::red_kind_abi(&__busbar_conformance_subject());
        }

        /// RED: a `ready` that fails refuses the boot with the plugin's text.
        #[test]
        fn red_a_failing_ready_refuses_the_boot() {
            $crate::conformance::red_ready(&__busbar_conformance_subject());
        }

        /// RED: a networked door bound to serve with no connection table is refused by name.
        #[test]
        fn red_a_networked_door_with_no_connection_table_is_refused() {
            $crate::conformance::red_no_table(&__busbar_conformance_subject());
        }

        /// The release binary, when asked for.
        #[test]
        fn the_suite_runs_in_the_profile_it_was_asked_to() {
            $crate::conformance::profile(cfg!(debug_assertions));
        }
    };
}

#[cfg(test)]
#[path = "../tests/conformance_suite_tests.rs"]
mod tests;
