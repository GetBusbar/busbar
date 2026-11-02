// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The published conformance suite** exercises a plugin through linked and dropped-in doors.
//! Real plugin repositories test themselves against busbar; core does not test plugins.
//! Busbar publishes this suite and every real plugin repo runs it,
//! in its own CI (`plugin-ci.yml`'s conformance step), at the busbar commit it pins (§9).
//!
//! A plugin repo calls it from its own `tests/conformance.rs`, one line:
//!
//! ```ignore
//! busbar_test_kit::conformance_suite! {
//!     door: <logic crate>::door::door,              // the LINKED door (its logic crate's)
//!     cdylib: "<logic crate>_plugin",               // the crate whose cdylib is the DROPPED door
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
//! busbar_test_kit::conformance_suite! {
//!     door: …, cdylib: …, inputs: …,
//!     host: <busbar's host connector, a `conformance::Host`>,
//!     tls: include_str!("test-ca.pem"),
//! }
//! ```
//!
//! with `busbar-test-kit = { git = …, rev = <the pin> }` as a dev-dependency. The macro emits the
//! suite's tests; `plugin-ci.yml` runs them under `--release`.
//!
//! A plugin whose declared needs reach a far end (an IdP's JWKS or token endpoint) names those far
//! ends in its inputs, `"far_ends": [{ "url", "cert_pem", "status", "body" }, ...]`: each instance
//! the suite opens is bound to a connection table serving them, as the host's connector carries
//! the plugin's requests ([`Subject::far_ends`]); the plugin holds no socket and no TLS.
//!
//! WHAT ONE RUN PROVES, for the kind the door states:
//!
//! * the dropped-in library states exactly the linked door's Statement (the signed manifest's
//!   rendering IS the linked row's), and both are admitted by the ONE loader ([`load_linked`] /
//!   [`load_dropped_bytes`], the library's bytes staged as every production load stages them) and
//!   bound to a dispatcher of their own, as the kernel binds them;
//! * the KIND'S SCRIPT (one module per kind, below) drives each leg through the same table, step by
//!   step, and records per step its answer and the crossings the instance made, counted by the
//!   dispatcher's own crossing gate;
//! * every step's crossings equal the count the script PINS, EXACTLY (M6/contract: never "above
//!   zero"), on both legs, and the two folds are equal step for step;
//! * the mechanism's optional `ready` (discovery at boot) is a step of every kind's script: a door
//!   that states none is not called (0 crossings); one that states it is awaited on a real ticket.
//!
//! The suite's connection table: a plugin whose Statement declares a
//! need the table serves (its stream transport, `stand_in.json`: `host:port` or a local socket
//! path) is bound, on each leg, to a connection
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
//! (`ManifestKindAbi`, before `dlopen`); the door under a Statement other than the stated one is
//! refused, both ways (`StatementMismatch`); the door asked for as every other kind is refused,
//! linked and dropped in (`ManifestKind`); its instance's connection over a need it
//! never declared is refused (`UndeclaredNeed`), and one instance's use of another's connection is
//! refused (`NotOwner`); a transport door whose tail states another frame piece size than the
//! host's is refused, linked and by the pack tool (`FramePieceSize`); a plane door whose tail
//! states another answer layout than the host's is refused, linked and by the pack tool
//! (`PlaneLayout`) (`red.rs`); the door with a `ready` that fails refuses the boot with the
//! plugin's text; a networked door (the real one, or restated with a stream need) bound to serve with
//! no connection table is refused at bind, naming the plugin. And `BUSBAR_CONFORMANCE_RED=count` perturbs the both-ways arm itself, so the CI
//! step can require that the suite FAILS when a count moves.
//!
//! THE SEAM: the suite lives in busbar-test-kit, a dev-dependency only, and reaches the one loader
//! through the dispatcher internals busbar-plugin-loader exports as its test seams.
//!
//! [`load_linked`]: crate::dispatch::load_linked
//! [`load_dropped_bytes`]: crate::dispatch::load_dropped_bytes

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, RawOutcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::{self as rendering, RENDERING_MAGIC};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::abi::sdk::door::RawDoorFn;

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use busbar_contract::conn::DeclaredConns;

use crate::dispatch::{
    in_head, load_dropped_bytes, load_linked, out_head, rendering_of_library, Bind, Called,
    ConnTable, DispatchConfig, Dispatcher, Done, Frame, InFrame, Kind, Lent, LinkedRow, LoadError,
    OutFrame, Plugin,
};
use crate::tcp_conns::TcpConns;
use busbar_contract::abi::mechanism::ticket::Ticket;

mod auth;
mod carrier;
mod datagram;
mod export;

pub use auth::{
    outbound_plant, red_outbound_double_fetch, red_outbound_writes_nothing, red_outbound_wrong_byte,
};
pub mod canary;
mod hook;
pub mod host_io;
mod plane;
mod secret;
mod store;
mod transport;

pub use store::store_newer_schema;

pub const READY_DEADLINE: Duration = crate::dispatch::ready::READY_DEADLINE;

pub const RED_ENV: &str = "BUSBAR_CONFORMANCE_RED";

pub const EXPECT_RELEASE_ENV: &str = "BUSBAR_EXPECT_RELEASE";

pub struct Subject {
    pub door: RawDoorFn,

    pub cdylib_crate: &'static str,

    pub inputs: serde_json::Value,

    pub host: Option<Host>,

    pub anchors: Option<String>,

    pub namespace: Option<(NamespaceHook, NamespaceHook)>,

    pub newer_schema: Option<NamespaceHook>,

    pub declares: Option<crate::sign::Declares>,
}

pub type NamespaceHook = fn(&str, &[u8]);

pub struct FoldSettings<'s> {
    subject: &'s Subject,
    namespace: String,

    // settings-leak-lint: allow — NON-PROJECTION conformance-harness type: one fold's filled
    settings: Vec<u8>,
}

impl FoldSettings<'_> {
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
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(&self.namespace, &self.settings);
            }));
        } else {
            drop(&self.namespace, &self.settings);
        }
    }
}

pub type Host = fn(busbar_contract::conn::ConnWake, Option<&str>) -> Arc<dyn DeclaredConns>;

impl Subject {
    #[must_use]
    pub fn new(door: DoorFn, cdylib_crate: &'static str, inputs: &str) -> Self {
        Self::of_raw(crate::dispatch::load::raw(door), cdylib_crate, inputs)
    }

    pub(crate) fn of_raw(door: RawDoorFn, cdylib_crate: &'static str, inputs: &str) -> Self {
        let inputs: serde_json::Value = serde_json::from_str(inputs)
            .unwrap_or_else(|e| panic!("conformance.json is not JSON: {e}"));
        assert!(inputs.is_object(), "conformance.json is not a JSON object");
        let s = Self {
            door,
            cdylib_crate,
            inputs,
            host: None,
            anchors: None,
            namespace: None,
            newer_schema: None,
            declares: None,
        };
        s.apply_env();
        s
    }

    #[must_use]
    pub fn of_macro(
        door: busbar_contract::abi::sdk::door::MacroDoor,
        cdylib_crate: &'static str,
        inputs: &str,
    ) -> Self {
        Self::new(door.door_fn(), cdylib_crate, inputs)
    }

    #[must_use]
    pub fn of_loaded(
        door: crate::dispatch::LoadedDoor,
        cdylib_crate: &'static str,
        inputs: &str,
    ) -> Self {
        Self::of_raw(door.door, cdylib_crate, inputs)
    }

    #[must_use]
    pub fn with_namespace(mut self, create: NamespaceHook, drop: NamespaceHook) -> Self {
        self.namespace = Some((create, drop));
        self
    }

    #[must_use]
    pub fn with_newer_schema(mut self, stamp: NamespaceHook) -> Self {
        self.newer_schema = Some(stamp);
        self
    }

    #[must_use]
    pub fn with_declares(mut self, declares: crate::sign::Declares) -> Self {
        self.declares = Some(declares);
        self
    }

    #[must_use]
    pub fn declared_in(self, manifest_dir: &str) -> Self {
        let Some(file) = declares_file(manifest_dir) else {
            return self;
        };
        let text = std::fs::read(&file)
            .unwrap_or_else(|e| panic!("{} does not read: {e}", file.display()));
        let declares = crate::sign::Declares::from_declares_json(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        self.with_declares(declares)
    }

    #[must_use]
    pub fn hook_orders(&self) -> bool {
        self.declares
            .as_ref()
            .is_none_or(crate::sign::Declares::hook_orders)
    }

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

    #[must_use]
    pub fn with_host(mut self, host: Host) -> Self {
        self.host = Some(host);
        self
    }

    #[must_use]
    pub fn with_anchors(mut self, pem: &str) -> Self {
        self.anchors = Some(pem.to_owned());
        self
    }

    #[must_use]
    pub fn kind(&self) -> KindCode {
        let p = crate::dispatch::load::enter_door(self.door);
        assert!(!p.is_null(), "the door function answered NULL");
        // SAFETY: a door function answers a `'static` door at least its stated size.
        let raw = unsafe { Door::read_parts(p) }.kind;
        KindCode::from_raw(raw).unwrap_or_else(|| panic!("the door names kind {raw}"))
    }

    #[must_use]
    pub fn cdylib(&self) -> PathBuf {
        cdylib_of(self.cdylib_crate)
    }

    #[must_use]
    pub fn stated(&self) -> Vec<u8> {
        rendering_of_library(&self.cdylib())
            .unwrap_or_else(|e| panic!("the cdylib's Statement does not render: {e}"))
            .expect("the cdylib exports busbar_plugin_door")
    }

    #[must_use]
    pub fn settings(&self) -> Vec<u8> {
        self.settings_in(&fold_namespace("suite"))
    }

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

    #[must_use]
    pub fn far_ends(&self) -> Option<Arc<dyn busbar_contract::conn::DeclaredConns>> {
        assert!(
            self.inputs.get("unreached_schemes").is_none(),
            "conformance.json: unreached_schemes is read by the plane suite only, which asserts \
             after its fold that no open touched one"
        );
        self.far_table()
            .map(|t| t as Arc<dyn busbar_contract::conn::DeclaredConns>)
    }

    #[must_use]
    pub fn far_table(&self) -> Option<Arc<crate::https_conns::HttpsConns>> {
        let ends = self.inputs.get("far_ends")?.as_array()?;
        let facts = crate::stand_in::FramedFacts::stand_in();
        let unreached = match self.inputs.get("unreached_schemes") {
            None => Vec::new(),
            Some(value) => {
                let transports: Vec<String> =
                    self.needs().into_iter().map(|n| n.transport).collect();
                crate::https_conns::judge_unreached(
                    value,
                    &facts.transport,
                    &transports,
                    &repo_root(),
                )
                .unwrap_or_else(|why| panic!("conformance.json: {why}"))
            }
        };
        let table = crate::https_conns::HttpsConns::framing(facts).unreached(unreached);
        for e in ends {
            let url = e["url"]
                .as_str()
                .expect("conformance.json: every far end names its url");
            let body = match &e["body"] {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            let status = match e.get("status") {
                None => 200,
                Some(v) => v
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .expect("conformance.json: far-end status must fit a u32"),
            };
            table.serve(url, e["cert_pem"].as_str(), status, &body);
        }
        Some(Arc::new(table))
    }

    #[must_use]
    pub fn kind_inputs(&self, kind: &str) -> &serde_json::Value {
        self.inputs.get(kind).unwrap_or(&serde_json::Value::Null)
    }

    #[must_use]
    pub fn needs(&self) -> Vec<rendering::ReadNeed> {
        let row = LinkedRow::of_raw(self.door)
            .unwrap_or_else(|e| panic!("the linked door is refused: {e}"));
        rendering::read(&row.statement)
            .unwrap_or_else(|e| panic!("the door's Statement does not read back: {e:?}"))
            .needs
    }

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
        let table = TcpConns::serving(crate::stand_in::StreamFacts::stand_in(), d.conn_waker());
        let served = needs
            .iter()
            .all(|n| n.transport.is_empty() || table.serves_scheme(&n.transport));
        (!needs.is_empty() && served).then(|| Arc::new(table) as Arc<dyn DeclaredConns>)
    }

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

    pub fn apply_env(&self) {
        let Some(env) = self.inputs.get("env").and_then(|e| e.as_object()) else {
            return;
        };
        assert_eq!(
            applied_env(env),
            env,
            "conformance.json's `env` is the process's: one environment per test binary"
        );
    }
}

fn applied_env(
    env: &serde_json::Map<String, serde_json::Value>,
) -> &'static serde_json::Map<String, serde_json::Value> {
    static APPLIED: std::sync::OnceLock<serde_json::Map<String, serde_json::Value>> =
        std::sync::OnceLock::new();
    APPLIED.get_or_init(|| {
        for (k, v) in env {
            match v {
                serde_json::Value::Null => std::env::remove_var(k),
                serde_json::Value::String(s) => std::env::set_var(k, s),
                other => std::env::set_var(k, other.to_string()),
            }
        }
        env.clone()
    })
}

/// THE ENVIRONMENT BEFORE ANY THREAD: what [`conformance_suite!`] runs as the test binary loads,
/// before `main` and so before the test harness starts a thread, so no test (the suite's or the
/// crate's own) reads the environment while it changes. The `env` of `inputs` (a
/// `conformance.json` text) is applied as [`Subject::apply_env`] applies it; text that is not
/// that JSON is left for [`Subject::new`] to refuse, in words. Never panics.
#[doc(hidden)]
pub fn apply_env_before_threads(inputs: &str) {
    if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(inputs) {
        if let Some(env) = o.get("env").and_then(|e| e.as_object()) {
            let _ = applied_env(env);
        }
    }
}

pub const CDYLIB_ENV: &str = "BUSBAR_CONFORMANCE_CDYLIB";

/// `crate_snake`'s cdylib, CHOSEN EXPLICITLY, never by age (audit loader-conformance #13), and only
/// ever an image that EXPORTS the dropped-in door (`busbar_plugin_door`):
///
/// 1. the path [`CDYLIB_ENV`] names (this run's cargo build output);
/// 2. else the image of the crate's own lib unit, `target/<profile>/deps/<lib>`: cargo names a
///    workspace cdylib with no metadata hash, and a TEST build never uplifts it (the lib is not a
///    root of `cargo test`), so this is where the test build that turned on the crate's
///    `dropped-in` feature put its image;
/// 3. else the image cargo UPLIFTED (`target/<profile>/<lib>` or `target/<profile>/examples/<lib>`,
///    unhashed: a root unit's newest output, an example's under `cargo test`);
/// 4. else the ONE hashed image under `deps/` (or `examples/`); several images with different
///    bytes (stale builds, another feature set's hash) are refused, naming them and
///    [`CDYLIB_ENV`], since nothing says which one this run built.
///
/// A candidate that exports no door is passed over at every rank: an earlier plain build of the
/// crate (no `dropped-in` feature) leaves an uplifted image with no door, and it is never the
/// dropped-in leg. When only such images are built the choice fails, naming them.
///
/// # Panics
/// When none is built, the named one does not exist, or the choice is ambiguous.
#[must_use]
pub fn cdylib_of(crate_snake: &str) -> PathBuf {
    if let Some(named) = std::env::var_os(CDYLIB_ENV) {
        let named = PathBuf::from(named);
        assert!(
            named.is_file(),
            "{CDYLIB_ENV} names {named:?}, which is not a built library"
        );
        return named;
    }
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>");
    choose_cdylib(profile, crate_snake).unwrap_or_else(|e| panic!("{e}"))
}

pub(crate) fn choose_cdylib(profile: &Path, crate_snake: &str) -> Result<PathBuf, String> {
    choose_cdylib_by(profile, crate_snake, &|p: &Path| {
        matches!(
            crate::dispatch::load::door_addresses_of_library(p),
            Ok(Some(_))
        )
    })
}

pub(crate) fn choose_cdylib_by(
    profile: &Path,
    crate_snake: &str,
    exports_door: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    let name = crate::plugin_library_filename(crate_snake);
    let (prefix, suffix) = name
        .split_once(crate_snake)
        .expect("the library name carries the crate's");
    let mut hashed: Vec<PathBuf> = ["deps", "examples"]
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
                .and_then(|stem| stem.strip_prefix('-'))
                .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .collect();
    hashed.sort();
    let ranks = [
        vec![profile.join("deps").join(&name)],
        vec![profile.join(&name), profile.join("examples").join(&name)],
        hashed,
    ];
    let mut doorless: Vec<PathBuf> = Vec::new();
    for rank in ranks {
        let mut images: Vec<(Vec<u8>, PathBuf)> = Vec::new();
        for p in rank.into_iter().filter(|p| p.is_file()) {
            let bytes = std::fs::read(&p).unwrap_or_default();
            if images.iter().any(|(b, _)| *b == bytes) {
                continue;
            }
            if exports_door(&p) {
                images.push((bytes, p));
            } else {
                doorless.push(p);
            }
        }
        match images.len() {
            0 => {}
            1 => return Ok(images.remove(0).1),
            _ => {
                return Err(format!(
                    "the plugin's cdylib ({name}) is built more than once under {profile:?} \
                     ({:?}); name this run's image in {CDYLIB_ENV}",
                    images.iter().map(|(_, p)| p).collect::<Vec<_>>()
                ))
            }
        }
    }
    if doorless.is_empty() {
        Err(format!(
            "the plugin's cdylib ({name}) is not built under {profile:?}"
        ))
    } else {
        Err(format!(
            "the plugin's cdylib ({name}) is built under {profile:?} only without its dropped-in \
             door ({doorless:?} do not load or export no busbar_plugin_door): build it with \
             the crate's `dropped-in` feature (its dev-dependency on itself turns it on for \
             `cargo test`), or name the image in {CDYLIB_ENV}"
        ))
    }
}

pub fn distinct_images(s: &Subject) {
    distinct(s.door, &s.cdylib()).unwrap_or_else(|e| panic!("{e}"));
}

pub(crate) fn distinct(door: RawDoorFn, path: &Path) -> Result<(), String> {
    let (dropped, ops) = crate::dispatch::load::door_addresses_of_library(path)
        .map_err(|e| format!("the dropped image {path:?} does not load: {e}"))?
        .ok_or_else(|| format!("the dropped image {path:?} exports no door"))?;
    let linked = door();
    if linked.is_null() {
        return Err("the door function answered NULL".into());
    }
    // SAFETY: a door function answers a `'static` door at least its stated size.
    let linked_ops = unsafe { Door::read_parts(linked) }.ops as usize;
    if dropped == linked as usize || ops == linked_ops {
        return Err(format!(
            "the dropped image {path:?} answers the LINKED door (door {dropped:#x}, ops {ops:#x}): \
             the two legs would compare one image with itself"
        ));
    }
    Ok(())
}

pub const FOLD: &str = "{fold}";

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
    #[must_use]
    pub fn settings(self, s: &Subject) -> FoldSettings<'_> {
        s.fold_settings(match self {
            Self::Linked => "linked",
            Self::Dropped => "dropped",
        })
    }
}

#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    FOLD_DISPATCHERS.with(|f| f.borrow_mut().push(Arc::clone(&d)));
    d
}

#[must_use]
pub fn dispatcher_serving(
    provider: Arc<dyn busbar_contract::services::HostServices>,
) -> Arc<Dispatcher> {
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        provider,
    ));
    FOLD_DISPATCHERS.with(|f| f.borrow_mut().push(Arc::clone(&d)));
    d
}

#[cfg(all(test, loader_self_tests))]
pub(crate) struct StaticDoor(Door);

#[cfg(all(test, loader_self_tests))]
impl StaticDoor {
    /// # Safety
    /// The door must satisfy `Door::__from_parts` and every table, Statement, and nested range it
    /// references must remain initialized and immutable for the process lifetime. Moving this
    /// value must not invalidate any of those references; no backing range may point into `door`.
    pub(crate) unsafe fn new(door: Door) -> Self {
        Self(door)
    }

    pub(crate) fn get(&self) -> &Door {
        &self.0
    }
}

// SAFETY: construction requires immutable static backing independent of this owned door's address.
#[cfg(all(test, loader_self_tests))]
unsafe impl Send for StaticDoor {}
// SAFETY: the owned door and its complete referenced graph are immutable after publication.
#[cfg(all(test, loader_self_tests))]
unsafe impl Sync for StaticDoor {}

#[cfg(all(test, loader_self_tests))]
pub(crate) mod transport_receive_fixture;

#[cfg(all(test, loader_self_tests))]
pub(crate) trait TestDoor {
    fn door() -> *const Door;
}

#[cfg(all(test, loader_self_tests))]
pub(crate) extern "C" fn test_door<T: TestDoor>() -> *const Door {
    T::door()
}

#[cfg(all(test, loader_self_tests))]
pub(crate) trait TestOp {
    fn op(
        instance: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome;
}

#[cfg(all(test, loader_self_tests))]
pub(crate) extern "C" fn test_op<T: TestOp>(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    T::op(instance, input, out)
}

thread_local! {
    /// The dispatchers made on this thread since the last [`woken`]: a fold's.
    static FOLD_DISPATCHERS: std::cell::RefCell<Vec<Arc<Dispatcher>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub fn woken() -> Result<(), String> {
    let lost: u64 = FOLD_DISPATCHERS
        .with(|f| std::mem::take(&mut *f.borrow_mut()))
        .iter()
        .map(|d| d.stats().deadline_without_wake)
        .sum();
    if lost == 0 {
        Ok(())
    } else {
        Err(format!(
            "bb_deadline_without_wake_total = {lost}: an op that answered PENDING was ended by its \
             deadline, never woken (THE DESIGN A.4.3)"
        ))
    }
}

#[must_use]
pub fn bind(d: &Dispatcher, instance: &str) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 1024,
        sink: canary::heard(),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    }
}

fn repo_root() -> PathBuf {
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    match dir.parent() {
        Some(parent) if parent.join("Cargo.toml").is_file() => parent.to_path_buf(),
        _ => dir,
    }
}

pub fn bind_far(d: &Dispatcher, instance: &str, s: &Subject) -> Bind {
    match s.far_ends() {
        Some(table) => Bind {
            conns: ConnTable::Host(table),
            ..bind(d, instance)
        },
        None => s.bind(d, instance),
    }
}

pub fn load<K: Kind>(s: &Subject, leg: Leg, b: Bind) -> Result<Plugin<K>, LoadError> {
    match leg {
        Leg::Linked => load_linked::<K>(&LinkedRow::of_raw(s.door)?, b),
        Leg::Dropped => load_dropped_staged::<K>(&s.cdylib(), &s.stated(), b),
    }
}

pub(crate) fn load_dropped_staged<K: Kind>(
    path: &Path,
    stated: &[u8],
    b: Bind,
) -> Result<Plugin<K>, LoadError> {
    let bytes = std::fs::read(path)
        .map_err(|e| LoadError::Open(format!("cannot read {}: {e}", path.display())))?;
    load_dropped_bytes::<K>(&bytes, &path.display().to_string(), stated, b)
}

pub(crate) fn crossings<K: Kind>(p: &Plugin<K>) -> Counts<'_> {
    crossings_of(&p.inner)
}

pub(crate) fn crossings_of(inner: &crate::dispatch::plugin::Instance) -> Counts<'_> {
    Counts {
        total: &inner.crossings,
        resumes: &inner.resumes,
    }
}

/// One instance's crossing counters, as the dispatcher keeps them.
#[derive(Clone, Copy)]
pub struct Counts<'a> {
    total: &'a AtomicU64,
    resumes: &'a AtomicU64,
}

impl Counts<'_> {
    #[must_use]
    pub fn read(&self) -> (u64, u64) {
        let resumes = self.resumes.load(Ordering::SeqCst);
        (self.total.load(Ordering::SeqCst) - resumes, resumes)
    }
}

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

pub type Fold = Vec<Step>;

pub struct Recorder<'a> {
    counter: Counts<'a>,
    steps: Fold,
}

impl<'a> Recorder<'a> {
    #[must_use]
    pub fn new(counter: Counts<'a>) -> Self {
        Self {
            counter,
            steps: Vec::new(),
        }
    }

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

    pub fn line(&mut self, label: &str, pinned: u64, f: impl FnOnce() -> String) {
        self.step(label, pinned, || (f(), ()));
    }

    pub fn absorb(&mut self, other: Recorder<'_>) {
        self.steps.extend(other.steps);
    }

    #[must_use]
    pub fn fold(self) -> Fold {
        self.steps
    }
}

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

#[must_use]
pub fn perturbed(mut fold: Fold, at: usize) -> Fold {
    if let Some(s) = fold.get_mut(at) {
        s.pinned += 1;
    }
    fold
}

#[must_use]
pub fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, raw pointers, `Option<fn>` and nested plain
    // structs, for which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

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

#[must_use]
pub fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

#[must_use]
pub fn called(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

#[must_use]
pub fn lend_secrets(refs: &[String], settings: &[u8], keep: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    if refs.is_empty() {
        return (settings.to_vec(), Vec::new());
    }
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(settings) else {
        return (settings.to_vec(), vec![Vec::new(); refs.len()]);
    };
    let as_bytes = |v: Option<serde_json::Value>| match v {
        Some(serde_json::Value::String(s)) => s.into_bytes(),
        _ => Vec::new(),
    };
    let secrets = busbar_contract::secret_fields::lend(
        &mut v,
        refs,
        keep,
        |_, v| Ok::<_, std::convert::Infallible>(as_bytes(v)),
        |_, v| Ok(as_bytes(Some(v))),
    )
    .unwrap_or_else(|e| match e {});
    if keep
        && !refs
            .iter()
            .any(|p| busbar_contract::secret_fields::is_wildcard(p))
    {
        return (settings.to_vec(), secrets);
    }
    (v.to_string().into_bytes(), secrets)
}

fn host_lends<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    match K::CODE {
        KindCode::Auth => lend_secrets(p.secret_refs(), settings, false),
        KindCode::Secret => lend_secrets(p.secret_refs(), settings, true),
        _ => (settings.to_vec(), Vec::new()),
    }
}

pub fn settings_as_the_kernel_resolves<K: Kind>(
    p: &Plugin<K>,
    settings: &[u8],
    resolve: impl FnMut(&str, &busbar_contract::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<Vec<u8>, String> {
    let mut tree: serde_json::Value = serde_json::from_slice(settings)
        .map_err(|e| format!("the settings are not a JSON document: {e}"))?;
    busbar_contract::secret_fields::resolve_declared_fields(
        &mut tree,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        resolve,
    )?;
    Ok(tree.to_string().into_bytes())
}

fn secret_blobs(secrets: &[Vec<u8>]) -> Vec<Blob> {
    use busbar_contract::abi::mechanism::call::{BLOB_OCTETS, BLOB_SECRET};
    secrets
        .iter()
        .map(|s| Blob {
            ptr: s.as_ptr(),
            len: s.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
        .collect()
}

pub fn validate<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let split;
    let settings = if K::CODE == KindCode::Auth {
        split = lend_secrets(p.secret_refs(), settings, false).0;
        &split[..]
    } else {
        settings
    };
    let mut err = [0_u8; 512];
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.err_buf = err.as_mut_ptr();
    f.input.err_cap = err.len();
    p.call(life::VALIDATE, &mut f)
}

pub fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let (settings, secrets) = host_lends(p, settings);
    let blobs = secret_blobs(&secrets);
    if K::CODE == KindCode::Plane {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        f.input.open.settings = json(&settings);
        f.input.open.secrets = blobs.as_ptr();
        f.input.open.secrets_len = blobs.len();
        f.input.open.generation = 1;
        return p.call(life::OPEN, &mut f);
    }
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json(&settings);
    f.input.secrets = blobs.as_ptr();
    f.input.secrets_len = blobs.len();
    f.input.generation = 1;
    p.call(life::OPEN, &mut f)
}

pub fn open_resumed<K: Kind>(p: &Plugin<K>, d: &Dispatcher, settings: &[u8]) -> Called {
    let deadline = crate::dispatch::now_ns().saturating_add(OPEN_DEADLINE.as_nanos() as u64);
    let (settings, secrets) = host_lends(p, settings);
    let blobs = secret_blobs(&secrets);
    let lend = OpenLend {
        settings,
        _secrets: secrets,
        blobs,
    };
    let (settings, blobs) = (
        json(&lend.settings),
        (lend.blobs.as_ptr(), lend.blobs.len()),
    );
    let lent: Lent = Arc::new(lend);
    if K::CODE == KindCode::Plane {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        f.input.open.settings = settings;
        (f.input.open.secrets, f.input.open.secrets_len) = blobs;
        f.input.open.generation = 1;
        return on_ticket(p, d, life::OPEN, f, DeadlineClass::Call, deadline, lent);
    }
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = settings;
    (f.input.secrets, f.input.secrets_len) = blobs;
    f.input.generation = 1;
    on_ticket(p, d, life::OPEN, f, DeadlineClass::Call, deadline, lent)
}

struct OpenLend {
    // settings-leak-lint: allow — NON-PROJECTION conformance-harness type: the settings bytes a
    settings: Vec<u8>,
    _secrets: Vec<Vec<u8>>,
    blobs: Vec<Blob>,
}

// SAFETY: the raw pointers in `blobs` point into `_secrets`, owned by the same `OpenLend`; nothing
// mutates it once its frame is built.
unsafe impl Send for OpenLend {}
// SAFETY: as above.
unsafe impl Sync for OpenLend {}

pub fn on_ticket<K: Kind, I: InFrame, O: OutFrame>(
    p: &Plugin<K>,
    d: &Dispatcher,
    s: u32,
    f: Frame<I, O>,
    class: DeadlineClass,
    deadline_ns: u64,
    lent: Lent,
) -> Called {
    on_ticket_frame(p, d, s, f, class, deadline_ns, lent).0
}

pub fn on_ticket_frame<K: Kind, I: InFrame, O: OutFrame>(
    p: &Plugin<K>,
    d: &Dispatcher,
    s: u32,
    f: Frame<I, O>,
    class: DeadlineClass,
    deadline_ns: u64,
    lent: Lent,
) -> (Called, Option<Frame<I, O>>) {
    let Some(ticket) = d.mint(0) else {
        let refused = Called {
            outcome: Outcome::Refused,
            error: None,
            lease: 0,
            recall: None,
        };
        return (refused, None);
    };
    let done = submit_on(
        p,
        d,
        ticket,
        s,
        f,
        (class, deadline_ns),
        lent,
        Duration::ZERO,
    );
    d.recycle(ticket);
    (answered(&done), done.frame)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn submit_on<K: Kind, I: InFrame, O: OutFrame>(
    p: &Plugin<K>,
    d: &Dispatcher,
    ticket: Ticket,
    s: u32,
    f: Frame<I, O>,
    (class, deadline_ns): (DeadlineClass, u64),
    lent: Lent,
    watch: Duration,
) -> Done<I, O> {
    d.submit_watched(p, ticket, s, f, class, deadline_ns, lent, watch)
        .wait_done()
}

pub(crate) fn answered<I, O>(done: &Done<I, O>) -> Called {
    Called {
        outcome: done.outcome,
        error: done.error.clone(),
        lease: done.lease,
        recall: None,
    }
}

const OPEN_DEADLINE: Duration = Duration::from_secs(30);

pub fn refresh<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let (settings, secrets) = host_lends(p, settings);
    let blobs = secret_blobs(&secrets);
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(&settings);
    f.input.secrets = blobs.as_ptr();
    f.input.secrets_len = blobs.len();
    f.input.generation = 2;
    p.call(life::REFRESH, &mut f)
}

pub fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut f: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    f.input.lease = lease;
    p.call(life::RELEASE, &mut f)
}

pub fn tick<K: Kind>(p: &Plugin<K>, now_ns: u64) -> (Called, u64) {
    let mut f: Frame<TickIn, TickOut> = Frame::new(input(), output());
    f.input.now_ns = now_ns;
    let c = p.call(life::TICK, &mut f);
    (c, f.out.next_tick_ns)
}

pub fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut f: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(life::CLOSE, &mut f)
}

pub fn ready_step<K: Kind>(rec: &mut Recorder<'_>, _s: &Subject, p: &Plugin<K>, d: &Dispatcher) {
    let pinned = u64::from(p.has_ready());
    rec.line("ready", pinned, || {
        let answer = p.ready(d, READY_DEADLINE);
        assert!(
            answer.is_ok(),
            "the honest door must become ready: {answer:?}"
        );
        format!("has_ready={} {answer:?}", p.has_ready())
    });
}

pub(crate) enum Want {
    Is(String),

    Starts(&'static str),
}

pub(crate) fn judge(fold: &[Step], want: &[(String, Want)]) {
    for (label, w) in want {
        let got = answer(fold, label);
        match w {
            Want::Is(line) => assert_eq!(got, line.as_str(), "{label}"),
            Want::Starts(prefix) => assert!(got.starts_with(prefix), "{label}: {got}"),
        }
    }
}

pub(crate) fn answer<'f>(fold: &'f [Step], label: &str) -> &'f str {
    fold.iter()
        .find(|s| s.label == label)
        .map(|s| s.answer.as_str())
        .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
}

pub(crate) struct Script<'a> {
    r: Recorder<'a>,
    want: Vec<(String, Want)>,
}

impl<'a> Script<'a> {
    pub(crate) fn new(counter: Counts<'a>) -> Self {
        Self {
            r: Recorder::new(counter),
            want: Vec::new(),
        }
    }

    pub(crate) fn judged(
        &mut self,
        label: &str,
        pinned: u64,
        want: Want,
        f: impl FnOnce() -> String,
    ) {
        self.r.line(label, pinned, f);
        self.want.push((label.to_owned(), want));
    }

    pub(crate) fn step_judged<T>(
        &mut self,
        label: &str,
        pinned: u64,
        want: Want,
        f: impl FnOnce() -> (String, T),
    ) -> T {
        self.want.push((label.to_owned(), want));
        self.r.step(label, pinned, f)
    }

    pub(crate) fn fold(self) -> Fold {
        let fold = self.r.fold();
        judge(&fold, &self.want);
        fold
    }
}

impl<'a> std::ops::Deref for Script<'a> {
    type Target = Recorder<'a>;
    fn deref(&self) -> &Recorder<'a> {
        &self.r
    }
}

impl std::ops::DerefMut for Script<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.r
    }
}

pub(crate) fn abi_bytes(b: &(impl AsRef<[u8]> + ?Sized)) -> AbiStr {
    let b = b.as_ref();
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

pub(crate) fn asis(line: String) -> String {
    line
}

pub(crate) fn facts<K: Kind>(p: &Plugin<K>) -> String {
    format!(
        "{:?} {} max_inflight={}",
        p.kind(),
        p.name(),
        p.max_inflight()
    )
}

pub(crate) fn opened<K: Kind>(
    sc: &mut Script<'_>,
    (s, p, d): (&Subject, &Plugin<K>, &Dispatcher),
    settings: &[u8],
    wrap: &dyn Fn(String) -> String,
) {
    sc.judged("validate", 1, Want::Starts("Ready "), || {
        wrap(called(&validate(p, settings)))
    });
    sc.judged("open", 1, Want::Starts("Ready "), || {
        wrap(called(&open(p, settings)))
    });
    ready_step(sc, s, p, d);
}

pub(crate) fn refused_settings<K: Kind>(
    sc: &mut Script<'_>,
    p: &Plugin<K>,
    bad: &[Vec<u8>],
    wrap: &dyn Fn(String) -> String,
) {
    for (i, b) in bad.iter().enumerate() {
        sc.line(&format!("validate bad #{i}"), 1, || {
            wrap(called(&validate(p, b)))
        });
    }
}

pub(crate) fn refreshed<K: Kind>(
    sc: &mut Script<'_>,
    p: &Plugin<K>,
    bad: Option<&[u8]>,
    settings: &[u8],
    wrap: &dyn Fn(String) -> String,
) {
    sc.line("tick", 1, || {
        let (c, next) = tick(p, 1);
        wrap(format!("{} next={next}", called(&c)))
    });
    if let Some(bad) = bad {
        sc.line("refresh bad", 1, || wrap(called(&refresh(p, bad))));
    }
    sc.judged("refresh", 1, Want::Starts("Ready "), || {
        wrap(called(&refresh(p, settings)))
    });
}

pub(crate) fn closed<K: Kind>(sc: &mut Script<'_>, p: &Plugin<K>, wrap: &dyn Fn(String) -> String) {
    sc.judged("close", 1, Want::Starts("Ready "), || {
        wrap(called(&close(p)))
    });
}

pub(crate) fn listed<'v>(
    k: &'v serde_json::Value,
    kind: &str,
    key: &str,
) -> &'v [serde_json::Value] {
    let list = k[key]
        .as_array()
        .unwrap_or_else(|| panic!("conformance.json: {kind}.{key} must be an array"));
    assert!(!list.is_empty(), "conformance.json: {kind}.{key} is empty");
    list
}

pub(crate) fn input_text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: {what} input is missing"),
        other => other.to_string().into_bytes(),
    }
}

fn fold(s: &Subject, leg: Leg) -> Fold {
    let _ = woken();
    let fold = kind_fold(s, leg);
    if let Err(e) = woken() {
        panic!("{leg:?}: {e}");
    }
    fold
}

fn kind_fold(s: &Subject, leg: Leg) -> Fold {
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

pub fn both_ways(s: &Subject) {
    s.apply_env();
    assert_eq!(
        LinkedRow::of_raw(s.door)
            .unwrap_or_else(|e| panic!("the linked door is refused: {e}"))
            .statement,
        s.stated(),
        "the dropped-in library must state exactly the linked door's Statement"
    );
    distinct_images(s);
    let red = std::env::var(RED_ENV).is_ok_and(|v| v == "count");

    let networked = s
        .needs()
        .iter()
        .any(|need| need.direction == DIRECTION_OUTBOUND)
        && s.conns(&dispatcher()).is_some();
    let dialing: Vec<String> = match s.inputs.get("dialing_steps") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .expect("conformance.json: dialing_steps must be an array")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("conformance.json: dialing_steps entries must be strings")
                    .to_owned()
            })
            .collect(),
    };
    let mut folds = Vec::new();
    for leg in [Leg::Linked, Leg::Dropped] {
        let mut f = fold(s, leg);
        assert!(!f.is_empty(), "the {leg:?} leg ran no step");
        assert!(
            f.iter().any(|st| st.label == "ready"),
            "the {leg:?} leg skipped the ready step"
        );
        if red {
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

pub fn canary(s: &Subject) {
    s.apply_env();
    let planted = canary::credentials(&s.inputs);
    if planted.is_empty() {
        assert!(
            s.kind() != KindCode::Secret,
            "conformance.json names no `credentials`: a kind: secret plugin's canary plants the \
             values its settings carry (`\"credentials\": [\"<value>\", ...]`) and searches every \
             answer and log record for them; with none it would pass without looking"
        );
        return;
    }
    for leg in [Leg::Linked, Leg::Dropped] {
        let _ = canary::take_heard();
        let f = fold(s, leg);
        let mut emitted: Vec<(String, Vec<u8>)> = f
            .iter()
            .map(|st| {
                (
                    format!("step '{}'", st.label),
                    st.answer.clone().into_bytes(),
                )
            })
            .collect();
        emitted.extend(
            canary::take_heard()
                .into_iter()
                .enumerate()
                .map(|(i, t)| (format!("log record {i}"), t)),
        );
        if let Some(at) = canary::find(&planted, &emitted) {
            panic!("{leg:?}: a configured credential crossed back in {at}");
        }
    }
}

pub fn red_unreported_class(s: &Subject) {
    s.apply_env();
    if s.kind() == KindCode::Plane {
        plane::red_unreported_class(s);
    }
}

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

struct Restated {
    door: AtomicPtr<Door>,

    held: Mutex<()>,
}

impl Restated {
    const fn new() -> Self {
        Self {
            door: AtomicPtr::new(std::ptr::null_mut()),
            held: Mutex::new(()),
        }
    }

    fn set(&self, d: DoorParts) {
        // SAFETY: every restated door is the subject's real door (`real_door`) with one part
        // replaced by `'static` data the suite built to the same contract: a Statement leaked
        // whole, a table copied from the real one, or a `ready` of its own.
        let d = unsafe { Door::__from_parts(d) };
        self.door
            .store(Box::into_raw(Box::new(d)), Ordering::SeqCst);
    }

    fn hold(&'static self, d: DoorParts) -> MutexGuard<'static, ()> {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        self.set(d);
        held
    }

    fn get(&self) -> *const Door {
        self.door.load(Ordering::SeqCst)
    }
}

static ABI_UP: Restated = Restated::new();
static ABI_DOWN: Restated = Restated::new();
static READY_FAILS: Restated = Restated::new();
static NETWORKED: Restated = Restated::new();

static VERSIONED: Restated = Restated::new();
static CONNECTED: Restated = Restated::new();

static PIECED: Restated = Restated::new();

static LAID: Restated = Restated::new();

static FINGERPRINTED: Restated = Restated::new();

extern "C" fn abi_up_door() -> *const Door {
    ABI_UP.get()
}
extern "C" fn abi_down_door() -> *const Door {
    ABI_DOWN.get()
}

extern "C" fn restated_door<const I: usize>() -> *const Door {
    [
        &NETWORKED,
        &VERSIONED,
        &CONNECTED,
        &PIECED,
        &LAID,
        &FINGERPRINTED,
    ][I]
        .get()
}
extern "C" fn ready_fails_door() -> *const Door {
    READY_FAILS.get()
}

/// The READY/CLOSE observations belong to the holder of `READY_FAILS`'s restatement lock.
/// The original CLOSE is kept only for the store branch, whose owned OPEN must be retired when
/// readiness fails. Never hold this mutex across the original callback.
#[derive(Default)]
struct ReadyWitness {
    ready_calls: u64,
    close: Option<busbar_contract::abi::mechanism::call::Op>,
    close_calls: u64,
    close_answer: Option<Outcome>,
}

static READY_WITNESS: Mutex<ReadyWitness> = Mutex::new(ReadyWitness {
    ready_calls: 0,
    close: None,
    close_calls: 0,
    close_answer: None,
});

extern "C" fn ready_store_close(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let close = {
        let mut witness = READY_WITNESS.lock().unwrap_or_else(PoisonError::into_inner);
        witness.close_calls += 1;
        witness.close
    };
    let Some(close) = close else {
        return RawOutcome::of(Outcome::Fault);
    };
    // SAFETY: this wrapper occupies CLOSE in an otherwise unchanged full store table. It forwards
    // the original live instance and exact complete InHead/OutHead frames unchanged, once, to the
    // genuine subject's CLOSE, whose static table remains live under the restatement lock.
    let answer = unsafe { close(instance, input, out) };
    READY_WITNESS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .close_answer = Some(answer.outcome());
    answer
}

pub const READY_FAILURE: &str = "conformance: discovery refused";

extern "C" fn ready_fails(
    _instance: *mut std::ffi::c_void,
    _input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    READY_WITNESS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .ready_calls += 1;
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

fn real_door(s: &Subject) -> DoorParts {
    let p = (s.door)();
    assert!(!p.is_null(), "the door function answered NULL");
    // SAFETY: a door function answers a `'static` door at least its stated size; `read_parts`
    // reads `ready` only when that size covers it.
    let real = unsafe { Door::read_parts(p) };
    DoorParts {
        size: std::mem::size_of::<Door>() as u32,
        ..real
    }
}

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

mod red;
pub use red::{
    red_cross_instance_conn, red_frame_piece, red_kind_layout, red_plane_layout, red_statement,
    red_undeclared_need, red_wrong_kind,
};

pub fn red_kind_abi(s: &Subject) {
    let kind = s.kind();
    let host = kind.abi_version();
    let real = real_door(s);
    assert_eq!(
        real.kind_abi, host,
        "the door states its kind's current ABI"
    );
    ABI_UP.set(DoorParts {
        kind_abi: host + 1,
        ..real
    });
    ABI_DOWN.set(DoorParts {
        kind_abi: host.wrapping_sub(1),
        ..real
    });
    let stated = s.stated();
    by_kind!(kind, K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest-linked")).expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
        for (door, abi) in [(abi_up_door as RawDoorFn, host + 1), (abi_down_door, host.wrapping_sub(1))] {
            let want = LoadError::KindAbi { kind, door: abi, host };
            assert_eq!(crate::dispatch::load::rendering_of_raw(door).err(), Some(want.clone()), "the pack tool signs no ABI {abi} door");
            let refused = LinkedRow::of_raw(door)
                .and_then(|row| load_linked::<K>(&row, s.bind(&d, "red-linked")).map(|_| ()))
                .expect_err("a linked door at another kind ABI is refused");
            assert_eq!(refused, want);
            assert!(refused.to_string().contains("rebuild"), "{refused}");
            let refused = load_dropped_staged::<K>(&s.cdylib(), &stating_abi(&stated, abi), s.bind(&d, "red-dropped"))
                .map(|_| ())
                .expect_err("a manifest stating another kind ABI is refused");
            assert_eq!(refused, LoadError::ManifestKindAbi { stated: abi, host });
        }
    });
}

pub fn red_ready(s: &Subject) {
    s.apply_env();
    let real = real_door(s);
    let _restated = READY_FAILS.hold(DoorParts {
        size: std::mem::size_of::<Door>() as u32,
        ready: Some(ready_fails),
        ..real
    });
    *READY_WITNESS.lock().unwrap_or_else(PoisonError::into_inner) = ReadyWitness::default();
    let settings = s.fold_settings("red");
    if s.kind() == KindCode::Store {
        // SAFETY: the subject is a current store door with its full immutable static Ops table;
        // copying it preserves all lifecycle/kind slots and their metadata, changing only CLOSE.
        let mut ops = unsafe {
            real.ops
                .cast::<busbar_contract::abi::store::Ops>()
                .read_unaligned()
        };
        READY_WITNESS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .close = Some(ops.head.close.expect("the store has its lifecycle CLOSE"));
        ops.head.close = Some(ready_store_close);
        let ops = Box::leak(Box::new(ops));
        READY_FAILS.set(DoorParts {
            size: std::mem::size_of::<Door>() as u32,
            ready: Some(ready_fails),
            ops: std::ptr::from_ref(ops).cast(),
            ..real
        });
        let d = dispatcher();
        let row =
            LinkedRow::of_raw(ready_fails_door).expect("the restated door states its Statement");
        let p =
            load_linked::<Store>(&row, s.bind(&d, "red-ready")).expect("the restated door loads");
        assert!(p.has_ready());
        let name = p.name().to_owned();
        let held = Arc::clone(&p.inner);
        let (before, _) = crossings_of(&held).read();
        let minted = store::LegMint::take(0);
        let refused =
            crate::store_v3::LoadedStore::open(p, Arc::clone(&d), &settings, minted.mint())
                .map(|_| ())
                .expect_err("a failing ready refuses the store's open");
        assert_eq!(
            refused,
            format!("plugin '{name}' ready failed: {READY_FAILURE}")
        );
        let witness = READY_WITNESS.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(witness.ready_calls, 1, "the failing READY is never retried");
        assert_eq!(
            witness.close_calls, 1,
            "the successful OPEN is closed exactly once"
        );
        assert_eq!(
            witness.close_answer,
            Some(Outcome::Ready),
            "the real CLOSE completes"
        );
        assert_eq!(
            crossings_of(&held).read().0 - before,
            3,
            "one OPEN, the independently observed failing READY, and its real cleanup CLOSE"
        );
        return;
    }
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        let row = LinkedRow::of_raw(ready_fails_door).expect("the restated door states its Statement");
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
        assert_eq!(
            READY_WITNESS.lock().unwrap_or_else(PoisonError::into_inner).ready_calls,
            1,
            "the failing READY is never retried"
        );
    });
}

fn with_an_outbound_need(real: DoorParts) -> DoorParts {
    use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
    use busbar_contract::abi::mechanism::door::Statement;
    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let stream: &'static str = Box::leak(
        crate::stand_in::StreamFacts::stand_in()
            .transport
            .into_boxed_str(),
    );
    let needs: &'static [Need] = Box::leak(Box::new([Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: AbiStr {
            ptr: stream.as_ptr(),
            len: stream.len(),
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
    DoorParts {
        statement: st,
        ..real
    }
}

fn connection_fixture(
    s: &Subject,
    door: RawDoorFn,
) -> (Arc<dyn DeclaredConns>, Box<dyn std::any::Any>, String) {
    let table = Subject::of_raw(door, s.cdylib_crate, "{}")
        .conns(&dispatcher())
        .expect("the suite's test table serves the restated need");
    let listening = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let at = listening.local_addr().expect("its address").to_string();
    (table, Box::new(listening), at)
}

pub fn red_no_table(s: &Subject) {
    let real = real_door(s);
    let needs = s.needs().len();
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest")).expect("the honest door binds over the suite's table");
        let restated = needs == 0;
        let (door, needs): (RawDoorFn, usize) = if restated {
            NETWORKED.set(with_an_outbound_need(real));
            (restated_door::<0>, 1)
        } else {
            (s.door, needs)
        };
        let row = LinkedRow::of_raw(door).expect("the door states its Statement");
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

#[must_use]
pub fn need_schemes(needs: &[rendering::ReadNeed]) -> Vec<String> {
    let mut out: Vec<String> = needs
        .iter()
        .filter(|n| !n.transport.is_empty())
        .map(|n| n.transport.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn declared_needs_are(declares: &str, statement: &[String]) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_str(declares).map_err(|e| format!("declares.json is not JSON: {e}"))?;
    let declared: Vec<String> = match v.get("needs") {
        None => Vec::new(),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("declares.json `needs`: {x} is not a transport scheme"))
            })
            .collect::<Result<_, _>>()?,
        Some(other) => return Err(format!("declares.json `needs` is not a list: {other}")),
    };
    let mut declared = declared;
    declared.sort();
    declared.dedup();
    let extra: Vec<&String> = declared.iter().filter(|d| !statement.contains(d)).collect();
    let missing: Vec<&String> = statement.iter().filter(|d| !declared.contains(d)).collect();
    if extra.is_empty() && missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "declares.json `needs` {declared:?} is not the Statement's {statement:?}: it names {extra:?} \
         the Statement does not, and misses {missing:?} it does (the Statement is the one truth)"
    ))
}

#[must_use]
pub fn declares_file(manifest_dir: &str) -> Option<PathBuf> {
    let crate_dir = Path::new(manifest_dir);
    let Some(root) = crate_dir
        .parent()
        .filter(|p| p.join("Cargo.toml").is_file())
    else {
        let own = crate_dir.join("declares.json");
        return own.is_file().then_some(own);
    };
    let mut found: Vec<PathBuf> = std::iter::once(root.to_path_buf())
        .chain(
            std::fs::read_dir(root)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && !p
                            .file_name()
                            .is_some_and(|n| n == "target" || n.to_string_lossy().starts_with('.'))
                }),
        )
        .map(|d| d.join("declares.json"))
        .filter(|f| f.is_file())
        .collect();
    found.sort();
    assert!(
        found.len() <= 1,
        "the repo holds one declares.json at its root or one directory below it: {found:?}"
    );
    found.pop()
}

pub fn needs_declared(s: &Subject, manifest_dir: &str) {
    let file = declares_file(manifest_dir).unwrap_or_else(|| {
        panic!(
            "no declares.json for the plugin at {manifest_dir} (its repo's root or one directory \
             below it; in busbar's tree, the crate's own directory): the declared needs are proven \
             against it, never passed unread"
        )
    });
    let text = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("{} does not read: {e}", file.display()));
    if let Err(e) = declared_needs_are(&text, &need_schemes(&s.needs())) {
        panic!("{}: {e}", file.display());
    }
}

pub fn profile(debug: bool) {
    assert!(
        !(debug && std::env::var_os(EXPECT_RELEASE_ENV).is_some()),
        "{EXPECT_RELEASE_ENV} is set: run the conformance suite with `--release`"
    );
}

/// A suite accepts either a plugin's `door` function or the `MACRO_DOOR` produced beside it by `plugin_door!`.
///
///
///
/// The two forms are told apart by method resolution: a `MacroDoor` answers its door function by
/// value (`MacroDoorArg`); any other value (a door function) answers itself through a reference
/// (`DoorFnArg`), and the caller's `DoorFn` annotation coerces the function item.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_door {
    ($door:path) => {{
        #[allow(unused_imports)]
        use $crate::conformance::{DoorFnArg as _, MacroDoorArg as _};
        let door: $crate::conformance::ConformanceDoorFn = (&$door).door_arg();
        door
    }};
}

/// The door function type a suite runs over, named where `__conformance_door!` expands.
#[doc(hidden)]
pub type ConformanceDoorFn = DoorFn;

/// `__conformance_door!`'s arm for a `MacroDoor`.
#[doc(hidden)]
pub trait MacroDoorArg {
    fn door_arg(&self) -> DoorFn;
}

impl MacroDoorArg for busbar_contract::abi::sdk::door::MacroDoor {
    fn door_arg(&self) -> DoorFn {
        self.door_fn()
    }
}

/// `__conformance_door!`'s arm for a door function: the value itself, coerced by the caller.
#[doc(hidden)]
pub trait DoorFnArg<F> {
    fn door_arg(&self) -> F;
}

impl<F: Copy> DoorFnArg<F> for &F {
    fn door_arg(&self) -> F {
        **self
    }
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
        $(, newer_schema: $stamp:path)?
        $(,)?
    ) => {
        $crate::conformance_suite!(@env $inputs);
        fn __busbar_conformance_subject() -> $crate::conformance::Subject {
            $crate::conformance_suite!(
                @subject door: $door,
                manifest_dir: env!("CARGO_MANIFEST_DIR"),
                cdylib: $cdylib,
                inputs: $inputs
                $(, host: $host)?
                $(, tls: $tls)?
                $(, namespace: ($create, $drop))?
                $(, newer_schema: $stamp)?
            )
        }
        $crate::conformance_suite!(@tests);
    };
    // A door named by a `LoadedDoor` (a crate that exports its `door` function alone restates it:
    // `loaded: unsafe { LoadedDoor::from_raw(plugin::door) }`).
    (
        loaded: $loaded:expr,
        cdylib: $cdylib:expr,
        inputs: $inputs:expr
        $(, host: $host:path)?
        $(, tls: $tls:expr)?
        $(, namespace: ($create:path, $drop:path))?
        $(, newer_schema: $stamp:path)?
        $(,)?
    ) => {
        $crate::conformance_suite!(@env $inputs);
        fn __busbar_conformance_subject() -> $crate::conformance::Subject {
            $crate::conformance_suite!(
                @subject loaded: $loaded,
                manifest_dir: env!("CARGO_MANIFEST_DIR"),
                cdylib: $cdylib,
                inputs: $inputs
                $(, host: $host)?
                $(, tls: $tls)?
                $(, namespace: ($create, $drop))?
                $(, newer_schema: $stamp)?
            )
        }
        $crate::conformance_suite!(@tests);
    };
    // INTERNAL: the inputs' `env`, applied as the test binary loads, before the harness starts a
    // thread (`apply_env_before_threads`): a platform with no load-time hook applies it at the
    // first subject, as before.
    (@env $inputs:expr) => {
        #[used]
        #[cfg_attr(
            any(target_os = "linux", target_os = "android", target_os = "freebsd"),
            unsafe(link_section = ".init_array")
        )]
        #[cfg_attr(target_vendor = "apple", unsafe(link_section = "__DATA,__mod_init_func"))]
        #[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
        static __BUSBAR_CONFORMANCE_ENV: extern "C" fn() = {
            extern "C" fn apply() {
                $crate::conformance::apply_env_before_threads($inputs);
            }
            apply
        };
    };
    // INTERNAL: the subject a suite runs over, its door named by either form, with the plugin
    // crate's manifest dir (the suite passes its own `CARGO_MANIFEST_DIR`; a loader test passes a
    // scratch dir). Both forms finish in the one `@declared` step, so each reads the declares file.
    (
        @subject door: $door:path,
        manifest_dir: $dir:expr,
        cdylib: $cdylib:expr,
        inputs: $inputs:expr
        $(, host: $host:path)?
        $(, tls: $tls:expr)?
        $(, namespace: ($create:path, $drop:path))?
        $(, newer_schema: $stamp:path)?
    ) => {
        $crate::conformance_suite!(
            @declared $crate::conformance::Subject::new(
                $crate::__conformance_door!($door),
                $cdylib,
                $inputs,
            ),
            manifest_dir: $dir
            $(, host: $host)?
            $(, tls: $tls)?
            $(, namespace: ($create, $drop))?
            $(, newer_schema: $stamp)?
        )
    };
    (
        @subject loaded: $loaded:expr,
        manifest_dir: $dir:expr,
        cdylib: $cdylib:expr,
        inputs: $inputs:expr
        $(, host: $host:path)?
        $(, tls: $tls:expr)?
        $(, namespace: ($create:path, $drop:path))?
        $(, newer_schema: $stamp:path)?
    ) => {
        $crate::conformance_suite!(
            @declared $crate::conformance::Subject::of_loaded($loaded, $cdylib, $inputs),
            manifest_dir: $dir
            $(, host: $host)?
            $(, tls: $tls)?
            $(, namespace: ($create, $drop))?
            $(, newer_schema: $stamp)?
        )
    };
    // INTERNAL: the one step both forms share: the host, anchors and namespace hooks named, then
    // the plugin crate's declares file read ([`Subject::declared_in`]).
    (
        @declared $subject:expr,
        manifest_dir: $dir:expr
        $(, host: $host:path)?
        $(, tls: $tls:expr)?
        $(, namespace: ($create:path, $drop:path))?
        $(, newer_schema: $stamp:path)?
    ) => {{
        #[allow(unused_mut)]
        let mut s: $crate::conformance::Subject = $subject;
        $(s = s.with_host($host);)?
        $(s = s.with_anchors($tls);)?
        $(s = s.with_namespace($create, $drop);)?
        $(s = s.with_newer_schema($stamp);)?
        s.declared_in($dir)
    }};
    (@tests) => {
        /// THE CANARY: no configured credential crosses back, linked or dropped in.
        #[test]
        fn no_configured_credential_crosses_back() {
            $crate::conformance::canary(&__busbar_conformance_subject());
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

        /// RED: a plane declaring a billable class no case reports is refused (a door of another
        /// kind has nothing to plant).
        #[test]
        fn red_a_declared_class_no_case_reports_is_refused() {
            $crate::conformance::red_unreported_class(&__busbar_conformance_subject());
        }

        /// RED: the door at its kind ABI ± 1 is refused, linked and dropped in.
        #[test]
        fn red_a_door_at_another_kind_abi_is_refused() {
            $crate::conformance::red_kind_abi(&__busbar_conformance_subject());
        }

        /// RED: a door stating another layout fingerprint than its kind's is refused at load, for
        /// every kind.
        #[test]
        fn red_a_door_built_against_another_kind_layout_is_refused() {
            $crate::conformance::red_kind_layout(&__busbar_conformance_subject());
        }

        /// RED: a transport door whose tail states another frame piece size is refused at load
        /// (a door of another kind has no pieces).
        #[test]
        fn red_a_transport_built_against_another_frame_piece_is_refused() {
            $crate::conformance::red_frame_piece(&__busbar_conformance_subject());
        }

        /// RED: a plane door whose tail states another answer layout is refused at load (a door
        /// of another kind writes no plane answers).
        #[test]
        fn red_a_plane_built_against_another_layout_is_refused() {
            $crate::conformance::red_plane_layout(&__busbar_conformance_subject());
        }

        /// RED: the door under a row or manifest stating another Statement is refused, both ways.
        #[test]
        fn red_a_statement_other_than_the_stated_one_is_refused() {
            $crate::conformance::red_statement(&__busbar_conformance_subject());
        }

        /// RED: the door asked for as every other kind is refused, linked and dropped in.
        #[test]
        fn red_a_door_asked_for_as_another_kind_is_refused() {
            $crate::conformance::red_wrong_kind(&__busbar_conformance_subject());
        }

        /// RED: a connection over a need the plugin never declared is refused.
        #[test]
        fn red_a_connection_over_an_undeclared_need_is_refused() {
            $crate::conformance::red_undeclared_need(&__busbar_conformance_subject());
        }

        /// RED: an instance using another instance's connection is refused.
        #[test]
        fn red_another_instances_connection_is_refused() {
            $crate::conformance::red_cross_instance_conn(&__busbar_conformance_subject());
        }

        /// RED: a `ready` that fails refuses the boot with the plugin's text.
        #[test]
        fn red_a_failing_ready_refuses_the_boot() {
            $crate::conformance::red_ready(&__busbar_conformance_subject());
        }

        /// RED: an outbound auth door writing one wrong field byte fails the outbound script
        /// (over a door with no outbound family, the door and its inputs agree there is none).
        #[test]
        fn red_an_outbound_field_byte_off_is_refused() {
            $crate::conformance::outbound_plant(
                &__busbar_conformance_subject(),
                $crate::conformance::red_outbound_wrong_byte,
            );
        }

        /// RED: an outbound auth door whose `fields` writes nothing fails the outbound script
        /// (over a door with no outbound family, the door and its inputs agree there is none).
        #[test]
        fn red_an_outbound_door_writing_no_field_is_refused() {
            $crate::conformance::outbound_plant(
                &__busbar_conformance_subject(),
                $crate::conformance::red_outbound_writes_nothing,
            );
        }

        /// RED: an outbound auth door fetching its token twice fails the outbound script
        /// (over a door with no outbound family, the door and its inputs agree there is none).
        #[test]
        fn red_a_second_token_fetch_is_refused() {
            $crate::conformance::outbound_plant(
                &__busbar_conformance_subject(),
                $crate::conformance::red_outbound_double_fetch,
            );
        }

        /// RED: a networked door bound to serve with no connection table is refused by name.
        #[test]
        fn red_a_networked_door_with_no_connection_table_is_refused() {
            $crate::conformance::red_no_table(&__busbar_conformance_subject());
        }

        /// A durable store refuses a schema newer than its build (a door of another kind, or an
        /// ephemeral store, keeps no schema).
        #[test]
        fn a_store_refuses_a_schema_newer_than_its_build() {
            $crate::conformance::store_newer_schema(&__busbar_conformance_subject());
        }

        /// The declares file's `needs` is the Statement's (the one truth).
        #[test]
        fn the_declared_needs_are_the_statements() {
            $crate::conformance::needs_declared(
                &__busbar_conformance_subject(),
                env!("CARGO_MANIFEST_DIR"),
            );
        }

        /// The release binary, when asked for.
        #[test]
        fn the_suite_runs_in_the_profile_it_was_asked_to() {
            $crate::conformance::profile(cfg!(debug_assertions));
        }
    };
}

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_suite_tests.rs"]
mod tests;

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_declared_tests.rs"]
mod declared_tests;

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_newer_schema_tests.rs"]
mod newer_schema_tests;

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_ready_result_tests.rs"]
mod ready_result_tests;

#[cfg(test)]
mod ready_cleanup_tests {
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::store::{
        Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail,
    };
    use busbar_contract::abi::store::OpId;
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::records::{
        AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
        PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    pub struct ReadinessStore;

    impl Drop for ReadinessStore {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    macro_rules! refuse_data {
        ($error:expr; $($name:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {$(
            fn $name(&self, $($arg: $ty),*) -> Step<$result> {
                Step::Ready(Err($error))
            }
        )*};
    }

    impl StoreSlots for ReadinessStore {
        const TAIL: Tail = Tail {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: false,
        };
        fn validate(_: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn open_with_secrets(_: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Self, String> {
            Ok(Self)
        }
        refuse_data!(busbar_contract::records::RecordStoreError("readiness fixture has no data backend".into());
            put_key(_cx: &mut Op<'_>, _key: &VirtualKey) -> RecordStoreResult<()>;
            get_key(_cx: &mut Op<'_>, _id: &str) -> RecordStoreResult<Option<VirtualKey>>;
            list_keys(_cx: &mut Op<'_>) -> RecordStoreResult<Vec<VirtualKey>>;
            delete_key(_cx: &mut Op<'_>, _id: &str) -> RecordStoreResult<()>;
            list_keys_since(_cx: &mut Op<'_>, _since: u64) -> RecordStoreResult<Vec<VirtualKey>>;
            get_usage(_cx: &mut Op<'_>, _bucket_id: &str, _window_start: u64) -> RecordStoreResult<UsageLedger>;
            put_usage(_cx: &mut Op<'_>, _bucket_id: &str, _window_start: u64, _ledger: &UsageLedger) -> RecordStoreResult<()>;
            list_metering(_cx: &mut Op<'_>, _bucket: u64) -> RecordStoreResult<Vec<MeteringRow>>;
            put_credential(_cx: &mut Op<'_>, _secret: &CredentialSecret) -> RecordStoreResult<()>;
            put_key_with_credential(_cx: &mut Op<'_>, _key: &VirtualKey, _secret: &CredentialSecret) -> RecordStoreResult<()>;
            list_credentials(_cx: &mut Op<'_>, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>>;
            revoke_credential(_cx: &mut Op<'_>, _id: &str, _reason: &str) -> RecordStoreResult<()>;
            list_credentials_since(_cx: &mut Op<'_>, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>>;
            list_audit(_cx: &mut Op<'_>) -> RecordStoreResult<Vec<AuditRecord>>;
            add_denylist(_cx: &mut Op<'_>, _id: &str, _reason: &str) -> RecordStoreResult<()>;
            list_denylist(_cx: &mut Op<'_>) -> RecordStoreResult<Vec<String>>;
            list_audit_tail(_cx: &mut Op<'_>, _limit: u64) -> RecordStoreResult<Vec<AuditRecord>>;
            upsert_plane_record(_cx: &mut Op<'_>, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
            get_plane_record(_cx: &mut Op<'_>, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>>;
            list_plane_records(_cx: &mut Op<'_>, _kind: &str, _selector: &PlaneSelector<'_>) -> RecordStoreResult<Vec<Vec<u8>>>;
            list_plane_record_parents(_cx: &mut Op<'_>, _kind: &str) -> RecordStoreResult<Vec<String>>;
            purge_plane_records_before(_cx: &mut Op<'_>, _kind: &str, _before: u64) -> RecordStoreResult<u64>;
            delete_plane_record(_cx: &mut Op<'_>, _kind: &str, _id: &str) -> RecordStoreResult<()>;
            redeem_plane_token(_cx: &mut Op<'_>, _kind: &str, _token: &str, _expires_at: u64, _now: u64) -> RecordStoreResult<bool>;
            plane_token_live(_cx: &mut Op<'_>, _kind: &str, _token: &str, _expires_at: u64, _now: u64) -> RecordStoreResult<bool>;
        );
        refuse_data!(OpRefused::Refused("readiness fixture has no data backend".into());
            append_plane_record_op(_cx: &mut Op<'_>, _op: OpId, _record: PlaneRecordRef<'_>) -> OpResult<()>;
            add_usage_batch(_cx: &mut Op<'_>, _op: OpId, _cells: &[(&str, u64, UsageDelta)]) -> OpResult<()>;
            add_metering_batch(_cx: &mut Op<'_>, _op: OpId, _deltas: &[MeteringDelta]) -> OpResult<()>;
        );
        refuse_data!("readiness fixture has no data backend".into();
            record_put(_cx: &mut Op<'_>, _schema: &str, _key: &[u8], _value: &[u8]) -> Result<(), String>;
            record_get(_cx: &mut Op<'_>, _schema: &str, _key: &[u8]) -> Result<Option<RecordBytes>, String>;
            record_scan(_cx: &mut Op<'_>, _schema: &str, _prefix: &[u8], _limit: u32) -> Result<Scanned, String>;
        );
    }

    mod real {
        busbar_contract::store_door!(super::ReadinessStore, "ready-cleanup", "1.0.0", 8);
    }

    #[test]
    fn failed_store_ready_is_invoked_once_and_closes_its_successful_open() {
        DROPS.store(0, Ordering::SeqCst);
        let subject = super::Subject::new(real::door, "unused", "{}");
        super::red_ready(&subject);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the real SDK CLOSE drops its opened store exactly once"
        );
    }
}
