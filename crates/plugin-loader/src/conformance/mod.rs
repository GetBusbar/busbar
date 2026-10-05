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
//! THE RED ARMS, run in the plugin's own run: a perturbed pinned count is refused by the same
//! comparator; the door restated at its kind ABI ± 1 is refused, linked (`KindAbi`) and dropped in
//! (`ManifestKindAbi`, before `dlopen`); the door with a `ready` that fails refuses the boot with the
//! plugin's text. And `BUSBAR_CONFORMANCE_RED=count` perturbs the both-ways arm itself, so the CI
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
    AbiStr, Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, rendering_of_library, Bind, Called,
    DispatchConfig, Dispatcher, Frame, InFrame, Kind, LinkedRow, LoadError, NoSink, OutFrame,
    Plugin,
};

mod auth;
mod export;

pub use auth::{red_outbound_double_fetch, red_outbound_wrong_byte};
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
}

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
        }
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

    /// The settings the plugin opens over (`inputs.settings`, a JSON value, serialized).
    #[must_use]
    pub fn settings(&self) -> Vec<u8> {
        match self.inputs.get("settings") {
            None | Some(serde_json::Value::Null) => b"{}".to_vec(),
            Some(serde_json::Value::String(s)) => s.as_bytes().to_vec(),
            Some(v) => v.to_string().into_bytes(),
        }
    }

    /// The resolved secrets the instance opens with (`inputs.secrets`: one string per key the
    /// Statement's `secret_refs` names, in that order), as the kernel hands them to `open` and
    /// `refresh` once the secret kind resolved them. None when absent: a plugin that states no
    /// secret reference opens with none.
    ///
    /// # Panics
    /// When `inputs.secrets` is not an array of strings.
    #[must_use]
    pub fn secrets(&self) -> Vec<Vec<u8>> {
        match self.inputs.get("secrets") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("conformance.json: every secret is a string"))
                        .as_bytes()
                        .to_vec()
                })
                .collect(),
            Some(_) => panic!("conformance.json: `secrets` is an array of strings"),
        }
    }

    /// The kind's own inputs (`inputs.<kind>`), `Null` when absent.
    #[must_use]
    pub fn kind_inputs(&self, kind: &str) -> &serde_json::Value {
        self.inputs.get(kind).unwrap_or(&serde_json::Value::Null)
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

/// How a leg reaches the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The compiled-in row: the linked door.
    Linked,
    /// The dropped-in library, admitted against the Statement its manifest states.
    Dropped,
}

/// A dispatcher of the leg's own.
#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The bind the kernel makes: a label, the inflight clamp, no envelope sink, the adopting
/// dispatcher, no connection table.
#[must_use]
pub fn bind(d: &Dispatcher, instance: &str) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
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

/// The crossings `p` has made, by the dispatcher's own crossing gate.
pub(crate) fn crossings<K: Kind>(p: &Plugin<K>) -> &AtomicU64 {
    &p.inner.crossings
}

// ---- the fold ----

/// One step of a kind's script: what it is, what it answered (as the host reads it), the crossings
/// it made and the crossings the script pins for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The step's label.
    pub label: String,
    /// Its answer, one transcript line.
    pub answer: String,
    /// The crossings the instance made while it ran.
    pub crossed: u64,
    /// The crossings the kind's script pins for it.
    pub pinned: u64,
}

/// A leg's fold: its steps, in script order.
pub type Fold = Vec<Step>;

/// Records a script's steps against one instance's crossing counter.
pub struct Recorder<'a> {
    counter: &'a AtomicU64,
    steps: Fold,
}

impl<'a> Recorder<'a> {
    /// A recorder over `counter` (the instance's crossing gate).
    #[must_use]
    pub fn new(counter: &'a AtomicU64) -> Self {
        Self {
            counter,
            steps: Vec::new(),
        }
    }

    /// Run `f` as step `label`, pinned at `pinned` crossings; its answer is what `f` returns.
    pub fn step<T>(&mut self, label: &str, pinned: u64, f: impl FnOnce() -> (String, T)) -> T {
        let before = self.counter.load(Ordering::SeqCst);
        let (answer, value) = f();
        let crossed = self.counter.load(Ordering::SeqCst) - before;
        self.steps.push(Step {
            label: label.to_string(),
            answer,
            crossed,
            pinned,
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
                "step '{}': {} crossing(s), pinned {} (answer: {})",
                s.label, s.crossed, s.pinned, s.answer
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
                "the two doors part at '{}':\n  linked:  {} [{} crossing(s)]\n  dropped: {} [{} crossing(s)]",
                l.label, l.answer, l.crossed, d.answer, d.crossed
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
/// lifecycle's `OpenIn`/`OpenOut`. No secrets: [`open_with`] hands the resolved ones.
pub fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    open_with(p, settings, &[])
}

/// A [`BLOB_SECRET`] octet blob over each of `secrets`, in order.
fn secret_blobs(secrets: &[Vec<u8>]) -> Vec<Blob> {
    secrets
        .iter()
        .map(|v| Blob {
            ptr: v.as_ptr(),
            len: v.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
        .collect()
}

/// [`open`] with the resolved `secrets` ([`Subject::secrets`]), as the kernel opens an instance
/// whose Statement names secret references.
pub fn open_with<K: Kind>(p: &Plugin<K>, settings: &[u8], secrets: &[Vec<u8>]) -> Called {
    let blobs = secret_blobs(secrets);
    let (at, len) = if blobs.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (blobs.as_ptr(), blobs.len())
    };
    if K::CODE == KindCode::Plane {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        f.input.open.settings = json(settings);
        f.input.open.secrets = at;
        f.input.open.secrets_len = len;
        f.input.open.generation = 1;
        return p.call(life::OPEN, &mut f);
    }
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.secrets = at;
    f.input.secrets_len = len;
    f.input.generation = 1;
    p.call(life::OPEN, &mut f)
}

/// `refresh` over `settings`, generation 2.
pub fn refresh<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    refresh_with(p, settings, &[])
}

/// [`refresh`] with the resolved `secrets`, as the kernel refreshes an instance whose Statement
/// names secret references.
pub fn refresh_with<K: Kind>(p: &Plugin<K>, settings: &[u8], secrets: &[Vec<u8>]) -> Called {
    let blobs = secret_blobs(secrets);
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(settings);
    if !blobs.is_empty() {
        f.input.secrets = blobs.as_ptr();
        f.input.secrets_len = blobs.len();
    }
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
/// `ready` is not called: pinned at 0 crossings. One that states it is pinned at the plugin's own
/// `inputs.ready_crossings` (1 when it answers at once; 2 when it pends once and is resumed).
///
/// # Panics
/// When the door states `ready` and the inputs pin no count for it.
pub fn ready_step<K: Kind>(rec: &mut Recorder<'_>, s: &Subject, p: &Plugin<K>, d: &Dispatcher) {
    let pinned = if p.has_ready() {
        s.inputs["ready_crossings"].as_u64().unwrap_or_else(|| {
            panic!("the door states `ready`: conformance.json must pin `ready_crossings`")
        })
    } else {
        0
    };
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

extern "C" fn abi_up_door() -> *const Door {
    ABI_UP.get()
}
extern "C" fn abi_down_door() -> *const Door {
    ABI_DOWN.get()
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
        load::<K>(s, Leg::Linked, bind(&d, "honest-linked")).expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
        for (door, abi) in [(abi_up_door as DoorFn, host + 1), (abi_down_door, host.wrapping_sub(1))] {
            let want = LoadError::KindAbi { kind, door: abi, host };
            assert_eq!(rendering_of(door).err(), Some(want.clone()), "the pack tool signs no ABI {abi} door");
            let refused = LinkedRow::of(door)
                .and_then(|row| load_linked::<K>(&row, bind(&d, "red-linked")).map(|_| ()))
                .expect_err("a linked door at another kind ABI is refused");
            assert_eq!(refused, want);
            assert!(refused.to_string().contains("rebuild"), "{refused}");
            let refused = load_dropped::<K>(&s.cdylib(), &stating_abi(&stated, abi), bind(&d, "red-dropped"))
                .map(|_| ())
                .expect_err("a manifest stating another kind ABI is refused");
            assert_eq!(refused, LoadError::ManifestKindAbi { stated: abi, host });
        }
    });
}

/// **RED: a `ready` that fails refuses the boot with the plugin's text** (#391's arm, on the real
/// plugin). The real door restated with a `ready` that answers FAILED is loaded and opened as the
/// kernel opens it; its `ready` is awaited and refused, naming the plugin and the reason, in one
/// crossing. The honest door's `ready` (its own, or none) serves.
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
    let settings = s.settings();
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        let row = LinkedRow::of(ready_fails_door).expect("the restated door states its Statement");
        let p = load_linked::<K>(&row, bind(&d, "red-ready")).expect("the restated door loads");
        assert!(p.has_ready());
        let o = open_with(&p, &settings, &s.secrets());
        assert_eq!(o.outcome, Outcome::Ready, "open: {}", called(&o));
        let before = crossings(&p).load(Ordering::SeqCst);
        let refused = p.ready(&d, READY_DEADLINE).expect_err("a failing ready refuses the boot");
        assert_eq!(
            refused,
            format!("plugin '{}' ready failed: {READY_FAILURE}", p.name())
        );
        assert_eq!(crossings(&p).load(Ordering::SeqCst) - before, 1, "one crossing, not retried");
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
    (door: $door:path, cdylib: $cdylib:expr, inputs: $inputs:expr $(,)?) => {
        fn __busbar_conformance_subject() -> $crate::conformance::Subject {
            $crate::conformance::Subject::new($door, $cdylib, $inputs)
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

        /// RED: an outbound auth door writing one wrong field byte fails the outbound script
        /// (nothing to plant for a door with no outbound family).
        #[test]
        fn red_an_outbound_field_byte_off_is_refused() {
            $crate::conformance::red_outbound_wrong_byte(&__busbar_conformance_subject());
        }

        /// RED: an outbound auth door fetching its token twice fails the outbound script
        /// (nothing to plant for a door whose styles mint no token).
        #[test]
        fn red_a_second_token_fetch_is_refused() {
            $crate::conformance::red_outbound_double_fetch(&__busbar_conformance_subject());
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
