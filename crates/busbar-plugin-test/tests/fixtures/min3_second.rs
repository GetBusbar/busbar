// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIN-3 second-identity fixtures for the registry arms (C-ALIAS, C-BLIND, C-ERRORS, C-STASH-REOPEN,
//! C-CANCEL-OPEN, C-ERROR-RECORDS), written with `plugin!` like a shipped plugin
//! (SDK-SAFE-TEST-HOST §3.4 G). No `unsafe`: the glue is `plugin!`'s output only.
//!
//! Every image is the one secret [`Probe`] behind its own stamp (identity, `former_names`, describe): what an arm
//! needs from an image beyond its names is chosen by the instance's config, so the image count stays at what the
//! names need. The probe records every input it is handed (the bound config in `check` and `open`, each
//! reference, each Need result) under the config's `tag`, and counts what happened to it ([`count`]).
//!
//! Config members (all optional): `tag` (the record key), `password` (a secret position, D_SECRET_PATH: `open`
//! reads it through SECRET), `stash` (`open` keeps its config `ChainBytes` in a static, once), `hold` (`open` holds
//! a guard across its Needs whose `Drop` is counted `open.future.drop`), `loop` (a handle: `open` NEEDs SECRET of it
//! forever), `refuse` (`open` answers REFUSED with error [`OPEN_ERROR`]) and `panic` (`"open"`, `"check"`,
//! `"resume"` or `"close"`: the probe panics there). A reference `{"name": n}` answers VALUE n, except `log` (logs
//! [`LOG_ERROR`]), `raw-log` (two lines through the raw log entry carrying [`RAW_LOG_ERROR`]), `fail` (FAILED with
//! [`OPEN_ERROR`]), `need` (VALUE n after a SECRET of handle 1), `stale` (reads the stash), `panic` and
//! `resume-panic` (panics, the second after a SECRET).
//!
//! Members for the entry-guard, close-log and deployment arms (C-ENTRY-GUARD, C-CLOSE-LOG, C-DEPLOYMENT-ID):
//! `open_log` (`open` logs [`OPEN_LINE`] followed by the password it resolved), `close_log` (the value's `close`
//! logs [`CLOSE_LINE`] followed by that password, through the `Host` its `open` was handed), `settle_pad` (a
//! count: `open` answers a canonical CONFIG beside INSTANCE whose `pad` member is that many bytes) and
//! `deployment` (`check` and `open` record what `Host::deployment_id` answered, as `check.deployment` and
//! `open.deployment`: the 16 bytes, or nothing for None). [`threads`] names the thread each `describe`, `open`
//! and `close` ran on; [`on_close`] runs a test's hook inside one instance's `close`.
//!
//! [`ParkNeeds`] and [`registry`] are the doubles the cancel arms open these images over; [`trace`] is the
//! ordered record of what they, the held `open` futures and a test's pool observer saw.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::ThreadId;

use busbar_contract::json::{self as facade, JsonValueTrait};
use busbar_plugin_abi::fail::failed::F_UPSTREAM;
use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID};
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::{level, Host, HostExt};
use busbar_plugin_abi::host_side::caller::{Caller, InstanceLimits};
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, Needs, OpenNeed, RecordNeed, TlsMode,
};
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::need::need;
use busbar_plugin_abi::need::{ChainBytes, SecretHandle};
use busbar_plugin_abi::plugin::{Describe, Endpoints, Plugin};
use busbar_plugin_abi::records::{settled, tag, Full, Out, Records, Reply, Writer};
use busbar_plugin_abi::types::Str;
use busbar_plugin_loader::admit::admit_header;
use busbar_plugin_loader::instance::{Ceilings, InstanceSpec, Registry};
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::{Harness, MemBinder};
use busbar_ports::binder::ConfigBinder;

/// The error numbers the probe image declares (D_ERRORS).
pub const ERRORS: &[u16] = &[OPEN_ERROR, LOG_ERROR];
/// The number a refused `open` and a failed `fail` reference carry.
pub const OPEN_ERROR: u16 = 12;
/// The number the `log` reference logs with.
pub const LOG_ERROR: u16 = 7070;
/// The number the `raw-log` reference passes to the raw log entry: over 9999 and over `u16` (65,607 = 65,536 +
/// 71), so a host that truncated it would show 71.
pub const RAW_LOG_ERROR: u32 = 65_607;

/// The probe image's identity (its stamp name) and its `former_names` word.
pub const PROBE: &str = "fixture-second-b";
pub const PROBE_FORMER: &str = "second-old";
/// The alias image's identity and its two `former_names` words.
pub const ALIAS: &str = "fixture-alias-a";
pub const ALIAS_WORDS: [&str; 2] = ["alias-old", "alias-older"];

/// The loud image's identity (C-ENTRY-GUARD, C-CLOSE-LOG): a 64 KiB D_SCHEMA and a describe that logs.
pub const LOUD: &str = "fixture-entry-guard";
/// The line the loud image's describe logs.
pub const DESCRIBE_LINE: &str = "the fixture logs from describe";
/// What an `open_log` open logs, followed by a space and the password it resolved.
pub const OPEN_LINE: &str = "the fixture logs from open with";
/// What a `close_log` instance's close logs, followed by a space and the password its open resolved.
pub const CLOSE_LINE: &str = "the fixture logs from close with";
/// The loud image's D_SCHEMA is at least this long (the `description` member alone is).
pub const BIG: usize = 64 << 10;

const SCHEMA: &str = r#"{"type":"object"}"#;
const REF_SCHEMA: &str = r#"{"type":"object","properties":{"name":{"type":"string"}}}"#;

// ---------------------------------------------------------------------------------------------------------
// What the probe saw and did, by tag
// ---------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Book {
    inputs: Vec<(String, &'static str, Vec<u8>)>,
    counts: BTreeMap<(String, &'static str), u32>,
    drops: BTreeMap<String, Vec<ThreadId>>,
    threads: BTreeMap<(String, &'static str), Vec<ThreadId>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn book() -> MutexGuard<'static, Book> {
    static BOOK: OnceLock<Mutex<Book>> = OnceLock::new();
    lock(BOOK.get_or_init(Mutex::default))
}

fn note(tag: &str, what: &'static str, bytes: &[u8]) {
    book().inputs.push((tag.to_owned(), what, bytes.to_vec()));
}

fn bump(tag: &str, what: &'static str) {
    *book().counts.entry((tag.to_owned(), what)).or_insert(0) += 1;
}

/// Every input the probe was handed under `tag`, in order: (`open.config`, `check.config`, `open.need`,
/// `resolve.reference`, `resolve.need`, bytes).
pub fn inputs(tag: &str) -> Vec<(&'static str, Vec<u8>)> {
    book()
        .inputs
        .iter()
        .filter(|(t, _, _)| t == tag)
        .map(|(_, what, bytes)| (*what, bytes.clone()))
        .collect()
}

/// How often `what` happened under `tag`: `built` (an `open` built the plugin value), `close` (the value was
/// dropped, i.e. closed), `open.future.drop` (a held `open` future was dropped).
pub fn count(tag: &str, what: &'static str) -> u32 {
    book()
        .counts
        .get(&(tag.to_owned(), what))
        .copied()
        .unwrap_or(0)
}

/// The threads a held `open` future of `tag` was dropped on, in order.
pub fn drop_threads(tag: &str) -> Vec<ThreadId> {
    book().drops.get(tag).cloned().unwrap_or_default()
}

fn ran(tag: &str, what: &'static str) {
    book()
        .threads
        .entry((tag.to_owned(), what))
        .or_default()
        .push(std::thread::current().id());
}

/// The threads `what` ran on under `tag`, in order: `describe` (under the tag `describe`, the loud image's
/// describe), `open` and `close` (an instance's, under its config's tag).
pub fn threads(tag: &str, what: &'static str) -> Vec<ThreadId> {
    book()
        .threads
        .get(&(tag.to_owned(), what))
        .cloned()
        .unwrap_or_default()
}

/// One step of the ordered trace the cancel arms read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// [`ParkNeeds`] parked a SECRET of the chain running on watchdog slot `.0`.
    Parked(u32),
    /// A held `open` future of this tag was dropped (inside the plugin's cancel).
    Dropped(String),
    /// [`ParkNeeds`]' `release` ran for the chain on slot `.0` (the driver's release, after its cancel returned).
    NeedsReleased(u32),
    /// A test's pool observer saw this block leave the pool.
    Taken(usize),
    /// A test's pool observer saw this block come back: whether every byte of it was zero, and whether the
    /// slot under watch was still leased at that moment.
    Returned {
        block: usize,
        zeroed: bool,
        leased: bool,
    },
}

static TRACE: Mutex<Vec<Step>> = Mutex::new(Vec::new());

/// Appends `step` to the trace.
pub fn step(step: Step) {
    lock(&TRACE).push(step);
}

/// Every step so far, in order.
pub fn trace() -> Vec<Step> {
    lock(&TRACE).clone()
}

type CloseHook = Box<dyn FnOnce() + Send>;

static CLOSE_HOOKS: Mutex<BTreeMap<String, CloseHook>> = Mutex::new(BTreeMap::new());

/// Runs `hook` inside the `close` of the instance whose config's tag is `tag`, after its `close_log` line and
/// before the close returns (once).
pub fn on_close(tag: &str, hook: CloseHook) {
    lock(&CLOSE_HOOKS).insert(tag.to_owned(), hook);
}

/// C-STASH-REOPEN: the one stashed `ChainBytes` (the first `stash` open's config).
static STASH: Mutex<Option<ChainBytes>> = Mutex::new(None);

// ---------------------------------------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------------------------------------

/// What the config asks of the probe.
struct Cfg {
    tag: String,
    password: Option<u32>,
    stash: bool,
    hold: bool,
    looping: Option<u32>,
    refuse: bool,
    panic: String,
    open_log: bool,
    close_log: bool,
    settle_pad: usize,
    deployment: bool,
}

impl Cfg {
    fn read(bytes: &[u8]) -> Result<Cfg, Fail> {
        let bad = || Fail::refused_because(R_CONFIG, "config must be a JSON object");
        let v = facade::parse_typed(bytes).map_err(|_| bad())?;
        if !v.is_object() {
            return Err(bad());
        }
        let text = |key: &str| {
            v.get(key)
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let flag = |key: &str| v.get(key).and_then(|x| x.as_bool()).unwrap_or(false);
        let handle = |x: Option<&facade::Value>| {
            x.and_then(|x| x.as_u64())
                .and_then(|n| u32::try_from(n).ok())
        };
        Ok(Cfg {
            tag: text("tag"),
            password: handle(v.get("password").and_then(|p| p.get("$secret"))),
            stash: flag("stash"),
            hold: flag("hold"),
            looping: handle(v.get("loop")),
            refuse: flag("refuse"),
            panic: text("panic"),
            open_log: flag("open_log"),
            close_log: flag("close_log"),
            settle_pad: v
                .get("settle_pad")
                .and_then(|x| x.as_u64())
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0),
            deployment: flag("deployment"),
        })
    }
}

/// Held across a held `open`'s Needs: its `Drop` is the future's drop (a cancel drops it with the chain).
struct Held {
    tag: String,
}

impl Drop for Held {
    fn drop(&mut self) {
        bump(&self.tag, "open.future.drop");
        book()
            .drops
            .entry(self.tag.clone())
            .or_default()
            .push(std::thread::current().id());
        step(Step::Dropped(self.tag.clone()));
    }
}

/// The secret source every image here wraps.
pub struct Probe {
    tag: String,
    panic_close: bool,
    /// `close_log`: the line `close` logs and the `Host` its `open` was handed.
    close_line: Option<(&'static Host, String)>,
    settle_pad: usize,
}

impl Drop for Probe {
    fn drop(&mut self) {
        bump(&self.tag, "close");
        ran(&self.tag, "close");
        if let Some((h, line)) = &self.close_line {
            h.log(level::WARN, line);
        }
        let hook = lock(&CLOSE_HOOKS).remove(&self.tag);
        if let Some(hook) = hook {
            hook();
        }
        if self.panic_close {
            panic!("the probe fixture panics in close");
        }
    }
}

/// What `Host::deployment_id` answers now: the 16 bytes, or nothing for None.
fn deployment_seen(h: &Host) -> Vec<u8> {
    h.deployment_id()
        .map(|id| id.0.to_vec())
        .unwrap_or_default()
}

/// The reference's settings object: the request is one CONFIG record whose body is the object (IF §8.2).
fn settings(bytes: &[u8]) -> &[u8] {
    Records::new(bytes)
        .next()
        .and_then(Result::ok)
        .filter(|rec| rec.tag == tag::CONFIG)
        .map_or(bytes, |rec| rec.body)
}

fn reference_name(bytes: &[u8]) -> Option<String> {
    let v = facade::parse_typed(settings(bytes)).ok()?;
    v.get("name").and_then(|n| n.as_str()).map(str::to_owned)
}

/// Two lines through the raw `log` entry (not `HostExt::log_error`, whose number is a `u16`).
fn raw_log(h: &Host) {
    if let Some(log) = h.fns().log {
        for _ in 0..2 {
            h.scoped(|ctx| {
                log(
                    ctx,
                    level::WARN,
                    RAW_LOG_ERROR,
                    Str::new("a raw log line numbered over 9999"),
                );
            });
        }
    }
}

/// Reads the stashed `ChainBytes` outside its own chain: the read panics (FAULT StaleHandle).
fn read_stash() {
    let stash = lock(&STASH);
    if let Some(bytes) = stash.as_ref() {
        let _ = bytes.with(<[u8]>::len);
    }
}

impl Probe {
    async fn open(h: &'static Host, config: ChainBytes) -> Result<Probe, Fail> {
        let bytes = config.to_vec();
        let cfg = Cfg::read(&bytes)?;
        note(&cfg.tag, "open.config", &bytes);
        ran(&cfg.tag, "open");
        if cfg.deployment {
            note(&cfg.tag, "open.deployment", &deployment_seen(h));
        }
        let mut password = String::new();
        if cfg.panic == "open" {
            panic!("the probe fixture panics in open");
        }
        let held = cfg.hold.then(|| Held {
            tag: cfg.tag.clone(),
        });
        if cfg.stash {
            let mut stash = lock(&STASH);
            if stash.is_none() {
                *stash = Some(config);
            }
        }
        if let Some(handle) = cfg.password {
            let value = need::secret(SecretHandle(handle))
                .await
                .map_err(Fail::from)?;
            note(&cfg.tag, "open.need", &value);
            password = String::from_utf8_lossy(&value).into_owned();
            if cfg.panic == "resume" {
                panic!("the probe fixture panics in a resumed open");
            }
        }
        if cfg.open_log {
            h.log(level::WARN, &format!("{OPEN_LINE} {password}"));
        }
        if let Some(handle) = cfg.looping {
            loop {
                let _ = need::secret(SecretHandle(handle)).await;
            }
        }
        drop(held);
        if cfg.refuse {
            return Err(
                Fail::refused_because(R_CONFIG, "the probe refuses this config")
                    .with_error(OPEN_ERROR),
            );
        }
        bump(&cfg.tag, "built");
        Ok(Probe {
            close_line: cfg
                .close_log
                .then(|| (h, format!("{CLOSE_LINE} {password}"))),
            tag: cfg.tag,
            panic_close: cfg.panic == "close",
            settle_pad: cfg.settle_pad,
        })
    }

    /// `settle_pad`: a canonical CONFIG of the tag and a `pad` member that many bytes long.
    fn settled(&self, w: &mut Out<'_>) -> Result<(), Full> {
        if self.settle_pad == 0 {
            return Ok(());
        }
        let bag = format!(
            r#"{{"tag":"{}","pad":"{}"}}"#,
            self.tag,
            "p".repeat(self.settle_pad)
        );
        settled::config(w, bag.as_bytes())
    }

    fn check(h: &Host, config: &[u8]) -> Result<(), Fail> {
        let cfg = Cfg::read(config)?;
        note(&cfg.tag, "check.config", config);
        if cfg.deployment {
            note(&cfg.tag, "check.deployment", &deployment_seen(h));
        }
        if cfg.panic == "check" {
            panic!("the probe fixture panics in check");
        }
        Ok(())
    }

    async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
        let bytes = reference.to_vec();
        note(&self.tag, "resolve.reference", &bytes);
        let name = reference_name(&bytes).ok_or_else(|| {
            Fail::refused_because(R_INVALID, "reference must be {\"name\": text}")
        })?;
        match name.as_str() {
            "log" => h.log_error(level::WARN, LOG_ERROR, "the probe logs a declared number"),
            "raw-log" => raw_log(h),
            "fail" => {
                return Err(Fail::failed_because(F_UPSTREAM, "the probe backend failed")
                    .with_error(OPEN_ERROR));
            }
            "stale" => read_stash(),
            "panic" => panic!("the probe fixture panics in resolve"),
            "need" | "resume-panic" => {
                let value = need::secret(SecretHandle(1)).await.map_err(Fail::from)?;
                note(&self.tag, "resolve.need", &value);
                if name == "resume-panic" {
                    panic!("the probe fixture panics in a resumed resolve");
                }
            }
            _ => {}
        }
        let mut reply = Reply::new();
        reply
            .put(busbar_plugin_abi::secret::tag::VALUE, name.as_bytes())
            .map_err(Fail::from)?;
        Ok(reply)
    }
}

/// The describe every image shares: a permissive schema, the `password` secret position and the reference schema.
fn describe_common(d: &mut Describe<'_>) {
    d.schema(SCHEMA);
    d.secret_path("/password");
    d.item_text(busbar_plugin_abi::secret::tag::D_REF_SCHEMA, REF_SCHEMA);
}

/// One image over the probe: `$T` wraps it, `$describe` is its describe body.
macro_rules! probe_image {
    ($T:ident, |$d:ident| $describe:block) => {
        pub struct $T(super::Probe);

        impl busbar_plugin_abi::plugin::Open for $T {
            async fn open(h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
                super::Probe::open(h, config).await.map($T)
            }

            fn settled(&self, w: &mut Out<'_>) -> Result<(), Full> {
                self.0.settled(w)
            }

            fn check(h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                super::Probe::check(h, config)
            }

            fn describe($d: &mut Describe<'_>) $describe
        }

        impl busbar_plugin_abi::Secret for $T {
            async fn resolve(
                &self,
                h: &'static Host,
                reference: ChainBytes,
            ) -> Result<Reply, Fail> {
                self.0.resolve(h, reference).await
            }
        }
    };
}

/// The probe image: a second identity with a former name and declared error numbers (C-BLIND, C-ERRORS,
/// C-STASH-REOPEN, C-CANCEL-OPEN, C-ERROR-RECORDS).
pub mod probe {
    use super::*;

    probe_image!(Image, |d| {
        describe_common(d);
        d.errors(ERRORS);
    });

    busbar_plugin_abi::plugin!(Secret, Image, former_names: "second-old", name: "fixture-second-b");
}

/// The loud image's D_SCHEMA: a permissive object schema whose `description` alone is [`BIG`] bytes.
fn big_schema() -> &'static str {
    static SCHEMA: OnceLock<String> = OnceLock::new();
    SCHEMA.get_or_init(|| format!(r#"{{"type":"object","description":"{}"}}"#, "d".repeat(BIG)))
}

/// C-ENTRY-GUARD, C-CLOSE-LOG: the probe behind an identity whose describe answers a 64 KiB D_SCHEMA and logs
/// [`DESCRIBE_LINE`]. The SDK hands `describe` no `Host`, so the line goes through the host table this
/// in-process image is admitted over (`HOST`, the one [`registry`] and the harness pass), as a C image's describe
/// logs through the `bb_host` its entry receives.
pub mod loud {
    use super::*;

    probe_image!(Image, |d| {
        ran("describe", "describe");
        HOST.log(level::WARN, DESCRIBE_LINE);
        d.schema(big_schema());
        d.secret_path("/password");
        d.item_text(busbar_plugin_abi::secret::tag::D_REF_SCHEMA, REF_SCHEMA);
    });

    busbar_plugin_abi::plugin!(Secret, Image, name: "fixture-entry-guard");
}

/// C-ALIAS: an identity with two `former_names` words.
pub mod alias {
    use super::*;

    probe_image!(Image, |d| {
        describe_common(d);
    });

    busbar_plugin_abi::plugin!(Secret, Image, former_names: "alias-old,alias-older", name: "fixture-alias-a");
}

/// C-ALIAS: a `former_names` word equal to the alias image's identity.
pub mod alias_identity_word {
    use super::*;

    probe_image!(Image, |d| {
        describe_common(d);
    });

    busbar_plugin_abi::plugin!(Secret, Image, former_names: "fixture-alias-a", name: "fixture-alias-b");
}

/// C-ALIAS: a `former_names` word equal to one of the alias image's words.
pub mod alias_shared_word {
    use super::*;

    probe_image!(Image, |d| {
        describe_common(d);
    });

    busbar_plugin_abi::plugin!(Secret, Image, former_names: "alias-old", name: "fixture-alias-c");
}

/// C-ALIAS: an identity equal to one of the alias image's words.
pub mod alias_named_word {
    use super::*;

    probe_image!(Image, |d| {
        describe_common(d);
    });

    busbar_plugin_abi::plugin!(Secret, Image, name: "alias-old");
}

// ---------------------------------------------------------------------------------------------------------
// Doubles for the arms that build their own registry
// ---------------------------------------------------------------------------------------------------------

/// A `Needs` whose SECRET of handle [`ParkNeeds::PARK`] never answers (the chain parks on it) and whose every
/// other Need answers DENIED at once.
#[derive(Default)]
pub struct ParkNeeds {
    parked: AtomicU32,
}

impl ParkNeeds {
    /// The handle a SECRET parks on.
    pub const PARK: u32 = 1;

    /// How many SECRETs have parked so far.
    pub fn parked(&self) -> u32 {
        self.parked.load(Ordering::SeqCst)
    }
}

impl Needs for ParkNeeds {
    fn open(
        &self,
        _cx: &Caller<'_>,
        _n: OpenNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn starttls(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _tls: TlsMode<'_>,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn write(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _bytes: &[u8],
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn read(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _max: u32,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn close(
        &self,
        _cx: &Caller<'_>,
        _c: ConnId,
        _reusable: bool,
    ) -> impl core::future::Future<Output = ()> + Send {
        core::future::ready(())
    }

    fn fetch(
        &self,
        _cx: &Caller<'_>,
        _n: FetchNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        let parks = handle == Self::PARK;
        if parks {
            step(Step::Parked(cx.slot));
            self.parked.fetch_add(1, Ordering::SeqCst);
        }
        Park(parks)
    }

    fn record(
        &self,
        _cx: &Caller<'_>,
        _n: RecordNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn directory(
        &self,
        _cx: &Caller<'_>,
        _n: DirNeed<'_>,
        _res: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        core::future::ready(Err(NeedErr::Denied))
    }

    fn release(&self, cx: &Caller<'_>) {
        step(Step::NeedsReleased(cx.slot));
    }
}

/// A SECRET answer: pending for ever when it parks, DENIED at once otherwise.
struct Park(bool);

impl core::future::Future for Park {
    type Output = Result<(), NeedErr>;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if self.0 {
            core::task::Poll::Pending
        } else {
            core::task::Poll::Ready(Err(NeedErr::Denied))
        }
    }
}

/// A registry over `needs`, the real `HOST` and a [`MemBinder`], with `max_steps` as its step cap and every image
/// of `plugins` admitted, in order.
pub fn registry<N: Needs>(
    needs: Arc<N>,
    max_steps: u32,
    plugins: &[&'static Plugin],
) -> Registry<N> {
    let binder: Arc<dyn ConfigBinder> = Arc::new(MemBinder::new());
    let mut registry = Registry::new(
        &HOST,
        needs,
        binder,
        Ceilings {
            max_steps,
            ..Ceilings::DEFAULT
        },
    );
    for plugin in plugins {
        let admitted = admit_header(*plugin).unwrap_or_else(|r| panic!("admit: {r:?}"));
        registry
            .add(admitted)
            .unwrap_or_else(|r| panic!("add: {r:?}"));
    }
    registry
}

/// The spec of instance `name` of the image `module` names, with `config` and no limits.
pub fn spec<'a>(module: &'a str, name: &'a str, config: &'a [u8]) -> InstanceSpec<'a> {
    InstanceSpec {
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity: module,
        name,
        config_json: config,
        limits: InstanceLimits::default(),
        public_url: None,
        caller_upstreams: &[],
    }
}

/// `plugin` admitted into a [`Harness`] over `needs` whose every answered SECRET is first registered in the
/// asking chain's scrub set (`Registry::scrub_of`, as the boot attaches it to custody), with the watchdog slot of
/// each such chain recorded, in order, in the returned list.
pub fn scrubbed(plugin: &'static Plugin, needs: FakeNeeds) -> (Arc<Harness>, Arc<Mutex<Vec<u32>>>) {
    let h = Arc::new(Harness::admit(plugin, needs).unwrap_or_else(|r| panic!("admit: {r:?}")));
    let slots = Arc::new(Mutex::new(Vec::new()));
    let (weak, seen) = (Arc::downgrade(&h), Arc::clone(&slots));
    h.needs().attach_scrubs(Arc::new(move |slot| {
        lock(&seen).push(slot);
        weak.upgrade()?.registry().scrub_of(slot)
    }));
    (h, slots)
}
