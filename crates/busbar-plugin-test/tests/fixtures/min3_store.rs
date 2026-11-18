// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIN-3 store fixtures (C-SCRUB-CUT, C-FAIL-FACTS, C-STORE-INFO, C-STORE-LANE, C-WATCH-CEILING), written with
//! `plugin!` like a shipped plugin (SDK-SAFE-TEST-HOST §3.4 G): the `Store` trait, `Open` and one `plugin!` line
//! per image. No `unsafe`: the glue is `plugin!`'s output.
//!
//! One store body, [`Fixture`], behind three images, because describe facts are static (a describe cannot read a
//! config): [`inline`] (FB_EPHEMERAL, every entry inline), [`lane`] (F_BLOCKING_FILE | FB_EPHEMERAL, so every
//! entry runs on core's store lane; it declares CEIL_OPEN 3,600 s, a 60 s commit ceiling and a scan ceiling
//! above the lane range, which core clamps) and [`stall`] (the inline image whose describe runs 6 s, past the
//! fixed 5 s describe ceiling).
//!
//! What an instance does is its config (an object; every member optional):
//! - `"id"`: the key its calls are counted under ([`counts`]): `info` calls, commits (and the thread each ran
//!   on) and closes.
//! - `"secret"`: a secret reference (D_SECRET_PATH `/secret`); `open` resolves it with one SECRET, as a backend
//!   password is resolved, so custody registers the value in the instance's scrub set.
//! - `"open_sleep_ms"`, `"read_sleep_ms"`, `"commit_sleep_ms"`: block that entry's first poll this long.
//! - `"info"`, `"read"`, `"commit"`: a planned failure of that method, `{"status": "refused" | "failed",
//!   "code": n, "text": t, "retry_after_s": n, "backend_status": n}` (the facts only on FAILED).
//! - `"durability"`: `"local"` makes `info` answer DUR_LOCAL against the FB_EPHEMERAL fact (default
//!   DUR_EPHEMERAL).
//! - `"authority"`: `"wrong"` stamps READ_DONE, COMMITTED and CLOCK with an authority `info` did not state.
//! - `"commit_code"`: `"time_guard_failed"` answers COMMIT_TIME_GUARD_FAILED (default COMMIT_APPLIED).
//! - `"settle": true`: `open` answers a canonical CONFIG beside INSTANCE (`{"canonical":true}`), which core keeps
//!   for the write-back (`Registry::take_settled`) only when the open succeeds.
//! - `"hold": true`: `open` holds a guard across its Needs whose `Drop` is counted (`open_drops`, with the thread
//!   in `drop_threads`): a cancel drops it with the parked chain (C-CANCEL-MIGRATE). A value that was built is
//!   counted in `built`.
//! - `"loop": n`: after the `secret`, `open` NEEDs SECRET of handle n for ever.
//! - `"deployment": true`: `check` and `open` record what `Host::deployment_id` answered (`checks_saw`,
//!   `opens_saw`: the 16 bytes, or empty for None) (C-DEPLOYMENT-ID).
//! - `"install": text`: the install binding `check` decides on once `deployment_id()` is Some: 16 bytes other than
//!   the id refuse R_CONFIG with [`INSTALL_REFUSAL`] (whose URL carries [`INSTALL_PASSWORD`]); None skips.
//! - `"check_recovery": true`: `check` also asks the `"recovery"` gate (`Host::migrate_admit`), which the
//!   config-only CHECK denies. Every open runs `check` first, and `check` calls no host service unless
//!   `"deployment"`, `"install"` or this asks it to.
//!
//! It answers `read` with READ_DONE (READ_VALUES) and one absent VALUE per ADDRESS, `scan` with an exhausted
//! empty page, `commit` with COMMITTED (evaluating nothing) and `clock` with CLOCK.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

use busbar_contract::json::{self as facade, JsonValueTrait, Value};
use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::{fact, Fail};
use busbar_plugin_abi::host::{Host, HostExt};
use busbar_plugin_abi::need::need::secret;
use busbar_plugin_abi::need::{ChainBytes, SecretHandle};
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{Out, Records, Reply, Writer, CEIL_OPEN};
use busbar_plugin_abi::store as wire;
use busbar_plugin_abi::Store;
use tracing::field::{Field, Visit};
use tracing::{span, Event, Metadata, Subscriber};

/// What `info` states (and what every time-bearing answer is stamped with).
pub const DATASET: [u8; 16] = *b"fixture.dataset\0";
pub const DOMAIN: [u8; 16] = *b"fixture.domain\0\0";
pub const AUTHORITY: [u8; 16] = *b"fixture.clock.a\0";
/// The authority `"authority": "wrong"` stamps instead.
const WRONG_AUTHORITY: [u8; 16] = *b"fixture.clock.z\0";
pub const PHYSICAL_VERSION: u32 = 3;
/// The `observed_at` of every answer.
pub const OBSERVED_AT: u64 = 1_800_000_000;

/// The lane image's declared ceilings: CEIL_OPEN 3,600 s, commit 60 s, and a scan ceiling of 500 s that core
/// clamps to the lane range's 120 s.
const LANE_OPEN_US: u64 = 3_600_000_000;
const LANE_COMMIT_US: u64 = 60_000_000;
pub const LANE_SCAN_US: u64 = 500_000_000;
pub const LANE_SCAN_CLAMPED_US: u64 = 120_000_000;

/// The stall image's describe runs this long (the describe ceiling is 5 s).
const STALL_DESCRIBE: Duration = Duration::from_secs(6);

/// The password in the URL an `"install"` refusal names (core's scrub masks URL userinfo).
pub const INSTALL_PASSWORD: &str = "pw-install-7781";
/// The text a wrong install binding refuses with.
const INSTALL_REFUSAL: &str =
    "the install binding https://installer:pw-install-7781@licence.example names another deployment";

/// What one config `"id"` saw.
#[derive(Clone, Debug, Default)]
pub struct Counts {
    pub info: u32,
    pub commits: u32,
    pub commit_threads: Vec<ThreadId>,
    pub closes: u32,
    pub built: u32,
    pub open_drops: u32,
    pub drop_threads: Vec<ThreadId>,
    pub opens_saw: Vec<Vec<u8>>,
    pub checks_saw: Vec<Vec<u8>>,
}

/// Held across a `"hold"` open's Needs; its drop is the open future's.
struct HeldOpen(String);

impl Drop for HeldOpen {
    fn drop(&mut self) {
        let thread = std::thread::current().id();
        bump(&self.0, |c| {
            c.open_drops += 1;
            c.drop_threads.push(thread);
        });
    }
}

/// What `Host::deployment_id` answers now: the 16 bytes, or nothing for None.
fn deployment_seen(h: &Host) -> Vec<u8> {
    h.deployment_id()
        .map(|id| id.0.to_vec())
        .unwrap_or_default()
}

static COUNTS: Mutex<BTreeMap<String, Counts>> = Mutex::new(BTreeMap::new());

fn bump(id: &str, f: impl FnOnce(&mut Counts)) {
    let mut all = COUNTS.lock().unwrap_or_else(PoisonError::into_inner);
    f(all.entry(id.to_owned()).or_default());
}

/// What the instances opened with `"id": id` saw so far.
pub fn counts(id: &str) -> Counts {
    COUNTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(id)
        .cloned()
        .unwrap_or_default()
}

/// A JSON non-negative integer, typed or kept as its lexeme.
pub fn number(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_raw_number()
            .and_then(|n| n.as_str().parse::<u64>().ok())
    })
}

/// A planned REFUSED or FAILED answer.
#[derive(Clone, Debug)]
pub struct Planned {
    pub refused: bool,
    pub code: u32,
    pub text: String,
    pub retry_after_s: Option<u64>,
    pub backend_status: Option<u64>,
}

impl Planned {
    /// `{"status", "code", "text", "retry_after_s", "backend_status"}`; None when `v` is no such object.
    pub fn of(v: &Value) -> Option<Planned> {
        let refused = match v.get("status")?.as_str()? {
            "refused" => true,
            "failed" => false,
            _ => return None,
        };
        Some(Planned {
            refused,
            code: u32::try_from(v.get("code").and_then(number)?).ok()?,
            text: v
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_owned(),
            retry_after_s: v.get("retry_after_s").and_then(number),
            backend_status: v.get("backend_status").and_then(number),
        })
    }

    /// The `Fail` a plugin answers: `Fail::refused_because` or `Fail::failed_because(..).with_fact(..)`.
    pub fn fail(&self) -> Fail {
        if self.refused {
            return Fail::refused_because(self.code, self.text.clone());
        }
        let mut fail = Fail::failed_because(self.code, self.text.clone());
        if let Some(s) = self.retry_after_s {
            fail = fail.with_fact(fact::FACT_RETRY_AFTER_S, s);
        }
        if let Some(s) = self.backend_status {
            fail = fail.with_fact(fact::FACT_BACKEND_STATUS, s);
        }
        fail
    }
}

/// The `{"$secret": n}` handle core bound at `/secret`, if the config has one.
pub fn secret_handle(config: &Value) -> Option<SecretHandle> {
    let n = config.get("secret")?.get("$secret").and_then(number)?;
    u32::try_from(n).ok().map(SecretHandle)
}

fn object(config: &[u8]) -> Result<Value, Fail> {
    facade::parse_value(config)
        .ok()
        .filter(|v| v.is_object())
        .ok_or_else(|| Fail::refused_because(R_CONFIG, "config must be an object"))
}

fn millis(config: &Value, key: &str) -> Duration {
    Duration::from_millis(config.get(key).and_then(number).unwrap_or(0))
}

/// What one instance's config asked for.
pub struct Plan {
    id: String,
    read_sleep: Duration,
    commit_sleep: Duration,
    info: Option<Planned>,
    read: Option<Planned>,
    commit: Option<Planned>,
    ephemeral: bool,
    authority: [u8; 16],
    commit_code: u32,
    settle: bool,
    hold: bool,
    looping: Option<u32>,
    deployment: bool,
    install: Option<String>,
    recovery: Option<u64>,
    ignore_recovery: bool,
    teardown_probe: bool,
    recovery_fail: bool,
    check_recovery: bool,
}

impl Plan {
    fn of(config: &Value) -> Self {
        let text = |key: &str| config.get(key).and_then(|v| v.as_str()).map(str::to_owned);
        Plan {
            id: text("id").unwrap_or_default(),
            read_sleep: millis(config, "read_sleep_ms"),
            commit_sleep: millis(config, "commit_sleep_ms"),
            info: config.get("info").and_then(Planned::of),
            read: config.get("read").and_then(Planned::of),
            commit: config.get("commit").and_then(Planned::of),
            ephemeral: text("durability").as_deref() != Some("local"),
            authority: if text("authority").as_deref() == Some("wrong") {
                WRONG_AUTHORITY
            } else {
                AUTHORITY
            },
            commit_code: if text("commit_code").as_deref() == Some("time_guard_failed") {
                wire::COMMIT_TIME_GUARD_FAILED
            } else {
                wire::COMMIT_APPLIED
            },
            settle: config.get("settle").and_then(|v| v.as_bool()) == Some(true),
            hold: config.get("hold").and_then(|v| v.as_bool()) == Some(true),
            looping: config
                .get("loop")
                .and_then(number)
                .and_then(|n| u32::try_from(n).ok()),
            deployment: config.get("deployment").and_then(|v| v.as_bool()) == Some(true),
            install: text("install"),
            recovery: config.get("recovery").and_then(number),
            ignore_recovery: config.get("ignore_recovery").and_then(Value::as_bool) == Some(true),
            teardown_probe: config.get("teardown_probe").and_then(Value::as_bool) == Some(true),
            recovery_fail: config.get("recovery_fail").and_then(Value::as_bool) == Some(true),
            check_recovery: config.get("check_recovery").and_then(Value::as_bool) == Some(true),
        }
    }
}

/// One opened store instance; `MODE` picks the image (0 inline, 1 lane, 2 stall). Its drop (the instance's
/// close) is counted.
pub struct Fixture<const MODE: u8>(Plan);

impl<const MODE: u8> core::ops::Deref for Fixture<MODE> {
    type Target = Plan;
    fn deref(&self) -> &Plan {
        &self.0
    }
}

impl<const MODE: u8> Drop for Fixture<MODE> {
    fn drop(&mut self) {
        bump(&self.0.id, |c| c.closes += 1);
    }
}

impl<const MODE: u8> Open for Fixture<MODE> {
    async fn open(h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let (plan, handle, sleep) = config.with(|bytes| {
            object(bytes).map(|v| (Plan::of(&v), secret_handle(&v), millis(&v, "open_sleep_ms")))
        })?;
        if plan.deployment {
            let seen = deployment_seen(h);
            bump(&plan.id, |c| c.opens_saw.push(seen));
        }
        std::thread::sleep(sleep);
        let held = plan.hold.then(|| HeldOpen(plan.id.clone()));
        if let Some(count) = plan.recovery {
            let result = h.migrate_admit(count);
            if !plan.ignore_recovery {
                result?;
            }
        }
        if plan.teardown_probe {
            crate::c_migrate::probe_teardown(h);
        }
        if plan.recovery_fail {
            return Err(Fail::failed(busbar_plugin_abi::fail::failed::F_UNAVAILABLE));
        }
        if let Some(handle) = handle {
            // The backend password: resolved and used once, never kept (wiped on drop).
            drop(secret(handle).await?);
            if let Some(count) = plan.recovery {
                let result = h.migrate_admit(count);
                if !plan.ignore_recovery {
                    result?;
                }
            }
        }
        if let Some(handle) = plan.looping {
            loop {
                let _ = secret(SecretHandle(handle)).await;
            }
        }
        drop(held);
        bump(&plan.id, |c| c.built += 1);
        Ok(Fixture(plan))
    }

    fn settled(&self, w: &mut Out<'_>) -> Result<(), busbar_plugin_abi::records::Full> {
        if self.settle {
            busbar_plugin_abi::records::settled::config(w, br#"{"canonical":true}"#)?;
        }
        Ok(())
    }

    fn check(h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        let plan = Plan::of(&object(config)?);
        // Every open runs this check first under the config-only CHECK host (694764d34e), where any host call
        // faults the check: host services are asked for only when the config asks this check to.
        if plan.check_recovery {
            if let Some(count) = plan.recovery {
                h.migrate_admit(count)?;
            }
        }
        let seen = if plan.deployment || plan.install.is_some() {
            deployment_seen(h)
        } else {
            Vec::new()
        };
        if plan.deployment {
            bump(&plan.id, |c| c.checks_saw.push(seen.clone()));
        }
        match &plan.install {
            Some(install) if !seen.is_empty() && seen != install.as_bytes() => {
                Err(Fail::refused_because(R_CONFIG, INSTALL_REFUSAL))
            }
            _ => Ok(()),
        }
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.secret_path("/secret");
        match MODE {
            1 => {
                d.facts(wire::F_BLOCKING_FILE | wire::FB_EPHEMERAL);
                d.ceiling_us(CEIL_OPEN, LANE_OPEN_US);
                d.ceiling_us(wire::M_COMMIT, LANE_COMMIT_US);
                d.ceiling_us(wire::M_SCAN, LANE_SCAN_US);
            }
            2 => {
                std::thread::sleep(STALL_DESCRIBE);
                d.facts(wire::FB_EPHEMERAL);
            }
            _ => {
                d.facts(wire::FB_EPHEMERAL);
            }
        }
    }
}

impl<const MODE: u8> Store for Fixture<MODE> {
    async fn read(&self, _h: &'static Host, req: ChainBytes) -> Result<Reply, Fail> {
        std::thread::sleep(self.read_sleep);
        if let Some(planned) = &self.read {
            return Err(planned.fail());
        }
        let addresses = req.with(|bytes| {
            Records::new(bytes)
                .filter(|rec| matches!(rec, Ok(rec) if rec.tag == wire::tag::ADDRESS))
                .count()
        });
        let mut reply = Reply::new();
        let done = wire::ReadDone {
            code: wire::READ_VALUES,
            _r: 0,
            observed_at: OBSERVED_AT,
            authority: self.authority,
        };
        reply.put_pod(wire::tag::READ_DONE, &done)?;
        for _ in 0..addresses {
            let absent = wire::ValueRec { found: 0, _r: 0 };
            reply.put_pod_tail(wire::tag::VALUE, &absent, &[])?;
        }
        Ok(reply)
    }

    async fn scan(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
        let mut reply = Reply::new();
        let done = wire::ScanDone {
            code: wire::SCAN_PAGE,
            continuation: wire::SCAN_EXHAUSTED,
            generation: 0,
        };
        reply.put_pod(wire::tag::SCAN_DONE, &done)?;
        Ok(reply)
    }

    async fn commit(&self, _h: &'static Host, _cand: ChainBytes) -> Result<Reply, Fail> {
        std::thread::sleep(self.commit_sleep);
        let thread = std::thread::current().id();
        bump(&self.id, |c| {
            c.commits += 1;
            c.commit_threads.push(thread);
        });
        if let Some(planned) = &self.commit {
            return Err(planned.fail());
        }
        let mut reply = Reply::new();
        let done = wire::Committed {
            code: self.commit_code,
            _r: 0,
            observed_at: OBSERVED_AT,
            authority: self.authority,
        };
        reply.put_pod(wire::tag::COMMITTED, &done)?;
        Ok(reply)
    }

    async fn clock(&self, _h: &'static Host, _dataset: ChainBytes) -> Result<Reply, Fail> {
        let mut reply = Reply::new();
        let clock = wire::ClockRec {
            observed_at: OBSERVED_AT,
            authority: self.authority,
        };
        reply.put_pod(wire::tag::CLOCK, &clock)?;
        Ok(reply)
    }

    fn info(&self, _h: &Host, out: &mut Out<'_>) -> Result<(), Fail> {
        bump(&self.id, |c| c.info += 1);
        if let Some(planned) = &self.info {
            return Err(planned.fail());
        }
        let info = wire::InfoRec {
            dataset: DATASET,
            atomic_domain: DOMAIN,
            clock_authority: AUTHORITY,
            physical_version: PHYSICAL_VERSION,
            durability: if self.ephemeral {
                wire::DUR_EPHEMERAL
            } else {
                wire::DUR_LOCAL
            },
        };
        out.put_pod(wire::tag::INFO, &info)?;
        Ok(())
    }
}

/// Every entry inline (FB_EPHEMERAL).
pub mod inline {
    busbar_plugin_abi::plugin!(Store, super::Fixture<0>, name: "fixture-store-inline");
}

/// Every entry on core's store lane (F_BLOCKING_FILE | FB_EPHEMERAL), with declared ceilings.
pub mod lane {
    busbar_plugin_abi::plugin!(Store, super::Fixture<1>, name: "fixture-store-lane");
}

/// The inline image whose describe runs past its 5 s ceiling.
pub mod stall {
    busbar_plugin_abi::plugin!(Store, super::Fixture<2>, name: "fixture-store-stall");
}

// ---------------------------------------------------------------------------------------------------------
// Capture: the events core emits outside the plugin log sink (adapter warnings, `add`'s clamp line)
// ---------------------------------------------------------------------------------------------------------

/// One tracing event: its message and every other field as text (`?` fields as their `Debug`).
#[derive(Clone, Debug, Default)]
pub struct Captured {
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

impl Captured {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

impl Visit for Captured {
    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        let text = format!("{value:?}");
        if field.name() == "message" {
            self.message = text;
        } else {
            self.fields.insert(field.name().to_owned(), text);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.message);
        } else {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }
}

/// A subscriber that keeps every event emitted on the threads it is the default of. Install it with
/// [`Capture::install`] after a `Harness` is built (the harness's own tap keeps only plugin log lines, which
/// carry `kind` and `instance`; the store adapter's "store call not answered OK" and `add`'s clamp line do not).
#[derive(Clone, Default)]
pub struct Capture {
    events: Arc<Mutex<Vec<Captured>>>,
    spans: Arc<std::sync::atomic::AtomicU64>,
}

impl Capture {
    /// This thread's default subscriber until the guard drops.
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(self.clone())
    }

    pub fn events(&self) -> Vec<Captured> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The events whose message is `message`.
    pub fn with_message(&self, message: &str) -> Vec<Captured> {
        self.events()
            .into_iter()
            .filter(|e| e.message == message)
            .collect()
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(
            self.spans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1,
        )
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = Captured::default();
        event.record(&mut captured);
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(captured);
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

/// `text` as a JSON string literal (quotes, backslashes and control bytes escaped).
pub fn json_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------------------------------------
// Booting: the harness with custody's scrub registration attached
// ---------------------------------------------------------------------------------------------------------

/// `plugin` admitted into a [`Harness`] whose `FakeNeeds` registers every SECRET it answers in the asking
/// instance's scrub set (`Registry::scrub_of`, as the boot attaches it to custody), with the test kernel seal
/// installed for store opens.
pub fn booted(
    plugin: &'static busbar_plugin_abi::plugin::Plugin,
    needs: busbar_plugin_test::fake_needs::FakeNeeds,
) -> Arc<busbar_plugin_test::suites::harness::Harness> {
    Arc::new(
        busbar_plugin_test::suites::harness::Harness::admit(plugin, needs.scrubbing())
            .unwrap_or_else(|r| panic!("admit refused: {r:?}")),
    )
}

/// The namespace the arms read.
pub const NS: [u8; 16] = *b"fixture.ns.v1\0\0\0";

/// One unguarded read of one address of the store's dataset.
pub async fn read_one(
    b: &dyn busbar_contract::persistence::PersistenceBackend,
) -> Result<busbar_contract::persistence::ReadResult, busbar_contract::persistence::Failure> {
    use busbar_contract::persistence::{Address, Read};
    b.read(Arc::new(Read {
        dataset: b.info().dataset,
        addresses: vec![Address {
            namespace: NS,
            key: b"k".to_vec(),
        }],
        time: None,
    }))
    .await
}

/// The writer the arms' initialization candidates register.
pub const WRITER: [u8; 16] = [0xA1; 16];

/// A self-fenced initialization candidate for `b`'s dataset and its key (the SDK store cases' bootstrap).
pub fn initialization(
    b: &dyn busbar_contract::persistence::PersistenceBackend,
) -> (
    busbar_contract::persistence::PreparedCandidate,
    busbar_contract::persistence::CommitKey,
) {
    use busbar_contract::persistence::{CommitKey, SelfFenced};
    let init = busbar_contract::persistence::conformance::initialization(b, WRITER, 1);
    let key =
        CommitKey::self_fenced(&SelfFenced::check(&init).expect("a self-fenced initialization"));
    (init, key)
}

/// The store adapter's warning for a REFUSED or FAILED answer (store.rs `exec`).
pub const NOT_ANSWERED_OK: &str = "store call not answered OK";
