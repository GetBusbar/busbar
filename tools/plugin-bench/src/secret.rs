// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET: `resolve` (and the config-time `check`) against one opened instance.
//!
//! The instance is opened through the lifecycle `open` slot with the instance settings (default
//! `{}`, which is what core's shared linked source is opened with; `--settings` overrides) and
//! readied on the dispatcher, as `LoadedSecret::open` does. Measured ops then cross the secret
//! slots inline:
//!
//! - `resolve` over a reference naming an API-key-sized value (40 B) and a token-sized one (200 B),
//!   into a lent [`FIRST_SECRET_CAP`] buffer, the host's first buffer on the real path
//!   (`secret_calls.rs`). The bench sets the two variables in its own environment at setup, so the
//!   `env` source resolves them; the references are `{"key": VAR}`, the `{ env: VAR }` sugar as the
//!   host rewrites it. `BUSBAR_BENCH_SECRET_REF` (a JSON reference object) replaces both references
//!   for another source; its answer is then only required to be READY and non-empty.
//! - `resolve` of an unset variable: the FAILED (NOT_FOUND) answer, text and all.
//! - `check`: the config-time reference judgement (pure, never pends).
//!
//! The host's secret buffer and reason buffer are allocated once per thread and reused; the host
//! on the real path allocates and wipes a fresh zeroed 4 KiB buffer per resolve, which is host
//! cost and not measured here.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::secret::{
    slot, CheckIn, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNSET, FIRST_SECRET_CAP,
};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, Plugin};

use crate::frames::{input, json, output};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

/// The variables the bench resolves, and their value lengths.
const API_KEY_VAR: &str = "BUSBAR_BENCH_SECRET_API_KEY";
const API_KEY_BYTES: usize = 40;
const TOKEN_VAR: &str = "BUSBAR_BENCH_SECRET_TOKEN";
const TOKEN_BYTES: usize = 200;
const UNSET_VAR: &str = "BUSBAR_BENCH_SECRET_UNSET";
const REASON_CAP: usize = 4096;

struct Opened {
    plugin: Plugin<Secret>,
    _d: Arc<Dispatcher>,
}

// SAFETY: one opened secret instance is shared by the bench threads as core shares its
// `LoadedSecret` between resolvers; every measured op is a `Plugin::answer` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

/// A deterministic value of `len` printable bytes, shaped like a provider key.
fn value(prefix: &str, len: usize) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::from(prefix);
    let mut z: u64 = 0x9e37_79b9_7f4a_7c15;
    while s.len() < len {
        z = z.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        s.push(alphabet[(z >> 33) as usize % alphabet.len()] as char);
    }
    s
}

fn reference(var: &str) -> Vec<u8> {
    format!("{{\"key\":\"{var}\"}}").into_bytes()
}

fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let plugin = crate::load::<Secret>(target, crate::bind(&d, "secrets.bench", ConnTable::Probe))?;
    let settings = cfg.settings.clone().unwrap_or_else(|| b"{}".to_vec());
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    (f.input.generation, f.input.settings) = (1, json(&settings));
    let called = plugin.answer(life::OPEN, &mut f);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "secret open answered {:?}: {}",
            called.outcome,
            String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
        ));
    }
    plugin
        .ready(&d, std::time::Duration::from_secs(30))
        .map_err(|e| format!("secret ready: {e}"))?;
    Ok(Arc::new(Opened { plugin, _d: d }))
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    // Set before any bench thread (or the dispatcher's workers) exists.
    std::env::set_var(API_KEY_VAR, value("sk-bench-", API_KEY_BYTES));
    std::env::set_var(TOKEN_VAR, value("tok-bench-", TOKEN_BYTES));
    std::env::remove_var(UNSET_VAR);
    let custom = std::env::var("BUSBAR_BENCH_SECRET_REF").ok();
    let opened = open(cfg, target)?;
    let mut specs = Vec::new();
    let mut resolve = |name: String, var: &'static str, want: Want| {
        let o = opened.clone();
        let reference = match (&custom, want) {
            (Some(r), Want::Value(_)) => (r.clone().into_bytes(), Want::Any),
            _ => (reference(var), want),
        };
        specs.push(Spec {
            name,
            ops: vec!["resolve"],
            primary: 0,
            make: Box::new(move |_| {
                Ok(Box::new(Resolve::new(
                    o.clone(),
                    &reference.0,
                    reference.1,
                )?))
            }),
        });
    };
    resolve(
        format!("secret.resolve(api key {API_KEY_BYTES}B)"),
        API_KEY_VAR,
        Want::Value(API_KEY_BYTES),
    );
    resolve(
        format!("secret.resolve(token {TOKEN_BYTES}B)"),
        TOKEN_VAR,
        Want::Value(TOKEN_BYTES),
    );
    resolve(
        "secret.resolve(unset: not found)".into(),
        UNSET_VAR,
        Want::NotFound,
    );
    let o = opened;
    let checked = custom.map_or_else(|| reference(API_KEY_VAR), String::into_bytes);
    specs.push(Spec {
        name: "secret.check(config time)".into(),
        ops: vec!["check"],
        primary: 0,
        make: Box::new(move |_| Ok(Box::new(Check::new(o.clone(), &checked)?))),
    });
    Ok(specs)
}

/// What a resolve must answer.
#[derive(Clone, Copy)]
enum Want {
    /// READY with exactly this many bytes.
    Value(usize),
    /// READY with any non-empty value (a custom reference).
    Any,
    /// FAILED, NOT_FOUND.
    NotFound,
}

/// One reference and the host's lent secret buffer, allocated once per thread.
struct Resolve {
    opened: Arc<Opened>,
    settings: Box<[u8]>,
    buf: Box<[u8]>,
    want: Want,
}

impl Resolve {
    fn new(opened: Arc<Opened>, settings: &[u8], want: Want) -> Result<Self, String> {
        let mut r = Self {
            opened,
            settings: settings.into(),
            buf: vec![0; FIRST_SECRET_CAP].into_boxed_slice(),
            want,
        };
        // One untimed resolve: the answer is checked before anything is measured.
        let mut f = r.frame();
        let called = r.opened.plugin.answer(slot::RESOLVE, &mut f);
        r.check(called.outcome, called.error.as_deref(), &f.out)?;
        Ok(r)
    }

    fn frame(&mut self) -> Frame<ResolveIn, ResolveOut> {
        let mut i: ResolveIn = input();
        i.settings = json(&self.settings);
        i.secret_buf = self.buf.as_mut_ptr();
        i.secret_cap = self.buf.len();
        Frame::new(i, output())
    }

    fn check(
        &self,
        outcome: Outcome,
        error: Option<&[u8]>,
        out: &ResolveOut,
    ) -> Result<(), String> {
        let ok = match self.want {
            Want::Value(n) => {
                outcome == Outcome::Ready
                    && out.secret.len == n
                    && std::ptr::eq(out.secret.ptr, self.buf.as_ptr())
            }
            Want::Any => {
                outcome == Outcome::Ready
                    && out.secret.len > 0
                    && std::ptr::eq(out.secret.ptr, self.buf.as_ptr())
            }
            Want::NotFound => outcome == Outcome::Failed && out.error_kind == ERROR_KIND_NOT_FOUND,
        };
        if crate::report::verbose() {
            eprintln!(
                "[resolve] {outcome:?} len={} error_kind={} needed={}: {}",
                out.secret.len,
                out.error_kind,
                out.needed,
                String::from_utf8_lossy(error.unwrap_or_default())
            );
        }
        if ok {
            return Ok(());
        }
        Err(format!(
            "resolve {} answered {outcome:?} len={} error_kind={} (unset={ERROR_KIND_UNSET}, \
             not found={ERROR_KIND_NOT_FOUND}) needed={}: {}",
            String::from_utf8_lossy(&self.settings),
            out.secret.len,
            out.error_kind,
            out.needed,
            String::from_utf8_lossy(error.unwrap_or_default())
        ))
    }
}

impl Scenario for Resolve {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame();
        let plugin = &self.opened.plugin;
        let called = rec.time(0, || plugin.answer(slot::RESOLVE, &mut f));
        self.check(called.outcome, called.error.as_deref(), &f.out)
    }
}

/// One reference and the host's lent reason buffer, allocated once per thread.
struct Check {
    opened: Arc<Opened>,
    settings: Box<[u8]>,
    reason: Box<[u8]>,
}

impl Check {
    fn new(opened: Arc<Opened>, settings: &[u8]) -> Result<Self, String> {
        let mut c = Self {
            opened,
            settings: settings.into(),
            reason: vec![0; REASON_CAP].into_boxed_slice(),
        };
        let mut f = c.frame();
        let called = c.opened.plugin.answer(slot::CHECK, &mut f);
        c.verdict(called.outcome, called.error.as_deref())?;
        Ok(c)
    }

    fn frame(&mut self) -> Frame<CheckIn, OutHead> {
        let mut i: CheckIn = input();
        i.settings = json(&self.settings);
        i.err_buf = self.reason.as_mut_ptr();
        i.err_cap = self.reason.len();
        Frame::new(i, output())
    }

    fn verdict(&self, outcome: Outcome, error: Option<&[u8]>) -> Result<(), String> {
        if outcome == Outcome::Ready {
            return Ok(());
        }
        Err(format!(
            "check {} answered {outcome:?}: {}",
            String::from_utf8_lossy(&self.settings),
            String::from_utf8_lossy(error.unwrap_or_default())
        ))
    }
}

impl Scenario for Check {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame();
        let plugin = &self.opened.plugin;
        let called = rec.time(0, || plugin.answer(slot::CHECK, &mut f));
        self.verdict(called.outcome, called.error.as_deref())
    }
}
