// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! (b) for auth plugins: an instance whose own credential rotates takes it through its `refresh`,
//! or is re-opened and swapped when it has none; a refusal keeps it (BUSBAR-8028). Core stubs only.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use busbar_contract::auth_calls::{AuthAxis, AuthCalls, VerifyAnswer, VerifyRequest, Verifying};
use busbar_contract::plugin_settings::ResolvedSettings;
use busbar_contract::secret::AuthRelent;

use super::*;

/// One opened stub instance: its generation in its name, answering `relend` from a script.
struct Instance {
    name: String,
    answer: Result<AuthRelent, String>,
    relent: AtomicUsize,
}

impl AuthCalls for Instance {
    fn name(&self) -> &str {
        &self.name
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        unreachable!("no request is verified in these cells")
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
    fn relend(&self, _: &ResolvedSettings) -> Result<AuthRelent, String> {
        self.relent.fetch_add(1, Ordering::SeqCst);
        self.answer.clone()
    }
}

/// An axis whose every open is a new stub instance answering `answer`.
struct Axis {
    opened: AtomicUsize,
    answer: Mutex<Result<AuthRelent, String>>,
    refuse_open: Mutex<bool>,
}

impl Axis {
    fn new(answer: Result<AuthRelent, String>) -> Arc<Self> {
        Arc::new(Self {
            opened: AtomicUsize::new(0),
            answer: Mutex::new(answer),
            refuse_open: Mutex::new(false),
        })
    }
}

impl AuthAxis for Axis {
    fn linked_names(&self) -> Vec<String> {
        Vec::new()
    }
    fn answers(&self, _: &str) -> bool {
        true
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn operator_claims(&self) -> busbar_contract::auth_calls::OperatorClaims {
        busbar_contract::auth_calls::OperatorClaims::default()
    }
    fn open(
        &self,
        module: &str,
        _: &str,
        _: &ResolvedSettings,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        if *self.refuse_open.lock().unwrap() {
            return Err("the successor did not open".into());
        }
        let n = self.opened.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Arc::new(Instance {
            name: format!("{module}-{n}"),
            answer: self.answer.lock().unwrap().clone(),
            relent: AtomicUsize::new(0),
        }))
    }
}

/// One captured report line: its diagnostic code (`None` for info), level and fields.
type CapturedLine = (Option<u16>, tracing::Level, Vec<(&'static str, String)>);

#[derive(Default)]
struct Captured {
    lines: Mutex<Vec<CapturedLine>>,
    audits: Mutex<Vec<(String, String, &'static str)>>,
}

impl crate::refresh::Report for Captured {
    fn diag(
        &self,
        diag: &'static crate::diagnostics::Diagnostic,
        level: tracing::Level,
        _: &str,
        fields: &[(&'static str, String)],
    ) {
        self.lines
            .lock()
            .unwrap()
            .push((Some(diag.code), level, fields.to_vec()));
    }
    fn info(&self, _: &str, fields: &[(&'static str, String)]) {
        self.lines
            .lock()
            .unwrap()
            .push((None, tracing::Level::INFO, fields.to_vec()));
    }
    fn audit(&self, action: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((action.into(), resource.into(), outcome));
    }
}

fn relending(axis: &Arc<Axis>, reresolve: Reresolve) -> (RelendingAuth, &'static Captured) {
    let report: &'static Captured = Box::leak(Box::default());
    let dyn_axis = Arc::clone(axis) as Arc<dyn AuthAxis>;
    let first = dyn_axis
        .open("wif", "chain.wif", &ResolvedSettings::default())
        .expect("opens");
    (
        RelendingAuth::new(dyn_axis, "wif", "chain.wif", reresolve, first, report),
        report,
    )
}

fn settled() -> Reresolve {
    Box::new(|| Ok(ResolvedSettings::default()))
}

#[test]
fn an_auth_instance_takes_its_rotated_credential_through_its_refresh() {
    let axis = Axis::new(Ok(AuthRelent::Refreshed));
    let (auth, report) = relending(&axis, settled());
    auth.relend_now(Instant::now());
    assert_eq!(auth.name(), "wif-1");
    assert_eq!(
        axis.opened.load(Ordering::SeqCst),
        1,
        "refreshed in place: no second instance"
    );
    assert_eq!(
        *report.audits.lock().unwrap(),
        vec![(
            "plugin.credential.rotate".to_string(),
            "plugin:chain.wif".to_string(),
            "applied"
        )]
    );
}

#[test]
fn an_auth_plugin_with_no_refresh_is_reopened_and_swapped() {
    let axis = Axis::new(Ok(AuthRelent::NotRefreshed));
    let (auth, report) = relending(&axis, settled());
    auth.relend_now(Instant::now());
    assert_eq!(axis.opened.load(Ordering::SeqCst), 2, "a successor opened");
    assert_eq!(
        auth.now().name(),
        "wif-2",
        "every later call goes to the successor"
    );
    assert_eq!(report.audits.lock().unwrap()[0].2, "applied");
    assert_eq!(auth.name(), "wif-1", "the stated name never changes");
}

#[test]
fn a_refused_rotation_keeps_the_auth_instance_and_reports_8028() {
    let axis = Axis::new(Err("the plugin refused the new assertion".into()));
    let (auth, report) = relending(&axis, settled());
    let now = Instant::now();
    auth.relend_now(now);
    auth.relend_now(now + std::time::Duration::from_secs(1));
    assert_eq!(auth.now().name(), "wif-1", "kept");
    let lines = report.lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "once a minute: {lines:?}");
    assert_eq!(lines[0].0, Some(8028));
    assert_eq!(lines[0].1, tracing::Level::ERROR, "a refusal is ERROR");
    assert!(lines[0].2.contains(&("cause", "refused".to_string())));
    assert_eq!(report.audits.lock().unwrap()[0].2, "degraded");
}

#[test]
fn an_unresolvable_or_unopenable_rotation_keeps_the_instance() {
    let axis = Axis::new(Ok(AuthRelent::Unchanged));
    let (auth, report) = relending(
        &axis,
        Box::new(|| Err("file: /var/run/secrets/token: not found".into())),
    );
    auth.relend_now(Instant::now());
    let lines = report.lines.lock().unwrap().clone();
    assert_eq!(lines[0].1, tracing::Level::WARN);
    assert!(lines[0].2.contains(&("cause", "unresolvable".to_string())));

    let axis = Axis::new(Ok(AuthRelent::NotRefreshed));
    let (auth, report) = relending(&axis, settled());
    *axis.refuse_open.lock().unwrap() = true;
    auth.relend_now(Instant::now());
    assert_eq!(auth.now().name(), "wif-1", "the running instance is kept");
    let lines = report.lines.lock().unwrap().clone();
    assert!(lines[0].2.contains(&("cause", "reopen-failed".to_string())));
}
