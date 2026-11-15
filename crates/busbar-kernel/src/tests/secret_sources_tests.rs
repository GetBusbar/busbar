// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The resolver's opened secret sources: opened outside the map lock (O3), swapped whole by a
//! re-lend while in-flight callers finish on the instance they hold (b), and reported (8028).
//! Core stubs only.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::redacted::Secret;
use busbar_contract::secret::{
    RelendCause, RelendRefused, SecretCalls, SecretRefused, SecretRelent,
};
use busbar_contract::secret_ref::SecretRef;

use crate::preflight::{OpenedSecrets, Source};

/// A stub instance: answers its name, optionally parks its first resolve on a gate, and answers
/// `relend` from a script.
struct Stub {
    name: &'static str,
    gate: Mutex<Option<mpsc::Receiver<()>>>,
    entered: Mutex<Option<mpsc::SyncSender<()>>>,
    relent: Mutex<Option<Result<SecretRelent, RelendRefused>>>,
    closed: Arc<AtomicBool>,
}

fn stub(name: &'static str) -> Stub {
    Stub {
        name,
        gate: Mutex::new(None),
        entered: Mutex::new(None),
        relent: Mutex::new(None),
        closed: Arc::new(AtomicBool::new(false)),
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl SecretCalls for Stub {
    fn resolve(&self, _: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        Ok(Secret::new(self.name.as_bytes().to_vec()))
    }

    fn relends(&self) -> bool {
        true
    }

    fn relend(
        &self,
        _: &dyn Fn(&SecretRef) -> Result<Secret<Vec<u8>>, String>,
    ) -> Result<SecretRelent, RelendRefused> {
        self.relent
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(SecretRelent::Unchanged))
    }
}

fn answer(calls: &dyn SecretCalls) -> String {
    let held = calls.resolve(b"{}").expect("answers");
    String::from_utf8(
        held.expose(&busbar_contract::plugin::TestKernelSeal)
            .clone(),
    )
    .unwrap()
}

type CodeRecord = (u16, tracing::Level, Vec<(&'static str, String)>);

#[derive(Default)]
struct Captured {
    codes: Mutex<Vec<CodeRecord>>,
    infos: AtomicUsize,
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
        self.codes
            .lock()
            .unwrap()
            .push((diag.code, level, fields.to_vec()));
    }
    fn info(&self, _: &str, _: &[(&'static str, String)]) {
        self.infos.fetch_add(1, Ordering::SeqCst);
    }
    fn audit(&self, action: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((action.into(), resource.into(), outcome));
    }
}

// T-B4 (O3)
#[test]
fn a_slow_open_never_blocks_another_modules_resolution() {
    let opened = Arc::new(OpenedSecrets::default());
    let (release, gate) = mpsc::channel::<()>();
    let (entered_tx, entered) = mpsc::sync_channel(1);
    let slow = Arc::clone(&opened);
    let opening = std::thread::spawn(move || {
        slow.calls("slow", || {
            let _ = entered_tx.send(());
            let _ = gate.recv();
            Ok(Arc::new(stub("slow")) as Arc<dyn SecretCalls>)
        })
        .map(|_| ())
    });
    entered
        .recv_timeout(Duration::from_secs(5))
        .expect("the slow open started");

    let fast = Arc::clone(&opened);
    let (done_tx, done) = mpsc::channel();
    std::thread::spawn(move || {
        let calls = fast
            .calls(
                "fast",
                || Ok(Arc::new(stub("fast")) as Arc<dyn SecretCalls>),
            )
            .expect("opens");
        let _ = done_tx.send(answer(&*calls));
    });
    assert_eq!(
        done.recv_timeout(Duration::from_secs(5)).as_deref(),
        Ok("fast"),
        "another module opened and resolved while the slow open held no lock"
    );
    release.send(()).unwrap();
    opening.join().unwrap().expect("the slow one opens too");
}

// T-B3
#[test]
fn an_in_flight_resolve_on_the_old_instance_completes_after_the_swap() {
    let report: &'static Captured = Box::leak(Box::default());
    let old = stub("old");
    let old_closed = Arc::clone(&old.closed);
    let (release, gate) = mpsc::channel();
    let (entered_tx, entered) = mpsc::sync_channel(1);
    *old.gate.lock().unwrap() = Some(gate);
    *old.entered.lock().unwrap() = Some(entered_tx);
    *old.relent.lock().unwrap() = Some(Ok(SecretRelent::Reopened(
        Arc::new(stub("new")) as Arc<dyn SecretCalls>
    )));
    let source = Arc::new(Source::new("vault", Arc::new(old), report));

    let held = source.calls();
    let in_flight = std::thread::spawn(move || answer(&*held));
    entered
        .recv_timeout(Duration::from_secs(5))
        .expect("the resolve is in flight on the old instance");

    source.relend_now(Instant::now());
    assert_eq!(
        answer(&*source.calls()),
        "new",
        "new callers get the successor"
    );
    assert!(
        !old_closed.load(Ordering::SeqCst),
        "the old instance is not closed under its in-flight caller"
    );
    release.send(()).unwrap();
    assert_eq!(
        in_flight.join().unwrap(),
        "old",
        "it finishes on what it held"
    );
    assert!(
        old_closed.load(Ordering::SeqCst),
        "and the old instance closes once its last caller lets go"
    );
    assert_eq!(report.infos.load(Ordering::SeqCst), 1);
    assert_eq!(
        *report.audits.lock().unwrap(),
        vec![(
            "plugin.credential.rotate".to_string(),
            "plugin:secrets.vault".to_string(),
            "applied"
        )]
    );
}

// T-B5
#[test]
fn an_unchanged_credential_reports_nothing() {
    let report: &'static Captured = Box::leak(Box::default());
    let source = Source::new("file-backed", Arc::new(stub("same")), report);
    for _ in 0..8 {
        source.relend_now(Instant::now());
    }
    assert_eq!(answer(&*source.calls()), "same");
    assert!(report.codes.lock().unwrap().is_empty());
    assert_eq!(report.infos.load(Ordering::SeqCst), 0);
    assert!(report.audits.lock().unwrap().is_empty());
}

// T-B2 at the source: 8028, rate limited, the running instance kept.
#[test]
fn a_failed_rotation_reports_8028_once_a_minute_and_keeps_the_source() {
    let report: &'static Captured = Box::leak(Box::default());
    let calls = stub("kept");
    *calls.relent.lock().unwrap() = Some(Err(RelendRefused {
        cause: RelendCause::ReopenFailed,
        text: "the successor did not open".into(),
    }));
    let source = Source::new("vault", Arc::new(calls), report);
    let now = Instant::now();
    source.relend_now(now);
    assert_eq!(answer(&*source.calls()), "kept");
    let codes = report.codes.lock().unwrap().clone();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].0, 8028);
    assert_eq!(codes[0].1, tracing::Level::ERROR);
    assert!(codes[0].2.contains(&("cause", "reopen-failed".to_string())));
    assert!(codes[0]
        .2
        .contains(&("instance", "secrets.vault".to_string())));
    assert_eq!(report.audits.lock().unwrap()[0].2, "degraded");
}
