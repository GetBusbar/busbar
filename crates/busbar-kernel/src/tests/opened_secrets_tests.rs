// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPENED SECRET PLUGINS (audit kernel-K1 #6): one handle per plugin, and no lock held while a
//! plugin answers, so one slow or hung secret source stalls only the resolutions it answers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretCalls, SecretRefused};

use crate::preflight::OpenedSecrets;

/// A source that answers its settings back, after waiting for `gate` when it holds one.
struct Source {
    gate: Option<std::sync::Mutex<mpsc::Receiver<()>>>,
}

impl SecretCalls for Source {
    fn resolve(&self, settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        if let Some(gate) = &self.gate {
            let _ = gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(Duration::from_secs(10));
        }
        Ok(Secret::new(settings.to_vec()))
    }
}

#[test]
fn a_slow_secret_source_does_not_stall_another_modules_resolution() {
    let opened = Arc::new(OpenedSecrets::default());
    let (release, gate) = mpsc::channel::<()>();
    let gate = std::sync::Mutex::new(gate);
    let slow: Arc<dyn SecretCalls> = Arc::new(Source { gate: Some(gate) });

    // The slow module's resolution is in the plugin, waiting.
    let slow_side = {
        let opened = Arc::clone(&opened);
        std::thread::spawn(move || opened.resolve("slow-source", "slow", None, || Ok(slow)))
    };
    std::thread::sleep(Duration::from_millis(200));

    // Another module resolves while it waits.
    let (done_tx, done) = mpsc::channel();
    {
        let opened = Arc::clone(&opened);
        std::thread::spawn(move || {
            let fast: Arc<dyn SecretCalls> = Arc::new(Source { gate: None });
            let _ = done_tx.send(opened.resolve("fast-source", "fast", None, || Ok(fast)));
        });
    }
    let answered = done.recv_timeout(Duration::from_secs(3));
    let _ = release.send(());
    assert_eq!(
        answered.expect("another module's resolution was stalled behind a slow source"),
        Ok(b"fast".to_vec())
    );
    assert_eq!(
        slow_side.join().expect("the slow side ends"),
        Ok(b"slow".to_vec())
    );
}

#[test]
fn a_plugin_is_opened_once_under_its_key() {
    let opened = OpenedSecrets::default();
    let opens = AtomicUsize::new(0);
    let open = || {
        opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Source { gate: None }) as Arc<dyn SecretCalls>)
    };
    assert_eq!(
        opened.resolve("one-source", "a", None, open),
        Ok(b"a".to_vec())
    );
    assert_eq!(
        opened.resolve("one-source", "b", None, open),
        Ok(b"b".to_vec())
    );
    assert_eq!(opens.load(Ordering::SeqCst), 1);
}

/// A source that reads the disk, as the loader serves one (THE DESIGN §11.11 R4): refused without
/// the config-time proof, answering with it.
struct DiskSource;

impl SecretCalls for DiskSource {
    fn resolve(&self, _settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        Err(SecretRefused {
            error_kind: busbar_contract::abi::secret::ERROR_KIND_DENIED,
            text: busbar_contract::config_time::RESOLVE_OFF_CONFIG_TIME.to_string(),
        })
    }

    fn resolve_at_config(
        &self,
        settings: &[u8],
        _scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<Secret<Vec<u8>>, SecretRefused> {
        Ok(Secret::new(settings.to_vec()))
    }
}

/// A DROPPED-IN source answers through the opened handle with the caller's proof: at config time it
/// resolves, and without the proof (a request path) it is refused. RED before: `OpenedSecrets`
/// dropped the proof and asked the request-path form whatever the caller held.
#[test]
fn a_dropped_in_source_is_handed_the_callers_config_time_proof() {
    let opened = OpenedSecrets::default();
    let open = || Ok(Arc::new(DiskSource) as Arc<dyn SecretCalls>);
    let scope = busbar_contract::config_time::ConfigScope::config_time();
    assert_eq!(
        opened.resolve("disk-source", "at-config", Some(&scope), open),
        Ok(b"at-config".to_vec())
    );
    let refused = opened
        .resolve("disk-source", "on-a-request", None, open)
        .expect_err("a request path is refused");
    assert!(refused.contains("never on a request path"), "{refused}");
}
