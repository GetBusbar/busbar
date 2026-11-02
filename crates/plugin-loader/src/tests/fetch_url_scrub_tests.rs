// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{Arc, Mutex};

fn logged(run: impl FnOnce()) -> Vec<String> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Capture(Arc::clone(&seen));
    tracing::subscriber::with_default(subscriber, run);
    let lines = seen.lock().unwrap().clone();
    lines
}

struct Capture(Arc<Mutex<Vec<String>>>);

struct Fields<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push(format!("{}={value:?}", field.name()));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push(format!("{}={value}", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(fields.join(" "));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn tmpdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    p.push(format!(
        "busbar-fetch-scrub-test-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

const SECRET_URL: &str =
    "https://fetcher:pw-H10-s3cr3t@plugins.example.test:8443/p/x.tar.gz?token=q-H10-tok&v=1";

fn refusing(url: &str) -> Result<Vec<u8>, String> {
    Err(format!("GET {url}: error sending request for url ({url})"))
}

fn reload_miss(url: &str) -> (Vec<String>, Vec<FetchOutcome>) {
    let dir = tmpdir();
    let spec = FetchSpec {
        url: url.to_string(),
        sha256: None,
        filename: "x.tar.gz".to_string(),
    };
    let mut outcomes = Vec::new();
    let lines = logged(|| {
        outcomes = fetch_plugins(&dir, &[spec], false, &refusing).expect("a reload miss warns");
    });
    (lines, outcomes)
}

#[test]
fn the_reload_warn_line_prints_no_url_userinfo_or_query() {
    let (lines, _) = reload_miss(SECRET_URL);
    let all = lines.join("\n");
    assert!(!lines.is_empty(), "the reload miss is logged");
    for secret in ["fetcher", "pw-H10-s3cr3t", "q-H10-tok"] {
        assert!(
            !all.contains(secret),
            "the reload warn line leaks {secret:?}: {all}"
        );
    }
    assert!(
        all.contains("url=https://plugins.example.test:8443/p/x.tar.gz?<redacted>"),
        "the host, port and path stay (they are the diagnosis): {all}"
    );
}

#[test]
fn a_plain_fetch_url_is_printed_byte_for_byte() {
    let plain = "http://127.0.0.1:49761/busbar-store-sqlite-1.0.6-x86_64.tar.gz";
    let (lines, outcomes) = reload_miss(plain);
    let all = lines.join("\n");
    assert!(all.contains(&format!("url={plain}")), "{all}");
    assert!(
        all.contains(&format!(
            "error=download failed: GET {plain}: error sending request for url ({plain})"
        )),
        "{all}"
    );
    assert_eq!(
        outcomes,
        vec![FetchOutcome::Warned {
            url: plain.to_string(),
            error: format!("download failed: GET {plain}: error sending request for url ({plain})"),
        }]
    );
}

#[test]
fn the_recorded_reload_miss_carries_no_url_userinfo_or_query() {
    let (_, outcomes) = reload_miss(SECRET_URL);
    let shown = "https://plugins.example.test:8443/p/x.tar.gz?<redacted>";
    assert_eq!(
        outcomes,
        vec![FetchOutcome::Warned {
            url: shown.to_string(),
            error: format!("download failed: GET {shown}: error sending request for url ({shown})"),
        }]
    );
}

#[test]
fn fatal_fetch_errors_redact_the_same_url_as_reload_errors() {
    let dir = tmpdir();
    for url in [
        SECRET_URL,
        "https://user:pw-boot@plugins.example.test/x.tar.gz#fragment-boot",
        "https://plugins.example.test/plain.tar.gz",
    ] {
        let spec = FetchSpec {
            url: url.to_owned(),
            sha256: None,
            filename: "x.tar.gz".to_owned(),
        };
        let errors = fetch_plugins(&dir, std::slice::from_ref(&spec), true, &refusing).unwrap_err();
        let reload = fetch_plugins(&dir, &[spec], false, &refusing).unwrap();
        let [FetchOutcome::Warned { error, .. }] = reload.as_slice() else {
            panic!("one recorded reload refusal");
        };
        assert_eq!(
            errors.as_slice(),
            std::slice::from_ref(error),
            "boot and reload expose the same diagnosis"
        );
        for secret in ["pw-H10-s3cr3t", "q-H10-tok", "pw-boot", "fragment-boot"] {
            assert!(!errors[0].contains(secret));
        }
        assert!(!dir.join("x.tar.gz").exists());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
