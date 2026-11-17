// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-454 r3.1 §5-§6 (core #454, #142): a rotation on a non-export kind degrades with BUSBAR-8028 and takes
//! effect at the next reload or restart. Core's words only: no value, no digest, no plugin text.

use std::sync::Mutex;
use std::time::Instant;

use busbar_contract::secret::{RelendCause, RelendRefused};

use super::{RelendStreak, RELEND_ACTION};

type Diag = (u16, tracing::Level, String, Vec<(&'static str, String)>);

#[derive(Default)]
struct Captured {
    diags: Mutex<Vec<Diag>>,
    audits: Mutex<Vec<(String, String, &'static str)>>,
}

impl crate::refresh::Report for Captured {
    fn diag(
        &self,
        diag: &'static crate::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(&'static str, String)],
    ) {
        self.diags
            .lock()
            .unwrap()
            .push((diag.code, level, message.to_owned(), fields.to_vec()));
    }
    fn info(&self, _: &str, _: &[(&'static str, String)]) {}
    fn audit(&self, action: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((action.into(), resource.into(), outcome));
    }
}

fn degraded(cause: RelendCause) -> Captured {
    let report = Captured::default();
    let mut streak = RelendStreak::default();
    streak.failed(
        &report,
        "hooks.audit-sink",
        &RelendRefused {
            cause,
            text: super::rotation_text(cause).to_owned(),
        },
        Instant::now(),
    );
    report
}

/// T19 (D1): a non-export rotation says the value takes effect at the next reload or restart (MIN-3 reload is
/// refused while exports are configured, so a restart may be the only way), and the process store says restart.
#[test]
fn a_non_export_rotation_reports_8028_reload_or_restart_required() {
    let report = degraded(RelendCause::ReloadRequired);
    let diags = report.diags.lock().unwrap();
    let (code, level, message, fields) = diags.first().expect("one 8028");
    assert_eq!(*code, 8028);
    assert_eq!(*level, tracing::Level::WARN);
    assert!(message.contains("reload or restart"), "{message}");
    assert!(fields.contains(&("cause", "reload-required".to_owned())));
    assert!(fields
        .iter()
        .any(|(k, v)| *k == "error" && v.contains("reload or restart")));
    assert_eq!(
        *report.audits.lock().unwrap(),
        vec![(
            RELEND_ACTION.to_owned(),
            "plugin:hooks.audit-sink".to_owned(),
            crate::audit_ring::OUTCOME_DEGRADED
        )]
    );

    let store = degraded(RelendCause::RestartRequired);
    let diags = store.diags.lock().unwrap();
    let (_, _, message, fields) = diags.first().expect("one 8028");
    assert!(message.contains("restart"), "{message}");
    assert!(!message.contains("reload"), "{message}");
    assert!(fields.contains(&("cause", "restart-required".to_owned())));
}

/// T9: each new cause has core's own text, and none of it can carry a value or plugin text.
#[test]
fn every_rotation_cause_has_core_text_and_its_own_word() {
    let causes = [
        (RelendCause::Unstable, "unstable"),
        (RelendCause::Deadline, "deadline"),
        (RelendCause::ShapeChanged, "shape-changed"),
        (RelendCause::ReloadRequired, "reload-required"),
        (RelendCause::RestartRequired, "restart-required"),
    ];
    for (cause, word) in causes {
        assert_eq!(cause.as_str(), word);
        let text = super::rotation_text(cause);
        assert!(!text.is_empty(), "{word} has core text");
        let report = degraded(cause);
        let diags = report.diags.lock().unwrap();
        let (_, _, _, fields) = diags.first().expect("one 8028");
        assert!(fields.contains(&("cause", word.to_owned())));
        assert!(fields.contains(&("error", text.to_owned())));
    }
}
