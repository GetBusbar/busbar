// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::WarnCapture;

fn fire() {
    tracing::warn!("a warn a later capture must still be able to see");
}

#[test]
fn building_a_capture_leaves_the_process_interested_in_warns() {
    let _cap = WarnCapture::default();
    assert!(
        tracing::level_filters::LevelFilter::current() >= tracing::Level::WARN,
        "after a capture exists the process must be interested in WARN callsites, not OFF — \
         otherwise a callsite touched outside a capture can be cached off for every later test"
    );
}

#[test]
fn a_warn_fired_without_a_subscriber_does_not_blind_a_later_capture() {
    fire();

    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), fire);

    assert!(
        cap.contains("a warn a later capture must still be able to see"),
        "the capture must observe a callsite an earlier listener-less fire touched; captured: {:?}",
        cap.messages()
    );
}

#[test]
fn a_warn_is_captured_with_its_fields_and_a_debug_is_not() {
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        tracing::warn!(header = "x-key", "credential omitted");
        tracing::debug!("quiet detail");
        tracing::info!("routine");
    });
    assert_eq!(
        cap.messages(),
        vec!["credential omitted header=x-key".to_string()]
    );
    assert!(cap.contains("omitted"));
    assert_eq!(cap.count("credential"), 1);
}

#[test]
fn capturing_debug_admits_debug_and_above() {
    let cap = WarnCapture::capturing_debug();
    tracing::subscriber::with_default(cap.clone(), || {
        tracing::debug!(protocol = "p", "benign recurring");
        tracing::trace!("too fine");
        tracing::error!("broken");
    });
    assert_eq!(
        cap.messages(),
        vec![
            "benign recurring protocol=p".to_string(),
            "broken ".to_string()
        ]
    );
}

#[test]
fn an_event_on_another_thread_is_not_captured() {
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        std::thread::spawn(|| tracing::warn!("elsewhere"))
            .join()
            .expect("thread joins");
    });
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}
