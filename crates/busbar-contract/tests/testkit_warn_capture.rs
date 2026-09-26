//! The contract's test kit is the same module in every build (no feature), and its log double records
//! exactly what a plugin's own diagnostic assertions read: the WARN-and-above events emitted on the
//! capturing thread — message and structured fields — and DEBUG only when asked.

use busbar_contract::testkit::WarnCapture;

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
