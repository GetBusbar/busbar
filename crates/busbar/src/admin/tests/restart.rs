use super::*;

/// With no channel published — any build that never reached `run()` — the process must report that
/// it cannot restart, so a handler refuses instead of claiming a restart it cannot cause.
#[test]
fn cannot_restart_when_no_channel_is_published() {
    assert!(
        !can_restart(),
        "an unpublished shutdown channel cannot restart, and must say so"
    );
}

/// Supervisor detection reads the markers systemd and Kubernetes stamp. Absence is not proof — a
/// `docker run --restart` container sets neither — which is why the handler asks for confirmation
/// rather than refusing when this is false.
#[test]
fn supervisor_detection_reads_the_known_markers() {
    // The test process has neither marker set in any supported CI or dev environment.
    let detected = supervisor_detected();
    let has_marker = std::env::var_os("INVOCATION_ID").is_some()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some();
    assert_eq!(
        detected, has_marker,
        "detection must follow the markers exactly, never guess"
    );
}
