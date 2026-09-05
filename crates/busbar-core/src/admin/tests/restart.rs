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

/// A composition with an exit path takes the drain OUT of the handler: the ask is recorded, and the
/// exit path releases it once. "Once" is the property that matters — a second release would be a
/// second drain for one restart, and a release with nothing asked must not drain a process nobody
/// asked to restart.
///
/// Safe to declare in this shared-process binary: no test publishes a shutdown channel (the test
/// above pins that), so `begin_drain` moves nothing either way here, and the exit-path release is
/// the only observer of the ask.
#[test]
fn a_drain_asked_for_is_released_by_the_exit_path_exactly_once() {
    assert!(
        !release_asked_drain(),
        "nothing asked ⇒ nothing released; a bare exit path never drains a process"
    );
    drain_released_at_exit();
    begin_drain();
    assert!(
        release_asked_drain(),
        "the ask the handler recorded is the drain the exit path releases"
    );
    assert!(
        !release_asked_drain(),
        "one restart is one drain — the release is taken, not repeated"
    );
}

/// Supervisor detection reads the markers systemd and Kubernetes stamp. Absence is not proof — a
/// `docker run --restart` container sets neither — which is why the handler asks for confirmation
/// rather than refusing when this is false.
///
/// Drives `supervisor_detected_in` with a fixture closure rather than mutating the real process
/// environment: `supervisor_detected()` itself is a byte-for-byte re-implementation target (the old
/// version of this test literally re-derived the same boolean expression it was testing, an
/// `assert_eq!(false, false)` in practice), and the two markers it reads are also read by
/// `test_admin_v1_restart_refuses_when_it_cannot_restart` elsewhere in this shared-process binary, so
/// `set_var` would be a cross-test hazard even where edition allows it.
#[test]
fn supervisor_detection_reads_the_known_markers() {
    assert!(
        !supervisor_detected_in(|_| false),
        "no marker set ⇒ no supervisor claimed"
    );
    assert!(
        supervisor_detected_in(|k| k == "INVOCATION_ID"),
        "systemd's INVOCATION_ID is a supervisor marker"
    );
    assert!(
        supervisor_detected_in(|k| k == "KUBERNETES_SERVICE_HOST"),
        "kubernetes' service-host is a supervisor marker"
    );
    assert!(
        !supervisor_detected_in(|k| k == "DOCKER_HOST"),
        "presence of an UNRELATED var is not a marker — the handler asks for confirmation \
         precisely because docker --restart sets neither known marker"
    );
}
