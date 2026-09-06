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
/// The ask cell is one process-wide cell, so the tests that write it take turns. Without this they
/// would be testing each other's writes — which is the very fault the keyed ask exists to stop, and
/// not something to reproduce in the harness that proves it.
static ASK_CELL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ASK_CELL.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn a_drain_asked_for_is_released_by_the_exit_path_exactly_once() {
    let _turn = one_at_a_time();
    assert!(
        !release_asked_drain(UNKEYED_UNIT),
        "nothing asked ⇒ nothing released; a bare exit path never drains a process"
    );
    drain_released_at_exit();
    begin_drain();
    assert!(
        release_asked_drain(UNKEYED_UNIT),
        "the ask the handler recorded is the drain the exit path releases"
    );
    assert!(
        !release_asked_drain(UNKEYED_UNIT),
        "one restart is one drain — the release is taken, not repeated"
    );
}

/// THE ASK BELONGS TO ONE UNIT. A second administrative request finishing between the restart's
/// handler and the restart's own exit path used to take the ask with it: one process-wide bit, taken
/// by whoever reached the tail next. The drain then began under somebody else's response, and the
/// shutdown raced the 202 the restarting caller had not been sent yet.
///
/// Driven on the runtime because the attribution is ambient to the task the operation's body runs
/// on, which is the same place the real seam puts it.
#[tokio::test]
async fn a_drain_is_released_only_by_the_unit_that_asked_for_it() {
    let _turn = one_at_a_time();
    drain_released_at_exit();
    // Unit seven asks, from inside its own scope, exactly as an operation's body does.
    as_unit(7, async { begin_drain() }).await;
    assert!(
        !release_asked_drain(9),
        "a unit that asked for nothing releases nothing, however it is ordered against one that did"
    );
    assert!(
        !release_asked_drain(UNKEYED_UNIT),
        "and neither does a composition that names no unit at all"
    );
    assert!(
        release_asked_drain(7),
        "the ask is the asking unit's, and its own exit path is what releases it"
    );
    assert!(
        !release_asked_drain(7),
        "one restart is one drain, keyed or not"
    );
}

/// A drain asked for OUTSIDE any unit scope is attributed to the reserved unkeyed marker rather than
/// lost. That is the posture of a composition with an exit path but no loop behind it, and losing
/// the ask there would be a restart that answered 202 and never restarted.
#[tokio::test]
async fn an_ask_made_outside_a_unit_scope_is_the_unkeyed_one() {
    let _turn = one_at_a_time();
    drain_released_at_exit();
    begin_drain();
    assert!(
        !release_asked_drain(1),
        "an unkeyed ask is not any particular unit's to take"
    );
    assert!(
        release_asked_drain(UNKEYED_UNIT),
        "and it is released by the composition that made it"
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
