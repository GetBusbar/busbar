use super::*;

#[test]
fn cannot_restart_when_no_channel_is_published() {
    assert!(
        !can_restart(),
        "an unpublished shutdown channel cannot restart, and must say so"
    );
}

static ASK_CELL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ASK_CELL.lock().unwrap_or_else(|p| p.into_inner())
}

fn on_a_runtime<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime builds")
        .block_on(f)
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

#[test]
fn a_drain_is_released_only_by_the_unit_that_asked_for_it() {
    let _turn = one_at_a_time();
    drain_released_at_exit();

    on_a_runtime(as_unit(7, async { begin_drain() }));
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

#[test]
fn an_ask_made_outside_a_unit_scope_is_the_unkeyed_one() {
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
