// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R3: the outbound auth `FieldsRequest` is built once per attempt, by the far end.
//! On a ticket the loader moves the request it was handed into what it lends the plugin and
//! copies it only for a grown resubmit, while the first lend is still out. On the spot it is
//! borrowed, so the lend, which owns what it lends, copies it once. Either copy clones only a
//! handle on the caller credential's one shared buffer (SP-AU6), never its bytes.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

/// The test door's handle whose `FIELDS` crossings record where the caller credential was lent.
/// It answers 17 fields, so its first lend is short and is asked again, grown.
pub(super) const LENT: u64 = 14;

static LENDS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// The test door records one `LENT` crossing's caller-credential pointer.
pub(super) fn lent(at: *const u8) {
    LENDS.lock().unwrap().push(at.addr());
}

/// The pointers the `LENT` crossings were lent so far, in order, taken.
fn lends() -> Vec<usize> {
    std::mem::take(&mut *LENDS.lock().unwrap())
}

/// The test door's handle whose grown `FIELDS` crossing holds, still lent, until the test lets it
/// answer. It answers 17 fields, so it is first asked short and then grown.
pub(super) const IN_FLIGHT: u64 = 15;

/// The caller credential the `IN_FLIGHT` call is lent.
pub(super) const IN_FLIGHT_SECRET: &[u8] = b"sk-in-flight-secret";

/// Where the held crossing was lent the credential, whether the test let it answer, and whether
/// the credential it read then was intact.
struct Held {
    lent: Option<usize>,
    open: bool,
    intact: Option<bool>,
}

static HELD: std::sync::Mutex<Held> = std::sync::Mutex::new(Held {
    lent: None,
    open: false,
    intact: None,
});

static TURN: std::sync::Condvar = std::sync::Condvar::new();

const HOLD: Duration = Duration::from_secs(10);

/// The test door holds its grown `IN_FLIGHT` crossing: it states where it was lent the credential,
/// waits until the test lets it answer, then reads whether the credential is still intact.
pub(super) fn held_in_flight(at: *const u8, intact: impl FnOnce() -> bool) {
    let mut held = HELD.lock().unwrap();
    held.lent = Some(at.addr());
    TURN.notify_all();
    let (mut held, _) = TURN.wait_timeout_while(held, HOLD, |h| !h.open).unwrap();
    held.intact = Some(intact());
}

#[test]
fn auth_fields_request_copied_once() {
    let a = opened();
    // Handle 1 answers within the first lend; handle 2 answers short and is asked again, grown.
    for (handle, answered, regrown) in [(1, 1, 0), (2, 17, 1)] {
        let wide = |f: Fields| match f {
            Fields::Ready(v) => v.len(),
            other => panic!("{other:?}"),
        };

        let scope = Scope::open();
        assert_eq!(a.fields_now(handle, &request()).map(wide), Some(answered));
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            1,
            "handle {handle}: on the spot the borrowed request is copied once into the lend"
        );
        drop(scope);

        let scope = Scope::open();
        assert_eq!(
            wide(futures_lite_block_on(a.fields(handle, request(), 0))),
            answered
        );
        assert_eq!(
            scope.count(Derive::AuthFieldsCopy),
            regrown,
            "handle {handle}: on a ticket the request moves in; only a grown resubmit copies it"
        );
    }
}

/// SINGLE-PATH SP-AU6: the plugin is lent the request's own caller-credential buffer on every
/// path, never a copy of it: on the spot and on its recall, and on a ticket's first submit and on
/// its grown resubmit.
#[test]
fn caller_secret_lent_to_plugin_without_copy() {
    let a = opened();
    let seal = busbar_contract::plugin::TestKernelSeal;
    let passthrough = || {
        let mut r = request();
        r.caller_credential = Some(b"sk-caller-secret".to_vec().into());
        r
    };
    let held = |r: &FieldsRequest| {
        r.caller_credential
            .as_ref()
            .map(|c| c.expose(&seal).as_ptr().addr())
    };
    let wide = |f: Fields| match f {
        Fields::Ready(v) => v.len(),
        other => panic!("{other:?}"),
    };

    let spot = passthrough();
    assert_eq!(a.fields_now(LENT, &spot).map(wide), Some(17));
    let lent = lends();
    assert_eq!(lent.len(), 2, "on the spot: the first lend and its recall");
    assert_eq!(
        lent[1], lent[0],
        "on the spot the recall resizes the same lend, so it lends the same buffer"
    );
    assert_eq!(
        Some(lent[0]),
        held(&spot),
        "on the spot the plugin is lent the request's own credential buffer, not a copy"
    );

    let ticketed = passthrough();
    let at = held(&ticketed);
    assert_eq!(wide(futures_lite_block_on(a.fields(LENT, ticketed, 0))), 17);
    let lent = lends();
    assert_eq!(
        lent.len(),
        2,
        "on a ticket: the first submit and its grown resubmit"
    );
    assert_eq!(
        Some(lent[0]),
        at,
        "on a ticket the first submit moves the request in and lends its own buffer"
    );
    assert_eq!(
        Some(lent[1]),
        at,
        "on a ticket the grown resubmit lends the same buffer, not a copy"
    );
}

/// SINGLE-PATH SP-AU6, failure mode 2: the in-flight lend of a ticketed call's grown resubmit holds
/// a handle on the one shared buffer, so with every other handle dropped the plugin still reads it
/// intact, and the buffer is released only once the crossing retires.
#[test]
fn an_in_flight_lend_holds_the_shared_secret_until_its_crossing_retires() {
    let a = opened();
    let shared: busbar_contract::SharedSecret = IN_FLIGHT_SECRET.to_vec().into();
    let at = shared
        .expose(&busbar_contract::plugin::TestKernelSeal)
        .as_ptr()
        .addr();
    let watch = shared.watch();
    let mut request = request();
    request.caller_credential = Some(shared.clone());

    let releaser = std::thread::spawn(move || {
        let lent = {
            let held = HELD.lock().unwrap();
            let (held, _) = TURN
                .wait_timeout_while(held, HOLD, |h| h.lent.is_none())
                .unwrap();
            held.lent
        };
        drop(shared);
        let released = watch.released();
        HELD.lock().unwrap().open = true;
        TURN.notify_all();
        (lent, released, watch)
    });
    let answered = futures_lite_block_on(a.fields(IN_FLIGHT, request, 0));
    let (lent, released, watch) = releaser.join().unwrap();

    assert!(
        matches!(answered, Fields::Ready(ref v) if v.len() == 17),
        "{answered:?}"
    );
    assert_eq!(
        lent,
        Some(at),
        "the grown resubmit's lend points into the shared buffer"
    );
    assert!(
        !released,
        "with every other handle dropped, the in-flight lend still holds the buffer"
    );
    assert_eq!(
        HELD.lock().unwrap().intact,
        Some(true),
        "the plugin reads the credential intact while only its lend holds it"
    );
    let retired = std::time::Instant::now() + HOLD;
    while !watch.released() && std::time::Instant::now() < retired {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        watch.released(),
        "retiring the crossing drops the last handle, releasing the buffer for its wipe"
    );
}
