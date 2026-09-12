//! THE SESSION-PARAMETER PROJECTION CELLS — what an operator's gate and rewrite tap see when this
//! plane's session opens, and what it takes back when one commits a rewrite.
//!
//! These are the PROJECTION half of the two hook cells the 1.5.x mount carries
//! (`busbar-voice`'s `hook_gate_tests` / `hook_tap_tests`). Those cells prove the two hops FIRE —
//! a rejecting gate refuses an open, a committed rewrite reaches the wire — and they stay where the
//! firing is. What could not be proven there, and is proven here, is that the payload the hops carry
//! is THIS PLANE'S, rendered by the plane itself: an operator's configured gate matches bytes, so a
//! projection that rendered different bytes would silently stop matching every gate a deployment
//! already had, with no signal anywhere.
//!
//! The carrier cell is the sharp one. `busbar_voice_codec::ir::config::g711_config` is the µ-law
//! lock the 1.5.x front door opens a carrier leg with, and the assertion is byte equality against
//! it — not "a config with µ-law in it".

use busbar_contract::bounded::Labels;
use busbar_contract::plane::{PlaneSessionState, SessionPlane};
use busbar_contract::unit::{Clock, ConfigView, Ctx};
use busbar_voice_codec::ir::config::{self, SessionConfig};

use crate::session::VoiceSessionState;
use crate::tests::harness::{ctx, EmptyConfig, LeakArena, WsStack};
use crate::VoicePlane;

/// A configuration block that answers ONE key — the deployment's own declared session defaults.
#[derive(Debug)]
struct DeclaredConfig {
    session_defaults: String,
}

impl ConfigView for DeclaredConfig {
    fn get_str(&self, key: &str) -> Option<&str> {
        (key == "session_defaults").then_some(self.session_defaults.as_str())
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// A plane with no upstream table: the projection reads none.
fn plane() -> VoicePlane {
    VoicePlane::new(&[])
}

/// One half of a session's state, already bound to the dialect under test.
fn opened(dialect: &'static crate::dialect::Dialect) -> PlaneSessionState {
    PlaneSessionState::new(VoiceSessionState::for_dialect(dialect))
}

/// EVERY OTHER DIALECT opens on the deployment's declared defaults, and on the section default when
/// a deployment declares none.
#[test]
fn a_declared_default_is_what_a_session_projects_and_the_section_default_when_none_is_declared() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();

    // ── THE CONTROL: nothing declared ⇒ the section default, byte for byte.
    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);
    let mut st = opened(&super::harness::A_DIALECT);
    let params = SessionPlane::session_params(&plane(), &mut st, &c).expect("a session projects");
    assert_eq!(
        params.declared,
        serde_json::to_vec(&config::default_session()).unwrap(),
        "with nothing declared the projection is the section default, which is the value the 1.5.x \
         front door locks a non-carrier leg with"
    );

    // ── THE TEST: a declared posture the section default never carries reaches the projection.
    let declared = SessionConfig {
        instructions: Some("declared-by-the-deployment".to_string()),
        voice: Some("marin".to_string()),
        ..SessionConfig::default()
    };
    let cfg = DeclaredConfig {
        session_defaults: serde_json::to_string(&declared).unwrap(),
    };
    let c = Ctx::new(
        Clock {
            unix_secs: 1_772_000_000,
            monotonic_nanos: 0,
        },
        &cfg,
        None,
        &stack,
        &labels,
        &arena,
    );
    let mut st = opened(&super::harness::A_DIALECT);
    let params = SessionPlane::session_params(&plane(), &mut st, &c).expect("a session projects");
    assert_eq!(
        params.declared,
        serde_json::to_vec(&declared).unwrap(),
        "the DEPLOYMENT's declared session defaults are what a gate sees. The section default here \
         would be the whole finding: the projection ignoring what an operator wrote down"
    );
}

/// A COMMITTED REWRITE replaces the locked posture; a payload that is not a session shape does not.
#[test]
fn an_adopted_rewrite_replaces_the_projection_and_an_unreadable_one_does_not() {
    let arena = LeakArena;
    let cfg = EmptyConfig;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let c = ctx(&arena, &cfg, &stack, &labels);
    let p = plane();

    let mut st = opened(&super::harness::A_DIALECT);
    let locked = SessionPlane::session_params(&p, &mut st, &c)
        .expect("a session projects")
        .declared
        .to_vec();

    let rewritten = SessionConfig {
        instructions: Some("rewritten-by-hook".to_string()),
        ..SessionConfig::default()
    };
    let committed = serde_json::to_vec(&rewritten).unwrap();
    SessionPlane::adopt_session_params(&p, &mut st, &committed);
    assert_eq!(
        SessionPlane::session_params(&p, &mut st, &c)
            .expect("a session still projects")
            .declared,
        committed.as_slice(),
        "what a rewrite committed is what the session opens on. The locked posture here would mean \
         the rewrite fired and changed nothing, which is the failure the tap cell cannot see"
    );

    // A payload that does not read back as a session shape is not a rewrite of these parameters.
    SessionPlane::adopt_session_params(&p, &mut st, b"{\"turn_detection\": 7}");
    assert_eq!(
        SessionPlane::session_params(&p, &mut st, &c)
            .expect("a session still projects")
            .declared,
        committed.as_slice(),
        "an unreadable payload leaves the last posture the plane could read standing"
    );
    assert_ne!(
        locked, committed,
        "the control: the rewrite has to differ from the lock or the assertion above proves nothing"
    );
}

// ── the opening frame ───────────────────────────────────────────────────────────────────────────

/// A DIALECT THAT DECLARES AN OPENING EVENT OPENS ITS SESSION WITH ONE, AND ONE THAT DOES NOT OWES
/// NOTHING.
///
/// The claim the whole declaration exists for. A duplex session is not always client-speaks-first:
/// the GA realtime handshake opens with the resolved session object, and a client that never
/// receives one has no session to update in and no id to name — so it sends nothing and waits. Every
/// other seam on the session face is driven BY an arriving frame, so a wire like that had no way to
/// say its first byte was the server's, and a composition that mounted it served an upgraded socket
/// that stayed silent until the client gave up.
///
/// WHICH event is the row's and the bytes are the session's: this cell asserts both ends of that
/// division — the frame appears only for the row that declares one, and what it carries is the
/// posture the session resolved to rather than a shape invented here.
#[test]
fn an_opening_event_is_declared_by_the_row_and_rendered_from_the_resolved_posture() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);
    let p = plane();

    // ── A ROW THAT DECLARES NONE owes nothing, which is the ordinary answer.
    let mut silent = opened(&super::harness::A_DIALECT);
    let _ = SessionPlane::session_params(&p, &mut silent, &c);
    assert!(
        SessionPlane::opening_frames(&p, &mut silent).is_empty(),
        "a wire that is client-speaks-first owes no frame before one arrives"
    );

    // ── A ROW THAT DECLARES ONE opens with it.
    let mut speaking = opened(&super::harness::A_SPEAKING_DIALECT);
    let _ = SessionPlane::session_params(&p, &mut speaking, &c);
    let frames = SessionPlane::opening_frames(&p, &mut speaking);
    assert_eq!(frames.len(), 1, "one opening event, once");
    let rendered: serde_json::Value =
        serde_json::from_slice(&frames[0]).expect("the opening frame is this dialect's own JSON");
    assert_eq!(
        rendered.get("type").and_then(serde_json::Value::as_str),
        Some("session.created"),
        "the event the row declared, rendered through the codec its row names: {rendered}"
    );
    assert_eq!(
        rendered.get("session"),
        Some(&serde_json::to_value(config::default_session()).unwrap()),
        "and what it announces is the posture this session RESOLVED to, byte for byte — not a \
         stand-in shape and not the request's own hint"
    );
}

/// AND IT ANNOUNCES WHAT A REWRITE COMMITTED, never the posture the projector first rendered.
///
/// The ordering claim, and it is the one that costs something to get wrong. An operator's tap may
/// rewrite a session's parameters at the open; the session then RUNS under what the tap committed.
/// A node that announced the pre-rewrite posture would tell the client one session and serve
/// another, and every later frame the client built against what it was told would be built against
/// a session that does not exist.
#[test]
fn the_opening_event_announces_what_a_rewrite_committed() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);
    let p = plane();

    let mut st = opened(&super::harness::A_SPEAKING_DIALECT);
    // The projector runs first, as the accept file runs it.
    let _ = SessionPlane::session_params(&p, &mut st, &c);
    // A tap commits a different, still-readable posture.
    let mut rewritten: SessionConfig = config::default_session();
    rewritten.model = Some("a-model-a-tap-chose".to_string());
    let committed = serde_json::to_vec(&rewritten).unwrap();
    SessionPlane::adopt_session_params(&p, &mut st, &committed);

    let frames = SessionPlane::opening_frames(&p, &mut st);
    let rendered: serde_json::Value = serde_json::from_slice(&frames[0]).expect("one frame");
    assert_eq!(
        rendered.get("session"),
        Some(&serde_json::to_value(&rewritten).unwrap()),
        "the announcement is what the session resolved to after the tap, not what the projector \
         first rendered: {rendered}"
    );
}

// ── the request terminal ─────────────────────────────────────────────────────────────────────────

/// A SERVED SESSION MARKS A REQUEST IT CANNOT ANSWER, AND A WIRE WITH NO REQUEST EVENT MARKS
/// NOTHING.
///
/// The claim the declaration exists for. Most client events on a duplex wire are NOTIFICATIONS and
/// the dialect gives a server nothing to send back for them; a REQUEST is the kind a client BLOCKS
/// on, and a session that cannot answer one owes it a terminal. Which events are which is the
/// dialect's own fact, so the plane reads the row rather than deciding — and this cell drives both
/// answers over two rows, because a cell that mutated one row between two assertions would prove the
/// plane reads a variable.
///
/// THE MARK IS THE WHOLE OF THE PLANE'S PART. What the fact does is open a unit that will be
/// REFUSED, which is what puts the wire's own terminal on the socket: past the door an ending is a
/// failure and a failure renders no frame, so a request nothing can answer has to be refused before
/// the door or answered with silence.
#[test]
fn a_request_a_served_session_cannot_answer_is_marked_and_a_notification_is_not() {
    use busbar_contract::bounded::FactValue;
    use busbar_contract::plane::Ingress;

    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);

    let marked = |dialect: &'static crate::dialect::Dialect, request: bool| -> bool {
        let mut state = VoiceSessionState::for_dialect(dialect);
        let read = crate::plane::open_or_relay(
            &mut state,
            dialect,
            busbar_contract::bounded::ArenaBytes::new(&[]),
            None,
            None,
            request,
            &c,
        )
        .expect("a frame opens a turn");
        match read {
            Ingress::Open(draft) => matches!(
                draft.facts.get(crate::meta::FACT_AWAITS_TERMINAL),
                Some(FactValue::Bool(true))
            ),
            _ => false,
        }
    };

    assert!(
        marked(&super::harness::A_SPEAKING_DIALECT, true),
        "a request this session has no leg for is marked, so the unit opened on it is refused and \
         the wire's own terminal reaches the client"
    );
    assert!(
        !marked(&super::harness::A_SPEAKING_DIALECT, false),
        "and a notification is not: the wire gives a server nothing to send back for one, and \
         inventing an acknowledgement would put a frame on the socket the dialect does not define"
    );
    // AND WHAT DECIDES `request` IS THE ROW, never this crate. The fixture rows declare no request
    // event at all, which is the answer a carrier gives; the plane reads that declaration and marks
    // nothing for them. A plane that decided it here would be deciding a wire fact for a dialect
    // that had already answered it.
    assert!(
        super::harness::A_DIALECT.request_terminal.is_none(),
        "a row that declares no request event has none to read"
    );
}

/// AND THE ROW'S OWN TERMINAL IS WHAT A REFUSED REQUEST RENDERS.
///
/// The other half: the mark opens a unit that is refused, and what that refusal writes is this
/// wire's own word for "nothing could answer" rather than a generic one. A client library for this
/// dialect has a case for its own error shape; a string this plane invented is one it would have to
/// guess at.
#[test]
fn a_refused_request_renders_the_rows_own_terminal() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);
    let st = opened(&super::harness::A_SPEAKING_DIALECT);

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Verify,
        reason: busbar_contract::unit::RefusalReason::NoDestination,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let bytes =
        busbar_contract::plane::Plane::encode_refusal(&plane(), &refusal, None, Some(&st), &c)
            .expect("a refusal renders");
    let rendered: serde_json::Value =
        serde_json::from_slice(bytes.as_slice()).expect("this dialect's own JSON");
    assert_eq!(
        rendered.get("type").and_then(serde_json::Value::as_str),
        Some("error"),
        "the wire's own terminal shape, got: {rendered}"
    );
}
