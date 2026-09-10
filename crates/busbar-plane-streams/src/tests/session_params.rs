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

use crate::claims::Dialect;
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
fn opened(dialect: Dialect) -> PlaneSessionState {
    PlaneSessionState::new(VoiceSessionState::for_dialect(dialect))
}

/// THE CARRIER LEG opens on the µ-law lock, byte for byte.
///
/// The whole of the hook wire's payload for a carrier open is these bytes. Equality is against the
/// shared constructor rather than against a hand-written literal, because a literal here would be a
/// second opinion about the lock and the two would drift apart silently.
#[test]
fn a_carrier_session_projects_the_mu_law_lock_byte_for_byte() {
    let arena = LeakArena;
    let cfg = EmptyConfig;
    let stack = WsStack::new("/telephony/call-1");
    let labels = Labels::default();
    let c = ctx(&arena, &cfg, &stack, &labels);

    let mut st = opened(Dialect::TwilioMediaStreams);
    let params =
        SessionPlane::session_params(&plane(), &mut st, &c).expect("a carrier leg projects");

    assert_eq!(
        params.declared,
        serde_json::to_vec(&config::g711_config()).unwrap(),
        "a carrier session's declared parameters must be the µ-law lock BYTE FOR BYTE — this is the \
         payload an operator's configured gate matches on"
    );
    assert_eq!(
        (params.container, params.operation),
        ("streams", "session.open"),
        "the container and the method name are the hook wire's own, not this plane's operation class"
    );
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
    let mut st = opened(Dialect::OpenaiRealtime);
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
    let mut st = opened(Dialect::OpenaiRealtime);
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

    let mut st = opened(Dialect::OpenaiRealtime);
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
