//! THE DESTINATION-FACT CELLS — what a Verify step is handed when this plane's session opens, and
//! what the rule makes of it.
//!
//! The face exists so that no step reads this plane's `streams:` section itself. So what these cells
//! pin is the two halves of that: the deployment's refused-destination list REACHES the step, and the
//! destination the step judges is the posture the connection actually opens on — including after a
//! rewrite tap has replaced it, which is the ordering the 1.5.x mount already had and the one a
//! migration is most likely to lose.
//!
//! The rule itself (`SessionDestinationFacts::admits`) is asserted here rather than in the two loops
//! that ask it, because it is one function and two loops: a cell per loop would be two cells that
//! agree until one of them is edited.

use busbar_contract::bounded::Labels;
use busbar_contract::plane::{PlaneSessionState, SessionDestinationFacts, SessionPlane};
use busbar_contract::unit::{Clock, ConfigView, Ctx};
use busbar_voice_codec::ir::config::SessionConfig;

use crate::claims::Dialect;
use crate::session::VoiceSessionState;
use crate::tests::harness::{ctx, EmptyConfig, LeakArena, WsStack};
use crate::VoicePlane;

/// A configuration block that answers the two keys this face reads.
#[derive(Debug, Default)]
struct PolicyConfig {
    session_defaults: Option<String>,
    denied_destinations: Option<String>,
}

impl ConfigView for PolicyConfig {
    fn get_str(&self, key: &str) -> Option<&str> {
        match key {
            "session_defaults" => self.session_defaults.as_deref(),
            "denied_destinations" => self.denied_destinations.as_deref(),
            _ => None,
        }
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

/// A session config naming one upstream model and nothing else.
fn declaring(model: &str) -> SessionConfig {
    SessionConfig {
        model: Some(model.to_string()),
        ..SessionConfig::default()
    }
}

/// THE OPERATOR'S LIST REACHES THE STEP, and the rule refuses exactly what it names.
///
/// This is the whole of the migration in one cell: the denial set is a `streams:` key, and what a
/// Verify step is handed is that key's contents — not a boolean somebody else computed from it.
#[test]
fn the_declared_denial_set_reaches_the_face_and_the_rule_refuses_exactly_what_it_names() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let cfg = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("blocked-model")).unwrap()),
        denied_destinations: Some(r#"["blocked-model","also-blocked"]"#.to_string()),
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
    let facts = SessionPlane::session_destinations(&plane(), &mut st, &c)
        .expect("this plane HAS a destination policy key, so it always answers Some");
    assert_eq!(
        facts.declared, "blocked-model",
        "the destination judged is the one the deployment's declared posture named"
    );
    assert_eq!(
        facts.denied,
        ["blocked-model".to_string(), "also-blocked".to_string()],
        "the operator's own list is what crosses the face — a step must never read the section itself"
    );
    assert!(
        !facts.admits(),
        "a destination on the deployment's denial set is refused at Verify"
    );

    // The control, on the same list: a destination the operator did NOT name proceeds.
    let cfg = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("allowed-model")).unwrap()),
        denied_destinations: Some(r#"["blocked-model","also-blocked"]"#.to_string()),
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
    let facts = SessionPlane::session_destinations(&plane(), &mut st, &c).expect("still Some");
    assert!(
        facts.admits(),
        "a destination the deployment never named proceeds — a denial set is a deny list and not an \
         allow list, and every deployment that names nothing must keep admitting everything"
    );
}

/// A DEPLOYMENT THAT NAMES NOTHING ADMITS EVERYTHING, and so does one whose list is unreadable.
///
/// The second half is the sharp one: failing closed on a malformed list would take a deployment's
/// whole plane down on a typo, and an unreadable policy is not a policy.
#[test]
fn an_absent_or_unreadable_denial_set_admits_everything() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();

    let empty = EmptyConfig;
    let c = ctx(&arena, &empty, &stack, &labels);
    let mut st = opened(Dialect::OpenaiRealtime);
    let facts = SessionPlane::session_destinations(&plane(), &mut st, &c).expect("still Some");
    assert!(
        facts.denied.is_empty() && facts.admits(),
        "nothing declared ⇒ an empty denial set ⇒ every destination proceeds, which is the posture \
         every existing deployment already has"
    );

    let cfg = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("some-model")).unwrap()),
        denied_destinations: Some("not-a-list".to_string()),
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
    let facts = SessionPlane::session_destinations(&plane(), &mut st, &c).expect("still Some");
    assert!(
        facts.denied.is_empty() && facts.admits(),
        "an unreadable list is not half-adopted and is not read as deny-all"
    );
}

/// THE DESTINATION JUDGED IS THE ONE THE SESSION OPENS ON — including after a tap rewrote it.
///
/// The 1.5.x mount runs the rewrite tap BEFORE the destination gauntlet judges (`ws_accept`, step 2
/// then the gate). A face that read the pre-rewrite posture would refuse a session on a destination
/// the deployment itself had just rewritten away from, which is a refusal nobody asked for and one
/// no cell on the firing side could see.
#[test]
fn a_committed_rewrite_is_the_destination_the_face_reports() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let cfg = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("blocked-model")).unwrap()),
        denied_destinations: Some(r#"["blocked-model"]"#.to_string()),
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
    let p = plane();
    let mut st = opened(Dialect::OpenaiRealtime);

    // The tap commits a rewrite onto an allowed destination, exactly as it does at the mount.
    let rewritten = serde_json::to_vec(&declaring("allowed-model")).unwrap();
    SessionPlane::adopt_session_params(&p, &mut st, &rewritten);

    let facts = SessionPlane::session_destinations(&p, &mut st, &c).expect("still Some");
    assert_eq!(
        facts.declared, "allowed-model",
        "the destination judged is the rewritten one. `blocked-model` here would be the whole \
         finding: a session refused for a destination it is not opening on"
    );
    assert!(facts.admits(), "and so the open proceeds");
}

/// THE SET IS READ ONCE AND HELD, so the answer cannot change under a session already admitted on it.
#[test]
fn the_facts_are_read_once_and_held_for_the_life_of_the_connection() {
    let arena = LeakArena;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let p = plane();
    let mut st = opened(Dialect::OpenaiRealtime);

    let first = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("first-model")).unwrap()),
        denied_destinations: Some(r#"["blocked-model"]"#.to_string()),
    };
    let c = Ctx::new(
        Clock {
            unix_secs: 1_772_000_000,
            monotonic_nanos: 0,
        },
        &first,
        None,
        &stack,
        &labels,
        &arena,
    );
    let held: Vec<String> = SessionPlane::session_destinations(&p, &mut st, &c)
        .expect("still Some")
        .denied
        .to_vec();

    // A SECOND ask, through a configuration view that says something else entirely.
    let second = PolicyConfig {
        session_defaults: Some(serde_json::to_string(&declaring("second-model")).unwrap()),
        denied_destinations: Some(r#"["first-model"]"#.to_string()),
    };
    let c2 = Ctx::new(
        Clock {
            unix_secs: 1_772_000_000,
            monotonic_nanos: 0,
        },
        &second,
        None,
        &stack,
        &labels,
        &arena,
    );
    let again = SessionPlane::session_destinations(&p, &mut st, &c2).expect("still Some");
    assert_eq!(
        (again.declared, again.denied.to_vec()),
        ("first-model", held),
        "the facts a session was admitted on are the facts it keeps — a second reading here would \
         mean one session judged against two policies, the second arriving after the socket bound"
    );
}

/// THE RULE, on the two edges a set-membership test gets wrong.
#[test]
fn the_rule_is_exact_membership_and_an_empty_destination_is_not_a_wildcard() {
    let denied = vec!["gpt-realtime".to_string()];
    assert!(
        !SessionDestinationFacts {
            declared: "gpt-realtime",
            denied: &denied,
        }
        .admits(),
        "the named destination is refused"
    );
    assert!(
        SessionDestinationFacts {
            declared: "gpt-realtime-mini",
            denied: &denied,
        }
        .admits(),
        "membership is EXACT: a denial of one name must not refuse every name it is a prefix of"
    );
    assert!(
        SessionDestinationFacts {
            declared: "",
            denied: &denied,
        }
        .admits(),
        "an open that declared no destination is not matched by a set that names some — it is a \
         session going nowhere in particular, and refusing it here would refuse every deployment \
         whose posture carries no model at all"
    );
    let deny_the_empty = vec![String::new()];
    assert!(
        !SessionDestinationFacts {
            declared: "",
            denied: &deny_the_empty,
        }
        .admits(),
        "and an operator who explicitly named the empty destination has named it"
    );
}
