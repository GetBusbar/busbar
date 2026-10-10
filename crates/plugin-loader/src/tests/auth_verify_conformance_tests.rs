// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: auth`, BOTH WAYS, VERIFY VERDICTS, ON THE MEMORY ABI — the auth kind's both-ways proof
//! over the token cases** (DECISIONS #2; THE DESIGN, compiled-in = dropped-in: a compiled-in plugin exports the same door
//! as a dropped-in one and is called through the same table; ARCHITECT 2026-09-27: the shipped
//! admin-auth module is a REAL auth plugin and its both-ways conformance is the AUTH kind proof;
//! ARCHITECT 2026-09-30, AUTH-DOOR Q1: this proof moves to the door, linked vs dropped, with a RED
//! arm).
//!
//! The plugin is reached through the `auth-verify` row of `[package.metadata.busbar.both-ways]`, so
//! no test source names a plugin instance. It is registered LINKED (its `rlib`'s `door::door`,
//! through [`crate::PluginRegistry::link`]) and DROPPED IN (its `cdylib`, signed first-party into
//! `plugins/` and found by the scan), each opened by the loader's auth rows on a real dispatcher and
//! driven over the same token cases at the `Head` point, on the spot and submitted. The two rows
//! and the two transcripts must be byte-identical, and the transcript must reach every verdict —
//! the accepted token IDENTIFIES, a wrong opaque token is REJECTED, another scheme's token and no
//! credential PASS.
//!
//! ## The RED arms stay in the file
//!
//! [`a_door_judging_another_token_is_told_apart`] opens the dropped-in door over a ROTATED token's
//! digest: its verdicts differ, so the verdict equality is not vacuous.
//! [`a_third_party_signature_is_a_different_row`] signs the same `cdylib` as a third party: the row
//! differs (it is not first-party), so the row equality is not vacuous either.

use std::sync::Arc;
use std::time::Duration;

use super::both_ways::{cdylib, door_fixture, dropped, dropped_third_party, row, statement};
use crate::auth_axis::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::redacted::{sha256_hex, Redacted};

/// The both-ways table row this proof reads.
const PROOF: &str = "auth-verify";

/// The operator's token. The plugin is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// The token cases, as the two field lines a request presents them on — the Bearer on the
/// `authorization` line, the other on the second credential line: the accepted token on either,
/// a wrong opaque token, a token in another scheme's grammar (a JWS compact serialization), none.
/// The line names are the plugin's own, read here as the request's data.
const CASES: [(Option<&str>, Option<&str>); 6] = [
    (Some(TOKEN), None),
    (None, Some(TOKEN)),
    (Some("not-the-token"), None),
    (None, Some("not-the-token")),
    (Some("aaa.bbb.ccc"), None),
    (None, None),
];

/// The two credential lines the cases are presented on.
const LINES: (&str, &str) = ("authorization", "x-admin-token");

/// The manifest both doors state, carrying the Statement rendering the linked `door` states (a
/// dropped-in plugin's signed manifest carries its rendering: the design's One Statement).
fn stated(door: busbar_contract::abi::mechanism::door::DoorFn) -> crate::sign::Manifest {
    let rendering = crate::dispatch::LinkedRow::of(door)
        .expect("the door states itself")
        .statement;
    crate::sign::Manifest {
        statement: Some(hex::encode(rendering)),
        ..statement(
            "auth",
            "auth-fixture",
            "the-auth",
            busbar_contract::abi::auth::ABI_VERSION,
        )
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

/// One case at the `Head` point.
fn request(bearer: Option<&str>, other: Option<&str>) -> VerifyRequest {
    let line = |name: &str, value: String| (name.to_string(), Redacted::new(value.into_bytes()));
    let lines = bearer
        .map(|b| line(LINES.0, format!("Bearer {b}")))
        .into_iter()
        .chain(other.map(|h| line(LINES.1, h.to_string())))
        .collect();
    VerifyRequest {
        point: AuthPoint::Head,
        lines,
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

/// An answer as the transcript spells it: the verdict, the decision, the lines to strip.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    format!("{verdict} {:?} [{}]", a.decision, strips.join(", "))
}

/// The linked and dropped-in registries of the fixture; a `cdylib` not built is a hard failure
/// naming the command that builds it ([`cdylib`]), never a skip.
fn doors(third_party: bool) -> [PluginRegistry; 2] {
    let (crate_snake, door) = door_fixture(PROOF);
    let lib = std::fs::read(cdylib(crate_snake)).expect("read the cdylib");
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(stated(door), door)])
        .expect("the linked door admits the plugin");
    let dropped = if third_party {
        let mut m = stated(door);
        m.publisher = "a-third-party".into();
        dropped_third_party(crate_snake, m, &lib)
    } else {
        dropped(crate_snake, stated(door), &lib)
    };
    [linked, dropped]
}

/// What one door does, as one comparable transcript: the opened instance's name and facts, the
/// operator credential's row the axis finds by its Statement, and its answer for every case on the
/// spot and submitted.
async fn transcript(registry: PluginRegistry, digest: &str) -> String {
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
    let opened = rows
        .open("the-auth", "the-auth", &serde_json::json!(digest))
        .expect("the plugin opens through its alias over a digest");
    let mut out = vec![format!(
        "name={} facts={} operator={:?}",
        opened.name(),
        opened.facts(),
        rows.operator()
    )];
    for (bearer, other) in CASES {
        let now = opened
            .verify_now(&request(bearer, other))
            .map_or_else(|| "not on the spot".to_string(), |a| spelled(&a));
        let submitted = spelled(&Box::into_pin(opened.verify(request(bearer, other))).await);
        out.push(format!(
            "{bearer:?} {other:?} -> now {now} / submitted {submitted}"
        ));
    }
    out.join("\n")
}

/// The transcript reaches every verdict, so the equality it is compared under covers them all.
fn assert_every_verdict(transcript: &str) {
    assert!(
        transcript.contains("Identity")
            && transcript.contains("Reject")
            && transcript.contains("Pass"),
        "the token cases must identify, reject and pass: {transcript}"
    );
}

/// **THE AXIS, BOTH WAYS** (#2 rule (1), THE DESIGN: compiled-in = dropped-in). The linked door and the dropped-in door
/// resolve to the byte-identical registry row, and the instance each opens answers every token case
/// the same, on the spot and submitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_and_a_dropped_in_auth_door_answer_byte_identically() {
    let [linked, dropped] = doors(false);
    let rows = [row(&linked, "auth-fixture"), row(&dropped, "auth-fixture")];
    assert!(
        !rows[0].starts_with("no row"),
        "the linked door registered no row: {}",
        rows[0]
    );
    assert_eq!(rows[0], rows[1], "the two doors must register one row");
    let digest = sha256_hex(TOKEN.as_bytes());
    let linked = transcript(linked, &digest).await;
    let dropped = transcript(dropped, &digest).await;
    assert_every_verdict(&linked);
    assert!(
        linked.contains(r#"operator=Some(("the-auth", "admin"))"#),
        "the axis finds the operator credential's row by its Statement: {linked}"
    );
    assert_eq!(linked, dropped, "the two doors must answer as one plugin");
}

/// **THE RED ARM OF THE VERDICT COMPARISON.** The dropped-in door opened over a ROTATED token's
/// digest answers the same cases differently: the accepted token is no longer identified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_judging_another_token_is_told_apart() {
    let [linked, dropped] = doors(false);
    let linked = transcript(linked, &sha256_hex(TOKEN.as_bytes())).await;
    let dropped = transcript(dropped, &sha256_hex(b"a-rotated-token")).await;
    assert_every_verdict(&linked);
    assert!(
        !dropped.contains("Identity"),
        "the rotated door identified the operator's token: {dropped}"
    );
    assert_ne!(
        linked, dropped,
        "a door judging another token must not compare equal — this inequality is what \
         `a_linked_and_a_dropped_in_auth_door_answer_byte_identically` exists to refuse"
    );
}

/// **THE RED ARM OF THE ROW COMPARISON.** The same `cdylib` signed by a third party is a different
/// row from the linked first-party one.
#[test]
fn a_third_party_signature_is_a_different_row() {
    let [linked, dropped] = doors(true);
    let dropped_row = row(&dropped, "auth-fixture");
    assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
    assert_ne!(
        row(&linked, "auth-fixture"),
        dropped_row,
        "a third-party row must not compare equal to the first-party one"
    );
}
