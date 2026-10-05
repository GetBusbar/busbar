// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: auth`, BOTH WAYS, ON THE MEMORY ABI, THROUGH THE HOST'S CONNECTION TABLE** — the auth
//! kind's login-capable both-ways witness (DECISIONS #2, OWNER-LOCKED: "THE COST OF A REAL AUTH
//! WITNESS, IN ORDER", step (5); THE DESIGN, compiled-in = dropped-in: a compiled-in plugin exports
//! the same door as a dropped-in one and is called through the same table).
//!
//! ONE crate — the `auth` row of `[package.metadata.busbar.both-ways]`, a REAL token-verifying IdP
//! plugin pulled from its own repo (the owner's FIXTURES ruling), reached by KIND so no test source
//! names a plugin instance — registered LINKED (its logic crate's `door::door`, through
//! [`crate::PluginRegistry::link`]) and DROPPED IN (its `-plugin` crate's `cdylib`, signed
//! first-party into `plugins/` and found by the scan), each opened by the loader's auth rows
//! ([`crate::auth_axis::AuthRows`], the axis the kernel opens every `kind: auth` provider through)
//! on a real dispatcher, BOUND TO A CONNECTION TABLE ([`crate::https_conns::HttpsConns`], standing
//! in for the process's connector): the plugin holds no socket and no TLS; the table fetches its
//! JWKS for it from a LOCAL ISSUER ([`crate::test_issuer::Issuer`]: an ES256 key, its JWKS served
//! only to a need trusting the issuer's certificate, which the plugin names as its `ca_cert_pem`,
//! and genuinely signed tokens). Both run one script — every token case to its verdict, the login kind, the
//! authorize URL, a code redeemed at an unreachable token endpoint — and the two registry rows and
//! the two transcripts must be byte-identical.
//!
//! ## The RED arms stay in the file
//!
//! [`a_door_judging_another_audience_is_told_apart`] opens the dropped-in door for another
//! audience: the token the linked door identified is refused, so the transcript equality is not
//! vacuous. [`a_door_handed_no_connection_table_identifies_no_one`] opens it with no table: it
//! cannot fetch the JWKS, so it identifies no one — the table is what carries the fetch.
//! [`a_third_party_signature_is_a_different_row`] signs the same `cdylib` as a third party: the row
//! differs, so the row equality is not vacuous either.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::both_ways::{cdylib, door_fixture, dropped, dropped_third_party, row, statement};
use crate::auth_axis::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::https_conns::HttpsConns;
use crate::test_issuer::Issuer;
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::auth::{BeginLogin, CompleteLogin, LoginOutcome};
use busbar_contract::auth_calls::{AuthCalls, LoginCallback, Verified, VerifyRequest};
use busbar_contract::redacted::Redacted;

/// The both-ways table row this proof reads.
const PROOF: &str = "auth";

/// The registry name and alias the fixture is stated under (data the test chooses).
const NAME: &str = "auth-fixture";
const ALIAS: &str = "the-auth";

/// The audience the issuer's tokens are minted for.
const AUDIENCE: &str = "api://both-ways";

/// A connection table serving the local issuer's JWKS.
fn conns() -> Arc<HttpsConns> {
    let c = Arc::new(HttpsConns::new());
    c.serve_issuer(issuer());
    c
}

/// The ONE local issuer of this test process.
fn issuer() -> &'static Issuer {
    static ONE: OnceLock<Issuer> = OnceLock::new();
    ONE.get_or_init(|| Issuer::start("https://issuer.both-ways.invalid", "both-ways"))
}

/// The plugin's settings for `audience` (its JWKS on the local issuer, its certificate trusted
/// through `ca_cert_pem`, explicit login endpoints on an unreachable host), with its client secret.
fn settings(audience: &str) -> serde_json::Value {
    let mut s = issuer().settings(audience);
    s.insert("client_secret".into(), "both-ways-secret".into());
    serde_json::Value::Object(s)
}

/// The manifest both doors state, carrying the Statement rendering the linked `door` states.
fn stated(door: busbar_contract::abi::mechanism::door::DoorFn) -> crate::sign::Manifest {
    let rendering = crate::dispatch::LinkedRow::of(door)
        .expect("the door states itself")
        .statement;
    crate::sign::Manifest {
        statement: Some(hex::encode(rendering)),
        ..statement("auth", NAME, ALIAS, busbar_contract::abi::auth::ABI_VERSION)
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

/// The fixture's `cdylib`: the `-plugin` crate of its row's logic crate.
fn fixture_cdylib() -> Option<Vec<u8>> {
    let (krate, _) = door_fixture(PROOF);
    let path = cdylib(&format!("{krate}_plugin"))?;
    Some(std::fs::read(path).expect("read the cdylib"))
}

/// The linked and dropped-in registries of the fixture; `None` when its `cdylib` is not built in
/// this scoped, non-CI run ([`cdylib`] hard-fails under CI).
fn doors(third_party: bool) -> Option<[PluginRegistry; 2]> {
    let (krate, door) = door_fixture(PROOF);
    let lib = fixture_cdylib()?;
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(stated(door), door)])
        .expect("the linked door admits the plugin");
    let dropped = if third_party {
        let mut m = stated(door);
        m.publisher = "a-third-party".into();
        dropped_third_party(krate, m, &lib)
    } else {
        dropped(krate, stated(door), &lib)
    };
    Some([linked, dropped])
}

/// One verdict as the transcript spells it.
fn spelled(v: &Verified) -> String {
    match v {
        Verified::Identity(id) => format!(
            "Identity({}, name={:?}, groups={:?})",
            id.subject, id.name, id.groups
        ),
        other => format!("{other:?}"),
    }
}

/// One login step as the transcript spells it (an authorize URL by its host and path only: its
/// query carries the core-minted values of this run).
fn step(o: &LoginOutcome) -> String {
    match o {
        LoginOutcome::Authorize(url) => format!(
            "Authorize({})",
            url.split_once('?').map_or(url.as_str(), |(at, _)| at)
        ),
        LoginOutcome::Identify(p) => format!("Identify({})", p.id),
        other => format!("{other:?}"),
    }
}

fn presented(token: Option<&str>) -> VerifyRequest {
    VerifyRequest {
        credential: token.map(|t| Redacted::new(t.as_bytes().to_vec())),
        ..VerifyRequest::default()
    }
}

/// What one door does, as one comparable transcript. `conns`: the table the opened instance is
/// bound to (`None`: none handed).
async fn transcript(
    registry: PluginRegistry,
    audience: &str,
    conns: Option<Arc<HttpsConns>>,
) -> String {
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
    let rows = match conns {
        Some(c) => rows.with_table(c),
        None => rows,
    };
    let opened: Arc<dyn AuthCalls> = rows
        .open(ALIAS, ALIAS, &settings(audience))
        .expect("the plugin opens through its alias");
    let mut out = vec![format!(
        "name={} facts={} login_kind={:?}",
        opened.name(),
        opened.facts(),
        opened.login_kind()
    )];
    let foreign = Issuer::start("https://issuer.both-ways.invalid", "both-ways");
    let cases = [
        (
            "valid",
            Some(issuer().mint("alice", &["platform"], AUDIENCE)),
        ),
        (
            "another-key",
            Some(foreign.mint("alice", &["platform"], AUDIENCE)),
        ),
        (
            "another-audience",
            Some(issuer().mint("alice", &["platform"], "api://someone-else")),
        ),
        ("not-a-token", Some("not-a-token".to_string())),
        ("none", None),
    ];
    for (case, token) in &cases {
        let v = Box::into_pin(opened.verify(presented(token.as_deref()))).await;
        out.push(format!("{case} -> {}", spelled(&v.verified)));
    }
    let begun = Box::into_pin(opened.begin_login(BeginLogin {
        redirect_uri: "https://node.example/auth/token".into(),
        state: "s".into(),
        code_challenge: "c".into(),
        nonce: Some("n".into()),
        scopes: Vec::new(),
    }))
    .await;
    out.push(format!("begin -> {}", step(&begun)));
    let completed = Box::into_pin(opened.complete_login(LoginCallback {
        state: "s".into(),
        nonce: Some("n".into()),
        login: CompleteLogin {
            code: Some("a-code".into()),
            redirect_uri: Some("https://node.example/auth/token".into()),
            code_verifier: Some("v".into()),
            ..CompleteLogin::default()
        },
    }))
    .await;
    out.push(format!("complete -> {}", step(&completed)));
    out.join("\n")
}

/// **THE AXIS, BOTH WAYS.** The linked door and the dropped-in door resolve to the byte-identical
/// registry row, and the instance each opens — its JWKS fetched by the host's table — answers every
/// step of the script the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_linked_and_the_dropped_in_auth_door_are_one_plugin() {
    let Some([linked, dropped]) = doors(false) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    let rows = [row(&linked, NAME), row(&dropped, NAME)];
    assert!(
        !rows[0].starts_with("no row"),
        "the linked door registered no row: {}",
        rows[0]
    );
    assert_eq!(rows[0], rows[1], "the two doors must register one row");
    let (linked_conns, dropped_conns) = (conns(), conns());
    let a = transcript(linked, AUDIENCE, Some(linked_conns.clone())).await;
    let b = transcript(dropped, AUDIENCE, Some(dropped_conns.clone())).await;
    assert_eq!(a, b, "the two doors must answer as one plugin");
    // Not a vacuous pass: the script did what the plugin is for.
    assert!(
        a.contains("valid -> Identity(") && a.contains("\"platform\""),
        "the valid token identifies its subject with its roles: {a}"
    );
    for refused in ["another-key -> Reject", "another-audience -> Reject"] {
        assert!(a.contains(refused), "{refused}: {a}");
    }
    for passed in ["not-a-token -> Pass", "none -> Pass"] {
        assert!(a.contains(passed), "{passed}: {a}");
    }
    assert!(
        a.contains("begin -> Authorize(https://issuer.both-ways.invalid/authorize)"),
        "{a}"
    );
    assert!(
        a.contains("complete -> Outage"),
        "a token endpoint nothing answers is an outage: {a}"
    );
    // The fetch went out through the table, to the JWKS the settings name: once per door (cached).
    for conns in [&linked_conns, &dropped_conns] {
        let jwks: Vec<_> = conns
            .sent()
            .into_iter()
            .filter(|(_, t)| t == issuer().jwks_url())
            .collect();
        assert_eq!(jwks.len(), 1, "one JWKS fetch per door: {:?}", conns.sent());
    }
}

/// **THE RED ARM OF THE TRANSCRIPT COMPARISON.** The dropped-in door opened for ANOTHER audience
/// answers the same script differently: the valid token is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_judging_another_audience_is_told_apart() {
    let Some([linked, dropped]) = doors(false) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    let a = transcript(linked, AUDIENCE, Some(conns())).await;
    let b = transcript(dropped, "api://someone-else", Some(conns())).await;
    assert!(a.contains("valid -> Identity("), "{a}");
    assert!(b.contains("valid -> Reject"), "{b}");
    assert_ne!(
        a, b,
        "a door judging another audience must not compare equal — this inequality is what \
         `the_linked_and_the_dropped_in_auth_door_are_one_plugin` exists to refuse"
    );
}

/// **THE RED ARM OF THE CONNECTION TABLE.** The same dropped-in door handed NO table cannot fetch
/// its JWKS (the plugin holds no socket), so it identifies no one and refuses the valid token
/// (fail-closed: a token it cannot check is refused): the identity the comparison sees is the
/// table's fetch, not something the plugin did on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_handed_no_connection_table_identifies_no_one() {
    let Some([_, dropped]) = doors(false) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    let t = transcript(dropped, AUDIENCE, None).await;
    assert!(!t.contains("Identity("), "{t}");
    assert!(t.contains("valid -> Reject"), "{t}");
}

/// **THE RED ARM OF THE ROW COMPARISON.** The same `cdylib` signed by a third party is a different
/// row from the linked first-party one.
#[test]
fn a_third_party_signature_is_a_different_row() {
    let Some([linked, dropped]) = doors(true) else {
        eprintln!("skip: the auth fixture's cdylib is not built");
        return;
    };
    let dropped_row = row(&dropped, NAME);
    assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
    assert_ne!(
        row(&linked, NAME),
        dropped_row,
        "a third-party row must not compare equal to the first-party one"
    );
}
