// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::auth::LoginField;
use std::sync::atomic::AtomicUsize;

fn form(fields: &[(&str, FieldKind)]) -> LoginForm {
    LoginForm {
        fields: fields
            .iter()
            .map(|(n, k)| LoginField {
                name: (*n).into(),
                label: (*n).into(),
                kind: *k,
                required: true,
            })
            .collect(),
    }
}

fn user_pass() -> LoginForm {
    form(&[
        ("username", FieldKind::Text),
        ("password", FieldKind::Password),
    ])
}

fn posted(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ---- the account key -------------------------------------------------------------------------

#[test]
fn account_aliases_share_one_key() {
    let k = key::AccountKeyer::derive(&[7; 32]);
    let alice = k.fingerprint("alice");
    for alias in [
        "Alice",
        "ALICE",
        " alice ",
        "CORP\\alice",
        "alice@corp.example",
        "ＡＬＩＣＥ",
        "al\u{200B}ice",
        "CORP\\ALICE@corp.example",
    ] {
        assert_eq!(k.fingerprint(alias), alice, "{alias:?}");
    }
    assert_ne!(k.fingerprint("bob"), alice);
    assert_eq!(key::normalise_account("Straße"), "strasse");
    assert_eq!(key::normalise_account("a   b"), "a b");
}

#[test]
fn stored_key_is_hmac_not_plain_username() {
    let k = key::AccountKeyer::derive(&[7; 32]);
    let fp = k.fingerprint("alice");
    assert_eq!(fp.len(), 32);
    assert!(!fp.contains("alice"));
    assert_ne!(
        key::AccountKeyer::derive(&[8; 32]).fingerprint("alice"),
        fp,
        "a different signing key is a different key"
    );
    assert_eq!(
        key::AccountKeyer::derive(&[7; 32]).fingerprint("alice"),
        fp,
        "every node with the same signing key computes the same key"
    );
}

#[test]
fn the_state_key_signs_and_refuses_a_forgery() {
    let k = key::StateKey::derive(&[7; 32]);
    let tag = k.sign(b"payload");
    assert!(k.verify(b"payload", &tag));
    assert!(!k.verify(b"payload2", &tag));
    assert!(!key::StateKey::derive(&[8; 32]).verify(b"payload", &tag));
}

// ---- canonicalisation ------------------------------------------------------------------------

#[test]
fn undeclared_extra_fields_do_not_change_the_key_and_are_not_forwarded() {
    let c = canonicalise(
        &user_pass(),
        &posted(&[
            ("pad", "x"),
            ("password", "pw"),
            ("username", "alice"),
            ("extra", "y"),
        ]),
    )
    .unwrap();
    assert_eq!(c.account.as_deref(), Some("alice"));
    assert_eq!(
        c.forwarded,
        posted(&[("username", "alice"), ("password", "pw")]),
        "declared names only, in declared order"
    );
}

#[test]
fn duplicate_declared_field_is_refused() {
    assert_eq!(
        canonicalise(
            &user_pass(),
            &posted(&[
                ("username", "r4nd0m"),
                ("username", "ceo"),
                ("password", "x")
            ])
        ),
        Err(DuplicateField("username".into()))
    );
    assert!(
        canonicalise(&user_pass(), &posted(&[("extra", "1"), ("extra", "2")])).is_ok(),
        "an undeclared duplicate is just dropped"
    );
}

#[test]
fn a_second_text_field_does_not_change_the_key() {
    let f = form(&[
        ("username", FieldKind::Text),
        ("password", FieldKind::Password),
        ("totp", FieldKind::Text),
    ]);
    let a = canonicalise(&f, &posted(&[("username", "ceo"), ("totp", "111111")])).unwrap();
    let b = canonicalise(&f, &posted(&[("username", "ceo"), ("totp", "999999")])).unwrap();
    assert_eq!(a.account, b.account);
    assert_eq!(a.account.as_deref(), Some("ceo"));
}

// ---- the orchestrator, against a counting fake plugin -----------------------------------------

struct Fake {
    form: Option<LoginForm>,
    answer: Mutex<Vec<(LoginJudged, Option<RejectHint>)>>,
    default: (LoginJudged, Option<RejectHint>),
    calls: AtomicUsize,
    seen: Mutex<Vec<Vec<(String, String)>>>,
    gate: Option<Arc<tokio::sync::Notify>>,
}

impl Fake {
    fn answering(judged: LoginJudged) -> Self {
        Self {
            form: Some(user_pass()),
            answer: Mutex::new(Vec::new()),
            default: (judged, None),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            gate: None,
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialDoor for Fake {
    fn declared_form<'a>(&'a self, _: &'a str) -> DoorFuture<'a, Option<LoginForm>> {
        Box::pin(async move { self.form.clone() })
    }
    fn complete<'a>(
        &'a self,
        _: &'a str,
        _: String,
        submitted: Vec<(String, String)>,
    ) -> DoorFuture<'a, (LoginJudged, Option<RejectHint>)> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.seen).push(submitted);
            if let Some(g) = &self.gate {
                g.notified().await;
            }
            lock(&self.answer)
                .pop()
                .unwrap_or_else(|| self.default.clone())
        })
    }
}

fn reject() -> LoginJudged {
    LoginJudged::Plugin(LoginOutcome::Reject)
}

fn attempt(user: &str, source: &str) -> CredentialAttempt {
    CredentialAttempt {
        method: "corp-ad".into(),
        state: "st".into(),
        form: posted(&[("username", user), ("password", "WRONG")]),
        source: ClientSource::Known(source.parse().unwrap()),
    }
}

fn no_audit(_: &str, _: &str, _: &'static str, _: &str) {}

async fn run(
    guard: &LoginGuard,
    store: Option<&CoreStore>,
    door: &Fake,
    a: CredentialAttempt,
    now: u64,
) -> CredentialVerdict {
    judge(
        Context {
            guard,
            store,
            keyer: Some(key::AccountKeyer::derive(&[7; 32])),
            door,
            now,
        },
        a,
    )
    .await
}

const T0: u64 = 1_800_000_000;

#[tokio::test]
async fn duplicate_declared_field_is_refused_without_calling_the_plugin() {
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    let mut a = attempt("ceo", "203.0.113.1");
    a.form = posted(&[("username", "x"), ("username", "ceo"), ("password", "p")]);
    assert_eq!(
        run(&guard, None, &door, a, T0).await,
        CredentialVerdict::Malformed
    );
    assert_eq!(door.calls(), 0);
}

#[tokio::test]
async fn no_signing_key_refuses_without_calling_the_plugin() {
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    let verdict = judge(
        Context {
            guard: &guard,
            store: None,
            keyer: None,
            door: &door,
            now: T0,
        },
        attempt("alice", "203.0.113.1"),
    )
    .await;
    assert!(matches!(verdict, CredentialVerdict::Unavailable { .. }));
    assert_eq!(door.calls(), 0);
}

#[tokio::test]
async fn store_unavailable_refuses_without_calling_the_plugin() {
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    let verdict = run(&guard, None, &door, attempt("alice", "203.0.113.1"), T0).await;
    assert!(matches!(verdict, CredentialVerdict::Unavailable { .. }));
    assert_eq!(door.calls(), 0);
}

#[tokio::test]
async fn an_undeclarable_form_refuses_without_calling_the_plugin() {
    let guard = LoginGuard::with_sink(no_audit);
    let mut door = Fake::answering(reject());
    door.form = None;
    let verdict = run(&guard, None, &door, attempt("alice", "203.0.113.1"), T0).await;
    assert!(matches!(verdict, CredentialVerdict::Unavailable { .. }));
    assert_eq!(door.calls(), 0);
}

static AUDITED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn capture(action: &str, _: &str, _: &'static str, principal: &str) {
    lock(&AUDITED).push((action.to_string(), principal.to_string()));
}

// ---- store-backed (the in-tree memory backend) ----------------------------

async fn store() -> Arc<CoreStore> {
    crate::real_store::core().await
}

#[tokio::test]
async fn fourth_failure_for_one_account_is_refused_without_calling_the_plugin() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    for i in 0..3 {
        assert_eq!(
            run(
                &guard,
                Some(&store),
                &door,
                attempt("alice", &format!("203.0.113.{i}")),
                T0
            )
            .await,
            CredentialVerdict::Declined
        );
    }
    let fourth = run(
        &guard,
        Some(&store),
        &door,
        attempt("ALICE", "198.51.100.9"),
        T0,
    )
    .await;
    assert_eq!(
        fourth,
        CredentialVerdict::Throttled {
            retry_after_secs: 900
        }
    );
    assert_eq!(door.calls(), 3, "the directory saw three binds, not four");
    assert_eq!(
        run(
            &guard,
            Some(&store),
            &door,
            attempt("bob", "198.51.100.9"),
            T0
        )
        .await,
        CredentialVerdict::Declined,
        "another account has its own budget"
    );
}

#[tokio::test]
async fn concurrent_submissions_reserve_before_the_call() {
    let store = store().await;
    let guard = Arc::new(LoginGuard::with_sink(no_audit));
    let gate = Arc::new(tokio::sync::Notify::new());
    let mut fake = Fake::answering(reject());
    fake.gate = Some(gate.clone());
    let door = Arc::new(fake);
    let mut tasks = Vec::new();
    for i in 0..20 {
        let (guard, store, door) = (guard.clone(), store.clone(), door.clone());
        tasks.push(tokio::spawn(async move {
            run(
                &guard,
                Some(&store),
                &door,
                attempt("ceo", &format!("192.0.2.{i}")),
                T0,
            )
            .await
        }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        door.calls() <= 3,
        "at most three reached the plugin: {}",
        door.calls()
    );
    gate.notify_waiters();
    for _ in 0..20 {
        gate.notify_waiters();
        tokio::task::yield_now().await;
    }
    let mut throttled = 0;
    for t in tasks {
        if matches!(t.await.unwrap(), CredentialVerdict::Throttled { .. }) {
            throttled += 1;
        }
    }
    assert_eq!(throttled, 17);
    assert_eq!(door.calls(), 3);
}

#[tokio::test]
async fn success_clears_the_account_failures() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    for _ in 0..2 {
        run(
            &guard,
            Some(&store),
            &door,
            attempt("carol", "203.0.113.4"),
            T0,
        )
        .await;
    }
    lock(&door.answer).push((
        LoginJudged::Plugin(LoginOutcome::Identify(Principal::from_id("carol"))),
        None,
    ));
    assert!(matches!(
        run(
            &guard,
            Some(&store),
            &door,
            attempt("carol", "203.0.113.4"),
            T0
        )
        .await,
        CredentialVerdict::Identified(_)
    ));
    for _ in 0..3 {
        assert_eq!(
            run(
                &guard,
                Some(&store),
                &door,
                attempt("carol", "203.0.113.4"),
                T0
            )
            .await,
            CredentialVerdict::Declined,
            "the success released every slot: three fresh failures are allowed again"
        );
    }
}

#[tokio::test]
async fn only_not_run_is_refunded() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let not_run = Fake::answering(LoginJudged::NotRun);
    for _ in 0..10 {
        assert!(matches!(
            run(
                &guard,
                Some(&store),
                &not_run,
                attempt("dave", "203.0.113.5"),
                T0
            )
            .await,
            CredentialVerdict::Unavailable { .. }
        ));
    }
    let declines = Fake::answering(reject());
    for _ in 0..3 {
        assert_eq!(
            run(
                &guard,
                Some(&store),
                &declines,
                attempt("dave", "203.0.113.5"),
                T0
            )
            .await,
            CredentialVerdict::Declined,
            "ten NotRun attempts spent nothing"
        );
    }
    for (judged, name) in [
        (
            LoginJudged::Plugin(LoginOutcome::Outage {
                retry_after_secs: None,
            }),
            "erin",
        ),
        (
            LoginJudged::Plugin(LoginOutcome::SecurityCheckFailed),
            "frank",
        ),
        (LoginJudged::Faulted, "gina"),
    ] {
        let door = Fake::answering(judged.clone());
        for _ in 0..3 {
            run(
                &guard,
                Some(&store),
                &door,
                attempt(name, "198.51.100.20"),
                T0 + 100,
            )
            .await;
        }
        assert!(
            matches!(
                run(
                    &guard,
                    Some(&store),
                    &door,
                    attempt(name, "198.51.100.21"),
                    T0 + 100
                )
                .await,
                CredentialVerdict::Throttled { .. }
            ),
            "{judged:?} keeps its reservation: the bind may have been sent"
        );
        assert_eq!(door.calls(), 3);
    }
}

#[tokio::test]
async fn two_apps_sharing_one_core_store_share_the_account_budget() {
    let store = store().await;
    let node_a = LoginGuard::with_sink(no_audit);
    let node_b = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    run(
        &node_a,
        Some(&store),
        &door,
        attempt("henry", "203.0.113.6"),
        T0,
    )
    .await;
    run(
        &node_b,
        Some(&store),
        &door,
        attempt("henry", "203.0.113.7"),
        T0,
    )
    .await;
    run(
        &node_a,
        Some(&store),
        &door,
        attempt("henry", "203.0.113.8"),
        T0,
    )
    .await;
    assert!(matches!(
        run(
            &node_b,
            Some(&store),
            &door,
            attempt("henry", "203.0.113.9"),
            T0
        )
        .await,
        CredentialVerdict::Throttled { .. }
    ));
    assert_eq!(door.calls(), 3);
}

#[tokio::test]
async fn a_plugin_account_locked_hint_saturates_the_account() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    lock(&door.answer).push((reject(), Some(RejectHint::AccountLocked)));
    assert_eq!(
        run(
            &guard,
            Some(&store),
            &door,
            attempt("ivan", "203.0.113.10"),
            T0
        )
        .await,
        CredentialVerdict::Declined
    );
    assert!(
        matches!(
            run(
                &guard,
                Some(&store),
                &door,
                attempt("ivan", "203.0.113.11"),
                T0
            )
            .await,
            CredentialVerdict::Throttled { .. }
        ),
        "the directory said locked: nothing more is forwarded for the account"
    );
    assert_eq!(door.calls(), 1);
}

#[tokio::test]
async fn the_outage_breaker_answers_503_without_calling_or_counting() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(LoginJudged::Plugin(LoginOutcome::Outage {
        retry_after_secs: None,
    }));
    for i in 0..5 {
        run(
            &guard,
            Some(&store),
            &door,
            attempt(&format!("u{i}"), "203.0.113.12"),
            T0,
        )
        .await;
    }
    let held = run(
        &guard,
        Some(&store),
        &door,
        attempt("judy", "203.0.113.12"),
        T0 + 1,
    )
    .await;
    assert_eq!(
        held,
        CredentialVerdict::Unavailable {
            retry_after_secs: Some(30)
        }
    );
    assert_eq!(door.calls(), 5);
}

#[tokio::test]
async fn throttled_answers_are_identical_across_limiters_and_accounts() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let door = Fake::answering(reject());
    for _ in 0..3 {
        run(
            &guard,
            Some(&store),
            &door,
            attempt("known", "203.0.113.13"),
            T0,
        )
        .await;
    }
    let by_account = run(
        &guard,
        Some(&store),
        &door,
        attempt("known", "203.0.113.14"),
        T0,
    )
    .await;
    for i in 0..20 {
        run(
            &guard,
            Some(&store),
            &door,
            attempt(&format!("s{i}"), "198.51.100.30"),
            T0,
        )
        .await;
    }
    let by_source = run(
        &guard,
        Some(&store),
        &door,
        attempt("never-seen", "198.51.100.30"),
        T0,
    )
    .await;
    assert_eq!(by_account, by_source);
    assert_eq!(
        by_account,
        CredentialVerdict::Throttled {
            retry_after_secs: 900
        }
    );
}

#[tokio::test]
async fn throttles_are_audited_first_in_window_by_fingerprint_never_by_name() {
    let store = store().await;
    lock(&AUDITED).clear();
    let guard = LoginGuard::with_sink(capture);
    let door = Fake::answering(reject());
    for _ in 0..6 {
        run(
            &guard,
            Some(&store),
            &door,
            attempt("kate", "203.0.113.15"),
            T0,
        )
        .await;
    }
    let audited = lock(&AUDITED).clone();
    let throttled: Vec<_> = audited
        .iter()
        .filter(|(a, _)| a == "auth.login_throttled")
        .collect();
    assert_eq!(throttled.len(), 1, "{audited:?}");
    assert!(throttled[0].1.starts_with("fp:"));
    assert!(audited.iter().all(|(_, p)| !p.contains("kate")));
}

#[tokio::test]
async fn a_login_state_is_single_use() {
    let store = store().await;
    let guard = LoginGuard::with_sink(no_audit);
    let expires = crate::store::now() + 600;
    assert_eq!(
        claim_state_in(&guard, &store, "state-1", expires).await,
        StateClaim::Fresh
    );
    assert_eq!(
        claim_state_in(&guard, &store, "state-1", expires).await,
        StateClaim::Replayed
    );
    assert_eq!(
        claim_state_in(&guard, &store, "state-2", expires).await,
        StateClaim::Fresh
    );
}

// ---- config ----------------------------------------------------------------------------------

#[test]
fn absent_config_gives_the_owner_signed_defaults() {
    let p = policy::resolve(
        None,
        &Default::default(),
        &crate::config::AdvancedCfg::default(),
    )
    .unwrap();
    assert_eq!(p, LoginLimitsPolicy::default());
    assert_eq!(p.account.max, 3);
    assert_eq!(p.account.window_secs, 900);
    assert_eq!(p.source.failures.max, 20);
    assert_eq!(p.admin.max, 50);
    assert_eq!(p.admin.window_secs, 300);
}

#[test]
fn invalid_limits_are_refused_with_3133() {
    let yaml =
        |s: &str| -> crate::config::LoginLimitsCfg { busbar_contract::yaml::from_str(s).unwrap() };
    for (cfg, needle) in [
        (
            "per_account: { max_failures: 0 }",
            "per_account.max_failures",
        ),
        (
            "per_account: { max_failures: 101 }",
            "per_account.max_failures",
        ),
        ("per_account: { window: 30s }", "per_account.window"),
        ("per_account: { window: 2d }", "per_account.window"),
        ("per_source: { max_failures: 2 }", "exceeds"),
        ("admin: { max_failures: 0 }", "admin.max_failures"),
        ("global: { max_failures_per_minute: 0 }", "global"),
    ] {
        let errors = policy::resolve(
            Some(&yaml(cfg)),
            &Default::default(),
            &crate::config::AdvancedCfg::default(),
        )
        .unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("BUSBAR-3133: ") && e.contains(needle)),
            "{cfg}: {errors:?}"
        );
    }
    let advanced: crate::config::AdvancedCfg =
        busbar_contract::yaml::from_str("trusted_proxies: [\"10.0.0.1/8\"]").unwrap();
    assert!(policy::resolve(None, &Default::default(), &advanced).is_err());
    assert!(
        busbar_contract::yaml::from_str::<crate::config::LoginLimitsCfg>(
            "per_account: { enabled: false }"
        )
        .is_err(),
        "the per-account limiter has no `enabled`: it cannot be disabled"
    );
}

#[test]
fn a_provider_override_wins_for_its_method() {
    let providers: crate::config::IdentityProviders = busbar_contract::yaml::from_str(
        "corp-ad: { module: ldap, browser_login: { max_failures: 2, failure_window: 30m } }",
    )
    .unwrap();
    let p = policy::resolve(None, &providers, &crate::config::AdvancedCfg::default()).unwrap();
    assert_eq!(
        p.account_for("corp-ad"),
        policy::Limit {
            max: 2,
            window_secs: 1800
        }
    );
    assert_eq!(p.account_for("other"), p.account);
}

#[tokio::test]
async fn concurrent_replays_of_one_login_state_have_exactly_one_winner() {
    let store = store().await;
    let guard = Arc::new(LoginGuard::with_sink(no_audit));
    let expires = crate::store::now() + 600;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (guard, store) = (guard.clone(), store.clone());
        tasks.push(tokio::spawn(async move {
            claim_state_in(&guard, &store, "raced-state", expires).await
        }));
    }
    let mut fresh = 0;
    for t in tasks {
        match t.await.unwrap() {
            StateClaim::Fresh => fresh += 1,
            StateClaim::Replayed => {}
            StateClaim::Unavailable => panic!("contention is not an outage"),
        }
    }
    assert_eq!(fresh, 1);
}
