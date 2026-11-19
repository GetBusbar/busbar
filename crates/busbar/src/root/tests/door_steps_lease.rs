// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MEMBER'S UPSTREAM CREDENTIAL ON ITS LEASE: keep-until-expiry, the owner-signed revocation
//! rule, the retry schedule and what each step reports. Core stubs only: a scripted
//! `SecretResolve`, a stub `OutboundAuth` and a capturing report.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::secret::ERROR_KIND_UNAVAILABLE;
use busbar_contract::redacted::Secret;
use busbar_contract::secret::codes::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
};
use busbar_contract::secret::{SecretRefused, SecretResolve};
use busbar_contract::secret_ref::SecretRef;
use busbar_kernel::refresh::{Refreshable, Report};

use super::super::{next_due, Attempt, Next, PerHop};

/// One line a refresh reported.
#[derive(Debug, Clone)]
pub(super) struct Line {
    pub(super) code: Option<u16>,
    pub(super) level: tracing::Level,
    pub(super) message: String,
    pub(super) fields: Vec<(&'static str, String)>,
}

impl Line {
    pub(super) fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A report that keeps what it is told.
#[derive(Default)]
pub(super) struct Captured {
    lines: Mutex<Vec<Line>>,
    audits: Mutex<Vec<(String, String, &'static str)>>,
}

impl Captured {
    pub(super) fn leak() -> &'static Captured {
        Box::leak(Box::default())
    }

    /// The lines coded `code` at INFO or louder.
    pub(super) fn coded(&self, code: u16) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code == Some(code) && l.level != tracing::Level::DEBUG)
            .cloned()
            .collect()
    }

    /// The lines coded `code` at debug (held back by a rate limit).
    pub(super) fn quiet(&self, code: u16) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code == Some(code) && l.level == tracing::Level::DEBUG)
            .cloned()
            .collect()
    }

    pub(super) fn infos(&self) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code.is_none())
            .cloned()
            .collect()
    }

    pub(super) fn all(&self) -> String {
        format!("{:?}", self.lines.lock().unwrap())
    }

    pub(super) fn audits(&self) -> Vec<(String, String, &'static str)> {
        self.audits.lock().unwrap().clone()
    }
}

impl Report for Captured {
    fn diag(
        &self,
        diag: &'static busbar_kernel::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(&'static str, String)],
    ) {
        self.lines.lock().unwrap().push(Line {
            code: Some(diag.code),
            level,
            message: message.to_string(),
            fields: fields.to_vec(),
        });
    }

    fn info(&self, message: &str, fields: &[(&'static str, String)]) {
        self.lines.lock().unwrap().push(Line {
            code: None,
            level: tracing::Level::INFO,
            message: message.to_string(),
            fields: fields.to_vec(),
        });
    }

    fn audit(&self, action: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((action.to_string(), resource.to_string(), outcome));
    }
}

/// A source that answers from a script, then repeats its last answer.
struct Scripted {
    answers: Mutex<VecDeque<Result<&'static str, u32>>>,
    last: Mutex<Result<&'static str, u32>>,
}

fn scripted(answers: &[Result<&'static str, u32>]) -> Arc<Scripted> {
    Arc::new(Scripted {
        answers: Mutex::new(answers.iter().copied().collect()),
        last: Mutex::new(answers[0]),
    })
}

impl Scripted {
    fn next(&self) -> Result<&'static str, u32> {
        let mut last = self.last.lock().unwrap();
        if let Some(answer) = self.answers.lock().unwrap().pop_front() {
            *last = answer;
        }
        *last
    }

    fn then(&self, answers: &[Result<&'static str, u32>]) {
        self.answers.lock().unwrap().extend(answers.iter().copied());
    }
}

impl SecretResolve for Scripted {
    fn resolve(&self, secret: &SecretRef) -> Result<Secret<Vec<u8>>, String> {
        self.resolve_refusing(secret, None).map_err(|r| r.text)
    }

    fn resolve_string(&self, secret: &SecretRef) -> Result<Secret<String>, String> {
        let bytes = self.resolve(secret)?;
        bytes.into_text().map_err(|e| format!("{e:?}"))
    }

    fn resolve_refusing(
        &self,
        _: &SecretRef,
        _: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<Secret<Vec<u8>>, SecretRefused> {
        match self.next() {
            Ok(value) => Ok(Secret::new(value.as_bytes().to_vec())),
            Err(error_kind) => Err(SecretRefused {
                error_kind,
                text: format!("scripted refusal {error_kind}"),
            }),
        }
    }
}

/// An outbound auth that hands out numbered handles and refuses the value `refuse`.
#[derive(Default)]
struct Stub {
    opened: Mutex<Vec<Vec<u8>>>,
}

impl Stub {
    fn opens(&self) -> usize {
        self.opened.lock().unwrap().len()
    }
}

impl busbar_contract::auth_calls::OutboundAuth for Stub {
    fn open_outbound(
        &self,
        _: &str,
        credential: &[u8],
        _: &serde_json::Value,
    ) -> Result<u64, String> {
        if credential == b"refuse" {
            return Err("the auth plugin refused the credential".into());
        }
        let mut opened = self.opened.lock().unwrap();
        opened.push(credential.to_vec());
        Ok(opened.len() as u64)
    }

    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }

    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        unreachable!("no hop is presented in these cells")
    }
}

const LEASE: Duration = Duration::from_secs(60);

fn reference(member: &str) -> SecretRef {
    super::source_path(format!("/lease-cells/{member}/{}", std::process::id()))
}

struct Bound {
    per: PerHop,
    secrets: Arc<Scripted>,
    auth: Arc<Stub>,
    report: &'static Captured,
    minted: Instant,
}

fn bound(member: &str, answers: &[Result<&'static str, u32>]) -> Bound {
    let secrets = scripted(answers);
    let auth = Arc::new(Stub::default());
    let report = Captured::leak();
    let minted = Instant::now();
    let per = super::per_hop_on(
        member,
        reference(member),
        Arc::clone(&auth) as Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
        Arc::clone(&secrets) as Arc<dyn SecretResolve>,
        LEASE,
        report,
    );
    Bound {
        per,
        secrets,
        auth,
        report,
        minted,
    }
}

fn scope() -> busbar_contract::config_time::ConfigScope {
    busbar_contract::config_time::ConfigScope::config_time()
}

fn expires_at(per: &PerHop) -> Option<Instant> {
    per.held.load().as_deref().map(|h| h.expires_at)
}

// T-A1
#[test]
fn a_failed_refresh_keeps_the_held_credential_until_its_lease_ends() {
    for kind in [
        ERROR_KIND_UNAVAILABLE,
        ERROR_KIND_INTERNAL,
        ERROR_KIND_INVALID,
    ] {
        let b = bound("ta1", &[Ok("v1"), Err(kind)]);
        let first = b.per.handle_at(b.minted).expect("bound");
        let ends = expires_at(&b.per).expect("held");
        assert_eq!(
            b.per.refresh(&scope()),
            Attempt::Failed { error_kind: kind },
            "kind {kind}"
        );
        assert_eq!(
            b.per.handle_at(Instant::now()),
            Some(first),
            "an outage (kind {kind}) keeps the credential"
        );
        assert_eq!(
            b.per.handle_at(ends - Duration::from_millis(1)),
            Some(first),
            "until the last instant of its lease"
        );
        assert_eq!(
            b.per.handle_at(ends + Duration::from_millis(1)),
            None,
            "and never past it"
        );
        assert_eq!(expires_at(&b.per), Some(ends), "a failure never extends it");
    }
}

// T-A3
#[test]
fn a_failed_reopen_after_rotation_keeps_the_old_handle_and_lease() {
    let b = bound("ta3", &[Ok("v1"), Ok("refuse")]);
    let first = b.per.handle_at(b.minted).expect("bound");
    let ends = expires_at(&b.per).expect("held");
    assert_eq!(b.per.refresh(&scope()), Attempt::Refused);
    assert_eq!(
        b.per.handle_at(Instant::now()),
        Some(first),
        "the old handle"
    );
    assert_eq!(
        expires_at(&b.per),
        Some(ends),
        "the old value was not re-confirmed: its lease is not extended"
    );
    let reported = b.report.coded(8026);
    assert_eq!(reported.len(), 1, "{}", b.report.all());
    assert_eq!(
        reported[0].level,
        tracing::Level::ERROR,
        "a refused rotation is ERROR from the first (it will not heal by retrying)"
    );
    assert_eq!(reported[0].field("cause"), Some("reopen"));
}

// T-A4
#[test]
fn a_refresh_failure_emits_8026_once_per_streak_window_and_audits_degraded() {
    let b = bound(
        "ta4-member",
        &[Ok("ta4-SECRET-VALUE"), Err(ERROR_KIND_UNAVAILABLE)],
    );
    let t0 = Instant::now();
    for s in [0, 1, 2, 30] {
        b.per
            .refresh_with(&scope(), t0 + Duration::from_secs(s), 0.5);
    }
    let warned = b.report.coded(8026);
    assert_eq!(warned.len(), 1, "one per streak window: {}", b.report.all());
    assert_eq!(warned[0].level, tracing::Level::WARN);
    assert_eq!(warned[0].field("member"), Some("ta4-member"));
    assert_eq!(
        warned[0].field("reference"),
        Some(reference("ta4-member").describe().as_str())
    );
    assert_eq!(
        warned[0].field("error_kind"),
        Some(ERROR_KIND_UNAVAILABLE.to_string().as_str())
    );
    for field in ["failures", "retry_in_ms", "expires_in_ms", "style", "cause"] {
        assert!(warned[0].field(field).is_some(), "{field} missing");
    }
    assert_eq!(
        b.report.audits(),
        vec![(
            "upstream_credential.refresh".to_string(),
            "member:ta4-member".to_string(),
            "degraded"
        )],
        "the audit follows the report's cadence"
    );
    b.per
        .refresh_with(&scope(), t0 + Duration::from_secs(61), 0.5);
    assert_eq!(b.report.coded(8026).len(), 2, "again after a minute");

    let seen = b.report.all();
    let digest = busbar_kernel::refresh::fingerprint([b"ta4-SECRET-VALUE".as_slice()])
        .expect("the process is keyed");
    let plain: [u8; 32] = busbar_contract::digest::sha256(b"ta4-SECRET-VALUE");
    for leaked in [
        "ta4-SECRET-VALUE".to_string(),
        hex::encode(digest),
        hex::encode(plain),
        busbar_contract::media::base64_encode(&digest),
        busbar_contract::media::base64_encode(&plain),
    ] {
        assert!(!seen.contains(&leaked), "a report carries {leaked}: {seen}");
    }
}

// T-A5 (M5: from the refresher, with no hop)
#[test]
fn a_lapse_emits_8027_once_and_audits_rejected() {
    let b = bound("ta5", &[Ok("v1"), Err(ERROR_KIND_UNAVAILABLE)]);
    let ends = expires_at(&b.per).expect("held");
    let due = Refreshable::refresh(&b.per, ends - Duration::from_secs(10));
    assert!(due <= ends, "the refresher wakes for the lapse itself");
    assert!(b.report.coded(8027).is_empty(), "not yet");
    Refreshable::refresh(&b.per, ends + Duration::from_millis(1));
    Refreshable::refresh(&b.per, ends + Duration::from_secs(5));
    let lapsed = b.report.coded(8027);
    assert_eq!(lapsed.len(), 1, "once per lapse: {}", b.report.all());
    assert_eq!(lapsed[0].level, tracing::Level::ERROR);
    assert_eq!(lapsed[0].field("cause"), Some("lease-expired"));
    assert!(b.report.audits().contains(&(
        "upstream_credential.refresh".into(),
        "member:ta5".into(),
        "rejected"
    )));
}

// T-A6
#[test]
fn recovery_after_failures_audits_applied_and_resets_the_schedule() {
    let b = bound(
        "ta6",
        &[
            Ok("v1"),
            Err(ERROR_KIND_UNAVAILABLE),
            Err(ERROR_KIND_UNAVAILABLE),
            Ok("v1"),
        ],
    );
    let t0 = Instant::now();
    b.per.refresh_with(&scope(), t0, 0.5);
    b.per
        .refresh_with(&scope(), t0 + Duration::from_secs(1), 0.5);
    let (attempt, due) = b
        .per
        .refresh_with(&scope(), t0 + Duration::from_secs(2), 0.5);
    assert_eq!(attempt, Attempt::Renewed);
    assert_eq!(
        due,
        t0 + Duration::from_secs(2) + LEASE / 2,
        "back on the renewal cadence"
    );
    assert_eq!(b.report.infos().len(), 1, "one recovery line");
    assert_eq!(b.report.audits().last().map(|a| a.2), Some("applied"));
    b.secrets.then(&[Err(ERROR_KIND_UNAVAILABLE)]);
    b.per
        .refresh_with(&scope(), t0 + Duration::from_secs(3), 0.5);
    assert_eq!(
        b.per.refreshing.lock().unwrap().failures,
        1,
        "the streak restarted"
    );
}

// T-A7
#[test]
fn retry_schedule_is_jittered_exponential_capped_and_fits_two_attempts_before_expiry() {
    let now = Instant::now();
    let lease = Duration::from_secs(60);
    let ends = Some(now + lease);
    let at = |next, unit| next_due(lease, next, ends, now, unit) - now;
    // Success: lease/2 ± 10 %.
    assert_eq!(at(Next::Renew, 0.0), Duration::from_secs(27));
    assert_eq!(at(Next::Renew, 1.0), Duration::from_secs(33));
    // A definitive answer is re-read after the 1 s base.
    assert_eq!(at(Next::Confirm, 0.7), Duration::from_secs(1));
    // Failure n: full jitter under min(2^(n-1) s, cap), cap = clamp(60/8, 1, 30) = 7.5 s.
    for (n, ceiling) in [(1, 1_000), (2, 2_000), (3, 4_000), (4, 7_500), (9, 7_500)] {
        assert_eq!(
            at(Next::Retry(n), 1.0),
            Duration::from_millis(ceiling),
            "n={n}"
        );
        assert_eq!(
            at(Next::Retry(n), 0.0),
            busbar_kernel::retry::FLOOR,
            "n={n}"
        );
    }
    // Near expiry a wait that would reach it is halved toward it: never past it, never a spin.
    let close = Some(now + Duration::from_secs(3));
    let wait = next_due(lease, Next::Retry(9), close, now, 1.0) - now;
    assert_eq!(wait, Duration::from_millis(1_500));
    let tight = Some(now + Duration::from_millis(50));
    assert_eq!(
        next_due(lease, Next::Retry(9), tight, now, 1.0) - now,
        busbar_kernel::retry::FLOOR
    );
    // Past expiry: steady, uniform in [cap/2, cap].
    let past = Some(now - Duration::from_secs(1));
    assert_eq!(
        next_due(lease, Next::Retry(3), past, now, 0.0) - now,
        Duration::from_millis(3_750)
    );
    assert_eq!(
        next_due(lease, Next::Retry(3), None, now, 1.0) - now,
        Duration::from_millis(7_500)
    );
    // The cap is clamped to [1 s, 30 s]; the renewal never waits more than five minutes.
    let long = Duration::from_secs(3600);
    assert_eq!(
        next_due(long, Next::Retry(40), None, now, 1.0) - now,
        Duration::from_secs(30)
    );
    assert_eq!(
        next_due(long, Next::Renew, None, now, 0.5) - now,
        Duration::from_secs(300)
    );
    let short = Duration::from_millis(1);
    assert_eq!(
        next_due(short, Next::Renew, None, now, 0.5) - now,
        busbar_kernel::retry::FLOOR,
        "a 1 ms lease never spins the refresher"
    );
    // Under failures, every attempt before expiry lands before it.
    let mut t = now;
    let mut attempts = 0;
    for n in 1..64 {
        let next = next_due(lease, Next::Retry(n), ends, t, 1.0);
        if next >= now + lease {
            break;
        }
        attempts += 1;
        t = next;
    }
    assert!(
        attempts >= 2,
        "at least two attempts before expiry: {attempts}"
    );
}

// B1: the owner-signed rule.
#[test]
fn a_definitive_answer_drops_after_one_confirming_reread_and_an_outage_keeps() {
    for kind in [ERROR_KIND_NOT_FOUND, ERROR_KIND_DENIED] {
        let b = bound("b1-def", &[Ok("v1"), Err(kind), Err(kind)]);
        let first = b.per.handle_at(b.minted).expect("bound");
        let now = b.minted;
        let (attempt, due) = b.per.refresh_with(&scope(), now, 0.5);
        assert_eq!(attempt, Attempt::Confirming { error_kind: kind });
        assert_eq!(
            due,
            now + Duration::from_secs(1),
            "re-read after one second"
        );
        assert_eq!(b.per.handle_at(now), Some(first), "kept meanwhile");
        let (attempt, _) = b.per.refresh_with(&scope(), due, 0.5);
        assert_eq!(attempt, Attempt::Dropped { error_kind: kind });
        assert_eq!(b.per.handle_at(due), None, "dropped at once");
        assert_eq!(
            b.report.coded(8027)[0].field("cause"),
            Some("revoked-at-source")
        );
        assert_eq!(b.report.audits().last().map(|a| a.2), Some("rejected"));
    }

    let mixed = bound(
        "b1-mixed",
        &[
            Ok("v1"),
            Err(ERROR_KIND_DENIED),
            Err(ERROR_KIND_NOT_FOUND),
            Ok("v1"),
        ],
    );
    assert!(matches!(
        mixed.per.refresh(&scope()),
        Attempt::Confirming { .. }
    ));
    assert_eq!(
        mixed.per.refresh(&scope()),
        Attempt::Confirming {
            error_kind: ERROR_KIND_NOT_FOUND
        },
        "a different answer is not a confirmation: it is confirmed afresh"
    );
    assert_eq!(mixed.per.refresh(&scope()), Attempt::Renewed);

    let blip = bound("b1-blip", &[Ok("v1"), Err(ERROR_KIND_NOT_FOUND), Ok("v1")]);
    let first = blip.per.handle_at(blip.minted).expect("bound");
    blip.per.refresh(&scope());
    assert_eq!(blip.per.refresh(&scope()), Attempt::Renewed);
    assert_eq!(
        blip.per.handle_at(Instant::now()),
        Some(first),
        "a blip never drops"
    );
    assert!(blip.report.coded(8027).is_empty());

    let outage = bound(
        "b1-outage",
        &[
            Ok("v1"),
            Err(ERROR_KIND_UNAVAILABLE),
            Err(ERROR_KIND_INTERNAL),
            Err(ERROR_KIND_INVALID),
        ],
    );
    let first = outage.per.handle_at(outage.minted).expect("bound");
    for _ in 0..3 {
        assert!(matches!(
            outage.per.refresh(&scope()),
            Attempt::Failed { .. }
        ));
    }
    assert_eq!(
        outage.per.handle_at(Instant::now()),
        Some(first),
        "outages keep it"
    );
}

// M4
#[test]
fn an_unchanged_file_with_a_trailing_newline_never_reopens() {
    let path = super::own_secret("lease-newline", "tok\n");
    let auth = Arc::new(Stub::default());
    let per = super::per_hop_on(
        "newline",
        super::source_path(path.display().to_string()),
        Arc::clone(&auth) as Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        LEASE,
        Captured::leak(),
    );
    for _ in 0..8 {
        assert_eq!(per.refresh(&scope()), Attempt::Renewed);
    }
    assert_eq!(auth.opens(), 1, "the build's one open, never a re-open");
    let _ = std::fs::remove_file(&path);
}

// M6
#[test]
fn a_flapping_source_reuses_the_previous_handle() {
    let b = bound("m6", &[Ok("v1"), Ok("v2"), Ok("v1"), Ok("v2"), Ok("v1")]);
    let first = b.per.handle_at(b.minted).expect("bound");
    assert_eq!(b.per.refresh(&scope()), Attempt::Rotated);
    let second = b.per.handle_at(Instant::now()).expect("rotated");
    assert_ne!(first, second);
    for expect in [first, second, first] {
        assert_eq!(b.per.refresh(&scope()), Attempt::Rotated);
        assert_eq!(b.per.handle_at(Instant::now()), Some(expect));
    }
    assert_eq!(
        b.auth.opens(),
        2,
        "two values, two opens, however often they flip"
    );
}

// M5: many members on one source report once a minute, the rest counted.
#[test]
fn members_failing_on_one_source_report_once_and_count_the_others() {
    let path = format!("/lease-cells/shared-source/{}", std::process::id());
    let report = Captured::leak();
    let members: Vec<PerHop> = (0..5)
        .map(|i| {
            super::per_hop_on(
                &format!("m5-{i}"),
                super::source_path(&path),
                Arc::new(Stub::default()) as Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
                scripted(&[Ok("v"), Err(ERROR_KIND_UNAVAILABLE)]) as Arc<dyn SecretResolve>,
                LEASE,
                report,
            )
        })
        .collect();
    let t0 = Instant::now();
    for per in &members {
        per.refresh_with(&scope(), t0, 0.5);
    }
    assert_eq!(report.coded(8026).len(), 1, "{}", report.all());
    assert_eq!(report.quiet(8026).len(), 4, "the rest at debug");
    members[1].refresh_with(&scope(), t0 + Duration::from_secs(61), 0.5);
    let again = report.coded(8026);
    assert_eq!(again.len(), 2);
    assert_eq!(
        again[1].field("others"),
        Some("4"),
        "the held-back members are counted"
    );
}
