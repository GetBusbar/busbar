// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLUGIN TESTS ITSELF, BOTH WAYS**: this crate's `door` (the `DoorFn` a compiled-in row
//! holds) through [`load_linked`], and its dropped-in image (`examples/webhook_signature_door.rs`,
//! the one exported `busbar_plugin_door`) through [`load_dropped`] — the loader's ONE path, every
//! answer judged by the auth kind's own `check_identify`.
//!
//! TWO scripts, one per variant: `open` with the settings and the signing secret, then `verify`.
//! `twilio`: a Media Streams WebSocket upgrade and a signed form POST — a valid signature
//! (identity), and the RED arms: a bad signature, a missing header, a signature replayed on another
//! URL, a tampered form, no body lent. `standard-webhooks`: the specification's published vector,
//! and the RED arms: a bad signature, a stale timestamp, missing headers, no body lent.

use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_auth_webhook_signature::signature::twilio_sign;
use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, NamedValue, RequestFacts, StripName, VerifyIn,
    DECISION_CONTINUE, DECISION_STOP, POINT_HEAD_BODY, SPAN_ABSENT, STRIP_FIELD, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

const TOKEN: &str = "twilio-auth-token";
const SETTINGS: &str = r#"{"variant":"twilio","origin":"wss://edge.example.com"}"#;
const PATH: &str = "/twilio/inbound";
const QUERY: &str = "tenant=acme";
const SIGNED_URL: &str = "wss://edge.example.com/twilio/inbound?tenant=acme";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

#[derive(Default)]
struct Folds(Mutex<Vec<String>>);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!("diag {}", d.id));
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(folds: &Arc<Folds>, d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_webhook_signature::door), bind(folds, d))
        .expect("the linked door loads")
}

/// The dropped-in image `cargo test` builds (`examples/`). Under CI a missing artifact is a
/// failure, never a skip.
fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Option<Plugin<Auth>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let file = format!(
        "{}webhook_signature_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [
        profile.join("examples").join(&file),
        profile.join("examples").join("deps").join(&file),
    ]
    .into_iter()
    .find(|p| p.exists());
    assert!(
        path.is_some() || std::env::var_os("CI").is_none(),
        "the webhook-signature dropped-in image is not built under CI; a both-ways proof must not skip"
    );
    let stated =
        rendering_of(busbar_auth_webhook_signature::door).expect("the door renders its Statement");
    path.map(|p| load_dropped::<Auth>(&p, &stated, bind(folds, d)).expect("the dropped door loads"))
}

fn open(p: &Plugin<Auth>, settings: &str, secret: &str) -> Outcome {
    let secrets = [blob(secret.as_bytes(), BLOB_OCTETS, BLOB_SECRET)];
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    o.input.settings = blob(settings.as_bytes(), BLOB_JSON, 0);
    o.input.secrets = secrets.as_ptr();
    o.input.secrets_len = secrets.len();
    p.call(life::OPEN, &mut o).outcome
}

/// One `verify` at `HeadBody`: `outcome verdict subject`, as the loader judged it. The host lends
/// `body` (none = no body lent, which a body-signed request is refused for).
#[allow(clippy::too_many_arguments)]
fn verify_req(
    p: &Plugin<Auth>,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &str)],
) -> String {
    verify_answer(p, method, path, query, body, now, headers).0
}

/// [`verify_req`]'s line, and the decision and the strip names (lower-case) the answer carried.
#[allow(clippy::too_many_arguments)]
fn verify_answer(
    p: &Plugin<Auth>,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &str)],
) -> (String, u32, Vec<String>) {
    let mut buf = vec![0u8; 256];
    let mut groups = vec![Span { offset: 0, len: 0 }; 4];
    let mut strips = vec![
        StripName {
            name: Span { offset: 0, len: 0 },
            place: 0,
            _reserved: 0,
        };
        8
    ];
    let lines: Vec<NamedValue> = headers
        .iter()
        .map(|(n, v)| NamedValue {
            name: s(n),
            value: blob(v.as_bytes(), BLOB_OCTETS, BLOB_SECRET),
        })
        .collect();
    let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.credential = z();
    f.input.lines = lines.as_ptr();
    f.input.lines_len = lines.len();
    f.input.point = POINT_HEAD_BODY;
    f.input.body = body.map_or(z(), |b| blob(b, BLOB_OCTETS, 0));
    f.input.strip = strips.as_mut_ptr();
    f.input.strip_cap = strips.len() as u32;
    f.input.request = RequestFacts {
        method: s(method),
        authority: s("edge.example.com"),
        canonical_path: s(path),
        query: query.map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            s,
        ),
        timestamp: now,
    };
    f.input.out_buf = IdentityBuf {
        buf: buf.as_mut_ptr(),
        buf_cap: buf.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let c = p.call(slot::VERIFY, &mut f);
    let verdict = match f.out.verdict {
        VERDICT_IDENTITY => "identity",
        VERDICT_REJECT => "reject",
        VERDICT_PASS => "pass",
        _ => "?",
    };
    let subject = f.out.identity.subject;
    let subject = if c.outcome == Outcome::Ready
        && f.out.verdict == VERDICT_IDENTITY
        && subject.offset != SPAN_ABSENT
    {
        String::from_utf8_lossy(
            &buf[subject.offset as usize..(subject.offset + subject.len) as usize],
        )
        .into_owned()
    } else {
        String::new()
    };
    let replay = f.out.identity.replay_key;
    let replay = if c.outcome == Outcome::Ready
        && f.out.verdict == VERDICT_IDENTITY
        && replay.offset != SPAN_ABSENT
    {
        format!(
            " replay={}/{}s",
            String::from_utf8_lossy(
                &buf[replay.offset as usize..(replay.offset + replay.len) as usize]
            ),
            f.out.identity.replay_ttl_secs
        )
    } else {
        String::new()
    };
    let named = if c.outcome == Outcome::Ready {
        strips[..f.out.strip_len as usize]
            .iter()
            .map(|n| {
                assert_eq!(n.place, STRIP_FIELD, "a signature header is a field line");
                String::from_utf8_lossy(
                    &buf[n.name.offset as usize..(n.name.offset + n.name.len) as usize],
                )
                .to_ascii_lowercase()
            })
            .collect()
    } else {
        Vec::new()
    };
    (
        format!("{:?} {verdict} {subject}{replay}", c.outcome)
            .trim_end()
            .to_string(),
        f.out.decision,
        named,
    )
}

/// A Twilio Media Streams upgrade (a GET) with `signature` in `X-Twilio-Signature`, or none.
fn verify(p: &Plugin<Auth>, path: &str, query: Option<&str>, signature: Option<&str>) -> String {
    let headers: Vec<(&str, &str)> = signature
        .map(|v| ("X-Twilio-Signature", v))
        .into_iter()
        .collect();
    verify_req(p, "GET", path, query, None, 0, &headers)
}

/// THE TWILIO SCRIPT, one line per call.
fn script(p: &Plugin<Auth>) -> Vec<String> {
    let valid = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    let wrong_key = twilio_sign(b"not-the-token", SIGNED_URL.as_bytes(), &[]);
    let form = b"CallSid=CA1&Digits=12";
    let params = vec![
        (b"CallSid".to_vec(), b"CA1".to_vec()),
        (b"Digits".to_vec(), b"12".to_vec()),
    ];
    let post_sig = twilio_sign(
        TOKEN.as_bytes(),
        b"wss://edge.example.com/twilio/status",
        &params,
    );
    let post = |body: Option<&[u8]>| {
        verify_req(
            p,
            "POST",
            "/twilio/status",
            None,
            body,
            0,
            &[("X-Twilio-Signature", &post_sig)],
        )
    };
    vec![
        format!("open {:?}", open(p, SETTINGS, TOKEN)),
        format!("valid {}", verify(p, PATH, Some(QUERY), Some(&valid))),
        format!(
            "bad-signature {}",
            verify(p, PATH, Some(QUERY), Some(&wrong_key))
        ),
        format!("garbage {}", verify(p, PATH, Some(QUERY), Some("%%%"))),
        format!("missing-header {}", verify(p, PATH, Some(QUERY), None)),
        format!(
            "replayed-path {}",
            verify(p, "/twilio/other", Some(QUERY), Some(&valid))
        ),
        format!(
            "replayed-query {}",
            verify(p, PATH, Some("tenant=evil"), Some(&valid))
        ),
        format!("replayed-no-query {}", verify(p, PATH, None, Some(&valid))),
        format!("signed-post {}", post(Some(form))),
        format!(
            "signed-post-tampered {}",
            post(Some(b"CallSid=CA1&Digits=99"))
        ),
        format!("signed-post-no-body {}", post(None)),
    ]
}

const EXPECTED: &[&str] = &[
    "open Ready",
    "valid Ready identity webhook-signature:twilio",
    "bad-signature Ready reject",
    "garbage Ready reject",
    "missing-header Ready pass",
    "replayed-path Ready reject",
    "replayed-query Ready reject",
    "replayed-no-query Ready reject",
    "signed-post Ready identity webhook-signature:twilio",
    "signed-post-tampered Ready reject",
    "signed-post-no-body Ready reject",
];

/// THE STANDARD WEBHOOKS SCRIPT: the specification's published vector, and its REDs.
fn standard_script(p: &Plugin<Auth>) -> Vec<String> {
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const TS: &str = "1614265330";
    const NOW: u64 = 1_614_265_330;
    const BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SIG: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    let all = [
        ("webhook-id", ID),
        ("webhook-timestamp", TS),
        ("webhook-signature", SIG),
    ];
    let deliver = |headers: &[(&str, &str)], body: Option<&[u8]>, now: u64| {
        verify_req(p, "POST", "/v1/webhooks/inbound", None, body, now, headers)
    };
    vec![
        format!(
            "open {:?}",
            open(p, r#"{"variant":"standard-webhooks"}"#, SECRET)
        ),
        format!("valid {}", deliver(&all, Some(BODY), NOW)),
        format!(
            "bad-signature {}",
            deliver(
                &[
                    ("webhook-id", ID),
                    ("webhook-timestamp", TS),
                    (
                        "webhook-signature",
                        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc="
                    ),
                ],
                Some(BODY),
                NOW
            )
        ),
        format!("stale {}", deliver(&all, Some(BODY), NOW + 301)),
        format!("missing-headers {}", deliver(&[], Some(BODY), NOW)),
        format!("missing-signature {}", deliver(&all[..2], Some(BODY), NOW)),
        format!("no-body-lent {}", deliver(&all, None, NOW)),
    ]
}

const STANDARD_EXPECTED: &[&str] = &[
    "open Ready",
    "valid Ready identity webhook-signature:standard-webhooks \
     replay=standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek/301s",
    "bad-signature Ready reject",
    "stale Ready reject",
    "missing-headers Ready pass",
    "missing-signature Ready reject",
    "no-body-lent Ready reject",
];

#[test]
fn compiled_in_and_dropped_in_verify_every_variant_identically() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let linked_t = script(&linked(&folds, &d));
    assert_eq!(linked_t, EXPECTED, "the linked door");
    let linked_s = standard_script(&linked(&folds, &d));
    assert_eq!(
        linked_s, STANDARD_EXPECTED,
        "the linked door, standard-webhooks"
    );
    let folds = Arc::new(Folds::default());
    if let Some(p) = dropped(&folds, &d) {
        assert_eq!(script(&p), linked_t, "the dropped door");
        let p = dropped(&folds, &d).expect("loaded once already");
        assert_eq!(
            standard_script(&p),
            linked_s,
            "the dropped door, standard-webhooks"
        );
        println!(
            "PROOF auth-webhook-signature: linked and dropped answered {} calls identically",
            linked_t.len() + linked_s.len()
        );
    }
}

#[test]
fn red_open_without_a_signing_secret_or_with_foreign_settings_fails() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    assert_eq!(open(&linked(&folds, &d), SETTINGS, ""), Outcome::Failed);
    assert_eq!(
        open(
            &linked(&folds, &d),
            r#"{"variant":"stripe","origin":"wss://x"}"#,
            TOKEN
        ),
        Outcome::Failed
    );
}

/// THE STRIPS AND THE DECISION (THE DESIGN, "Auth points and guest lists", step 3): whatever the
/// verdict, the plugin names its four signature header lines for the transport to strip, so the
/// request's handler never sees them; an identity or a pass continues, a reject stops.
#[test]
fn every_verdict_names_the_signature_lines_and_a_decision() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    assert_eq!(open(&p, SETTINGS, TOKEN), Outcome::Ready);
    let valid = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    let names = [
        "x-twilio-signature",
        "webhook-id",
        "webhook-timestamp",
        "webhook-signature",
    ];
    for (sig, verdict, decision) in [
        (Some(valid.as_str()), "identity", DECISION_CONTINUE),
        (Some("%%%"), "reject", DECISION_STOP),
        (None, "pass", DECISION_CONTINUE),
    ] {
        let headers: Vec<(&str, &str)> =
            sig.map(|v| ("X-Twilio-Signature", v)).into_iter().collect();
        let (line, got, stripped) = verify_answer(&p, "GET", PATH, Some(QUERY), None, 0, &headers);
        assert!(line.starts_with(&format!("Ready {verdict}")), "{line}");
        assert_eq!(got, decision, "{line}");
        assert_eq!(stripped, names, "{line}");
    }
}
