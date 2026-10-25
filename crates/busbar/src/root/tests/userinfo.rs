// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BASIC CREDENTIAL A URL'S USERINFO SPELLS, HELD BY THE ROOT: read the way
//! reqwest 0.12.28 read it, and presented through the auth kind's outbound call as 1.5.5 sent it
//! — first, unless the binding's own answer names `authorization`.

use std::sync::Arc;

use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Secret;

use super::{lead_with, UserinfoBasic};

fn basic(plain: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(plain)
    )
}

fn value_of(basic: &UserinfoBasic) -> String {
    let led = basic.leading(&[]).expect("no field names authorization");
    String::from_utf8(led[0].1.to_vec()).expect("ascii")
}

#[test]
fn a_urls_userinfo_reads_as_reqwest_read_it() {
    for (url, plain) in [
        (
            "https://svcuser:hunter2-P4ss@api.example.com/v1",
            "svcuser:hunter2-P4ss",
        ),
        (
            "https://svcuser:hun@ter2@api.example.com",
            "svcuser:hun@ter2",
        ),
        (
            "https://svcuser:p%40ss%3A1@api.example.com",
            "svcuser:p@ss:1",
        ),
        ("https://svcuser@api.example.com", "svcuser:"),
        ("https://svcuser:@api.example.com", "svcuser:"),
        ("https://:hunter2@api.example.com", ":hunter2"),
        ("https://svcuser:%FF@api.example.com", "svcuser:"),
        ("https://a:b@api.example.com", "a:b"),
        ("https://ab:c@api.example.com", "ab:c"),
    ] {
        let read = UserinfoBasic::of(url).expect("a userinfo");
        assert_eq!(value_of(&read), basic(plain), "{url}");
        assert_eq!(format!("{read:?}"), "UserinfoBasic(<redacted>)");
    }
    for url in [
        "https://api.example.com/v1",
        "https://api.example.com/x@y",
        "https://@api.example.com",
        "https://:@api.example.com",
        "https://%FF:hunter2@api.example.com",
        "https://:%FF@api.example.com",
        "api.example.com",
    ] {
        assert!(UserinfoBasic::of(url).is_none(), "{url} presents nothing");
    }
}

/// A binding that answers one field, `name: k`, on the spot and when submitted.
struct Answers(&'static [u8]);

struct Done(Fields);

impl std::future::Future for Done {
    type Output = Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        std::task::Poll::Ready(self.0.clone())
    }
}

impl Fielding for Done {
    fn settled(&mut self) -> Option<Fields> {
        Some(self.0.clone())
    }
}

impl OutboundAuth for Answers {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(7)
    }
    fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
        Some(Fields::Ready(vec![AuthField {
            name: self.0.to_vec(),
            value: Secret::new(b"k".to_vec()),
            sensitive: true,
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
}

fn names_and_values(answer: Option<Fields>) -> Vec<(String, String)> {
    match answer {
        Some(Fields::Ready(fields)) => fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).into_owned(),
                    String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend()))
                        .into_owned(),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// ROW 74 (F25), THE MEMBER'S REQUEST: a binding whose credential rides another field is led by the
/// Basic value, on the spot and when submitted; one whose credential is `authorization` displaces
/// it (1.5.5's `replace_headers`); a binding with no userinfo is handed over as it is.
#[tokio::test]
async fn a_binding_is_led_by_the_basic_value_unless_it_names_authorization() {
    let read =
        UserinfoBasic::of("https://svcuser:hunter2-P4ss@api.example.com").expect("a userinfo");
    let expected = basic("svcuser:hunter2-P4ss");

    let led = lead_with(Arc::new(Answers(b"x-api-key")), Some(read.clone()));
    let want = vec![
        ("authorization".to_string(), expected.clone()),
        ("x-api-key".to_string(), "k".to_string()),
    ];
    assert_eq!(
        names_and_values(led.fields_now(7, &FieldsRequest::default())),
        want
    );
    let submitted = led.fields(7, FieldsRequest::default(), 0).await;
    assert_eq!(names_and_values(Some(submitted)), want);

    let displaced = lead_with(Arc::new(Answers(b"authorization")), Some(read));
    assert_eq!(
        names_and_values(displaced.fields_now(7, &FieldsRequest::default())),
        vec![("authorization".to_string(), "k".to_string())]
    );

    let plain: Arc<dyn OutboundAuth> = Arc::new(Answers(b"x-api-key"));
    let same = lead_with(Arc::clone(&plain), None);
    assert!(
        Arc::ptr_eq(&plain, &same),
        "no userinfo, the binding as it is"
    );
}

/// ROW 74 (F25), THE TOKEN POST'S HEAD: the minting plugin's open is led by the Basic value unless
/// its own fields name `authorization`.
#[test]
fn a_token_posts_head_is_led_by_the_basic_value_unless_it_names_authorization() {
    let read =
        UserinfoBasic::of("https://svcuser:hunter2-P4ss@login.example.com").expect("a userinfo");
    let form: &[(&str, &[u8])] = &[("content-type", b"application/x-www-form-urlencoded")];
    let led = read.leading(form).expect("led");
    assert_eq!(led[0].0, "authorization");
    assert_eq!(led[0].1, basic("svcuser:hunter2-P4ss").as_bytes());
    assert_eq!(led[1], form[0]);
    assert!(read
        .leading(&[("Authorization", b"Bearer t".as_slice())])
        .is_none());
}
