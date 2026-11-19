// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a head presents as a sender-constrained credential on the native path, the URL its proof
//! must name, and the view the chain is handed once the proof is proven. The proof's own checks
//! (signature, `htm`, `htu`, `iat`, `jti`, `ath`, `cnf.jkt`) are the authorization server's and
//! are tested beside it (`busbar-core-oauth2`, `native_dpop_tests`).

use base64::Engine as _;
use busbar_contract::json;

use super::{as_bearer, read, received_at, verdict, Presentation, Reason};
use crate::auth::native_data::DataRefused;
use crate::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::oauth_as::seam::{DpopRefused, DpopVerdict};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn jwt(claims: json::Value) -> String {
    format!(
        "{}.{}.c2ln",
        B64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        B64.encode(claims.to_string())
    )
}

fn bound() -> String {
    jwt(json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }))
}

fn unbound() -> String {
    jwt(json::json!({ "sub": "a" }))
}

/// The route's chain reads `x-api-key` beside `authorization`.
fn reads(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-api-key")
}

fn presented<'h>(head: &'h [(&'h str, String)]) -> Presentation<'h> {
    read(
        head.iter().map(|(name, value)| (*name, value.as_bytes())),
        reads,
    )
}

#[test]
fn an_unbound_token_is_unaffected() {
    for head in [
        vec![],
        vec![("authorization", format!("Bearer {}", unbound()))],
        vec![("authorization", "Bearer an-opaque-key".to_string())],
        vec![("x-api-key", unbound())],
        vec![("authorization", "Basic dXNlcjpwYXNz".to_string())],
        // A proof header beside an ordinary bearer proves nothing and changes nothing.
        vec![
            ("authorization", format!("Bearer {}", unbound())),
            ("dpop", "a.b.c".to_string()),
        ],
    ] {
        assert_eq!(presented(&head), Presentation::Unbound, "{head:?}");
    }
}

#[test]
fn a_bound_token_used_as_a_bearer_is_refused() {
    for head in [
        vec![("authorization", format!("Bearer {}", bound()))],
        vec![("Authorization", format!("bearer {}", bound()))],
        vec![("x-api-key", bound())],
        // Behind a decoy first bearer, and with a proof header that no DPoP scheme asks for.
        vec![
            ("authorization", format!("Bearer {}", unbound())),
            ("authorization", format!("Bearer {}", bound())),
        ],
        vec![
            ("authorization", format!("Bearer {}", bound())),
            ("dpop", "a.b.c".to_string()),
        ],
    ] {
        assert_eq!(
            presented(&head),
            Presentation::Refused(Reason::BoundBearer),
            "{head:?}"
        );
    }
}

#[test]
fn a_dpop_presentation_is_one_token_and_one_proof() {
    let token = bound();
    for scheme in ["DPoP", "dpop", "DPOP"] {
        let head = [
            ("authorization", format!("{scheme} {token}")),
            ("DPoP", "a.b.c".to_string()),
            ("content-type", "application/json".to_string()),
        ];
        assert_eq!(
            presented(&head),
            Presentation::Dpop {
                token: &token,
                proof: "a.b.c"
            },
            "{scheme}"
        );
    }
}

#[test]
fn a_dpop_presentation_without_exactly_one_proof_is_refused() {
    let token = bound();
    let none = [("authorization", format!("DPoP {token}"))];
    assert_eq!(
        presented(&none),
        Presentation::Refused(Reason::NotOneProof),
        "a bound token WITHOUT a proof"
    );
    let two = [
        ("authorization", format!("DPoP {token}")),
        ("dpop", "a.b.c".to_string()),
        ("dpop", "d.e.f".to_string()),
    ];
    assert_eq!(
        presented(&two),
        Presentation::Refused(Reason::NotOneProof),
        "RFC 9449 s4.3 (1): not more than one DPoP header"
    );
    let not_text: [(&str, &[u8]); 2] = [("authorization", b"DPoP a.b.c"), ("dpop", &[0xff, 0xfe])];
    assert_eq!(
        read(not_text.iter().copied(), reads),
        Presentation::Refused(Reason::NotOneProof)
    );
}

#[test]
fn a_dpop_presentation_beside_any_other_credential_is_refused() {
    let token = bound();
    let proof = ("dpop", "a.b.c".to_string());
    for other in [
        ("authorization", format!("Bearer {}", unbound())),
        ("authorization", format!("DPoP {token}")),
        ("authorization", "Basic dXNlcjpwYXNz".to_string()),
        ("x-api-key", "an-opaque-key".to_string()),
        ("x-api-key", bound()),
    ] {
        let head = [
            ("authorization", format!("DPoP {token}")),
            other.clone(),
            proof.clone(),
        ];
        assert_eq!(
            presented(&head),
            Presentation::Refused(Reason::NotOneCredential),
            "beside {other:?}: a proven token never shares the head with another credential"
        );
    }
    let empty = [("authorization", "DPoP ".to_string()), proof];
    assert_eq!(
        presented(&empty),
        Presentation::Refused(Reason::NotOneCredential)
    );
}

#[test]
fn the_proof_names_the_public_origin_and_the_path_as_received() {
    assert_eq!(
        received_at("https://gw.example.com/mcp", "/mcp").as_deref(),
        Some("https://gw.example.com/mcp")
    );
    assert_eq!(
        received_at("https://gw.example.com:8443/mcp?x=1#frag", "/mcp/messages").as_deref(),
        Some("https://gw.example.com:8443/mcp/messages"),
        "no query and no fragment; the port is part of the origin"
    );
    assert_eq!(
        received_at("https://gw.example.com", "/mcp").as_deref(),
        Some("https://gw.example.com/mcp")
    );
    for (public, path) in [
        ("gw.example.com/mcp", "/mcp"),
        ("https:///mcp", "/mcp"),
        ("ftp://gw.example.com/mcp", "/mcp"),
        ("https://gw.example.com/mcp", "mcp"),
        ("https://gw.example.com/mcp", ""),
        ("https://gw.example.com/mcp", "/mcp?x=1"),
        ("https://gw.example.com/mcp", "/mcp#frag"),
        ("https://user@gw.example.com/mcp", "/mcp"),
    ] {
        assert_eq!(
            received_at(public, path),
            None,
            "{public} {path}: no URL can be stated, so no proof can match it"
        );
    }
}

#[test]
fn only_a_proven_verdict_is_an_admission() {
    assert_eq!(verdict(DpopVerdict::Proven), Ok(()));
    for refused in [
        DpopRefused::Malformed,
        DpopRefused::NotAProof,
        DpopRefused::Algorithm,
        DpopRefused::ProofKey,
        DpopRefused::Signature,
        DpopRefused::Method,
        DpopRefused::Uri,
        DpopRefused::Stale,
        DpopRefused::Jti,
        DpopRefused::AccessTokenHash,
        DpopRefused::KeyBinding,
        DpopRefused::NotHeld,
        DpopRefused::Replayed,
    ] {
        assert_eq!(
            verdict(DpopVerdict::Refused(refused)),
            Err(DataRefused::Credential),
            "{refused:?} is the one 401: the reason is logged, never answered"
        );
        assert!(!refused.as_str().is_empty());
    }
    assert_eq!(
        verdict(DpopVerdict::Unavailable),
        Err(DataRefused::Unavailable),
        "a store that cannot answer is never an admission"
    );
}

#[test]
fn a_proven_token_reaches_the_chain_as_a_bearer_and_its_proof_reaches_nobody() {
    let budget = ProcessAdmission::with_limits(2, 8192, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let token = bound();
    let presented = format!("dPoP {token}");
    let headers: [(&str, &[u8]); 4] = [
        ("content-type", b"application/json"),
        ("Authorization", presented.as_bytes()),
        ("DPoP", b"a.b.c"),
        ("mcp-session-id", b"s1"),
    ];
    let original = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "POST",
            path: "/mcp",
            query: "a=1",
            query_present: true,
            authority: "gw.example.com",
            headers: headers.iter().copied(),
            peer: "192.0.2.1:123",
            tls_peer_cert: b"certificate",
            body: b"{\"jsonrpc\":\"2.0\"}",
            now_s: 10,
        },
        &request,
    )
    .unwrap();
    let view = as_bearer(&original, &token).expect("the view fits the request's budget");
    let bearer = format!("Bearer {token}");
    assert_eq!(
        view.headers().collect::<Vec<_>>(),
        vec![
            ("content-type", b"application/json".as_slice()),
            ("Authorization", bearer.as_bytes()),
            ("mcp-session-id", b"s1".as_slice()),
        ],
        "the scheme is rewritten in place and the spent proof is dropped; nothing else moves"
    );
    assert_eq!(view.method(), original.method());
    assert_eq!(view.target(), original.target());
    assert_eq!(view.path(), original.path());
    assert_eq!(view.query(), original.query());
    assert_eq!(view.query_present(), original.query_present());
    assert_eq!(view.authority(), original.authority());
    assert_eq!(view.peer(), original.peer());
    assert_eq!(view.tls_peer_cert(), original.tls_peer_cert());
    assert_eq!(view.body(), original.body());
    assert_eq!(view.now_s(), original.now_s());
    assert!(view.request().same_request(original.request()));
    // The view presents a bound token as a bearer: it is made only for a proven presentation and
    // is handed to the chain, never read as a head a caller sent.
    assert_eq!(
        read(view.headers(), |_| false),
        Presentation::Refused(Reason::BoundBearer)
    );
}

#[test]
fn a_view_the_request_cannot_pay_for_is_refused() {
    let budget = ProcessAdmission::with_limits(2, 96, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let headers: [(&str, &[u8]); 1] = [("authorization", b"DPoP a.b.c")];
    let original = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "POST",
            path: "/mcp",
            query: "",
            query_present: false,
            authority: "gw.example.com",
            headers: headers.iter().copied(),
            peer: "",
            tls_peer_cert: b"",
            body: b"",
            now_s: 10,
        },
        &request,
    )
    .unwrap();
    assert_eq!(
        as_bearer(&original, "a.b.c").err(),
        Some(DataRefused::Capacity)
    );
}

/// A proven DPoP request's body is charged once (OPEN-3 row 10): the view the chain is handed
/// pays only for its restated head, never again for the body. A body the request's budget admits
/// without DPoP is admitted with it.
#[test]
fn dpop_body_charged_once() {
    let body = vec![b'x'; 4096];
    // Room for the body once with its head and its restated head, never for the body twice.
    let cap = u32::try_from(body.len() + body.len() / 2).unwrap();
    let token = bound();
    let bearer = format!("Bearer {token}");
    let presented = format!("DPoP {token}");
    let capture = |request, headers: &[(&'static str, &[u8])]| {
        ChargedRequestSnapshot::capture(
            SnapshotInput {
                method: "POST",
                path: "/mcp",
                query: "",
                query_present: false,
                authority: "gw.example.com",
                headers: headers.iter().copied(),
                peer: "192.0.2.1:123",
                tls_peer_cert: b"",
                body: &body,
                now_s: 10,
            },
            request,
        )
    };

    // Without DPoP: the body is admitted.
    let budget = ProcessAdmission::with_limits(2, cap, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let plain = capture(
        &request,
        &[
            ("content-type", b"application/json"),
            ("authorization", bearer.as_bytes()),
        ],
    )
    .expect("the body fits the request's budget");
    drop(plain);
    assert_eq!(budget.used(), (0, 0));

    // With DPoP: the same body is admitted, and the view pays for its head alone.
    let original = capture(
        &request,
        &[
            ("content-type", b"application/json"),
            ("authorization", presented.as_bytes()),
            ("dpop", b"a.b.c"),
        ],
    )
    .expect("the body fits the request's budget");
    let before = budget.used();
    let view =
        as_bearer(&original, &token).expect("a proven body is admitted as it is without DPoP");
    let head = 2 * 16
        + "content-type".len()
        + "application/json".len()
        + "authorization".len()
        + bearer.len();
    assert_eq!(
        budget.used(),
        (before.0 + head, before.1 + head),
        "the view is charged exactly its restated head; the body is not charged again"
    );
    assert_eq!(view.body(), original.body());
    assert_eq!(&view.body_bytes()[..], body.as_slice());
    assert_eq!(view.method(), "POST");
    assert_eq!(view.target(), "/mcp");
    assert!(view.request().same_request(original.request()));
    drop(original);
    // The view keeps the original's body alive, still charged once.
    assert_eq!(view.body(), body.as_slice());
    drop(view);
    assert_eq!(budget.used(), (0, 0));
}
