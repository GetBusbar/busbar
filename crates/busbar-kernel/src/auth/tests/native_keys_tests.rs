// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An engine-minted token on the native path: admitted on the plane it was minted for, by the
//! chain member `keys`, and nowhere else.

use super::*;
use crate::auth::native_data::DataRefused;
use crate::auth::route_record::{RouteRecord, Scope};
use crate::governance::signing::{TokenSigner, TOKEN_PREFIX};
use crate::governance::{GovState, NewKeySpec, VirtualKey};
use crate::oauth_as::seam::AccessStanding;
use busbar_contract::records::ScopeRef;

const PLANE_A: &str = "https://gw.example.com/mcp";
const PLANE_B: &str = "https://gw.example.com/mcp-staging";
const SECRET: [u8; 32] = [7; 32];
const KID: &str = "k1";
const MINTED: u64 = 1_000;
const EXPIRES: u64 = 2_000;
const NOW: u64 = 1_500;

async fn gov() -> GovState {
    GovState::new_with_core(
        crate::real_store::core().await,
        None,
        Some(TokenSigner::from_secret_bytes(&SECRET, KID)),
    )
    .await
    .expect("governance over the test store")
}

fn spec() -> NewKeySpec {
    NewKeySpec {
        name: "mcp-client".into(),
        ..NewKeySpec::default()
    }
}

/// A key and its token bound to `audience` (`None`: a plain data-plane key).
async fn minted(gov: &GovState, audience: Option<&str>) -> (VirtualKey, String) {
    let (key, token) = match audience {
        Some(audience) => gov
            .mint_signed_for_audience_async(spec(), EXPIRES, MINTED, audience)
            .await
            .expect("mint for the audience"),
        None => gov
            .mint_signed_async(spec(), EXPIRES, MINTED)
            .await
            .expect("mint"),
    };
    (key, token.expose(&crate::seal::lend()).to_string())
}

fn bearer(token: &str) -> Vec<u8> {
    format!("Bearer {token}").into_bytes()
}

/// The head `fields` as the chain member `keys` reads it on a route whose own credential header
/// is `x-route-key`.
fn scanned<'h>(fields: &'h [(&'h str, Vec<u8>)]) -> Presented<'h> {
    Presented::scan(
        fields.iter().map(|(name, value)| (*name, value.as_slice())),
        |name| name.eq_ignore_ascii_case("x-route-key"),
    )
}

fn judged(
    gov: &GovState,
    token: &str,
    audience: Option<&str>,
    now: u64,
) -> Result<Option<CoreKey>, DataRefused> {
    let fields = [("authorization", bearer(token))];
    admit(Some(gov), &scanned(&fields), true, audience, now)
}

#[tokio::test]
async fn the_right_token_is_admitted_on_its_own_plane() {
    let gov = gov().await;
    let (key, token) = minted(&gov, Some(PLANE_A)).await;
    let core = judged(&gov, &token, Some(PLANE_A), NOW)
        .expect("a token minted for this plane is admitted")
        .expect("the head presents a core token");
    assert_eq!(core.subject(), key.id);
    let standing = core
        .standing(Some(&gov), NOW)
        .expect("its key stands at the gate");
    assert_eq!(standing.id, key.id);
}

#[tokio::test]
async fn a_token_for_plane_a_is_refused_on_plane_b() {
    let gov = gov().await;
    let (_, token) = minted(&gov, Some(PLANE_A)).await;
    assert_eq!(
        judged(&gov, &token, Some(PLANE_B), NOW).unwrap_err(),
        DataRefused::Credential,
        "an audience is an opaque identifier compared for equality: never a prefix"
    );
}

#[tokio::test]
async fn the_audience_boundary_holds_in_both_directions() {
    let gov = gov().await;
    let (_, bound) = minted(&gov, Some(PLANE_A)).await;
    let (_, plain) = minted(&gov, None).await;
    assert_eq!(
        judged(&gov, &bound, None, NOW).unwrap_err(),
        DataRefused::Credential,
        "a token bound to a plane is never spent on a route bound to no audience"
    );
    assert_eq!(
        judged(&gov, &plain, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential,
        "a token that states no audience is never enough on an audience-bound plane"
    );
    assert!(
        judged(&gov, &plain, None, NOW).unwrap().is_some(),
        "a plain key is admitted where no audience is bound, as 1.5.5 admitted it"
    );
}

#[tokio::test]
async fn a_token_minted_by_another_issuer_is_refused() {
    let gov = gov().await;
    let (key, _) = minted(&gov, Some(PLANE_A)).await;
    // The same key id, kid, audience and expiry, signed by a key this engine does not hold.
    let forged = TokenSigner::from_secret_bytes(&[8; 32], KID).mint_for_audience(
        &key.id,
        EXPIRES,
        None,
        PLANE_A,
        None,
    );
    assert_eq!(
        judged(&gov, &forged, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential
    );
    // And one signed under a key id this engine does not know.
    let unknown_kid = TokenSigner::from_secret_bytes(&SECRET, "k2").mint_for_audience(
        &key.id,
        EXPIRES,
        None,
        PLANE_A,
        None,
    );
    assert_eq!(
        judged(&gov, &unknown_kid, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let gov = gov().await;
    let (_, token) = minted(&gov, Some(PLANE_A)).await;
    assert!(judged(&gov, &token, Some(PLANE_A), EXPIRES - 1)
        .unwrap()
        .is_some());
    for now in [EXPIRES, EXPIRES + 1] {
        assert_eq!(
            judged(&gov, &token, Some(PLANE_A), now).unwrap_err(),
            DataRefused::Credential,
            "dead at and after its expiry"
        );
    }
}

#[tokio::test]
async fn a_revoked_token_is_refused_at_the_head_and_at_the_gate() {
    let gov = gov().await;
    let (key, token) = minted(&gov, Some(PLANE_A)).await;
    // Verified while it stood; revoked before the gate.
    let verified = judged(&gov, &token, Some(PLANE_A), NOW)
        .unwrap()
        .expect("verified before the revocation");
    gov.revoke_async(&key.id, "test").await.expect("revoke");
    assert_eq!(
        verified.standing(Some(&gov), NOW).unwrap_err(),
        DataRefused::Policy,
        "a token revoked between its verification and the gate opens nothing"
    );
    assert_eq!(
        judged(&gov, &token, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential
    );
}

#[tokio::test]
async fn a_disabled_key_is_refused_and_a_key_disabled_before_the_gate_is_answered_as_disabled() {
    let gov = gov().await;
    let (key, token) = minted(&gov, Some(PLANE_A)).await;
    let verified = judged(&gov, &token, Some(PLANE_A), NOW)
        .unwrap()
        .expect("verified while enabled");
    gov.update_key_outcome_async(&key.id, Some(false), None)
        .await
        .expect("disable");
    assert_eq!(
        verified.standing(Some(&gov), NOW).unwrap_err(),
        DataRefused::Disabled
    );
    assert_eq!(
        judged(&gov, &token, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential
    );
}

#[tokio::test]
async fn a_token_expired_before_the_gate_opens_nothing() {
    let gov = gov().await;
    let (_, token) = minted(&gov, Some(PLANE_A)).await;
    let verified = judged(&gov, &token, Some(PLANE_A), NOW).unwrap().unwrap();
    assert_eq!(
        verified.standing(Some(&gov), EXPIRES).unwrap_err(),
        DataRefused::Policy
    );
    assert_eq!(
        verified.standing(None, NOW).unwrap_err(),
        DataRefused::Policy,
        "with no governance at the gate nothing stands"
    );
}

#[tokio::test]
async fn a_valid_token_is_refused_where_the_chain_does_not_name_keys() {
    let gov = gov().await;
    let (_, token) = minted(&gov, Some(PLANE_A)).await;
    let fields = [("authorization", bearer(&token))];
    assert_eq!(
        admit(Some(&gov), &scanned(&fields), false, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential,
        "the operator chain and a chain of other verifiers never admit a core token"
    );
    assert_eq!(
        admit(None, &scanned(&fields), true, Some(PLANE_A), NOW).unwrap_err(),
        DataRefused::Credential,
        "a core token no governance can verify is never accepted unverified"
    );
}

#[tokio::test]
async fn one_core_token_and_nothing_else_is_what_a_head_may_present() {
    let gov = gov().await;
    let (_, token) = minted(&gov, Some(PLANE_A)).await;
    let (_, second) = minted(&gov, Some(PLANE_A)).await;
    // The same token twice, two tokens, a decoy first, a second credential on the route's header.
    for fields in [
        vec![
            ("authorization", bearer(&token)),
            ("Authorization", bearer(&token)),
        ],
        vec![
            ("authorization", bearer(&token)),
            ("authorization", bearer(&second)),
        ],
        vec![
            ("authorization", b"Bearer harmless-decoy".to_vec()),
            ("authorization", bearer(&token)),
        ],
        vec![
            ("authorization", bearer(&token)),
            ("x-route-key", b"sk-other".to_vec()),
        ],
        vec![
            ("authorization", b"Basic dXNlcjpwYXNz".to_vec()),
            ("X-Route-Key", token.clone().into_bytes()),
        ],
    ] {
        assert_eq!(
            admit(Some(&gov), &scanned(&fields), true, Some(PLANE_A), NOW).unwrap_err(),
            DataRefused::Credential,
            "{} carrier lines",
            fields.len()
        );
    }
    // On the route's own header, alone, it is the one credential.
    let fields = [
        ("x-route-key", token.clone().into_bytes()),
        ("x-unrelated", b"bbk_not-a-carrier".to_vec()),
    ];
    assert!(
        admit(Some(&gov), &scanned(&fields), true, Some(PLANE_A), NOW)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_head_with_no_core_token_is_the_other_members_to_judge() {
    let fields = [
        ("authorization", b"Bearer eyJhbGciOiJFUzI1NiJ9.e30.sig".to_vec()),
        ("x-route-key", b"sk-other".to_vec()),
    ];
    let presented = scanned(&fields);
    assert!(!presented.core_presented());
    assert!(admit(None, &presented, true, Some(PLANE_A), NOW)
        .unwrap()
        .is_none());
    assert!(admit(None, &presented, false, None, NOW).unwrap().is_none());
    // The prefix is read on the credential, not anywhere in the line.
    let fields = [(
        "authorization",
        format!("Bearer x{TOKEN_PREFIX}y").into_bytes(),
    )];
    assert!(!scanned(&fields).core_presented());
}

fn key_with(scopes: Option<Vec<(&str, &str)>>) -> VirtualKey {
    VirtualKey {
        id: "vk_test".into(),
        enabled: true,
        allowed_scopes: scopes.map(|scopes| {
            scopes
                .into_iter()
                .map(|(kind, value)| ScopeRef {
                    kind: kind.into(),
                    value: value.into(),
                })
                .collect()
        }),
        ..VirtualKey::default()
    }
}

fn record(scope: Scope) -> RouteRecord {
    let mut record = RouteRecord::from_declared(
        0,
        busbar_plugin_abi::plane::AUTH_PRINCIPAL,
        None,
        &[],
        None,
        true,
    )
    .expect("a principal data route");
    record.scope = scope;
    record.scope_stated = true;
    record
}

#[test]
fn a_restricted_key_must_hold_a_grant_of_a_kind_the_routes_record_names() {
    let mcp = record(Scope::walk_and_selected("mcp_server", &["mcp_tool"]));
    assert!(
        holds_record_scope(&mcp, &key_with(None)),
        "an unrestricted key"
    );
    assert!(holds_record_scope(
        &mcp,
        &key_with(Some(vec![("mcp_server", "acme")]))
    ));
    assert!(holds_record_scope(
        &mcp,
        &key_with(Some(vec![("pool", "chat"), ("mcp_tool", "acme_search")]))
    ));
    assert!(
        !holds_record_scope(&mcp, &key_with(Some(vec![("pool", "chat")]))),
        "a key restricted to another plane's kinds carries no scope here"
    );
    assert!(
        !holds_record_scope(&mcp, &key_with(Some(Vec::new()))),
        "a key restricted to nothing"
    );
    assert!(
        holds_record_scope(&record(Scope::none()), &key_with(Some(Vec::new()))),
        "a route whose record states scope none requires none"
    );
}

#[test]
fn the_authorization_servers_standing_only_ever_refuses() {
    assert_eq!(as_standing_of(AccessStanding::NotMine), Ok(false));
    assert_eq!(as_standing_of(AccessStanding::Live), Ok(true));
    assert_eq!(
        as_standing_of(AccessStanding::Dead),
        Err(DataRefused::Credential),
        "revoked, expired, unknown to its own issuer, or minted for another resource"
    );
    assert_eq!(
        as_standing_of(AccessStanding::Unavailable),
        Err(DataRefused::Unavailable),
        "a store that cannot answer is 503, never an admission and never a 401"
    );
}
