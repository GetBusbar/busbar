// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An audience-bound plane (MCP's `canonical_uri`, RFC 8707) served on the native DATA path,
//! case by case at the route's own preparation: a token minted for this plane goes on to the
//! chain, a token minted for another plane or for none is refused, a plain key is refused in
//! every carrier the chain reads, and every refusal is the one uniform 401 with the route's
//! declared `resource_metadata` challenge (RFC 9728 s5.1).

use super::*;
use base64::Engine as _;

const PLANE_A: &str = "https://gw.example.com/mcp";
const PLANE_B: &str = "https://gw.example.com/mcp-staging";
const CHALLENGE: &str =
    "Bearer resource_metadata=\"https://gw.example.com/.well-known/oauth-protected-resource/mcp\"";

/// A verifier that reads its credential from `authorization` and `x-api-key` and accepts any
/// value it is handed: the engine, not the plugin, keeps the plane's audience.
struct CarrierKeys {
    calls: AtomicUsize,
    carriers: Box<[Box<str>]>,
}

impl AuthPort for CarrierKeys {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &self.carriers
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, req: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let presented = req.headers.iter().any(|field| {
            !field.value.get().is_empty()
                && self
                    .carriers
                    .iter()
                    .any(|carrier| carrier.eq_ignore_ascii_case(field.name.get()))
        });
        if !presented {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let mut records = Reply::new();
        records.put_text(tag::ID_SUBJECT, "client").unwrap();
        records.put_text(tag::ID_GROUP, "reader").unwrap();
        let VerifyOk::Identity(identity) =
            decode_verify_ok(Records::new(records.as_bytes())).unwrap()
        else {
            panic!("identity")
        };
        Verify::Done(Ok(VerifyAnswer::Identity(identity)))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        _: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

/// The fixture's route bound to `PLANE_A` with its declared challenge, judged by a chain whose
/// one member reads `authorization` and `x-api-key`.
fn bound_route() -> (Fixture, Arc<CarrierKeys>) {
    let mut f = fixture(true);
    let port = Arc::new(CarrierKeys {
        calls: AtomicUsize::new(0),
        carriers: vec![
            Box::<str>::from("authorization"),
            Box::<str>::from("x-api-key"),
        ]
        .into_boxed_slice(),
    });
    let member = Arc::new(AuthInstance {
        opened: OpenedAuth {
            who: Namespace {
                plugin: "verified-image".into(),
                name: "provider-42".into(),
                instance: 42,
                slot: 4,
            },
            port: port.clone(),
            methods: busbar_plugin_abi::auth::M_VERIFY,
            out_of_process: false,
            limits: InstanceLimits::default(),
        },
        keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
        holds: Box::default(),
    });
    let chain = Arc::new(NativeChain::data(7, vec![member], chain_owners()).unwrap());
    let route = Arc::get_mut(&mut f.route).unwrap();
    route.withheld = withheld_carriers(&chain, None);
    route.owners.chain = chain;
    route.audience = Some(Arc::from(PLANE_A));
    route.challenge = Some(Box::from(CHALLENGE));
    (f, port)
}

/// A JWT whose payload is `claims`; only the engine's audience pre-filter reads it here.
fn jwt(claims: &str) -> String {
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.{}",
        b64(br#"{"alg":"RS256","typ":"JWT"}"#),
        b64(claims.as_bytes()),
        b64(b"not-a-real-signature")
    )
}

fn minted_for(audience: &str) -> String {
    jwt(&format!(r#"{{"sub":"client","aud":"{audience}"}}"#))
}

/// The route's preparation of one request carrying `fields`: Ok when it goes on verified.
async fn prepared(f: &Fixture, stream: u64, fields: &[(&str, String)]) -> Result<(), DataRefused> {
    let fields = fields
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.as_bytes().to_vec()))
        .collect();
    let (mut request, _wire, cx, _owner) = arrival_with(f, stream, fields, b"admin-body");
    let preparation = request.begin_data_preparation().unwrap();
    f.route
        .prepare(preparation, cx)
        .await
        .map(drop)
        .map_err(|failed| failed.reason())
}

#[tokio::test]
async fn audience_bound_plane_admits_only_its_own_token_in_every_carrier() {
    let (f, port) = bound_route();
    let own = minted_for(PLANE_A);
    let foreign = minted_for(PLANE_B);
    let unbound = jwt(r#"{"sub":"client"}"#);

    // A token minted for this plane goes on to the chain, in either carrier the chain reads.
    assert_eq!(
        prepared(&f, 1, &[("authorization", format!("Bearer {own}"))]).await,
        Ok(())
    );
    assert_eq!(prepared(&f, 2, &[("x-api-key", own.clone())]).await, Ok(()));
    assert_eq!(port.calls.load(Ordering::SeqCst), 2);

    // A token minted for another plane, or for none, is refused before any verifier runs,
    // whichever carrier it arrives in: an audience is compared for equality, never a prefix.
    let mut stream = 3;
    for token in [&foreign, &unbound] {
        for fields in [
            vec![("authorization", format!("Bearer {token}"))],
            vec![("x-api-key", token.clone())],
            // Never a decoy: this plane's token beside a foreign one admits nothing.
            vec![
                ("authorization", format!("Bearer {own}")),
                ("x-api-key", token.clone()),
            ],
        ] {
            assert_eq!(
                prepared(&f, stream, &fields).await,
                Err(DataRefused::Credential),
                "{fields:?}"
            );
            stream += 1;
        }
    }
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        2,
        "a foreign token never reaches a verifier"
    );
}

#[tokio::test]
async fn audience_bound_plane_refuses_a_plain_key_in_every_carrier() {
    let (f, port) = bound_route();
    let plain = "sk-plain-gateway-key".to_owned();
    for (stream, fields) in (1_u64..).zip([
        vec![("authorization", format!("Bearer {plain}"))],
        vec![("x-api-key", plain.clone())],
        vec![
            ("authorization", format!("Bearer {}", minted_for(PLANE_A))),
            ("x-api-key", plain.clone()),
        ],
    ]) {
        assert_eq!(
            prepared(&f, stream, &fields).await,
            Err(DataRefused::Credential),
            "a credential that states no audience is never enough here: {fields:?}"
        );
    }
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        0,
        "a plain key is refused before any verifier runs"
    );
}

#[tokio::test]
async fn audience_bound_plane_answers_every_unverified_caller_the_one_401() {
    let (f, _port) = bound_route();
    // Nothing presented: no member verifies the caller.
    assert_eq!(prepared(&f, 1, &[]).await, Err(DataRefused::Credential));
    // A foreign token and a plain key are refused for the same reason.
    assert_eq!(
        prepared(
            &f,
            2,
            &[("authorization", format!("Bearer {}", minted_for(PLANE_B)))]
        )
        .await,
        Err(DataRefused::Credential)
    );
    assert_eq!(
        prepared(&f, 3, &[("x-api-key", "sk-plain".to_owned())]).await,
        Err(DataRefused::Credential)
    );
    // All three are the one 401: the same bytes whether or not a credential was presented,
    // carrying the route's declared `resource_metadata` challenge.
    for presented in [false, true] {
        assert_eq!(
            DataRefused::Credential.refusal(presented),
            Some(crate::auth::admission_table::Refusal::Unverified { presented })
        );
    }
    assert_eq!(f.route.challenge(), Some(CHALLENGE));
    let absent = crate::auth::core_answer::unverified(false, f.route.challenge());
    let refused = crate::auth::core_answer::unverified(true, f.route.challenge());
    assert_eq!(
        absent, refused,
        "no oracle: which check failed changes no byte"
    );
    assert_eq!(absent.status, 401);
    assert!(absent
        .fields
        .contains(&(b"www-authenticate".to_vec(), CHALLENGE.as_bytes().to_vec())));
}
