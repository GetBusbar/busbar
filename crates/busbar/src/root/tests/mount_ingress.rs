//! Tests for `mount_ingress.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! What is here is the two properties that make this a seam rather than a struct: the answer is one
//! answer about one caller, and it is per-arrival rather than per-process.

use super::*;
use busbar_api::{PlaneRequestCtx, VirtualKey};
use busbar_core::{governance::MemoryStore, plane_host::engine_host, test_support::TestApp};
use busbar_substrate::{ingress::arrival::ArrivalPayload, plane_host::EngineHost};

/// THE DEPLOYMENT's own engine host, minted over a bare test app exactly as the composition root
/// mints one. Not a stub: what these cells assert about the host is that ONE of them reaches every
/// arrival, and a stub would make that a property of the stub.
pub(crate) fn a_host() -> Arc<dyn EngineHost> {
    engine_host(&TestApp::new().build())
}

/// THE ONE GOVERNANCE STORE a cell hands a leg, built the way every mount cell builds one — in
/// memory, empty, and owned by the cell. Written once here so the retiring crate is named in one
/// test module rather than in each leg's.
pub(crate) fn memory_store() -> Arc<MemoryStore> {
    Arc::new(MemoryStore::new())
}

/// **THE PROTOCOL REGISTRY, INSTALLED** — the dialect declarations a cell needs before it can ask
/// what an address means or how its callers authenticate.
///
/// Written ONCE here, for the reason [`memory_store`] gives beside it: the retiring crate is named
/// in one test module rather than in each leg's, and a mention of another kind's vocabulary is
/// counted per LINE — six call sites spelled it six times to say one thing. Idempotent.
pub(crate) fn install_seams() {
    busbar_llm::testkit::install_test_seams();
}

/// THE BOOT'S MINT, as a cell writes it: close over one deployment's host and box the substrate's
/// own payload around a caller's resolved half. Shared by every cell in this crate that seals a
/// `BootIngress`, so the shape of what the boot hands the seam is written once.
pub(crate) fn minted(
    host: Arc<dyn EngineHost>,
) -> impl Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync + 'static {
    move |gov, caller_token| {
        ArrivalCtx::new(ArrivalPayload {
            host: Arc::clone(&host),
            gov,
            caller_token,
        })
    }
}

/// The payload a sealed context carries, read the way a leg reads it.
fn payload(ctx: &ArrivalCtx) -> &ArrivalPayload {
    ctx.downcast_ref()
        .expect("a sealed mount arrival carries the substrate's payload")
}

/// A GOVERNED deployment's state: the in-memory store every mount cell uses, with an admin token,
/// which is what makes `keys` enforcement live. Empty of keys on purpose — what the cells below ask
/// is what this node does with a credential it has NEVER minted, and every credential is one.
fn a_governed_state() -> Arc<busbar_core::governance::GovState> {
    Arc::new(
        busbar_core::governance::GovState::new(memory_store(), Some("admintok".to_string()))
            .expect("an empty in-memory governance store loads"),
    )
}

/// **A SEALED ARRIVAL FOR ONE KNOWN CALLER**, for the cells whose subject is the LEG and not the
/// chain.
///
/// The money cells, the ending cell and the boot-composition cells below and in `units_llm_mount`
/// are about what a mounted leg DOES with a caller the door already admitted: which book the posting
/// lands in, whether the ending survives the exit arm, whether the boot's own row answers this
/// plane's address. Running a real auth chain inside them would make every one of those assertions
/// depend on a credential fixture that has nothing to do with what they assert, and a chain that
/// refused would fail them for a reason none of them names.
///
/// So this admits, always, with the key the cell handed it — which is exactly what the seam's
/// `resolve` half used to do for every caller including the ones it should have refused. The
/// difference is that it is now a TEST DOUBLE that says so in its name, rather than the production
/// path's only behaviour.
pub(crate) struct AdmitsOneCaller {
    mint: Box<dyn Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync>,
    key: Option<Arc<VirtualKey>>,
}

impl AdmitsOneCaller {
    pub(crate) fn new(
        mint: impl Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync + 'static,
        key: Option<Arc<VirtualKey>>,
    ) -> Self {
        AdmitsOneCaller {
            mint: Box::new(mint),
            key,
        }
    }
}

#[async_trait::async_trait]
impl ArrivalSource for AdmitsOneCaller {
    async fn arrival(&self, presented: Presented<'_>) -> Admitted {
        Admitted::Arrival((self.mint)(
            PlaneRequestCtx {
                key: self.key.clone(),
            },
            presented
                .credential
                .and_then(presented_secret)
                .map(str::to_string),
        ))
    }
}

/// ONE CALLER PRESENTING A CREDENTIAL AND NOTHING ELSE — the shape every cell below whose subject is
/// the credential asks with.
///
/// The request line and the headers are a plain unsigned arrival, deliberately: a cell about what a
/// chain makes of a bearer must not accidentally take the signature arm, and a cell about the
/// signature arm builds the arrival it is actually about rather than editing this one.
pub(crate) fn presenting(credential: Option<&str>) -> Presented<'_> {
    Presented {
        credential,
        method: "POST",
        target: "/v1/chat/completions",
        headers: &[],
        body: b"{}",
    }
}

/// The sealed arrival a source admitted, or a panic naming the refusal the cell did not expect.
fn admitted(answer: Admitted) -> ArrivalCtx {
    match answer {
        Admitted::Arrival(ctx) => ctx,
        Admitted::Refused => panic!("the chain refused a caller this cell expected it to admit"),
    }
}

/// **A CREDENTIAL THE CHAIN CANNOT RESOLVE IS REFUSED, NOT ADMITTED AS NOBODY.**
///
/// THE CELL THIS SEAM EXISTED WITHOUT, and the hole it left was a money-and-auth hole rather than a
/// tidiness one. The seam used to resolve a presented credential itself — `presented_secret` into
/// `GovState::verify_token` — and map EVERY failure to `PlaneRequestCtx { key: None }`. But
/// `key: None` is not "refused". It is the UNGOVERNED POSTURE, and every step downstream reads it
/// that way: the plane's authenticate step attributes the anonymous actor and proceeds, the verify
/// step's scope guard is `if let Some(key)` and so never fires, and the door has no key to meter
/// against. A mounted deployment therefore answered `200` to a caller presenting a credential this
/// node never minted, served it out of scope, and recorded no usage for it.
///
/// The app here runs the `keys` chain over real governance, which is the shape an operator who has
/// configured governance at all is running. A bogus bearer resolves to nothing in it — so the chain
/// DENIES, and the seam must carry that denial rather than flatten it into anonymity.
#[tokio::test]
async fn a_credential_the_chain_denies_is_refused_rather_than_admitted_as_anonymous() {
    let app = TestApp::new()
        .keys_chain()
        .governance(a_governed_state())
        .build();
    let source = BootIngress::new(minted(engine_host(&app)), engine_host(&app));

    assert!(
        matches!(
            source
                .arrival(presenting(Some("Bearer sk-not-a-key")))
                .await,
            Admitted::Refused
        ),
        "a credential this node never minted is a REFUSAL, not the anonymous actor"
    );
    assert!(
        matches!(source.arrival(presenting(None)).await, Admitted::Refused),
        "and presenting nothing at all to a governed node is refused for the same reason"
    );
}

/// **THE RESOLUTION IS THE DEPLOYMENT'S OWN CHAIN, asked per arrival.**
///
/// The property a struct with a baked-in governance context could not have, and the one a global
/// could not have either — restated over the door that now answers it. An UNGOVERNED deployment
/// runs an empty chain, which answers `Open`, which is the explicit open-front-door posture the boot
/// banner warns about; the same source over a GOVERNED one refuses the same caller. One seam, two
/// deployments, two answers — and neither of them is this file's opinion.
#[tokio::test]
async fn the_chain_the_deployment_configured_is_the_one_that_answers() {
    let open = TestApp::new().build();
    let open_source = BootIngress::new(minted(engine_host(&open)), engine_host(&open));
    let ctx = admitted(open_source.arrival(presenting(Some("Bearer sk-one"))).await);
    assert!(
        payload(&ctx).gov.key.is_none(),
        "an empty chain answers Open, which is ungoverned and not a refusal renamed"
    );

    let governed = TestApp::new()
        .keys_chain()
        .governance(a_governed_state())
        .build();
    let governed_source = BootIngress::new(minted(engine_host(&governed)), engine_host(&governed));
    assert!(
        matches!(
            governed_source
                .arrival(presenting(Some("Bearer sk-one")))
                .await,
            Admitted::Refused
        ),
        "the same caller, on a node that configured governance, is refused by that node's chain"
    );
}

/// **THE HOST IS THE DEPLOYMENT'S**, and every arrival on one mount reaches the same one.
///
/// The other half of the split. A source that minted a host per request would be composing a second
/// engine for every caller; a source that resolved a caller once would be answering every caller
/// with the first one's identity. This is the pair asserted together, because separately either one
/// reads as an implementation detail.
#[tokio::test]
async fn every_arrival_on_one_mount_reaches_the_one_host_the_boot_sealed() {
    let host = a_host();
    let source = BootIngress::new(minted(Arc::clone(&host)), Arc::clone(&host));

    let (first, second) = (
        admitted(source.arrival(presenting(Some("Bearer sk-one"))).await),
        admitted(source.arrival(presenting(Some("Bearer sk-two"))).await),
    );
    assert!(
        Arc::ptr_eq(&payload(&first).host, &host) && Arc::ptr_eq(&payload(&second).host, &host),
        "one deployment, one engine host, however many callers"
    );
}

/// **THE TOKEN THAT TRAVELS UPSTREAM IS THE SECRET AND NOT THE HEADER.**
///
/// The driven path carries the caller's RESOLVED token — the catch-all boxes the secret, not the
/// header value it arrived on. A mounted leg that forwarded the whole credential would put the
/// scheme word inside the token and send `Bearer Bearer sk-…` to a destination, which is a
/// credential no upstream has ever accepted and a difference no cell downstream of here would
/// attribute to this line.
#[tokio::test]
async fn the_caller_token_is_the_secret_the_driven_path_carries() {
    let host = a_host();
    let source = BootIngress::new(minted(Arc::clone(&host)), host);
    let token = |credential: Option<&'static str>| {
        let source = &source;
        async move {
            payload(&admitted(source.arrival(presenting(credential)).await))
                .caller_token
                .clone()
        }
    };

    assert_eq!(
        token(Some("Bearer sk-live")).await.as_deref(),
        Some("sk-live")
    );
    // A bare secret is what a vendor SDK writing its own key header sends, and it is the whole
    // value: there is no scheme word to drop.
    assert_eq!(token(Some("sk-live")).await.as_deref(), Some("sk-live"));
    // The scheme word is not matched against a list — which alternatives a plane accepts is the
    // authentication chain's answer, and a list here would be a second one that could drift.
    assert_eq!(
        token(Some("ApiKey sk-live")).await.as_deref(),
        Some("sk-live")
    );
    // Presented nothing, and presented a blank, are two different statements and only one of them
    // is a caller.
    assert_eq!(token(None).await, None);
    assert_eq!(token(Some("Bearer   ")).await, None);
    assert_eq!(token(Some("   ")).await, None);
}

/// ONE ARRIVAL SIGNED THE WAY A VENDOR SDK SIGNS ONE, with the SAME signer a real client uses
/// (`busbar_substrate::sigv4::sign_v4`) rather than a hand-written header — a fixture that spelled
/// a signature out would be asserting against itself.
///
/// Returns the credential as presented and the headers as sent, borrowed the way the mount publishes
/// them.
fn signed(
    secret: &str,
    access_key_id: &str,
    target: &str,
    body: &[u8],
) -> (String, Vec<(String, String)>) {
    let (amzdate, datestamp) =
        busbar_substrate::sigv4::format_amz_time(busbar_substrate::store::now());
    let payload_hash = busbar_substrate::sigv4::sha256_hex(body);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amzdate.clone()),
    ];
    let (signature, signed_headers) = busbar_substrate::sigv4::sign_v4(
        secret,
        "us-east-1",
        "bedrock",
        "POST",
        &busbar_substrate::sigv4::uri_encode_path(path),
        query,
        &headers,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let credential = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{datestamp}/us-east-1/bedrock/aws4_request, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );
    // AND THE CREDENTIAL AMONG THE HEADERS, because that is where it arrived and where the mount
    // publishes it. A signature is not a header a signature covers — `SignedHeaders` never names
    // `authorization` — but it is read off the same map the signed ones are, by the door, exactly as
    // the driven middleware reads it off the request.
    let mut headers = headers;
    headers.insert(0, ("authorization".to_string(), credential.clone()));
    (credential, headers)
}

/// **A CREDENTIAL THAT IS A SIGNATURE OVER THE ARRIVAL IS ADMITTED — AND A TAMPERED ONE IS NOT.**
///
/// THE CELL THE SEAM'S ARGUMENT MADE UNWRITABLE. The door used to be asked about a credential
/// STRING, and one whole family of credentials cannot be answered from one: a signature binds the
/// method, the target, the headers it names and a hash of the body, so a door handed the leftovers
/// after the first space has nothing to verify against and can only fail closed. Every mounted
/// request signed that way was therefore REFUSED where the driven path admits it — the fail-closed
/// half of the same hole the refusal arm closed, and just as wrong.
///
/// Three statements, and the third is the one that makes the first two worth anything:
///
/// - a correctly signed arrival is admitted, and admitted AS THE KEY THAT OWNS THE CREDENTIAL —
///   not as the ungoverned anonymous posture, which is what "admitted" would mean if the key were
///   `None`. The money and the scope guard downstream both read that key.
/// - the SAME signature over a DIFFERENT body is refused. That is the payload bind: the signature
///   only covers the bytes if the bytes are re-hashed and compared, and a door that skipped it
///   would leave a MitM free to rewrite the request in flight and still authenticate.
/// - and a credential this node never minted, signed with a secret that is not the key's, is
///   refused. So "admitted" above is a statement about the signature and not about the shape.
///
/// None of it is this file's opinion: the verification is the deployment's own, reached through the
/// plane-host ABI, and it is the SAME verifier the driven middleware runs for the same request.
#[tokio::test]
async fn a_credential_that_signs_the_whole_arrival_is_admitted_and_a_tampered_one_is_not() {
    install_seams();
    // A GOVERNED node holding ONE key that carries a signing credential. `create_key_with_aws` is
    // the same mint the operator surface calls, so what the cell signs with is a credential this
    // node really issued rather than a fixture's invention.
    let gov = a_governed_state();
    let (_key, _bearer, access_key_id, secret) = gov
        .create_key_with_aws(
            busbar_substrate::governance::NewKeySpec {
                name: "signed".to_string(),
                allowed_pools: None,
                group: None,
                ..Default::default()
            },
            busbar_substrate::store::now(),
        )
        .expect("a governed node mints a signing credential");
    let app = TestApp::new().keys_chain().governance(gov).build();
    let source = BootIngress::new(minted(engine_host(&app)), engine_host(&app));

    let target = "/model/anthropic.claude-3-5-sonnet/converse";
    let body = br#"{"messages":[]}"#;
    let (credential, headers) = signed(&secret, &access_key_id, target, body);
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    fn arrived<'a>(
        credential: &'a str,
        target: &'a str,
        headers: &'a [(&'a str, &'a str)],
        body: &'a [u8],
    ) -> Presented<'a> {
        Presented {
            credential: Some(credential),
            method: "POST",
            target,
            headers,
            body,
        }
    }

    let admitted_ctx = admitted(
        source
            .arrival(arrived(&credential, target, &borrowed, body))
            .await,
    );
    assert_eq!(
        payload(&admitted_ctx)
            .gov
            .key
            .as_ref()
            .map(|key| key.name.clone()),
        Some("signed".to_string()),
        "a signed arrival is admitted as the key that owns the credential, never as the anonymous \
         actor a `key: None` context would make it"
    );

    assert!(
        matches!(
            source
                .arrival(arrived(
                    &credential,
                    target,
                    &borrowed,
                    br#"{"messages":[{"tampered":true}]}"#
                ))
                .await,
            Admitted::Refused
        ),
        "the signature binds the payload: the same signature over other bytes is not this caller"
    );

    let (forged, forged_headers) = signed("not-this-nodes-secret", &access_key_id, target, body);
    let forged_borrowed: Vec<(&str, &str)> = forged_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert!(
        matches!(
            source
                .arrival(Presented {
                    credential: Some(&forged),
                    method: "POST",
                    target,
                    headers: &forged_borrowed,
                    body,
                })
                .await,
            Admitted::Refused
        ),
        "a signature made with a secret this node never issued is refused"
    );
}
