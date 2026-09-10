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
    async fn arrival(&self, credential: Option<&str>) -> Admitted {
        Admitted::Arrival((self.mint)(
            PlaneRequestCtx {
                key: self.key.clone(),
            },
            credential.and_then(presented_secret).map(str::to_string),
        ))
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
            source.arrival(Some("Bearer sk-not-a-key")).await,
            Admitted::Refused
        ),
        "a credential this node never minted is a REFUSAL, not the anonymous actor"
    );
    assert!(
        matches!(source.arrival(None).await, Admitted::Refused),
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
    let ctx = admitted(open_source.arrival(Some("Bearer sk-one")).await);
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
            governed_source.arrival(Some("Bearer sk-one")).await,
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
        admitted(source.arrival(Some("Bearer sk-one")).await),
        admitted(source.arrival(Some("Bearer sk-two")).await),
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
            payload(&admitted(source.arrival(credential).await))
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
