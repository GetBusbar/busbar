//! Tests for `mount_ingress.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! What is here is the two properties that make this a seam rather than a struct: the answer is one
//! answer about one caller, and it is per-arrival rather than per-process.

use super::*;
use busbar_api::{PlaneRequestCtx, VirtualKey};

/// THE DEPLOYMENT's own engine host, minted over a bare test app exactly as the composition root
/// mints one. Not a stub: what these cells assert about the host is that ONE of them reaches every
/// arrival, and a stub would make that a property of the stub.
fn a_host() -> Arc<dyn busbar_substrate::plane_host::EngineHost> {
    busbar_core::plane_host::engine_host(&busbar_core::test_support::TestApp::new().build())
}

/// THE BOOT'S MINT, as a cell writes it: close over one deployment's host and box the substrate's
/// own payload around a caller's resolved half. Shared by every cell in this crate that seals a
/// `BootIngress`, so the shape of what the boot hands the seam is written once.
pub(crate) fn minted(
    host: Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> impl Fn(PlaneRequestCtx, Option<String>) -> ArrivalCtx + Send + Sync + 'static {
    move |gov, caller_token| {
        ArrivalCtx::new(busbar_substrate::ingress::arrival::ArrivalPayload {
            host: Arc::clone(&host),
            gov,
            caller_token,
        })
    }
}

/// The payload a sealed context carries, read the way a leg reads it.
fn payload(ctx: &ArrivalCtx) -> &busbar_substrate::ingress::arrival::ArrivalPayload {
    ctx.downcast_ref()
        .expect("a sealed mount arrival carries the substrate's payload")
}

/// A governance context naming one key by its identifier, for a cell that only has to tell two
/// callers apart. Built from the public type's own shape and nothing else.
fn ctx_for(credential: Option<&str>) -> PlaneRequestCtx {
    PlaneRequestCtx {
        key: credential.map(|c| {
            Arc::new(VirtualKey {
                id: c.to_string(),
                ..Default::default()
            })
        }),
    }
}

/// **THE CALLER IS RESOLVED PER ARRIVAL, not once at boot.**
///
/// The property a struct with a baked-in governance context could not have, and the one a global
/// could not have either: two callers on ONE sealed source resolve to two different keys. A source
/// that answered the first caller's identity to the second is the failure this shape exists against,
/// and it is a failure that serves traffic and bills the wrong principal for it.
#[test]
fn two_callers_on_one_sealed_source_resolve_to_two_governance_contexts() {
    let source = BootIngress::new(minted(a_host()), ctx_for);

    let (first, second, none) = (
        source.arrival(Some("Bearer sk-one")),
        source.arrival(Some("Bearer sk-two")),
        source.arrival(None),
    );
    let (first, second, none) = (payload(&first), payload(&second), payload(&none));

    assert_eq!(
        first.gov.key.as_ref().map(|k| k.id.clone()),
        Some("Bearer sk-one".to_string())
    );
    assert_eq!(
        second.gov.key.as_ref().map(|k| k.id.clone()),
        Some("Bearer sk-two".to_string()),
        "the second caller is the second caller"
    );
    assert!(
        none.gov.key.is_none(),
        "and an arrival that presented nothing resolves to nothing"
    );
}

/// **THE HOST IS THE DEPLOYMENT'S**, and every arrival on one mount reaches the same one.
///
/// The other half of the split. A source that minted a host per request would be composing a second
/// engine for every caller; a source that resolved a caller once would be answering every caller
/// with the first one's identity. This is the pair asserted together, because separately either one
/// reads as an implementation detail.
#[test]
fn every_arrival_on_one_mount_reaches_the_one_host_the_boot_sealed() {
    let host = a_host();
    let source = BootIngress::new(minted(Arc::clone(&host)), ctx_for);

    let (first, second) = (
        source.arrival(Some("Bearer sk-one")),
        source.arrival(Some("Bearer sk-two")),
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
#[test]
fn the_caller_token_is_the_secret_the_driven_path_carries() {
    let source = BootIngress::new(minted(a_host()), |_| PlaneRequestCtx { key: None });
    let token =
        |credential: Option<&str>| payload(&source.arrival(credential)).caller_token.clone();

    assert_eq!(token(Some("Bearer sk-live")).as_deref(), Some("sk-live"));
    // A bare secret is what a vendor SDK writing its own key header sends, and it is the whole
    // value: there is no scheme word to drop.
    assert_eq!(token(Some("sk-live")).as_deref(), Some("sk-live"));
    // The scheme word is not matched against a list — which alternatives a plane accepts is the
    // authentication chain's answer, and a list here would be a second one that could drift.
    assert_eq!(token(Some("ApiKey sk-live")).as_deref(), Some("sk-live"));
    // Presented nothing, and presented a blank, are two different statements and only one of them
    // is a caller.
    assert_eq!(token(None), None);
    assert_eq!(token(Some("Bearer   ")), None);
    assert_eq!(token(Some("   ")), None);
}
