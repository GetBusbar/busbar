// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS POSTURES, as the engine builds them. The handshake itself is the connector's, which this
//! crate cannot name, so the postures are driven through `build_client` over the TLS test double
//! (`egress::fixtures::TlsDouble`): what each posture HANDS the wrap — the ALPN offer 1.5.5's hello
//! carried, the extra roots joining the webpki store, the identity presented only when one was built
//! in — and that a peer demanding an identity refuses a hop that carried none. The identity's key is
//! wiped on the last handle's drop. The same postures over the REAL wrap — the R4 parity corpus of
//! the identity PEM walk against `reqwest::Identity::from_pem`, the mutual handshake recording the
//! engine identity's leaf, the private CA accepted only with its extra root, the garbage root
//! failing the build — are the connector's `tls/engine_tests.rs`.

use std::sync::Arc;

use http_body_util::BodyExt;

use super::*;
use crate::egress::fixtures::{
    ca_and_leaf, spawn_double, CaLeaf, CannedResponse, DoublePeer, TlsDouble,
};
use crate::secure::KeyDer;

/// An identity built from a fixture's parts: its leaf and that leaf's PKCS#8 key.
fn parts(material: &CaLeaf) -> ClientIdentity {
    ClientIdentity::from_parts(
        vec![material.leaf_der.clone()],
        KeyDer::Pkcs8(material.leaf_key_der.clone()),
    )
}

fn hop(host: &str, port: u16) -> http::Request<Full<Bytes>> {
    egress_request(
        format!("https://{host}:{port}/v1/x").parse().expect("uri"),
        http::HeaderMap::new(),
        Bytes::new(),
    )
}

/// A SUPERSEDED IDENTITY'S PRIVATE KEY MUST NOT BE FREED INTACT.
///
/// The key's DER is an ordinary `Vec<u8>`, and its drop glue is an ordinary deallocation, so without an `impl Drop` here the key DER is handed back to
/// the allocator byte-for-byte. The drop is on a live path — `plane_host::identity::register`
/// retains `MAX_RETAINED_IDENTITIES` identities and evicts the oldest FIFO, and the evicted
/// `ClientIdentity` drops right there — so a long-lived node that rotates its mTLS client
/// certificate accumulates one intact client key in freed heap per eviction.
///
/// HOW THIS IS MADE SOUND. Reading a value after its own `Drop` has run is a read of freed memory,
/// so this test does not do that. It proves the two halves separately, both in safe Rust:
///
/// 1. **That the wipe wipes** — observably. `Drop` delegates to `ClientIdentity::wipe`; the test
///    calls exactly what `drop` calls and then reads the key back out of a LIVE identity through
///    the same `key()` accessor the client build uses. `Zeroize for Vec<u8>` overwrites the
///    elements, drops the length to zero and then zeroes the spare capacity, so a wiped key reads
///    back EMPTY — the key material is not merely absent from the answer, there is no answer left.
/// 2. **That `Drop` is wired to it** — by source review, the technique this tree already uses for
///    guarantees that cannot be observed at runtime.
///
/// The key is a real rcgen-minted fixture, so what is asserted absent is the actual DER the parser
/// produced rather than a marker the test could have arranged to find.
#[test]
fn the_drop_path_wipes_the_private_key() {
    // (2) The wiring.
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/egress/engine/tls.rs"
    ));
    let drop_fn = src
        .split("impl Drop for ClientIdentity {")
        .nth(1)
        .expect(
            "ClientIdentity must have a Drop impl in src/egress/engine/tls.rs — without one an \
             evicted identity's private key goes back to the allocator intact",
        )
        .split("\n}")
        .next()
        .expect("the Drop impl must close");
    assert!(
        drop_fn.contains("self.wipe()"),
        "Drop regressed to not wiping the key. Body was: {drop_fn}"
    );

    // (1) The wipe itself, observed on a live identity.
    let a = ca_and_leaf(&["wipe-on-drop.test"]);
    let mut identity = parts(&a);
    let der = identity.key().secret_der().to_vec();
    // Precondition: there really is key material to lose, or the absence assertion proves nothing.
    assert!(
        der.len() > 32,
        "precondition: the parsed identity holds a real private key"
    );
    let leaf_before = identity.leaf_der().to_vec();

    identity.wipe();

    assert!(
        identity.key().secret_der().is_empty(),
        "the private key must not survive the wipe the drop path performs"
    );
    // The certificate is what busbar PRESENTS — the peer already has it, and wiping it would cost
    // the diagnosis (which identity was this?) for no secrecy at all.
    assert_eq!(
        identity.leaf_der(),
        leaf_before.as_slice(),
        "the wipe touches the key and nothing else"
    );
}

/// ...AND IT FIRES AT THE LAST HANDLE, NOT AT EVERY ONE.
///
/// The whole point of the `Arc` is that one parsed identity is shared — `plane_host::identity`
/// hands out a clone per resolve, and the client build clones again. A wipe that fired on every
/// handle's drop would blank a key another hop is about to hand to the TLS stack, turning a memory-hygiene
/// fix into a handshake failure. `Arc::get_mut` is what makes the wipe fire only when this handle
/// is the last one.
///
/// The first half of this test is a CHARACTERISATION: with an `Arc<KeyDer>` and no `unsafe`,
/// blanking a key another handle still holds is not expressible at all — `Arc::get_mut` is the only
/// safe door to `&mut` and it refuses while the count is above one — so the guard is structural and
/// no safe perturbation can make that assertion fail. The second half is the one that carries the
/// canary: once the other handle is gone, the wipe MUST fire, and a `wipe` that stopped overwriting
/// turns it red.
#[test]
fn the_wipe_waits_for_the_last_handle_and_then_fires() {
    let a = ca_and_leaf(&["shared-identity.test"]);
    let mut first = parts(&a);
    let mut still_in_the_registry = first.clone();
    let der = still_in_the_registry.key().secret_der().to_vec();
    assert!(der.len() > 32, "precondition: a real key is being shared");

    first.wipe();

    assert_eq!(
        still_in_the_registry.key().secret_der(),
        der.as_slice(),
        "a handle that is not the last one must leave the shared key exactly where it is"
    );

    // The other handle goes away — now this one IS the last, and the wipe is owed.
    drop(first);
    still_in_the_registry.wipe();

    assert!(
        still_in_the_registry.key().secret_der().is_empty(),
        "once it is the last handle the wipe must fire, or an evicted identity's key still \
         reaches the allocator intact"
    );
}

/// The mutual posture through the REAL pinned build: `EngineSpec::pinned` with an identity hands the
/// wrap exactly that identity's leaf, and the peer that demands one answers; the response carries
/// the peer's observed key pin (the pinned posture observes by construction). Without the identity
/// the wrap is handed none, and the demanding peer refuses — busbar presents nothing rather than
/// forging something.
#[tokio::test]
async fn the_pinned_posture_presents_its_identity_and_a_demanding_peer_refuses_without_one() {
    let server = ca_and_leaf(&["mtls.test"]);
    let client_material = ca_and_leaf(&["engine.busbar.test"]);
    let fixture = spawn_double(
        DoublePeer {
            leaf: Some(server.leaf_der.clone()),
            require_identity: true,
            ..DoublePeer::default()
        },
        CannedResponse::ok("mutual"),
        4,
    );
    let tls = TlsDouble::default();
    let spec = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        Some(parts(&client_material)),
        vec![server.ca_pem.clone().into_bytes()],
    );
    let client = build_client(&EngineSpec {
        tls: Some(tls.layer()),
        ..spec
    })
    .expect("the pinned mTLS posture builds");
    let resp = client
        .request(hop("mtls.test", fixture.addr.port()))
        .await
        .expect("the mutual handshake completes");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        peer_key_pin(&resp),
        Some(crate::egress::fixtures::double_pin(&server.leaf_der).as_str()),
        "the pinned posture observes the peer by construction"
    );
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"mutual");
    let records = fixture.records_when(|r| r.first().is_some_and(|c| c.client_cert.is_some()));
    assert_eq!(
        records[0].client_cert.as_deref(),
        Some(client_material.leaf_der.as_slice()),
        "the peer must have seen exactly the engine identity's leaf"
    );

    let without = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        None,
        vec![server.ca_pem.clone().into_bytes()],
    );
    let client = build_client(&EngineSpec {
        tls: Some(tls.layer()),
        ..without
    })
    .expect("the identityless posture still builds");
    let refused = client.request(hop("mtls.test", fixture.addr.port())).await;
    assert!(
        refused.is_err(),
        "a peer demanding an identity must refuse a hop that carried none"
    );
    let hellos = tls.hellos();
    assert_eq!(
        hellos.last().map(|h| h.identity_leaf.clone()),
        Some(None),
        "the identityless posture hands the wrap no identity"
    );
}

/// 1.5.5's ClientHello offered ALPN `http/1.1` under the http1-only key, and `h2, http/1.1`
/// otherwise; the engine states the offer it hands the wrap (hyper-rustls left the http1-only offer
/// EMPTY). The peer agrees only `http/1.1`, so what it agrees tells the offer reached it.
#[tokio::test]
async fn the_http1_only_posture_offers_http_1_1_as_1_5_5_did() {
    for http1_only in [true, false] {
        let server = ca_and_leaf(&["alpn.test"]);
        let fixture = spawn_double(
            DoublePeer {
                leaf: Some(server.leaf_der.clone()),
                alpn: vec![b"http/1.1".to_vec()],
                ..DoublePeer::default()
            },
            CannedResponse::ok("alpn"),
            1,
        );
        let tls = TlsDouble::default();
        let mut spec =
            EngineSpec::pinned(Arc::from("alpn.test"), fixture.addr.ip(), None, Vec::new());
        spec.http1_only = http1_only;
        let client = build_client(&EngineSpec {
            tls: Some(tls.layer()),
            ..spec
        })
        .expect("the posture builds");
        let resp = client
            .request(hop("alpn.test", fixture.addr.port()))
            .await
            .expect("the handshake completes");
        assert_eq!(resp.status(), 200);
        let expected: Vec<Vec<u8>> = if http1_only {
            vec![b"http/1.1".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
        assert_eq!(
            tls.hellos()[0].offer,
            expected,
            "http1_only = {http1_only}: the offer handed to the wrap"
        );
        let records = fixture.records_when(|r| r.first().is_some_and(|c| c.handshake_ok));
        assert_eq!(
            records[0].alpn.as_deref(),
            Some(&b"http/1.1"[..]),
            "http1_only = {http1_only}: the peer agreed http/1.1 off the offer"
        );
    }
}

/// The trust the postures hand the wrap: the pooled posture's webpki roots ALONE (`Trust::Webpki`,
/// the one shared store), and the pinned posture's extras JOINING them (`Trust::WebpkiPlus` — never
/// replacing them; the wrap adds them to the webpki store).
#[tokio::test]
async fn the_extras_join_the_webpki_roots_and_the_pooled_posture_carries_none() {
    let material = ca_and_leaf(&["private.test"]);
    let fixture = spawn_double(
        DoublePeer {
            leaf: Some(material.leaf_der.clone()),
            ..DoublePeer::default()
        },
        CannedResponse::ok("privately rooted"),
        4,
    );
    let tls = TlsDouble::default();
    let rooted = EngineSpec::pinned(
        Arc::from("private.test"),
        fixture.addr.ip(),
        None,
        vec![
            material.ca_pem.clone().into_bytes(),
            material.leaf_der.clone(),
        ],
    );
    let client = build_client(&EngineSpec {
        tls: Some(tls.layer()),
        ..rooted
    })
    .expect("the rooted posture builds");
    let resp = client
        .request(hop("private.test", fixture.addr.port()))
        .await
        .expect("the rooted hop answers");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        tls.hellos()[0].extra_roots,
        Some(2),
        "both extras reach the wrap"
    );

    let pooled = EngineSpec {
        dns: Dns::Custom(Arc::new(
            crate::egress::fixtures::RebindingResolver::counting(fixture.addr),
        )),
        judge: Some(crate::egress::fixtures::private_refusing(&["private.test"])),
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    let client = build_client(&EngineSpec {
        tls: Some(tls.layer()),
        ..pooled
    })
    .expect("the pooled posture builds");
    let resp = client
        .request(hop("private.test", fixture.addr.port()))
        .await
        .expect("the pooled hop answers");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        tls.hellos()[1].extra_roots,
        None,
        "the pooled posture hands the wrap the webpki roots alone"
    );
}
