// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pin-as-resolver contract: the pinned arm answers exactly one name (case-insensitively,
//! port 0) and refuses every other with the doctrine text BYTE-IDENTICAL to the reqwest-facing
//! `RefuseSecondLookup` — one shared source, asserted here so it can never drift. The
//! client-level half drives the REAL `build_client` wiring: under a pin the spec's `dns` arm is
//! structurally unreachable (zero calls on a live counting resolver across pooled requests), and
//! a request for a different name through a pinned client fails with the doctrine message.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper_util::client::legacy::connect::dns::Name;
use tower::Service;

use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::{spawn_http, CannedResponse};
use crate::egress::{refuse_second_lookup_message, with_cause, RefuseSecondLookup};

/// A scripted `ResolveNames` double: always the same address (with whatever PORT the test
/// chose), counting how often the engine asked.
struct Scripted {
    addr: SocketAddr,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Scripted {
            addr,
            calls: AtomicUsize::new(0),
        })
    }
}

impl ResolveNames for Scripted {
    fn resolve(
        &self,
        _name: &str,
    ) -> futures::future::BoxFuture<
        'static,
        Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let addr = self.addr;
        Box::pin(std::future::ready(Ok(vec![addr])))
    }
}

/// The pinned arm answers ITS name — case-insensitively, since DNS names are — with exactly one
/// address at PORT 0, the sentinel `HttpConnector` replaces with the destination URI's port.
#[tokio::test]
async fn the_pin_answers_only_its_host_at_port_zero() {
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mut resolver = EgressResolver::Pinned {
        host: Arc::from("pinned.test"),
        addr,
    };
    let answered: Vec<SocketAddr> = resolver
        .call(Name::from_str("PINNED.test").expect("a name"))
        .await
        .expect("the pinned name resolves")
        .collect();
    assert_eq!(answered, vec![SocketAddr::new(addr, 0)]);
}

/// Any OTHER name is refused with the doctrine message — and the text is byte-identical to what
/// the reqwest-facing [`RefuseSecondLookup`] produces for the same name, because both quote the
/// one shared source. This is the parity the migration's step-5 cutover leans on: a fixture that
/// asserted the reqwest resolver's refusal keeps passing against the engine's.
#[tokio::test]
async fn refusal_text_is_byte_identical_to_the_reqwest_resolver() {
    let mut resolver = EgressResolver::Pinned {
        host: Arc::from("pinned.test"),
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    let engine_err = resolver
        .call(Name::from_str("other.test").expect("a name"))
        .await
        .err()
        .expect("a second name must refuse")
        .to_string();

    let reqwest_err = reqwest::dns::Resolve::resolve(
        &RefuseSecondLookup,
        reqwest::dns::Name::from_str("other.test").expect("a name"),
    )
    .await
    .err()
    .expect("the reqwest resolver refuses every name")
    .to_string();

    assert_eq!(engine_err, reqwest_err, "one doctrine, one spelling");
    assert_eq!(engine_err, refuse_second_lookup_message("other.test"));
}

/// The `Custom` arm delegates to the caller's resolver — the seam the counting assertions ride.
#[tokio::test]
async fn the_custom_arm_delegates_and_is_countable() {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 443);
    let scripted = Scripted::new(target);
    let mut resolver = EgressResolver::Custom(Arc::clone(&scripted) as Arc<dyn ResolveNames>);
    let answered: Vec<SocketAddr> = resolver
        .call(Name::from_str("api.example.test").expect("a name"))
        .await
        .expect("the custom resolver answers")
        .collect();
    assert_eq!(answered, vec![target]);
    assert_eq!(scripted.calls.load(Ordering::SeqCst), 1);
}

/// THE CLIENT-LEVEL PROOF, through the real `build_client` wiring: a pinned spec never consults
/// the spec's `dns` arm (zero calls on a live counting resolver across two pooled requests), and
/// a request for a DIFFERENT name through the same client fails with the doctrine message in its
/// cause chain — the pin is one enum arm doing both jobs.
#[tokio::test]
async fn a_pinned_client_performs_zero_engine_lookups_and_refuses_other_names() {
    let fixture = spawn_http(CannedResponse::ok("pinned answer"), 4);
    let counting = Scripted::new(fixture.addr);
    let spec = EngineSpec {
        pin: Some(PinnedDest {
            host: Arc::from("pinned.test"),
            addr: fixture.addr.ip(),
        }),
        dns: Dns::Custom(Arc::clone(&counting) as Arc<dyn ResolveNames>),
        observe_spki: true,
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    let client = build_client(&spec).expect("a pinned client builds");

    for _ in 0..2 {
        let req = egress_request(
            format!("http://pinned.test:{}/v1/x", fixture.addr.port())
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            Bytes::new(),
        );
        let resp = client.request(req).await.expect("the pinned hop answers");
        assert_eq!(resp.status(), 200);
        // A plaintext hop under an observing posture is honestly absent, never a pass.
        assert_eq!(peer_spki(&resp), None);
        use http_body_util::BodyExt;
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&body[..], b"pinned answer");
    }
    assert_eq!(
        counting.calls.load(Ordering::SeqCst),
        0,
        "under a pin the dns arm must be structurally unreachable"
    );

    let other = egress_request(
        format!("http://other.test:{}/v1/x", fixture.addr.port())
            .parse()
            .expect("uri"),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    let err = client
        .request(other)
        .await
        .expect_err("a second name must refuse");
    assert!(err.is_connect(), "the refusal is connect-class");
    let rendered = with_cause(&err);
    assert!(
        rendered.contains("resolves each name exactly once"),
        "the refusal must carry the doctrine text: {rendered}"
    );
}
