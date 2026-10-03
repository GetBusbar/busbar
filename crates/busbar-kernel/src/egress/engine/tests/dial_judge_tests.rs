// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAL JUDGE on the pooled posture: a name is resolved once per new connection, every address
//! it answered with is judged by the destination guard (OWNER ruling DESTINATION GUARD; here its
//! test double, `fixtures::PrivateRefusing`) before any socket opens, and the connection that does
//! open keeps the name for SNI, the certificate check and `Host`.
//!
//! The rows: a rebinding answer (an admitted address first, a metadata address on the next fresh
//! dial) is refused at the second dial with no connect attempted; a mixed answer is refused whole;
//! a loopback answer is refused unless the allowlist names it, and allowlisted it dials and pools;
//! a refusal is a connect-class failure with no timeout in its chain; and a judged TLS dial
//! presents the configured name as SNI and `Host`, byte-identical to the head the pinned posture
//! sends.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::{
    ca_and_leaf, certs_from_pem, private_refusing, spawn_http, spawn_tls, CannedResponse,
    ClientAuth, RebindingResolver, TlsServerSpec,
};
use crate::host_services::{DestJudge, DestRefusal};
use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_METADATA};

/// The AWS/GCP instance-metadata address: what a rebinding name answers with on its second lookup.
const IMDS: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));

/// A pooled client whose names resolve through `names` and are judged by `judge`.
fn judged_client(names: Arc<dyn ResolveNames>, judge: Arc<dyn DestJudge>) -> EngineClient {
    let spec = EngineSpec {
        dns: Dns::Custom(names),
        judge: Some(judge),
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    build_client(&spec).expect("the pooled posture builds")
}

fn get(url: &str) -> http::Request<http_body_util::Full<Bytes>> {
    egress_request(
        url.parse().expect("uri"),
        http::HeaderMap::new(),
        Bytes::new(),
    )
}

/// The refusal the destination guard raised, found in an error's source chain.
fn dial_refusal<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a DestRefusal> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(refused) = e.downcast_ref::<DestRefusal>() {
            return Some(refused);
        }
        cur = e.source();
    }
    None
}

/// A scripted answer list for one name.
struct Answers(Vec<SocketAddr>);

impl ResolveNames for Answers {
    fn resolve(
        &self,
        _name: &str,
    ) -> futures::future::BoxFuture<
        'static,
        Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        Box::pin(std::future::ready(Ok(self.0.clone())))
    }
}

/// THE REBINDING ROW. The name answers the fixture's loopback address first, and the dial goes
/// through; the fixture closes that connection, so the next request needs a fresh dial, and this
/// time the name answers the metadata address. That dial is refused before any socket opens: the
/// fixture saw exactly one connection, and the resolver was asked exactly twice.
#[tokio::test]
async fn a_rebinding_answer_is_refused_at_the_next_dial() {
    let fixture = spawn_http(CannedResponse::ok("first answer"), 1);
    let rebinding = Arc::new(RebindingResolver::new(
        fixture.addr,
        SocketAddr::new(IMDS, fixture.addr.port()),
    ));
    let client = judged_client(
        Arc::clone(&rebinding) as Arc<dyn ResolveNames>,
        private_refusing(&["127.0.0.1"]),
    );
    let url = format!("http://rebind.test:{}/v1/x", fixture.addr.port());

    let first = client.request(get(&url)).await.expect("the first dial");
    assert_eq!(first.status(), 200);
    drop(first);
    // Let the fixture's close land, so the next request dials afresh rather than racing it.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let err = client
        .request(get(&url))
        .await
        .expect_err("the rebound answer must be refused");
    assert!(err.is_connect(), "a refused dial is connect class: {err:?}");
    let refused = dial_refusal(&err).expect("the guard's refusal is in the chain");
    assert_eq!(refused.verdict, DEST_METADATA);
    assert!(refused.reason.contains("rebind.test"), "{refused}");
    assert_eq!(rebinding.calls(), 2, "one resolution per fresh dial");
    assert_eq!(
        fixture.records().len(),
        1,
        "the refused dial opened no connection"
    );
}

/// A MIXED ANSWER is refused whole: a reachable loopback address beside a metadata one does not
/// let the dial pick the good one.
#[tokio::test]
async fn a_mixed_answer_is_refused_whole() {
    let fixture = spawn_http(CannedResponse::ok("never served"), 4);
    let client = judged_client(
        Arc::new(Answers(vec![fixture.addr, SocketAddr::new(IMDS, 0)])),
        private_refusing(&["127.0.0.1"]),
    );
    let err = client
        .request(get(&format!(
            "http://mixed.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect_err("a mixed answer must be refused");
    assert!(
        dial_refusal(&err).is_some(),
        "refused by the table: {err:?}"
    );
    assert!(fixture.records().is_empty(), "no connection was opened");
}

/// RED (the destination guard): a name answering loopback is refused at the dial unless the
/// allowlist names it; no socket opens.
#[tokio::test]
async fn a_loopback_answer_is_refused_unless_allowlisted() {
    let fixture = spawn_http(CannedResponse::ok("never served"), 4);
    let client = judged_client(Arc::new(Answers(vec![fixture.addr])), private_refusing(&[]));
    let err = client
        .request(get(&format!(
            "http://local-model.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect_err("a loopback answer is refused by default");
    assert!(err.is_connect(), "{err:?}");
    assert_eq!(dial_refusal(&err).map(|r| r.verdict), Some(DEST_INTERNAL));
    assert!(fixture.records().is_empty(), "no connection was opened");
}

/// GREEN: allowlisted, a name answering loopback is served, and its connection is pooled and
/// reused like any other.
#[tokio::test]
async fn an_allowlisted_loopback_answer_dials_and_pools() {
    let fixture = spawn_http(CannedResponse::ok("local model"), 4);
    let counting = Arc::new(RebindingResolver::counting(fixture.addr));
    let client = judged_client(
        Arc::clone(&counting) as Arc<dyn ResolveNames>,
        private_refusing(&["local-model.test"]),
    );
    let url = format!("http://local-model.test:{}/v1/x", fixture.addr.port());
    for _ in 0..2 {
        let resp = client.request(get(&url)).await.expect("loopback dials");
        assert_eq!(resp.status(), 200);
        let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
    }
    assert_eq!(
        counting.calls(),
        1,
        "the second request reused the pooled connection"
    );
    assert_eq!(fixture.records().len(), 1);
    assert_eq!(fixture.records()[0].requests, 2);
}

/// THE CLASS A PLANE READS: a refused dial is a connect failure with no timeout anywhere in its
/// chain, so a plane classifies it as a refused connection (`connect`), never as a timeout.
#[tokio::test]
async fn a_refusal_is_connect_class_with_no_timeout_in_its_chain() {
    let client = judged_client(
        Arc::new(Answers(vec![SocketAddr::new(IMDS, 0)])),
        private_refusing(&[]),
    );
    let err = client
        .request(get("http://imds.test:80/latest"))
        .await
        .expect_err("refused");
    assert!(err.is_connect());
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(&err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            assert_ne!(
                io.kind(),
                std::io::ErrorKind::TimedOut,
                "no timeout in the chain"
            );
        }
        cur = e.source();
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let hop = send_bounded(&client, get("http://imds.test:80/latest"), deadline)
        .await
        .expect_err("refused");
    assert!(hop.is_connect(), "the seam's split reads it as connect");
}

/// THE NAME STAYS ON THE WIRE. A judged TLS dial connects to the address the name answered with
/// and presents the configured NAME: the ClientHello's SNI is the name, the certificate is
/// verified against it (the leaf is minted for the name only), and the request head carries it as
/// `Host`, byte-identical to the head the pinned posture sends for the same request.
#[tokio::test]
async fn a_judged_tls_dial_keeps_the_name_for_sni_and_host() {
    let material = ca_and_leaf(&["provider.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("named"),
        max_requests_per_connection: 4,
    });
    let url = format!("https://provider.test:{}/v1/x", fixture.addr.port());

    let judged = EngineSpec {
        dns: Dns::Custom(Arc::new(Answers(vec![fixture.addr]))),
        judge: Some(private_refusing(&["provider.test"])),
        trust: Trust::WebpkiPlus(certs_from_pem(&material.ca_pem)),
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    let client = build_client(&judged).expect("builds");
    let resp = client.request(get(&url)).await.expect("the named dial");
    assert_eq!(resp.status(), 200);
    let _ = http_body_util::BodyExt::collect(resp.into_body()).await;

    let pinned = EngineSpec::pinned(
        Arc::from("provider.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&material.ca_pem),
    );
    let client = build_client(&pinned).expect("builds");
    let resp = client.request(get(&url)).await.expect("the pinned dial");
    assert_eq!(resp.status(), 200);
    let _ = http_body_util::BodyExt::collect(resp.into_body()).await;

    let records = fixture.records_when(|r| r.len() == 2 && r.iter().all(|c| c.requests == 1));
    let judged_conn = &records[0];
    assert!(judged_conn.handshake_ok, "verified against the name");
    assert_eq!(judged_conn.sni.as_deref(), Some("provider.test"));
    let host_line = format!("host: provider.test:{}", fixture.addr.port());
    assert!(
        judged_conn.heads[0]
            .lines()
            .any(|l| l.eq_ignore_ascii_case(&host_line)),
        "Host is the name: {:?}",
        judged_conn.heads[0]
    );
    assert_eq!(
        judged_conn.heads, records[1].heads,
        "the judged head is the pinned head, byte for byte"
    );
    assert_eq!(judged_conn.sni, records[1].sni);
}

/// THE SEAM, FAIL CLOSED (ARCHITECT ruling (C)): a pooled client naming no judge of its own asks
/// the root-installed egress-trust seam; in a process that installed none (or the pass-through,
/// which has no guard behind it) a private or metadata answer is refused, never allowed, as a
/// connect failure, and no socket opens.
#[tokio::test]
async fn with_no_guard_installed_a_pooled_dial_fails_closed() {
    let fixture = spawn_http(CannedResponse::ok("never served"), 4);
    for answer in [fixture.addr, SocketAddr::new(IMDS, fixture.addr.port())] {
        let spec = EngineSpec {
            dns: Dns::Custom(Arc::new(Answers(vec![answer]))),
            judge: None,
            ..EngineSpec::pooled_webpki(4, 300, false, false)
        };
        let client = build_client(&spec).expect("builds");
        let err = client
            .request(get(&format!(
                "http://seam.test:{}/v1/x",
                fixture.addr.port()
            )))
            .await
            .expect_err("refused without a guard");
        assert!(err.is_connect(), "{err:?}");
        assert!(
            dial_refusal(&err).is_some(),
            "refused through the seam: {err:?}"
        );
    }
    assert!(fixture.records().is_empty(), "no connection was opened");
}
