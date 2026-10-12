// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TUNNELLED TARGET IS JUDGED (K3 #5, ARCHITECT ruling): a CONNECT proxy connects to the target
//! itself, so the target is judged before the proxy is asked anything. The guard's name arm always
//! runs (a literal as its own answer); a name that resolves here has its whole answer judged and a
//! refused answer is never tunnelled to; a name that does not resolve here goes to the proxy after
//! the name arm (reach behind the proxy is the proxy's boundary).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::private_refusing;

/// A resolver with one scripted answer for every name; `None` answers an error (the name does not
/// resolve here).
struct Scripted(Option<Vec<SocketAddr>>);

impl ResolveNames for Scripted {
    fn resolve(
        &self,
        name: &str,
    ) -> futures::future::BoxFuture<
        'static,
        Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        let answer = self
            .0
            .clone()
            .ok_or_else(|| format!("`{name}` does not resolve here").into());
        Box::pin(std::future::ready(answer))
    }
}

/// A scripted CONNECT proxy on loopback: it records every CONNECT head it is sent, answers 200, then
/// serves one plain `200 ok` on the tunnel itself.
async fn scripted_proxy() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 512];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _ = sock
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let mut req = Vec::new();
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, seen)
}

/// A client tunnelling every target through the proxy at `proxy`, judged by the refusing guard
/// double (nothing allowlisted) over `names`.
fn tunnelled_client(
    proxy: SocketAddr,
    names: Option<Vec<SocketAddr>>,
) -> hyper_util::client::legacy::Client<
    super::https::HttpsConnector<tunnel::TunnelConnector>,
    Full<Bytes>,
> {
    let config = tunnel::test_config(&proxy.ip().to_string(), proxy.port(), None, "");
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(
        EgressResolver::system(),
    );
    http.enforce_http(false);
    let posture = tunnel::DialPosture::Judged {
        judge: Some(private_refusing(&[])),
        names: EgressResolver::Custom(Arc::new(Scripted(names))),
    };
    let connector = tunnel::TunnelConnector::new(
        http,
        Some(config),
        tunnel::connects_per_shard_for_tests(),
        posture,
    );
    let https = super::https::HttpsConnector::new(
        connector,
        super::client_tls(&EngineSpec::pooled_webpki(4, 300, true, false), &[])
            .expect("the pooled tls posture builds"),
    );
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

fn get(url: &str) -> http::Request<Full<Bytes>> {
    egress_request(url.parse().unwrap(), http::HeaderMap::new(), Bytes::new())
}

/// RED (K3 #5): a private LITERAL target is refused before the proxy is dialled; the proxy is never
/// sent a CONNECT for it. Before, the tunnel judged only the proxy and CONNECTed to any target.
#[tokio::test]
async fn a_private_literal_target_is_never_tunnelled_to() {
    let (proxy, seen) = scripted_proxy().await;
    let client = tunnelled_client(proxy, None);
    client
        .request(get("http://10.1.2.3:8080/v1/x"))
        .await
        .expect_err("a private literal target is refused");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no CONNECT reached the proxy: {:?}",
        seen.lock().unwrap()
    );
}

/// RED (K3 #5): a NAME that resolves here to a private answer is refused before the proxy is
/// dialled.
#[tokio::test]
async fn a_name_resolving_here_to_a_private_answer_is_never_tunnelled_to() {
    let (proxy, seen) = scripted_proxy().await;
    let client = tunnelled_client(
        proxy,
        Some(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            0,
        )]),
    );
    client
        .request(get("http://internal.test:8080/v1/x"))
        .await
        .expect_err("a private answer is refused");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no CONNECT reached the proxy: {:?}",
        seen.lock().unwrap()
    );
}

/// GREEN (the ruled boundary): a name that does NOT resolve here still tunnels, after the name arm;
/// the proxy resolves it, as 1.5.5's proxied deployments did.
#[tokio::test]
async fn a_name_that_does_not_resolve_here_still_tunnels() {
    let (proxy, seen) = scripted_proxy().await;
    let client = tunnelled_client(proxy, None);
    let resp = client
        .request(get("http://upstream.test:8080/v1/x"))
        .await
        .expect("an unresolvable name tunnels");
    assert_eq!(resp.status(), 200);
    let heads = seen.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].starts_with("CONNECT upstream.test:8080 HTTP/1.1\r\n"),
        "{heads:?}"
    );
}

/// GREEN: a name that resolves here to a public answer tunnels.
#[tokio::test]
async fn a_name_resolving_here_to_a_public_answer_tunnels() {
    let (proxy, seen) = scripted_proxy().await;
    let client = tunnelled_client(
        proxy,
        Some(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
            0,
        )]),
    );
    let resp = client
        .request(get("http://public.test:8080/v1/x"))
        .await
        .expect("a public answer tunnels");
    assert_eq!(resp.status(), 200);
    assert_eq!(seen.lock().unwrap().len(), 1);
}
