// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Need judge: name, answer and own-port judgement in order, on a counting resolver.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;
use crate::guard::Resolved;

const DEFAULT: u32 = 0;
const OPS: u32 = 2;
const OWNER: (u64, u32) = (1, 0);

/// Answers every name with a fixed result and counts the lookups.
struct Fixed {
    answer: Result<Vec<IpAddr>, String>,
    lookups: Arc<AtomicUsize>,
}

impl Resolve for Fixed {
    fn resolve(&self, _host: &str, done: Resolved) {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        done(self.answer.clone());
    }
}

fn judge(answer: Result<Vec<&str>, &str>) -> (Judge<Fixed>, Arc<AtomicUsize>) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let g = Guard::default();
    g.publish_own(&[8080], &[]);
    let answer = answer
        .map(|v| v.into_iter().map(|a| a.parse().unwrap()).collect())
        .map_err(str::to_owned);
    (
        Judge::new(
            g,
            Fixed {
                answer,
                lookups: Arc::clone(&lookups),
            },
        ),
        lookups,
    )
}

/// A public name resolves, is judged and comes back as socket addresses in answer order.
#[tokio::test]
async fn a_public_name_is_resolved_and_judged() {
    let (j, n) = judge(Ok(vec!["93.184.216.34", "2606:2800:220:1::1"]));
    let at = j.dial("db.example", 5432, DEFAULT, OWNER).await.unwrap();
    assert_eq!(
        at,
        [
            "93.184.216.34:5432".parse().unwrap(),
            "[2606:2800:220:1::1]:5432".parse().unwrap()
        ]
    );
    assert_eq!(n.load(Ordering::SeqCst), 1);
}

/// A literal address is judged by the name arm and never resolved.
#[tokio::test]
async fn a_literal_never_reaches_the_resolver() {
    let (j, n) = judge(Err("must not be asked"));
    assert_eq!(
        j.dial("93.184.216.34", 443, DEFAULT, OWNER)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        j.dial("10.0.0.1", 443, DEFAULT, OWNER).await,
        Err(NeedErr::Denied)
    );
    assert_eq!(
        j.dial("169.254.169.254", 80, OPS, OWNER).await,
        Err(NeedErr::Denied)
    );
    assert_eq!(n.load(Ordering::SeqCst), 0);
}

/// A name that answers a private address is refused in the default class; and one bad address
/// among good ones refuses the whole dial.
#[tokio::test]
async fn one_refused_answer_refuses_the_dial() {
    let (j, _) = judge(Ok(vec!["93.184.216.34", "10.0.0.7"]));
    assert_eq!(
        j.dial("db.example", 5432, DEFAULT, OWNER).await,
        Err(NeedErr::Denied)
    );
    let (j, _) = judge(Ok(vec!["10.0.0.7"]));
    assert!(
        j.dial("db.example", 5432, OPS, OWNER).await.is_ok(),
        "operator infrastructure reaches private space"
    );
}

/// The node's own ports are refused in every class, on an address that was admitted: this is the
/// plugin that dials core's own front door.
#[tokio::test]
async fn the_nodes_own_port_is_refused_in_every_class() {
    for class in 0..=4 {
        let (j, _) = judge(Ok(vec!["127.0.0.1"]));
        assert_eq!(
            j.dial("self.example", 8080, class, OWNER).await,
            Err(NeedErr::Denied),
            "{class}"
        );
    }
    let (j, _) = judge(Ok(vec!["127.0.0.1"]));
    assert!(
        j.dial("self.example", 8081, 4, OWNER).await.is_ok(),
        "another port on loopback in the loopback class"
    );
}

/// A failed lookup is Unavailable, a lookup the resolver drops is too.
#[tokio::test]
async fn a_failed_lookup_is_unavailable() {
    let (j, _) = judge(Err("nxdomain"));
    assert_eq!(
        j.dial("nx.example", 1, DEFAULT, OWNER).await,
        Err(NeedErr::Unavailable)
    );
    let (j, _) = judge(Ok(vec![]));
    assert_eq!(
        j.dial("empty.example", 1, DEFAULT, OWNER).await,
        Err(NeedErr::Denied),
        "no addresses is a refusal"
    );
}

#[test]
fn a_dest_splits_into_host_and_port() {
    assert_eq!(split_dest("db:5432"), Ok(("db", 5432)));
    assert_eq!(split_dest("[::1]:6379"), Ok(("::1", 6379)));
    for bad in ["db", "db:", "db:70000", ":80", "[]:80", "db:x"] {
        assert_eq!(split_dest(bad), Err(NeedErr::Invalid), "{bad}");
    }
}

#[test]
fn a_url_splits_into_host_and_port_with_the_scheme_default() {
    assert_eq!(
        split_url("https://idp.example/jwks"),
        Ok(("idp.example".to_owned(), 443))
    );
    assert_eq!(split_url("http://[::1]:9/x"), Ok(("::1".to_owned(), 9)));
    for bad in ["ftp://h/", "nope", "https:///x"] {
        assert_eq!(split_url(bad), Err(NeedErr::Invalid), "{bad}");
    }
}
