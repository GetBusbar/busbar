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

#[tokio::test]
async fn native_judge_keeps_its_own_listener_snapshot() {
    let guard = Guard::default();
    guard.publish_own(&[8080], &[]);
    let make = || Fixed {
        answer: Err("literal only".into()),
        lookups: Arc::default(),
    };
    let boot = Judge::new(guard.clone(), make());
    guard.publish_own(&[9090], &[]);
    let serving = Judge::new(guard, make());
    assert_eq!(
        boot.dial("127.0.0.1", 8080, OPS, OWNER).await,
        Err(NeedErr::Denied)
    );
    assert!(boot.dial("127.0.0.1", 9090, OPS, OWNER).await.is_ok());
    assert_eq!(
        serving.dial("127.0.0.1", 9090, OPS, OWNER).await,
        Err(NeedErr::Denied)
    );
    assert!(serving.dial("127.0.0.1", 8080, OPS, OWNER).await.is_ok());
}

#[tokio::test]
async fn proxy_dns_checks_available_answers_and_only_delegates_unresolved_names() {
    use busbar_kernel::config::tls::ProxyResolution;
    let proxy = crate::proxy::test_config("127.0.0.1", 3128, None, "direct.example");
    for answer in [
        Ok(vec!["10.0.0.7".parse().unwrap()]),
        Err("no local answer".into()),
        Ok(vec![]),
    ] {
        let denied = answer.as_ref().is_ok_and(|ips| !ips.is_empty());
        let resolver = Fixed {
            answer,
            lookups: Arc::default(),
        };
        let judge = Judge::with_proxy(
            Guard::default().freeze(),
            resolver,
            Some(proxy.clone()),
            ProxyResolution::Proxy,
        );
        let route = judge
            .plan("origin.example", 443, DEFAULT, false, true, OWNER)
            .await;
        if denied {
            assert!(matches!(route, Err(NeedErr::Denied)));
        } else {
            assert_eq!(route.unwrap().tunnel.unwrap().target, "origin.example:443");
        }
        assert!(
            judge
                .plan("direct.example", 443, DEFAULT, false, true, OWNER)
                .await
                .is_err(),
            "NO_PROXY still needs local address admission"
        );
    }
}

#[tokio::test]
async fn proxy_local_dns_pins_the_target_and_checks_proxy_own_node() {
    use busbar_kernel::config::tls::ProxyResolution;
    let proxy = crate::proxy::test_config("127.0.0.1", 3128, None, "");
    let resolver = || Fixed {
        answer: Ok(vec!["93.184.216.34".parse().unwrap()]),
        lookups: Arc::default(),
    };
    let guard = Guard::default();
    let judge = Judge::with_proxy(
        guard.freeze(),
        resolver(),
        Some(proxy.clone()),
        ProxyResolution::Local,
    );
    let route = judge
        .plan("origin.example", 443, DEFAULT, false, true, OWNER)
        .await
        .expect("public target through configured proxy");
    assert_eq!(route.addrs, ["127.0.0.1:3128".parse().unwrap()]);
    assert_eq!(route.tunnel.unwrap().target, "93.184.216.34:443");
    guard.publish_own(&[3128], &[]);
    let judge = Judge::with_proxy(
        guard.freeze(),
        resolver(),
        Some(proxy),
        ProxyResolution::Local,
    );
    assert!(matches!(
        judge
            .plan("origin.example", 443, DEFAULT, false, true, OWNER)
            .await,
        Err(NeedErr::Denied)
    ));
}

/// The deployment the root composes the new interface's guard from: the data door on the wildcard
/// address (the shipped default's shape, `0.0.0.0:8080`), the admin surface on one configured
/// address.
fn own_doors_deployment(block_private: bool) -> busbar_kernel::config::RootCfg {
    let deploy: busbar_kernel::config::DeployCfg = busbar_contract::yaml::from_str(&format!(
        "providers: {{}}\nmodels: {{}}\nlisten: \"0.0.0.0:18080\"\n\
         admin_listen: \"10.20.30.40:18081\"\nadmin_require_mtls: false\n\
         advanced: {{block_private_addresses: {block_private}}}\n"
    ))
    .expect("the deployment parses");
    busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .unwrap_or_else(|errors| panic!("the deployment resolves: {errors:?}"))
}

/// A Need judge over the guard exactly as the root builds one for the new interface: the
/// deployment's `destinations()`, the one destination judge built from them
/// (`root::connector::dest_judge`), its guard frozen into a stage's network inputs
/// (`root::min3_boot::network_inputs`), every name answered with `answer`.
fn composed_judge(
    cfg: &busbar_kernel::config::RootCfg,
    answer: &str,
    seen: &Arc<crate::need::observations::Observations>,
) -> Judge<Fixed> {
    let dest = crate::process::dest_judge(&cfg.destinations()).expect("the guard builds");
    Judge::observed(
        dest.guard().freeze(),
        Fixed {
            answer: Ok(vec![answer.parse().unwrap()]),
            lookups: Arc::default(),
        },
        None,
        busbar_kernel::config::tls::ProxyResolution::Local,
        Arc::clone(seen),
    )
}

/// IF 12.1, on the new interface as the root composes it: a Need aimed at the engine's own data
/// port or its own admin port is refused `DEST_INTERNAL`, in every class, whatever else the
/// deployment lets that class reach: on loopback, on the unspecified address (the data door is
/// bound to the wildcard), on the address the admin listener is configured on, in an IPv4-mapped
/// spelling, and by a name that resolves to one of those. The same addresses on a port the engine
/// does not listen on stay reachable, so the refusal is this rule's and no other's.
#[tokio::test]
async fn a_need_never_reaches_the_engines_own_ports_as_the_root_composes_the_guard() {
    use crate::need::observations::Outcome;
    use busbar_contract::conn::codes::{
        EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_PROVIDER,
    };
    use busbar_contract::services::codes::DEST_INTERNAL;
    const DATA: u16 = 18080;
    const ADMIN: u16 = 18081;
    const ELSEWHERE: u16 = 18082;
    // (the target as the Need names it, the address its name answers with)
    let data_door: &[(&str, &str)] = &[
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("0.0.0.0", "0.0.0.0"),
        ("::", "::"),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1"),
        ("front.example", "127.0.0.1"),
    ];
    let admin_door: &[(&str, &str)] = &[
        ("10.20.30.40", "10.20.30.40"),
        ("::ffff:10.20.30.40", "::ffff:10.20.30.40"),
        ("127.0.0.1", "127.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("admin.example", "10.20.30.40"),
    ];
    let every_class = [
        EGRESS_DEFAULT,
        EGRESS_PROVIDER,
        EGRESS_OPERATOR_INFRASTRUCTURE,
        EGRESS_OPEN_WEB,
        EGRESS_LOOPBACK_ALLOWED,
    ];
    // A deployment that allows private addresses lets every class reach these addresses; the
    // shipped default still lets the operator-infrastructure class reach them.
    let deployments = [
        (own_doors_deployment(false), &every_class[..]),
        (
            own_doors_deployment(true),
            &[EGRESS_OPERATOR_INFRASTRUCTURE][..],
        ),
    ];
    let mut judged = 0usize;
    for (cfg, classes) in &deployments {
        for &class in *classes {
            for (port, targets) in [(DATA, data_door), (ADMIN, admin_door)] {
                for &(target, answer) in targets {
                    let seen = Arc::default();
                    let judge = composed_judge(cfg, answer, &seen);
                    assert!(
                        judge.dial(target, ELSEWHERE, class, OWNER).await.is_ok(),
                        "class {class}: {target}:{ELSEWHERE} is not one of the engine's ports and \
                         this deployment lets the class reach it"
                    );
                    assert_eq!(
                        judge.dial(target, port, class, OWNER).await,
                        Err(NeedErr::Denied),
                        "class {class}: a Need reached the engine's own port {target}:{port}"
                    );
                    let facts = seen.drain().facts;
                    assert_eq!(
                        facts.iter().map(|f| f.outcome).collect::<Vec<_>>(),
                        [Outcome::Denied(DEST_INTERNAL)],
                        "class {class}: {target}:{port} is refused by the own-port rule"
                    );
                    judged += 1;
                }
            }
        }
    }
    assert_eq!(judged, (5 + 1) * (6 + 5));
}
