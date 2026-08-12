// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADVERSARIAL TESTS FOR THE CARD FETCH.
//!
//! These are not coverage. Every one of them is a published SSRF technique aimed at the one module
//! on this plane that makes an outbound request at a stranger's direction, and the fixtures below
//! exist because none of them is reproducible against a real resolver: a rebinding answer, a mixed
//! answer and a second lookup that differs from the first are all facts about TIMING that no
//! integration test can arrange.
//!
//! The resolver fixture COUNTS ITS CALLS, because the assertion that matters most here is not that
//! a bad address is refused — it is that the second lookup an attacker needs in order to win never
//! happens at all.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;

use super::*;

const PUBLIC: [u8; 4] = [93, 184, 216, 34];
const PUBLIC_2: [u8; 4] = [93, 184, 216, 35];

fn ip(o: [u8; 4]) -> IpAddr {
    IpAddr::from(o)
}

/// A resolver that answers from a script and RECORDS every question it was asked.
///
/// `answers` maps a host to a QUEUE of answers: the first lookup gets the first entry, the second
/// the second, and the last entry repeats. That is what makes a rebinding upstream expressible —
/// one that is honest exactly once.
/// One scripted answer: the addresses a lookup returns, or the failure it returns instead.
type Answer = Result<Vec<IpAddr>, String>;

struct ScriptedResolver {
    answers: RefCell<HashMap<String, Vec<Answer>>>,
    asked: RefCell<Vec<String>>,
}

impl ScriptedResolver {
    fn new() -> Self {
        Self {
            answers: RefCell::new(HashMap::new()),
            asked: RefCell::new(Vec::new()),
        }
    }

    fn always(self, host: &str, addrs: Vec<IpAddr>) -> Self {
        self.answers
            .borrow_mut()
            .insert(host.to_string(), vec![Ok(addrs)]);
        self
    }

    /// A REBINDING upstream: honest on the first lookup, hostile on every one after it.
    fn then(self, host: &str, first: Vec<IpAddr>, rest: Vec<IpAddr>) -> Self {
        self.answers
            .borrow_mut()
            .insert(host.to_string(), vec![Ok(first), Ok(rest)]);
        self
    }

    fn failing(self, host: &str, err: &str) -> Self {
        self.answers
            .borrow_mut()
            .insert(host.to_string(), vec![Err(err.to_string())]);
        self
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.asked.borrow_mut().push(host.to_string());
        let mut answers = self.answers.borrow_mut();
        let queue: &mut Vec<Answer> = answers
            .get_mut(host)
            .unwrap_or_else(|| panic!("test resolver has no script for `{host}`"));
        if queue.len() > 1 {
            queue.remove(0)
        } else {
            queue[0].clone()
        }
    }
}

/// A transport that answers from a script keyed on the URL, and RECORDS the (url, pinned address)
/// pairs it was handed. The recording is the point: "the socket went to the address the guard
/// approved" is the property, and it is invisible from the return value.
struct ScriptedTransport {
    routes: RefCell<HashMap<String, HttpResponse>>,
    calls: RefCell<Vec<(String, IpAddr)>>,
}

impl ScriptedTransport {
    fn new() -> Self {
        Self {
            routes: RefCell::new(HashMap::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn ok(self, url: &str, body: &str) -> Self {
        self.routes.borrow_mut().insert(
            url.to_string(),
            HttpResponse {
                status: 200,
                location: None,
                body: body.as_bytes().to_vec(),
                peer_spki: None,
                client_identity_offered: false,
            },
        );
        self
    }

    fn redirect(self, url: &str, to: &str) -> Self {
        self.routes.borrow_mut().insert(
            url.to_string(),
            HttpResponse {
                status: 302,
                location: Some(to.to_string()),
                body: Vec::new(),
                peer_spki: None,
                client_identity_offered: false,
            },
        );
        self
    }

    fn status(self, url: &str, status: u16) -> Self {
        self.routes.borrow_mut().insert(
            url.to_string(),
            HttpResponse {
                status,
                location: None,
                body: Vec::new(),
                peer_spki: None,
                client_identity_offered: false,
            },
        );
        self
    }

    fn calls(&self) -> Vec<(String, IpAddr)> {
        self.calls.borrow().clone()
    }
}

impl Transport for ScriptedTransport {
    fn get(&self, url: &reqwest::Url, addr: IpAddr) -> Result<HttpResponse, String> {
        self.calls.borrow_mut().push((url.to_string(), addr));
        self.routes
            .borrow()
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| format!("test transport has no route for `{url}`"))
    }
}

fn card_body() -> &'static str {
    r#"{"protocolVersion":"0.3.0","name":"planner","skills":[{"id":"plan"}]}"#
}

// ══ THE PIN ITSELF ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a_public_host_resolves_once_and_is_pinned_to_the_address_that_was_judged() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new().ok(
        "https://a2a.vendor/.well-known/agent-card.json",
        card_body(),
    );

    let got = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect("a public host must fetch");

    assert_eq!(
        got.addr,
        ip(PUBLIC),
        "the fetch must be pinned to the judged address"
    );
    assert_eq!(
        t.calls(),
        vec![(
            "https://a2a.vendor/.well-known/agent-card.json".to_string(),
            ip(PUBLIC)
        )],
        "the transport must be handed the pinned address, not left to re-resolve"
    );
    assert_eq!(r.asked(), vec!["a2a.vendor"], "exactly one lookup per hop");
    assert_eq!(got.document["name"], "planner");
}

// ══ DNS REBINDING / TOCTOU ═══════════════════════════════════════════════════════════════════════

#[test]
fn a_host_that_resolves_differently_on_the_second_lookup_never_gets_a_second_lookup() {
    // THE TOCTOU CASE, stated as the design states it: the guard does not win the race, it removes
    // it. The upstream is honest once and answers the metadata endpoint forever after; if anything
    // in the fetch path resolved the name a second time, the socket would go to 169.254.169.254.
    let r = ScriptedResolver::new().then(
        "a2a.vendor",
        vec![ip(PUBLIC)],
        vec![ip([169, 254, 169, 254])],
    );
    let t = ScriptedTransport::new().ok(
        "https://a2a.vendor/.well-known/agent-card.json",
        card_body(),
    );

    let got = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect("the first, honest answer is the one that is used");

    assert_eq!(
        r.asked().len(),
        1,
        "a SECOND lookup is the whole attack; there must not be one"
    );
    assert_eq!(got.addr, ip(PUBLIC));
    assert!(
        t.calls().iter().all(|(_, a)| *a == ip(PUBLIC)),
        "every socket must go to the pinned address, got {:?}",
        t.calls()
    );
}

#[test]
fn a_rebinding_host_is_refused_outright_once_it_answers_the_metadata_address() {
    // Same upstream, but the pin happens on a hop where it has already flipped: the answer itself
    // is now internal, so there is nothing to pin and the fetch is refused.
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip([169, 254, 169, 254])]);
    let t = ScriptedTransport::new();

    let err = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect_err("a name answering link-local must be refused");

    assert_eq!(
        err,
        FetchRefusal::InternalAddress {
            host: "a2a.vendor".to_string(),
            addr: ip([169, 254, 169, 254]),
        }
    );
    assert!(
        t.calls().is_empty(),
        "nothing may be sent on a refused fetch"
    );
}

#[test]
fn a_mixed_answer_is_refused_whole_rather_than_filtered_to_the_public_address() {
    // The split-answer form of rebinding. Filtering would make the guard's verdict depend on the
    // ORDER the upstream chose to list its addresses in.
    for answer in [
        vec![ip(PUBLIC), ip([169, 254, 169, 254])],
        vec![ip([169, 254, 169, 254]), ip(PUBLIC)],
    ] {
        let r = ScriptedResolver::new().always("a2a.vendor", answer.clone());
        let err = resolve_and_pin(
            "https://a2a.vendor/.well-known/agent-card.json",
            &r,
            &FetchPolicy::default(),
        )
        .expect_err("a mixed answer must be refused whole");
        assert_eq!(
            err,
            FetchRefusal::InternalAddress {
                host: "a2a.vendor".to_string(),
                addr: ip([169, 254, 169, 254]),
            },
            "answer {answer:?} must be refused for its internal member"
        );
    }
}

// ══ REDIRECT CHAINS ══════════════════════════════════════════════════════════════════════════════

#[test]
fn a_redirect_to_the_cloud_metadata_address_is_refused_at_the_hop_that_names_it() {
    // The classic chain: a public, guarded, entirely legitimate first hop that then points the
    // guarded client at IMDS. Treating a redirect as a continuation of an approved fetch is exactly
    // how this succeeds.
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new().redirect(
        "https://a2a.vendor/.well-known/agent-card.json",
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
    );

    let err = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect_err("a redirect to IMDS must be refused");

    assert_eq!(
        err,
        FetchRefusal::InternalAddress {
            host: "169.254.169.254".to_string(),
            addr: ip([169, 254, 169, 254]),
        }
    );
    assert_eq!(
        t.calls().len(),
        1,
        "the metadata hop must never be sent; only the first hop was"
    );
}

#[test]
fn a_redirect_to_a_metadata_dns_name_is_refused_before_it_is_resolved() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new().redirect(
        "https://a2a.vendor/.well-known/agent-card.json",
        "https://metadata.google.internal/computeMetadata/v1/",
    );

    let err = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect_err("a redirect to a metadata NAME must be refused");

    assert!(
        matches!(err, FetchRefusal::InternalHostName { ref host, .. } if host == "metadata.google.internal"),
        "got {err:?}"
    );
    assert_eq!(
        r.asked(),
        vec!["a2a.vendor"],
        "a metadata name is refused structurally; the resolver is never asked about it"
    );
}

#[test]
fn a_redirect_to_a_name_that_resolves_internally_is_refused_on_the_answer() {
    // The redirect target is an ordinary-looking public NAME. Only resolving it and judging what
    // came back catches this one — a name-shaped denylist does not.
    let r = ScriptedResolver::new()
        .always("a2a.vendor", vec![ip(PUBLIC)])
        .always("cdn.partner", vec![ip([10, 0, 0, 7])]);
    let t = ScriptedTransport::new().redirect(
        "https://a2a.vendor/.well-known/agent-card.json",
        "https://cdn.partner/card.json",
    );

    let err = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect_err("a redirect target resolving into RFC1918 must be refused");

    assert_eq!(
        err,
        FetchRefusal::InternalAddress {
            host: "cdn.partner".to_string(),
            addr: ip([10, 0, 0, 7]),
        }
    );
}

#[test]
fn every_hop_of_a_legal_chain_is_resolved_and_pinned_separately() {
    let r = ScriptedResolver::new()
        .always("a2a.vendor", vec![ip(PUBLIC)])
        .always("cdn.partner", vec![ip(PUBLIC_2)]);
    let t = ScriptedTransport::new()
        .redirect(
            "https://a2a.vendor/.well-known/agent-card.json",
            "https://cdn.partner/card.json",
        )
        .ok("https://cdn.partner/card.json", card_body());

    let got = fetch_card(
        "https://a2a.vendor/.well-known/agent-card.json",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect("a two-hop public chain is legal");

    assert_eq!(
        r.asked(),
        vec!["a2a.vendor", "cdn.partner"],
        "each hop gets its OWN single lookup"
    );
    assert_eq!(
        t.calls(),
        vec![
            (
                "https://a2a.vendor/.well-known/agent-card.json".to_string(),
                ip(PUBLIC)
            ),
            ("https://cdn.partner/card.json".to_string(), ip(PUBLIC_2)),
        ],
        "each hop is pinned to its own judged address"
    );
    assert_eq!(
        got.chain,
        vec![
            "https://a2a.vendor/.well-known/agent-card.json".to_string(),
            "https://cdn.partner/card.json".to_string()
        ],
        "the chain is recorded so an operator approving a card can see where it came from"
    );
}

#[test]
fn a_redirect_chain_longer_than_the_policy_is_refused_rather_than_followed() {
    // A guard applied correctly to an unbounded number of hops is a way to spend the process.
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new()
        .redirect("https://a2a.vendor/0", "https://a2a.vendor/1")
        .redirect("https://a2a.vendor/1", "https://a2a.vendor/2")
        .redirect("https://a2a.vendor/2", "https://a2a.vendor/3")
        .redirect("https://a2a.vendor/3", "https://a2a.vendor/4")
        .redirect("https://a2a.vendor/4", "https://a2a.vendor/5");

    let policy = FetchPolicy {
        max_redirects: 2,
        ..FetchPolicy::default()
    };
    let err = fetch_card("https://a2a.vendor/0", &r, &t, &policy)
        .expect_err("a chain over the limit must be refused");

    assert_eq!(
        err,
        FetchRefusal::TooManyRedirects {
            limit: 2,
            at: "https://a2a.vendor/2".to_string(),
        }
    );
    assert_eq!(
        t.calls().len(),
        3,
        "max_redirects: 2 means three requests — the original and two follows"
    );
}

#[test]
fn a_redirect_loop_terminates_on_the_hop_limit_rather_than_spinning() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new()
        .redirect("https://a2a.vendor/a", "https://a2a.vendor/b")
        .redirect("https://a2a.vendor/b", "https://a2a.vendor/a");

    let err = fetch_card("https://a2a.vendor/a", &r, &t, &FetchPolicy::default())
        .expect_err("a loop must terminate on the limit");
    assert!(
        matches!(err, FetchRefusal::TooManyRedirects { limit: 3, .. }),
        "got {err:?}"
    );
}

#[test]
fn a_relative_location_is_resolved_against_the_hop_that_sent_it() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new()
        .redirect("https://a2a.vendor/agents/planner/card", "../../card.json")
        .ok("https://a2a.vendor/card.json", card_body());

    let got = fetch_card(
        "https://a2a.vendor/agents/planner/card",
        &r,
        &t,
        &FetchPolicy::default(),
    )
    .expect("a relative Location is legal");
    assert_eq!(got.chain[1], "https://a2a.vendor/card.json");
}

#[test]
fn a_redirect_with_no_location_is_a_refusal_and_not_a_silent_stop() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new().status("https://a2a.vendor/card", 302);

    let err = fetch_card("https://a2a.vendor/card", &r, &t, &FetchPolicy::default())
        .expect_err("a 3xx with no Location must refuse");
    assert_eq!(
        err,
        FetchRefusal::RedirectWithoutLocation {
            at: "https://a2a.vendor/card".to_string(),
            status: 302,
        }
    );
}

// ══ LINK-LOCAL, METADATA AND THE OBFUSCATED SPELLINGS ════════════════════════════════════════════

#[test]
fn every_internal_literal_and_metadata_target_is_refused_by_name() {
    // Judged BY NAME, one row per hazard, so a regression names the target it stopped blocking
    // rather than reporting "one of nineteen cases".
    let cases: &[(&str, &str)] = &[
        ("https://169.254.169.254/", "AWS/GCP/Azure IMDS link-local"),
        ("https://169.254.170.2/", "ECS task metadata"),
        ("https://127.0.0.1/", "loopback"),
        ("https://127.1/", "short-dotted loopback"),
        ("https://2130706433/", "decimal loopback"),
        ("https://0x7f000001/", "hex loopback"),
        ("https://017700000001/", "octal loopback"),
        ("https://0.0.0.0/", "unspecified"),
        ("https://255.255.255.255/", "broadcast"),
        ("https://10.0.0.1/", "RFC1918 /8"),
        ("https://172.16.5.4/", "RFC1918 /12"),
        ("https://192.168.1.1/", "RFC1918 /16"),
        ("https://100.64.0.1/", "RFC6598 CGNAT"),
        (
            "https://168.63.129.16/",
            "Azure WireServer, a PUBLIC address",
        ),
        ("https://192.0.0.192/", "OCI IMDS, an IETF-reserved address"),
        ("https://[::1]/", "IPv6 loopback"),
        ("https://[::ffff:127.0.0.1]/", "IPv4-mapped loopback"),
        ("https://[::ffff:169.254.169.254]/", "IPv4-mapped IMDS"),
        ("https://[fd00::1]/", "IPv6 unique-local"),
        ("https://[fe80::1]/", "IPv6 link-local"),
        ("https://localhost/", "the loopback NAME"),
        ("https://localhost./", "the loopback name, FQDN-rooted"),
        (
            "https://api.localhost/",
            "the RFC6761 loopback subdomain family",
        ),
        ("https://metadata.google.internal/", "the GCP metadata NAME"),
        (
            "https://metadata.google.internal./",
            "the GCP metadata name, FQDN-rooted",
        ),
        ("https://metadata.internal/", "the metadata NAME"),
    ];

    // A resolver that PANICS: nothing in this table may reach it. Every one of these is refusable
    // from the URL alone, and a case that needed a lookup would be a case where the guard depends
    // on what the attacker's nameserver says.
    struct NeverAsked;
    impl Resolver for NeverAsked {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            panic!("the guard resolved `{host}`, which it must refuse structurally");
        }
    }

    for (url, what) in cases {
        let err = resolve_and_pin(url, &NeverAsked, &FetchPolicy::default())
            .expect_err(&format!("{url} ({what}) must be refused"));
        assert!(
            matches!(
                err,
                FetchRefusal::InternalAddress { .. } | FetchRefusal::InternalHostName { .. }
            ),
            "{url} ({what}) was refused as {err:?}, which is the wrong reason"
        );
    }
}

// ══ SCHEME, SHAPE AND THE THINGS THAT ARE NOT CARDS ══════════════════════════════════════════════

#[test]
fn a_plaintext_endpoint_is_refused_unless_the_operator_opted_in() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);

    let err = resolve_and_pin("http://a2a.vendor/card", &r, &FetchPolicy::default())
        .expect_err("http:// is off by default");
    assert_eq!(
        err,
        FetchRefusal::NotHttps {
            url: "http://a2a.vendor/card".to_string(),
            scheme: "http".to_string(),
        }
    );

    let opted_in = FetchPolicy {
        allow_plaintext: true,
        ..FetchPolicy::default()
    };
    assert!(
        resolve_and_pin("http://a2a.vendor/card", &r, &opted_in).is_ok(),
        "the opt-in must actually opt in"
    );
}

#[test]
fn a_non_http_scheme_is_refused_however_the_plaintext_knob_is_set() {
    // `file:` and `data:` are the two that turn a fetch into a local read. Neither is reachable by
    // opting into plaintext, because the knob is about TRANSPORT confidentiality and these are not
    // transports at all.
    struct NeverAsked;
    impl Resolver for NeverAsked {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            panic!("resolved `{host}`");
        }
    }
    for policy in [
        FetchPolicy::default(),
        FetchPolicy {
            allow_plaintext: true,
            ..FetchPolicy::default()
        },
    ] {
        for url in [
            "file:///etc/passwd",
            "data:application/json,{}",
            "gopher://x/",
        ] {
            let err = resolve_and_pin(url, &NeverAsked, &policy)
                .expect_err(&format!("`{url}` must be refused"));
            assert!(
                matches!(
                    err,
                    FetchRefusal::NotHttps { .. } | FetchRefusal::NotAUrl(_)
                ),
                "`{url}` was refused as {err:?}, which is the wrong reason"
            );
        }
    }
}

#[test]
fn a_resolution_failure_is_a_failure_and_not_an_absence_of_internal_addresses() {
    let r = ScriptedResolver::new().failing("a2a.vendor", "NXDOMAIN");
    let err = resolve_and_pin("https://a2a.vendor/card", &r, &FetchPolicy::default())
        .expect_err("a resolution failure must refuse");
    assert_eq!(
        err,
        FetchRefusal::ResolutionFailed {
            host: "a2a.vendor".to_string(),
            err: "NXDOMAIN".to_string(),
        }
    );
}

#[test]
fn an_empty_resolver_answer_is_refused_rather_than_read_as_nothing_internal() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![]);
    let err = resolve_and_pin("https://a2a.vendor/card", &r, &FetchPolicy::default())
        .expect_err("an empty answer must refuse");
    assert_eq!(err, FetchRefusal::NoAddresses("a2a.vendor".to_string()));
}

#[test]
fn an_oversized_body_is_refused_before_it_is_parsed() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let big = format!(r#"{{"name":"{}"}}"#, "x".repeat(4096));
    let t = ScriptedTransport::new().ok("https://a2a.vendor/card", &big);
    let policy = FetchPolicy {
        max_body_bytes: 64,
        ..FetchPolicy::default()
    };
    let err = fetch_card("https://a2a.vendor/card", &r, &t, &policy)
        .expect_err("an oversized card must refuse");
    assert!(
        matches!(err, FetchRefusal::BodyTooLarge { bytes, .. } if bytes == big.len()),
        "got {err:?}"
    );
}

#[test]
fn a_body_that_is_not_a_json_object_is_not_a_card() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    for body in ["[]", "\"card\"", "null", "not json at all"] {
        let t = ScriptedTransport::new().ok("https://a2a.vendor/card", body);
        let err = fetch_card("https://a2a.vendor/card", &r, &t, &FetchPolicy::default())
            .expect_err("a non-object body must refuse");
        assert!(
            matches!(err, FetchRefusal::NotACard { .. }),
            "body `{body}` gave {err:?}"
        );
    }
}

#[test]
fn a_non_2xx_status_is_reported_with_the_status_rather_than_as_a_missing_card() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let t = ScriptedTransport::new().status("https://a2a.vendor/card", 404);
    let err = fetch_card("https://a2a.vendor/card", &r, &t, &FetchPolicy::default())
        .expect_err("a 404 must refuse");
    assert_eq!(
        err,
        FetchRefusal::Status {
            url: "https://a2a.vendor/card".to_string(),
            status: 404,
        }
    );
}

// ══ DISCOVERY PATHS ══════════════════════════════════════════════════════════════════════════════

#[test]
fn both_well_known_paths_are_offered_canonical_first_and_joined_onto_the_origin() {
    // The path MOVED between protocol revisions, so both are tried. And they are joined onto the
    // ORIGIN: joining onto the endpoint path would look for the card somewhere the specification
    // never puts it.
    let urls = discovery_urls("https://a2a.vendor/agents/planner?v=1#x").expect("a legal endpoint");
    assert_eq!(
        urls,
        vec![
            "https://a2a.vendor/.well-known/agent-card.json".to_string(),
            "https://a2a.vendor/.well-known/agent.json".to_string(),
        ]
    );
}

// ══ `allow_private` — WHAT IT OPENS, AND THE MUCH LONGER LIST OF WHAT IT DOES NOT ════════════════

/// THE KNOB DOES ITS JOB. A hermetic rig runs the agent it points busbar at, and on a laptop that
/// agent is `http://127.0.0.1:<port>`. Without this there is no way to point busbar at it at all.
#[test]
fn allow_private_admits_the_loopback_endpoint_it_is_for() {
    struct NeverAsked;
    impl Resolver for NeverAsked {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            panic!("a literal needs no resolver, and `{host}` reached one");
        }
    }
    let policy = FetchPolicy {
        allow_private: true,
        ..FetchPolicy::default()
    };
    for url in [
        "http://127.0.0.1:8080/agent",
        "https://127.0.0.1/agent",
        "https://10.0.0.5/agent",
        "https://192.168.1.7/agent",
        "https://[::1]/agent",
    ] {
        assert!(
            resolve_and_pin(url, &NeverAsked, &policy).is_ok(),
            "`allow_private: true` must actually admit `{url}`, or the knob is decoration"
        );
    }
    // AND THE NAME FORM, which needs a resolver and must be judged on what it answered.
    let r = ScriptedResolver::new().always("agent.local", vec![ip([127, 0, 0, 1])]);
    assert!(resolve_and_pin("http://agent.local/agent", &r, &policy).is_ok());
}

/// THE HALF THAT MAKES THE KNOB SAFE TO HAVE: a cloud-metadata target is refused WITH
/// `allow_private: true` SET, by literal, by IPv4-mapped literal, by name, and by what a hostile
/// resolver answers.
///
/// This is the one regression that would turn an operator's "this agent is on the internal network"
/// into "and may therefore read the instance's IAM credentials". It is asserted row by row, against
/// the flag ON, because the version of this test that only ran with the flag off would have passed
/// for a guard that consulted the flag first and the metadata list second.
#[test]
fn allow_private_never_opens_a_cloud_metadata_target() {
    let policy = FetchPolicy {
        allow_private: true,
        ..FetchPolicy::default()
    };

    struct NeverAsked;
    impl Resolver for NeverAsked {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            panic!("`{host}` must be refused structurally, before any resolution");
        }
    }
    let structural: &[(&str, &str)] = &[
        ("https://169.254.169.254/", "AWS/GCP/Azure IMDS link-local"),
        ("https://169.254.170.2/", "ECS task metadata"),
        (
            "https://168.63.129.16/",
            "Azure WireServer, a PUBLIC address",
        ),
        ("https://192.0.0.192/", "OCI IMDS, IETF-reserved"),
        ("https://[::ffff:169.254.169.254]/", "IPv4-mapped IMDS"),
        ("https://[::169.254.169.254]/", "IPv4-compatible IMDS"),
        ("https://metadata.google.internal/", "the GCP metadata NAME"),
        (
            "https://metadata.google.internal./",
            "the metadata name, FQDN-rooted",
        ),
        ("https://metadata.internal/", "the metadata NAME"),
        // THE OBFUSCATED SPELLINGS OF IMDS. `Url::parse` normalises these to the literal, so they
        // land in the same arm — which is the point: an operator who set `allow_private` for their
        // sidecar has not thereby permitted `0xa9fea9fe`.
        ("https://0xa9fea9fe/", "hex IMDS"),
        ("https://2852039166/", "decimal IMDS"),
    ];
    for (url, what) in structural {
        let err = resolve_and_pin(url, &NeverAsked, &policy).expect_err(&format!(
            "{url} ({what}) must be refused WITH allow_private set"
        ));
        assert!(
            matches!(
                err,
                FetchRefusal::InternalAddress { .. } | FetchRefusal::InternalHostName { .. }
            ),
            "{url} ({what}) was refused as {err:?}, which is the wrong reason"
        );
    }

    // AND ON THE ANSWER. A name an operator believes is their internal agent, whose nameserver
    // answers with IMDS, is the rebinding shape of the same attack.
    let r = ScriptedResolver::new().always("agent.internal", vec![ip([169, 254, 169, 254])]);
    let err = resolve_and_pin("https://agent.internal/agent", &r, &policy)
        .expect_err("a resolved metadata address is refused with allow_private set");
    assert!(
        matches!(err, FetchRefusal::InternalAddress { .. }),
        "got {err:?}"
    );
}

/// `allow_private` ADMITS PLAINTEXT, because that is what the word means on the `tools:` plane
/// (`mcp::client::ssrf::precheck` refuses `http://` with exactly `!https && !allow_private`), and a
/// loopback agent that could only be reached over TLS is a knob that does not do its job.
#[test]
fn allow_private_carries_the_plaintext_permission_its_mcp_sibling_carries() {
    let r = ScriptedResolver::new().always("a2a.vendor", vec![ip(PUBLIC)]);
    let policy = FetchPolicy {
        allow_private: true,
        ..FetchPolicy::default()
    };
    assert!(
        resolve_and_pin("http://a2a.vendor/card", &r, &policy).is_ok(),
        "one operator decision, one flag — the same one the sibling plane spells"
    );
    // AND THE FLOOR IS UNMOVED: with neither opt-in, plaintext is still refused.
    assert!(matches!(
        resolve_and_pin("http://a2a.vendor/card", &r, &FetchPolicy::default()),
        Err(FetchRefusal::NotHttps { .. })
    ));
}

/// EVERY ROW OF THE ORIGINAL REFUSAL TABLE IS STILL REFUSED WITH THE FLAG OFF. The knob's default
/// is the floor, and this is the assertion that the split of `dns_name_is_internal` into a
/// metadata arm and a loopback arm did not quietly drop one of them.
#[test]
fn the_default_policy_still_refuses_the_loopback_family_by_name() {
    struct NeverAsked;
    impl Resolver for NeverAsked {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            panic!("the guard resolved `{host}`, which it must refuse structurally");
        }
    }
    for url in [
        "https://localhost/",
        "https://localhost./",
        "https://api.localhost/",
    ] {
        let err = resolve_and_pin(url, &NeverAsked, &FetchPolicy::default())
            .expect_err(&format!("{url} must be refused by default"));
        assert!(
            matches!(err, FetchRefusal::InternalHostName { .. }),
            "{url} was refused as {err:?}"
        );
    }
}
