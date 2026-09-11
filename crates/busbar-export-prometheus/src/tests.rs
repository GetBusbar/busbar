// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sink held to the three decisions it exists to make, plus the declaration it states.

use super::*;

/// A process with a registry.
struct Installed(&'static str);
impl Scrape for Installed {
    fn registry(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// A process whose recorder is not installed.
struct NotInstalled;
impl Scrape for NotInstalled {
    fn registry(&self) -> Option<String> {
        None
    }
}

/// A process that counts how many times it was read.
struct Counting(std::cell::Cell<usize>, Option<&'static str>);
impl Scrape for Counting {
    fn registry(&self) -> Option<String> {
        self.0.set(self.0.get() + 1);
        self.1.map(str::to_string)
    }
}

/// THE DECLARATION: one route, the well-known path, the data-plane bar. Written out rather than
/// derived, because every one of the three is a decision somebody has to re-read to change.
#[test]
fn the_sink_declares_one_route_and_it_is_the_well_known_scrape_path() {
    assert_eq!(ROUTES.len(), 1);
    assert_eq!(ROUTES[0].path, "/metrics");
    assert_eq!(ROUTES[0].method, "GET");
    assert_eq!(ROUTES[0].auth, Auth::Key);
    assert_eq!(METRICS_PATH, "/metrics");
    assert_eq!(MODULE, "prometheus");
}

/// AN INSTALLED REGISTRY IS RELAYED BYTE FOR BYTE under the exposition's own content type. The
/// sink adds nothing to the body and reorders nothing in it: a scrape is what the process said.
#[test]
fn an_installed_registry_is_relayed_unchanged_with_the_exposition_content_type() {
    let body = "# HELP busbar_requests_total x\n# TYPE busbar_requests_total counter\nbusbar_requests_total 1\n";
    let served = PrometheusSink.render(&Installed(body));
    assert_eq!(served.status, 200);
    assert_eq!(served.body, body.as_bytes().to_vec());
    assert_eq!(
        served.headers,
        vec![(
            "content-type".to_string(),
            "text/plain; version=0.0.4".to_string()
        )]
    );
}

/// AN EMPTY-BUT-INSTALLED REGISTRY IS A 200, and that is the point of `registry()` answering with
/// an option rather than a string: installed-and-empty is a true state and it is not a refusal.
#[test]
fn an_installed_but_empty_registry_is_a_two_hundred_not_a_refusal() {
    let served = PrometheusSink.render(&Installed(""));
    assert_eq!(served.status, 200);
    assert!(served.body.is_empty());
    assert_eq!(served.headers[0].0, "content-type");
}

/// NO REGISTRY IS A REFUSAL, not a 200 with an empty body — the boot-window distinction an operator
/// wiring up a scraper before traffic starts has to be able to make on the wire.
#[test]
fn no_registry_is_refused_with_a_retry_hint_and_no_body() {
    let served = PrometheusSink.render(&NotInstalled);
    assert_eq!(served.status, 503);
    assert!(served.body.is_empty());
    assert_eq!(
        served.headers,
        vec![("retry-after".to_string(), "1".to_string())]
    );
}

/// THE READER RUNS INSIDE `render`, EXACTLY ONCE, AND ONLY ONCE PER SCRAPE. The read behind it
/// walks a store, so a second call would double a scrape's cost, and a call made by the composer
/// before this one would refresh for a request that is about to be refused.
#[test]
fn the_process_is_read_exactly_once_per_scrape() {
    let counting = Counting(std::cell::Cell::new(0), Some("# HELP x\n"));
    let _ = PrometheusSink.render(&counting);
    assert_eq!(counting.0.get(), 1);

    let refused = Counting(std::cell::Cell::new(0), None);
    let served = PrometheusSink.render(&refused);
    assert_eq!(served.status, 503);
    assert_eq!(
        refused.0.get(),
        1,
        "the refusal is decided BY the read, so it is read once and never twice"
    );
}
