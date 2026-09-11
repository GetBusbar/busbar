// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FACE, held to what it promises: a declaration is data, a dispatcher is handed a reading of
//! the process and nothing else, and both are the same for every plugin that has them.

use super::*;
use crate::{RouteAuth, RouteMethod};

/// A process that has no registry installed — the answer a dispatcher must be able to tell apart
/// from an empty one.
struct Silent;
impl ProcessSnapshot for Silent {
    fn metrics(&self) -> Option<String> {
        None
    }
}

/// A process with a registry.
struct Speaking(&'static str);
impl ProcessSnapshot for Speaking {
    fn metrics(&self) -> Option<String> {
        Some(self.0.to_string())
    }
}

/// A sink that answers with whatever the process said, or refuses when it said nothing.
struct Echo;
impl HttpDispatch for Echo {
    fn handle_http(
        &self,
        _req: &HttpEndpointRequest,
        process: &dyn ProcessSnapshot,
    ) -> HttpEndpointResponse {
        match process.metrics() {
            Some(body) => HttpEndpointResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            },
            None => HttpEndpointResponse {
                status: 503,
                headers: Vec::new(),
                body: Vec::new(),
            },
        }
    }
}

fn req() -> HttpEndpointRequest {
    HttpEndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// A DECLARATION IS DATA: the three facts survive a clone, and the dispatcher rides along without
/// the declaration becoming something only its author can read.
#[test]
fn a_declaration_is_the_three_facts_and_a_dispatcher() {
    let decl = RouteDecl {
        owner: "prometheus".to_string(),
        kind: RouteKind::Export,
        route: Route {
            path: "/metrics".to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
        },
        dispatch: Arc::new(Echo),
    };
    let copy = decl.clone();
    assert_eq!(copy.owner, "prometheus");
    assert_eq!(copy.kind, RouteKind::Export);
    assert_eq!(copy.route.path, "/metrics");
    assert_eq!(copy.route.method, RouteMethod::Get);
    assert_eq!(copy.route.auth, RouteAuth::Key);
    // The debug spelling names the declared facts and does not try to spell the dispatcher.
    let d = format!("{decl:?}");
    assert!(d.contains("prometheus") && d.contains("/metrics"), "{d}");
}

/// THE SNAPSHOT IS THE ONLY THING A DISPATCHER READS OF THE PROCESS, and "no registry" is a
/// distinct answer from "an empty registry" — the distinction the refusal policy is built on.
#[test]
fn a_dispatcher_reads_the_process_only_through_the_snapshot() {
    assert_eq!(
        Echo.handle_http(&req(), &Speaking("# HELP x\n")).status,
        200
    );
    assert_eq!(
        Echo.handle_http(&req(), &Speaking("# HELP x\n")).body,
        b"# HELP x\n".to_vec()
    );
    let refused = Echo.handle_http(&req(), &Silent);
    assert_eq!(refused.status, 503);
    assert!(refused.body.is_empty());
}
