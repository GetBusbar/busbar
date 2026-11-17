// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SDK surface (compile-only): a plugin repository's tests hand `plugin!`'s `&'static LinkedPlugin` to the
//! suites and name the suite case-input types from outside this crate. Nothing runs; it must compile.
#![forbid(unsafe_code)]

use busbar_ffi::LinkedPlugin;
use busbar_plugin_test::suites::{
    self, AuthCase, AuthIn, Expect, MigrateExpect, Pair, PlaneCase, PlaneIn, TransportCase,
};
use busbar_plugin_test::{CallCx, FakeNeeds, LoginAnswer, LoginIn, PlaneOut, PortError, TargetIn};

#[allow(dead_code)]
fn surface(p: &'static LinkedPlugin) {
    let headers: &[Pair<'_>] = &[];
    let auth = AuthIn {
        method: "GET",
        path: "/",
        query: "",
        authority: "",
        headers,
        peer: "",
        tls_peer_cert: &[],
        body: &[],
        now_s: 0,
    };
    let cases = [AuthCase {
        req: auth,
        expect: Expect::NotMine,
    }];
    suites::auth(p, b"{}", FakeNeeds::new(), &cases);
    let plane = PlaneIn {
        route: 0,
        flags: 0,
        auth: 0,
        method: "GET",
        path: "/",
        query: "",
        headers,
        identity: &[],
        request_id: 0,
        carrier: 0,
        work: "",
        ticket_record: &[],
    };
    let pc = [PlaneCase {
        req: plane,
        body: &[],
        upstream: &[],
        lookups: &[],
        expect_status: 200,
    }];
    suites::plane(p, b"{}", FakeNeeds::new(), &pc);
    let tc = [TransportCase {
        role: 0,
        alpn: "",
        input: &[],
        expect_streams: 0,
    }];
    suites::transport(p, b"{}", &tc);
    suites::migrate(p, b"{}", FakeNeeds::new(), MigrateExpect::Refused(0));
    suites::store(p, b"{}", FakeNeeds::new());
    suites::secret(p, b"{}", FakeNeeds::new(), &[], &[]);
    suites::hook(p, b"{}", FakeNeeds::new());
    suites::export(p, b"{}", FakeNeeds::new());
}

#[test]
fn surface_compiles() {}

#[test]
fn auth_login_surface_compiles() {
    // A plugin repository names the complete login call through its one test dev-dependency.
    async fn login(
        harness: &suites::harness::Harness,
        cx: CallCx,
    ) -> Result<LoginAnswer, PortError> {
        let auth = harness.open_auth("auth", b"{}").expect("open auth");
        auth.login(
            cx,
            LoginIn::Credential {
                username: "test-user",
                password: b"",
            },
        )
        .await
    }

    let _login = login;
}

#[test]
fn plane_upstream_surface_compiles() {
    // A plugin repository drives a request and target using only its test facade.
    fn exchange(
        harness: &suites::harness::Harness,
        request: &PlaneIn<'_>,
    ) -> Result<(), PortError> {
        let plane = harness.open_plane("plane", b"{}").expect("open plane");
        let target = TargetIn {
            attempt: 0,
            flags: 0,
            dialect: "test",
            model: "test-model",
            base_path: "/",
            upstream: "test-upstream",
            provider: "test-provider",
            params: &[],
            admission: &[],
        };
        let mut sink = |_: PlaneOut<'_>| {};
        let mut session = plane.request(request, b"{}", &mut sink)?;
        plane.upstream(&mut session, &target, &mut sink)?;
        plane.end(session, &mut sink)
    }

    let _exchange = exchange;
}
