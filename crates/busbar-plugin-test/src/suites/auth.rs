// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth suite body (IF §14). Owned by the auth agent: this is the only file it edits. Drive the plugin with
//! [`super::harness::Harness`].
//!
//! What it runs, over the plugin image admitted into a `Registry<FakeNeeds>` (real `HOST`, `MemBinder`):
//!
//! 1. admit: the stamp names the auth kind;
//! 2. `check` (DRY_RUN) and `open` of the operator `config`, both answered OK, with no refusal recorded;
//! 3. the described surface the port reads: credential headers are non-empty lowercase, a declared issued kind
//!    is non-empty;
//! 4. every [`AuthCase`] through the port's `verify`, with `Expect::Subject` (an identity whose subject
//!    matches), `Expect::NotMine` (the plugin declines the request) or `Expect::Rejected` (a rejection with that
//!    kind code), a `verify_io` plugin's boxed chain included. A plugin failure (`PortError`) or a verdict the
//!    case did not expect fails the suite and names the case;
//! 5. a plugin that does not declare FB_PROVISION answers `serve` as unsupported without a call;
//! 6. a config that is not JSON is refused by `check` (never an instance, never a fault);
//! 7. the instance closes (drops) and nothing the harness collected is a refusal the suite did not expect.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth as abi;
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller};
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::adapters::auth::AuthCore;
use busbar_ports::auth::{ServeIn, Verdict, Verify};
use busbar_ports::{CallCx, PortError};

use super::harness::Harness;
use super::{AuthCase, Expect};
use crate::fake_needs::FakeNeeds;

/// The instance name every suite instance opens under.
const NAME: &str = "suite";

/// `auth.unknown_key_refresh_s` the suite installs (the adapter's floor).
const KEY_REFRESH: Duration = Duration::from_secs(30);

/// The kernel's side of the auth adapter, over what the suite's `FakeNeeds` scripted: `issued` answers from
/// `FakeNeeds::issued` (empty when the id is unknown, the same answer an ungranted kind gets), and `claim` is a
/// replay guard that admits the first sighting of a key and declines every later one.
struct SuiteCore {
    issued: Vec<(String, String, Vec<u8>)>,
    seen: Mutex<HashSet<Vec<u8>>>,
}

impl AuthCore for SuiteCore {
    fn issued<'a>(
        &'a self,
        _auth_instance: u64,
        kind: &'a str,
        id: &'a str,
    ) -> BoxFut<'a, SecureVec> {
        let mut out = SecureVec::new();
        if let Some((_, _, value)) = self.issued.iter().find(|(k, i, _)| k == kind && i == id) {
            out.extend_from_slice(value);
        }
        Box::pin(core::future::ready(out))
    }

    fn claim<'a>(
        &'a self,
        _who: &'a Caller<'_>,
        key: &'a [u8],
        _ttl_s: u64,
    ) -> BoxFut<'a, Option<bool>> {
        let first = self
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_vec());
        Box::pin(core::future::ready(Some(first)))
    }
}

fn cx(n: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: n,
        stack: CallStack::default(),
    }
}

/// What a verdict says, for failure messages. Never prints secret bytes: identity records stay out.
fn describe(verdict: &Result<Verdict, PortError>) -> String {
    match verdict {
        Ok(Verdict::Identity(id)) => format!("identity (subject {:?})", id.subject()),
        Ok(Verdict::NotMine) => "not mine".to_owned(),
        Ok(Verdict::Rejected { code, text }) => format!("rejected (code {code}, {text:?})"),
        Err(e) => format!("port error {e:?}"),
    }
}

fn expected(expect: &Expect<'_>) -> String {
    match expect {
        Expect::Subject(s) => format!("identity (subject {s:?})"),
        Expect::NotMine => "not mine".to_owned(),
        Expect::Rejected(code) => format!("rejected (code {code})"),
    }
}

fn matches(expect: &Expect<'_>, verdict: &Result<Verdict, PortError>) -> bool {
    match (expect, verdict) {
        (Expect::Subject(want), Ok(Verdict::Identity(id))) => id.subject() == *want,
        (Expect::NotMine, Ok(Verdict::NotMine)) => true,
        (Expect::Rejected(want), Ok(Verdict::Rejected { code, .. })) => code == want,
        _ => false,
    }
}

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    cases: &[AuthCase<'_>],
) {
    let core = Arc::new(SuiteCore {
        issued: needs.kernel().issued,
        seen: Mutex::new(HashSet::new()),
    });
    let harness = match Harness::admit(plugin, needs) {
        Ok(h) => h,
        Err(refusal) => panic!("auth suite: admit refused the image: {refusal:?}"),
    };
    assert_eq!(
        harness.kind(),
        KindCode::Auth,
        "auth suite: the stamp of {} names kind {:?}, not auth",
        harness.identity(),
        harness.kind()
    );
    harness.registry().set_auth_core(core, KEY_REFRESH);

    // check (DRY_RUN) and open of the operator config.
    if let Err(e) = harness.check(NAME, config) {
        panic!("auth suite: check refused the config: {e:?}");
    }
    let port = match harness.open_auth(NAME, config) {
        Ok(port) => port,
        Err(e) => panic!("auth suite: open refused the config: {e:?}"),
    };
    // The settled answer of open (canonical CONFIG, CORE_CFG*) is for the migrate suite; drain it so a later
    // open of the same name starts clean.
    let _ = harness.settled(NAME);

    // The described surface the adapter reads.
    for header in port.cred_headers() {
        assert!(
            !header.is_empty() && header.bytes().all(|b| !b.is_ascii_uppercase()),
            "auth suite: D_CRED_HEADER {header:?} must be non-empty lowercase"
        );
    }
    if let Some(kind) = port.issued_kind() {
        assert!(!kind.is_empty(), "auth suite: D_ISSUED_KIND is empty");
    }

    // Every case through verify.
    for (n, case) in cases.iter().enumerate() {
        let request_id = u64::try_from(n).unwrap_or(u64::MAX).saturating_add(1);
        let verdict = match port.verify(cx(request_id), &case.req) {
            Verify::Done(done) => done,
            Verify::Io(chain) => harness.block_on(chain),
        };
        assert!(
            matches(&case.expect, &verdict),
            "auth suite: case {n} ({} {}): expected {}, got {}",
            case.req.method,
            case.req.path,
            expected(&case.expect),
            describe(&verdict)
        );
    }

    // A plugin without FB_PROVISION answers serve as unsupported, without a call.
    if port.facts() & abi::FB_PROVISION == 0 {
        let req = ServeIn {
            method: "GET",
            path: "/",
            query: "",
            headers: &[],
            body: &[],
            client: "suite",
        };
        let answer = harness.block_on(port.serve(cx(u64::MAX), &req));
        assert!(
            matches!(&answer, Err(PortError::Refused { code, .. }) if *code == R_UNSUPPORTED),
            "auth suite: serve on a plugin without FB_PROVISION must be REFUSED R_UNSUPPORTED, got {}",
            match &answer {
                Ok(_) => "an answer".to_owned(),
                Err(e) => format!("{e:?}"),
            }
        );
    }

    // A config that is not JSON is refused as a config, never opened.
    assert!(
        harness.check("suite-bad", b"\xff not json").is_err(),
        "auth suite: check accepted a config that is not JSON"
    );
    let expected_refusals = 1;

    // Close: drop the port (and with it the instance's last reference).
    drop(port);
    let refusals = harness.refusals();
    assert_eq!(
        refusals.len(),
        expected_refusals,
        "auth suite: refusals beyond the bad-config probe: {refusals:?}"
    );
    harness.assert_needs_declared("auth");
}
