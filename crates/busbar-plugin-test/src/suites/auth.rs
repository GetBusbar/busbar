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

use std::time::{Duration, Instant};

use busbar_plugin_abi::auth as abi;
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{ServeIn, Verify, VerifyAnswer};
use busbar_ports::{CallCx, PortError};

use super::harness::Harness;
use super::{AuthCase, Expect};
use crate::fake_needs::FakeNeeds;

/// The instance name every suite instance opens under.
const NAME: &str = "suite";

fn cx(n: u64) -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: n,
        stack: CallStack::default(),
    }
}

/// What a verdict says, for failure messages. Never prints secret bytes: identity records stay out.
fn describe(verdict: &Result<VerifyAnswer, PortError>) -> String {
    match verdict {
        Ok(VerifyAnswer::Identity(id)) => format!("identity (subject {:?})", id.subject()),
        Ok(VerifyAnswer::NotMine) => "not mine".to_owned(),
        Ok(VerifyAnswer::Refused { code, text }) => format!("rejected (code {code}, {text:?})"),
        Ok(VerifyAnswer::IssuedWanted(id)) => format!("issued wanted {id:?}"),
        Ok(VerifyAnswer::KeysStale) => "keys stale".to_owned(),
        Err(e) => format!("port error {e:?}"),
    }
}

fn expected(expect: &Expect<'_>) -> String {
    match expect {
        Expect::Subject(s) => format!("identity (subject {s:?})"),
        Expect::IssuedWanted(id) => format!("issued wanted {id:?}"),
        Expect::KeysStale => "keys stale".to_owned(),
        Expect::NotMine => "not mine".to_owned(),
        Expect::Rejected(code) => format!("rejected (code {code})"),
    }
}

fn matches(expect: &Expect<'_>, verdict: &Result<VerifyAnswer, PortError>) -> bool {
    match (expect, verdict) {
        (Expect::Subject(want), Ok(VerifyAnswer::Identity(id))) => id.subject() == *want,
        (Expect::IssuedWanted(want), Ok(VerifyAnswer::IssuedWanted(id))) => id.as_ref() == *want,
        (Expect::KeysStale, Ok(VerifyAnswer::KeysStale)) => true,
        (Expect::NotMine, Ok(VerifyAnswer::NotMine)) => true,
        (Expect::Rejected(want), Ok(VerifyAnswer::Refused { code, .. })) => code == want,
        _ => false,
    }
}

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    cases: &[AuthCase<'_>],
) {
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
        let verdict = match port.verify(cx(request_id), &case.req, None) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::auth::{tag, AuthReq};
    use busbar_plugin_abi::fail::{refused::R_CONFIG, Fail};
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Out, Writer};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static VERIFIES: AtomicUsize = AtomicUsize::new(0);
    static REFRESHES: AtomicUsize = AtomicUsize::new(0);
    pub struct RawAuth;
    impl Open for RawAuth {
        async fn open(_: &'static Host, _: ChainBytes) -> Result<Self, Fail> {
            Ok(Self)
        }
        fn check(_: &Host, config: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
            busbar_contract::json::parse_value(config)
                .map(|_| ())
                .map_err(|_| Fail::refused(R_CONFIG))
        }
        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.methods(abi::M_VERIFY | abi::M_REFRESH);
            d.item_text(tag::D_CRED_HEADER, "authorization");
        }
    }
    impl busbar_plugin_abi::Auth for RawAuth {
        fn verify(&self, _: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
            VERIFIES.fetch_add(1, Ordering::SeqCst);
            match req.path.get() {
                "/issued" => {
                    out.put_text(tag::ISSUED_WANTED, "key")
                        .map_err(|_| Fail::refused(R_CONFIG))?;
                    Ok(())
                }
                _ => Err(Fail::refused(abi::KEYS_STALE)),
            }
        }
        async fn refresh(
            &self,
            _: &'static Host,
        ) -> Result<busbar_plugin_abi::records::Reply, Fail> {
            REFRESHES.fetch_add(1, Ordering::SeqCst);
            Ok(busbar_plugin_abi::records::Reply::new())
        }
    }
    busbar_plugin_abi::plugin!(Auth, RawAuth, name: "fixture-raw-auth");

    #[test]
    fn suite_observes_issued_wanted_and_keys_stale_without_host_retries() {
        let request = |path| busbar_ports::auth::AuthIn {
            method: "GET",
            path,
            query: "",
            authority: "example",
            headers: &[],
            peer: "",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1000,
        };
        let cases = [
            AuthCase {
                req: request("/issued"),
                expect: Expect::IssuedWanted("key"),
            },
            AuthCase {
                req: request("/stale"),
                expect: Expect::KeysStale,
            },
        ];
        run(&PLUGIN, b"{}", FakeNeeds::new(), &cases);
        assert_eq!(
            VERIFIES.load(Ordering::SeqCst),
            2,
            "one port call makes one plugin call"
        );
        assert_eq!(
            REFRESHES.load(Ordering::SeqCst),
            0,
            "the loader never refreshes a raw answer"
        );
    }
}
