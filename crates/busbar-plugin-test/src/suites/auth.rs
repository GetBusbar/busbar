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
//!    kind code), a `verify_io` plugin's boxed chain included. `Expect::IssuedWanted` is the raw first answer; for
//!    every other expectation a first ISSUED_WANTED gets core's second call, with the credential scripted by
//!    [`FakeNeeds::issued`] under the plugin's D_ISSUED_KIND (empty when none was), and a second ISSUED_WANTED is
//!    BAD_CREDENTIAL. A plugin failure (`PortError`) or a verdict the case did not expect fails the suite and
//!    names the case;
//! 5. a plugin that does not declare FB_PROVISION answers `serve` as unsupported without a call;
//! 6. a config that is not JSON is refused by `check` (never an instance, never a fault);
//! 7. the instance closes (drops) and nothing the harness collected is a refusal the suite did not expect.
//!
//! [`super::auth_migrated`] runs the same steps on settings core migrated from older ones: the older bag opened and
//! settled as the migrate suite's first case checks it, each CORE_CFG(LIFT) literal moved into custody, then 2 to 7
//! on what core persisted.

use std::time::{Duration, Instant};

use busbar_plugin_abi::auth as abi;
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{AuthIn, AuthPort, ServeIn, Verify, VerifyAnswer};
use busbar_ports::{CallCx, PortError};

use super::harness::Harness;
use super::{AuthCase, Expect, MigrateCase, MigrateExpect};
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

/// One plugin `verify` invocation, driven to its answer.
fn call(
    harness: &Harness,
    port: &dyn AuthPort,
    request_id: u64,
    req: &AuthIn<'_>,
    issued: Option<&[u8]>,
) -> Result<VerifyAnswer, PortError> {
    match port.verify(cx(request_id), req, issued) {
        Verify::Done(done) => done,
        Verify::Io(chain) => harness.block_on(chain),
    }
}

/// What core answers after a first ISSUED_WANTED (busbar-kernel `auth::chain_run::settle`): with no D_ISSUED_KIND,
/// BAD_CREDENTIAL; else the id looked up under that kind (here [`FakeNeeds::issued`], empty for an id nothing was
/// issued under) and `verify` called once more with it, where a second ISSUED_WANTED is BAD_CREDENTIAL.
fn looked_up(
    harness: &Harness,
    port: &dyn AuthPort,
    request_id: u64,
    req: &AuthIn<'_>,
    id: &str,
) -> Result<VerifyAnswer, PortError> {
    let rejected = || {
        Ok(VerifyAnswer::Refused {
            code: abi::BAD_CREDENTIAL,
            text: "auth admission refused".into(),
        })
    };
    let Some(kind) = port.issued_kind() else {
        return rejected();
    };
    let value = harness.needs().issued_value(kind, id);
    match call(harness, port, request_id, req, Some(&value)) {
        Ok(VerifyAnswer::IssuedWanted(_)) => rejected(),
        second => second,
    }
}

/// The plugin admitted under `needs`; its stamp must name the auth kind.
fn admitted(plugin: &'static Plugin, needs: FakeNeeds) -> Harness {
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
    harness
}

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    cases: &[AuthCase<'_>],
) {
    run_on(&admitted(plugin, needs), config, cases);
}

/// The older `case.bag` opened and settled as the migrate suite's case 1 checks it (with the legacy marker at
/// `legacy`, if any), each CORE_CFG(LIFT) literal moved into custody as core moves it, then every step of [`run`]
/// on the settings core persisted: a literal secret in older settings verifies through the reference core wrote.
pub(super) fn migrated(
    plugin: &'static Plugin,
    case: &MigrateCase<'_>,
    legacy: &[&str],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
    cases: &[AuthCase<'_>],
) {
    let MigrateExpect::Settled { config, core_cfg } = expect else {
        panic!("auth suite: an auth case runs on settings that open; a refused migration is the migrate suite's");
    };
    let harness = admitted(plugin, needs);
    if !legacy.is_empty() {
        harness.mark_legacy("migrate", legacy);
    }
    let persisted = super::migrate::persisted(&harness, case, config, core_cfg);
    run_on(&harness, &persisted, cases);
}

fn run_on(harness: &Harness, config: &[u8], cases: &[AuthCase<'_>]) {
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

    // Every case through verify: the raw first answer for an ISSUED_WANTED case, else core's final verdict.
    for (n, case) in cases.iter().enumerate() {
        let request_id = u64::try_from(n).unwrap_or(u64::MAX).saturating_add(1);
        let first = call(harness, &*port, request_id, &case.req, None);
        let verdict = match (&case.expect, first) {
            (Expect::IssuedWanted(_), first) => first,
            (_, Ok(VerifyAnswer::IssuedWanted(id))) => {
                looked_up(harness, &*port, request_id, &case.req, &id)
            }
            (_, first) => first,
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

    /// An auth plugin that answers ISSUED_WANTED and judges the credential core looked up for it.
    mod issued {
        use super::*;
        use busbar_plugin_abi::auth::{IssuedShapeRec, BAD_CREDENTIAL, REQ_ISSUED_LOOKED_UP};
        use busbar_plugin_abi::records::{tag as rec, Full, Nested};

        pub(super) const KIND: &str = "fixture-key";
        pub(super) const ID: &str = "AKIAFIXTURE000000001";
        pub(super) const KEY: &[u8] = b"fixture/secret+KEY0000000000000000000000";
        pub(super) const SUBJECT: &str = "issued-subject";

        pub(super) static VERIFIES: AtomicUsize = AtomicUsize::new(0);

        fn shape_texts(w: &mut Nested<'_>) -> Result<(), Full> {
            for text in [
                "AKIA",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            ] {
                w.put_text(rec::TEXT, text)?;
            }
            Ok(())
        }

        pub struct IssuedAuth;
        impl Open for IssuedAuth {
            async fn open(_: &'static Host, _: ChainBytes) -> Result<Self, Fail> {
                Ok(Self)
            }
            fn check(_: &Host, _: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
                Ok(())
            }
            fn describe(d: &mut Describe<'_>) {
                d.schema(r#"{"type":"object"}"#);
                d.methods(abi::M_VERIFY);
                d.item_text(tag::D_CRED_HEADER, "authorization");
                d.item_text(tag::D_ISSUED_KIND, KIND);
                d.item_pod_nested(
                    tag::D_ISSUED_SHAPE,
                    &IssuedShapeRec {
                        id_len: 20,
                        secret_len: 40,
                    },
                    shape_texts,
                );
            }
        }
        impl busbar_plugin_abi::Auth for IssuedAuth {
            /// `/known` and `/unknown` ask for an id, then judge what core looked up; `/again` asks a second
            /// time, which core rejects.
            fn verify(&self, _: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                VERIFIES.fetch_add(1, Ordering::SeqCst);
                let looked_up = req.flags & REQ_ISSUED_LOOKED_UP != 0;
                let wanted = match req.path.get() {
                    "/known" => ID,
                    "/unknown" => "AKIAUNKNOWN000000001",
                    "/again" => ID,
                    _ => return Err(Fail::refused(abi::NOT_MINE)),
                };
                if !looked_up || req.path.get() == "/again" {
                    return out
                        .put_text(tag::ISSUED_WANTED, wanted)
                        .map_err(|_| Fail::refused(R_CONFIG));
                }
                if req.issued.get() == KEY {
                    out.put_text(rec::ID_SUBJECT, SUBJECT)
                        .map_err(|_| Fail::refused(R_CONFIG))
                } else {
                    Err(Fail::refused(BAD_CREDENTIAL))
                }
            }
        }
        busbar_plugin_abi::plugin!(Auth, IssuedAuth, name: "fixture-issued-auth");
    }

    /// An auth plugin whose older settings held its bearer key as a literal at `/token`: a converting open takes the
    /// literal and names it CORE_CFG(LIFT); every later open reads the key through the reference core wrote there.
    mod lift {
        use super::*;
        use busbar_contract::json::{self, JsonValueTrait};
        use busbar_plugin_abi::need::{need, SecretHandle};
        use busbar_plugin_abi::records::{core_cfg, settled, tag as rec, Full};
        use busbar_plugin_abi::secure::SecureVec;

        pub(super) const BAG: &[u8] = br#"{"token":"lifted-bearer-key"}"#;
        pub(super) const SUBJECT: &str = "lifted-subject";

        /// The settings it opened with, the key, and whether the key came as a literal.
        pub struct LiftAuth(Vec<u8>, SecureVec, bool);

        impl Open for LiftAuth {
            async fn open(_: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
                let config = config.to_vec();
                let value = json::parse_value(&config).map_err(|_| Fail::refused(R_CONFIG))?;
                let token = value.get("token").ok_or_else(|| Fail::refused(R_CONFIG))?;
                if let Some(literal) = token.as_str() {
                    let key = SecureVec::from(literal.as_bytes());
                    return Ok(Self(config, key, true));
                }
                let handle = token
                    .get("$secret")
                    .and_then(|n| n.as_u64())
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| Fail::refused(R_CONFIG))?;
                let key = need::secret(SecretHandle(handle)).await?;
                Ok(Self(config, key, false))
            }
            fn check(_: &Host, _: &[u8], _: &mut Endpoints<'_>) -> Result<(), Fail> {
                Ok(())
            }
            fn describe(d: &mut Describe<'_>) {
                d.schema(r#"{"type":"object"}"#).secret_path("/token");
                d.methods(abi::M_VERIFY);
                d.item_text(tag::D_CRED_HEADER, "authorization");
            }
            fn settled(&self, out: &mut Out<'_>) -> Result<(), Full> {
                settled::config(out, &self.0)?;
                if self.2 {
                    settled::core_cfg(out, core_cfg::LIFT, "", br#""/token""#)?;
                }
                Ok(())
            }
        }
        impl busbar_plugin_abi::Auth for LiftAuth {
            /// `authorization: Bearer <key>` is the subject; another bearer is BAD_CREDENTIAL; none is not mine.
            fn verify(&self, _: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
                let Some(line) = req
                    .headers
                    .get()
                    .iter()
                    .find(|p| p.name.get() == "authorization")
                else {
                    return Err(Fail::refused(abi::NOT_MINE));
                };
                let presented = line.value.get().strip_prefix(b"Bearer ".as_slice());
                if presented == Some(&self.1[..]) {
                    out.put_text(rec::ID_SUBJECT, SUBJECT)
                        .map_err(|_| Fail::refused(R_CONFIG))
                } else {
                    Err(Fail::refused(abi::BAD_CREDENTIAL))
                }
            }
        }
        busbar_plugin_abi::plugin!(Auth, LiftAuth, name: "fixture-lift-auth");
    }

    /// Older settings with a literal key at a secret position: the converting open lifts it, and the auth cases run
    /// on the settings core persisted, where the key is the reference core wrote, resolved by custody to the literal.
    #[test]
    fn a_migrated_literal_secret_verifies_through_the_reference_core_wrote() {
        use super::super::{auth_migrated, harness::OpenPurpose, MigrateCase, MigrateExpect};
        use busbar_plugin_abi::records::core_cfg::LIFT;
        use busbar_plugin_abi::types::{Bytes, Pair, Str};
        let line = |value: &'static str| Pair {
            name: Str::new("authorization"),
            value: Bytes::new(value.as_bytes()),
        };
        fn with<'a>(headers: &'a [Pair<'a>]) -> busbar_ports::auth::AuthIn<'a> {
            busbar_ports::auth::AuthIn {
                headers,
                ..request("/")
            }
        }
        let good = [line("Bearer lifted-bearer-key")];
        let bad = [line("Bearer another-key")];
        let cases = [
            AuthCase {
                req: with(&good),
                expect: Expect::Subject(lift::SUBJECT),
            },
            AuthCase {
                req: with(&bad),
                expect: Expect::Rejected(abi::BAD_CREDENTIAL),
            },
            AuthCase {
                req: request("/"),
                expect: Expect::NotMine,
            },
        ];
        auth_migrated(
            &lift::PLUGIN,
            MigrateCase {
                bag: lift::BAG,
                purpose: OpenPurpose::ConvertUnstamped,
                limits: Default::default(),
            },
            &[],
            FakeNeeds::new(),
            MigrateExpect::Settled {
                config: Some(lift::BAG),
                core_cfg: &[(LIFT, "", br#""/token""#)],
            },
            &cases,
        );
    }

    fn request(path: &str) -> busbar_ports::auth::AuthIn<'_> {
        busbar_ports::auth::AuthIn {
            method: "GET",
            path,
            query: "",
            authority: "example",
            headers: &[],
            peer: "",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1000,
        }
    }

    /// A case that expects a final verdict from a plugin that first answers ISSUED_WANTED gets core's second
    /// call: the id looked up under D_ISSUED_KIND in `FakeNeeds::issued` (empty when none is scripted), and a
    /// second ISSUED_WANTED rejected BAD_CREDENTIAL. A case that expects ISSUED_WANTED stays one raw call.
    #[test]
    fn the_second_verify_after_issued_wanted_is_driven_with_the_scripted_credential() {
        use busbar_plugin_abi::auth::BAD_CREDENTIAL;
        let cases = [
            AuthCase {
                req: request("/known"),
                expect: Expect::Subject(issued::SUBJECT),
            },
            AuthCase {
                req: request("/unknown"),
                expect: Expect::Rejected(BAD_CREDENTIAL),
            },
            AuthCase {
                req: request("/again"),
                expect: Expect::Rejected(BAD_CREDENTIAL),
            },
            AuthCase {
                req: request("/known"),
                expect: Expect::IssuedWanted(issued::ID),
            },
        ];
        let mut needs = FakeNeeds::new();
        needs.issued(issued::KIND, issued::ID, issued::KEY);
        run(&issued::PLUGIN, b"{}", needs, &cases);
        assert_eq!(
            issued::VERIFIES.load(Ordering::SeqCst),
            7,
            "two calls for each final verdict after ISSUED_WANTED, one for the raw ISSUED_WANTED case"
        );
    }
}
