// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use super::both_ways::{cdylib, door_fixture, dropped, dropped_third_party, row, statement};
use crate::auth_axis::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::redacted::{sha256_hex, Secret};

const PROOF: &str = "auth-verify";

const TOKEN: &str = "the-operator-token";

const CASES: [(Option<&str>, Option<&str>); 6] = [
    (Some(TOKEN), None),
    (None, Some(TOKEN)),
    (Some("not-the-token"), None),
    (None, Some("not-the-token")),
    (Some("aaa.bbb.ccc"), None),
    (None, None),
];

const LINES: (&str, &str) = ("authorization", "x-admin-token");

fn stated(door: busbar_contract::abi::mechanism::door::DoorFn) -> crate::sign::Manifest {
    let rendering = crate::dispatch::LinkedRow::of(door)
        .expect("the door states itself")
        .statement;
    crate::sign::Manifest {
        statement: Some(hex::encode(rendering)),
        ..statement(
            "auth",
            "auth-fixture",
            "the-auth",
            busbar_contract::abi::auth::ABI_VERSION,
        )
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }))
}

fn request(bearer: Option<&str>, other: Option<&str>) -> VerifyRequest {
    let line = |name: &str, value: String| (name.to_string(), Secret::new(value.into_bytes()));
    let lines = bearer
        .map(|b| line(LINES.0, format!("Bearer {b}")))
        .into_iter()
        .chain(other.map(|h| line(LINES.1, h.to_string())))
        .collect();
    VerifyRequest {
        point: AuthPoint::Head,
        lines,
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        conn: 0,
        unit: 0,
        credential: None,
        peer: None,
        body: None,
        query: None,
        timestamp: 0,
    }
}

fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    format!("{verdict} {:?} [{}]", a.decision, strips.join(", "))
}

fn doors(third_party: bool) -> [PluginRegistry; 2] {
    let (crate_snake, door) = door_fixture(PROOF);
    let lib = std::fs::read(cdylib(crate_snake)).expect("read the cdylib");
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(stated(door), door)])
        .expect("the linked door admits the plugin");
    let dropped = if third_party {
        let mut m = stated(door);
        m.publisher = "a-third-party".into();
        dropped_third_party(crate_snake, m, &lib)
    } else {
        dropped(crate_snake, stated(door), &lib)
    };
    [linked, dropped]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_verdicts_keep_the_first_judgment_through_both_auth_doors() {
    for registry in doors(false) {
        let rows = AuthRows::new(Arc::new(registry), dispatcher());
        let opened = rows
            .open(
                "the-auth",
                "the-auth",
                &serde_json::json!(sha256_hex(TOKEN.as_bytes())),
            )
            .expect("the fixture opens");
        let wide = || {
            let mut r = request(Some(TOKEN), None);
            r.path = "/auth-short-custody".into();
            r
        };
        let identity = |answer: VerifyAnswer, judgment: u64| {
            let Verified::Identity(id) = answer.verified else {
                panic!("the fixture must identify")
            };
            assert_eq!(id.subject, format!("judgment-{judgment}"));
            assert_eq!(id.groups.len(), 300);
            assert_eq!(id.groups[299], "group-299");
        };
        identity(opened.verify_now(&wide()).expect("on the spot"), 1);
        identity(Box::into_pin(opened.verify(wide())).await, 2);

        identity(Box::into_pin(opened.verify(wide())).await, 3);
        identity(
            opened.verify_now(&wide()).expect("another on-the-spot op"),
            4,
        );
    }
}

#[test]
fn abandoned_short_tokens_release_and_closed_auth_instances_refuse_recall_both_ways() {
    use crate::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::auth::{slot, IdentifyOut, VerifyIn, POINT_HEAD};
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, ReleaseIn};
    let frame = || {
        let mut input: VerifyIn = busbar_contract::abi::sdk::test_support::zeroed();
        input.head = in_head();
        input.point = POINT_HEAD;
        input.request.canonical_path =
            busbar_contract::abi::sdk::door::abi_str("/auth-short-custody");
        let mut output: IdentifyOut = busbar_contract::abi::sdk::test_support::zeroed();
        output.head = out_head();
        Frame::new(input, output)
    };
    for registry in doors(false) {
        let d = dispatcher();
        let rows = AuthRows::new(Arc::new(registry), d.clone());
        let opened = rows
            .open_for_test(
                "the-auth",
                "the-auth",
                &serde_json::json!(sha256_hex(TOKEN.as_bytes())),
            )
            .unwrap();
        let plugin = opened.plugin();
        let mut first = frame();
        let short = plugin.call(slot::VERIFY, &mut first);
        assert_eq!(short.outcome, Outcome::Failed);
        assert_eq!(short.lease, 0, "negotiated storage stays private");
        let lease = first.out.head.lease;
        assert_ne!(lease, 0);
        drop(short.recall.expect("one recall token"));
        let mut release = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        assert_eq!(
            plugin.call(life::RELEASE, &mut release).outcome,
            Outcome::Refused,
            "token drop already returned its lease"
        );
        for cancel in [false, true] {
            use busbar_contract::abi::mechanism::call::DeadlineClass;
            use busbar_contract::abi::mechanism::lifecycle::{TickIn, TickOut};
            let ticket = d.mint(0).unwrap();
            let done = d
                .submit(
                    plugin,
                    ticket,
                    slot::VERIFY,
                    frame(),
                    DeadlineClass::Call,
                    0,
                )
                .wait(Duration::from_secs(10))
                .unwrap();
            assert!(done.short);
            assert_eq!(done.lease, 0);
            let lease = done.frame.unwrap().out.head.lease;
            if cancel {
                d.drop_client(ticket);
            } else {
                d.recycle(ticket);
            }

            for _ in 0..2 {
                let barrier = d.mint(0).unwrap();
                let tick = Frame::new(
                    TickIn {
                        head: in_head(),
                        now_ns: 0,
                    },
                    TickOut {
                        head: out_head(),
                        next_tick_ns: 0,
                    },
                );
                assert_eq!(
                    d.submit(plugin, barrier, life::TICK, tick, DeadlineClass::Call, 0)
                        .wait(Duration::from_secs(10))
                        .unwrap()
                        .outcome,
                    Outcome::Ready
                );
                d.recycle(barrier);
            }
            let mut release = Frame::new(
                ReleaseIn {
                    head: in_head(),
                    lease,
                },
                out_head(),
            );
            assert_eq!(
                plugin.call(life::RELEASE, &mut release).outcome,
                Outcome::Refused,
                "ticket lifecycle already returned its lease"
            );
            if cancel {
                d.recycle(ticket);
            }
        }
        let mut second = frame();
        let token = plugin.call(slot::VERIFY, &mut second).recall.unwrap();
        assert_eq!(
            plugin
                .call(life::CLOSE, &mut Frame::new(in_head(), out_head()))
                .outcome,
            Outcome::Ready
        );
        assert!(!plugin.is_open());
        assert!(matches!(
            plugin.recall(token, slot::VERIFY, &mut frame()).outcome,
            Outcome::Refused | Outcome::Fault
        ));
    }
}

async fn transcript(registry: PluginRegistry, digest: &str) -> String {
    let rows = AuthRows::new(Arc::new(registry), dispatcher());
    let opened = rows
        .open("the-auth", "the-auth", &serde_json::json!(digest))
        .expect("the plugin opens through its alias over a digest");
    let mut out = vec![format!(
        "name={} facts={} operator={:?}",
        opened.name(),
        opened.facts(),
        rows.operator()
    )];
    for (bearer, other) in CASES {
        let now = opened
            .verify_now(&request(bearer, other))
            .map_or_else(|| "not on the spot".to_string(), |a| spelled(&a));
        let submitted = spelled(&Box::into_pin(opened.verify(request(bearer, other))).await);
        out.push(format!(
            "{bearer:?} {other:?} -> now {now} / submitted {submitted}"
        ));
    }
    out.join("\n")
}

fn assert_every_verdict(transcript: &str) {
    assert!(
        transcript.contains("Identity")
            && transcript.contains("Reject")
            && transcript.contains("Pass"),
        "the token cases must identify, reject and pass: {transcript}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_and_a_dropped_in_auth_door_answer_byte_identically() {
    let [linked, dropped] = doors(false);
    let rows = [row(&linked, "auth-fixture"), row(&dropped, "auth-fixture")];
    assert!(
        !rows[0].starts_with("no row"),
        "the linked door registered no row: {}",
        rows[0]
    );
    assert_eq!(rows[0], rows[1], "the two doors must register one row");
    let digest = sha256_hex(TOKEN.as_bytes());
    let linked = transcript(linked, &digest).await;
    let dropped = transcript(dropped, &digest).await;
    assert_every_verdict(&linked);
    assert!(
        linked.contains(r#"operator=Some(("the-auth", "admin"))"#),
        "the axis finds the operator credential's row by its Statement: {linked}"
    );
    assert_eq!(linked, dropped, "the two doors must answer as one plugin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_door_judging_another_token_is_told_apart() {
    let [linked, dropped] = doors(false);
    let linked = transcript(linked, &sha256_hex(TOKEN.as_bytes())).await;
    let dropped = transcript(dropped, &sha256_hex(b"a-rotated-token")).await;
    assert_every_verdict(&linked);
    assert!(
        !dropped.contains("Identity"),
        "the rotated door identified the operator's token: {dropped}"
    );
    assert_ne!(
        linked, dropped,
        "a door judging another token must not compare equal — this inequality is what \
         `a_linked_and_a_dropped_in_auth_door_answer_byte_identically` exists to refuse"
    );
}

// The real OIDC image is held while its immutable SDK descriptor is lent to the registry.
fn actual_oidc() -> (
    std::path::PathBuf,
    busbar_contract::abi::mechanism::door::DoorFn,
) {
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use std::sync::OnceLock;
    static IMAGE: OnceLock<(std::path::PathBuf, libloading::Library, RawDoorFn)> = OnceLock::new();
    extern "C" fn door() -> &'static busbar_contract::abi::mechanism::door::Door {
        let image = IMAGE.get_or_init(|| {
            let path = std::env::var_os("BUSBAR_TEST_OIDC_CDYLIB")
                .map(std::path::PathBuf::from)
                .expect("BUSBAR_TEST_OIDC_CDYLIB names the actual qualified OIDC image");
            assert!(path.is_absolute() && path.is_file());
            let library = crate::dlopen_on_worker(path.as_os_str())
                .expect("actual OIDC loads on the plugin worker");
            // SAFETY: the exact product image exports the typed SDK door entry and remains in IMAGE.
            let entry = unsafe {
                *library
                    .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                    .expect("actual OIDC door")
            };
            (path, library, entry)
        });
        let raw = crate::dispatch::load::enter_door(image.2);
        crate::dispatch::load::validate_door::<crate::dispatch::kinds::auth::Auth>(raw)
            .expect("actual OIDC auth descriptor validates");
        // SAFETY: validation establishes the descriptor; IMAGE holds its mapping for every loan.
        unsafe { &*raw }
    }
    let _ = door();
    (IMAGE.get().unwrap().0.clone(), door)
}

#[test]
fn a_third_party_signature_is_a_different_row() {
    let (path, door) = actual_oidc();
    let image = std::fs::read(path).expect("read the actual OIDC image");
    let stated = crate::dispatch::rendering_of(door).expect("actual OIDC statement renders");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("actual OIDC statement reads")
        .name;
    let manifest = LinkedPlugin::first_party_door("auth", &module, "the-auth", door).manifest;
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(manifest.clone(), door)])
        .expect("actual OIDC linked row");
    let mut third_party = manifest;
    third_party.publisher = "a-third-party".into();
    let dropped = dropped_third_party("actual-oidc", third_party, &image);
    let dropped_row = row(&dropped, &module);
    assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
    assert_ne!(
        row(&linked, &module),
        dropped_row,
        "a third-party actual OIDC row must not compare equal to the first-party one"
    );
}
