// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE COLD EXPORT SINK, BOTH WAYS** (DECISIONS #11: a plugin is compiled in OR dropped in over
//! the same contract and one loading path; the distinction is a BUILD property and nothing more).
//!
//! M6-COLD-DELETE (TRANSITIONAL): the request-log WEBHOOK sink (the `export-webhook` both-ways row)
//! is the one export sink still on the cold lane, so its declared diagnostics, host-carried
//! outbound requests, in-flight admission and egress grants are held here through the LINKED door
//! (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door (its `cdylib`). The request-log FILE
//! sink is door-only at its pin and has no cold entry: busbar tests no plugin (owner Q7,
//! CONF-SUITE-DEL), and its both-doors conformance is its own repo's.

use super::both_ways::export_webhook_fixture;
use super::*;
use busbar_contract::abi::export::ExportStream;

/// One fold the host was handed, without the host-assigned display name: `(kind, metrics,
/// diagnostics)` — what the PLUGIN said.
type Compared = (String, Vec<serde_json::Value>, Vec<serde_json::Value>);

/// **K9a S3 — PLUGIN DIAGNOSTICS, BOTH WAYS.** The request-log WEBHOOK sink (the `export-webhook`
/// row), its manifest declaring the `BUSBAR-NNNN` codes it raises (its own `declares.json`),
/// registered through the LINKED door and the DROPPED-IN door: both rows state the same declaration
/// and are FIRST-PARTY — which is everything the composition root reads to register the codes into
/// the host's catalogue (`root::linked::declared_diagnostics`, whose own tests hold the catalogue
/// half) — and the sink raising a code (a delivery the host's egress refused: BUSBAR-7072) hands the
/// host the same diagnostic either way. RED ARM, in the same test: the same declaration dropped in by
/// a THIRD party is not first-party, which the root refuses.
#[test]
fn a_declared_diagnostic_is_stated_and_raised_the_same_through_either_door() {
    crate::install_egress_carrier(&CARRIER);
    let decl = serde_json::from_str::<crate::sign::Declares>(export_webhook_fixture::DECLARES)
        .expect("the sink's declaration parses")
        .diagnostics;
    assert!(decl.iter().any(|d| d.code == 7072), "{decl:?}");
    let declaring = |name: &str| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            name,
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        );
        m.declares.diagnostics = decl.clone();
        m
    };
    let cfg = serde_json::json!({ "url": "https://refused.example/in" }).to_string();
    let _guard = crate::observe::testing::exclusive();
    let transcript = |registry: &PluginRegistry| {
        let first_party = registry.resolve("s3-fixture").map(|p| p.first_party());
        let sink = registry.open_export("s3-fixture", &cfg).expect("opens");
        let before = crate::observe::testing::folds().len();
        sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": 1 }))
            .expect("deliver");
        let raised: Vec<Vec<serde_json::Value>> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s3-fixture")
            .map(|(.., d)| d.clone())
            .collect();
        serde_json::json!({ "first_party": first_party, "raised": raised }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors_of(
        "export-webhook",
        declaring("s3-fixture"),
        transcript,
        String::clone,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    assert!(
        linked.0.contains("webhook-delivery-transport-error"),
        "{}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""first_party":true"#) && linked.1.contains("BUSBAR-7072"),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors state and raise the same");

    // RED ARM: a third party's declaration is not first-party.
    let (crate_snake, _) = super::both_ways::fixture("export-webhook");
    let lib = std::fs::read(super::both_ways::cdylib(crate_snake).expect("built above"))
        .expect("read the cdylib");
    let mut third = declaring("s3-third-party");
    third.publisher = "acme".into();
    let registry = super::both_ways::dropped_third_party(crate_snake, third, &lib);
    let row = registry.resolve("s3-third-party").expect("admitted");
    assert_eq!(row.manifest.declares.diagnostics, decl);
    assert!(!row.first_party());
}

/// The egress this test binary installs: it records every request it is asked to carry and answers
/// `204`, and its POLICY refuses any URL on `refused.example` before anything is sent — the shape of
/// the host's own carrier (URL policy first, then the hop).
struct RecordingCarrier(std::sync::Mutex<Vec<busbar_contract::abi::cold::export::HttpRequest>>);

impl crate::EgressCarrier for RecordingCarrier {
    fn carry(
        &self,
        request: &busbar_contract::abi::cold::export::HttpRequest,
    ) -> busbar_contract::abi::cold::export::HostResult {
        use busbar_contract::abi::cold::export::{HostResult, HttpResponse};
        if request.url.contains("stall.example") {
            // Held until released, holding the calling thread (the blocking hop).
            STALLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while !RELEASED.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            STALLED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return HostResult::Http(HttpResponse {
                status: 204,
                body: String::new(),
            });
        }
        if request.url.contains("refused.example") {
            return HostResult::Failed {
                step: "refused".into(),
                error: "the host's egress policy refuses this target".into(),
                rotation: None,
            };
        }
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        HostResult::Http(HttpResponse {
            status: 204,
            body: String::new(),
        })
    }

    fn carry_async(
        &'static self,
        request: busbar_contract::abi::cold::export::HttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = busbar_contract::abi::cold::export::HostResult> + Send,
        >,
    > {
        Box::pin(async move {
            if !request.url.contains("stall.example") {
                return self.carry(&request);
            }
            // Held until released, AWAITED: no thread waits on the far end.
            STALLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while !RELEASED.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            STALLED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            busbar_contract::abi::cold::export::HostResult::Http(
                busbar_contract::abi::cold::export::HttpResponse {
                    status: 204,
                    body: String::new(),
                },
            )
        })
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        match url.contains("refused.example") {
            true => Err("the host's egress policy refuses this target".into()),
            false => Ok(()),
        }
    }
}

static CARRIER: RecordingCarrier = RecordingCarrier(std::sync::Mutex::new(Vec::new()));

/// Requests to `stall.example` the carrier is holding right now, and the switch that lets them go.
static STALLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RELEASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// **K9a S5 — THE EGRESS CARRIER, BOTH WAYS.** The request-log WEBHOOK sink (the `export-webhook`
/// row) registered through the LINKED door and the DROPPED-IN door, opened with a `url`: each
/// delivery has the HOST carry the POST through the installed egress (the sink never dials), and
/// both doors hand the carrier the same requests and fold the same answer — nothing, for a far end
/// that accepted every line, as the 1.5.5 webhook reported nothing. RED ARM, in the same test: a
/// target the host's policy refuses never reaches the wire — nothing is carried — and the sink is
/// told, and reports it (its BUSBAR-7072 transport-error diagnostic).
#[test]
fn a_sinks_outbound_request_is_carried_by_the_host_the_same_through_either_door() {
    crate::install_egress_carrier(&CARRIER);
    let manifest = super::both_ways::statement(
        "export",
        "s5-fixture",
        "s5-fixture",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let _guard = crate::observe::testing::exclusive();
    let run = |registry: &PluginRegistry, url: &str| {
        let cfg = serde_json::json!({ "url": url }).to_string();
        let sink = registry.open_export("s5-fixture", &cfg).expect("opens");
        let before = crate::observe::testing::folds().len();
        CARRIER.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
        for n in 1..=2 {
            sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": n }))
                .expect("deliver");
        }
        let carried = CARRIER.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s5-fixture")
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        serde_json::json!({ "carried": carried, "folds": folds }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors_of(
        "export-webhook",
        manifest.clone(),
        |registry| run(registry, "https://collector.example/v1"),
        String::clone,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    assert!(
        linked.1.contains(r#""body":"{\"n\":2}""#) && linked.1.contains(r#""folds":[]"#),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors are carried the same");

    // RED ARM: the policy refuses the target — nothing is carried, and the sink reports it.
    let registry =
        super::both_ways::linked(manifest, super::both_ways::fixture("export-webhook").1);
    let refused = run(&registry, "https://refused.example/v1");
    assert!(refused.contains(r#""carried":[]"#), "{refused}");
    assert!(refused.contains("BUSBAR-7072"), "{refused}");
}

/// **K9c — A SINK'S DELIVERIES IN FLIGHT ARE BOUNDED BY ITS ADMISSION ALONE.** The request-log
/// WEBHOOK sink (the `export-webhook` row), whose every delivery is a host-carried POST. At an
/// in-flight bound
/// of 600 — above the runtime's 512 blocking threads — 600 deliveries are in flight at once, each
/// awaiting the far end on the host's egress, and the 601st is shed at the gate: the effective
/// concurrency is the configured bound, as the 1.5.5 webhook's async deliveries were. (RED: a
/// delivery that holds a blocking thread while the far end answers plateaus at 512.)
#[test]
fn a_sinks_deliveries_in_flight_reach_its_admission_bound_past_the_blocking_pool() {
    const BOUND: usize = 600;
    crate::install_egress_carrier(&CARRIER);
    let manifest = super::both_ways::statement(
        "export",
        "k9c-bound",
        "k9c-bound",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let registry =
        super::both_ways::linked(manifest, super::both_ways::fixture("export-webhook").1);
    // The far end is held until released: a per-delivery deadline past the wait below.
    let settings =
        serde_json::json!({ "url": "https://stall.example/in", "delivery_timeout_secs": 600 })
            .to_string();
    let sink = std::sync::Arc::new(registry.open_export("k9c-bound", &settings).expect("opens"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let (in_flight, shed) = runtime.block_on(async {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(BOUND));
        let mut shed = 0;
        for n in 0..=BOUND {
            match gate.clone().try_acquire_owned() {
                Ok(permit) => sink.deliver_detached(
                    ExportStream::Logs,
                    std::sync::Arc::new(serde_json::json!({ "n": n })),
                    permit,
                ),
                Err(_) => shed += 1,
            }
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let stalled = || STALLED.load(std::sync::atomic::Ordering::SeqCst);
        while stalled() < BOUND && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Held a moment longer: nothing beyond the bound joins.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let in_flight = stalled();
        RELEASED.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = gate.acquire_many(BOUND as u32).await;
        (in_flight, shed)
    });
    assert_eq!(
        in_flight, BOUND,
        "every admitted delivery is in flight at once"
    );
    assert_eq!(shed, 1, "the delivery past the bound is shed");
}

/// **K9e-2 — A CARRIER CARRIES ONLY THE POLICIES IT IMPLEMENTS.** The loader routes an outbound
/// request with its octets and the sink's granted policy; a carrier that implements only the open
/// web (this binary's recording one, every carrier written before the seam) carries a TEXT body
/// under it exactly as `carry` always did, and REFUSES — carrying nothing — a binary body or any
/// other policy, in words that name what it lacks.
#[test]
fn a_carrier_that_implements_no_policy_but_the_open_web_refuses_the_rest() {
    use crate::EgressPolicy;
    use busbar_contract::abi::cold::export::{HostOp, HostResult, HttpRequest};
    crate::install_egress_carrier(&CARRIER);
    let request = HttpRequest {
        method: "POST".into(),
        url: "https://k9e2-open-web.example/in".into(),
        headers: Vec::new(),
        body: "ignored: the octets travel beside the head".into(),
        timeout_ms: 1000,
    };
    let ours = || {
        CARRIER
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.url.contains("k9e2-open-web.example"))
            .map(|r| r.body.clone())
            .collect::<Vec<_>>()
    };
    let text = crate::host::carry_under(EgressPolicy::OpenWeb, &request, b"{\"a\":1}");
    assert!(
        matches!(text, HostResult::Http(ref r) if r.status == 204),
        "{text:?}"
    );
    assert_eq!(ours(), vec![r#"{"a":1}"#.to_string()], "carried as text");

    let refused = |answer: HostResult, words: &str| match answer {
        HostResult::Failed { step, error, .. } => {
            assert_eq!((step.as_str(), error.as_str()), ("refused", words))
        }
        other => panic!("expected a refusal, got {other:?}"),
    };
    refused(
        crate::host::carry_under(EgressPolicy::OpenWeb, &request, &[0x0a, 0xff]),
        "this host carries no binary request body",
    );
    refused(
        crate::host::carry_under(EgressPolicy::Collector, &request, b"{}"),
        "this host carries no `collector` plugin egress",
    );
    refused(
        crate::host::admit_under(EgressPolicy::Collector, "http://127.0.0.1:4318/v1/traces"),
        "this host carries no `collector` plugin egress",
    );
    // A binary body that is not hex never reaches any carrier.
    let not_hex = HostOp::HttpBinary(HttpRequest {
        body: "zz".into(),
        ..request.clone()
    });
    match crate::host::Destinations::default().perform(&not_hex) {
        HostResult::Failed { step, error, .. } => {
            assert_eq!(step, "request");
            assert!(
                error.starts_with("the binary request body is not hex ("),
                "{error}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ours().len(),
        1,
        "a refused request never reaches the carrier's wire"
    );
}

/// **K9e-2 — A DECLARED EGRESS POLICY IS GRANTED TO A FIRST-PARTY SINK ONLY, AND EVERY REQUEST THE
/// SINK ASKS FOR MEETS IT.** A cold sink (the `export-webhook` row), its manifest stating the
/// `egress: collector` declaration, linked, opens under it, and its admission and its carried requests are judged under that policy (this binary's
/// carrier implements only the open web, so both are refused with the policy's name — the proof
/// the policy, not the open web, reached the carrier). RED ARMS: the same declaration from a third
/// party refuses the open, naming the policy; and a sink that declares none is judged under the
/// open web, as every sink before the seam was.
#[test]
fn a_declared_egress_policy_is_granted_to_a_first_party_sink_only() {
    use crate::EgressPolicy;
    use busbar_contract::abi::cold::export::{HostOp, HostResult, HttpRequest};
    crate::install_egress_carrier(&CARRIER);
    // The declaration's manifest spelling; the default is left off the signed bytes.
    let collector = crate::sign::Declares {
        egress: EgressPolicy::Collector,
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&collector).expect("encode"),
        serde_json::json!({"egress": "collector"})
    );
    assert!(!collector.is_empty() && crate::sign::Declares::default().is_empty());
    assert_eq!(
        serde_json::to_value(crate::sign::Declares::default()).expect("encode"),
        serde_json::json!({})
    );
    let shipped = collector;
    let declaring = |name: &str| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            name,
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        );
        m.declares = shipped.clone();
        m
    };
    let registry = super::both_ways::linked(
        declaring("k9e2-collector"),
        super::both_ways::fixture("export-webhook").1,
    );
    let sink = registry
        .open_export("k9e2-collector", "{}")
        .expect("a first-party declaration is granted");
    assert_eq!(sink.egress(), EgressPolicy::Collector);
    let lacks = "this host carries no `collector` plugin egress";
    let binary = HostOp::HttpBinary(HttpRequest {
        method: "POST".into(),
        url: "http://127.0.0.1:4318/v1/traces".into(),
        headers: Vec::new(),
        body: "0a00".into(),
        timeout_ms: 1000,
    });
    let admit = HostOp::Admit {
        url: "http://127.0.0.1:4318/v1/traces".into(),
    };
    for op in [&binary, &admit] {
        match sink.perform(op) {
            HostResult::Failed { step, error, .. } => {
                assert_eq!(
                    (step.as_str(), error.as_str()),
                    ("refused", lacks),
                    "{op:?}"
                )
            }
            other => panic!("{op:?} was not judged under the declared policy: {other:?}"),
        }
    }

    // RED ARM 1: a third party declaring the same policy is refused at open, naming it.
    let (crate_snake, _) = super::both_ways::fixture("export-webhook");
    let Some(path) = super::both_ways::cdylib(crate_snake) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    let lib = std::fs::read(path).expect("read the cdylib");
    let mut third = declaring("k9e2-third-party");
    third.publisher = "acme".into();
    let refused = super::both_ways::dropped_third_party(crate_snake, third, &lib)
        .open_export("k9e2-third-party", "{}")
        .expect_err("a third party is not granted a policy past the open web");
    assert!(
        refused.contains(
            "declares the `collector` egress policy, which the host grants to a \
             first-party plugin only"
        ),
        "{refused}"
    );

    // RED ARM 2: declaring none is the open web — the admission reaches the carrier's own policy.
    let plain = super::both_ways::linked(
        super::both_ways::statement(
            "export",
            "k9e2-open-web",
            "k9e2-open-web",
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        ),
        super::both_ways::fixture("export-webhook").1,
    )
    .open_export("k9e2-open-web", "{}")
    .expect("opens");
    assert_eq!(plain.egress(), EgressPolicy::OpenWeb);
    assert_eq!(plain.perform(&admit), HostResult::Done { rotation: None });
}
