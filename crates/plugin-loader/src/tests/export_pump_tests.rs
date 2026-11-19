// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-EXPORT red-first: the kernel's export lane delivers STREAM_METRICS, STREAM_LOGS and STREAM_TRACES
//! (0/1/2) through a kind-level `ExportPort` double (rule 17 Δ4: no real export image) in the round-33 shape:
//! pump-minted `delivery`, counted `attempt`, the ACK-prefix split, APPEND to the bound destination and custody
//! counted per (stream, level). The real-image arms (export-file, export-otlp) are filed on #217.

use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::export_calls::{Delivered as Queued, ExportCalls, Family, Sample};
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::kinds::export::export as x;

use super::{AppendBytes, AppendDenied, DestAppend, PortDoor};
use busbar_ports::export::{Custody, Delivered, ExportPort, FamilyIn, RecorderNeeds, ScopeInfo};
use busbar_ports::{CallCx, PortError};

/// One family as the fake port rendered it: kind, name, unit, and each sample (kind, value, stamp, labels).
type Rendered = (
    u32,
    String,
    u32,
    Vec<(u32, f64, f64, Vec<(String, String)>)>,
);

const WAIT: Duration = Duration::from_secs(5);
const ACCEPTED: Custody = Custody {
    level: x::CUSTODY_ACCEPTED,
    recheck_s: 0,
};

#[test]
fn retry_wait_keeps_the_host_floor_and_shared_backoff_ceiling() {
    for hint in [None, Some(0)] {
        let wait = super::Shared::resend_wait(2, hint);
        assert!(wait >= Duration::from_millis(100));
        assert!(wait <= Duration::from_millis(250));
    }
    assert!(super::Shared::resend_wait(u32::MAX, None) <= Duration::from_secs(60));
    assert_eq!(
        super::Shared::resend_wait(2, Some(2)),
        Duration::from_secs(2)
    );
    assert_eq!(
        super::Shared::resend_wait(2, Some(301)),
        Duration::from_secs(300)
    );
}

#[derive(Debug, Clone, PartialEq)]
struct Call {
    stream: u32,
    delivery: u64,
    attempt: u32,
    lines: Vec<Vec<u8>>,
}

/// The kind-level export double: answers from a script (default: ACK every line, ACCEPTED) and reports each
/// `deliver` call on a channel.
struct Double {
    streams: u32,
    span: bool,
    ceiling: Option<u32>,
    scopes: Vec<ScopeInfo>,
    script: Mutex<VecDeque<Result<Delivered, PortError>>>,
    calls: Mutex<Sender<Call>>,
    /// When set, the next `deliver` holds the pump until the test sends on it.
    gate: Mutex<Option<Receiver<()>>>,
    pending: bool,
    rendered: Mutex<Vec<Rendered>>,
}

impl Double {
    fn new(streams: &[u32]) -> (Arc<Self>, Receiver<Call>) {
        let (tx, rx) = channel();
        let d = Arc::new(Self {
            streams: streams.iter().fold(0, |m, s| m | (1 << s)),
            span: false,
            ceiling: None,
            scopes: vec![ScopeInfo {
                scope: x::SCOPE_METRICS,
                path: "/metrics".into(),
            }],
            script: Mutex::new(VecDeque::new()),
            calls: Mutex::new(tx),
            gate: Mutex::new(None),
            pending: false,
            rendered: Mutex::new(Vec::new()),
        });
        (d, rx)
    }

    fn answer(&self, a: Result<Delivered, PortError>) {
        self.script.lock().unwrap().push_back(a);
    }
}

impl ExportPort for Double {
    fn streams(&self) -> u32 {
        self.streams
    }
    fn scopes(&self) -> &[ScopeInfo] {
        &self.scopes
    }
    fn recorder(&self) -> Option<RecorderNeeds> {
        Some(RecorderNeeds {
            retention_s: 60,
            key_gauge_limit: 7,
        })
    }
    fn span_records(&self) -> bool {
        self.span
    }
    fn deliver<'a>(
        &'a self,
        _cx: CallCx,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: &'a [&'a [u8]],
    ) -> BoxFut<'a, Result<Delivered, PortError>> {
        let answer = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(Delivered::Acked {
                accepted: lines.len() as u64,
                custody: ACCEPTED,
            }));
        let _ = self.calls.lock().unwrap().send(Call {
            stream,
            delivery,
            attempt,
            lines: lines.iter().map(|l| l.to_vec()).collect(),
        });
        let gate = self.gate.lock().unwrap().take();
        if let Some(g) = gate {
            let _ = g.recv_timeout(WAIT);
        }
        if self.pending {
            Box::pin(futures::future::pending())
        } else {
            Box::pin(async move { answer })
        }
    }
    fn custody_ceiling(&self) -> Option<u32> {
        self.ceiling
    }
    fn pending_capacity(&self) -> Option<u64> {
        None
    }
    fn confirm(&self, _cx: CallCx, _delivery: u64) -> BoxFut<'_, Result<Custody, PortError>> {
        Box::pin(async {
            Err(PortError::Refused {
                code: busbar_plugin_abi::fail::refused::R_UNSUPPORTED,
                text: "the double does not declare confirm".into(),
                error: None,
            })
        })
    }
    fn render(
        &self,
        scope: u32,
        snapshot: &[FamilyIn<'_>],
        sink: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<(), PortError> {
        let mut seen = self.rendered.lock().unwrap();
        for f in snapshot {
            seen.push((
                scope,
                f.name.to_string(),
                f.kind,
                f.samples
                    .iter()
                    .map(|s| {
                        (
                            s.role,
                            s.value,
                            s.bound,
                            s.labels
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect(),
                        )
                    })
                    .collect(),
            ));
        }
        sink("text/plain; version=0.0.4", b"rendered");
        Ok(())
    }
}

/// The disk lane double: records each append, joined with newlines.
#[derive(Default)]
struct Disk {
    appended: Mutex<Vec<(u32, Vec<u8>)>>,
    deny: Mutex<Option<AppendDenied>>,
}

impl DestAppend for Disk {
    fn append(&self, dest: u32, bytes: AppendBytes<'_>) -> Result<(), AppendDenied> {
        if let Some(d) = *self.deny.lock().unwrap() {
            return Err(d);
        }
        let bytes = match bytes {
            AppendBytes::Batch(lines) => lines.iter().fold(Vec::new(), |mut b, l| {
                b.extend_from_slice(l);
                b.push(b'\n');
                b
            }),
            AppendBytes::Owned(b) => b,
        };
        self.appended.lock().unwrap().push((dest, bytes));
        Ok(())
    }
}

fn open(port: Arc<Double>, disk: Arc<Disk>) -> Arc<PortDoor> {
    PortDoor::open(
        "export.test",
        port,
        disk,
        &InstanceLimits::default(),
        Arc::new(Observations::default()),
    )
    .expect("the pump starts")
}

fn send(door: &PortDoor, stream: u32, line: &str) {
    assert_eq!(
        door.deliver(stream as u8, line.as_bytes().to_vec(), Box::new(())),
        Queued::Queued
    );
}

fn next(rx: &Receiver<Call>) -> Call {
    rx.recv_timeout(WAIT).expect("the pump called deliver")
}

#[test]
fn prepared_export_does_not_start_delivery_until_publication() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    let door = PortDoor::prepare(
        "prepared",
        port,
        Arc::new(Disk::default()),
        &InstanceLimits::default(),
        Arc::new(Observations::default()),
    );
    assert!(door.pump.lock().unwrap().is_none());
    send(&door, x::STREAM_LOGS, "held");
    assert!(matches!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    door.start().expect("publication starts the prepared pump");
    assert!(door.start().is_err(), "one candidate can start only once");
    assert_eq!(next(&rx).lines, vec![b"held".to_vec()]);
    assert!(door.stop_until(Instant::now() + WAIT).clean());
    assert!(
        door.start().is_err(),
        "a stopped generation cannot be restarted"
    );
}

#[test]
fn streams_0_1_2_reach_the_port_with_minted_deliveries() {
    let (port, rx) = Double::new(&[x::STREAM_METRICS, x::STREAM_LOGS, x::STREAM_TRACES]);
    let door = open(port, Arc::new(Disk::default()));
    assert_eq!(door.streams(), &[0, 1, 2]);
    let mut seen = Vec::new();
    for stream in [x::STREAM_METRICS, x::STREAM_LOGS, x::STREAM_TRACES] {
        send(&door, stream, &format!("{{\"s\":{stream}}}"));
        let call = next(&rx);
        assert_eq!(call.stream, stream);
        assert_eq!(call.attempt, 1, "a first send is attempt 1");
        assert_ne!(call.delivery, 0, "a delivery id is never 0");
        assert_eq!(call.lines, vec![format!("{{\"s\":{stream}}}").into_bytes()]);
        seen.push(call.delivery);
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "each line set gets its own delivery id");
    assert_eq!(door.custody_total(x::STREAM_LOGS, x::CUSTODY_ACCEPTED), 1);
}

#[test]
fn an_undeclared_stream_is_shed_not_delivered() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    let door = open(port, Arc::new(Disk::default()));
    assert_eq!(
        door.deliver(x::STREAM_TRACES as u8, b"{}".to_vec(), Box::new(())),
        Queued::Shed
    );
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
}

#[test]
fn a_failed_send_resends_the_same_delivery_with_the_next_attempt() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Err(PortError::Failed {
        code: 1,
        text: "down".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }));
    let door = open(port, Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "a");
    let first = next(&rx);
    let again = next(&rx);
    assert_eq!(
        again.delivery, first.delivery,
        "a resend keeps its delivery"
    );
    assert_eq!(again.attempt, first.attempt + 1);
    assert_eq!(again.lines, first.lines);
}

#[test]
fn the_unaccepted_rest_is_a_new_line_set_with_the_next_attempt() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    let (release, gate) = channel();
    *port.gate.lock().unwrap() = Some(gate);
    // "x" is acked whole; the set {a, b} is acked 1 of 2.
    port.answer(Ok(Delivered::Acked {
        accepted: 1,
        custody: ACCEPTED,
    }));
    port.answer(Ok(Delivered::Acked {
        accepted: 1,
        custody: ACCEPTED,
    }));
    let door = open(port, Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "x");
    let _ = next(&rx); // the pump is held inside this call
    send(&door, x::STREAM_LOGS, "a");
    send(&door, x::STREAM_LOGS, "b");
    release.send(()).unwrap();
    let set = next(&rx);
    assert_eq!(set.lines, vec![b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(set.attempt, 1);
    let rest = next(&rx);
    assert_eq!(rest.lines, vec![b"b".to_vec()]);
    assert_ne!(rest.delivery, set.delivery, "the rest is a new line set");
    assert_eq!(rest.attempt, set.attempt + 1);
}

#[test]
fn an_append_with_no_bytes_lands_the_delivered_lines_verbatim() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Ok(Delivered::Append {
        dest: 0,
        bytes: None,
        accepted: 1,
    }));
    let disk = Arc::new(Disk::default());
    let door = open(port, disk.clone());
    send(&door, x::STREAM_LOGS, "{\"a\":1}");
    let _ = next(&rx);
    let deadline = std::time::Instant::now() + WAIT;
    while door.custody_total(x::STREAM_LOGS, x::CUSTODY_ACCEPTED) == 0
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        *disk.appended.lock().unwrap(),
        vec![(0, b"{\"a\":1}\n".to_vec())]
    );
    assert_eq!(
        door.custody_total(x::STREAM_LOGS, x::CUSTODY_ACCEPTED),
        1,
        "an APPEND counts ACCEPTED, never DURABLE"
    );
    assert_eq!(door.custody_total(x::STREAM_LOGS, x::CUSTODY_DURABLE), 0);
}

#[test]
fn a_foreign_destination_drops_the_lines_without_a_resend() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Ok(Delivered::Append {
        dest: 9,
        bytes: None,
        accepted: 1,
    }));
    let disk = Arc::new(Disk::default());
    *disk.deny.lock().unwrap() = Some(AppendDenied::Foreign);
    let door = open(port, disk);
    send(&door, x::STREAM_LOGS, "a");
    let _ = next(&rx);
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(door.dropped(), 1);
}

#[test]
fn facts_and_ceiling_are_read_through_the_port() {
    let (tx, _rx) = channel();
    let port = Arc::new(Double {
        streams: 1 << x::STREAM_TRACES,
        span: true,
        ceiling: Some(x::CUSTODY_DURABLE),
        scopes: Vec::new(),
        script: Mutex::new(VecDeque::new()),
        calls: Mutex::new(tx),
        gate: Mutex::new(None),
        pending: false,
        rendered: Mutex::new(Vec::new()),
    });
    let door = open(port, Arc::new(Disk::default()));
    assert!(door.takes_span_records());
    assert_eq!(door.custody_ceiling(), Some(x::CUSTODY_DURABLE));
    let r = door.recorder_requirements().expect("D_RECORDER read");
    assert_eq!((r.retention_seconds, r.key_gauge_limit), (60, 7));
    assert!(door.routes().is_empty());
    assert!(door.scrape_hooks(&[]).is_err(), "no SCOPE_HOOKS declared");
}

#[test]
fn a_scrape_renders_the_lowered_snapshot_at_scope_metrics() {
    let (port, _rx) = Double::new(&[x::STREAM_METRICS]);
    let door = open(port.clone(), Arc::new(Disk::default()));
    let sample = |name: &str, labels: &[(&str, &str)], value: &str| Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        value: value.into(),
    };
    let fam = Family {
        name: "lat".into(),
        help: Some("latency".into()),
        unit: None,
        kind: busbar_contract::export_calls::kind_of("histogram").unwrap(),
        samples: vec![
            sample("lat_bucket", &[("route", "r"), ("le", "0.5")], "3"),
            sample("lat_sum", &[("route", "r")], "1.25"),
            sample("lat_count", &[("route", "r")], "3"),
        ],
    };
    assert_eq!(door.scrape(&[fam]).unwrap(), b"rendered");
    let seen = port.rendered.lock().unwrap();
    let (scope, name, kind, samples) = &seen[0];
    assert_eq!(
        (*scope, name.as_str(), *kind),
        (x::SCOPE_METRICS, "lat", x::FAMILY_HISTOGRAM)
    );
    assert_eq!(samples[0].0, x::SAMPLE_BUCKET);
    assert_eq!(samples[0].2, 0.5, "le becomes the bound");
    assert_eq!(samples[0].3, vec![("route".to_string(), "r".to_string())]);
    assert_eq!(samples[1].0, x::SAMPLE_SUM);
    assert!(samples[1].2.is_nan());
    assert_eq!(samples[2].0, x::SAMPLE_COUNT);
    assert_eq!(samples[2].1, 3.0);
}

/// One family exactly as a port is lent it: kind, name, help, and each sample's role, value bits, bound bits,
/// stamp and labels. Floats as bits, so NaN compares and -0.0 differs from 0.0.
type Lent = (
    u32,
    String,
    String,
    Vec<(u32, u64, u64, u64, Vec<(String, String)>)>,
);

fn lent(snapshot: &[FamilyIn<'_>]) -> Vec<Lent> {
    snapshot
        .iter()
        .map(|f| {
            (
                f.kind,
                f.name.to_string(),
                f.help.to_string(),
                f.samples
                    .iter()
                    .map(|s| {
                        (
                            s.role,
                            s.value.to_bits(),
                            s.bound.to_bits(),
                            s.ts_ms,
                            s.labels
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect(),
                        )
                    })
                    .collect(),
            )
        })
        .collect()
}

/// The lowering as it was before the flat lists (a list per family of sample shapes, a list per family of
/// samples, the families), copied verbatim: the reference the new lowering's output is compared against.
fn nested_lowering<R>(families: &[Family], f: impl FnOnce(&[FamilyIn<'_>]) -> R) -> R {
    fn shape<'f>(
        family: &'f Family,
        sample_name: &str,
        labels: &'f [(String, String)],
    ) -> (u32, f64, Vec<(&'f str, &'f str)>) {
        let suffix = sample_name.strip_prefix(family.name.as_str()).unwrap_or("");
        let coordinate = |key: &str| {
            labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| super::number(v))
        };
        let (role, bound, drop) = match suffix {
            "_bucket" => (
                x::SAMPLE_BUCKET,
                coordinate("le").unwrap_or(f64::NAN),
                Some("le"),
            ),
            "_sum" => (x::SAMPLE_SUM, f64::NAN, None),
            "_count" => (x::SAMPLE_COUNT, f64::NAN, None),
            _ if super::family_kind(family.kind) == x::FAMILY_SUMMARY => {
                match coordinate("quantile") {
                    Some(q) => (x::SAMPLE_QUANTILE, q, Some("quantile")),
                    None => (x::SAMPLE_VALUE, f64::NAN, None),
                }
            }
            _ => (x::SAMPLE_VALUE, f64::NAN, None),
        };
        let kept = labels
            .iter()
            .filter(|(k, _)| Some(k.as_str()) != drop)
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        (role, bound, kept)
    }
    type Shape<'a> = (u32, f64, Vec<(&'a str, &'a str)>);
    let shapes: Vec<Vec<Shape<'_>>> = families
        .iter()
        .map(|fam| {
            fam.samples
                .iter()
                .map(|s| shape(fam, &s.name, &s.labels))
                .collect()
        })
        .collect();
    let samples: Vec<Vec<busbar_ports::export::SampleIn<'_>>> = families
        .iter()
        .zip(&shapes)
        .map(|(fam, shapes)| {
            fam.samples
                .iter()
                .zip(shapes)
                .map(
                    |(s, (role, bound, labels))| busbar_ports::export::SampleIn {
                        value: super::number(&s.value),
                        bound: *bound,
                        ts_ms: 0,
                        role: *role,
                        labels,
                    },
                )
                .collect()
        })
        .collect();
    let snapshot: Vec<FamilyIn<'_>> = families
        .iter()
        .zip(&samples)
        .map(|(fam, samples)| FamilyIn {
            kind: super::family_kind(fam.kind),
            name: &fam.name,
            help: fam.help.as_deref().unwrap_or(""),
            samples,
        })
        .collect();
    f(&snapshot)
}

/// Every shape the lowering distinguishes: each family kind (untyped renders as a gauge), help absent and
/// present, a family with no samples, samples with no labels, `le` and `quantile` coordinates first, middle and
/// last, a coordinate on a sample that does not drop it, a repeated coordinate key, a summary sample without a
/// quantile, a sample name outside its family's prefix, and values that are spaced, signed, infinite or not
/// numbers.
fn lowering_fixtures() -> Vec<Family> {
    let kind = |w: &str| busbar_contract::export_calls::kind_of(w).unwrap();
    let sample = |name: &str, labels: &[(&str, &str)], value: &str| Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        value: value.into(),
    };
    let family = |name: &str, help: Option<&str>, kind: u8, samples: Vec<Sample>| Family {
        name: name.into(),
        help: help.map(Into::into),
        unit: None,
        kind,
        samples,
    };
    vec![
        family(
            "requests_total",
            Some("requests served"),
            kind("counter"),
            vec![
                sample("requests_total", &[("route", "a"), ("code", "200")], "12"),
                sample("requests_total", &[], " 3 "),
                sample("requests_total", &[("le", "1"), ("route", "b")], "-0"),
            ],
        ),
        family("empty", None, kind("gauge"), Vec::new()),
        family(
            "temp",
            None,
            kind("gauge"),
            vec![
                sample("temp", &[("zone", "x")], "+Inf"),
                sample("temp", &[("zone", "y")], "NaN"),
                sample("temp", &[("zone", "z")], "not a number"),
            ],
        ),
        family(
            "lat",
            Some("latency"),
            kind("histogram"),
            vec![
                sample("lat_bucket", &[("le", "0.1"), ("route", "r")], "1"),
                sample(
                    "lat_bucket",
                    &[("route", "r"), ("le", "0.5"), ("m", "GET")],
                    "3",
                ),
                sample("lat_bucket", &[("route", "r"), ("le", "+Inf")], "4"),
                sample("lat_bucket", &[("route", "r")], "4"),
                sample("lat_bucket", &[("le", "1"), ("le", "2")], "5"),
                sample("lat_sum", &[("route", "r"), ("le", "9")], "1.25"),
                sample("lat_count", &[("route", "r")], "4"),
            ],
        ),
        family(
            "rpc",
            Some(""),
            kind("summary"),
            vec![
                sample("rpc", &[("quantile", "0.5"), ("svc", "s")], "0.2"),
                sample("rpc", &[("svc", "s"), ("quantile", "0.99")], "0.9"),
                sample("rpc", &[("svc", "s")], "0.4"),
                sample("rpc_sum", &[("svc", "s"), ("quantile", "1")], "7"),
                sample("rpc_count", &[], "9"),
            ],
        ),
        family(
            "raw",
            Some("untyped"),
            kind("untyped"),
            vec![
                sample("raw", &[("quantile", "0.5")], "1e3"),
                sample("other_name", &[("le", "1")], "2"),
            ],
        ),
    ]
}

#[test]
fn the_flat_lowering_lends_the_port_what_the_nested_lowering_did() {
    let families = lowering_fixtures();
    let before = nested_lowering(&families, lent);
    let after = super::with_snapshot(&families, lent);
    assert_eq!(after, before);
    assert_eq!(after.len(), 6);
    assert_eq!(
        after.iter().map(|f| f.3.len()).sum::<usize>(),
        20,
        "every sample reaches the port"
    );
    // Each prefix of the families, and none: a family's run of samples never borrows its neighbour's.
    for n in 0..=families.len() {
        assert_eq!(
            super::with_snapshot(&families[..n], lent),
            nested_lowering(&families[..n], lent)
        );
    }
    for one in &families {
        let one = std::slice::from_ref(one);
        assert_eq!(super::with_snapshot(one, lent), nested_lowering(one, lent));
    }
}

#[test]
fn the_flat_lowering_reaches_the_port_through_scrape_and_render_scope() {
    let (port, _rx) = Double::new(&[x::STREAM_METRICS]);
    let door = open(port.clone(), Arc::new(Disk::default()));
    let families = lowering_fixtures();
    assert_eq!(door.scrape(&families).unwrap(), b"rendered");
    let served = door
        .render_scope(x::SCOPE_METRICS, &families)
        .expect("renders");
    assert_eq!(served.body, b"rendered");
    let expected: Vec<Rendered> = nested_lowering(&families, |snapshot| {
        snapshot
            .iter()
            .map(|f| {
                (
                    x::SCOPE_METRICS,
                    f.name.to_string(),
                    f.kind,
                    f.samples
                        .iter()
                        .map(|s| {
                            (
                                s.role,
                                s.value,
                                s.bound,
                                s.labels
                                    .iter()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    });
    let seen = port.rendered.lock().unwrap();
    assert_eq!(
        seen.len(),
        2 * expected.len(),
        "one scrape, one scope render"
    );
    let bits = |r: &[Rendered]| {
        r.iter()
            .map(|(scope, name, kind, samples)| {
                (
                    *scope,
                    name.clone(),
                    *kind,
                    samples
                        .iter()
                        .map(|(role, value, bound, labels)| {
                            (*role, value.to_bits(), bound.to_bits(), labels.clone())
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(bits(&seen[..expected.len()]), bits(&expected));
    assert_eq!(bits(&seen[expected.len()..]), bits(&expected));
}

#[test]
fn each_attempt_lends_the_tail_not_yet_accepted() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    let (release, gate) = channel();
    *port.gate.lock().unwrap() = Some(gate);
    // "x" is acked whole. The set {a, b, c, d}: 1 appended verbatim, then a failure, then 1 acked, then the rest.
    port.answer(Ok(Delivered::Acked {
        accepted: 1,
        custody: ACCEPTED,
    }));
    port.answer(Ok(Delivered::Append {
        dest: 0,
        bytes: None,
        accepted: 1,
    }));
    port.answer(Err(PortError::Failed {
        code: 1,
        text: "down".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }));
    port.answer(Ok(Delivered::Acked {
        accepted: 1,
        custody: ACCEPTED,
    }));
    let disk = Arc::new(Disk::default());
    let door = open(port, disk.clone());
    send(&door, x::STREAM_LOGS, "x");
    let _ = next(&rx); // the pump is held inside this call
    for line in ["a", "b", "c", "d"] {
        send(&door, x::STREAM_LOGS, line);
    }
    release.send(()).unwrap();
    let lines = |c: &Call| c.lines.clone();
    let set = next(&rx);
    assert_eq!(
        lines(&set),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    );
    assert_eq!(set.attempt, 1);
    let after_append = next(&rx);
    assert_eq!(
        lines(&after_append),
        vec![b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    );
    assert_eq!(after_append.attempt, 2);
    assert_ne!(after_append.delivery, set.delivery);
    let resent = next(&rx);
    assert_eq!(
        resent.lines, after_append.lines,
        "a resend lends the same tail"
    );
    assert_eq!(resent.delivery, after_append.delivery);
    assert_eq!(resent.attempt, 3);
    // Out of attempts after the third send: c and d are dropped, never sent again.
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(*disk.appended.lock().unwrap(), vec![(0, b"a\n".to_vec())]);
    assert_eq!(door.delivered(), 3, "x, a and b");
    assert_eq!(door.dropped(), 2);
}

#[test]
fn a_terminal_limit_failure_is_not_reoffered() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Err(PortError::Failed {
        code: busbar_plugin_abi::fail::failed::F_LIMIT,
        text: "limit".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }));
    let door = open(port, Arc::new(Disk::default()));
    let lines = [super::Line {
        stream: x::STREAM_LOGS as u8,
        bytes: busbar_contract::secure::SecureVec::from(b"limit-line".to_vec()),
        _hold: Box::new(()),
    }];
    // Drive the production delivery loop synchronously: no sleeps or timeout-based
    // assertion can hide a late retry, and the background queue stays empty.
    door.shared.deliver_set(x::STREAM_LOGS as u8, &lines);
    assert_eq!(next(&rx).attempt, 1);
    assert!(
        rx.try_recv().is_err(),
        "F_LIMIT is terminal, never a resend"
    );
    assert_eq!(door.dropped(), 1);
    assert_eq!(door.delivered(), 0);
}

#[test]
fn draining_rejects_new_lines_and_finishes_the_accepted_queue() {
    let (port, rx) = Double::new(&[x::STREAM_LOGS]);
    let (release, gate) = channel();
    *port.gate.lock().unwrap() = Some(gate);
    let door = open(port, Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "first");
    let _ = next(&rx);
    send(&door, x::STREAM_LOGS, "queued");
    let deadline = std::time::Instant::now() + WAIT;
    door.begin_drain(deadline);
    assert_eq!(
        door.deliver(x::STREAM_LOGS as u8, b"late".to_vec(), Box::new(())),
        Queued::Shed
    );
    release.send(()).unwrap();
    let report = door.stop_until(deadline);
    assert!(report.worker_stopped);
    assert_eq!((report.queued, report.in_flight, report.dropped), (0, 0, 1));
    assert_eq!(door.delivered(), 2);
    assert_eq!(next(&rx).lines, vec![b"queued".to_vec()]);
    assert!(rx.try_recv().is_err());
}

#[test]
fn stop_cancels_a_pending_call_without_an_unbounded_join() {
    struct Released(Sender<()>);
    impl Drop for Released {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let (mut port, calls) = Double::new(&[x::STREAM_LOGS]);
    Arc::get_mut(&mut port).unwrap().pending = true;
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    door.start().unwrap();
    let (released, custody) = channel();
    assert_eq!(
        door.deliver(
            x::STREAM_LOGS as u8,
            b"held".to_vec(),
            Box::new(Released(released))
        ),
        Queued::Queued
    );
    let _ = next(&calls);
    let began = std::time::Instant::now();
    let _ = door.stop_until(began + Duration::from_millis(20));
    assert!(
        began.elapsed() < WAIT,
        "shutdown is bounded even when deliver stays pending"
    );
    custody
        .recv_timeout(WAIT)
        .expect("cancellation releases custody");
    let report = door.stop_until(std::time::Instant::now() + WAIT);
    assert_eq!(report.dropped, 1);
    assert_eq!(door.delivered(), 0);
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[busbar_contract::export_calls::ExportObservation::Dropped {
            reason: busbar_contract::export_calls::ExportDropReason::Stopped,
            lines: 1,
        },]
    );
    assert!(calls.try_recv().is_err(), "no offer after cancellation");
}

#[test]
fn stop_interrupts_a_long_retry_after_without_another_offer() {
    struct Released(Sender<()>);
    impl Drop for Released {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let (port, calls) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Err(PortError::Failed {
        code: 1,
        text: "retry later".into(),
        retry_after_s: Some(300),
        backend_status: None,
        error: None,
    }));
    let door = open(port, Arc::new(Disk::default()));
    let (released, custody) = channel();
    assert_eq!(
        door.deliver(
            x::STREAM_LOGS as u8,
            b"held".to_vec(),
            Box::new(Released(released))
        ),
        Queued::Queued
    );
    let first = next(&calls);
    assert_eq!(first.attempt, 1);
    let began = Instant::now();
    let report = door.stop_until(began + Duration::from_millis(20));
    assert!(
        began.elapsed() < WAIT,
        "Retry-After cannot extend the shutdown deadline"
    );
    assert!(!report.clean(), "the accepted line was not delivered");
    custody
        .recv_timeout(WAIT)
        .expect("the interrupted retry releases its retained custody");
    assert_eq!(door.delivered(), 0);
    assert!(
        calls.try_recv().is_err(),
        "stopping cannot reoffer the failed delivery"
    );
}

#[test]
fn a_later_stop_request_cannot_extend_the_first_deadline() {
    let (mut port, calls) = Double::new(&[x::STREAM_LOGS]);
    Arc::get_mut(&mut port).unwrap().pending = true;
    let door = open(port, Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "held");
    let _ = next(&calls);
    let first = std::time::Instant::now();
    door.begin_drain(first);
    let report = door.stop_until(first + WAIT);
    assert!(first.elapsed() < Duration::from_secs(1));
    assert!(
        !report.clean(),
        "deadline loss must not look like a clean drain"
    );
}

#[test]
fn declared_scopes_are_get_routes_before_the_pump_starts() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    let (mut port, _) = Double::new(&[x::STREAM_METRICS]);
    Arc::get_mut(&mut port).unwrap().scopes.push(ScopeInfo {
        scope: x::SCOPE_HOOKS,
        path: "/observations/hooks".into(),
    });
    let door = PortDoor::prepare(
        "observations",
        port,
        Arc::new(Disk::default()),
        &InstanceLimits::default(),
        Arc::new(Observations::default()),
    );
    let paths: Vec<_> = door
        .routes()
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    assert_eq!(paths, ["/metrics", "/observations/hooks"]);
    assert!(door
        .routes()
        .iter()
        .all(|route| { route.method == RouteMethod::Get && route.auth == RouteAuth::None }));
    assert_eq!(door.public_routes(), ["/metrics", "/observations/hooks"]);
    assert!(
        door.pump.lock().unwrap().is_none(),
        "route assembly never starts the delivery worker"
    );
}

#[derive(Default)]
struct Observations(Mutex<Vec<busbar_contract::export_calls::ExportObservation>>);

impl busbar_contract::export_calls::ExportObserver for Observations {
    fn observe(&self, event: busbar_contract::export_calls::ExportObservation) {
        self.0.lock().unwrap().push(event);
    }
}

fn observed(port: Arc<Double>, disk: Arc<Disk>) -> (Arc<PortDoor>, Arc<Observations>) {
    let observer = Arc::new(Observations::default());
    let door = PortDoor::prepare(
        "observed",
        port,
        disk,
        &InstanceLimits::default(),
        observer.clone(),
    );
    (door, observer)
}

fn retained_lines(n: usize) -> Vec<super::Line> {
    (0..n)
        .map(|_| super::Line {
            stream: x::STREAM_LOGS as u8,
            bytes: busbar_contract::secure::SecureVec::from(b"line".to_vec()),
            _hold: Box::new(()),
        })
        .collect()
}

#[test]
fn observer_records_exact_accepted_prefixes_and_terminal_remainder() {
    use busbar_contract::export_calls::{ExportCustodyLevel, ExportDropReason, ExportObservation};
    use busbar_contract::export_stream::ExportStream;
    let (port, calls) = Double::new(&[x::STREAM_LOGS]);
    port.answer(Ok(Delivered::Acked {
        accepted: 1,
        custody: ACCEPTED,
    }));
    port.answer(Err(PortError::Failed {
        code: busbar_plugin_abi::fail::failed::F_LIMIT,
        text: "private".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }));
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    door.shared
        .deliver_set(x::STREAM_LOGS as u8, &retained_lines(3));
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[
            ExportObservation::Custody {
                stream: ExportStream::Logs,
                level: ExportCustodyLevel::Accepted,
                lines: 1
            },
            ExportObservation::Dropped {
                reason: ExportDropReason::Refused,
                lines: 2
            },
        ]
    );
    assert_eq!(door.delivered(), 1);
    assert_eq!(door.dropped(), 2);
    assert_eq!(next(&calls).lines.len(), 3);
    assert_eq!(next(&calls).lines.len(), 2);
    assert!(calls.try_recv().is_err());
}

#[test]
fn observer_separates_capture_integrity_queue_full_and_stopped() {
    use busbar_contract::export_calls::{ExportDropReason, ExportLossKind, ExportObservation};
    let (port, _) = Double::new(&[x::STREAM_LOGS]);
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    door.shed(ExportLossKind::CaptureRefused);
    door.shed(ExportLossKind::IntegrityFailed);
    assert_eq!(
        door.deliver(x::STREAM_METRICS as u8, vec![], Box::new(())),
        Queued::Shed
    );
    for _ in 0..super::MAX_QUEUED_LINES {
        send(&door, x::STREAM_LOGS, "line");
    }
    assert_eq!(
        door.deliver(x::STREAM_LOGS as u8, vec![], Box::new(())),
        Queued::Shed
    );
    door.begin_drain(Instant::now());
    assert_eq!(
        door.deliver(x::STREAM_LOGS as u8, vec![], Box::new(())),
        Queued::Shed
    );
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[
            ExportObservation::CaptureRefused,
            ExportObservation::IntegrityFailed,
            ExportObservation::CaptureRefused,
            ExportObservation::Dropped {
                reason: ExportDropReason::QueueFull,
                lines: 1
            },
            ExportObservation::Dropped {
                reason: ExportDropReason::Stopped,
                lines: 1
            },
        ]
    );
    assert_eq!(
        door.dropped(),
        2,
        "capture/integrity failures are not dropped lines"
    );
    drop(door);
    assert_eq!(
        observer.0.lock().unwrap().last(),
        Some(&ExportObservation::Dropped {
            reason: ExportDropReason::Stopped,
            lines: super::MAX_QUEUED_LINES as u64,
        })
    );
}

#[test]
fn observer_append_acknowledges_only_successful_disk_custody() {
    use busbar_contract::export_calls::{ExportCustodyLevel, ExportDropReason, ExportObservation};
    use busbar_contract::export_stream::ExportStream;
    for foreign in [false, true] {
        let (port, _) = Double::new(&[x::STREAM_LOGS]);
        port.answer(Ok(Delivered::Append {
            dest: 7,
            bytes: None,
            accepted: 2,
        }));
        let disk = Arc::new(Disk::default());
        if foreign {
            *disk.deny.lock().unwrap() = Some(AppendDenied::Foreign);
        }
        let (door, observer) = observed(port, disk);
        door.shared
            .deliver_set(x::STREAM_LOGS as u8, &retained_lines(2));
        let expected = if foreign {
            ExportObservation::Dropped {
                reason: ExportDropReason::ForeignDestination,
                lines: 2,
            }
        } else {
            ExportObservation::Custody {
                stream: ExportStream::Logs,
                level: ExportCustodyLevel::Accepted,
                lines: 2,
            }
        };
        assert_eq!(observer.0.lock().unwrap().as_slice(), &[expected]);
    }
}

#[test]
fn observer_maps_only_canonical_positive_wire_custody() {
    use busbar_contract::export_calls::{ExportCustodyLevel, ExportObservation};
    use busbar_contract::export_stream::ExportStream;
    let (port, _) = Double::new(&[x::STREAM_LOGS]);
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    for wire in [x::CUSTODY_NONE, x::CUSTODY_INDEXED + 1, u32::MAX] {
        door.shared.count_custody(x::STREAM_LOGS as u8, wire, 1);
    }
    assert!(observer.0.lock().unwrap().is_empty());
    let levels = [
        (
            x::CUSTODY_ACCEPTED,
            ExportCustodyLevel::Accepted,
            "accepted",
        ),
        (x::CUSTODY_DURABLE, ExportCustodyLevel::Durable, "durable"),
        (x::CUSTODY_INDEXED, ExportCustodyLevel::Indexed, "indexed"),
    ];
    for (wire, level, label) in levels {
        door.shared.count_custody(x::STREAM_LOGS as u8, wire, 1);
        assert_eq!(door.custody_total(x::STREAM_LOGS, wire), 1);
        assert_eq!(level.as_str(), label);
    }
    assert_eq!(
        *observer.0.lock().unwrap(),
        levels.map(|(_, level, _)| ExportObservation::Custody {
            stream: ExportStream::Logs,
            level,
            lines: 1,
        })
    );
}

#[test]
fn observer_ignores_zero_and_invalid_custody_levels() {
    use busbar_contract::export_calls::{ExportCustodyLevel, ExportObservation};
    use busbar_contract::export_stream::ExportStream;
    let (port, _) = Double::new(&[x::STREAM_LOGS]);
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    for level in [0, 4, u32::MAX] {
        door.shared.count_custody(x::STREAM_LOGS as u8, level, 1);
    }
    door.shared
        .count_custody(x::STREAM_LOGS as u8, x::CUSTODY_ACCEPTED, 0);
    door.shared
        .count_custody(x::STREAM_LOGS as u8, x::CUSTODY_INDEXED, 2);
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[ExportObservation::Custody {
            stream: ExportStream::Logs,
            level: ExportCustodyLevel::Indexed,
            lines: 2
        },]
    );
    assert_eq!(door.custody_total(x::STREAM_LOGS, 0), 0);
}

#[test]
fn observer_reports_stopping_inflight_bytes_once() {
    use busbar_contract::export_calls::{ExportDropReason, ExportObservation};
    let (port, calls) = Double::new(&[x::STREAM_LOGS]);
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    door.begin_drain(Instant::now());
    door.shared
        .deliver_set(x::STREAM_LOGS as u8, &retained_lines(2));
    assert!(calls.try_recv().is_err());
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[ExportObservation::Dropped {
            reason: ExportDropReason::Stopped,
            lines: 2
        },]
    );
}

#[test]
fn observer_records_one_drop_after_zero_ack_exhausts_attempts() {
    use busbar_contract::export_calls::{ExportDropReason, ExportObservation};
    let (port, calls) = Double::new(&[x::STREAM_LOGS]);
    for _ in 0..super::DELIVER_ATTEMPTS {
        port.answer(Ok(Delivered::Acked {
            accepted: 0,
            custody: ACCEPTED,
        }));
    }
    let (door, observer) = observed(port, Arc::new(Disk::default()));
    door.shared
        .deliver_set(x::STREAM_LOGS as u8, &retained_lines(2));
    assert_eq!(
        observer.0.lock().unwrap().as_slice(),
        &[ExportObservation::Dropped {
            reason: ExportDropReason::AttemptsExhausted,
            lines: 2
        },]
    );
    let attempts: Vec<_> = calls.try_iter().collect();
    assert_eq!(attempts.len(), super::DELIVER_ATTEMPTS as usize);
    assert!(attempts
        .iter()
        .all(|call| call.delivery == attempts[0].delivery));
    assert_eq!(door.delivered(), 0);
    assert_eq!(door.dropped(), 2);
}

// DES-454 r3.1 §4 (core #454): the export swap seam. The kernel's export lane keeps one door; a credential
// rotation (and, reusing the seam, an export reload, #461) swaps the port and its disk lane under it together.

fn binding(port: Arc<Double>, disk: Arc<Disk>) -> super::ExportBinding {
    super::ExportBinding { port, disk }
}

fn gated(port: &Double) -> Sender<()> {
    let (release, gate) = channel();
    *port.gate.lock().unwrap() = Some(gate);
    release
}

fn denied() -> PortError {
    PortError::Refused {
        code: busbar_plugin_abi::fail::refused::R_DENIED,
        text: "the old credential was revoked".into(),
        error: None,
    }
}

fn no_drops(observer: &Observations) -> bool {
    !observer.0.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            busbar_contract::export_calls::ExportObservation::Dropped { .. }
        )
    })
}

/// T5: the set in flight finishes on the old port; the queued lines and a racing `deliver` go to the successor,
/// each line once, in order.
#[test]
fn a_swap_delivers_the_set_in_flight_and_the_queue_once_in_order() {
    let (old, old_rx) = Double::new(&[x::STREAM_LOGS]);
    let (new, new_rx) = Double::new(&[x::STREAM_LOGS]);
    let release = gated(&old);
    let door = open(Arc::clone(&old), Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "a");
    assert_eq!(next(&old_rx).lines, vec![b"a".to_vec()]);
    send(&door, x::STREAM_LOGS, "b");
    let held = door.binding();
    let predecessor = door
        .swap_binding(&held, binding(Arc::clone(&new), Arc::new(Disk::default())))
        .map_err(|(why, _)| why)
        .expect("the same shape swaps");
    assert!(Arc::ptr_eq(&predecessor, &held));
    send(&door, x::STREAM_LOGS, "c");
    release.send(()).unwrap();
    let mut seen = Vec::new();
    while seen.len() < 2 {
        seen.extend(next(&new_rx).lines);
    }
    assert_eq!(seen, vec![b"b".to_vec(), b"c".to_vec()]);
    assert!(old_rx.recv_timeout(Duration::from_millis(200)).is_err());
    assert_eq!((door.delivered(), door.dropped()), (3, 0));
}

/// T27 (owner Q5): a refusal from a binding the door no longer holds is not final. The next attempt goes to the
/// successor at once with the same delivery id; the old port gets no further call and nothing is dropped.
#[test]
fn the_attempt_after_a_swap_goes_to_the_successor_with_the_same_delivery() {
    let (old, old_rx) = Double::new(&[x::STREAM_LOGS]);
    let (new, new_rx) = Double::new(&[x::STREAM_LOGS]);
    old.answer(Err(denied()));
    let release = gated(&old);
    let (door, observer) = observed(Arc::clone(&old), Arc::new(Disk::default()));
    door.start().unwrap();
    send(&door, x::STREAM_LOGS, "a");
    let first = next(&old_rx);
    door.swap_binding(
        &door.binding(),
        binding(Arc::clone(&new), Arc::new(Disk::default())),
    )
    .map_err(|(why, _)| why)
    .expect("swaps");
    release.send(()).unwrap();
    let retried = next(&new_rx);
    assert_eq!(retried.delivery, first.delivery);
    assert_eq!(retried.attempt, first.attempt + 1);
    assert_eq!(retried.lines, first.lines);
    assert!(old_rx.recv_timeout(Duration::from_millis(200)).is_err());
    assert!(no_drops(&observer));
    assert_eq!(door.delivered(), 1);
}

/// T6: after a swap, a scrape and a scope render are the successor's.
#[test]
fn scrape_and_render_scope_are_served_by_the_successor() {
    let (old, _) = Double::new(&[x::STREAM_METRICS]);
    let (new, _) = Double::new(&[x::STREAM_METRICS]);
    let door = open(Arc::clone(&old), Arc::new(Disk::default()));
    door.swap_binding(
        &door.binding(),
        binding(Arc::clone(&new), Arc::new(Disk::default())),
    )
    .map_err(|(why, _)| why)
    .expect("swaps");
    let fam = Family {
        name: "up".into(),
        help: None,
        unit: None,
        kind: busbar_contract::export_calls::kind_of("gauge").unwrap(),
        samples: vec![Sample {
            name: "up".into(),
            labels: Vec::new(),
            value: "1".into(),
        }],
    };
    door.scrape(std::slice::from_ref(&fam)).expect("scrapes");
    door.render_scope(x::SCOPE_METRICS, std::slice::from_ref(&fam))
        .expect("renders");
    assert!(old.rendered.lock().unwrap().is_empty());
    assert_eq!(new.rendered.lock().unwrap().len(), 2);
}

/// T7: a successor of another shape is refused and handed back; the door keeps serving the old binding.
#[test]
fn a_successor_of_another_shape_is_refused_and_handed_back() {
    let (old, old_rx) = Double::new(&[x::STREAM_LOGS]);
    let door = open(Arc::clone(&old), Arc::new(Disk::default()));
    let held = door.binding();
    let (streams, _) = Double::new(&[x::STREAM_LOGS, x::STREAM_TRACES]);
    let (mut ceiling, _) = Double::new(&[x::STREAM_LOGS]);
    Arc::get_mut(&mut ceiling).unwrap().ceiling = Some(x::CUSTODY_DURABLE);
    let (mut span, _) = Double::new(&[x::STREAM_LOGS]);
    Arc::get_mut(&mut span).unwrap().span = true;
    let (mut scopes, _) = Double::new(&[x::STREAM_LOGS]);
    Arc::get_mut(&mut scopes).unwrap().scopes.clear();
    for successor in [streams, ceiling, span, scopes] {
        let refused = door
            .swap_binding(
                &held,
                binding(Arc::clone(&successor), Arc::new(Disk::default())),
            )
            .err()
            .expect("refused");
        assert_eq!(refused.0, super::SwapRefused::ShapeChanged);
        assert!(Arc::ptr_eq(
            &refused.1.port,
            &(successor as Arc<dyn ExportPort>)
        ));
    }
    assert!(Arc::ptr_eq(&door.binding(), &held));
    send(&door, x::STREAM_LOGS, "still-old");
    assert_eq!(next(&old_rx).lines, vec![b"still-old".to_vec()]);
}

/// A stale or draining swap is refused: the cell is fenced on the binding read and on the door's stop.
#[test]
fn a_stale_or_draining_swap_is_refused() {
    let (old, _) = Double::new(&[x::STREAM_LOGS]);
    let (first, _) = Double::new(&[x::STREAM_LOGS]);
    let (second, _) = Double::new(&[x::STREAM_LOGS]);
    let door = open(old, Arc::new(Disk::default()));
    let held = door.binding();
    door.swap_binding(&held, binding(first, Arc::new(Disk::default())))
        .map_err(|(why, _)| why)
        .expect("swaps");
    let stale = door
        .swap_binding(
            &held,
            binding(Arc::clone(&second), Arc::new(Disk::default())),
        )
        .err()
        .expect("stale");
    assert_eq!(stale.0, super::SwapRefused::Superseded);
    door.begin_drain(Instant::now() + WAIT);
    let draining = door
        .swap_binding(&door.binding(), binding(second, Arc::new(Disk::default())))
        .err()
        .expect("draining");
    assert_eq!(draining.0, super::SwapRefused::Stopping);
}

/// T25: an `Append` export writes through the successor's disk lane after the swap, port and disk together,
/// and keeps writing once the predecessor is gone.
#[test]
fn an_append_export_keeps_writing_after_a_swap_and_the_predecessor_closing() {
    let (old, old_rx) = Double::new(&[x::STREAM_LOGS]);
    let (new, new_rx) = Double::new(&[x::STREAM_LOGS]);
    let old_disk = Arc::new(Disk::default());
    let new_disk = Arc::new(Disk::default());
    let append = || {
        Ok(Delivered::Append {
            dest: 0,
            bytes: None,
            accepted: 1,
        })
    };
    old.answer(append());
    new.answer(append());
    new.answer(append());
    let door = open(Arc::clone(&old), Arc::clone(&old_disk));
    send(&door, x::STREAM_LOGS, "before");
    next(&old_rx);
    let predecessor = door
        .swap_binding(&door.binding(), binding(new, Arc::clone(&new_disk)))
        .map_err(|(why, _)| why)
        .expect("swaps");
    send(&door, x::STREAM_LOGS, "after");
    next(&new_rx);
    drop(predecessor);
    drop(old);
    send(&door, x::STREAM_LOGS, "closed");
    next(&new_rx);
    let deadline = Instant::now() + WAIT;
    while new_disk.appended.lock().unwrap().len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        *old_disk.appended.lock().unwrap(),
        vec![(0, b"before\n".to_vec())]
    );
    assert_eq!(
        *new_disk.appended.lock().unwrap(),
        vec![(0, b"after\n".to_vec()), (0, b"closed\n".to_vec())]
    );
}

/// T32 (door side): once the attempt running on the predecessor ends, the pump holds no clone of it, so the
/// caller's copy is the last and its drop (the instance close) runs where the caller puts it, never on the pump.
#[test]
fn the_pump_releases_the_predecessor_once_its_attempt_ends() {
    let (old, old_rx) = Double::new(&[x::STREAM_LOGS]);
    let (new, new_rx) = Double::new(&[x::STREAM_LOGS]);
    let release = gated(&old);
    let door = open(old, Arc::new(Disk::default()));
    send(&door, x::STREAM_LOGS, "a");
    next(&old_rx);
    let predecessor = door
        .swap_binding(&door.binding(), binding(new, Arc::new(Disk::default())))
        .map_err(|(why, _)| why)
        .expect("swaps");
    assert!(
        Arc::strong_count(&predecessor) > 1,
        "the pump's attempt holds it"
    );
    release.send(()).unwrap();
    send(&door, x::STREAM_LOGS, "b");
    next(&new_rx);
    let deadline = Instant::now() + WAIT;
    while Arc::strong_count(&predecessor) > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(Arc::strong_count(&predecessor), 1);
}
