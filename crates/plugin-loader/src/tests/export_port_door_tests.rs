// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-EXPORT red-first: the kernel's export lane delivers STREAM_METRICS, STREAM_LOGS and STREAM_TRACES
//! (0/1/2) through a kind-level `ExportPort` double (rule 17 Δ4: no real export image) in the round-33 shape:
//! pump-minted `delivery`, counted `attempt`, the ACK-prefix split, APPEND to the bound destination and custody
//! counted per (stream, level). The real-image arms (export-file, export-otlp) are filed on #217.

use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::export_calls::{Delivered as Queued, ExportCalls, Family, Sample};
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::kinds::export::export as x;

use super::{AppendBytes, AppendDenied, DestAppend, PortDoor};
use crate::ports::export::{Custody, Delivered, ExportPort, FamilyIn, RecorderNeeds, ScopeInfo};
use crate::ports::{CallCx, PortError};

const WAIT: Duration = Duration::from_secs(5);
const ACCEPTED: Custody = Custody {
    level: x::CUSTODY_ACCEPTED,
    recheck_s: 0,
};

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
    rendered: Mutex<
        Vec<(
            u32,
            String,
            u32,
            Vec<(u32, f64, f64, Vec<(String, String)>)>,
        )>,
    >,
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
        Box::pin(async move { answer })
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
    PortDoor::open("export.test", port, disk, &InstanceLimits::default()).expect("the pump starts")
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
    seen.sort_unstable();
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
