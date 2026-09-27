// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `traces` STREAM, BOTH DOORS, TO A COLLECTOR** — K9a S7 (BUSBAR-1.6.0 18b(d)) and K9e-2 end
//! to end through the kernel's real export axis: the kernel's traces producer turns closed tracing
//! spans into `traces` records, and the OTLP sink (`module: otlp`, GetBusbar/busbar-export-otlp at the
//! root's pinned rev) is handed them the same whether it came in LINKED or DROPPED IN — and has the
//! host post each as an OTLP/HTTP protobuf request to a collector.
//!
//! The sink is registered twice through the one registration: its logic crate's boundary as a
//! LINKED row (`busbar_export_otlp::linked::EXPORT`, the row the composition root states), and its
//! repo's `cdylib`, release-signed under the same statement (`declares` — the collector egress
//! policy — included), as a DROPPED-IN row of a scanned `plugins/` directory. The kernel resolves an
//! `export:` block naming both, each pointed at its own path on one local collector, opens and
//! starts them, and the producer is installed exactly as `observability::init_logging` installs it —
//! at the span floor, DEBUG. Two spans are closed (a child inside a parent).
//!
//! The host's egress here is this test's carrier, which POSTs over a real socket to the collector —
//! a loopback listener that keeps every request body. Every body must be an OTLP
//! `ExportTraceServiceRequest` by the OpenTelemetry project's own generated types, re-encoding to
//! the very same bytes; the two doors must deliver the SAME requests byte for byte (up to the order
//! two concurrent deliveries land in); and the spans must be the producer's: the child joined to its
//! parent, both in the parent's trace, the span's own vocabulary as attributes.
//!
//! RED ARMS, in the same test: an instance of the same sink whose endpoint the host's collector
//! policy refuses (a private address) starts not live and is handed no span — the host never even
//! asks to carry one — and a span above the DEBUG floor (`trace`) produces no record at all.
//!
//! This is its own test binary because the export axis, the opened sinks and the egress carrier are
//! process-global, set once — as they are at boot.

mod common;

use busbar_plugin_loader::{
    EgressPolicy, HostResult, HttpRequest, HttpResponse, LinkedPlugin, PluginRegistry,
};
use common::plugins;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message as _;
use std::io::{Read as _, Write as _};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing_subscriber::layer::SubscriberExt as _;

/// The dropped-in door's library: the export-otlp repo's cdylib crate, snake-cased.
const CDYLIB: &str = "busbar_export_otlp_plugin";

/// What the collector received, per request path: the bodies, in arrival order.
static RECEIVED: Mutex<Vec<(String, Vec<u8>)>> = Mutex::new(Vec::new());
/// Every URL the host asked this carrier to carry a request to.
static ASKED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The carrier this test installs as the host's egress: the collector policy takes plaintext
/// `http://127.0.0.1` (and nothing else here); it POSTs the octets over a real socket, one
/// connection per request, and answers with the collector's status.
struct Carrier;

impl busbar_plugin_loader::EgressCarrier for Carrier {
    fn carry(&self, request: &HttpRequest) -> HostResult {
        self.carry_under(EgressPolicy::OpenWeb, request, request.body.as_bytes())
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        Err(format!("the open web does not take '{url}' here"))
    }

    fn admit_under(&self, policy: EgressPolicy, url: &str) -> Result<(), String> {
        match (policy, url.strip_prefix("http://127.0.0.1:")) {
            (EgressPolicy::Collector, Some(_)) => Ok(()),
            _ => self.admit(url),
        }
    }

    fn carry_under(&self, policy: EgressPolicy, request: &HttpRequest, body: &[u8]) -> HostResult {
        ASKED.lock().unwrap().push(request.url.clone());
        if let Err(e) = self.admit_under(policy, &request.url) {
            return failed("refused", e);
        }
        let rest = &request.url["http://".len()..];
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let Ok(mut conn) = std::net::TcpStream::connect(authority) else {
            return failed("request", "connect".into());
        };
        let headers: String = request
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\r\n"))
            .collect();
        let head = format!(
            "{} {path} HTTP/1.1\r\nhost: {authority}\r\n{headers}content-length: {}\r\n\
             connection: close\r\n\r\n",
            request.method,
            body.len()
        );
        let mut answer = String::new();
        let sent = conn
            .write_all(head.as_bytes())
            .and_then(|()| conn.write_all(body))
            .and_then(|()| conn.read_to_string(&mut answer));
        let status = answer
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok());
        match (sent, status) {
            (Ok(_), Some(status)) => HostResult::Http(HttpResponse {
                status,
                body: String::new(),
            }),
            _ => failed("request", "no answer".into()),
        }
    }
}

fn failed(step: &str, error: String) -> HostResult {
    HostResult::Failed {
        step: step.into(),
        error,
        rotation: None,
    }
}

/// A loopback OTLP collector: every request's path and body kept, answered 200.
fn collector() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the collector");
    let port = listener.local_addr().expect("an address").port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || serve_one(conn));
        }
    });
    port
}

fn serve_one(mut conn: std::net::TcpStream) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let Ok(n) = conn.read(&mut buf) else { return };
        if n == 0 {
            return;
        }
        raw.extend_from_slice(&buf[..n]);
        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if raw.len() < end + 4 + length {
            continue;
        }
        let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
        assert!(
            head.contains("\r\ncontent-type: application/x-protobuf"),
            "an OTLP/HTTP protobuf request: {head}"
        );
        RECEIVED
            .lock()
            .unwrap()
            .push((path, raw[end + 4..end + 4 + length].to_vec()));
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        return;
    }
}

/// The sink's built `cdylib`: uplifted, or — a git dependency's — under `deps/` with its metadata
/// hash (`lib<name>-<hash>.<ext>`), newest wins. Under CI a missing artifact is a failure, never a
/// skip.
fn cdylib() -> Option<Vec<u8>> {
    let found = plugins::cdylib(CDYLIB);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {CDYLIB} cdylib is not built under CI; a both-doors proof must not skip"
    );
    found
}

/// THE DROPPED-IN DOOR: `lib` release-signed under the sink's statement into a fresh `plugins/`
/// directory, scanned under a policy holding the release key. THE LINKED DOOR joins it through
/// `PluginRegistry::link`, the same admission boot runs. Both state the first-party manifest the
/// linked row states — `declares` included.
fn both_doors(lib: &[u8]) -> &'static PluginRegistry {
    let (_, _, declares, entry) = busbar_export_otlp::linked::EXPORT;
    let statement = |name: &str| {
        let mut m = plugins::manifest("export", name, "busbar");
        m.declares = serde_json::from_str(declares).expect("the sink's declares section");
        m
    };
    let release = plugins::key(11);
    let dir = plugins::scratch("k9e2-plugins");
    let tarball = plugins::signed(&release, statement("k9e-dropped"), lib);
    std::fs::write(dir.join("otlp.tar.gz"), tarball).unwrap();
    let scanned = plugins::boot_with(&dir, &plugins::release_policy(&release));
    let linked = LinkedPlugin::boundary(statement("k9e-linked"), entry);
    let registry = scanned
        .link(vec![linked])
        .expect("the linked door admits it");
    Box::leak(Box::new(registry))
}

/// The requests a collector path received, each decoded by the publisher's types and required to
/// re-encode to the very bytes that arrived.
fn requests(path: &str) -> Vec<ExportTraceServiceRequest> {
    let received = RECEIVED.lock().unwrap().clone();
    received
        .iter()
        .filter(|(p, _)| p == path)
        .map(|(_, body)| {
            let request = ExportTraceServiceRequest::decode(&body[..]).expect("an OTLP request");
            assert_eq!(
                request.encode_to_vec(),
                *body,
                "the canonical OTLP encoding"
            );
            request
        })
        .collect()
}

/// The raw bodies a collector path received, sorted (two deliveries may land in either order).
fn bodies(path: &str) -> Vec<Vec<u8>> {
    let mut b: Vec<Vec<u8>> = RECEIVED
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _)| p == path)
        .map(|(_, body)| body.clone())
        .collect();
    b.sort();
    b
}

fn attribute(span: &Span, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| kv.value.as_ref()?.value.clone())
        .map(|v| match v {
            AnyValue::StringValue(s) => s,
            other => format!("{other:?}"),
        })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_span_reaches_an_otlp_collector_the_same_through_either_door() {
    let Some(lib) = cdylib() else {
        eprintln!("skip: the OTLP sink's cdylib is not built");
        return;
    };
    assert!(busbar_plugin_loader::install_egress_carrier(&Carrier));
    busbar_kernel::export::plugin::install(both_doors(&lib));
    let port = collector();
    let instance = |module: &str, stream: &str, path: &str| {
        serde_json::json!({
            "module": module,
            "streams": [stream],
            "settings": { "url": format!("http://127.0.0.1:{port}{path}") },
        })
    };
    let defs: busbar_kernel::config::ExportDefs = serde_json::from_value(serde_json::json!({
        "linked": instance("k9e-linked", "traces", "/linked/v1/traces"),
        "dropped": instance("k9e-dropped", "traces", "/dropped/v1/traces"),
        "refused": {
            "module": "k9e-dropped",
            "settings": { "url": "http://10.0.0.1/v1/traces" },
        },
    }))
    .expect("an export: block");
    let mut errors = Vec::new();
    let cfg = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    busbar_kernel::export::plugin::open(&cfg).expect("the sinks open");
    // Each sink asks the host's collector policy about its endpoint and starts live.
    tokio::task::spawn_blocking(busbar_kernel::export::plugin::start)
        .await
        .expect("the sinks start");

    // The producer as `init_logging` installs it: the span floor, DEBUG.
    let floor = tracing_subscriber::filter::LevelFilter::DEBUG;
    let producer = busbar_kernel::export::traces::layer(floor);
    assert!(producer.is_some(), "an installed axis has a producer");
    let subscriber = tracing_subscriber::registry().with(producer);
    tracing::subscriber::with_default(subscriber, || {
        let parent = tracing::debug_span!("forward", pool = "p1", ingress = "k9e", op = "chat");
        parent.in_scope(|| {
            tracing::debug_span!("adhoc", provider = "mock", model = "m1").in_scope(|| {});
            // RED ARM: above the floor — no record.
            tracing::trace_span!("too_fine", pool = "p1").in_scope(|| {});
        });
    });

    // Delivery is off the span's thread: wait for both doors' requests to reach the collector.
    let (linked, dropped) = ("/linked/v1/traces", "/dropped/v1/traces");
    let deadline = Instant::now() + Duration::from_secs(20);
    while bodies(linked).len() < 2 || bodies(dropped).len() < 2 {
        assert!(
            Instant::now() < deadline,
            "the spans never reached the collector through both doors: {:?}",
            RECEIVED
                .lock()
                .unwrap()
                .iter()
                .map(|(p, b)| (p.clone(), b.len()))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Let anything that should NOT have been delivered have its chance to land.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        bodies(linked),
        bodies(dropped),
        "the two doors did not post the same OTLP requests"
    );
    let requests = requests(linked);
    assert_eq!(requests.len(), 2, "one request per closed span");
    let spans: Vec<&Span> = requests
        .iter()
        .map(|r| {
            let rs = &r.resource_spans[0];
            let resource = rs.resource.as_ref().expect("a resource");
            assert_eq!(resource.attributes[0].key, "service.name");
            let scope = &rs.scope_spans[0];
            assert_eq!(
                scope.scope.as_ref().map(|s| s.name.as_str()),
                Some("busbar")
            );
            &scope.spans[0]
        })
        .collect();
    let named = |name: &str| {
        *spans
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no `{name}` span: {spans:?}"))
    };
    let (parent, child) = (named("forward"), named("adhoc"));
    assert_eq!(attribute(parent, "pool").as_deref(), Some("p1"));
    assert_eq!(attribute(parent, "ingress").as_deref(), Some("k9e"));
    assert_eq!(attribute(parent, "op").as_deref(), Some("chat"));
    assert!(parent.parent_span_id.is_empty(), "{parent:?}");
    assert_eq!(
        parent.trace_id[8..],
        parent.span_id[..],
        "a root is its own trace"
    );
    assert_eq!(attribute(child, "provider").as_deref(), Some("mock"));
    assert_eq!(attribute(child, "model").as_deref(), Some("m1"));
    assert_eq!(child.parent_span_id, parent.span_id);
    assert_eq!(child.trace_id, parent.trace_id);
    for span in &spans {
        assert_eq!((span.trace_id.len(), span.span_id.len()), (16, 8));
        assert!(
            span.start_time_unix_nano > 0 && span.end_time_unix_nano >= span.start_time_unix_nano,
            "{span:?}"
        );
    }

    // RED ARM: the instance whose endpoint the policy refused took no span — nothing was ever asked
    // to be carried there.
    let asked = ASKED.lock().unwrap().clone();
    assert!(
        !asked.iter().any(|u| u.starts_with("http://10.0.0.1")),
        "a sink the policy refused at start was handed spans: {asked:?}"
    );
    assert_eq!(asked.len(), 4, "two spans, two doors: {asked:?}");
}
