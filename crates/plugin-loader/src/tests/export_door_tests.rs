// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`ExportInstance`] on the one dispatcher, over the real prometheus sink LINKED by its door: its
//! Statement tail read at bind, its settings judged before it opens, its scrape rendering the host
//! snapshot, the one re-call a short answer earns, and the ops it does not serve answered as such.

use std::sync::Arc;

use busbar_contract::abi::export::ExportStream;
use busbar_contract::export_calls::{parse_families, ServeRequest};

use super::*;
use crate::dispatch::{load_linked, Bind, DispatchConfig, LinkedRow, NoSink};

/// The real prometheus sink's door, LINKED: the one place the loader's export tests name it
/// (`conformance::export`'s unjudged test restates it).
pub(crate) const SCRAPE_DOOR: busbar_contract::abi::mechanism::door::DoorFn =
    busbar_export_prometheus::door::door;

fn linked() -> (Plugin<Export>, Arc<Dispatcher>) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(SCRAPE_DOOR).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("export.metrics"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    (plugin, dispatcher)
}

#[test]
fn the_tail_is_read_at_bind() {
    let (plugin, _) = linked();
    let facts = plugin.context::<ExportFacts>().expect("an export tail");
    assert_eq!(facts.streams, vec![ExportStream::Metrics as u8]);
    let routes: Vec<String> = facts
        .routes
        .iter()
        .map(|r| format!("{} {} {:?}", r.method.as_str(), r.path, r.auth))
        .collect();
    assert_eq!(
        routes,
        ["GET /metrics Key", "GET /metrics/hooks Key"],
        "the scrape sink declares its own two well-known routes"
    );
}

#[test]
fn settings_the_sink_refuses_never_open() {
    let (plugin, dispatcher) = linked();
    let refused = ExportInstance::open(plugin, dispatcher, br#"{"bogus":1}"#)
        .expect_err("refused settings do not open");
    assert!(
        refused.starts_with("settings: unknown field `bogus`"),
        "{refused}"
    );
}

#[test]
fn a_scrape_renders_the_snapshot_and_a_short_answer_is_re_called_once() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    // Larger than the first exposition buffer: the sink answers short, the host grows it once.
    let mut text = String::from("# TYPE busbar_big counter\n");
    for i in 0..4000 {
        text.push_str(&format!("busbar_big{{n=\"{i:020}\"}} {i}\n"));
    }
    text.push('\n');
    assert!(text.len() > SCRAPE_BUF);
    let families = parse_families(&text).expect("the snapshot reads");
    let body = sink.scrape(&families).expect("the sink renders");
    assert_eq!(body, text.as_bytes());
    assert_eq!(sink.scrape(&[]).expect("an empty snapshot"), b"");
}

/// THE HOOK FAMILIES' FLAG RIDES THROUGH THE DISPATCHER (P2 D4): `scrape_hooks` sets
/// `SCRAPE_FLAG_HOOK_FAMILIES` on the head, the dispatcher keeps it (it clears only its own bit), and
/// the sink renders the 1.5.5 `/metrics/hooks` layout — on the short answer's re-call too. RED: a
/// dispatcher that zeroes the head renders the `/metrics` layout (a blank line after each family).
#[test]
fn a_hook_scrape_carries_its_flag_through_the_call_and_the_re_call() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    let mut big = String::from("# TYPE big_total counter\n");
    for i in 0..4000 {
        big.push_str(&format!("big_total{{hook=\"h\",n=\"{i:020}\"}} {i}\n"));
    }
    let small = "# TYPE small gauge\nsmall{hook=\"h\"} 1\n";
    let text = format!("{big}{small}");
    assert!(text.len() > SCRAPE_BUF);
    let mut families = parse_families(&format!("{big}\n{small}\n")).expect("the families read");
    families.reverse();
    let body = sink
        .scrape_hooks(&families)
        .expect("the sink renders hook families");
    assert_eq!(String::from_utf8_lossy(&body), text);
    let plain = sink
        .scrape(&families)
        .expect("the sink renders the snapshot");
    assert!(
        String::from_utf8_lossy(&plain).contains("\n\n"),
        "without the flag: /metrics' layout"
    );
}

#[test]
fn the_ops_the_sink_does_not_serve_are_answered_as_such() {
    let (plugin, dispatcher) = linked();
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    assert_eq!(sink.status(), None);
    let req = ServeRequest {
        method: "GET",
        path: "/metrics",
        query: None,
        headers: &[],
        body: &[],
    };
    assert!(
        sink.serve(&req).is_err(),
        "with no host services bound the snapshot read is declined: an error, never bytes"
    );
    assert!(check(sink.plugin(), 1, &[])
        .expect("check answers")
        .is_empty());
}

/// How many times the counting door's `close` was called.
static CLOSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// The real door's `close`, which the counting door forwards to.
static REAL_CLOSE: std::sync::OnceLock<Option<busbar_contract::abi::mechanism::call::Op>> =
    std::sync::OnceLock::new();

extern "C" fn counted_close(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    CLOSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    match REAL_CLOSE.get().copied().flatten() {
        Some(close) => close(instance, input, out),
        None => busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Ready),
    }
}

/// The scrape sink's door with its `close` counted.
extern "C" fn counting_door() -> *const busbar_contract::abi::mechanism::door::Door {
    static AT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let at = *AT.get_or_init(|| {
        // SAFETY: the sink's door and its export table are `'static` plain data.
        let base = unsafe { *SCRAPE_DOOR() };
        // SAFETY: as above; an export door's table is the export `Ops`.
        let mut ops = unsafe { *base.ops.cast::<busbar_contract::abi::export::Ops>() };
        let _ = REAL_CLOSE.set(ops.head.close);
        ops.head.close = Some(counted_close);
        let ops: &'static busbar_contract::abi::export::Ops = Box::leak(Box::new(ops));
        let door = busbar_contract::abi::mechanism::door::Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..base
        };
        std::ptr::from_ref(Box::leak(Box::new(door))) as usize
    });
    at as *const busbar_contract::abi::mechanism::door::Door
}

/// RED (Q128 plugin-loader u70 MEDIUM): an export instance the host lets go is CLOSED, as every
/// sibling kind's is (THE DESIGN: setup and refresh go through open, refresh and tick; the
/// dispatcher's close discipline). Dropping an opened instance (a reload, or the probe a
/// configuration check opens) calls its `close` once.
#[test]
fn red_an_export_instance_let_go_is_closed() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(counting_door).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("export.closed"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let plugin = load_linked::<Export>(&row, bind).expect("the linked door loads");
    let sink = ExportInstance::open(plugin, dispatcher, br#"{"buffer_seconds":60}"#)
        .expect("the sink opens");
    let before = CLOSES.load(std::sync::atomic::Ordering::SeqCst);
    drop(sink);
    assert_eq!(
        CLOSES.load(std::sync::atomic::Ordering::SeqCst) - before,
        1,
        "the instance let go was never closed"
    );
}
